// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package a2aproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	aigv1a1 "github.com/envoyproxy/ai-gateway/api/v1alpha1"
	"github.com/envoyproxy/ai-gateway/internal/filterapi"
	"github.com/envoyproxy/ai-gateway/internal/internalapi"
	"github.com/envoyproxy/ai-gateway/internal/json"
	"github.com/envoyproxy/ai-gateway/internal/mcpproxy"
	"github.com/envoyproxy/ai-gateway/internal/metrics"
)

// jsonRPCRequest represents a JSON-RPC 2.0 request.
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// jsonRPCResponse represents a JSON-RPC 2.0 response.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

// jsonRPCError represents a JSON-RPC 2.0 error object.
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// messageSendParams represents the params for the message/send method.
type messageSendParams struct {
	// TaskID is an optional existing task ID to continue an existing task.
	TaskID *string `json:"taskId,omitempty"`
	// Message is the message content.
	Message json.RawMessage `json:"message,omitempty"`
	// Metadata is optional request metadata.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// tasksGetParams represents the params for the tasks/get method.
type tasksGetParams struct {
	// ID is the task ID to retrieve.
	ID string `json:"id"`
}

// a2aRequestContext handles A2A requests.
type a2aRequestContext struct {
	*ProxyConfig
	metrics       metrics.A2AMetrics
	sessionCrypto mcpproxy.SessionCrypto
	logger        *slog.Logger
	client        *http.Client
}

// serveHTTP is the main HTTP handler for A2A requests.
func (a *a2aRequestContext) serveHTTP(w http.ResponseWriter, r *http.Request) {
	startAt := time.Now()

	// Handle agent card discovery.
	if r.Method == http.MethodGet {
		if r.URL.Path == agentCardPath || r.URL.Path == agentCardLegacyPath {
			a.handleAgentCard(w, r)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse JSON-RPC request.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONRPCError(w, nil, -32700, "failed to read request body")
		return
	}

	var rpcReq jsonRPCRequest
	if err = json.Unmarshal(body, &rpcReq); err != nil {
		writeJSONRPCError(w, nil, -32700, "failed to parse JSON-RPC request")
		return
	}

	// Record method count.
	a.metrics.RecordMethodCount(r.Context(), rpcReq.Method)

	// Dispatch by method.
	var result json.RawMessage
	var rpcErr *jsonRPCError
	switch rpcReq.Method {
	case "message/send", "tasks/send": // tasks/send is the legacy alias.
		result, rpcErr = a.handleMessageSend(r, rpcReq)
	case "tasks/get":
		result, rpcErr = a.handleTasksGet(r, rpcReq)
	case "agent/getAuthenticatedExtendedCard":
		result, rpcErr = a.handleGetExtendedCard(r, rpcReq)
	default:
		rpcErr = &jsonRPCError{Code: -32601, Message: fmt.Sprintf("method not found: %s", rpcReq.Method)}
	}

	if rpcErr != nil {
		a.metrics.RecordRequestError(r.Context(), rpcReq.Method, "rpc_error")
		resp := jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      rpcReq.ID,
			Error:   rpcErr,
		}
		writeJSONResponse(w, http.StatusOK, resp)
		return
	}

	a.metrics.RecordRequestDuration(r.Context(), startAt, rpcReq.Method)
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      rpcReq.ID,
		Result:  result,
	}
	writeJSONResponse(w, http.StatusOK, resp)
}

// handleAgentCard handles agent card discovery requests.
func (a *a2aRequestContext) handleAgentCard(w http.ResponseWriter, r *http.Request) {
	// Find the route from the route header.
	routeName := r.Header.Get(internalapi.A2ARouteHeader)
	route := a.routes[routeName]
	if route == nil {
		// Return a minimal agent card if no route is configured.
		card := &aigv1a1.AgentCard{Name: "AI Gateway A2A Proxy"}
		writeJSONResponse(w, http.StatusOK, card)
		return
	}

	// Collect agent cards from all backends.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	backendCards := make(map[string]*aigv1a1.AgentCard)
	for _, backend := range route.backends {
		if backend.URL == "" {
			continue
		}
		card, err := fetchAgentCard(ctx, a.client, backend.URL)
		if err != nil {
			a.logger.Warn("failed to fetch agent card from backend",
				slog.String("backend", backend.Name),
				slog.String("error", err.Error()),
			)
			continue
		}
		backendCards[backend.Name] = card
	}

	// Build ordered list of backends for consistent aggregation.
	var backends []filterapi.A2ABackend
	for _, b := range route.backends {
		backends = append(backends, b)
	}

	// Get the gateway URL from the request.
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	gatewayURL := fmt.Sprintf("%s://%s", scheme, r.Host)

	aggregated := aggregateAgentCards(backends, backendCards, gatewayURL, route.agentCard, route.skillSelectors)
	writeJSONResponse(w, http.StatusOK, aggregated)
}

// handleMessageSend handles message/send (and legacy tasks/send) requests.
func (a *a2aRequestContext) handleMessageSend(r *http.Request, rpcReq jsonRPCRequest) (json.RawMessage, *jsonRPCError) {
	var params messageSendParams
	if len(rpcReq.Params) > 0 {
		if err := json.Unmarshal(rpcReq.Params, &params); err != nil {
			return nil, &jsonRPCError{Code: -32602, Message: "invalid params for message/send"}
		}
	}

	routeName := r.Header.Get(internalapi.A2ARouteHeader)
	route := a.routes[routeName]
	if route == nil {
		return nil, &jsonRPCError{Code: -32603, Message: fmt.Sprintf("no route found: %s", routeName)}
	}

	// Determine backend: decode from task ID if present, else use first backend.
	var backendName string
	var backendTaskID string
	if params.TaskID != nil && *params.TaskID != "" {
		var routeFromTask string
		var err error
		backendName, backendTaskID, routeFromTask, err = decodeTaskID(a.sessionCrypto, *params.TaskID)
		if err != nil {
			return nil, &jsonRPCError{Code: -32602, Message: "invalid task ID"}
		}
		_ = routeFromTask // routeName already known from header.
	}

	if backendName == "" {
		// Pick first backend as default.
		for name := range route.backends {
			backendName = name
			break
		}
	}

	backend, ok := route.backends[backendName]
	if !ok {
		return nil, &jsonRPCError{Code: -32603, Message: fmt.Sprintf("backend not found: %s", backendName)}
	}

	// Rewrite the params to include the backend task ID if we decoded one.
	forwardParams := rpcReq.Params
	if backendTaskID != "" {
		// Replace taskId in params with backend-side task ID.
		var paramsMap map[string]any
		if err := json.Unmarshal(forwardParams, &paramsMap); err == nil {
			paramsMap["taskId"] = backendTaskID
			if rewritten, err := json.Marshal(paramsMap); err == nil {
				forwardParams = rewritten
			}
		}
	}

	// Forward to backend listener.
	respBody, err := a.forwardToBackend(r.Context(), routeName, backend, rpcReq.Method, forwardParams, rpcReq.ID)
	if err != nil {
		return nil, &jsonRPCError{Code: -32603, Message: fmt.Sprintf("backend error: %s", err.Error())}
	}

	// Parse the backend response and rewrite the task ID.
	var backendResp jsonRPCResponse
	if err = json.Unmarshal(respBody, &backendResp); err != nil {
		return nil, &jsonRPCError{Code: -32603, Message: "failed to parse backend response"}
	}
	if backendResp.Error != nil {
		return nil, backendResp.Error
	}

	// Rewrite the task ID in the result to encode our gateway-side task ID.
	result := backendResp.Result
	if len(result) > 0 {
		var resultMap map[string]any
		if err = json.Unmarshal(result, &resultMap); err == nil {
			if tid, ok := resultMap["id"].(string); ok && tid != "" {
				encoded, encErr := encodeTaskID(a.sessionCrypto, backendName, tid, routeName)
				if encErr == nil {
					resultMap["id"] = encoded
				}
			} else if tid, ok := resultMap["taskId"].(string); ok && tid != "" {
				encoded, encErr := encodeTaskID(a.sessionCrypto, backendName, tid, routeName)
				if encErr == nil {
					resultMap["taskId"] = encoded
				}
			}
			if rewritten, encErr := json.Marshal(resultMap); encErr == nil {
				result = rewritten
			}
		}
	}

	return result, nil
}

// handleTasksGet handles tasks/get requests.
func (a *a2aRequestContext) handleTasksGet(r *http.Request, rpcReq jsonRPCRequest) (json.RawMessage, *jsonRPCError) {
	var params tasksGetParams
	if len(rpcReq.Params) > 0 {
		if err := json.Unmarshal(rpcReq.Params, &params); err != nil {
			return nil, &jsonRPCError{Code: -32602, Message: "invalid params for tasks/get"}
		}
	}
	if params.ID == "" {
		return nil, &jsonRPCError{Code: -32602, Message: "missing task ID"}
	}

	routeName := r.Header.Get(internalapi.A2ARouteHeader)
	route := a.routes[routeName]
	if route == nil {
		return nil, &jsonRPCError{Code: -32603, Message: fmt.Sprintf("no route found: %s", routeName)}
	}

	backendName, backendTaskID, _, err := decodeTaskID(a.sessionCrypto, params.ID)
	if err != nil {
		return nil, &jsonRPCError{Code: -32602, Message: "invalid task ID"}
	}

	backend, ok := route.backends[backendName]
	if !ok {
		return nil, &jsonRPCError{Code: -32603, Message: fmt.Sprintf("backend not found: %s", backendName)}
	}

	// Forward with the backend task ID.
	forwardParams, err := json.Marshal(map[string]string{"id": backendTaskID})
	if err != nil {
		return nil, &jsonRPCError{Code: -32603, Message: "failed to marshal params"}
	}

	respBody, err := a.forwardToBackend(r.Context(), routeName, backend, "tasks/get", forwardParams, rpcReq.ID)
	if err != nil {
		return nil, &jsonRPCError{Code: -32603, Message: fmt.Sprintf("backend error: %s", err.Error())}
	}

	var backendResp jsonRPCResponse
	if err = json.Unmarshal(respBody, &backendResp); err != nil {
		return nil, &jsonRPCError{Code: -32603, Message: "failed to parse backend response"}
	}
	if backendResp.Error != nil {
		return nil, backendResp.Error
	}

	return backendResp.Result, nil
}

// handleGetExtendedCard handles agent/getAuthenticatedExtendedCard requests (stub).
func (a *a2aRequestContext) handleGetExtendedCard(_ *http.Request, _ jsonRPCRequest) (json.RawMessage, *jsonRPCError) {
	// Phase 1 stub: return the same card as the public card.
	return json.RawMessage(`{"message":"authenticated extended card not yet supported"}`), nil
}

// forwardToBackend sends a JSON-RPC request to the backend listener.
func (a *a2aRequestContext) forwardToBackend(ctx context.Context, routeName string, backend filterapi.A2ABackend, method string, params json.RawMessage, id any) ([]byte, error) {
	reqID := uuid.NewString()
	rpcReq := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}
	if rpcReq.ID == nil {
		rpcReq.ID = reqID
	}

	encoded, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.backendListenerAddr, bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(internalapi.A2ABackendHeader, backend.Name)
	req.Header.Set(internalapi.A2ARouteHeader, routeName)
	req.Header.Set(internalapi.A2AMetadataHeaderMethod, method)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to backend: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read backend response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("backend returned status %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// writeJSONResponse writes a JSON response to the http.ResponseWriter.
func writeJSONResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONRPCError writes a JSON-RPC error response.
func writeJSONRPCError(w http.ResponseWriter, id any, code int, message string) {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonRPCError{Code: code, Message: message},
	}
	writeJSONResponse(w, http.StatusOK, resp)
}
