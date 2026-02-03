// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/tests/internal/e2elib"
	"github.com/envoyproxy/ai-gateway/tests/internal/testmcp"
)

// mcpHeaderForwardingTransport implements [http.RoundTripper] to inject custom headers
// that should be forwarded to the backend MCP server.
type mcpHeaderForwardingTransport struct {
	headers map[string]string
	base    http.RoundTripper
}

// RoundTrip implements [http.RoundTripper.RoundTrip].
func (t *mcpHeaderForwardingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

func TestMCPRouteHeaderForwarding(t *testing.T) {
	const manifest = "testdata/mcp_route_header_forwarding.yaml"
	require.NoError(t, e2elib.KubectlApplyManifest(t.Context(), manifest))
	t.Cleanup(func() {
		_ = e2elib.KubectlDeleteManifest(context.Background(), manifest)
	})

	const egSelector = "gateway.envoyproxy.io/owning-gateway-name=mcp-gateway-header-forwarding"
	e2elib.RequireWaitForGatewayPodReady(t, egSelector)

	fwd := e2elib.RequireNewHTTPPortForwarder(t, e2elib.EnvoyGatewayNamespace, egSelector, e2elib.EnvoyGatewayDefaultServicePort)
	defer fwd.Kill()

	client := mcp.NewClient(&mcp.Implementation{Name: "demo-http-client", Version: "0.1.0"}, nil)

	t.Run("headers are forwarded to backend", func(t *testing.T) {
		customHeaders := map[string]string{
			"X-User-ID":    "user-123",
			"X-Tenant-ID":  "tenant-456",
			"X-Request-ID": "req-789",
		}

		httpClient := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &mcpHeaderForwardingTransport{
				headers: customHeaders,
			},
		}

		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
		t.Cleanup(cancel)

		var sess *mcp.ClientSession
		require.Eventually(t, func() bool {
			var err error
			sess, err = client.Connect(
				ctx,
				&mcp.StreamableClientTransport{
					Endpoint:   fmt.Sprintf("%s/mcp", fwd.Address()),
					HTTPClient: httpClient,
				}, nil)
			if err != nil {
				t.Logf("failed to connect to MCP server: %v", err)
				return false
			}
			return true
		}, 30*time.Second, 100*time.Millisecond, "failed to connect to MCP server")
		t.Cleanup(func() {
			if sess != nil {
				_ = sess.Close()
			}
		})

		// List tools to verify the session is working
		tools, err := sess.ListTools(ctx, &mcp.ListToolsParams{})
		require.NoError(t, err)
		require.NotEmpty(t, tools.Tools)

		// Find the get_header tool
		var getHeaderTool string
		for _, tool := range tools.Tools {
			if tool.Name == "mcp-backend-header-forwarding__"+testmcp.ToolGetHeaderName {
				getHeaderTool = tool.Name
				break
			}
		}
		require.NotEmpty(t, getHeaderTool, "get_header tool not found")

		// Verify each forwarded header
		for headerName, expectedValue := range customHeaders {
			res, err := sess.CallTool(ctx, &mcp.CallToolParams{
				Name:      getHeaderTool,
				Arguments: testmcp.ToolGetHeaderArgs{HeaderName: headerName},
			})
			require.NoError(t, err)
			require.False(t, res.IsError)
			require.Len(t, res.Content, 1)
			txt, ok := res.Content[0].(*mcp.TextContent)
			require.True(t, ok)
			require.Equal(t, expectedValue, txt.Text, "header %s not forwarded correctly", headerName)
		}
	})

	t.Run("non-forwarded headers are not passed", func(t *testing.T) {
		customHeaders := map[string]string{
			"X-User-ID":       "user-123",        // This will be forwarded
			"X-Non-Forwarded": "should-not-pass", // This should not be forwarded
		}

		httpClient := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &mcpHeaderForwardingTransport{
				headers: customHeaders,
			},
		}

		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
		t.Cleanup(cancel)

		var sess *mcp.ClientSession
		require.Eventually(t, func() bool {
			var err error
			sess, err = client.Connect(
				ctx,
				&mcp.StreamableClientTransport{
					Endpoint:   fmt.Sprintf("%s/mcp", fwd.Address()),
					HTTPClient: httpClient,
				}, nil)
			if err != nil {
				t.Logf("failed to connect to MCP server: %v", err)
				return false
			}
			return true
		}, 30*time.Second, 100*time.Millisecond, "failed to connect to MCP server")
		t.Cleanup(func() {
			if sess != nil {
				_ = sess.Close()
			}
		})

		// Find the get_header tool
		tools, err := sess.ListTools(ctx, &mcp.ListToolsParams{})
		require.NoError(t, err)
		var getHeaderTool string
		for _, tool := range tools.Tools {
			if tool.Name == "mcp-backend-header-forwarding__"+testmcp.ToolGetHeaderName {
				getHeaderTool = tool.Name
				break
			}
		}
		require.NotEmpty(t, getHeaderTool, "get_header tool not found")

		// Verify forwarded header is present
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{
			Name:      getHeaderTool,
			Arguments: testmcp.ToolGetHeaderArgs{HeaderName: "X-User-ID"},
		})
		require.NoError(t, err)
		require.False(t, res.IsError)
		require.Len(t, res.Content, 1)
		txt, ok := res.Content[0].(*mcp.TextContent)
		require.True(t, ok)
		require.Equal(t, "user-123", txt.Text)

		// Verify non-forwarded header is not present
		res, err = sess.CallTool(ctx, &mcp.CallToolParams{
			Name:      getHeaderTool,
			Arguments: testmcp.ToolGetHeaderArgs{HeaderName: "X-Non-Forwarded"},
		})
		require.NoError(t, err)
		require.False(t, res.IsError)
		require.Len(t, res.Content, 1)
		txt, ok = res.Content[0].(*mcp.TextContent)
		require.True(t, ok)
		require.Empty(t, txt.Text, "non-forwarded header should not be present")
	})
}
