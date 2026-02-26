// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// Package a2aproxy provides the A2A (Agent-to-Agent) proxy implementation.
// It follows the same architectural pattern as the mcpproxy package.
package a2aproxy

import (
	"log/slog"
	"net/http"

	"github.com/envoyproxy/ai-gateway/internal/mcpproxy"
	"github.com/envoyproxy/ai-gateway/internal/metrics"
)

// NewA2AProxy creates a new A2AProxy instance and returns the ProxyConfig and HTTP mux.
func NewA2AProxy(
	l *slog.Logger,
	a2aMetrics metrics.A2AMetrics,
	sessionCrypto mcpproxy.SessionCrypto,
) (*ProxyConfig, *http.ServeMux) {
	cfg := &ProxyConfig{
		a2aProxyConfig: &a2aProxyConfig{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		reqCtx := &a2aRequestContext{
			ProxyConfig:   cfg,
			metrics:       a2aMetrics.WithRequestAttributes(r),
			sessionCrypto: sessionCrypto,
			logger:        l,
			client:        &http.Client{},
		}
		reqCtx.serveHTTP(w, r)
	})
	return cfg, mux
}
