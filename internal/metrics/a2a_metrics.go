// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package metrics

import (
	"context"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// nolint: godot
const (
	// A2A Request Duration is a histogram metric that records the duration of A2A requests.
	a2aRequestDuration = "a2a.request.duration"
	// A2A Method Count is a counter metric that records the total number of A2A methods invoked.
	a2aMethodCount = "a2a.method.count"
	// A2A Request Error is a counter metric that records total number of A2A request errors.
	a2aRequestError = "a2a.request.error"

	// a2aAttributeMethod is the A2A method attribute (e.g., "message/send").
	a2aAttributeMethod = "a2a.method"
	// a2aAttributeBackendProtocol is the backend protocol attribute.
	a2aAttributeBackendProtocol = "backend.protocol"
	// a2aAttributeErrType is the error type attribute.
	a2aAttributeErrType = "error.type"

	// a2aBackendProtocolValue is the constant protocol value for A2A backends.
	a2aBackendProtocolValue = "a2a"
)

// A2AMetrics holds metrics for A2A operations.
type A2AMetrics interface {
	// WithRequestAttributes returns a new A2AMetrics instance with default attributes extracted from the HTTP request.
	WithRequestAttributes(req *http.Request) A2AMetrics
	// RecordRequestDuration records the duration of a completed A2A request.
	RecordRequestDuration(ctx context.Context, startAt time.Time, method string)
	// RecordMethodCount records the count of method invocations.
	RecordMethodCount(ctx context.Context, method string)
	// RecordRequestError records a request error.
	RecordRequestError(ctx context.Context, method, errType string)
}

type a2a struct {
	requestDuration   metric.Float64Histogram
	methodCount       metric.Float64Counter
	requestError      metric.Float64Counter
	defaultAttributes []attribute.KeyValue
}

// NewA2A creates a new A2A metrics instance.
func NewA2A(meter metric.Meter) A2AMetrics {
	return &a2a{
		requestDuration: mustRegisterHistogram(meter,
			a2aRequestDuration,
			metric.WithDescription("Duration of A2A requests"),
			metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)),
		methodCount: mustRegisterCounter(
			meter,
			a2aMethodCount,
			metric.WithDescription("Total number of A2A methods invoked"),
		),
		requestError: mustRegisterCounter(
			meter,
			a2aRequestError,
			metric.WithDescription("Total number of A2A request errors"),
		),
	}
}

// WithRequestAttributes implements [A2AMetrics.WithRequestAttributes].
func (m *a2a) WithRequestAttributes(_ *http.Request) A2AMetrics {
	return &a2a{
		requestDuration:   m.requestDuration,
		methodCount:       m.methodCount,
		requestError:      m.requestError,
		defaultAttributes: m.defaultAttributes,
	}
}

// RecordRequestDuration implements [A2AMetrics.RecordRequestDuration].
func (m *a2a) RecordRequestDuration(ctx context.Context, startAt time.Time, method string) {
	duration := time.Since(startAt).Seconds()
	attrs := make([]attribute.KeyValue, 0, len(m.defaultAttributes)+2)
	attrs = append(attrs, m.defaultAttributes...)
	attrs = append(attrs,
		attribute.String(a2aAttributeMethod, method),
		attribute.String(a2aAttributeBackendProtocol, a2aBackendProtocolValue),
	)
	m.requestDuration.Record(ctx, duration, metric.WithAttributes(attrs...))
}

// RecordMethodCount implements [A2AMetrics.RecordMethodCount].
func (m *a2a) RecordMethodCount(ctx context.Context, method string) {
	attrs := make([]attribute.KeyValue, 0, len(m.defaultAttributes)+2)
	attrs = append(attrs, m.defaultAttributes...)
	attrs = append(attrs,
		attribute.String(a2aAttributeMethod, method),
		attribute.String(a2aAttributeBackendProtocol, a2aBackendProtocolValue),
	)
	m.methodCount.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordRequestError implements [A2AMetrics.RecordRequestError].
func (m *a2a) RecordRequestError(ctx context.Context, method, errType string) {
	attrs := make([]attribute.KeyValue, 0, len(m.defaultAttributes)+3)
	attrs = append(attrs, m.defaultAttributes...)
	attrs = append(attrs,
		attribute.String(a2aAttributeMethod, method),
		attribute.String(a2aAttributeErrType, errType),
		attribute.String(a2aAttributeBackendProtocol, a2aBackendProtocolValue),
	)
	m.requestError.Add(ctx, 1, metric.WithAttributes(attrs...))
}
