// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package a2aproxy

import (
	"fmt"
	"strings"

	"github.com/envoyproxy/ai-gateway/internal/mcpproxy"
)

// TaskID format: "backendName:backendTaskID:routeName"
const taskIDSeparator = ":"

// encodeTaskID encrypts a composite task ID that encodes the backend name, upstream task ID, and route name.
func encodeTaskID(crypto mcpproxy.SessionCrypto, backendName, backendTaskID, routeName string) (string, error) {
	plain := strings.Join([]string{backendName, backendTaskID, routeName}, taskIDSeparator)
	return crypto.Encrypt(plain)
}

// decodeTaskID decrypts an encoded task ID and returns its components.
func decodeTaskID(crypto mcpproxy.SessionCrypto, taskID string) (backendName, backendTaskID, routeName string, err error) {
	plain, err := crypto.Decrypt(taskID)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to decrypt task ID: %w", err)
	}
	parts := strings.SplitN(plain, taskIDSeparator, 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid task ID format: expected 3 parts, got %d", len(parts))
	}
	return parts[0], parts[1], parts[2], nil
}
