// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package a2aproxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	aigv1a1 "github.com/envoyproxy/ai-gateway/api/v1alpha1"
	"github.com/envoyproxy/ai-gateway/internal/filterapi"
	"github.com/envoyproxy/ai-gateway/internal/json"
)

const (
	agentCardPath       = "/.well-known/agent-card.json"
	agentCardLegacyPath = "/.well-known/agent.json"
)

// fetchAgentCard retrieves the agent card from a backend at its well-known URL.
func fetchAgentCard(ctx context.Context, client *http.Client, backendURL string) (*aigv1a1.AgentCard, error) {
	url := strings.TrimRight(backendURL, "/") + agentCardPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create agent card request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch agent card from %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent card fetch returned status %d from %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read agent card body: %w", err)
	}
	var card aigv1a1.AgentCard
	if err = json.Unmarshal(body, &card); err != nil {
		return nil, fmt.Errorf("failed to unmarshal agent card: %w", err)
	}
	return &card, nil
}

// aggregateAgentCards creates a single aggregated agent card from multiple backend cards.
// Skill IDs are prefixed with the backend name to avoid collisions.
func aggregateAgentCards(
	backends []filterapi.A2ABackend,
	backendCards map[string]*aigv1a1.AgentCard,
	gatewayURL string,
	spec *filterapi.A2AAgentCardSpec,
	skillSelectors map[string]*skillSelector,
) *aigv1a1.AgentCard {
	result := &aigv1a1.AgentCard{
		URL: gatewayURL,
		Capabilities: aigv1a1.AgentCapabilities{
			Streaming: false,
		},
	}

	if spec != nil {
		result.Name = spec.Name
		result.Description = spec.Description
		result.Version = spec.Version
		result.ProtocolVersion = spec.ProtocolVersion
		result.DefaultInputModes = spec.DefaultInputModes
		result.DefaultOutputModes = spec.DefaultOutputModes
	}

	for _, backend := range backends {
		card, ok := backendCards[backend.Name]
		if !ok {
			continue
		}

		// Merge capabilities: if any backend supports streaming, the gateway does too.
		if card.Capabilities.Streaming {
			result.Capabilities.Streaming = true
		}

		sel := skillSelectors[backend.Name]

		for i := range card.Skills {
			skill := &card.Skills[i]
			// Apply skill selector filtering.
			if sel != nil && !sel.allows(skill.ID) {
				continue
			}
			// Prefix the skill ID with backend name to avoid collisions.
			prefixedSkill := aigv1a1.AgentSkill{
				ID:          backend.Name + "/" + skill.ID,
				Name:        skill.Name,
				Description: skill.Description,
				InputModes:  skill.InputModes,
				OutputModes: skill.OutputModes,
				Tags:        skill.Tags,
				Examples:    skill.Examples,
			}
			result.Skills = append(result.Skills, prefixedSkill)
		}
	}

	return result
}
