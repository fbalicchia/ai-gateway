// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package a2aproxy

import (
	"context"
	"fmt"
	"regexp"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
)

// ProxyConfig holds the main A2A proxy configuration.
// This implements [filterapi.ConfigReceiver] to get up-to-date configuration.
type ProxyConfig struct {
	*a2aProxyConfig
}

type a2aProxyConfig struct {
	backendListenerAddr string
	routes              map[filterapi.A2ARouteName]*a2aProxyConfigRoute
}

type a2aProxyConfigRoute struct {
	backends       map[filterapi.A2ABackendName]filterapi.A2ABackend
	skillSelectors map[filterapi.A2ABackendName]*skillSelector
	agentCard      *filterapi.A2AAgentCardSpec
}

// skillSelector filters skills using include patterns with exact matches or regular expressions.
type skillSelector struct {
	include        map[string]struct{}
	includeRegexps []*regexp.Regexp
}

// allows returns true if the given skill ID is allowed by this selector.
func (s *skillSelector) allows(skillID string) bool {
	if len(s.include) > 0 {
		_, ok := s.include[skillID]
		return ok
	}
	if len(s.includeRegexps) > 0 {
		for _, re := range s.includeRegexps {
			if re.MatchString(skillID) {
				return true
			}
		}
		return false
	}
	// No filters: allow all.
	return true
}

// LoadConfig implements [filterapi.ConfigReceiver.LoadConfig].
func (p *ProxyConfig) LoadConfig(_ context.Context, config *filterapi.Config) error {
	if config.A2AConfig == nil {
		return nil
	}
	newConfig := &a2aProxyConfig{
		backendListenerAddr: config.A2AConfig.BackendListenerAddr,
		routes:              make(map[filterapi.A2ARouteName]*a2aProxyConfigRoute, len(config.A2AConfig.Routes)),
	}

	for _, route := range config.A2AConfig.Routes {
		r := &a2aProxyConfigRoute{
			backends:       make(map[filterapi.A2ABackendName]filterapi.A2ABackend, len(route.Backends)),
			skillSelectors: make(map[filterapi.A2ABackendName]*skillSelector, len(route.Backends)),
			agentCard:      route.AgentCard,
		}
		for _, backend := range route.Backends {
			r.backends[backend.Name] = backend
			if s := backend.SkillSelector; s != nil {
				ts := &skillSelector{
					include: make(map[string]struct{}),
				}
				for _, skill := range s.Include {
					ts.include[skill] = struct{}{}
				}
				for _, expr := range s.IncludeRegex {
					re, err := regexp.Compile(expr)
					if err != nil {
						return fmt.Errorf("failed to compile includeRegex %q for backend %q in route %q: %w", expr, backend.Name, route.Name, err)
					}
					ts.includeRegexps = append(ts.includeRegexps, re)
				}
				r.skillSelectors[backend.Name] = ts
			}
		}
		newConfig.routes[route.Name] = r
	}

	p.a2aProxyConfig = newConfig
	return nil
}
