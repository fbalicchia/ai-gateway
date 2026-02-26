// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package filterapi

// A2AConfig is the configuration for the A2A listener and routing.
type A2AConfig struct {
	// BackendListenerAddr is the address that speaks plain HTTP and can be used to
	// route to each A2A backend directly without interruption.
	//
	// The listener should only listen on the local interface, and equipped with
	// the HCM filter with the plain header-based routing for each backend based
	// on the [internalapi.A2ABackendHeader] header.
	BackendListenerAddr string `json:"backendListenerAddr"`

	// Routes is the list of routes that this listener can route to.
	Routes []A2ARoute `json:"routes,omitempty"`
}

// A2ARoute is the route configuration for routing to each A2A backend.
type A2ARoute struct {
	// Name is the fully qualified identifier of an A2ARoute.
	// This name is set in [internalapi.A2ARouteHeader] header to identify the route.
	Name A2ARouteName `json:"name"`

	// Backends is the list of backends that this route can route to.
	Backends []A2ABackend `json:"backends"`

	// AgentCard contains gateway-level agent card overrides for this route.
	AgentCard *A2AAgentCardSpec `json:"agentCard,omitempty"`
}

// A2ABackend is the A2A backend configuration.
type A2ABackend struct {
	// Name is the fully qualified identifier of an A2A backend.
	// This name is set in [internalapi.A2ABackendHeader] header to route the request to the specific backend.
	Name A2ABackendName `json:"name"`

	// SkillSelector filters the skills exposed by this backend. If not set, all skills are exposed.
	SkillSelector *A2ASkillSelector `json:"skillSelector,omitempty"`

	// URL is the base URL used for fetching the agent card from this backend.
	URL string `json:"url,omitempty"`
}

// A2ABackendName is the name of the A2A backend.
type A2ABackendName = string

// A2ARouteName is the name of the A2A route.
type A2ARouteName = string

// A2ASkillSelector filters skills using include patterns with exact matches or regular expressions.
type A2ASkillSelector struct {
	// Include is a list of skill IDs to include. Only the specified skills will be available.
	Include []string `json:"include,omitempty"`

	// IncludeRegex is a list of RE2-compatible regular expressions that, when matched, include the skill.
	IncludeRegex []string `json:"includeRegex,omitempty"`
}

// A2AAgentCardSpec defines gateway-level agent card overrides.
type A2AAgentCardSpec struct {
	// Name is the human-readable name of the gateway agent.
	Name string `json:"name,omitempty"`
	// Description is a human-readable description of the gateway agent.
	Description string `json:"description,omitempty"`
	// Version is the gateway agent version string.
	Version string `json:"version,omitempty"`
	// ProtocolVersion is the A2A protocol version.
	ProtocolVersion string `json:"protocolVersion,omitempty"`
	// DefaultInputModes is the list of supported input content types.
	DefaultInputModes []string `json:"defaultInputModes,omitempty"`
	// DefaultOutputModes is the list of supported output content types.
	DefaultOutputModes []string `json:"defaultOutputModes,omitempty"`
}
