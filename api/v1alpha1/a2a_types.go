// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package v1alpha1

// AgentCard represents the A2A v0.3.0 Agent Card data model describing an agent's capabilities.
//
// +k8s:deepcopy-gen=false
type AgentCard struct {
	// Name is the human-readable name of the agent.
	Name string `json:"name"`
	// Description is a human-readable description of the agent.
	Description string `json:"description,omitempty"`
	// Version is the agent version string.
	Version string `json:"version,omitempty"`
	// ProtocolVersion is the A2A protocol version the agent implements.
	ProtocolVersion string `json:"protocolVersion,omitempty"`
	// URL is the endpoint URL for this agent.
	URL string `json:"url,omitempty"`
	// Capabilities describes what the agent supports.
	Capabilities AgentCapabilities `json:"capabilities,omitempty"`
	// Skills is the list of skills the agent provides.
	Skills []AgentSkill `json:"skills,omitempty"`
	// DefaultInputModes is the list of supported input content types.
	DefaultInputModes []string `json:"defaultInputModes,omitempty"`
	// DefaultOutputModes is the list of supported output content types.
	DefaultOutputModes []string `json:"defaultOutputModes,omitempty"`
	// SecuritySchemes contains OpenAPI-compatible security scheme definitions keyed by scheme name.
	SecuritySchemes map[string]any `json:"securitySchemes,omitempty"`
	// Provider contains information about the agent's provider.
	Provider *AgentProvider `json:"provider,omitempty"`
	// SupportsAuthenticatedExtendedCard indicates whether the agent exposes
	// an authenticated extended agent card.
	SupportsAuthenticatedExtendedCard bool `json:"supportsAuthenticatedExtendedCard,omitempty"`
}

// AgentCapabilities describes the optional capabilities an agent supports.
type AgentCapabilities struct {
	// Streaming indicates whether the agent supports streaming responses.
	Streaming bool `json:"streaming,omitempty"`
	// PushNotifications indicates whether the agent supports push notification callbacks.
	PushNotifications bool `json:"pushNotifications,omitempty"`
	// StateTransitionHistory indicates whether the agent supports state transition history.
	StateTransitionHistory bool `json:"stateTransitionHistory,omitempty"`
}

// AgentSkill describes a single skill provided by the agent.
type AgentSkill struct {
	// ID is the unique identifier of the skill within the agent.
	ID string `json:"id"`
	// Name is the human-readable name of the skill.
	Name string `json:"name,omitempty"`
	// Description is a human-readable description of the skill.
	Description string `json:"description,omitempty"`
	// InputModes lists the content types the skill accepts as input.
	InputModes []string `json:"inputModes,omitempty"`
	// OutputModes lists the content types the skill produces as output.
	OutputModes []string `json:"outputModes,omitempty"`
	// Tags are labels used for discovery and filtering.
	Tags []string `json:"tags,omitempty"`
	// Examples lists example prompts or invocations for the skill.
	Examples []string `json:"examples,omitempty"`
}

// AgentProvider contains information about the agent provider organization.
type AgentProvider struct {
	// Organization is the name of the provider organization.
	Organization string `json:"organization,omitempty"`
	// URL is the provider's website or documentation URL.
	URL string `json:"url,omitempty"`
}
