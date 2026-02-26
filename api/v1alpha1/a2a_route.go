// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// A2ARoute defines how to route A2A (Agent-to-Agent) requests to backend A2A agents.
//
// This serves as a way to define a "unified" A2A API for a Gateway which allows downstream
// clients to use a single endpoint to interact with multiple A2A backend agents.
//
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.conditions[-1:].type`
type A2ARoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Spec defines the details of the A2ARoute.
	Spec A2ARouteSpec `json:"spec,omitempty"`
	// Status defines the status details of the A2ARoute.
	Status A2ARouteStatus `json:"status,omitempty"`
}

// A2ARouteList contains a list of A2ARoute.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
type A2ARouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []A2ARoute `json:"items"`
}

// A2ARouteSpec details the A2ARoute configuration.
type A2ARouteSpec struct {
	// ParentRefs are the names of the Gateway resources this A2ARoute is being attached to.
	// Cross namespace references are not supported. Currently, each reference's Kind must be Gateway.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:rule="self.all(match, match.kind == 'Gateway')", message="only Gateway is supported"
	ParentRefs []gwapiv1.ParentReference `json:"parentRefs"`

	// Path is the HTTP endpoint path that serves A2A requests.
	// If not specified, the default is "/a2a".
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=/a2a
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Path *string `json:"path,omitempty"`

	// BackendRefs is a list of backend references to the A2A agents.
	// These A2A agents will be aggregated and exposed as a single A2A endpoint to the clients.
	// All names must be unique within this list to avoid potential skill name collisions.
	// Cross-namespace references are not supported.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:XValidation:rule="self.all(i, self.exists_one(j, j.name == i.name))", message="all backendRefs names must be unique"
	BackendRefs []A2ARouteBackendRef `json:"backendRefs"`

	// SecurityPolicy defines the security policy for this A2ARoute.
	//
	// +kubebuilder:validation:Optional
	// +optional
	SecurityPolicy *A2ARouteSecurityPolicy `json:"securityPolicy,omitempty"`

	// AgentCard defines the gateway-level agent card metadata for this A2ARoute.
	// When specified, the gateway will serve a merged agent card at /.well-known/agent-card.json
	// aggregating skills from all configured backends.
	//
	// +kubebuilder:validation:Optional
	// +optional
	AgentCard *A2AAgentCardSpec `json:"agentCard,omitempty"`
}

// A2ARouteBackendRef wraps a BackendObjectReference to reference an A2A agent backend.
type A2ARouteBackendRef struct {
	gwapiv1.BackendObjectReference `json:",inline"`

	// Path is the HTTP endpoint path of the backend A2A agent.
	// If not specified, the default is "/a2a".
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=/a2a
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Path *string `json:"path,omitempty"`

	// SkillSelector filters the skills exposed by this A2A agent.
	// If not specified, all skills from the agent are exposed.
	//
	// +kubebuilder:validation:Optional
	// +optional
	SkillSelector *A2ASkillFilter `json:"skillSelector,omitempty"`

	// SecurityPolicy is the security policy to apply to this A2A backend.
	//
	// +kubebuilder:validation:Optional
	// +optional
	SecurityPolicy *A2ABackendSecurityPolicy `json:"securityPolicy,omitempty"`
}

// A2ASkillFilter filters skills using include patterns with exact matches or regular expressions.
//
// +kubebuilder:validation:XValidation:rule="(has(self.include) && !has(self.includeRegex)) || (!has(self.include) && has(self.includeRegex))", message="exactly one of include or includeRegex must be specified"
type A2ASkillFilter struct {
	// Include is a list of skill IDs to include. Only the specified skills will be available.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=32
	// +optional
	Include []string `json:"include,omitempty"`

	// IncludeRegex is a list of RE2-compatible regular expressions that, when matched, include the skill.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=32
	// +optional
	IncludeRegex []string `json:"includeRegex,omitempty"`
}

// A2ABackendSecurityPolicy defines the security policy for an A2A backend.
type A2ABackendSecurityPolicy struct {
	// APIKey is a mechanism to access a backend. The API key will be injected into the request headers.
	// +optional
	APIKey *A2ABackendAPIKey `json:"apiKey,omitempty"`
}

// A2ABackendAPIKey defines the configuration for API Key Authentication to a backend.
// When both `header` and `queryParam` are unspecified, the API key will be injected into the "Authorization" header by default.
//
// +kubebuilder:validation:XValidation:rule="(has(self.secretRef) && !has(self.inline)) || (!has(self.secretRef) && has(self.inline))", message="exactly one of secretRef or inline must be set"
// +kubebuilder:validation:XValidation:rule="!(has(self.header) && has(self.queryParam))", message="only one of header or queryParam can be set"
type A2ABackendAPIKey struct {
	// SecretRef is the Kubernetes secret which contains the API key.
	// The key of the secret should be "apiKey".
	// +optional
	SecretRef *gwapiv1.SecretObjectReference `json:"secretRef,omitempty"`

	// Inline contains the API key as an inline string.
	//
	// +optional
	Inline *string `json:"inline,omitempty"`

	// Header is the HTTP header to inject the API key into. If not specified,
	// defaults to "Authorization".
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +optional
	Header *string `json:"header,omitempty"`

	// QueryParam is the HTTP query parameter to inject the API key into.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +optional
	QueryParam *string `json:"queryParam,omitempty"`
}

// A2ARouteSecurityPolicy defines the security policy for an A2ARoute.
type A2ARouteSecurityPolicy struct {
	// APIKeyAuth defines the configuration for the API Key Authentication.
	//
	// +optional
	APIKeyAuth *A2ARouteAPIKeyAuth `json:"apiKeyAuth,omitempty"`
}

// A2ARouteAPIKeyAuth defines the configuration for API Key Authentication on the route.
type A2ARouteAPIKeyAuth struct {
	// SecretRef is the Kubernetes secret which contains the API key.
	// The key of the secret should be "apiKey".
	// +optional
	SecretRef *gwapiv1.SecretObjectReference `json:"secretRef,omitempty"`
}

// A2AAgentCardSpec defines the gateway-level agent card metadata for the A2ARoute.
type A2AAgentCardSpec struct {
	// Name is the human-readable name of the gateway agent.
	//
	// +kubebuilder:validation:Optional
	// +optional
	Name string `json:"name,omitempty"`

	// Description is a human-readable description of the gateway agent.
	//
	// +kubebuilder:validation:Optional
	// +optional
	Description string `json:"description,omitempty"`

	// Version is the gateway agent version string.
	//
	// +kubebuilder:validation:Optional
	// +optional
	Version string `json:"version,omitempty"`

	// ProtocolVersion is the A2A protocol version the gateway agent implements.
	//
	// +kubebuilder:validation:Optional
	// +optional
	ProtocolVersion string `json:"protocolVersion,omitempty"`

	// Provider contains information about the agent provider.
	//
	// +kubebuilder:validation:Optional
	// +optional
	Provider *A2AProviderSpec `json:"provider,omitempty"`

	// DefaultInputModes is the list of supported input content types for the gateway agent.
	//
	// +kubebuilder:validation:Optional
	// +optional
	DefaultInputModes []string `json:"defaultInputModes,omitempty"`

	// DefaultOutputModes is the list of supported output content types for the gateway agent.
	//
	// +kubebuilder:validation:Optional
	// +optional
	DefaultOutputModes []string `json:"defaultOutputModes,omitempty"`
}

// A2AProviderSpec contains information about the agent provider organization.
type A2AProviderSpec struct {
	// Organization is the name of the provider organization.
	Organization string `json:"organization,omitempty"`
	// URL is the provider's website or documentation URL.
	URL string `json:"url,omitempty"`
}

// A2ARouteStatus defines the observed state of A2ARoute.
type A2ARouteStatus struct {
	// Conditions describe the current conditions of the A2ARoute.
	//
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}
