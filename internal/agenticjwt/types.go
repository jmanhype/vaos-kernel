// Package agenticjwt implements the P0 compatibility profile of
// draft-goswami-agentic-jwt-01. It is intentionally independent from the
// legacy VAOS action-token issuer so protocol compatibility can be tested and
// reviewed without changing the existing enforcement path.
package agenticjwt

import (
	"crypto/ed25519"
	"time"
)

// Tool is the shallow checksum representation of an agent tool.
type Tool struct {
	Name        string         `json:"name"`
	Signature   string         `json:"signature"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}

// AgentSpec is the draft agent specification used to derive identity.
type AgentSpec struct {
	AgentID       string         `json:"agent_id"`
	Prompt        string         `json:"prompt"`
	Tools         []Tool         `json:"tools"`
	Configuration map[string]any `json:"configuration"`
}

// AgentRegistration is an immutable version of a registered agent identity.
type AgentRegistration struct {
	AppID            string
	AgentID          string
	Spec             AgentSpec
	RegistrationID   string
	Checksum         string
	PublicKey        ed25519.PublicKey
	RegisteredAt     time.Time
	Version          int
	RevokedAt        time.Time
	RevocationReason string
}

// WorkflowStep is one ordered step in a registered workflow.
type WorkflowStep struct {
	StepID           string `json:"step_id,omitempty"`
	Required         bool   `json:"required,omitempty"`
	RequiresApproval bool   `json:"requires_approval,omitempty"`
	ApprovalGate     bool   `json:"approval_gate,omitempty"`
	AgentID          string `json:"agent_id,omitempty"`
}

// WorkflowDefinition is the server-side ordered workflow profile used to
// validate workflow-bound token requests.
type WorkflowDefinition struct {
	WorkflowID string         `json:"workflow_id"`
	Steps      []WorkflowStep `json:"steps"`
}

// AgentRegistrationRequest is the P0 HTTP registration body.
type AgentRegistrationRequest struct {
	AgentSpec AgentSpec `json:"agent_components"`
	PublicKey string    `json:"public_key"`
}

// AgentRegistrationResponse returns only non-secret registration metadata.
type AgentRegistrationResponse struct {
	AgentID        string `json:"agent_id"`
	RegistrationID string `json:"registration_id"`
	Checksum       string `json:"checksum"`
}

// DelegationContext carries the P0 delegation trace.
type DelegationContext struct {
	Chain          []string `json:"chain,omitempty"`
	CompletedSteps []string `json:"completed_steps,omitempty"`
}

// Audience accepts either a JSON string or an array of strings.
type Audience []string

// TokenRequest is the draft agent_checksum token request.
type TokenRequest struct {
	GrantType         string             `json:"grant_type"`
	AgentID           string             `json:"agent_id"`
	ComputedChecksum  string             `json:"computed_checksum"`
	WorkflowID        string             `json:"workflow_id,omitempty"`
	WorkflowStep      string             `json:"workflow_step,omitempty"`
	WorkflowEnabled   bool               `json:"workflow_enabled,omitempty"`
	RequestedScopes   []string           `json:"requested_scopes"`
	Audience          Audience           `json:"audience"`
	DelegationContext *DelegationContext `json:"delegation_context,omitempty"`
}

// TokenResponse follows the OAuth-shaped successful response from section 4.4.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// Confirmation is the RFC 7800 cnf claim.
type Confirmation struct {
	JWK JWK `json:"jwk"`
}

// IntentClaims contains workflow and delegation bindings.
type IntentClaims struct {
	WorkflowID       string `json:"workflow_id,omitempty"`
	WorkflowStep     string `json:"workflow_step,omitempty"`
	ExecutedBy       string `json:"executed_by"`
	DelegationChain  string `json:"delegation_chain,omitempty"`
	StepSequenceHash string `json:"step_sequence_hash,omitempty"`
}

// AgentProof binds the token to the verified agent registration.
type AgentProof struct {
	AgentChecksum  string `json:"agent_checksum"`
	RegistrationID string `json:"registration_id"`
}
