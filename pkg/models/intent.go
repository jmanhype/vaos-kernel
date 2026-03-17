package models

import "time"

// IntentRequest represents a single scoped request that can be turned into a JWT.
type IntentRequest struct {
	AgentID     string            `json:"agent_id"`
	Action      string            `json:"action"`
	Resource    string            `json:"resource"`
	Parameters  map[string]string `json:"parameters,omitempty"`
	Description string            `json:"description,omitempty"`
	RequestedAt time.Time         `json:"requested_at"`
}

