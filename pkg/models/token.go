package models

import "time"

// TokenRecord tracks the lifecycle of an issued JWT.
type TokenRecord struct {
	TokenID           string            `json:"token_id"`
	AgentID           string            `json:"agent_id"`
	IntentFingerprint string            `json:"intent_fingerprint"`
	IssuedAt          time.Time         `json:"issued_at"`
	ExpiresAt         time.Time         `json:"expires_at"`
	UsedAt            *time.Time        `json:"used_at,omitempty"`
	RevokedAt         *time.Time        `json:"revoked_at,omitempty"`
	Status            string            `json:"status"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

