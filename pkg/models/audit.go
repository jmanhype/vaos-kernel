package models

import "time"

// AuditEntry stores ALCOA+ relevant evidence for a single operation.
type AuditEntry struct {
	ID                string            `json:"id"`
	Timestamp         time.Time         `json:"timestamp"`
	AgentID           string            `json:"agent_id"`
	IntentFingerprint string            `json:"intent_fingerprint"`
	Action            string            `json:"action"`
	Component         string            `json:"component"`
	Status            string            `json:"status"`
	Details           map[string]string `json:"details,omitempty"`
	Attestation       string            `json:"attestation"`
}

