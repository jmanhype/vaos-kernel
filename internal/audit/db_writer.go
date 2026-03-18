package audit

import (
	"encoding/json"
	"log"

	"vaos-kernel/pkg/db"
)

// DBWriter implements io.Writer and persists audit entries to Postgres.
// It wraps the DB's LogAction method so the Ledger writes to both
// stdout (for debugging) and the database (for ALCOA+ compliance).
type DBWriter struct {
	db *db.DB
}

// NewDBWriter creates a writer that persists audit entries to Postgres.
func NewDBWriter(database *db.DB) *DBWriter {
	return &DBWriter{db: database}
}

// Write parses the JSON audit entry and persists it to the alcoa_actions table.
func (w *DBWriter) Write(p []byte) (n int, err error) {
	// Parse the audit entry
	var entry struct {
		ID                string            `json:"id"`
		AgentID           string            `json:"agent_id"`
		Action            string            `json:"action"`
		Component         string            `json:"component"`
		Status            string            `json:"status"`
		Attestation       string            `json:"attestation"`
		IntentFingerprint string            `json:"intent_fingerprint"`
		Details           map[string]string `json:"details,omitempty"`
	}

	if err := json.Unmarshal(p, &entry); err != nil {
		log.Printf("[audit/db] failed to parse entry: %v", err)
		return len(p), nil // don't block the ledger
	}

	// Write to alcoa_actions table
	resourcesJSON, _ := json.Marshal(entry.Details)
	success := entry.Status == "success" || entry.Status == "completed"

	if err := w.db.LogAction(
		entry.ID,
		entry.AgentID,
		entry.Action,
		entry.Attestation,
		success,
		"",  // error message
		0,   // duration
		resourcesJSON,
	); err != nil {
		log.Printf("[audit/db] failed to persist: %v", err)
	}

	return len(p), nil
}
