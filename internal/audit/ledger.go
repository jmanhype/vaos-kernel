package audit

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"

	"vaos-kernel/pkg/models"
)

// Ledger stores immutable-style audit entries and emits structured log output.
type Ledger struct {
	mu      sync.RWMutex
	entries []models.AuditEntry
	logger  *log.Logger
	clock   func() time.Time
}

// NewLedger creates a ledger backed by an optional writer.
func NewLedger(writer io.Writer) *Ledger {
	if writer == nil {
		writer = io.Discard
	}
	return &Ledger{
		logger: log.New(writer, "", 0),
		clock:  time.Now().UTC,
	}
}

// Record appends an audit entry after deriving a cryptographic attestation.
func (l *Ledger) Record(entry models.AuditEntry) (models.AuditEntry, error) {
	if entry.AgentID == "" {
		return models.AuditEntry{}, errors.New("record audit entry: agent id is required")
	}
	if entry.Component == "" {
		return models.AuditEntry{}, errors.New("record audit entry: component is required")
	}
	if entry.Action == "" {
		return models.AuditEntry{}, errors.New("record audit entry: action is required")
	}

	if entry.ID == "" {
		entry.ID = entry.Component + "-" + l.clock().Format("20060102150405.000000000")
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = l.clock()
	}
	attestation, err := attest(entry)
	if err != nil {
		return models.AuditEntry{}, err
	}
	entry.Attestation = attestation

	l.mu.Lock()
	l.entries = append(l.entries, entry)
	l.mu.Unlock()

	payload, _ := json.Marshal(entry)
	l.logger.Print(string(payload))
	return entry, nil
}

// Entries returns a copy of all ledger entries.
func (l *Ledger) Entries() []models.AuditEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]models.AuditEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

func attest(entry models.AuditEntry) (string, error) {
	payload, err := json.Marshal(struct {
		ID                string            `json:"id"`
		Timestamp         time.Time         `json:"timestamp"`
		AgentID           string            `json:"agent_id"`
		IntentFingerprint string            `json:"intent_fingerprint"`
		Action            string            `json:"action"`
		Component         string            `json:"component"`
		Status            string            `json:"status"`
		Details           map[string]string `json:"details,omitempty"`
	}{
		ID:                entry.ID,
		Timestamp:         entry.Timestamp,
		AgentID:           entry.AgentID,
		IntentFingerprint: entry.IntentFingerprint,
		Action:            entry.Action,
		Component:         entry.Component,
		Status:            entry.Status,
		Details:           entry.Details,
	})
	if err != nil {
		return "", err
	}
	sum := blake2b.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

