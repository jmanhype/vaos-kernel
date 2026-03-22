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

// GenesisHash is the well-known seed for the hash chain.
const GenesisHash = "vaos-kernel-genesis-0000000000000000000000000000000000000000000000"

var (
	errMissingAgentID  = errors.New("record audit entry: agent id is required")
	errMissingComponent = errors.New("record audit entry: component is required")
	errMissingAction   = errors.New("record audit entry: action is required")
)

const defaultMaxEntries = 100000

// Ledger stores immutable-style audit entries with hash chaining.
type Ledger struct {
	mu         sync.RWMutex
	entries    []models.AuditEntry
	lastHash   string
	logger     *log.Logger
	clock      func() time.Time
	maxEntries int
}

// NewLedger creates a ledger backed by an optional writer.
func NewLedger(writer io.Writer) *Ledger {
	if writer == nil {
		writer = io.Discard
	}
	return &Ledger{
		lastHash:   GenesisHash,
		logger:     log.New(writer, "", 0),
		clock:      func() time.Time { return time.Now().UTC() },
		maxEntries: defaultMaxEntries,
	}
}

// Record appends an audit entry with hash-chained attestation.
// Each entry's attestation includes the previous entry's hash,
// creating a tamper-proof chain where modifying any historical
// entry invalidates all subsequent entries.
func (l *Ledger) Record(entry models.AuditEntry) (models.AuditEntry, error) {
	if entry.AgentID == "" {
		return models.AuditEntry{}, errMissingAgentID
	}
	if entry.Component == "" {
		return models.AuditEntry{}, errMissingComponent
	}
	if entry.Action == "" {
		return models.AuditEntry{}, errMissingAction
	}

	if entry.ID == "" {
		entry.ID = entry.Component + "-" + l.clock().Format("20060102150405.000000000")
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = l.clock()
	}

	l.mu.Lock()
	// Hash chain: H_n = BLAKE2b(canonical_fields_n || H_{n-1})
	attestation, err := attestChained(entry, l.lastHash)
	if err != nil {
		l.mu.Unlock()
		return models.AuditEntry{}, err
	}
	entry.Attestation = attestation
	l.lastHash = attestation
	l.entries = append(l.entries, entry)
	// Evict oldest half when capacity exceeded
	if l.maxEntries > 0 && len(l.entries) > l.maxEntries {
		half := len(l.entries) / 2
		l.entries = l.entries[half:]
	}
	l.mu.Unlock()

	payload, _ := json.Marshal(entry)
	l.logger.Print(string(payload))
	return entry, nil
}

// VerifyChain walks all entries and verifies the hash chain integrity.
// Returns the index of the first broken link, or -1 if the chain is valid.
// After eviction, the chain may be partial — the first entry is always
// trusted as the new anchor since its predecessor was evicted.
func (l *Ledger) VerifyChain() int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if len(l.entries) == 0 {
		return -1
	}

	// Start from the second entry; the first entry is the anchor after eviction.
	for i := 1; i < len(l.entries); i++ {
		prevHash := l.entries[i-1].Attestation
		expected, err := attestChained(l.entries[i], prevHash)
		if err != nil || expected != l.entries[i].Attestation {
			return i
		}
	}
	return -1
}

// Entries returns a copy of all ledger entries.
func (l *Ledger) Entries() []models.AuditEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]models.AuditEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

func attestChained(entry models.AuditEntry, prevHash string) (string, error) {
	payload, err := json.Marshal(struct {
		ID                string            `json:"id"`
		Timestamp         time.Time         `json:"timestamp"`
		AgentID           string            `json:"agent_id"`
		IntentFingerprint string            `json:"intent_fingerprint"`
		Action            string            `json:"action"`
		Component         string            `json:"component"`
		Status            string            `json:"status"`
		Details           map[string]string `json:"details,omitempty"`
		PrevHash          string            `json:"prev_hash"`
	}{
		ID:                entry.ID,
		Timestamp:         entry.Timestamp,
		AgentID:           entry.AgentID,
		IntentFingerprint: entry.IntentFingerprint,
		Action:            entry.Action,
		Component:         entry.Component,
		Status:            entry.Status,
		Details:           entry.Details,
		PrevHash:          prevHash,
	})
	if err != nil {
		return "", err
	}
	sum := blake2b.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

