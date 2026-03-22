package audit

import "vaos-kernel/pkg/models"

// Recorder is the interface satisfied by both Ledger (Mode A) and AsyncLedger (Mode B).
type Recorder interface {
	Record(entry models.AuditEntry) (models.AuditEntry, error)
	Entries() []models.AuditEntry
	VerifyChain() int
}
