package audit

import (
	"bytes"
	"testing"

	"vaos-kernel/pkg/models"
)

func TestLedgerRecord(t *testing.T) {
	var buf bytes.Buffer
	ledger := NewLedger(&buf)
	entry, err := ledger.Record(models.AuditEntry{
		AgentID:   "agent-1",
		Action:    "deploy",
		Component: "swarm",
		Status:    "success",
	})
	if err != nil {
		t.Fatalf("record entry: %v", err)
	}
	if entry.Attestation == "" {
		t.Fatal("expected attestation")
	}
	if len(ledger.Entries()) != 1 {
		t.Fatalf("expected one entry, got %d", len(ledger.Entries()))
	}
	if buf.Len() == 0 {
		t.Fatal("expected structured log output")
	}
}

