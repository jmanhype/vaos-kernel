package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
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

func TestAsyncLedgerRecordReturnsAttestation(t *testing.T) {
	var buf bytes.Buffer
	ledger := NewAsyncLedger(&buf, AsyncConfig{BufferSize: 4})
	defer ledger.Close()

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
		t.Fatal("async record returned an empty attestation")
	}
	if brokenAt := ledger.VerifyChain(); brokenAt != -1 {
		t.Fatalf("async chain broken at %d", brokenAt)
	}
}

func TestAsyncLedgerPersistsInChainOrder(t *testing.T) {
	var buf bytes.Buffer
	ledger := NewAsyncLedger(&buf, AsyncConfig{BufferSize: 1})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ledger.Record(models.AuditEntry{
				AgentID:   "agent-1",
				Action:    "deploy",
				Component: "swarm",
				Status:    "success",
			}); err != nil {
				t.Errorf("record entry: %v", err)
			}
		}()
	}
	wg.Wait()
	ledger.Close()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	entries := make([]models.AuditEntry, 0, len(lines))
	for _, line := range lines {
		var entry models.AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode persisted entry: %v", err)
		}
		entries = append(entries, entry)
	}
	if len(entries) != 100 {
		t.Fatalf("expected 100 persisted entries, got %d", len(entries))
	}
	if result := Replay(entries, nil, nil); result.ChainStatus != "ok" {
		t.Fatalf("persisted chain order is broken at %d", result.BrokenAtIndex)
	}
}
