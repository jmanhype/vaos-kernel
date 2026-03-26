package audit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"vaos-kernel/pkg/models"
)

func buildChain(t *testing.T, n int) (*Ledger, []models.AuditEntry) {
	t.Helper()
	ledger := NewLedger(&bytes.Buffer{})
	var entries []models.AuditEntry
	for i := 0; i < n; i++ {
		e, err := ledger.Record(models.AuditEntry{
			AgentID:   "agent-test",
			Action:    "action",
			Component: "test",
			Status:    "ok",
		})
		if err != nil {
			t.Fatalf("record entry %d: %v", i, err)
		}
		entries = append(entries, e)
	}
	return ledger, entries
}

func TestReplayEmpty(t *testing.T) {
	res := Replay(nil, nil, nil)
	if res.EntryCount != 0 {
		t.Fatalf("expected 0 entries, got %d", res.EntryCount)
	}
	if res.ChainStatus != "ok" {
		t.Fatalf("expected chain ok, got %s", res.ChainStatus)
	}
	if res.SigStatus != "skipped" {
		t.Fatalf("expected sig skipped, got %s", res.SigStatus)
	}
}

func TestReplayChainIntact(t *testing.T) {
	_, entries := buildChain(t, 3)
	res := Replay(entries, nil, nil)
	if res.EntryCount != 3 {
		t.Fatalf("expected 3 entries, got %d", res.EntryCount)
	}
	if res.ChainStatus != "ok" {
		t.Fatalf("expected chain ok, got %s", res.ChainStatus)
	}
	if res.BrokenAtIndex != -1 {
		t.Fatalf("expected no broken index, got %d", res.BrokenAtIndex)
	}
}

func TestReplayChainTampered(t *testing.T) {
	_, entries := buildChain(t, 3)
	entries[1].Attestation = "deadbeef"
	res := Replay(entries, nil, nil)
	if res.ChainStatus != "broken" {
		t.Fatalf("expected chain broken, got %s", res.ChainStatus)
	}
	if res.BrokenAtIndex != 1 {
		t.Fatalf("expected broken at 1, got %d", res.BrokenAtIndex)
	}
}

func TestReplayWithValidSigs(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, entries := buildChain(t, 3)

	sigs := make(map[string]string)
	for _, e := range entries {
		sig := ed25519.Sign(priv, []byte(e.Attestation))
		sigs[e.ID] = hex.EncodeToString(sig)
	}

	sigFn := func(e models.AuditEntry) string { return sigs[e.ID] }
	verifyFn := func(data []byte, sigHex string) bool {
		sig, err := hex.DecodeString(sigHex)
		if err != nil {
			return false
		}
		return ed25519.Verify(pub, data, sig)
	}

	res := Replay(entries, sigFn, verifyFn)
	if res.SigStatus != "ok" {
		t.Fatalf("expected sig ok, got %s", res.SigStatus)
	}
	if res.SigVerifiedCount != 3 {
		t.Fatalf("expected 3 verified, got %d", res.SigVerifiedCount)
	}
}

func TestReplayWithBadSig(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, entries := buildChain(t, 3)

	sigs := make(map[string]string)
	for i, e := range entries {
		sig := ed25519.Sign(priv, []byte(e.Attestation))
		h := hex.EncodeToString(sig)
		if i == 1 {
			// Corrupt second signature
			b := []byte(h)
			if b[len(b)-1] == 'a' {
				b[len(b)-1] = 'b'
			} else {
				b[len(b)-1] = 'a'
			}
			sigs[e.ID] = string(b)
		} else {
			sigs[e.ID] = h
		}
	}

	sigFn := func(e models.AuditEntry) string { return sigs[e.ID] }
	verifyFn := func(data []byte, sigHex string) bool {
		sig, err := hex.DecodeString(sigHex)
		if err != nil {
			return false
		}
		return ed25519.Verify(pub, data, sig)
	}

	res := Replay(entries, sigFn, verifyFn)
	if res.SigStatus != "failed" {
		t.Fatalf("expected sig failed, got %s", res.SigStatus)
	}
	if res.SigFailedAtID != entries[1].ID {
		t.Fatalf("expected failure at entry 1 ID, got %s", res.SigFailedAtID)
	}
}

func TestReplayNilSigFnSkips(t *testing.T) {
	_, entries := buildChain(t, 2)
	res := Replay(entries, nil, nil)
	if res.SigStatus != "skipped" {
		t.Fatalf("expected sig skipped, got %s", res.SigStatus)
	}
}

func TestReplayEmptySigGraceful(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	_, entries := buildChain(t, 2)

	sigFn := func(e models.AuditEntry) string { return "" }
	verifyFn := func(data []byte, sigHex string) bool {
		sig, err := hex.DecodeString(sigHex)
		if err != nil {
			return false
		}
		return ed25519.Verify(pub, data, sig)
	}

	res := Replay(entries, sigFn, verifyFn)
	if res.SigStatus != "ok" {
		t.Fatalf("expected sig ok (all skipped), got %s", res.SigStatus)
	}
	if res.SigVerifiedCount != 0 {
		t.Fatalf("expected 0 verified, got %d", res.SigVerifiedCount)
	}
}
