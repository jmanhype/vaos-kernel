package nhi

import (
	"testing"
	"time"

	"vaos-kernel/pkg/models"
)

func TestRegistryLifecycle(t *testing.T) {
	registry := NewRegistry()
	agent := models.Agent{ID: "agent-1", Name: "Agent One"}
	if err := registry.RegisterAgent(agent); err != nil {
		t.Fatalf("register agent: %v", err)
	}
	if _, err := registry.GetAgent(agent.ID); err != nil {
		t.Fatalf("get agent: %v", err)
	}
	if err := registry.StoreIntentFingerprint(agent.ID, "abc123"); err != nil {
		t.Fatalf("store fingerprint: %v", err)
	}
	if got, err := registry.IntentFingerprint(agent.ID); err != nil || got != "abc123" {
		t.Fatalf("fingerprint lookup = %q, %v", got, err)
	}

	record := models.TokenRecord{
		TokenID:           "tok-1",
		AgentID:           agent.ID,
		IntentFingerprint: "abc123",
		Status:            "issued",
		IssuedAt:          time.Now(),
		ExpiresAt:         time.Now().Add(time.Minute),
	}
	if err := registry.TrackToken(record); err != nil {
		t.Fatalf("track token: %v", err)
	}
	if err := registry.MarkTokenUsed(record.TokenID, time.Now()); err != nil {
		t.Fatalf("mark used: %v", err)
	}
	used, err := registry.Token(record.TokenID)
	if err != nil {
		t.Fatalf("token lookup: %v", err)
	}
	if used.Status != "used" || used.UsedAt == nil {
		t.Fatalf("unexpected used token state: %+v", used)
	}
	if err := registry.RevokeToken(record.TokenID, time.Now()); err != nil {
		t.Fatalf("revoke token: %v", err)
	}
	revoked, err := registry.Token(record.TokenID)
	if err != nil {
		t.Fatalf("token lookup after revoke: %v", err)
	}
	if revoked.Status != "revoked" || revoked.RevokedAt == nil {
		t.Fatalf("unexpected revoked token state: %+v", revoked)
	}
}

