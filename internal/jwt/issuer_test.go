package jwt

import (
	"testing"
	"time"

	"vaos-kernel/internal/nhi"
	"vaos-kernel/pkg/models"
)

func TestIssueAndVerify(t *testing.T) {
	registry := nhi.NewRegistry()
	if err := registry.RegisterAgent(models.Agent{ID: "agent-1", Name: "Agent One"}); err != nil {
		t.Fatalf("register agent: %v", err)
	}
	issuer, err := NewIssuer([]byte("test-signing-key"), registry)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	issuer.clock = func() time.Time { return base }
	token, record, err := issuer.Issue("agent-1", "fingerprint-1")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	if record.ExpiresAt.Sub(record.IssuedAt) != tokenTTL {
		t.Fatalf("unexpected ttl: %v", record.ExpiresAt.Sub(record.IssuedAt))
	}

	claims, err := issuer.Verify(token, "fingerprint-1")
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if claims.AgentID != "agent-1" {
		t.Fatalf("unexpected agent id: %s", claims.AgentID)
	}
}

func TestVerifyExpired(t *testing.T) {
	registry := nhi.NewRegistry()
	if err := registry.RegisterAgent(models.Agent{ID: "agent-1", Name: "Agent One"}); err != nil {
		t.Fatalf("register agent: %v", err)
	}
	issuer, err := NewIssuer([]byte("test-signing-key"), registry)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	issuer.clock = func() time.Time { return base }
	token, _, err := issuer.Issue("agent-1", "fingerprint-1")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	issuer.clock = func() time.Time { return base.Add(61 * time.Second) }
	if _, err := issuer.Verify(token, "fingerprint-1"); err == nil {
		t.Fatal("expected expired token error")
	}
}

