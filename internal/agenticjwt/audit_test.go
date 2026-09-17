package agenticjwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type recordingAuditRecorder struct {
	entries []map[string]string
	err     error
}

func (r *recordingAuditRecorder) Record(entry AuditEntry) (AuditEntry, error) {
	if r.err != nil {
		return AuditEntry{}, r.err
	}
	entry.ID = strings.ToLower(strings.ReplaceAll(entry.Action, "_", "-"))
	r.entries = append(r.entries, map[string]string{
		"id":       entry.ID,
		"agent_id": entry.AgentID,
		"action":   entry.Action,
		"status":   entry.Status,
	})
	return entry, nil
}

func TestAuthorityAuditTrail(t *testing.T) {
	setup := newTestAuthority(t)
	recorder := &recordingAuditRecorder{}
	authority, err := NewAuthority(
		"app-one",
		"https://idp.example.test",
		setup.signingPrivate,
		setup.registry,
		300*time.Second,
		func() time.Time { return time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC) },
		WithAuditRecorder(recorder),
	)
	if err != nil {
		t.Fatal(err)
	}

	registrationBody, err := json.Marshal(AgentRegistrationRequest{
		AgentSpec: func() AgentSpec {
			spec := testSpec()
			spec.AgentID = "audit-agent"
			spec.Prompt = "Audit registration agent."
			return spec
		}(),
		PublicKey: base64.RawURLEncoding.EncodeToString(setup.agentPublic),
	})
	if err != nil {
		t.Fatal(err)
	}
	registrationRecorder := httptest.NewRecorder()
	authority.HandleRegistration(registrationRecorder, httptest.NewRequest(
		http.MethodPost,
		"/v1/intent/register/agent",
		strings.NewReader(string(registrationBody)),
	))
	if registrationRecorder.Code != http.StatusOK {
		t.Fatalf("registration status = %d body = %s", registrationRecorder.Code, registrationRecorder.Body.String())
	}

	response, _, err := authority.Mint("app-one", setup.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Verify(response.AccessToken, "https://api.example.test"); err != nil {
		t.Fatal(err)
	}

	mismatch := setup.request
	mismatch.ComputedChecksum = strings.Repeat("b", 64)
	if _, _, err := authority.Mint("app-one", mismatch); !IsCode(err, "agent_checksum_mismatch") {
		t.Fatalf("mismatch error = %v", err)
	}

	wantActions := []string{
		"agentic_agent_registered",
		"agentic_token_minted",
		"agentic_token_verified",
		"agentic_token_mint_failed",
	}
	if len(recorder.entries) != len(wantActions) {
		t.Fatalf("audit entries = %#v", recorder.entries)
	}
	for index, action := range wantActions {
		if recorder.entries[index]["action"] != action {
			t.Fatalf("audit action %d = %s, want %s", index, recorder.entries[index]["action"], action)
		}
	}
	if recorder.entries[0]["agent_id"] != "audit-agent" {
		t.Fatalf("registration audit agent = %s", recorder.entries[0]["agent_id"])
	}
	if recorder.entries[3]["status"] != "error" {
		t.Fatalf("failed mint status = %s", recorder.entries[3]["status"])
	}
}

func TestAuthorityMintFailsClosedWhenAuditFails(t *testing.T) {
	setup := newTestAuthority(t)
	authority, err := NewAuthority(
		"app-one",
		"https://idp.example.test",
		setup.signingPrivate,
		setup.registry,
		300*time.Second,
		func() time.Time { return time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC) },
		WithAuditRecorder(&recordingAuditRecorder{err: errors.New("audit unavailable")}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := authority.Mint("app-one", setup.request); !IsCode(err, "server_error") {
		t.Fatalf("error = %v, want server_error", err)
	}
}
