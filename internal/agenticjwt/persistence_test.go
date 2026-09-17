package agenticjwt

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFileRegistryPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agentic-registry.json")
	store, err := NewFileRegistryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewRegistryWithStore(time.Now, store)
	if err != nil {
		t.Fatal(err)
	}
	registration, err := first.Register("app-one", testSpec(), newTestAuthority(t).agentPublic)
	if err != nil {
		t.Fatal(err)
	}
	workflow := WorkflowDefinition{
		WorkflowID: "workflow-one",
		Steps: []WorkflowStep{
			{StepID: "step-one", Required: true, AgentID: "supervisor"},
			{StepID: "step-two", Required: true, AgentID: "agent-one"},
		},
	}
	if err := first.RegisterWorkflow("app-one", workflow); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileRegistryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewRegistryWithStore(time.Now, reopened)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := second.Latest("app-one", "agent-one")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RegistrationID != registration.RegistrationID || loaded.Version != 1 {
		t.Fatalf("loaded registration = %#v, want %#v version 1", loaded, registration)
	}
	request := TokenRequest{
		GrantType:        "agent_checksum",
		AgentID:          "agent-one",
		ComputedChecksum: loaded.Checksum,
		WorkflowEnabled:  true,
		WorkflowID:       "workflow-one",
		WorkflowStep:     "step-two",
		RequestedScopes:  []string{"repo:write"},
		Audience:         Audience{"https://api.example.test"},
		DelegationContext: &DelegationContext{
			Chain:          []string{"supervisor"},
			CompletedSteps: []string{"step-one"},
		},
	}
	if _, err := second.ValidateRequest("app-one", request); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationRevocationInvalidatesMintAndExistingTokens(t *testing.T) {
	setup := newTestAuthority(t)
	response, _, err := setup.authority.Mint("app-one", setup.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := setup.authority.Verify(response.AccessToken, "https://api.example.test"); err != nil {
		t.Fatal(err)
	}
	registration, err := setup.registry.Latest("app-one", "agent-one")
	if err != nil {
		t.Fatal(err)
	}
	if err := setup.authority.RevokeRegistration("app-one", registration.RegistrationID, "security compromise"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := setup.authority.Mint("app-one", setup.request); !IsCode(err, "registration_revoked") {
		t.Fatalf("mint after revocation error = %v, want registration_revoked", err)
	}
	if _, err := setup.authority.Verify(response.AccessToken, "https://api.example.test"); !IsCode(err, "registration_revoked") {
		t.Fatalf("existing token after revocation error = %v, want registration_revoked", err)
	}
	loaded, err := setup.registry.Registration("app-one", registration.RegistrationID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RevokedAt.IsZero() || loaded.RevocationReason != "security compromise" {
		t.Fatalf("revocation metadata = %#v", loaded)
	}
}
