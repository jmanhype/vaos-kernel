package agenticjwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const goldenChecksum = "3a9933e5ed0ee4e93e4cde7a83d9e40af8fec4a41c07db9d666341793a1d8559"

func testSpec() AgentSpec {
	return AgentSpec{
		AgentID: "agent-one",
		Prompt:  "Line one\r\n\r\n  Line two  ",
		Tools: []Tool{
			{
				Name:        "read",
				Signature:   "read(source string)",
				Description: "Read data",
			},
		},
		Configuration: map[string]any{
			"model_name":  "test-model",
			"temperature": 0,
		},
	}
}

type testAuthority struct {
	registry       *Registry
	authority      *Authority
	signingPrivate ed25519.PrivateKey
	agentPrivate   ed25519.PrivateKey
	agentPublic    ed25519.PublicKey
	checksum       string
	request        TokenRequest
}

func newTestAuthority(t *testing.T) *testAuthority {
	t.Helper()
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	agentPublic, agentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spec := testSpec()
	checksum, err := CanonicalChecksum(spec)
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry(func() time.Time { return now })
	if _, err := registry.Register("app-one", spec, agentPublic); err != nil {
		t.Fatal(err)
	}
	if err := registry.RegisterWorkflow("app-one", WorkflowDefinition{
		WorkflowID: "workflow-one",
		Steps: []WorkflowStep{
			{StepID: "step-one", Required: true, AgentID: "supervisor"},
			{StepID: "step-two", Required: true, AgentID: "agent-one"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthority(
		"app-one",
		"https://idp.example.test",
		signingPrivate,
		registry,
		300*time.Second,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	authority.randomRead = func(data []byte) (int, error) {
		for index := range data {
			data[index] = byte(index + 1)
		}
		return len(data), nil
	}
	return &testAuthority{
		registry:       registry,
		authority:      authority,
		signingPrivate: signingPrivate,
		agentPrivate:   agentPrivate,
		agentPublic:    agentPublic,
		checksum:       checksum,
		request: TokenRequest{
			GrantType:        "agent_checksum",
			AgentID:          "agent-one",
			ComputedChecksum: checksum,
			WorkflowEnabled:  true,
			WorkflowID:       "workflow-one",
			WorkflowStep:     "step-two",
			RequestedScopes:  []string{"repo:write", "vulnerability:read"},
			Audience:         Audience{"https://api.example.test"},
			DelegationContext: &DelegationContext{
				Chain:          []string{"supervisor"},
				CompletedSteps: []string{"step-one"},
			},
		},
	}
}

func TestCanonicalChecksumGoldenVector(t *testing.T) {
	checksum, err := CanonicalChecksum(testSpec())
	if err != nil {
		t.Fatal(err)
	}
	if checksum != goldenChecksum {
		t.Fatalf("checksum = %s, want %s", checksum, goldenChecksum)
	}
}

func TestCanonicalChecksumToolOrderIsDeterministic(t *testing.T) {
	spec := testSpec()
	spec.Tools = append(spec.Tools, Tool{Name: "alpha", Signature: "alpha()", Description: "first"})
	first, err := CanonicalChecksum(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Tools[0], spec.Tools[1] = spec.Tools[1], spec.Tools[0]
	second, err := CanonicalChecksum(spec)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("tool order changed checksum: %s versus %s", first, second)
	}
}

func TestChecksumValidation(t *testing.T) {
	if err := ValidateChecksumFormat("sha256:" + strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateChecksumFormat(strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	for _, checksum := range []string{"", "sha256:abc", strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		if err := ValidateChecksumFormat(checksum); err == nil {
			t.Fatalf("accepted invalid checksum %q", checksum)
		}
	}
}

func TestAudienceJSONForms(t *testing.T) {
	var single Audience
	if err := json.Unmarshal([]byte(`"api"`), &single); err != nil {
		t.Fatal(err)
	}
	if len(single) != 1 || single[0] != "api" {
		t.Fatalf("single audience = %#v", single)
	}
	encoded, err := json.Marshal(single)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `"api"` {
		t.Fatalf("single audience encoded as %s", encoded)
	}
	var many Audience
	if err := json.Unmarshal([]byte(`["one","two"]`), &many); err != nil {
		t.Fatal(err)
	}
	if len(many) != 2 {
		t.Fatalf("array audience = %#v", many)
	}
	if err := json.Unmarshal([]byte(`17`), &many); err == nil {
		t.Fatal("accepted numeric audience")
	}
}

func TestRegistryDuplicateAndVersioning(t *testing.T) {
	setup := newTestAuthority(t)
	if _, err := setup.registry.Register("app-one", testSpec(), setup.agentPublic); !IsCode(err, "duplicate_agent") {
		t.Fatalf("duplicate error = %v", err)
	}
	changed := testSpec()
	changed.Prompt = changed.Prompt + "\nChanged"
	registration, err := setup.registry.Register("app-one", changed, setup.agentPublic)
	if err != nil {
		t.Fatal(err)
	}
	if registration.Version != 2 {
		t.Fatalf("version = %d, want 2", registration.Version)
	}
	latest, err := setup.registry.Latest("app-one", "agent-one")
	if err != nil {
		t.Fatal(err)
	}
	if latest.RegistrationID != registration.RegistrationID {
		t.Fatal("latest registration was not returned")
	}
}

func TestTokenRequestMUSTValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*TokenRequest)
		code   string
	}{
		{"grant", func(r *TokenRequest) { r.GrantType = "client_credentials" }, "unsupported_grant_type"},
		{"agent", func(r *TokenRequest) { r.AgentID = "" }, "invalid_request"},
		{"checksum", func(r *TokenRequest) { r.ComputedChecksum = "bad" }, "invalid_request"},
		{"workflow id", func(r *TokenRequest) { r.WorkflowID = "" }, "invalid_request"},
		{"workflow step", func(r *TokenRequest) { r.WorkflowStep = "" }, "invalid_request"},
		{"scopes", func(r *TokenRequest) { r.RequestedScopes = nil }, "invalid_request"},
		{"audience", func(r *TokenRequest) { r.Audience = nil }, "invalid_request"},
		{"unknown agent", func(r *TokenRequest) { r.AgentID = "missing" }, "unknown_agent"},
		{"checksum mismatch", func(r *TokenRequest) { r.ComputedChecksum = strings.Repeat("b", 64) }, "agent_checksum_mismatch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setup := newTestAuthority(t)
			request := setup.request
			test.mutate(&request)
			_, err := setup.registry.ValidateRequest("app-one", request)
			if !IsCode(err, test.code) {
				t.Fatalf("error = %v, want code %s", err, test.code)
			}
		})
	}
}

func TestMintAndVerifyClaims(t *testing.T) {
	setup := newTestAuthority(t)
	response, claims, err := setup.authority.Mint("app-one", setup.request)
	if err != nil {
		t.Fatal(err)
	}
	if response.TokenType != "Bearer" || response.ExpiresIn != 300 {
		t.Fatalf("unexpected response: %#v", response)
	}
	if claims.Issuer != "https://idp.example.test" || claims.Subject != "agent-one" {
		t.Fatalf("unexpected registered claims: %#v", claims.RegisteredClaims)
	}
	if claims.Scope != "repo:write vulnerability:read" {
		t.Fatalf("scope = %q", claims.Scope)
	}
	if claims.Confirmation.JWK.Kty != "OKP" || claims.Confirmation.JWK.Crv != "Ed25519" {
		t.Fatalf("confirmation = %#v", claims.Confirmation)
	}
	if claims.AgentProof.AgentChecksum != setup.checksum || claims.AgentProof.RegistrationID == "" {
		t.Fatalf("agent proof = %#v", claims.AgentProof)
	}
	if claims.Intent.ExecutedBy != "agent-one" || claims.Intent.WorkflowID != "workflow-one" {
		t.Fatalf("intent = %#v", claims.Intent)
	}

	verified, err := setup.authority.Verify(response.AccessToken, "https://api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if verified.ID != claims.ID {
		t.Fatalf("verified jti = %q, want %q", verified.ID, claims.ID)
	}
}

func TestVerifyRejectsWrongAudienceSignatureAndExpiry(t *testing.T) {
	setup := newTestAuthority(t)
	response, _, err := setup.authority.Mint("app-one", setup.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := setup.authority.Verify(response.AccessToken, "https://other.example.test"); !IsCode(err, "invalid_token") {
		t.Fatalf("wrong audience error = %v", err)
	}

	_, replacementPrivate, _ := ed25519.GenerateKey(rand.Reader)
	replacement, err := NewAuthority(
		"app-one",
		"https://idp.example.test",
		replacementPrivate,
		setup.registry,
		300*time.Second,
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replacement.Verify(response.AccessToken, "https://api.example.test"); !IsCode(err, "invalid_token") {
		t.Fatalf("wrong signature error = %v", err)
	}

	now := time.Date(2026, 9, 17, 12, 10, 1, 0, time.UTC)
	setup.authority.now = func() time.Time { return now }
	if _, err := setup.authority.Verify(response.AccessToken, "https://api.example.test"); !IsCode(err, "invalid_token") {
		t.Fatalf("expired error = %v", err)
	}
}

func TestProofOfPossession(t *testing.T) {
	setup := newTestAuthority(t)
	challenge := []byte("proof challenge")
	signature, err := SignProof(setup.agentPrivate, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProof(setup.agentPublic, challenge, signature); err != nil {
		t.Fatal(err)
	}
	if err := VerifyProof(setup.agentPublic, []byte("changed"), signature); !IsCode(err, "invalid_proof") {
		t.Fatalf("invalid proof error = %v", err)
	}
}
