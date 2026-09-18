package agenticresource

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"vaos-kernel/internal/agenticjwt"
)

type verifierSetup struct {
	authority      *agenticjwt.Authority
	registry       *agenticjwt.Registry
	agentPrivate   ed25519.PrivateKey
	signingPrivate ed25519.PrivateKey
	request        agenticjwt.TokenRequest
	token          string
	proof          Proof
	now            *time.Time
	providerServer *httptest.Server
}

func newVerifierSetup(t *testing.T) *verifierSetup {
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
	spec := agenticjwt.AgentSpec{
		AgentID: "resource-agent",
		Prompt:  "Execute the authorized resource operation.",
		Tools: []agenticjwt.Tool{{
			Name:        "operation",
			Signature:   "operation(input string)",
			Description: "Execute an operation",
		}},
		Configuration: map[string]any{"model_name": "resource-test"},
	}
	checksum, err := agenticjwt.CanonicalChecksum(spec)
	if err != nil {
		t.Fatal(err)
	}
	registry := agenticjwt.NewRegistry(func() time.Time { return now })
	if _, err := registry.Register("resource-app", spec, agentPublic); err != nil {
		t.Fatal(err)
	}
	request := agenticjwt.TokenRequest{
		GrantType:        "agent_checksum",
		AgentID:          spec.AgentID,
		ComputedChecksum: checksum,
		RequestedScopes:  []string{"resource:write"},
		Audience:         agenticjwt.Audience{"https://resource.example.test"},
	}
	authority, err := agenticjwt.NewAuthority(
		"resource-app",
		"https://issuer.example.test",
		signingPrivate,
		registry,
		5*time.Minute,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	response, _, err := authority.Mint("resource-app", request)
	if err != nil {
		t.Fatal(err)
	}
	challenge := ProofChallenge(http.MethodPost, "/resource", []byte(`{"input":"safe"}`), response.AccessToken)
	signature := ed25519.Sign(agentPrivate, challenge)
	jwks := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(authority.JWKS())
	}))
	t.Cleanup(jwks.Close)
	return &verifierSetup{
		authority:      authority,
		registry:       registry,
		agentPrivate:   agentPrivate,
		signingPrivate: signingPrivate,
		request:        request,
		token:          response.AccessToken,
		proof:          Proof{Challenge: challenge, Signature: signature},
		now:            &now,
		providerServer: jwks,
	}
}

func TestStandaloneVerifierValidatesJWKSSignatureClaimsAndAgentProof(t *testing.T) {
	setup := newVerifierSetup(t)
	provider, err := NewHTTPJWKSProvider(
		setup.providerServer.URL,
		WithHTTPClient(setup.providerServer.Client()),
	)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(Config{
		Issuer:   "https://issuer.example.test",
		Audience: "https://resource.example.test",
		JWKS:     provider,
		Now:      func() time.Time { return *setup.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.Verify(context.Background(), setup.token, setup.proof)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "resource-agent" || claims.Scope != "resource:write" {
		t.Fatalf("claims = %#v", claims)
	}
	if claims.Intent.ExecutedBy != claims.Subject || claims.AgentProof.RegistrationID == "" {
		t.Fatalf("intent/proof claims = %#v", claims)
	}
}

func TestStandaloneVerifierRejectsTamperingAndWrongProof(t *testing.T) {
	setup := newVerifierSetup(t)
	provider, err := NewHTTPJWKSProvider(
		setup.providerServer.URL,
		WithHTTPClient(setup.providerServer.Client()),
	)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(Config{
		Issuer:   "https://issuer.example.test",
		Audience: "https://resource.example.test",
		JWKS:     provider,
		Now:      func() time.Time { return *setup.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	tampered := setup.token[:len(setup.token)-2] + "aa"
	if _, err := verifier.Verify(context.Background(), tampered, setup.proof); err == nil {
		t.Fatal("accepted a modified JWT signature")
	}
	badProof := setup.proof
	badProof.Signature = append([]byte(nil), badProof.Signature...)
	badProof.Signature[0] ^= 1
	if _, err := verifier.Verify(context.Background(), setup.token, badProof); err == nil {
		t.Fatal("accepted an invalid agent proof")
	}
	expired := setup.now.Add(6 * time.Minute)
	setup.now = &expired
	if _, err := verifier.Verify(context.Background(), setup.token, setup.proof); err == nil {
		t.Fatal("accepted an expired token")
	}
}

func TestStandaloneVerifierRejectsMissingIntentClaims(t *testing.T) {
	setup := newVerifierSetup(t)
	provider, err := NewHTTPJWKSProvider(
		setup.providerServer.URL,
		WithHTTPClient(setup.providerServer.Client()),
	)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(Config{
		Issuer:   "https://issuer.example.test",
		Audience: "https://resource.example.test",
		JWKS:     provider,
		Now:      func() time.Time { return *setup.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	validClaims, err := verifier.Verify(context.Background(), setup.token, setup.proof)
	if err != nil {
		t.Fatal(err)
	}
	invalid := *validClaims
	invalid.Intent = agenticjwt.IntentClaims{}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, invalid)
	keySet := setup.authority.JWKS()
	token.Header["kid"] = keySet.Keys[0].Kid
	private := setup.signingPrivate
	signed, err := token.SignedString(private)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(setup.agentPrivate, ProofChallenge(http.MethodPost, "/resource", nil, signed))
	if _, err := verifier.Verify(context.Background(), signed, Proof{
		Challenge: ProofChallenge(http.MethodPost, "/resource", nil, signed),
		Signature: signature,
	}); err == nil {
		t.Fatal("accepted a token without required intent claims")
	}
}

func TestVerifierMiddlewareRequiresBearerAndProofHeader(t *testing.T) {
	setup := newVerifierSetup(t)
	provider, err := NewHTTPJWKSProvider(
		setup.providerServer.URL,
		WithHTTPClient(setup.providerServer.Client()),
	)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(Config{
		Issuer:   "https://issuer.example.test",
		Audience: "https://resource.example.test",
		JWKS:     provider,
		Now:      func() time.Time { return *setup.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	allowed := false
	handler := verifier.RequireScope("resource:write", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		allowed = true
		if ClaimsFromContext(request.Context()) == nil {
			t.Error("claims missing from request context")
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	body := `{"input":"safe"}`
	challenge := ProofChallenge(http.MethodPost, "/resource", []byte(body), setup.token)
	signature := ed25519.Sign(setup.agentPrivate, challenge)
	request := httptest.NewRequest(http.MethodPost, "/resource", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+setup.token)
	request.Header.Set("X-VAOS-Agent-Proof", base64.RawURLEncoding.EncodeToString(signature))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || !allowed {
		t.Fatalf("status = %d allowed = %v", recorder.Code, allowed)
	}

	request = httptest.NewRequest(http.MethodPost, "/resource", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+setup.token)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing proof status = %d, want 401", recorder.Code)
	}
}
