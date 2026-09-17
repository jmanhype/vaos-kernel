package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vaos-kernel/internal/agenticjwt"
	"vaos-kernel/internal/audit"
)

func agenticTestEnvironment(t *testing.T, keyMode string) map[string]string {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(private)
	if keyMode == "seed" {
		encoded = "seed:" + base64.RawURLEncoding.EncodeToString(private.Seed())
	}
	if keyMode == "public" {
		encoded = base64.RawURLEncoding.EncodeToString(public)
	}
	return map[string]string{
		"VAOS_AGENTIC_JWT_ENABLED":                 "true",
		"VAOS_AGENTIC_JWT_APP_ID":                  "test-app",
		"VAOS_AGENTIC_JWT_ISSUER":                  "https://idp.example.test",
		"VAOS_AGENTIC_JWT_SIGNING_KEY":             encoded,
		"VAOS_AGENTIC_JWT_REGISTRY_PATH":           filepath.Join(t.TempDir(), "agentic-registry.json"),
		"VAOS_AGENTIC_JWT_REGISTRAR_CLIENT_ID":     "registrar",
		"VAOS_AGENTIC_JWT_REGISTRAR_CLIENT_SECRET": "registrar-test-secret-with-32-bytes",
		"VAOS_AGENTIC_JWT_WORKFLOW_CLIENT_ID":      "workflow-admin",
		"VAOS_AGENTIC_JWT_WORKFLOW_CLIENT_SECRET":  "workflow-admin-test-secret-32-bytes!",
		"VAOS_AGENTIC_JWT_TOKEN_CLIENT_ID":         "token-issuer",
		"VAOS_AGENTIC_JWT_TOKEN_CLIENT_SECRET":     "token-issuer-test-secret-32-bytes!",
	}
}

func TestNewAgenticJWTAuthority(t *testing.T) {
	now := time.Now
	registry := agenticjwt.NewRegistry(now)

	disabled, err := newAgenticJWTAuthority(func(string) string { return "" }, registry, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if disabled != nil {
		t.Fatal("disabled configuration returned an authority")
	}

	for _, mode := range []string{"private", "seed"} {
		env := agenticTestEnvironment(t, mode)
		authority, err := newAgenticJWTAuthority(func(key string) string { return env[key] }, registry, now, audit.NewLedger(nil))
		if err != nil {
			t.Fatalf("%s key mode: %v", mode, err)
		}
		if authority == nil {
			t.Fatalf("%s key mode returned no authority", mode)
		}
	}

	env := agenticTestEnvironment(t, "public")
	if _, err := newAgenticJWTAuthority(func(key string) string { return env[key] }, registry, now, audit.NewLedger(nil)); err == nil {
		t.Fatal("accepted an Ed25519 public key as authority signing key")
	}

	env = agenticTestEnvironment(t, "private")
	env["VAOS_AGENTIC_JWT_APP_ID"] = ""
	if _, err := newAgenticJWTAuthority(func(key string) string { return env[key] }, registry, now, audit.NewLedger(nil)); err == nil {
		t.Fatal("accepted missing app ID")
	}

	env = agenticTestEnvironment(t, "private")
	env["VAOS_AGENTIC_JWT_REGISTRAR_CLIENT_ID"] = ""
	if _, err := newAgenticJWTAuthority(func(key string) string { return env[key] }, registry, now, audit.NewLedger(nil)); err == nil {
		t.Fatal("enabled agentic jwt without a registrar OAuth client")
	}

	env = agenticTestEnvironment(t, "private")
	env["VAOS_AGENTIC_JWT_WORKFLOW_CLIENT_ID"] = env["VAOS_AGENTIC_JWT_REGISTRAR_CLIENT_ID"]
	if _, err := newAgenticJWTAuthority(func(key string) string { return env[key] }, registry, now, audit.NewLedger(nil)); err == nil {
		t.Fatal("accepted duplicate OAuth client IDs")
	}

	env = agenticTestEnvironment(t, "private")
	env["VAOS_AGENTIC_JWT_TOKEN_CLIENT_SECRET"] = ""
	if _, err := newAgenticJWTAuthority(func(key string) string { return env[key] }, registry, now, audit.NewLedger(nil)); err == nil {
		t.Fatal("enabled agentic jwt without a token-issuer OAuth client secret")
	}

	env = agenticTestEnvironment(t, "private")
	if _, err := newAgenticJWTAuthority(func(key string) string { return env[key] }, registry, now, nil); err == nil {
		t.Fatal("enabled agentic jwt without an audit recorder")
	}
}

func TestNewAgenticJWTRuntimeDisabledDoesNotRequirePersistence(t *testing.T) {
	authority, err := newAgenticJWTRuntime(
		func(key string) string {
			if key == "VAOS_AGENTIC_JWT_ENABLED" {
				return "false"
			}
			return ""
		},
		time.Now,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if authority != nil {
		t.Fatal("disabled runtime returned an authority")
	}
}

func TestMountAgenticJWT(t *testing.T) {
	now := time.Now
	env := agenticTestEnvironment(t, "private")
	authority, err := newAgenticJWTAuthority(func(key string) string { return env[key] }, agenticjwt.NewRegistry(now), now, agenticTestAuditRecorder{})
	if err != nil {
		t.Fatal(err)
	}

	protected := http.NewServeMux()
	mountAgenticJWT(protected, authority)
	for _, path := range []string{
		"/v1/intent/register/agent",
		"/v1/intent/register/workflow",
		"/v1/intent/token",
	} {
		request := httptest.NewRequest(http.MethodPost, path, nil)
		request.Header.Set("Authorization", "Bearer "+env["VAOS_API_SECRET"])
		recorder := httptest.NewRecorder()
		protected.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s shared-secret status = %d, want 401", path, recorder.Code)
		}
	}

	token := scopedTransportToken(t, authority, env["VAOS_AGENTIC_JWT_REGISTRAR_CLIENT_ID"], env["VAOS_AGENTIC_JWT_REGISTRAR_CLIENT_SECRET"], agenticjwt.ScopeRegisterAgent)
	request := httptest.NewRequest(http.MethodPost, "/v1/intent/register/agent", strings.NewReader("{}"))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	protected.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("scoped registrar status = %d, want 400 after passing transport auth", recorder.Code)
	}

	workflowToken := scopedTransportToken(t, authority, env["VAOS_AGENTIC_JWT_WORKFLOW_CLIENT_ID"], env["VAOS_AGENTIC_JWT_WORKFLOW_CLIENT_SECRET"], agenticjwt.ScopeRegisterWorkflow)
	request = httptest.NewRequest(http.MethodPost, "/v1/intent/register/workflow", strings.NewReader("{}"))
	request.Header.Set("Authorization", "Bearer "+workflowToken)
	recorder = httptest.NewRecorder()
	protected.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("scoped workflow status = %d, want 400 after passing transport auth", recorder.Code)
	}

	crossScopeRecorder := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/v1/intent/register/workflow", strings.NewReader("{}"))
	request.Header.Set("Authorization", "Bearer "+token)
	protected.ServeHTTP(crossScopeRecorder, request)
	if crossScopeRecorder.Code != http.StatusForbidden {
		t.Fatalf("cross-scope status = %d, want 403", crossScopeRecorder.Code)
	}

	jwksRecorder := httptest.NewRecorder()
	protected.ServeHTTP(jwksRecorder, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if jwksRecorder.Code != http.StatusOK || !strings.Contains(jwksRecorder.Body.String(), `"keys"`) {
		t.Fatalf("JWKS status = %d body = %s", jwksRecorder.Code, jwksRecorder.Body.String())
	}

	unmounted := http.NewServeMux()
	mountAgenticJWT(unmounted, nil)
	recorder = httptest.NewRecorder()
	unmounted.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/intent/token", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("nil authority status = %d, want 404", recorder.Code)
	}
}

func TestAgenticJWTRuntimePersistsRegistrationsAcrossReopen(t *testing.T) {
	now := time.Now
	env := agenticTestEnvironment(t, "private")
	getenv := func(key string) string { return env[key] }

	firstRegistry, err := newAgenticJWTRegistry(getenv, now)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spec := agenticjwt.AgentSpec{
		AgentID: "agent-one",
		Prompt:  "Run the authorized workflow only.",
		Tools: []agenticjwt.Tool{{
			Name:        "run_step",
			Signature:   "run_step(step string)",
			Description: "Run one authorized workflow step",
		}},
	}
	registration, err := firstRegistry.Register(env["VAOS_AGENTIC_JWT_APP_ID"], spec, public)
	if err != nil {
		t.Fatal(err)
	}
	workflow := agenticjwt.WorkflowDefinition{
		WorkflowID: "workflow-one",
		Steps: []agenticjwt.WorkflowStep{
			{StepID: "step-one", Required: true, AgentID: "agent-one"},
		},
	}
	if err := firstRegistry.RegisterWorkflow(env["VAOS_AGENTIC_JWT_APP_ID"], workflow); err != nil {
		t.Fatal(err)
	}
	if len(private) != ed25519.PrivateKeySize {
		t.Fatal("unexpected proof key size")
	}

	reopened, err := newAgenticJWTRegistry(getenv, now)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.Latest(env["VAOS_AGENTIC_JWT_APP_ID"], "agent-one")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RegistrationID != registration.RegistrationID || loaded.Checksum != registration.Checksum {
		t.Fatalf("reopened registration = %#v, want %#v", loaded, registration)
	}
	request := agenticjwt.TokenRequest{
		GrantType:        "agent_checksum",
		AgentID:          "agent-one",
		ComputedChecksum: loaded.Checksum,
		WorkflowEnabled:  true,
		WorkflowID:       "workflow-one",
		WorkflowStep:     "step-one",
		RequestedScopes:  []string{"smoke:run"},
		Audience:         agenticjwt.Audience{"https://resource.example.test"},
	}
	if _, err := reopened.ValidateRequest(env["VAOS_AGENTIC_JWT_APP_ID"], request); err != nil {
		t.Fatalf("reopened workflow validation: %v", err)
	}
}

func scopedTransportToken(t *testing.T, authority *agenticjwt.Authority, clientID, clientSecret, scope string) string {
	t.Helper()
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {scope},
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	authority.HandleClientCredentials(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("client credentials status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.AccessToken == "" {
		t.Fatal("client credentials response omitted access_token")
	}
	return response.AccessToken
}

type agenticTestAuditRecorder struct{}

func (agenticTestAuditRecorder) Record(entry agenticjwt.AuditEntry) (agenticjwt.AuditEntry, error) {
	return entry, nil
}
