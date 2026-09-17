package agenticjwt

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleToken(t *testing.T) {
	setup := newTestAuthority(t)
	body, err := json.Marshal(setup.request)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	setup.authority.HandleToken(recorder, httptest.NewRequest(http.MethodPost, "/v1/intent/token", strings.NewReader(string(body))))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response TokenResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.TokenType != "Bearer" || response.AccessToken == "" {
		t.Fatalf("response = %#v", response)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("token response is cacheable")
	}
}

func TestHandleTokenOAuthError(t *testing.T) {
	setup := newTestAuthority(t)
	request := setup.request
	request.GrantType = "client_credentials"
	body, _ := json.Marshal(request)
	recorder := httptest.NewRecorder()
	setup.authority.HandleToken(recorder, httptest.NewRequest(http.MethodPost, "/v1/intent/token", strings.NewReader(string(body))))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response Error
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Code != "unsupported_grant_type" {
		t.Fatalf("error = %#v", response)
	}
}

func TestHandleRegistration(t *testing.T) {
	setup := newTestAuthority(t)
	spec := testSpec()
	spec.AgentID = "registered-over-http"
	spec.Prompt = "Register this agent."
	spec.Tools = []Tool{{
		Name:        "tool",
		Signature:   "tool()",
		Description: "Test tool",
	}}
	spec.Configuration = map[string]any{"model_name": "test"}

	body, err := json.Marshal(map[string]any{
		"agent_components": spec,
		"public_key":       base64.RawURLEncoding.EncodeToString(setup.agentPublic),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/intent/register/agent", strings.NewReader(string(body)))
	recorder := httptest.NewRecorder()
	setup.authority.HandleRegistration(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response AgentRegistrationResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.AgentID != spec.AgentID || response.RegistrationID == "" || response.Checksum == "" {
		t.Fatalf("response = %#v", response)
	}
	if strings.Contains(recorder.Body.String(), "Register this agent.") {
		t.Fatal("registration response leaked agent prompt")
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("registration response is cacheable")
	}

	tokenBody, err := json.Marshal(TokenRequest{
		GrantType:        "agent_checksum",
		AgentID:          response.AgentID,
		ComputedChecksum: response.Checksum,
		RequestedScopes:  []string{"repo:write"},
		Audience:         Audience{"https://api.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tokenRecorder := httptest.NewRecorder()
	setup.authority.HandleToken(
		tokenRecorder,
		httptest.NewRequest(http.MethodPost, "/v1/intent/token", strings.NewReader(string(tokenBody))),
	)
	if tokenRecorder.Code != http.StatusOK {
		t.Fatalf("token status = %d body = %s", tokenRecorder.Code, tokenRecorder.Body.String())
	}
	var tokenResponse TokenResponse
	if err := json.Unmarshal(tokenRecorder.Body.Bytes(), &tokenResponse); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.authority.Verify(tokenResponse.AccessToken, "https://api.example.test"); err != nil {
		t.Fatalf("registered token did not verify: %v", err)
	}
}

func TestHandleRegistrationRejectsBadPublicKeyAndUnknownFields(t *testing.T) {
	setup := newTestAuthority(t)
	spec := testSpec()
	spec.AgentID = "bad-registration"

	valid, _ := json.Marshal(map[string]any{
		"agent_components": spec,
		"public_key":       "not-base64",
	})
	recorder := httptest.NewRecorder()
	setup.authority.HandleRegistration(recorder, httptest.NewRequest(http.MethodPost, "/v1/intent/register/agent", strings.NewReader(string(valid))))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("bad key status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response Error
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Code != "invalid_request" {
		t.Fatalf("bad key error = %#v", response)
	}

	unknown, _ := json.Marshal(map[string]any{
		"agent_components": spec,
		"public_key":       base64.RawURLEncoding.EncodeToString(setup.agentPublic),
		"unexpected":       true,
	})
	recorder = httptest.NewRecorder()
	setup.authority.HandleRegistration(recorder, httptest.NewRequest(http.MethodPost, "/v1/intent/register/agent", strings.NewReader(string(unknown))))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown-field status = %d body = %s", recorder.Code, recorder.Body.String())
	}
}
