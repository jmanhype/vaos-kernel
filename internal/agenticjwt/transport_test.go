package agenticjwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestScopedOAuthClientCredentialsTransport(t *testing.T) {
	setup := newTestAuthority(t)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthority(
		"app-one",
		"https://idp.example.test",
		private,
		setup.registry,
		time.Minute,
		func() time.Time { return time.Now().UTC() },
		WithTransportClients(
			TransportClientCredential{
				ClientID:     "registrar",
				ClientSecret: "registrar-test-secret-with-32-bytes",
				Scopes:       []string{ScopeRegisterAgent, ScopeMintIntentToken},
			},
			TransportClientCredential{
				ClientID:     "workflow-admin",
				ClientSecret: "workflow-admin-test-secret-32-bytes!",
				Scopes:       []string{ScopeRegisterWorkflow},
			},
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	form := strings.NewReader(
		"grant_type=client_credentials&client_id=registrar&client_secret=registrar-test-secret-with-32-bytes&scope=agentic%3Aregister-agent+generate%3Aintent-token",
	)
	request := httptest.NewRequest(http.MethodPost, "/v1/oauth/token", form)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	authority.HandleClientCredentials(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("client credential status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var tokenResponse TokenResponse
	if err := decodeTestJSON(recorder.Body.Bytes(), &tokenResponse); err != nil {
		t.Fatal(err)
	}
	claims, err := authority.VerifyTransport(tokenResponse.AccessToken, ScopeMintIntentToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ClientID != "registrar" || claims.Scope != ScopeRegisterAgent+" "+ScopeMintIntentToken {
		t.Fatalf("transport claims = %#v", claims)
	}

	intent, _, err := authority.Mint("app-one", setup.request)
	if err != nil {
		t.Fatal(err)
	}
	authorized := false
	handler := authority.RequireTransportScope(ScopeMintIntentToken, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		authorized = true
	}))
	for name, token := range map[string]string{
		"transport": tokenResponse.AccessToken,
		"intent":    intent.AccessToken,
	} {
		recorder := httptest.NewRecorder()
		protected := httptest.NewRequest(http.MethodPost, "/protected", nil)
		protected.Header.Set("Authorization", "Bearer "+token)
		handler.ServeHTTP(recorder, protected)
		want := http.StatusOK
		if name == "intent" {
			want = http.StatusUnauthorized
		}
		if recorder.Code != want {
			t.Fatalf("%s token status = %d, want %d", name, recorder.Code, want)
		}
	}
	if !authorized {
		t.Fatal("scoped transport token did not reach handler")
	}
}

func TestClientCredentialsEndpointFailsClosed(t *testing.T) {
	setup := newTestAuthority(t)
	authority, err := NewAuthority(
		"app-one",
		"https://idp.example.test",
		setup.signingPrivate,
		setup.registry,
		time.Minute,
		func() time.Time { return time.Now().UTC() },
		WithTransportClients(TransportClientCredential{
			ClientID:     "registrar",
			ClientSecret: "registrar-test-secret-with-32-bytes",
			Scopes:       []string{ScopeRegisterAgent},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{{
		name: "wrong grant",
		body: "grant_type=password&client_id=registrar&client_secret=registrar-test-secret-with-32-bytes&scope=agentic%3Aregister-agent",
	}, {
		name:       "wrong secret",
		body:       "grant_type=client_credentials&client_id=registrar&client_secret=wrong-secret-that-is-definitely-32-b&scope=agentic%3Aregister-agent",
		wantStatus: http.StatusUnauthorized,
	}, {
		name: "excess scope",
		body: "grant_type=client_credentials&client_id=registrar&client_secret=registrar-test-secret-with-32-bytes&scope=agentic%3Aregister-agent+agentic%3Aregister-workflow",
	}, {
		name: "missing scope",
		body: "grant_type=client_credentials&client_id=registrar&client_secret=registrar-test-secret-with-32-bytes",
	}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/oauth/token", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			recorder := httptest.NewRecorder()
			authority.HandleClientCredentials(recorder, request)
			wantStatus := test.wantStatus
			if wantStatus == 0 {
				wantStatus = http.StatusBadRequest
			}
			if recorder.Code != wantStatus {
				t.Fatalf("status = %d want %d body = %s", recorder.Code, wantStatus, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "client_secret") {
				t.Fatal("response disclosed credential material")
			}
		})
	}
}

func TestTransportClientsRejectSharedSecrets(t *testing.T) {
	setup := newTestAuthority(t)
	_, err := NewAuthority(
		"app-one",
		"https://idp.example.test",
		setup.signingPrivate,
		setup.registry,
		time.Minute,
		setup.authority.now,
		WithTransportClients(
			TransportClientCredential{
				ClientID:     "registrar",
				ClientSecret: "shared-test-secret-with-exactly-32-b",
				Scopes:       []string{ScopeRegisterAgent},
			},
			TransportClientCredential{
				ClientID:     "workflow-admin",
				ClientSecret: "shared-test-secret-with-exactly-32-b",
				Scopes:       []string{ScopeRegisterWorkflow},
			},
		),
	)
	if err == nil {
		t.Fatal("accepted the same secret for two OAuth clients")
	}
}
