package agenticjwt

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestAuthorityJWKSMatchesTokenKid(t *testing.T) {
	setup := newTestAuthority(t)
	keySet := setup.authority.JWKS()
	if len(keySet.Keys) != 1 {
		t.Fatalf("JWKS keys = %#v", keySet.Keys)
	}
	key := keySet.Keys[0]
	if key.Kty != "OKP" || key.Crv != "Ed25519" || key.Alg != "EdDSA" || key.Use != "sig" || key.Kid == "" {
		t.Fatalf("JWK = %#v", key)
	}
	thumbprint, err := key.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if key.Kid != thumbprint {
		t.Fatalf("kid = %s, want RFC 7638 thumbprint %s", key.Kid, thumbprint)
	}

	response, _, err := setup.authority.Mint("app-one", setup.request)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := jwt.NewParser().ParseUnverified(response.AccessToken, &Claims{})
	if err != nil {
		t.Fatal(err)
	}
	if token.Header["alg"] != jwt.SigningMethodEdDSA.Alg() || token.Header["kid"] != key.Kid {
		t.Fatalf("token header = %#v, want EdDSA/%s", token.Header, key.Kid)
	}
}

func TestHandleJWKS(t *testing.T) {
	setup := newTestAuthority(t)
	recorder := httptest.NewRecorder()
	setup.authority.HandleJWKS(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %s", got)
	}
	var keySet JWKS
	if err := json.Unmarshal(recorder.Body.Bytes(), &keySet); err != nil {
		t.Fatal(err)
	}
	if len(keySet.Keys) != 1 || keySet.Keys[0].Kid == "" {
		t.Fatalf("JWKS = %#v", keySet)
	}

	recorder = httptest.NewRecorder()
	setup.authority.HandleJWKS(recorder, httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", recorder.Code)
	}
}
