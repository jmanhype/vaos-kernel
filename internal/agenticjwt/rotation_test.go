package agenticjwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSigningKeyRotationKeepsPreviousVerificationOverlap(t *testing.T) {
	setup := newTestAuthority(t)
	older, _, err := setup.authority.Mint("app-one", setup.request)
	if err != nil {
		t.Fatal(err)
	}
	_, replacement, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := setup.authority.RotateSigningKey(replacement, "security-admin"); err != nil {
		t.Fatal(err)
	}
	keySet := setup.authority.JWKS()
	if len(keySet.Keys) != 2 || keySet.Keys[0].Kid == keySet.Keys[1].Kid {
		t.Fatalf("rotated JWKS = %#v, want two distinct keys", keySet.Keys)
	}
	if _, err := setup.authority.Verify(older.AccessToken, "https://api.example.test"); err != nil {
		t.Fatalf("old token during overlap: %v", err)
	}
	newer, _, err := setup.authority.Mint("app-one", setup.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := setup.authority.Verify(newer.AccessToken, "https://api.example.test"); err != nil {
		t.Fatalf("new token after rotation: %v", err)
	}
	if err := setup.authority.RotateSigningKey(replacement, "security-admin"); err == nil {
		t.Fatal("accepted reuse of an active signing key")
	}
}
