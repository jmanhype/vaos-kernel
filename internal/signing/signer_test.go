package signing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewSigner_GeneratesKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.key")

	s, err := NewSigner(keyPath)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if len(s.pubKey) != 32 {
		t.Fatalf("expected 32-byte public key, got %d", len(s.pubKey))
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key file not created: %v", err)
	}
}

func TestNewSigner_LoadsExistingKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.key")

	s1, err := NewSigner(keyPath)
	if err != nil {
		t.Fatalf("first NewSigner: %v", err)
	}

	s2, err := NewSigner(keyPath)
	if err != nil {
		t.Fatalf("second NewSigner: %v", err)
	}

	if s1.PublicKeyHex() != s2.PublicKeyHex() {
		t.Fatalf("loaded key differs: %s vs %s", s1.PublicKeyHex(), s2.PublicKeyHex())
	}
}

func TestSignVerify_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSigner(filepath.Join(dir, "test.key"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	data := []byte("test attestation hash abc123")
	sig := s.Sign(data)

	if !s.Verify(data, sig) {
		t.Fatal("valid signature rejected")
	}
}

func TestVerify_RejectsTamperedData(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSigner(filepath.Join(dir, "test.key"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	data := []byte("original data")
	sig := s.Sign(data)

	if s.Verify([]byte("tampered data"), sig) {
		t.Fatal("tampered data should not verify")
	}
}

func TestVerify_RejectsInvalidHex(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSigner(filepath.Join(dir, "test.key"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	if s.Verify([]byte("data"), "not-hex!") {
		t.Fatal("invalid hex should not verify")
	}
}
