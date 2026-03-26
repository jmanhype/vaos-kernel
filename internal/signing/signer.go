package signing

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Signer holds an Ed25519 keypair for signing audit attestations.
type Signer struct {
	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey
}

// NewSigner loads a keypair from keyPath, or generates and persists one if the file does not exist.
// Key file format: hex-encoded 32-byte seed on one line (64 hex chars).
func NewSigner(keyPath string) (*Signer, error) {
	data, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		return generateAndPersist(keyPath)
	}
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}

	seedHex := strings.TrimSpace(string(data))
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid signing key: expected %d hex-encoded seed bytes", ed25519.SeedSize)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	return &Signer{
		privKey: priv,
		pubKey:  priv.Public().(ed25519.PublicKey),
	}, nil
}

// Sign returns a hex-encoded Ed25519 signature over data.
func (s *Signer) Sign(data []byte) string {
	sig := ed25519.Sign(s.privKey, data)
	return hex.EncodeToString(sig)
}

// PublicKeyHex returns the hex-encoded 32-byte public key.
func (s *Signer) PublicKeyHex() string {
	return hex.EncodeToString(s.pubKey)
}

// Verify checks a hex-encoded signature against data using this signer's public key.
func (s *Signer) Verify(data []byte, sigHex string) bool {
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return ed25519.Verify(s.pubKey, data, sig)
}

func generateAndPersist(keyPath string) (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}

	seedHex := hex.EncodeToString(priv.Seed())
	if err := os.WriteFile(keyPath, []byte(seedHex+"\n"), 0600); err != nil {
		return nil, fmt.Errorf("write signing key: %w", err)
	}

	return &Signer{privKey: priv, pubKey: pub}, nil
}
