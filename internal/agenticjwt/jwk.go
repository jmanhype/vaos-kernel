package agenticjwt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// JWK is the Ed25519 public JWK used for proof-of-possession key confirmation.
type JWK struct {
	Kid string `json:"kid,omitempty"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

// JWKS is the public Authority signing-key set used by resource servers.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

func publicJWK(publicKey ed25519.PublicKey) JWK {
	return JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(publicKey),
		Alg: "EdDSA",
		Use: "sig",
	}
}

func (jwk JWK) publicKey() (ed25519.PublicKey, error) {
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported confirmation JWK %s/%s", jwk.Kty, jwk.Crv)
	}
	raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("invalid confirmation JWK x: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("confirmation JWK has invalid Ed25519 key size")
	}
	return ed25519.PublicKey(raw), nil
}

// PublicKey returns the Ed25519 public key represented by this JWK.
func (jwk JWK) PublicKey() (ed25519.PublicKey, error) {
	return jwk.publicKey()
}

// Thumbprint computes the RFC 7638-style SHA-256 JWK thumbprint for the
// required Ed25519 members {crv,kty,x}.
func (jwk JWK) Thumbprint() (string, error) {
	if _, err := jwk.publicKey(); err != nil {
		return "", err
	}
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q}`, jwk.Crv, jwk.Kty, jwk.X)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// UnmarshalJSON lets Audience accept a string or an array of strings.
func (audience *Audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*audience = Audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("audience must be a string or array of strings")
	}
	*audience = many
	return nil
}

// MarshalJSON preserves the single-string form for a one-element audience.
func (audience Audience) MarshalJSON() ([]byte, error) {
	if len(audience) == 1 {
		return json.Marshal(audience[0])
	}
	return json.Marshal([]string(audience))
}
