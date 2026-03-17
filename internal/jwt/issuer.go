package jwt

import (
	"errors"
	"fmt"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"vaos-kernel/internal/nhi"
	"vaos-kernel/pkg/models"
)

const tokenTTL = 60 * time.Second

// Issuer signs and verifies ephemeral intent-scoped JWTs.
type Issuer struct {
	signingKey []byte
	registry   *nhi.Registry
	clock      func() time.Time
}

// Claims represent the exact one-intent scope of an issued token.
type Claims struct {
	AgentID           string `json:"agent_id"`
	IntentFingerprint string `json:"intent_fingerprint"`
	gjwt.RegisteredClaims
}

// NewIssuer constructs a JWT issuer for the provided signing key.
func NewIssuer(signingKey []byte, registry *nhi.Registry) (*Issuer, error) {
	if len(signingKey) == 0 {
		return nil, errors.New("new issuer: signing key is required")
	}
	if registry == nil {
		return nil, errors.New("new issuer: registry is required")
	}
	return &Issuer{
		signingKey: signingKey,
		registry:   registry,
		clock:      time.Now().UTC,
	}, nil
}

// Issue creates a token valid for exactly 60 seconds.
func (i *Issuer) Issue(agentID, intentFingerprint string) (string, models.TokenRecord, error) {
	if agentID == "" || intentFingerprint == "" {
		return "", models.TokenRecord{}, errors.New("issue token: agent id and fingerprint are required")
	}
	if _, err := i.registry.GetAgent(agentID); err != nil {
		return "", models.TokenRecord{}, err
	}

	now := i.clock().Truncate(time.Second)
	record := models.TokenRecord{
		TokenID:           fmt.Sprintf("%s-%d", agentID, now.UnixNano()),
		AgentID:           agentID,
		IntentFingerprint: intentFingerprint,
		IssuedAt:          now,
		ExpiresAt:         now.Add(tokenTTL),
		Status:            "issued",
	}
	claims := Claims{
		AgentID:           agentID,
		IntentFingerprint: intentFingerprint,
		RegisteredClaims: gjwt.RegisteredClaims{
			ID:        record.TokenID,
			Subject:   agentID,
			IssuedAt:  gjwt.NewNumericDate(record.IssuedAt),
			NotBefore: gjwt.NewNumericDate(record.IssuedAt),
			ExpiresAt: gjwt.NewNumericDate(record.ExpiresAt),
		},
	}

	token := gjwt.NewWithClaims(gjwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(i.signingKey)
	if err != nil {
		return "", models.TokenRecord{}, err
	}

	if err := i.registry.TrackToken(record); err != nil {
		return "", models.TokenRecord{}, err
	}
	if err := i.registry.StoreIntentFingerprint(agentID, intentFingerprint); err != nil {
		return "", models.TokenRecord{}, err
	}
	return signed, record, nil
}

// Verify validates a token signature, lifetime, registry state, and intent scope.
func (i *Issuer) Verify(tokenString, expectedFingerprint string) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("verify token: token is required")
	}
	if expectedFingerprint == "" {
		return nil, errors.New("verify token: expected fingerprint is required")
	}

	parser := gjwt.NewParser(
		gjwt.WithValidMethods([]string{gjwt.SigningMethodHS256.Name}),
		gjwt.WithTimeFunc(i.clock),
	)
	parsed, err := parser.ParseWithClaims(tokenString, &Claims{}, func(token *gjwt.Token) (interface{}, error) {
		return i.signingKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return nil, errors.New("verify token: invalid claims")
	}
	if claims.IntentFingerprint != expectedFingerprint {
		return nil, errors.New("verify token: fingerprint mismatch")
	}
	if claims.ExpiresAt == nil || claims.IssuedAt == nil {
		return nil, errors.New("verify token: missing time claims")
	}
	if claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time) != tokenTTL {
		return nil, errors.New("verify token: ttl must be exactly 60 seconds")
	}

	record, err := i.registry.Token(claims.ID)
	if err != nil {
		return nil, err
	}
	if record.Status == "revoked" {
		return nil, errors.New("verify token: token revoked")
	}
	if record.IntentFingerprint != expectedFingerprint {
		return nil, errors.New("verify token: registry fingerprint mismatch")
	}
	registryFingerprint, err := i.registry.IntentFingerprint(claims.AgentID)
	if err != nil {
		return nil, err
	}
	if registryFingerprint != expectedFingerprint {
		return nil, errors.New("verify token: current intent fingerprint mismatch")
	}
	_ = i.registry.MarkTokenUsed(record.TokenID, i.clock())
	return claims, nil
}
