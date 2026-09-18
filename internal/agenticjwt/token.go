package agenticjwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const defaultTTL = 300 * time.Second

// Transport OAuth scopes. Credentials are scoped least-privilege by role.
const (
	ScopeRegisterAgent      = "agentic:register-agent"
	ScopeRegisterWorkflow   = "agentic:register-workflow"
	ScopeMintIntentToken    = "generate:intent-token"
	ScopeRevokeRegistration = "agentic:revoke-registration"
	ScopeRotateSigningKey   = "agentic:rotate-signing-key"
)

// Claims is the P0 Agentic JWT claim set.
type Claims struct {
	jwt.RegisteredClaims
	Scope        string       `json:"scope"`
	Confirmation Confirmation `json:"cnf"`
	Intent       IntentClaims `json:"intent"`
	AgentProof   AgentProof   `json:"agent_proof"`
}

// TransportClaims is the internal OAuth client-credential access-token shape.
// TokenUse prevents an intent JWT from being replayed as transport.
type TransportClaims struct {
	jwt.RegisteredClaims
	ClientID string `json:"client_id"`
	TokenUse string `json:"token_use"`
	Scope    string `json:"scope"`
}

type signingKey struct {
	private ed25519.PrivateKey
	jwk     JWK
	kid     string
}

type transportClient struct {
	id         string
	secretHash [sha256.Size]byte
	scopes     []string
}

// Authority mints and verifies P0 Agentic JWT tokens.
type Authority struct {
	appID            string
	issuer           string
	ttl              time.Duration
	signingMu        sync.RWMutex
	activeKey        signingKey
	pastKeys         []signingKey
	registry         RegistryAPI
	audit            AuditRecorder
	now              func() time.Time
	randomRead       func([]byte) (int, error)
	transportClients map[string]transportClient
}

// RegistryAPI is the authority's registry dependency. Storage can be swapped
// without coupling protocol validation to a database implementation.
type RegistryAPI interface {
	ValidateRequest(appID string, request TokenRequest) (AgentRegistration, error)
	Register(appID string, spec AgentSpec, publicKey ed25519.PublicKey) (AgentRegistration, error)
	RegisterWorkflow(appID string, definition WorkflowDefinition) error
	Registration(appID, registrationID string) (AgentRegistration, error)
	RevokeRegistration(appID, registrationID, reason string) error
}

// NewAuthority creates an Agentic JWT authority. signingKey signs intent
// tokens; each registered agent retains its own proof-of-possession key.
func NewAuthority(
	appID string,
	issuer string,
	signingKey ed25519.PrivateKey,
	registry RegistryAPI,
	ttl time.Duration,
	now func() time.Time,
	options ...AuthorityOption,
) (*Authority, error) {
	if appID == "" {
		return nil, invalidRequest("app_id is required")
	}
	if issuer == "" {
		return nil, invalidRequest("issuer is required")
	}
	if len(signingKey) != ed25519.PrivateKeySize {
		return nil, invalidRequest("Ed25519 signing key is required")
	}
	if registry == nil {
		return nil, invalidRequest("registry is required")
	}
	if ttl <= 0 {
		ttl = defaultTTL
	}
	if now == nil {
		now = time.Now
	}
	activeKey, err := newSigningKey(signingKey)
	if err != nil {
		return nil, fmt.Errorf("compute authority signing key id: %w", err)
	}
	authority := &Authority{
		appID:            appID,
		issuer:           issuer,
		ttl:              ttl,
		activeKey:        activeKey,
		registry:         registry,
		now:              now,
		randomRead:       rand.Read,
		transportClients: make(map[string]transportClient),
	}
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(authority); err != nil {
			return nil, err
		}
	}
	return authority, nil
}

func newSigningKey(private ed25519.PrivateKey) (signingKey, error) {
	jwk := publicJWK(private.Public().(ed25519.PublicKey))
	kid, err := jwk.Thumbprint()
	if err != nil {
		return signingKey{}, err
	}
	jwk.Kid = kid
	return signingKey{private: append(ed25519.PrivateKey(nil), private...), jwk: jwk, kid: kid}, nil
}

// RotateSigningKey makes newKey active while retaining the previous key for
// verification overlap. Existing tokens remain valid until they expire.
func (a *Authority) RotateSigningKey(newKey ed25519.PrivateKey, actor string) error {
	if len(newKey) != ed25519.PrivateKeySize {
		return invalidRequest("Ed25519 signing key is required")
	}
	if strings.TrimSpace(actor) == "" {
		return invalidRequest("rotation actor is required")
	}
	replacement, err := newSigningKey(newKey)
	if err != nil {
		return fmt.Errorf("compute rotated signing key id: %w", err)
	}
	a.signingMu.Lock()
	if replacement.kid == a.activeKey.kid {
		a.signingMu.Unlock()
		return invalidRequest("new signing key must differ from active key")
	}
	for _, past := range a.pastKeys {
		if replacement.kid == past.kid {
			a.signingMu.Unlock()
			return invalidRequest("new signing key was previously used")
		}
	}
	previous := a.activeKey
	a.activeKey = replacement
	a.pastKeys = append(a.pastKeys, previous)
	a.signingMu.Unlock()
	if a.audit != nil {
		if err := a.recordAudit(AuditEntry{
			AgentID: actor,
			Action:  "agentic_signing_key_rotated",
			Status:  "success",
			Details: map[string]string{"new_kid": replacement.kid, "previous_kid": previous.kid},
		}); err != nil {
			// Preserve the pre-rotation state if the required audit event cannot be recorded.
			a.signingMu.Lock()
			a.activeKey = previous
			a.pastKeys = a.pastKeys[:len(a.pastKeys)-1]
			a.signingMu.Unlock()
			return serverError(err)
		}
	}
	return nil
}

// RevokeRegistration durably revokes a registration and invalidates its tokens.
func (a *Authority) RevokeRegistration(appID, registrationID, reason string) error {
	if err := a.registry.RevokeRegistration(appID, registrationID, reason); err != nil {
		return err
	}
	return nil
}

// Mint validates an agent_checksum request and returns an OAuth-shaped token.
func (a *Authority) Mint(appID string, request TokenRequest) (TokenResponse, *Claims, error) {
	registration, err := a.registry.ValidateRequest(appID, request)
	if err != nil {
		if auditErr := a.recordAudit(a.mintAuditEntry(request, nil, err)); auditErr != nil {
			return TokenResponse{}, nil, serverError(auditErr)
		}
		return TokenResponse{}, nil, err
	}

	now := a.now().UTC()
	expires := now.Add(a.ttl)
	jti, err := a.newJTI()
	if err != nil {
		err = fmt.Errorf("generate jti: %w", err)
		if auditErr := a.recordAudit(a.mintAuditEntry(request, nil, err)); auditErr != nil {
			return TokenResponse{}, nil, serverError(auditErr)
		}
		return TokenResponse{}, nil, serverError(err)
	}
	scopes := normalizeScopes(request.RequestedScopes)
	var chain []string
	var completed []string
	if request.DelegationContext == nil {
	} else {
		chain = request.DelegationContext.Chain
		completed = request.DelegationContext.CompletedSteps
	}

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    a.issuer,
			Subject:   registration.AgentID,
			Audience:  audienceClaimStrings(request.Audience),
			ExpiresAt: jwt.NewNumericDate(expires),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		Scope:        strings.Join(scopes, " "),
		Confirmation: Confirmation{JWK: publicJWK(registration.PublicKey)},
		Intent: IntentClaims{
			WorkflowID:       request.WorkflowID,
			WorkflowStep:     request.WorkflowStep,
			ExecutedBy:       registration.AgentID,
			DelegationChain:  truncatedHash(append(append([]string{}, chain...), registration.AgentID)),
			StepSequenceHash: truncatedHash(append(append([]string{}, completed...), request.WorkflowStep)),
		},
		AgentProof: AgentProof{
			AgentChecksum:  registration.Checksum,
			RegistrationID: registration.RegistrationID,
		},
	}
	a.signingMu.RLock()
	active := a.activeKey
	a.signingMu.RUnlock()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = active.kid
	signed, err := token.SignedString(active.private)
	if err != nil {
		err = fmt.Errorf("sign intent token: %w", err)
		if auditErr := a.recordAudit(a.mintAuditEntry(request, nil, err)); auditErr != nil {
			return TokenResponse{}, nil, serverError(auditErr)
		}
		return TokenResponse{}, nil, serverError(err)
	}
	if err := a.recordAudit(a.mintAuditEntry(request, &jti, nil)); err != nil {
		return TokenResponse{}, nil, serverError(err)
	}
	return TokenResponse{
		AccessToken: signed,
		TokenType:   "Bearer",
		ExpiresIn:   int(a.ttl.Seconds()),
		Scope:       claims.Scope,
	}, claims, nil
}

// JWKS returns the public Ed25519 Authority signing key. The kid is its RFC
// 7638 thumbprint and matches the minted JWT header.
func (a *Authority) JWKS() JWKS {
	a.signingMu.RLock()
	defer a.signingMu.RUnlock()
	keys := make([]JWK, 0, len(a.pastKeys)+1)
	keys = append(keys, a.activeKey.jwk)
	for _, past := range a.pastKeys {
		keys = append(keys, past.jwk)
	}
	return JWKS{Keys: keys}
}

// Verify validates signature, issuer, audience, expiry, required claims, and
// that the embedded agent proof still matches the latest registration.
func (a *Authority) Verify(tokenString string, expectedAudience string) (*Claims, error) {
	parsed, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (any, error) {
			keyID, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("unknown or missing signing key kid")
			}
			key, err := a.signingKeyByID(keyID)
			if err != nil {
				return nil, err
			}
			return key.private.Public(), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(a.issuer),
		jwt.WithAudience(expectedAudience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(a.now),
	)
	if err != nil {
		if auditErr := a.recordAudit(a.verifyAuditEntry("", nil, err)); auditErr != nil {
			return nil, serverError(auditErr)
		}
		return nil, newError("invalid_token", err.Error(), 401)
	}
	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		err := newError("invalid_token", "invalid token claims", 401)
		if auditErr := a.recordAudit(a.verifyAuditEntry("", nil, err)); auditErr != nil {
			return nil, serverError(auditErr)
		}
		return nil, err
	}
	if err := a.validateClaims(claims); err != nil {
		if auditErr := a.recordAudit(a.verifyAuditEntry("", nil, err)); auditErr != nil {
			return nil, serverError(auditErr)
		}
		return nil, err
	}
	if err := a.recordAudit(a.verifyAuditEntry(claims.ID, claims, nil)); err != nil {
		return nil, serverError(err)
	}
	return claims, nil
}

func (a *Authority) validateClaims(claims *Claims) error {
	if claims.Issuer != a.issuer || claims.Subject == "" || claims.ID == "" {
		return newError("invalid_token", "required registered claims are missing", 401)
	}
	if len(claims.Audience) == 0 || claims.Scope == "" {
		return newError("invalid_token", "audience and scope are required", 401)
	}
	if claims.Intent.ExecutedBy == "" || claims.Intent.ExecutedBy != claims.Subject {
		return newError("invalid_token", "intent.executed_by must equal subject", 401)
	}
	if claims.Intent.DelegationChain == "" || claims.Intent.StepSequenceHash == "" {
		return newError("invalid_token", "intent integrity hashes are required", 401)
	}
	if claims.AgentProof.AgentChecksum == "" || claims.AgentProof.RegistrationID == "" {
		return newError("invalid_token", "agent proof claims are required", 401)
	}
	registration, err := a.registry.Registration(a.appID, claims.AgentProof.RegistrationID)
	if err != nil || registration.AgentID != claims.Subject || registration.Checksum != claims.AgentProof.AgentChecksum {
		return newError("invalid_token", "agent proof does not match current registration", 401)
	}
	if !registration.RevokedAt.IsZero() {
		return ErrRegistrationRevoked
	}
	if string(registration.PublicKey) != string(mustPublicJWK(claims.Confirmation.JWK)) {
		return newError("invalid_token", "confirmation key does not match registration", 401)
	}
	return nil
}

func (a *Authority) signingKeyByID(keyID string) (signingKey, error) {
	a.signingMu.RLock()
	defer a.signingMu.RUnlock()
	if keyID == a.activeKey.kid {
		return a.activeKey, nil
	}
	for _, past := range a.pastKeys {
		if keyID == past.kid {
			return past, nil
		}
	}
	return signingKey{}, fmt.Errorf("unknown signing key kid")
}

// SignProof signs a challenge with an agent's Ed25519 proof-of-possession key.
func SignProof(privateKey ed25519.PrivateKey, challenge []byte) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, invalidRequest("Ed25519 proof key is required")
	}
	return ed25519.Sign(privateKey, challenge), nil
}

// VerifyProof verifies a proof-of-possession challenge signature.
func VerifyProof(publicKey ed25519.PublicKey, challenge, signature []byte) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return invalidRequest("Ed25519 public key is required")
	}
	if !ed25519.Verify(publicKey, challenge, signature) {
		return newError("invalid_proof", "proof-of-possession signature is invalid", 401)
	}
	return nil
}

func (a *Authority) newJTI() (string, error) {
	raw := make([]byte, 16)
	if _, err := a.randomRead(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func normalizeScopes(scopes []string) []string {
	seen := make(map[string]struct{}, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if _, exists := seen[scope]; exists {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	return out
}

func audienceClaimStrings(audience Audience) jwt.ClaimStrings {
	return jwt.ClaimStrings(audience)
}

func truncatedHash(values []string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "|")))
	return hex.EncodeToString(sum[:])[:16]
}

func mustPublicJWK(jwk JWK) ed25519.PublicKey {
	key, err := jwk.publicKey()
	if err != nil {
		return nil
	}
	return key
}
