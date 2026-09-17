// Package agenticresource provides standalone resource-server verification for
// Agentic JWT intent tokens.
package agenticresource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"vaos-kernel/internal/agenticjwt"
)

const jwksMaxBytes = 1024 * 1024

// JWKSProvider supplies Authority signing keys.
type JWKSProvider interface {
	KeySet(ctx context.Context) (agenticjwt.JWKS, error)
}

// HTTPJWKSProvider fetches a strict JSON JWKS from an HTTPS endpoint.
type HTTPJWKSProvider struct {
	endpoint *url.URL
	client   *http.Client
}

// HTTPJWKSOption configures an HTTPJWKSProvider.
type HTTPJWKSOption func(*HTTPJWKSProvider) error

// WithHTTPClient installs a custom HTTP client. It is primarily intended for
// tests and private PKI transports.
func WithHTTPClient(client *http.Client) HTTPJWKSOption {
	return func(provider *HTTPJWKSProvider) error {
		if client == nil {
			return errors.New("JWKS HTTP client is required")
		}
		provider.client = client
		return nil
	}
}

// NewHTTPJWKSProvider creates a strict JWKS HTTP provider.
func NewHTTPJWKSProvider(endpoint string, options ...HTTPJWKSOption) (*HTTPJWKSProvider, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("JWKS endpoint must be an HTTPS URL")
	}
	provider := &HTTPJWKSProvider{endpoint: parsed, client: &http.Client{Timeout: 10 * time.Second}}
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(provider); err != nil {
			return nil, err
		}
	}
	return provider, nil
}

// KeySet fetches and validates a public key set.
func (provider *HTTPJWKSProvider) KeySet(ctx context.Context) (agenticjwt.JWKS, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.endpoint.String(), nil)
	if err != nil {
		return agenticjwt.JWKS{}, fmt.Errorf("create JWKS request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := provider.client.Do(request)
	if err != nil {
		return agenticjwt.JWKS{}, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return agenticjwt.JWKS{}, fmt.Errorf("JWKS endpoint returned %d", response.StatusCode)
	}
	mediaType, params, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(params) != 0 {
		return agenticjwt.JWKS{}, errors.New("JWKS endpoint must return application/json")
	}

	decoder := json.NewDecoder(io.LimitReader(response.Body, jwksMaxBytes+1))
	decoder.DisallowUnknownFields()
	var keySet agenticjwt.JWKS
	if err := decoder.Decode(&keySet); err != nil {
		return agenticjwt.JWKS{}, fmt.Errorf("decode JWKS: %w", err)
	}
	if decoder.More() {
		return agenticjwt.JWKS{}, errors.New("JWKS response contains trailing JSON")
	}
	if len(keySet.Keys) == 0 {
		return agenticjwt.JWKS{}, errors.New("JWKS response contains no keys")
	}
	for _, key := range keySet.Keys {
		if _, err := key.PublicKey(); err != nil {
			return agenticjwt.JWKS{}, fmt.Errorf("validate JWKS key: %w", err)
		}
	}
	return keySet, nil
}

// Proof binds an intent token to a method, target, body, and agent key.
type Proof struct {
	Challenge []byte
	Signature []byte
}

// ProofChallenge constructs the deterministic proof challenge for a request.
func ProofChallenge(method, target string, body []byte, token string) []byte {
	bodyHash := sha256.Sum256(body)
	tokenHash := sha256.Sum256([]byte(token))
	var challenge bytes.Buffer
	challenge.WriteString(strings.ToUpper(method))
	challenge.WriteByte('\n')
	challenge.WriteString(target)
	challenge.WriteByte('\n')
	challenge.WriteString(hex.EncodeToString(bodyHash[:]))
	challenge.WriteByte('\n')
	challenge.WriteString(hex.EncodeToString(tokenHash[:]))
	return challenge.Bytes()
}

// Config configures a standalone resource-server Verifier.
type Config struct {
	Issuer   string
	Audience string
	JWKS     JWKSProvider
	Now      func() time.Time
}

// Verifier validates Agentic JWTs at a resource server.
type Verifier struct {
	issuer   string
	audience string
	jwks     JWKSProvider
	now      func() time.Time
}

// NewValidator is a deprecated spelling retained for API symmetry.
func NewValidator(config Config) (*Verifier, error) { return NewVerifier(config) }

// NewVerifier constructs a Verifier.
func NewVerifier(config Config) (*Verifier, error) {
	if config.Issuer == "" {
		return nil, errors.New("issuer is required")
	}
	if config.Audience == "" {
		return nil, errors.New("audience is required")
	}
	if config.JWKS == nil {
		return nil, errors.New("JWKS provider is required")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Verifier{issuer: config.Issuer, audience: config.Audience, jwks: config.JWKS, now: now}, nil
}

type contextKey struct{}

// Verify validates the JWT signature and required claims, then verifies the
// agent proof-of-possession signature.
func (verifier *Verifier) Verify(ctx context.Context, tokenString string, proof Proof) (*agenticjwt.Claims, error) {
	if tokenString == "" {
		return nil, errors.New("intent token is required")
	}
	if len(proof.Signature) == 0 {
		return nil, errors.New("agent proof signature is required")
	}
	keySet, err := verifier.jwks.KeySet(ctx)
	if err != nil {
		return nil, fmt.Errorf("load Authority JWKS: %w", err)
	}
	parsed, err := jwt.ParseWithClaims(
		tokenString,
		&agenticjwt.Claims{},
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodEdDSA {
				return nil, errors.New("unexpected signing method")
			}
			keyID, ok := token.Header["kid"].(string)
			if !ok || keyID == "" {
				return nil, errors.New("missing signing key kid")
			}
			for _, jwk := range keySet.Keys {
				if jwk.Kid != keyID {
					continue
				}
				public, err := jwk.PublicKey()
				if err != nil {
					return nil, err
				}
				return public, nil
			}
			return nil, errors.New("unknown signing key kid")
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(verifier.issuer),
		jwt.WithAudience(verifier.audience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(verifier.now),
	)
	if err != nil {
		return nil, fmt.Errorf("verify intent token: %w", err)
	}
	claims, ok := parsed.Claims.(*agenticjwt.Claims)
	if !ok || !parsed.Valid {
		return nil, errors.New("invalid intent token claims")
	}
	if err := verifier.validateClaims(claims); err != nil {
		return nil, err
	}
	public, err := claims.Confirmation.JWK.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("invalid confirmation key: %w", err)
	}
	if err := agenticjwt.VerifyProof(public, proof.Challenge, proof.Signature); err != nil {
		return nil, errors.New("agent proof-of-possession failed")
	}
	return claims, nil
}

func (verifier *Verifier) validateClaims(claims *agenticjwt.Claims) error {
	if claims.Subject == "" || claims.ID == "" || claims.IssuedAt == nil {
		return errors.New("required registered claims are missing")
	}
	if claims.Scope == "" || len(claims.Audience) == 0 {
		return errors.New("scope and audience are required")
	}
	if claims.Intent.ExecutedBy == "" || claims.Intent.ExecutedBy != claims.Subject {
		return errors.New("intent.executed_by must equal subject")
	}
	if claims.Intent.DelegationChain == "" || claims.Intent.StepSequenceHash == "" {
		return errors.New("intent integrity claims are required")
	}
	if claims.AgentProof.AgentChecksum == "" || claims.AgentProof.RegistrationID == "" {
		return errors.New("agent proof claims are required")
	}
	if _, err := claims.Confirmation.JWK.PublicKey(); err != nil {
		return fmt.Errorf("invalid confirmation JWK: %w", err)
	}
	return nil
}

// RequireScope returns middleware that enforces an intent-token scope and a
// request-bound agent proof before invoking next.
func (verifier *Verifier) RequireScope(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authorization := request.Header.Get("Authorization")
		token, ok := strings.CutPrefix(authorization, "Bearer ")
		if !ok || token == "" || token == authorization {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		encodedProof := request.Header.Get("X-VAOS-Agent-Proof")
		if encodedProof == "" {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		signature, err := base64.RawURLEncoding.DecodeString(encodedProof)
		if err != nil {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 1024*1024+1))
		if err != nil || len(body) > 1024*1024 {
			http.Error(writer, "request body is too large", http.StatusRequestEntityTooLarge)
			return
		}
		_ = request.Body.Close()
		request.Body = io.NopCloser(bytes.NewReader(body))
		expectedChallenge := ProofChallenge(request.Method, request.URL.RequestURI(), body, token)
		claims, err := verifier.Verify(request.Context(), token, Proof{
			Challenge: expectedChallenge,
			Signature: signature,
		})
		if err != nil {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !containsScope(claims.Scope, scope) {
			http.Error(writer, "forbidden", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(request.Context(), contextKey{}, claims)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

// ClaimsFromContext returns claims installed by RequireScope.
func ClaimsFromContext(ctx context.Context) *agenticjwt.Claims {
	claims, _ := ctx.Value(contextKey{}).(*agenticjwt.Claims)
	return claims
}

func containsScope(granted, required string) bool {
	for _, scope := range strings.Fields(granted) {
		if subtle.ConstantTimeCompare([]byte(scope), []byte(required)) == 1 {
			return true
		}
	}
	return false
}
