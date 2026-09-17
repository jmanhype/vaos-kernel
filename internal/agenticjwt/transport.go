package agenticjwt

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

const transportTokenUse = "client_credentials"

var (
	clientIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	scopePattern    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
)

// TransportClientCredential is a static OAuth client configured by the host.
// The secret is immediately reduced to a SHA-256 comparison digest.
type TransportClientCredential struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
}

// WithTransportClients installs scoped OAuth client credentials. At least one
// client is required when Agentic JWT endpoints are enabled.
func WithTransportClients(clients ...TransportClientCredential) AuthorityOption {
	return func(authority *Authority) error {
		if len(clients) == 0 {
			return invalidRequest("at least one OAuth transport client is required")
		}
		installed := make(map[string]transportClient, len(clients))
		seenSecrets := make(map[string]struct{}, len(clients))
		for _, client := range clients {
			if !clientIDPattern.MatchString(client.ClientID) {
				return invalidRequest("OAuth client_id is invalid")
			}
			if len(client.ClientSecret) < 32 || len(client.ClientSecret) > 512 {
				return invalidRequest("OAuth client secret must contain 32-512 characters")
			}
			if _, duplicate := installed[client.ClientID]; duplicate {
				return invalidRequest("OAuth client_id is duplicated")
			}
			if _, duplicate := seenSecrets[client.ClientSecret]; duplicate {
				return invalidRequest("OAuth client secrets must be unique")
			}
			scopes, err := validateTransportScopes(client.Scopes)
			if err != nil {
				return err
			}
			installed[client.ClientID] = transportClient{
				id:         client.ClientID,
				secretHash: sha256.Sum256([]byte(client.ClientSecret)),
				scopes:     scopes,
			}
			seenSecrets[client.ClientSecret] = struct{}{}
		}
		authority.transportClients = installed
		return nil
	}
}

func validateTransportScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, invalidRequest("OAuth client scopes are required")
	}
	seen := make(map[string]struct{}, len(scopes))
	allowed := AllowedTransportScopes()
	for _, scope := range scopes {
		if !scopePattern.MatchString(scope) {
			return nil, invalidRequest("OAuth scope is invalid")
		}
		if _, duplicate := seen[scope]; duplicate {
			return nil, invalidRequest("OAuth client scopes contain duplicates")
		}
		if !containsString(allowed, scope) {
			return nil, invalidRequest("OAuth scope is not recognized")
		}
		seen[scope] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for scope := range seen {
		result = append(result, scope)
	}
	return normalizeScopes(result), nil
}

// AllowedTransportScopes returns scopes supported by this authority.
func AllowedTransportScopes() []string {
	return []string{
		ScopeRegisterAgent,
		ScopeRegisterWorkflow,
		ScopeMintIntentToken,
		ScopeRevokeRegistration,
		ScopeRotateSigningKey,
	}
}

// HandleClientCredentials implements the OAuth 2.0 client-credentials grant.
// The endpoint is authenticated by HTTP Basic credentials or exactly one form
// credential pair; it never accepts shared bearer secrets.
func (a *Authority) HandleClientCredentials(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		a.writeError(writer, newError("invalid_request", "method must be POST", http.StatusMethodNotAllowed))
		return
	}
	mediaType, params, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || len(params) != 0 {
		a.writeError(writer, invalidRequest("Content-Type must be application/x-www-form-urlencoded"))
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 16*1024)
	if request.URL != nil && request.URL.RawQuery != "" {
		a.writeError(writer, invalidRequest("query parameters are not permitted"))
		return
	}
	if err := request.ParseForm(); err != nil {
		a.writeError(writer, invalidRequest("malformed client-credentials form"))
		return
	}
	clientID, clientSecret := request.PostForm.Get("client_id"), request.PostForm.Get("client_secret")
	basicID, basicSecret, hasBasic := request.BasicAuth()
	if hasBasic {
		if clientID != "" || clientSecret != "" {
			a.writeError(writer, invalidRequest("client credentials must not appear in both Basic auth and body"))
			return
		}
		clientID, clientSecret = basicID, basicSecret
	}
	if request.PostForm.Get("grant_type") != "client_credentials" {
		a.writeError(writer, ErrUnsupportedGrantType)
		return
	}
	if clientID == "" || clientSecret == "" {
		a.writeError(writer, invalidRequest("client_id and client_secret are required"))
		return
	}
	client, known := a.transportClients[clientID]
	secretDigest := sha256.Sum256([]byte(clientSecret))
	secretMatch := subtle.ConstantTimeCompare(secretDigest[:], client.secretHash[:]) == 1
	if !known || !secretMatch {
		a.writeError(writer, newError("invalid_client", "client authentication failed", http.StatusUnauthorized))
		return
	}
	requestedScope := strings.TrimSpace(request.PostForm.Get("scope"))
	if requestedScope == "" {
		a.writeError(writer, newError("invalid_scope", "scope is required", http.StatusBadRequest))
		return
	}
	requested, err := parseScopes(requestedScope)
	if err != nil {
		a.writeError(writer, newError("invalid_scope", "scope is invalid", http.StatusBadRequest))
		return
	}
	for _, scope := range requested {
		if !containsString(client.scopes, scope) {
			a.writeError(writer, newError("invalid_scope", "scope exceeds client authorization", http.StatusBadRequest))
			return
		}
	}
	response, err := a.mintTransport(client.id, requested)
	if err != nil {
		a.writeError(writer, err)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.WriteHeader(http.StatusOK)
	_ = writeJSONWithoutTrailingComma(writer, response)
}

// VerifyTransport validates a scoped client-credential JWT.
func (a *Authority) VerifyTransport(tokenString, requiredScope string) (*TransportClaims, error) {
	if !scopePattern.MatchString(requiredScope) {
		return nil, invalidRequest("required transport scope is invalid")
	}
	parsed, err := jwt.ParseWithClaims(
		tokenString,
		&TransportClaims{},
		func(token *jwt.Token) (any, error) {
			keyID, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("missing signing key kid")
			}
			key, err := a.signingKeyByID(keyID)
			if err != nil {
				return nil, err
			}
			return key.private.Public(), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(a.issuer),
		jwt.WithAudience(a.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithTimeFunc(a.now),
	)
	if err != nil {
		return nil, newError("invalid_token", err.Error(), 401)
	}
	claims, ok := parsed.Claims.(*TransportClaims)
	if !ok || !parsed.Valid {
		return nil, newError("invalid_token", "invalid transport token", 401)
	}
	if claims.ClientID == "" || claims.TokenUse != transportTokenUse || !containsString(splitScopes(claims.Scope), requiredScope) {
		return nil, newError("insufficient_scope", "transport token lacks the required scope", 403)
	}
	if _, authenticated := a.transportClients[claims.ClientID]; !authenticated {
		return nil, newError("invalid_client", "transport client is no longer configured", 401)
	}
	return claims, nil
}

// RequireTransportScope wraps a handler with OAuth scope enforcement.
func (a *Authority) RequireTransportScope(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authorization := request.Header.Get("Authorization")
		token, ok := strings.CutPrefix(authorization, "Bearer ")
		if !ok || token == "" || token == authorization {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		if _, err := a.VerifyTransport(token, scope); err != nil {
			status := http.StatusUnauthorized
			if IsCode(err, "insufficient_scope") {
				status = http.StatusForbidden
			}
			http.Error(writer, "forbidden", status)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (a *Authority) mintTransport(clientID string, scopes []string) (TokenResponse, error) {
	now := a.now().UTC()
	expires := now.Add(a.ttl)
	nonce, err := randomTransportID(a)
	if err != nil {
		return TokenResponse{}, serverError(fmt.Errorf("generate transport token id: %w", err))
	}
	jti := fmt.Sprintf("%s-%s", clientID, hex.EncodeToString(nonce))
	claims := &TransportClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    a.issuer,
			Subject:   clientID,
			Audience:  jwt.ClaimStrings{a.issuer},
			ExpiresAt: jwt.NewNumericDate(expires),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		ClientID: clientID,
		TokenUse: transportTokenUse,
		Scope:    strings.Join(scopes, " "),
	}
	a.signingMu.RLock()
	active := a.activeKey
	a.signingMu.RUnlock()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = active.kid
	signed, err := token.SignedString(active.private)
	if err != nil {
		return TokenResponse{}, serverError(fmt.Errorf("sign transport token: %w", err))
	}
	return TokenResponse{
		AccessToken: signed,
		TokenType:   "Bearer",
		ExpiresIn:   int(a.ttl.Seconds()),
		Scope:       claims.Scope,
	}, nil
}

func randomTransportID(a *Authority) ([]byte, error) {
	raw := make([]byte, 16)
	if _, err := a.randomRead(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func parseScopes(value string) ([]string, error) {
	return validateRequestedScopes(strings.Fields(value))
}

func splitScopes(value string) []string {
	return strings.Fields(value)
}

func validateRequestedScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, invalidRequest("scope is required")
	}
	for _, scope := range scopes {
		if !scopePattern.MatchString(scope) {
			return nil, invalidRequest("scope is invalid")
		}
	}
	return normalizeScopes(scopes), nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func writeJSONWithoutTrailingComma(writer http.ResponseWriter, value any) error {
	return json.NewEncoder(writer).Encode(value)
}
