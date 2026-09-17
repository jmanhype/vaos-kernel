package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"vaos-kernel/internal/agenticjwt"
)

const defaultAgenticJWTTTLSeconds = 300

// newAgenticJWTRegistry constructs the durable registry selected by kernel
// configuration. A path is required so an enabled authority cannot silently
// lose registrations and workflows on restart.
func newAgenticJWTRegistry(getenv func(string) string, now func() time.Time) (*agenticjwt.Registry, error) {
	path := getenv("VAOS_AGENTIC_JWT_REGISTRY_PATH")
	if path == "" {
		return nil, fmt.Errorf("agentic jwt requires VAOS_AGENTIC_JWT_REGISTRY_PATH")
	}
	store, err := agenticjwt.NewFileRegistryStore(path)
	if err != nil {
		return nil, fmt.Errorf("configure agentic jwt registry: %w", err)
	}
	registry, err := agenticjwt.NewRegistryWithStore(now, store)
	if err != nil {
		return nil, fmt.Errorf("restore agentic jwt registry: %w", err)
	}
	return registry, nil
}

// newAgenticJWTAuthority constructs the optional Agentic JWT P0 authority from
// environment configuration. It returns a nil authority when the feature is not
// explicitly enabled.
func newAgenticJWTAuthority(
	getenv func(string) string,
	registry *agenticjwt.Registry,
	now func() time.Time,
	auditRecorder agenticjwt.AuditRecorder,
) (*agenticjwt.Authority, error) {
	if registry == nil {
		return nil, fmt.Errorf("agentic jwt registry is required")
	}
	if now == nil {
		now = time.Now
	}

	enabledText := getenv("VAOS_AGENTIC_JWT_ENABLED")
	if enabledText == "" {
		return nil, nil
	}
	enabled, err := strconv.ParseBool(enabledText)
	if err != nil {
		return nil, fmt.Errorf("parse VAOS_AGENTIC_JWT_ENABLED: %w", err)
	}
	if !enabled {
		return nil, nil
	}
	if auditRecorder == nil {
		return nil, fmt.Errorf("agentic jwt requires an audit recorder when enabled")
	}

	appID := getenv("VAOS_AGENTIC_JWT_APP_ID")
	issuer := getenv("VAOS_AGENTIC_JWT_ISSUER")
	signingKeyText := getenv("VAOS_AGENTIC_JWT_SIGNING_KEY")
	if appID == "" || issuer == "" || signingKeyText == "" {
		return nil, fmt.Errorf("agentic jwt requires APP_ID, ISSUER, and SIGNING_KEY when enabled")
	}

	var signingKey ed25519.PrivateKey
	if seedText, isSeed := strings.CutPrefix(signingKeyText, "seed:"); isSeed {
		rawSeed, err := base64.RawURLEncoding.DecodeString(seedText)
		if err != nil {
			return nil, fmt.Errorf("decode VAOS_AGENTIC_JWT_SIGNING_KEY seed: %w", err)
		}
		if len(rawSeed) != ed25519.SeedSize {
			return nil, fmt.Errorf("agentic jwt seed must contain exactly 32 bytes")
		}
		signingKey = ed25519.NewKeyFromSeed(rawSeed)
	} else {
		rawKey, err := base64.RawURLEncoding.DecodeString(signingKeyText)
		if err != nil {
			return nil, fmt.Errorf("decode VAOS_AGENTIC_JWT_SIGNING_KEY: %w", err)
		}
		if len(rawKey) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("agentic jwt signing key must be a 64-byte Ed25519 private key or seed:<32-byte-key>")
		}
		signingKey = ed25519.PrivateKey(rawKey)
	}

	ttlSeconds := defaultAgenticJWTTTLSeconds
	if ttlText := getenv("VAOS_AGENTIC_JWT_TTL_SECONDS"); ttlText != "" {
		ttlSeconds, err = strconv.Atoi(ttlText)
		if err != nil || ttlSeconds <= 0 {
			return nil, fmt.Errorf("VAOS_AGENTIC_JWT_TTL_SECONDS must be a positive integer")
		}
	}
	registrar, err := transportClientFromEnv(getenv, "VAOS_AGENTIC_JWT_REGISTRAR", []string{agenticjwt.ScopeRegisterAgent})
	if err != nil {
		return nil, err
	}
	workflowAdmin, err := transportClientFromEnv(getenv, "VAOS_AGENTIC_JWT_WORKFLOW", []string{agenticjwt.ScopeRegisterWorkflow})
	if err != nil {
		return nil, err
	}
	tokenIssuer, err := transportClientFromEnv(getenv, "VAOS_AGENTIC_JWT_TOKEN", []string{agenticjwt.ScopeMintIntentToken})
	if err != nil {
		return nil, err
	}
	return agenticjwt.NewAuthority(
		appID,
		issuer,
		signingKey,
		registry,
		time.Duration(ttlSeconds)*time.Second,
		now,
		agenticjwt.WithAuditRecorder(auditRecorder),
		agenticjwt.WithTransportClients(registrar, workflowAdmin, tokenIssuer),
	)
}

func transportClientFromEnv(getenv func(string) string, prefix string, scopes []string) (agenticjwt.TransportClientCredential, error) {
	client := agenticjwt.TransportClientCredential{
		ClientID:     getenv(prefix + "_CLIENT_ID"),
		ClientSecret: getenv(prefix + "_CLIENT_SECRET"),
		Scopes:       scopes,
	}
	if client.ClientID == "" || client.ClientSecret == "" {
		return agenticjwt.TransportClientCredential{}, fmt.Errorf("agentic jwt requires %s_CLIENT_ID and %s_CLIENT_SECRET", prefix, prefix)
	}
	return client, nil
}

// newAgenticJWTRuntime returns nil when the optional feature is disabled; an
// enabled runtime always restores its durable registry before construction.
func newAgenticJWTRuntime(
	getenv func(string) string,
	now func() time.Time,
	auditRecorder agenticjwt.AuditRecorder,
) (*agenticjwt.Authority, error) {
	enabledText := getenv("VAOS_AGENTIC_JWT_ENABLED")
	if enabledText == "" {
		return nil, nil
	}
	enabled, err := strconv.ParseBool(enabledText)
	if err != nil {
		return nil, fmt.Errorf("parse VAOS_AGENTIC_JWT_ENABLED: %w", err)
	}
	if !enabled {
		return nil, nil
	}
	registry, err := newAgenticJWTRegistry(getenv, now)
	if err != nil {
		return nil, err
	}
	return newAgenticJWTAuthority(getenv, registry, now, auditRecorder)
}

// mountAgenticJWT mounts the P0 endpoints behind scoped OAuth transport tokens.
// A nil authority mounts nothing.
func mountAgenticJWT(mux *http.ServeMux, authority *agenticjwt.Authority) {
	if authority == nil || mux == nil {
		return
	}
	mux.HandleFunc("/v1/oauth/token", authority.HandleClientCredentials)
	mux.Handle("/v1/intent/register/agent", authority.RequireTransportScope(agenticjwt.ScopeRegisterAgent, http.HandlerFunc(authority.HandleRegistration)))
	mux.Handle("/v1/intent/register/workflow", authority.RequireTransportScope(agenticjwt.ScopeRegisterWorkflow, http.HandlerFunc(authority.HandleWorkflowRegistration)))
	mux.Handle("/v1/intent/token", authority.RequireTransportScope(agenticjwt.ScopeMintIntentToken, http.HandlerFunc(authority.HandleToken)))
	mux.HandleFunc("/.well-known/jwks.json", authority.HandleJWKS)
}

// agenticJWTEnvironment is a small helper for main; it keeps os.Getenv calls in
// one place while newAgenticJWTAuthority remains directly testable.
func agenticJWTEnvironment() func(string) string {
	return os.Getenv
}
