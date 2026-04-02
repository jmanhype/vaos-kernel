package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"vaos-kernel/internal/audit"
	"vaos-kernel/internal/hash"
	"vaos-kernel/internal/jwt"
	"vaos-kernel/internal/nhi"
	"vaos-kernel/internal/signing"
	"vaos-kernel/pkg/models"
)

func TestServerInitialization(t *testing.T) {
	registry := nhi.NewRegistry()
	signingKey := make([]byte, 32)
	issuer, err := jwt.NewIssuer(signingKey, registry)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}
	hasher := hash.Hasher{}
	ledger := audit.NewLedger(nil)

	tmpDir := t.TempDir()
	signingKeyPath := filepath.Join(tmpDir, "signing.key")
	signer, err := signing.NewSigner(signingKeyPath)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	d := &deps{registry, issuer, hasher, ledger, signer}

	if d.registry == nil {
		t.Error("Registry is nil")
	}
	if d.issuer == nil {
		t.Error("Issuer is nil")
	}
	if d.ledger == nil {
		t.Error("Ledger is nil")
	}
	if d.signer == nil {
		t.Error("Signer is nil")
	}
}

func TestBootstrapDefaultAgent(t *testing.T) {
	registry := nhi.NewRegistry()

	defaultAgent := models.Agent{
		ID:    "mcp-agent",
		Name:  "MCP Default Agent",
		State: models.AgentStateIdle,
	}

	if err := registry.RegisterAgent(defaultAgent); err != nil {
		t.Fatalf("Failed to register default agent: %v", err)
	}

	agent, err := registry.GetAgent("mcp-agent")
	if err != nil {
		t.Fatalf("Failed to get default agent: %v", err)
	}

	if agent.ID != "mcp-agent" {
		t.Errorf("Expected agent ID 'mcp-agent', got '%s'", agent.ID)
	}
	if agent.Name != "MCP Default Agent" {
		t.Errorf("Expected agent name 'MCP Default Agent', got '%s'", agent.Name)
	}
}

func TestHandleRequestCredential(t *testing.T) {
	registry := nhi.NewRegistry()
	defaultAgent := models.Agent{
		ID:    "test-agent",
		Name:  "Test Agent",
		State: models.AgentStateIdle,
	}
	if err := registry.RegisterAgent(defaultAgent); err != nil {
		t.Fatalf("Failed to register agent: %v", err)
	}

	signingKey := make([]byte, 32)
	issuer, err := jwt.NewIssuer(signingKey, registry)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}
	hasher := hash.Hasher{}
	ledger := audit.NewLedger(nil)

	tmpDir := t.TempDir()
	signingKeyPath := filepath.Join(tmpDir, "signing.key")
	signer, err := signing.NewSigner(signingKeyPath)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	d := &deps{registry, issuer, hasher, ledger, signer}

	params := RequestCredentialParams{
		AgentID:     "test-agent",
		Action:      "read",
		Resource:    "test-resource",
		Description: "Test credential request",
	}

	result, _, err := d.handleRequestCredential(nil, nil, params)
	if err != nil {
		t.Fatalf("handleRequestCredential failed: %v", err)
	}

	if result.IsError {
		t.Errorf("Expected success, got error: %s", result.Content[0].(*mcp.TextContent).Text)
	}

	var response map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*mcp.TextContent).Text), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if token, ok := response["token"].(string); !ok || token == "" {
		t.Error("Expected non-empty token in response")
	}
	if fingerprint, ok := response["intent_fingerprint"].(string); !ok || fingerprint == "" {
		t.Error("Expected non-empty intent_fingerprint in response")
	}
	if attestation, ok := response["attestation"].(string); !ok || attestation == "" {
		t.Error("Expected non-empty attestation in response")
	}
	if signature, ok := response["signature"].(string); !ok || signature == "" {
		t.Error("Expected non-empty signature in response")
	}
	if expiresIn, ok := response["expires_in_seconds"].(float64); !ok || expiresIn != 60 {
		t.Errorf("Expected expires_in_seconds 60, got %v", expiresIn)
	}
}

func TestHandleVerifyCredential(t *testing.T) {
	registry := nhi.NewRegistry()
	defaultAgent := models.Agent{
		ID:    "test-agent",
		Name:  "Test Agent",
		State: models.AgentStateIdle,
	}
	if err := registry.RegisterAgent(defaultAgent); err != nil {
		t.Fatalf("Failed to register agent: %v", err)
	}

	signingKey := make([]byte, 32)
	issuer, err := jwt.NewIssuer(signingKey, registry)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}
	hasher := hash.Hasher{}
	ledger := audit.NewLedger(nil)

	tmpDir := t.TempDir()
	signingKeyPath := filepath.Join(tmpDir, "signing.key")
	signer, err := signing.NewSigner(signingKeyPath)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	d := &deps{registry, issuer, hasher, ledger, signer}

	intent := models.IntentRequest{
		AgentID:     "test-agent",
		Action:      "read",
		Resource:    "test-resource",
		RequestedAt: time.Now().UTC(),
	}
	fingerprint, _ := hasher.HashIntent(intent)
	token, _, _ := issuer.Issue("test-agent", fingerprint)

	params := VerifyCredentialParams{
		Token:              token,
		ExpectedFingerprint: fingerprint,
	}

	result, _, err := d.handleVerifyCredential(nil, nil, params)
	if err != nil {
		t.Fatalf("handleVerifyCredential failed: %v", err)
	}

	if result.IsError {
		t.Errorf("Expected success, got error: %s", result.Content[0].(*mcp.TextContent).Text)
	}

	var response map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*mcp.TextContent).Text), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if valid, ok := response["valid"].(bool); !ok || !valid {
		t.Error("Expected valid=true in response")
	}
	if agentID, ok := response["agent_id"].(string); !ok || agentID != "test-agent" {
		t.Errorf("Expected agent_id 'test-agent', got '%v'", agentID)
	}
}

func TestHandleRecordAudit(t *testing.T) {
	registry := nhi.NewRegistry()
	signingKey := make([]byte, 32)
	issuer, err := jwt.NewIssuer(signingKey, registry)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}
	hasher := hash.Hasher{}
	ledger := audit.NewLedger(nil)

	tmpDir := t.TempDir()
	signingKeyPath := filepath.Join(tmpDir, "signing.key")
	signer, err := signing.NewSigner(signingKeyPath)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	d := &deps{registry, issuer, hasher, ledger, signer}

	params := RecordAuditParams{
		AgentID: "test-agent",
		Action:  "test_action",
		Status:  "success",
		Details: "Test audit entry",
	}

	result, _, err := d.handleRecordAudit(nil, nil, params)
	if err != nil {
		t.Fatalf("handleRecordAudit failed: %v", err)
	}

	if result.IsError {
		t.Errorf("Expected success, got error: %s", result.Content[0].(*mcp.TextContent).Text)
	}

	var response map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*mcp.TextContent).Text), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if entryID, ok := response["entry_id"].(string); !ok || entryID == "" {
		t.Error("Expected non-empty entry_id in response")
	}
	if attestation, ok := response["attestation"].(string); !ok || attestation == "" {
		t.Error("Expected non-empty attestation in response")
	}
	if signature, ok := response["signature"].(string); !ok || signature == "" {
		t.Error("Expected non-empty signature in response")
	}
	if chainPosition, ok := response["chain_position"].(float64); !ok || chainPosition != 0 {
		t.Errorf("Expected chain_position 0, got %v", chainPosition)
	}
}

func TestHandleVerifyChain(t *testing.T) {
	registry := nhi.NewRegistry()
	signingKey := make([]byte, 32)
	issuer, err := jwt.NewIssuer(signingKey, registry)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}
	hasher := hash.Hasher{}
	ledger := audit.NewLedger(nil)

	tmpDir := t.TempDir()
	signingKeyPath := filepath.Join(tmpDir, "signing.key")
	signer, err := signing.NewSigner(signingKeyPath)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	d := &deps{registry, issuer, hasher, ledger, signer}

	params := VerifyChainParams{}

	result, _, err := d.handleVerifyChain(nil, nil, params)
	if err != nil {
		t.Fatalf("handleVerifyChain failed: %v", err)
	}

	if result.IsError {
		t.Errorf("Expected success, got error: %s", result.Content[0].(*mcp.TextContent).Text)
	}

	var response map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*mcp.TextContent).Text), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if valid, ok := response["valid"].(bool); !ok || !valid {
		t.Error("Expected valid=true in response")
	}
	if entriesVerified, ok := response["entries_verified"].(float64); !ok || entriesVerified != 0 {
		t.Errorf("Expected entries_verified 0, got %v", entriesVerified)
	}
}

func TestHandleGetPublicKey(t *testing.T) {
	registry := nhi.NewRegistry()
	signingKey := make([]byte, 32)
	issuer, err := jwt.NewIssuer(signingKey, registry)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}
	hasher := hash.Hasher{}
	ledger := audit.NewLedger(nil)

	tmpDir := t.TempDir()
	signingKeyPath := filepath.Join(tmpDir, "signing.key")
	signer, err := signing.NewSigner(signingKeyPath)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	d := &deps{registry, issuer, hasher, ledger, signer}

	params := GetPublicKeyParams{}

	result, _, err := d.handleGetPublicKey(nil, nil, params)
	if err != nil {
		t.Fatalf("handleGetPublicKey failed: %v", err)
	}

	if result.IsError {
		t.Errorf("Expected success, got error: %s", result.Content[0].(*mcp.TextContent).Text)
	}

	var response map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*mcp.TextContent).Text), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if publicKey, ok := response["public_key"].(string); !ok || publicKey == "" {
		t.Error("Expected non-empty public_key in response")
	}
	if algorithm, ok := response["algorithm"].(string); !ok || algorithm != "Ed25519" {
		t.Errorf("Expected algorithm 'Ed25519', got '%v'", algorithm)
	}
}

func TestHandleRegisterAgent(t *testing.T) {
	registry := nhi.NewRegistry()
	signingKey := make([]byte, 32)
	issuer, err := jwt.NewIssuer(signingKey, registry)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}
	hasher := hash.Hasher{}
	ledger := audit.NewLedger(nil)

	tmpDir := t.TempDir()
	signingKeyPath := filepath.Join(tmpDir, "signing.key")
	signer, err := signing.NewSigner(signingKeyPath)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	d := &deps{registry, issuer, hasher, ledger, signer}

	params := RegisterAgentParams{
		AgentID: "new-agent",
		Name:    "New Agent",
		Type:    "test",
	}

	result, _, err := d.handleRegisterAgent(nil, nil, params)
	if err != nil {
		t.Fatalf("handleRegisterAgent failed: %v", err)
	}

	if result.IsError {
		t.Errorf("Expected success, got error: %s", result.Content[0].(*mcp.TextContent).Text)
	}

	var response map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*mcp.TextContent).Text), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if registered, ok := response["registered"].(bool); !ok || !registered {
		t.Error("Expected registered=true in response")
	}
	if agentID, ok := response["agent_id"].(string); !ok || agentID != "new-agent" {
		t.Errorf("Expected agent_id 'new-agent', got '%v'", agentID)
	}

	agent, err := registry.GetAgent("new-agent")
	if err != nil {
		t.Fatalf("Failed to retrieve registered agent: %v", err)
	}
	if agent.Name != "New Agent" {
		t.Errorf("Expected agent name 'New Agent', got '%s'", agent.Name)
	}
	// Type is stored in metadata
	if agent.Metadata == nil || agent.Metadata["type"] != "test" {
		t.Errorf("Expected agent type 'test' in metadata, got '%v'", agent.Metadata)
	}
}

func TestHandleRegisterAgentDefaultType(t *testing.T) {
	registry := nhi.NewRegistry()
	signingKey := make([]byte, 32)
	issuer, err := jwt.NewIssuer(signingKey, registry)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}
	hasher := hash.Hasher{}
	ledger := audit.NewLedger(nil)

	tmpDir := t.TempDir()
	signingKeyPath := filepath.Join(tmpDir, "signing.key")
	signer, err := signing.NewSigner(signingKeyPath)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	d := &deps{registry, issuer, hasher, ledger, signer}

	params := RegisterAgentParams{
		AgentID: "default-type-agent",
		Name:    "Default Type Agent",
	}

	result, _, err := d.handleRegisterAgent(nil, nil, params)
	if err != nil {
		t.Fatalf("handleRegisterAgent failed: %v", err)
	}

	if result.IsError {
		t.Errorf("Expected success, got error: %s", result.Content[0].(*mcp.TextContent).Text)
	}

	agent, err := registry.GetAgent("default-type-agent")
	if err != nil {
		t.Fatalf("Failed to retrieve registered agent: %v", err)
	}
	// No type specified, so no metadata should be present
	if agent.Metadata != nil && agent.Metadata["type"] != "" {
		t.Errorf("Expected no agent type in metadata when not specified, got '%s'", agent.Metadata["type"])
	}
}

func TestMainSignsKeyPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	signingKeyPath := filepath.Join(tmpDir, "signing.key")

	signer1, err := signing.NewSigner(signingKeyPath)
	if err != nil {
		t.Fatalf("Failed to create first signer: %v", err)
	}

	pubKey1 := signer1.PublicKeyHex()

	signer2, err := signing.NewSigner(signingKeyPath)
	if err != nil {
		t.Fatalf("Failed to load second signer: %v", err)
	}

	pubKey2 := signer2.PublicKeyHex()

	if pubKey1 != pubKey2 {
		t.Errorf("Public keys mismatch: %s != %s", pubKey1, pubKey2)
	}

	testData := []byte("test data")
	sig1 := signer1.Sign(testData)
	sig2 := signer2.Sign(testData)

	if sig1 != sig2 {
		t.Error("Signatures mismatch for same data")
	}
}

func TestEnvVarJWTSecret(t *testing.T) {
	originalSecret := os.Getenv("VAOS_JWT_SECRET")
	defer os.Setenv("VAOS_JWT_SECRET", originalSecret)

	testSecret := "test-secret-key-32-bytes-long!"
	os.Setenv("VAOS_JWT_SECRET", testSecret)

	signingKey := []byte(testSecret)
	registry := nhi.NewRegistry()
	issuer, err := jwt.NewIssuer(signingKey, registry)
	if err != nil {
		t.Fatalf("Failed to create issuer with env secret: %v", err)
	}

	defaultAgent := models.Agent{
		ID:    "test-agent",
		Name:  "Test Agent",
		State: models.AgentStateIdle,
	}
	if err := registry.RegisterAgent(defaultAgent); err != nil {
		t.Fatalf("Failed to register agent: %v", err)
	}

	hasher := hash.Hasher{}
	intent := models.IntentRequest{
		AgentID:     "test-agent",
		Action:      "test",
		Resource:    "resource",
		RequestedAt: time.Now().UTC(),
	}
	fingerprint, _ := hasher.HashIntent(intent)

	token, record, err := issuer.Issue("test-agent", fingerprint)
	if err != nil {
		t.Fatalf("Failed to issue token: %v", err)
	}

	if token == "" {
		t.Error("Expected non-empty token")
	}
	if record.TokenID == "" {
		t.Error("Expected non-empty token ID")
	}
}
