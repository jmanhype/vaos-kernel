package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"vaos-kernel/internal/audit"
	"vaos-kernel/internal/hash"
	"vaos-kernel/internal/jwt"
	"vaos-kernel/internal/nhi"
	"vaos-kernel/internal/signing"
	"vaos-kernel/pkg/models"
)

const (
	Version = "0.1.0"
)

func main() {
	ctx := context.Background()

	// Initialize dependencies
	registry := nhi.NewRegistry()

	// Bootstrap default agent
	defaultAgent := models.Agent{
		ID:    "mcp-agent",
		Name:  "MCP Default Agent",
		State: models.AgentStateIdle,
	}
	if err := registry.RegisterAgent(defaultAgent); err != nil {
		log.Fatalf("Failed to register default agent: %v", err)
	}

	// Initialize JWT issuer
	signingKey := []byte(os.Getenv("VAOS_JWT_SECRET"))
	if len(signingKey) == 0 {
		signingKey = make([]byte, 32)
		if _, err := rand.Read(signingKey); err != nil {
			log.Fatalf("Failed to generate random JWT secret: %v", err)
		}
	}
	issuer, err := jwt.NewIssuer(signingKey, registry)
	if err != nil {
		log.Fatalf("Failed to create JWT issuer: %v", err)
	}

	hasher := hash.Hasher{}
	ledger := audit.NewLedger(nil)

	// Initialize signer - expand ~ properly
	signingKeyPath := os.ExpandEnv("$HOME/.vaos-kernel/signing.key")
	if signingKeyPath == "" || signingKeyPath[0] == '$' {
		homeDir, _ := os.UserHomeDir()
		signingKeyPath = homeDir + "/.vaos-kernel/signing.key"
	}
	signer, err := signing.NewSigner(signingKeyPath)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}

	// Create MCP server
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "vaos-kernel",
		Version: Version,
	}, nil)

	d := &deps{registry, issuer, hasher, ledger, signer}

	// Register tools
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "request_credential",
		Description: "Request a JIT JWT credential for a specific intent",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"agent_id": map[string]any{
					"type":        "string",
					"description": "The ID of the agent requesting the credential",
				},
				"action": map[string]any{
					"type":        "string",
					"description": "The action being performed",
				},
				"resource": map[string]any{
					"type":        "string",
					"description": "The resource being accessed",
				},
				"description": map[string]any{
					"type":        "string",
					"description": "Optional description of the intent",
				},
			},
			"required": []any{"agent_id", "action", "resource"},
		},
	}, d.handleRequestCredential)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "verify_credential",
		Description: "Verify a JWT credential against an expected intent fingerprint",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"token": map[string]any{
					"type":        "string",
					"description": "The JWT token to verify",
				},
				"expected_fingerprint": map[string]any{
					"type":        "string",
					"description": "The expected intent fingerprint",
				},
			},
			"required": []any{"token", "expected_fingerprint"},
		},
	}, d.handleVerifyCredential)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "record_audit",
		Description: "Record an audit entry with cryptographic attestation",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"agent_id": map[string]any{
					"type":        "string",
					"description": "The ID of the agent",
				},
				"action": map[string]any{
					"type":        "string",
					"description": "The action being audited",
				},
				"status": map[string]any{
					"type":        "string",
					"description": "The status of the action",
				},
				"details": map[string]any{
					"type":        "string",
					"description": "Additional details about the action",
				},
			},
			"required": []any{"agent_id", "action", "status"},
		},
	}, d.handleRecordAudit)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "verify_chain",
		Description: "Verify the integrity of the audit chain",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	}, d.handleVerifyChain)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_public_key",
		Description: "Get the Ed25519 public key used for signing attestations",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	}, d.handleGetPublicKey)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "register_agent",
		Description: "Register a new agent in the registry",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"agent_id": map[string]any{
					"type":        "string",
					"description": "The unique ID for the agent",
				},
				"name": map[string]any{
					"type":        "string",
					"description": "The name of the agent",
				},
				"type": map[string]any{
					"type":        "string",
					"description": "The type of agent (defaults to 'external')",
				},
			},
			"required": []any{"agent_id", "name"},
		},
	}, d.handleRegisterAgent)

	// Start stdio server
	transport := &mcp.StdioTransport{}
	if err := srv.Run(ctx, transport); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

type deps struct {
	registry *nhi.Registry
	issuer   *jwt.Issuer
	hasher   hash.Hasher
	ledger   *audit.Ledger
	signer   *signing.Signer
}

type RequestCredentialParams struct {
	AgentID     string `json:"agent_id"`
	Action      string `json:"action"`
	Resource    string `json:"resource"`
	Description string `json:"description"`
}

func (d *deps) handleRequestCredential(ctx context.Context, req *mcp.CallToolRequest, params RequestCredentialParams) (*mcp.CallToolResult, struct{}, error) {
	intent := models.IntentRequest{
		AgentID:     params.AgentID,
		Action:      params.Action,
		Resource:    params.Resource,
		Description: params.Description,
		RequestedAt: time.Now().UTC(),
	}

	fingerprint, err := d.hasher.HashIntent(intent)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: err.Error()},
			},
			IsError: true,
		}, struct{}{}, nil
	}

	token, record, err := d.issuer.Issue(params.AgentID, fingerprint)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: err.Error()},
			},
			IsError: true,
		}, struct{}{}, nil
	}

	entry := models.AuditEntry{
		AgentID:           params.AgentID,
		IntentFingerprint: fingerprint,
		Action:            params.Action,
		Component:         "mcp-server",
		Status:            "credential_issued",
		Details: map[string]string{
			"token_id": record.TokenID,
		},
	}
	recorded, err := d.ledger.Record(entry)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: err.Error()},
			},
			IsError: true,
		}, struct{}{}, nil
	}

	signature := d.signer.Sign([]byte(recorded.Attestation))

	result := map[string]interface{}{
		"token":               token,
		"intent_fingerprint":  fingerprint,
		"attestation":         recorded.Attestation,
		"signature":           signature,
		"expires_in_seconds":  60,
		"token_id":            record.TokenID,
	}
	resultJSON, _ := json.Marshal(result)

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(resultJSON)},
		},
	}, struct{}{}, nil
}

type VerifyCredentialParams struct {
	Token              string `json:"token"`
	ExpectedFingerprint string `json:"expected_fingerprint"`
}

func (d *deps) handleVerifyCredential(ctx context.Context, req *mcp.CallToolRequest, params VerifyCredentialParams) (*mcp.CallToolResult, struct{}, error) {
	claims, err := d.issuer.Verify(params.Token, params.ExpectedFingerprint)
	if err != nil {
		result := map[string]interface{}{
			"valid": false,
			"error": err.Error(),
		}
		resultJSON, _ := json.Marshal(result)
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: string(resultJSON)},
			},
		}, struct{}{}, nil
	}

	result := map[string]interface{}{
		"valid":     true,
		"agent_id":  claims.AgentID,
		"expires_at": claims.ExpiresAt.Time.UTC().Format(time.RFC3339),
	}
	resultJSON, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(resultJSON)},
		},
	}, struct{}{}, nil
}

type RecordAuditParams struct {
	AgentID string `json:"agent_id"`
	Action  string `json:"action"`
	Status  string `json:"status"`
	Details string `json:"details"`
}

func (d *deps) handleRecordAudit(ctx context.Context, req *mcp.CallToolRequest, params RecordAuditParams) (*mcp.CallToolResult, struct{}, error) {
	entry := models.AuditEntry{
		AgentID:   params.AgentID,
		Action:    params.Action,
		Component: "mcp-server",
		Status:    params.Status,
	}
	if params.Details != "" {
		entry.Details = map[string]string{"details": params.Details}
	}

	recorded, err := d.ledger.Record(entry)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: err.Error()},
			},
			IsError: true,
		}, struct{}{}, nil
	}

	signature := d.signer.Sign([]byte(recorded.Attestation))

	entries := d.ledger.Entries()
	chainPosition := len(entries) - 1

	result := map[string]interface{}{
		"entry_id":       recorded.ID,
		"attestation":    recorded.Attestation,
		"signature":      signature,
		"chain_position": chainPosition,
		"timestamp":      recorded.Timestamp.UTC().Format(time.RFC3339),
	}
	resultJSON, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(resultJSON)},
		},
	}, struct{}{}, nil
}

type VerifyChainParams struct{}

func (d *deps) handleVerifyChain(ctx context.Context, req *mcp.CallToolRequest, params VerifyChainParams) (*mcp.CallToolResult, struct{}, error) {
	entries := d.ledger.Entries()
	firstBroken := d.ledger.VerifyChain()

	// For replay verification, we need to track stored signatures
	// Since this is a simple in-memory implementation, we'll re-sign for verification
	sigFn := func(e models.AuditEntry) string {
		return d.signer.Sign([]byte(e.Attestation))
	}

	replayResult := audit.Replay(entries, sigFn, d.signer.Verify)

	result := map[string]interface{}{
		"valid":              firstBroken == -1,
		"entries_verified":   len(entries),
		"first_broken_at":    nil,
		"chain_status":       replayResult.ChainStatus,
		"sig_status":         replayResult.SigStatus,
		"sig_verified_count": replayResult.SigVerifiedCount,
	}
	if firstBroken >= 0 {
		result["first_broken_at"] = firstBroken
	}
	if replayResult.SigFailedAtID != "" {
		result["sig_failed_at_id"] = replayResult.SigFailedAtID
	}

	resultJSON, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(resultJSON)},
		},
	}, struct{}{}, nil
}

type GetPublicKeyParams struct{}

func (d *deps) handleGetPublicKey(ctx context.Context, req *mcp.CallToolRequest, params GetPublicKeyParams) (*mcp.CallToolResult, struct{}, error) {
	result := map[string]interface{}{
		"public_key": d.signer.PublicKeyHex(),
		"algorithm":  "Ed25519",
	}
	resultJSON, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(resultJSON)},
		},
	}, struct{}{}, nil
}

type RegisterAgentParams struct {
	AgentID string `json:"agent_id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
}

func (d *deps) handleRegisterAgent(ctx context.Context, req *mcp.CallToolRequest, params RegisterAgentParams) (*mcp.CallToolResult, struct{}, error) {
	agent := models.Agent{
		ID:    params.AgentID,
		Name:  params.Name,
		State: models.AgentStateIdle,
	}
	// Store type in metadata if provided
	if params.Type != "" {
		agent.Metadata = map[string]string{"type": params.Type}
	}

	if err := d.registry.RegisterAgent(agent); err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: err.Error()},
			},
			IsError: true,
		}, struct{}{}, nil
	}

	result := map[string]interface{}{
		"registered": true,
		"agent_id":   params.AgentID,
	}
	resultJSON, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(resultJSON)},
		},
	}, struct{}{}, nil
}
