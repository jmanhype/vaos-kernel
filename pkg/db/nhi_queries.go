package db

import (
	"database/sql"
	"encoding/json"
	"time"

	"vaos-kernel/pkg/models"
)

// CreateAgent inserts a new agent into the NHI registry.
func (db *DB) CreateAgent(agent models.Agent) error {
	query := `
		INSERT INTO nhi_agents (agent_id, agent_name, agent_type, version, status)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (agent_id) DO UPDATE SET
			agent_name = EXCLUDED.agent_name,
			version = EXCLUDED.version,
			updated_at = NOW()
	`

	var agentType string
	switch agent.Persona {
	case "kernel":
		agentType = "kernel"
	case "swarm":
		agentType = "swarm"
	case "crucible":
		agentType = "crucible"
	case "interface":
		agentType = "interface"
	default:
		agentType = "external"
	}

	_, err := db.Exec(query, agent.ID, agent.Name, agentType, "0.1.0", "active")
	if err != nil {
		return err
	}

	// Store capabilities separately
	for _, cap := range agent.Capabilities {
		if err := db.CreateCapability(agent.ID, cap); err != nil {
			return err
		}
	}

	return nil
}

// GetAgent retrieves an agent by ID from the database.
func (db *DB) GetAgent(agentID string) (models.Agent, error) {
	query := `
		SELECT agent_id, agent_name, agent_type, version, status
		FROM nhi_agents
		WHERE agent_id = $1 AND status = 'active'
	`

	var agent models.Agent
	var agentType, version, status string

	err := db.QueryRow(query, agentID).Scan(&agent.ID, &agent.Name, &agentType, &version, &status)
	if err != nil {
		if err == sql.ErrNoRows {
			return models.Agent{}, sql.ErrNoRows
		}
		return models.Agent{}, err
	}

	// Map agent_type to persona
	switch agentType {
	case "kernel":
		agent.Persona = "kernel"
	case "swarm":
		agent.Persona = "swarm"
	case "crucible":
		agent.Persona = "crucible"
	case "interface":
		agent.Persona = "interface"
	default:
		agent.Persona = "external"
	}

	// Load capabilities
	caps, err := db.GetCapabilities(agentID)
	if err != nil {
		return models.Agent{}, err
	}
	agent.Capabilities = caps

	// Load reputation
	reputation, err := db.GetReputation(agentID)
	if err == nil {
		agent.ReputationScore = reputation
	}

	return agent, nil
}

// ListAgents returns all active agents from the database.
func (db *DB) ListAgents() ([]models.Agent, error) {
	query := `
		SELECT agent_id, agent_name, agent_type, version, status
		FROM nhi_agents
		WHERE status = 'active'
		ORDER BY created_at ASC
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	agents := make([]models.Agent, 0)
	for rows.Next() {
		var agent models.Agent
		var agentType, version, status string

		if err := rows.Scan(&agent.ID, &agent.Name, &agentType, &version, &status); err != nil {
			return nil, err
		}

		// Map agent_type to persona
		switch agentType {
		case "kernel":
			agent.Persona = "kernel"
		case "swarm":
			agent.Persona = "swarm"
		case "crucible":
			agent.Persona = "crucible"
		case "interface":
			agent.Persona = "interface"
		default:
			agent.Persona = "external"
		}

		// Load capabilities
		caps, err := db.GetCapabilities(agent.ID)
		if err != nil {
			return nil, err
		}
		agent.Capabilities = caps

		// Load reputation
		reputation, err := db.GetReputation(agent.ID)
		if err == nil {
			agent.ReputationScore = reputation
		}

		agents = append(agents, agent)
	}

	return agents, nil
}

// CreateCapability inserts a capability for an agent.
func (db *DB) CreateCapability(agentID string, cap models.Capability) error {
	query := `
		INSERT INTO nhi_capabilities (agent_id, capability_name, capability_type, version)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (agent_id, capability_name) DO NOTHING
	`

	_, err := db.Exec(query, agentID, cap.Name, "tool", "0.1.0")
	return err
}

// GetCapabilities retrieves all capabilities for an agent.
func (db *DB) GetCapabilities(agentID string) ([]models.Capability, error) {
	query := `
		SELECT capability_name, capability_type
		FROM nhi_capabilities
		WHERE agent_id = $1
		ORDER BY created_at ASC
	`

	rows, err := db.Query(query, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	caps := make([]models.Capability, 0)
	for rows.Next() {
		var cap models.Capability
		var capType string

		if err := rows.Scan(&cap.Name, &capType); err != nil {
			return nil, err
		}

		caps = append(caps, cap)
	}

	return caps, nil
}

// GetReputation retrieves the reputation score for an agent.
func (db *DB) GetReputation(agentID string) (float64, error) {
	query := `
		SELECT reputation_score
		FROM nhi_reputation
		WHERE agent_id = $1
	`

	var reputation float64
	err := db.QueryRow(query, agentID).Scan(&reputation)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0.0, nil // No reputation yet
		}
		return 0.0, err
	}

	return reputation, nil
}

// StoreIntentFingerprint stores an intent fingerprint for an agent.
func (db *DB) StoreIntentFingerprint(agentID, fingerprint string) error {
	query := `
		INSERT INTO nhi_intent_fingerprints (agent_id, intent_hash, intent_type)
		VALUES ($1, $2, $3)
		ON CONFLICT (intent_hash) DO UPDATE SET
			agent_id = EXCLUDED.agent_id,
			created_at = NOW()
	`

	_, err := db.Exec(query, agentID, fingerprint, "unknown")
	return err
}

// IntentFingerprint retrieves the last known fingerprint for an agent.
func (db *DB) IntentFingerprint(agentID string) (string, error) {
	query := `
		SELECT intent_hash
		FROM nhi_intent_fingerprints
		WHERE agent_id = $1
		ORDER BY created_at DESC
		LIMIT 1
	`

	var fingerprint string
	err := db.QueryRow(query, agentID).Scan(&fingerprint)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", sql.ErrNoRows
		}
		return "", err
	}

	return fingerprint, nil
}

// CreateToken creates a new JWT token record.
func (db *DB) CreateToken(tokenID, agentID, intentHash string, expiresAt time.Time) error {
	query := `
		INSERT INTO nhi_jwt_tokens (token_id, agent_id, intent_hash, issued_at, expires_at, consumed)
		VALUES ($1, $2, $3, NOW(), $4, FALSE)
	`

	_, err := db.Exec(query, tokenID, agentID, intentHash, expiresAt)
	return err
}

// GetToken retrieves a token record.
func (db *DB) GetToken(tokenID string) (models.TokenRecord, error) {
	query := `
		SELECT token_id, agent_id, intent_hash, issued_at, expires_at, consumed,
			CASE WHEN consumed THEN consumed_at ELSE NULL END as consumed_at
		FROM nhi_jwt_tokens
		WHERE token_id = $1
	`

	var token models.TokenRecord
	var consumed bool
	var consumedAt sql.NullTime
	var intentHash string

	err := db.QueryRow(query, tokenID).Scan(
		&token.TokenID,
		&token.AgentID,
		&intentHash,
		&token.IssuedAt,
		&token.ExpiresAt,
		&consumed,
		&consumedAt,
	)

	if err != nil {
		return models.TokenRecord{}, err
	}

	token.IntentFingerprint = intentHash
	token.Status = "issued"
	if consumed {
		token.Status = "used"
		token.UsedAt = &consumedAt.Time
	}

	return token, nil
}

// MarkTokenUsed marks a token as consumed.
func (db *DB) MarkTokenUsed(tokenID string, usedAt time.Time) error {
	query := `
		UPDATE nhi_jwt_tokens
		SET consumed = TRUE, consumed_at = $1
		WHERE token_id = $2 AND consumed = FALSE
	`

	result, err := db.Exec(query, usedAt, tokenID)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// RevokeToken marks a token as revoked.
func (db *DB) RevokeToken(tokenID string, revokedAt time.Time) error {
	query := `
		UPDATE nhi_jwt_tokens
		SET consumed = TRUE, consumed_at = $1
		WHERE token_id = $2 AND consumed = FALSE
	`

	result, err := db.Exec(query, revokedAt, tokenID)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// LogAction logs an agent action to the ALCOA audit ledger.
func (db *DB) LogAction(actionID, agentID, actionType, actionHash string, success bool, errorMessage string, durationMs int, resourcesUsed json.RawMessage) error {
	// Resolve agent_id by name (case-insensitive), use gen_random_uuid for action_id
	query := `
		INSERT INTO alcoa_actions (action_id, agent_id, action_type, action_hash, success, error_message, duration_ms, resources_used)
		VALUES (
			gen_random_uuid(),
			(SELECT agent_id FROM nhi_agents WHERE LOWER(agent_name) = LOWER($1) LIMIT 1),
			$2, $3, $4, $5, $6, $7
		)
	`

	_, err := db.Exec(query, agentID, actionType, actionHash, success, errorMessage, durationMs, resourcesUsed)
	return err
}

// LogGrpcCall logs a gRPC call between services.
func (db *DB) LogGrpcCall(logID, actionID, serviceName, methodName string, requestPayload, responsePayload json.RawMessage, latencyMs int, success bool) error {
	query := `
		INSERT INTO alcoa_grpc_logs (log_id, action_id, service_name, method_name, request_payload, response_payload, latency_ms, success)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := db.Exec(query, logID, actionID, serviceName, methodName, requestPayload, responsePayload, latencyMs, success)
	return err
}
