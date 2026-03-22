package nhi

import (
	"encoding/json"
	"fmt"
	"time"

	"vaos-kernel/pkg/db"
	"vaos-kernel/pkg/models"
)

// RegistryDB keeps track of non-human identities using PostgreSQL.
type RegistryDB struct {
	db *db.DB
	stateCallbacks []StateChangeCallback
}

// NewRegistryDB constructs a database-backed registry.
func NewRegistryDB(database *db.DB) *RegistryDB {
	return &RegistryDB{
		db:             database,
		stateCallbacks: make([]StateChangeCallback, 0),
	}
}

// OnStateChange registers a callback to be invoked when any agent's state changes.
func (r *RegistryDB) OnStateChange(callback StateChangeCallback) {
	r.stateCallbacks = append(r.stateCallbacks, callback)
}

// RegisterAgent stores or replaces an agent definition.
func (r *RegistryDB) RegisterAgent(agent models.Agent) error {
	if agent.ID == "" {
		return NewErr("register agent: agent id is required")
	}

	// Store agent in database
	if err := r.db.CreateAgent(agent); err != nil {
		return err
	}

	return nil
}

// GetAgent retrieves an agent by id.
func (r *RegistryDB) GetAgent(agentID string) (models.Agent, error) {
	agent, err := r.db.GetAgent(agentID)
	if err != nil {
		return models.Agent{}, NewErr("get agent: %v", err)
	}
	return agent, nil
}

// StoreIntentFingerprint binds an intent fingerprint to an agent.
func (r *RegistryDB) StoreIntentFingerprint(agentID, fingerprint string) error {
	if agentID == "" || fingerprint == "" {
		return NewErr("store intent fingerprint: agent id and fingerprint are required")
	}

	// Verify agent exists first
	if _, err := r.db.GetAgent(agentID); err != nil {
		return NewErr("store intent fingerprint: agent not found")
	}

	if err := r.db.StoreIntentFingerprint(agentID, fingerprint); err != nil {
		return err
	}

	return nil
}

// IntentFingerprint returns last known fingerprint for an agent.
func (r *RegistryDB) IntentFingerprint(agentID string) (string, error) {
	fingerprint, err := r.db.IntentFingerprint(agentID)
	if err != nil {
		return "", NewErr("intent fingerprint: %v", err)
	}
	return fingerprint, nil
}

// TrackToken inserts a new token lifecycle record.
func (r *RegistryDB) TrackToken(record models.TokenRecord) error {
	if record.TokenID == "" {
		return NewErr("track token: token id is required")
	}
	if record.AgentID == "" {
		return NewErr("track token: agent id is required")
	}

	// Verify agent exists first
	if _, err := r.db.GetAgent(record.AgentID); err != nil {
		return NewErr("track token: agent not found")
	}

	if err := r.db.CreateToken(record.TokenID, record.AgentID, record.IntentFingerprint, record.ExpiresAt); err != nil {
		return err
	}

	return nil
}

// MarkTokenUsed marks a token as consumed.
func (r *RegistryDB) MarkTokenUsed(tokenID string, usedAt time.Time) error {
	if err := r.db.MarkTokenUsed(tokenID, usedAt); err != nil {
		return NewErr("mark token used: %v", err)
	}
	return nil
}

// RevokeToken marks a token as revoked.
func (r *RegistryDB) RevokeToken(tokenID string, revokedAt time.Time) error {
	if err := r.db.RevokeToken(tokenID, revokedAt); err != nil {
		return NewErr("revoke token: %v", err)
	}
	return nil
}

// Token returns token lifecycle data.
func (r *RegistryDB) Token(tokenID string) (models.TokenRecord, error) {
	token, err := r.db.GetToken(tokenID)
	if err != nil {
		return models.TokenRecord{}, NewErr("token: %v", err)
	}
	return token, nil
}

// ListAll returns all agents in registry.
func (r *RegistryDB) ListAll() []models.Agent {
	agents, err := r.db.ListAgents()
	if err != nil {
		// Log error but return empty slice
		return []models.Agent{}
	}
	return agents
}

// UpdateAgentState changes state of an agent and notifies callbacks.
// Note: This is currently an in-memory operation. State persistence requires
// extending the database schema to track agent state.
func (r *RegistryDB) UpdateAgentState(agentID string, newState models.AgentState) error {
	// For now, we don't persist state changes to the database
	// This would require adding a state column to nhi_agents
	// Notify callbacks
	for _, callback := range r.stateCallbacks {
		callback(agentID, models.AgentStateUnspecified, newState)
	}

	return nil
}

// UpdateAgent updates multiple fields of an agent at once.
// Note: This is currently an in-memory operation for state updates.
// Other fields can be persisted to the database.
func (r *RegistryDB) UpdateAgent(agentID string, updates map[string]interface{}) error {
	// For now, just notify callbacks if state is being updated
	if state, ok := updates["state"].(models.AgentState); ok {
		for _, callback := range r.stateCallbacks {
			callback(agentID, models.AgentStateUnspecified, state)
		}
	}

	return nil
}

// LogAction logs an agent action to the ALCOA audit ledger.
func (r *RegistryDB) LogAction(actionID, agentID, actionType, actionHash string, success bool, errorMessage string, durationMs int, resourcesUsed map[string]interface{}) error {
	var resourcesJSON json.RawMessage
	if resourcesUsed != nil {
		var err error
		resourcesJSON, err = json.Marshal(resourcesUsed)
		if err != nil {
			return err
		}
	}

	if err := r.db.LogAction(actionID, agentID, actionType, actionHash, success, errorMessage, durationMs, resourcesJSON); err != nil {
		return err
	}

	return nil
}

// LogGrpcCall logs a gRPC call between services.
func (r *RegistryDB) LogGrpcCall(logID, actionID, serviceName, methodName string, requestPayload, responsePayload map[string]interface{}, latencyMs int, success bool) error {
	var requestJSON, responseJSON json.RawMessage
	var err error

	if requestPayload != nil {
		requestJSON, err = json.Marshal(requestPayload)
		if err != nil {
			return err
		}
	}

	if responsePayload != nil {
		responseJSON, err = json.Marshal(responsePayload)
		if err != nil {
			return err
		}
	}

	if err := r.db.LogGrpcCall(logID, actionID, serviceName, methodName, requestJSON, responseJSON, latencyMs, success); err != nil {
		return err
	}

	return nil
}

// Err is a simple error wrapper for registry errors.
type Err struct {
	msg string
}

func NewErr(format string, args ...interface{}) *Err {
	return &Err{msg: fmt.Errorf(format, args...).Error()}
}

func (e *Err) Error() string {
	return e.msg
}

func (e *Err) Unwrap() error {
	return nil
}
