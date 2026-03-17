package nhi

import (
	"errors"
	"sync"
	"time"

	"vaos-kernel/pkg/models"
)

// StateChangeCallback is called when an agent's state changes.
type StateChangeCallback func(agentID string, oldState, newState models.AgentState)

// Registry keeps track of non-human identities, intent fingerprints, and JWT lifecycle state.
type Registry struct {
	mu                 sync.RWMutex
	agents             map[string]models.Agent
	intentFingerprints map[string]string
	tokens             map[string]models.TokenRecord
	stateCallbacks     []StateChangeCallback
}

// NewRegistry constructs an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		agents:             make(map[string]models.Agent),
		intentFingerprints: make(map[string]string),
		tokens:             make(map[string]models.TokenRecord),
		stateCallbacks:      make([]StateChangeCallback, 0),
	}
}

// OnStateChange registers a callback to be invoked when any agent's state changes.
func (r *Registry) OnStateChange(callback StateChangeCallback) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stateCallbacks = append(r.stateCallbacks, callback)
}

// RegisterAgent stores or replaces an agent definition.
func (r *Registry) RegisterAgent(agent models.Agent) error {
	if agent.ID == "" {
		return errors.New("register agent: agent id is required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.agents[agent.ID] = agent
	return nil
}

// GetAgent retrieves an agent by id.
func (r *Registry) GetAgent(agentID string) (models.Agent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	agent, ok := r.agents[agentID]
	if !ok {
		return models.Agent{}, errors.New("get agent: agent not found")
	}
	return agent, nil
}

// StoreIntentFingerprint binds an intent fingerprint to an agent.
func (r *Registry) StoreIntentFingerprint(agentID, fingerprint string) error {
	if agentID == "" || fingerprint == "" {
		return errors.New("store intent fingerprint: agent id and fingerprint are required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.agents[agentID]; !ok {
		return errors.New("store intent fingerprint: agent not found")
	}
	r.intentFingerprints[agentID] = fingerprint
	return nil
}

// IntentFingerprint returns the last known fingerprint for an agent.
func (r *Registry) IntentFingerprint(agentID string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	fingerprint, ok := r.intentFingerprints[agentID]
	if !ok {
		return "", errors.New("intent fingerprint: fingerprint not found")
	}
	return fingerprint, nil
}

// TrackToken inserts a new token lifecycle record.
func (r *Registry) TrackToken(record models.TokenRecord) error {
	if record.TokenID == "" {
		return errors.New("track token: token id is required")
	}
	if record.AgentID == "" {
		return errors.New("track token: agent id is required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.agents[record.AgentID]; !ok {
		return errors.New("track token: agent not found")
	}
	r.tokens[record.TokenID] = record
	return nil
}

// MarkTokenUsed marks a token as consumed.
func (r *Registry) MarkTokenUsed(tokenID string, usedAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	record, ok := r.tokens[tokenID]
	if !ok {
		return errors.New("mark token used: token not found")
	}
	record.UsedAt = &usedAt
	record.Status = "used"
	r.tokens[tokenID] = record
	return nil
}

// RevokeToken marks a token as revoked.
func (r *Registry) RevokeToken(tokenID string, revokedAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	record, ok := r.tokens[tokenID]
	if !ok {
		return errors.New("revoke token: token not found")
	}
	record.RevokedAt = &revokedAt
	record.Status = "revoked"
	r.tokens[tokenID] = record
	return nil
}

// Token returns token lifecycle data.
func (r *Registry) Token(tokenID string) (models.TokenRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	record, ok := r.tokens[tokenID]
	if !ok {
		return models.TokenRecord{}, errors.New("token: token not found")
	}
	return record, nil
}

// ListAll returns all agents in the registry.
func (r *Registry) ListAll() []models.Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()

	agents := make([]models.Agent, 0, len(r.agents))
	for _, agent := range r.agents {
		agents = append(agents, agent)
	}
	return agents
}

// UpdateAgentState changes the state of an agent and notifies callbacks.
func (r *Registry) UpdateAgentState(agentID string, newState models.AgentState) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	agent, ok := r.agents[agentID]
	if !ok {
		return errors.New("update agent state: agent not found")
	}

	oldState := agent.State
	if oldState == newState {
		return nil // No change, no notification
	}

	// Update state and last active time
	agent.State = newState
	agent.LastActive = time.Now()
	r.agents[agentID] = agent

	// Notify callbacks outside the lock to prevent deadlock
	callbacks := make([]StateChangeCallback, len(r.stateCallbacks))
	copy(callbacks, r.stateCallbacks)

	r.mu.Unlock()
	for _, callback := range callbacks {
		callback(agentID, oldState, newState)
	}
	r.mu.Lock()

	return nil
}

// UpdateAgent updates multiple fields of an agent at once.
func (r *Registry) UpdateAgent(agentID string, updates map[string]interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	agent, ok := r.agents[agentID]
	if !ok {
		return errors.New("update agent: agent not found")
	}

	oldState := agent.State
	updated := false

	// Update supported fields
	if name, ok := updates["name"].(string); ok && name != "" {
		agent.Name = name
		updated = true
	}
	if persona, ok := updates["persona"].(string); ok {
		agent.Persona = persona
		updated = true
	}
	if state, ok := updates["state"].(models.AgentState); ok {
		agent.State = state
		updated = true
	}
	if metadata, ok := updates["metadata"].(map[string]string); ok {
		agent.Metadata = metadata
		updated = true
	}
	if capabilities, ok := updates["capabilities"].([]models.Capability); ok {
		agent.Capabilities = capabilities
		updated = true
	}

	if !updated {
		return errors.New("update agent: no valid fields to update")
	}

	// Update last active time on any change
	agent.LastActive = time.Now()
	r.agents[agentID] = agent

	// Notify callbacks if state changed
	if agent.State != oldState {
		callbacks := make([]StateChangeCallback, len(r.stateCallbacks))
		copy(callbacks, r.stateCallbacks)

		r.mu.Unlock()
		for _, callback := range callbacks {
			callback(agentID, oldState, agent.State)
		}
		r.mu.Lock()
	}

	return nil
}
