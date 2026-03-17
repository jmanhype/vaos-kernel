package nhi

import (
	"errors"
	"sync"
	"time"

	"vaos-kernel/pkg/models"
)

// Registry keeps track of non-human identities, intent fingerprints, and JWT lifecycle state.
type Registry struct {
	mu                 sync.RWMutex
	agents             map[string]models.Agent
	intentFingerprints map[string]string
	tokens             map[string]models.TokenRecord
}

// NewRegistry constructs an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		agents:             make(map[string]models.Agent),
		intentFingerprints: make(map[string]string),
		tokens:             make(map[string]models.TokenRecord),
	}
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
