package hash

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"golang.org/x/crypto/blake2b"

	"vaos-kernel/pkg/models"
)

// Hasher produces deterministic cryptographic intent fingerprints.
type Hasher struct{}

// HashRaw returns a BLAKE2b-256 hex digest of an arbitrary string.
func (Hasher) HashRaw(input string) string {
	sum := blake2b.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

// HashIntent returns a deterministic BLAKE2b-256 digest for the supplied intent.
func (Hasher) HashIntent(intent models.IntentRequest) (string, error) {
	if intent.AgentID == "" {
		return "", errors.New("hash intent: agent id is required")
	}
	if intent.Action == "" {
		return "", errors.New("hash intent: action is required")
	}
	if intent.Resource == "" {
		return "", errors.New("hash intent: resource is required")
	}

	normalized := struct {
		AgentID     string              `json:"agent_id"`
		Action      string              `json:"action"`
		Resource    string              `json:"resource"`
		Parameters  [][2]string         `json:"parameters,omitempty"`
		Description string              `json:"description,omitempty"`
	}{
		AgentID:     intent.AgentID,
		Action:      intent.Action,
		Resource:    intent.Resource,
		Description: intent.Description,
	}

	if len(intent.Parameters) > 0 {
		keys := make([]string, 0, len(intent.Parameters))
		for key := range intent.Parameters {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		normalized.Parameters = make([][2]string, 0, len(keys))
		for _, key := range keys {
			normalized.Parameters = append(normalized.Parameters, [2]string{key, intent.Parameters[key]})
		}
	}

	payload, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}

	sum := blake2b.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

