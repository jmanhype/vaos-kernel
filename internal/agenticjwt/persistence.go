package agenticjwt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const registrySnapshotVersion = 1

// FileRegistryStore is a strict, atomically updated local registry adapter.
// It deliberately contains no Authority signing keys or agent private keys.
type FileRegistryStore struct {
	path string
	mu   sync.Mutex
}

// NewFileRegistryStore validates a private file path. The parent directory
// must already exist so an accidental world-writable temp directory is not
// silently created.
func NewFileRegistryStore(path string) (*FileRegistryStore, error) {
	cleaned := filepath.Clean(path)
	if cleaned == "." || cleaned == string(filepath.Separator) {
		return nil, invalidRequest("registry path must name a file")
	}
	if info, err := os.Lstat(cleaned); err == nil {
		if !info.Mode().IsRegular() {
			return nil, invalidRequest("registry path must be a regular file")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, invalidRequest("registry file permissions must be owner-only")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("inspect agentic registry path: %w", err)
	} else if parent := filepath.Dir(cleaned); parent != "." {
		if _, err := os.Stat(parent); err != nil {
			return nil, fmt.Errorf("inspect agentic registry parent: %w", err)
		}
	}
	return &FileRegistryStore{path: cleaned}, nil
}

// Load reads a snapshot without following JSON unknown fields.
func (store *FileRegistryStore) Load() (RegistrySnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	raw, err := os.ReadFile(store.path)
	if errors.Is(err, fs.ErrNotExist) {
		return RegistrySnapshot{Version: registrySnapshotVersion}, nil
	}
	if err != nil {
		return RegistrySnapshot{}, fmt.Errorf("read agentic registry: %w", err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return RegistrySnapshot{}, invalidRequest("agentic registry file is empty")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var snapshot RegistrySnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return RegistrySnapshot{}, invalidRequest("agentic registry JSON is invalid: " + err.Error())
	}
	if decoder.More() {
		return RegistrySnapshot{}, invalidRequest("agentic registry contains trailing JSON")
	}
	if snapshot.Version != registrySnapshotVersion {
		return RegistrySnapshot{}, invalidRequest("unsupported agentic registry snapshot version")
	}
	return snapshot, nil
}

// AppendAgent durably appends an agent registration.
func (store *FileRegistryStore) AppendAgent(registration AgentRegistration) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	snapshot, err := store.loadLocked()
	if err != nil {
		return err
	}
	public := base64.RawURLEncoding.EncodeToString(registration.PublicKey)
	snapshot.Agents = append(snapshot.Agents, StoredAgentRegistration{
		AppID:            registration.AppID,
		AgentID:          registration.AgentID,
		Spec:             registration.Spec,
		RegistrationID:   registration.RegistrationID,
		Checksum:         registration.Checksum,
		PublicKey:        public,
		RegisteredAt:     registration.RegisteredAt,
		Version:          registration.Version,
		RevokedAt:        registration.RevokedAt,
		RevocationReason: registration.RevocationReason,
	})
	return store.writeLocked(snapshot)
}

// AppendWorkflow durably appends a workflow definition.
func (store *FileRegistryStore) AppendWorkflow(appID string, definition WorkflowDefinition) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	snapshot, err := store.loadLocked()
	if err != nil {
		return err
	}
	snapshot.Workflows = append(snapshot.Workflows, StoredWorkflowDefinition{
		AppID:      appID,
		Definition: definition,
	})
	return store.writeLocked(snapshot)
}

// RevokeRegistration durably updates one registration's revocation metadata.
func (store *FileRegistryStore) RevokeRegistration(appID, registrationID string, revokedAt time.Time, reason string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	snapshot, err := store.loadLocked()
	if err != nil {
		return err
	}
	for index := range snapshot.Agents {
		agent := &snapshot.Agents[index]
		if agent.AppID != appID || agent.RegistrationID != registrationID {
			continue
		}
		if !agent.RevokedAt.IsZero() {
			if agent.RevokedAt.Equal(revokedAt) && agent.RevocationReason == reason {
				return nil
			}
			return invalidRequest("registration is already revoked")
		}
		agent.RevokedAt = revokedAt
		agent.RevocationReason = reason
		return store.writeLocked(snapshot)
	}
	return ErrUnknownRegistration
}

func (store *FileRegistryStore) loadLocked() (RegistrySnapshot, error) {
	raw, err := os.ReadFile(store.path)
	if errors.Is(err, fs.ErrNotExist) {
		return RegistrySnapshot{Version: registrySnapshotVersion}, nil
	}
	if err != nil {
		return RegistrySnapshot{}, fmt.Errorf("read agentic registry: %w", err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return RegistrySnapshot{Version: registrySnapshotVersion}, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var snapshot RegistrySnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return RegistrySnapshot{}, invalidRequest("agentic registry JSON is invalid: " + err.Error())
	}
	if decoder.More() {
		return RegistrySnapshot{}, invalidRequest("agentic registry contains trailing JSON")
	}
	if snapshot.Version != registrySnapshotVersion {
		return RegistrySnapshot{}, invalidRequest("unsupported agentic registry snapshot version")
	}
	return snapshot, nil
}

func (store *FileRegistryStore) writeLocked(snapshot RegistrySnapshot) error {
	if err := validateDurableSnapshot(snapshot); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode agentic registry: %w", err)
	}
	raw = append(raw, '\n')
	directory := filepath.Dir(store.path)
	temp, err := os.CreateTemp(directory, ".agentic-registry-*")
	if err != nil {
		return fmt.Errorf("create agentic registry temp file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("restrict agentic registry temp file: %w", err)
	}
	if _, err := temp.Write(raw); err != nil {
		temp.Close()
		return fmt.Errorf("write agentic registry: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync agentic registry: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close agentic registry: %w", err)
	}
	if err := os.Rename(tempName, store.path); err != nil {
		return fmt.Errorf("replace agentic registry: %w", err)
	}
	if directoryHandle, err := os.Open(directory); err == nil {
		_ = directoryHandle.Sync()
		_ = directoryHandle.Close()
	}
	return nil
}

func (r *Registry) restore(snapshot RegistrySnapshot) error {
	if snapshot.Version != registrySnapshotVersion {
		return invalidRequest("unsupported agentic registry snapshot version")
	}
	agents := make(map[registryKey][]AgentRegistration)
	checksums := make(map[string]registryKey)
	for _, stored := range snapshot.Agents {
		if stored.AppID == "" || stored.RegistrationID == "" {
			return invalidRequest("persisted registration identifiers are required")
		}
		if err := ValidateAgentSpec(stored.Spec); err != nil {
			return err
		}
		if stored.Spec.AgentID != stored.AgentID {
			return invalidRequest("persisted agent ID does not match specification")
		}
		checksum, err := CanonicalChecksum(stored.Spec)
		if err != nil {
			return err
		}
		if checksum != stored.Checksum {
			return invalidRequest("persisted registration checksum mismatch")
		}
		if err := ValidateChecksumFormat(stored.Checksum); err != nil {
			return err
		}
		rawPublic, err := base64.RawURLEncoding.DecodeString(stored.PublicKey)
		if err != nil || len(rawPublic) != ed25519.PublicKeySize {
			return invalidRequest("persisted registration public key is invalid")
		}
		if stored.RegisteredAt.IsZero() || stored.Version <= 0 {
			return invalidRequest("persisted registration metadata is invalid")
		}
		if stored.RevokedAt.IsZero() != (stored.RevocationReason == "") {
			return invalidRequest("persisted revocation metadata is incomplete")
		}
		if !stored.RevokedAt.IsZero() && stored.RevokedAt.Before(stored.RegisteredAt) {
			return invalidRequest("registration was revoked before registration")
		}
		key := registryKey{AppID: stored.AppID, AgentID: stored.AgentID}
		if stored.Version != len(agents[key])+1 {
			return invalidRequest("persisted registration versions are not contiguous")
		}
		if existing, exists := checksums[stored.Checksum]; exists && existing != key {
			return invalidRequest("persisted checksum is shared across agents")
		}
		registration := AgentRegistration{
			AppID:            stored.AppID,
			AgentID:          stored.AgentID,
			Spec:             stored.Spec,
			RegistrationID:   stored.RegistrationID,
			Checksum:         stored.Checksum,
			PublicKey:        append(ed25519.PublicKey(nil), rawPublic...),
			RegisteredAt:     stored.RegisteredAt,
			Version:          stored.Version,
			RevokedAt:        stored.RevokedAt,
			RevocationReason: stored.RevocationReason,
		}
		agents[key] = append(agents[key], registration)
		checksums[stored.Checksum] = key
	}
	workflows := make(map[workflowRegistryKey]WorkflowDefinition)
	for _, stored := range snapshot.Workflows {
		if stored.AppID == "" {
			return invalidRequest("persisted workflow app_id is required")
		}
		if err := ValidateWorkflowDefinition(stored.Definition); err != nil {
			return err
		}
		key := workflowRegistryKey{AppID: stored.AppID, WorkflowID: stored.Definition.WorkflowID}
		if _, exists := workflows[key]; exists {
			return invalidRequest("persisted workflow ID is duplicated")
		}
		definition := stored.Definition
		definition.Steps = append([]WorkflowStep(nil), stored.Definition.Steps...)
		workflows[key] = definition
	}
	r.agents = agents
	r.checksums = checksums
	r.workflows = workflows
	return nil
}

func validateDurableSnapshot(snapshot RegistrySnapshot) error {
	if snapshot.Version != registrySnapshotVersion {
		return invalidRequest("unsupported agentic registry snapshot version")
	}
	seenAgents := make(map[string]struct{}, len(snapshot.Agents))
	for _, agent := range snapshot.Agents {
		if _, duplicate := seenAgents[agent.RegistrationID]; duplicate {
			return invalidRequest("agentic registry contains duplicate registration IDs")
		}
		seenAgents[agent.RegistrationID] = struct{}{}
	}
	seenWorkflows := make(map[string]struct{}, len(snapshot.Workflows))
	for _, workflow := range snapshot.Workflows {
		key := workflow.AppID + "\x00" + workflow.Definition.WorkflowID
		if _, duplicate := seenWorkflows[key]; duplicate {
			return invalidRequest("agentic registry contains duplicate workflow IDs")
		}
		seenWorkflows[key] = struct{}{}
	}
	return nil
}
