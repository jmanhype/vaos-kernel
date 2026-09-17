package agenticjwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"sync"
	"time"
)

type registryKey struct {
	AppID   string
	AgentID string
}

type workflowRegistryKey struct {
	AppID      string
	WorkflowID string
}

// RegistryStore persists the append-only registry state. Implementations must
// make each mutation durable before returning; the in-memory mutation happens
// only after that succeeds.
type RegistryStore interface {
	Load() (RegistrySnapshot, error)
	AppendAgent(AgentRegistration) error
	AppendWorkflow(appID string, definition WorkflowDefinition) error
	RevokeRegistration(appID, registrationID string, revokedAt time.Time, reason string) error
}

// RegistrySnapshot is the storage adapter's durable representation.
type RegistrySnapshot struct {
	Version   int                        `json:"version"`
	Agents    []StoredAgentRegistration  `json:"agents"`
	Workflows []StoredWorkflowDefinition `json:"workflows"`
}

// StoredAgentRegistration persists identity material needed to validate the
// checksum after restart. It never contains agent private keys.
type StoredAgentRegistration struct {
	AppID            string    `json:"app_id"`
	AgentID          string    `json:"agent_id"`
	Spec             AgentSpec `json:"agent_components"`
	RegistrationID   string    `json:"registration_id"`
	Checksum         string    `json:"checksum"`
	PublicKey        string    `json:"public_key"`
	RegisteredAt     time.Time `json:"registered_at"`
	Version          int       `json:"version"`
	RevokedAt        time.Time `json:"revoked_at,omitempty"`
	RevocationReason string    `json:"revocation_reason,omitempty"`
}

// StoredWorkflowDefinition associates a workflow with its application scope.
type StoredWorkflowDefinition struct {
	AppID      string             `json:"app_id"`
	Definition WorkflowDefinition `json:"definition"`
}

// RegistryOption configures optional registry dependencies.
type RegistryOption func(*Registry) error

// Registry stores immutable, versioned agent registrations.
type Registry struct {
	mu        sync.RWMutex
	agents    map[registryKey][]AgentRegistration
	checksums map[string]registryKey
	workflows map[workflowRegistryKey]WorkflowDefinition
	now       func() time.Time
	store     RegistryStore
}

// NewRegistry creates a registry. The now function is injectable for tests.
func NewRegistry(now func() time.Time) *Registry {
	if now == nil {
		now = time.Now
	}
	return &Registry{
		agents:    make(map[registryKey][]AgentRegistration),
		checksums: make(map[string]registryKey),
		workflows: make(map[workflowRegistryKey]WorkflowDefinition),
		now:       now,
	}
}

// NewRegistryWithStore creates a registry and restores its durable snapshot.
func NewRegistryWithStore(now func() time.Time, store RegistryStore) (*Registry, error) {
	if store == nil {
		return nil, invalidRequest("registry store is required")
	}
	registry := NewRegistry(now)
	if err := WithRegistryStore(store)(registry); err != nil {
		return nil, err
	}
	return registry, nil
}

// WithRegistryStore loads and attaches durable registry storage.
func WithRegistryStore(store RegistryStore) RegistryOption {
	return func(registry *Registry) error {
		if store == nil {
			return invalidRequest("registry store is required")
		}
		snapshot, err := store.Load()
		if err != nil {
			return fmt.Errorf("load agentic registry: %w", err)
		}
		if err := registry.restore(snapshot); err != nil {
			return fmt.Errorf("restore agentic registry: %w", err)
		}
		registry.store = store
		return nil
	}
}

// ValidateAgentSpec enforces the REQUIRED fields from draft section 5.2.1.
func ValidateAgentSpec(spec AgentSpec) error {
	if spec.AgentID == "" {
		return invalidRequest("agent_id is required")
	}
	if NormalizePrompt(spec.Prompt) == "" {
		return invalidRequest("prompt is required")
	}
	if len(spec.Tools) == 0 {
		return invalidRequest("at least one tool is required")
	}
	for index, tool := range spec.Tools {
		if tool.Name == "" || tool.Signature == "" || tool.Description == "" {
			return invalidRequest(fmt.Sprintf("tool %d requires name, signature, and description", index))
		}
	}
	return nil
}

// Register recomputes and stores an agent checksum. Registration records are
// append-only; a changed configuration creates a new version.
func (r *Registry) Register(appID string, spec AgentSpec, publicKey ed25519.PublicKey) (AgentRegistration, error) {
	if appID == "" {
		return AgentRegistration{}, invalidRequest("app_id is required")
	}
	if err := ValidateAgentSpec(spec); err != nil {
		return AgentRegistration{}, err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return AgentRegistration{}, invalidRequest("Ed25519 public key is required")
	}
	checksum, err := CanonicalChecksum(spec)
	if err != nil {
		return AgentRegistration{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	key := registryKey{AppID: appID, AgentID: spec.AgentID}
	if existingKey, exists := r.checksums[checksum]; exists {
		if existingKey == key {
			return AgentRegistration{}, newError("duplicate_agent", "agent with identical checksum already exists", 400)
		}
		return AgentRegistration{}, newError("duplicate_agent", "checksum is already registered by another agent", 400)
	}

	version := len(r.agents[key]) + 1
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return AgentRegistration{}, fmt.Errorf("generate registration id: %w", err)
	}
	registration := AgentRegistration{
		AppID:          appID,
		AgentID:        spec.AgentID,
		Spec:           spec,
		RegistrationID: fmt.Sprintf("reg_%s_%d_%s", spec.AgentID, r.now().Unix(), hex.EncodeToString(nonce)),
		Checksum:       checksum,
		PublicKey:      append(ed25519.PublicKey(nil), publicKey...),
		RegisteredAt:   r.now().UTC(),
		Version:        version,
	}
	if r.store != nil {
		if err := r.store.AppendAgent(registration); err != nil {
			return AgentRegistration{}, fmt.Errorf("persist agent registration: %w", err)
		}
	}
	r.agents[key] = append(r.agents[key], registration)
	r.checksums[checksum] = key
	return registration, nil
}

// Registration returns one immutable registration by ID.
func (r *Registry) Registration(appID, registrationID string) (AgentRegistration, error) {
	if appID == "" || registrationID == "" {
		return AgentRegistration{}, invalidRequest("app_id and registration_id are required")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, records := range r.agents {
		for _, registration := range records {
			if registration.AppID == appID && registration.RegistrationID == registrationID {
				return registration, nil
			}
		}
	}
	return AgentRegistration{}, ErrUnknownRegistration
}

// Latest returns the newest registration for an agent.
func (r *Registry) Latest(appID, agentID string) (AgentRegistration, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	records := r.agents[registryKey{AppID: appID, AgentID: agentID}]
	if len(records) == 0 {
		return AgentRegistration{}, ErrUnknownAgent
	}
	return records[len(records)-1], nil
}

// RegisterWorkflow validates and stores an immutable ordered workflow.
func (r *Registry) RegisterWorkflow(appID string, definition WorkflowDefinition) error {
	if appID == "" {
		return invalidRequest("app_id is required")
	}
	if err := ValidateWorkflowDefinition(definition); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	key := workflowRegistryKey{AppID: appID, WorkflowID: definition.WorkflowID}
	if _, exists := r.workflows[key]; exists {
		return invalidRequest("workflow_id is already registered")
	}
	stored := definition
	stored.Steps = append([]WorkflowStep(nil), definition.Steps...)
	if r.store != nil {
		if err := r.store.AppendWorkflow(appID, stored); err != nil {
			return fmt.Errorf("persist workflow registration: %w", err)
		}
	}
	r.workflows[key] = stored
	return nil
}

var revocationReasonPattern = regexp.MustCompile(`^[[:print:]]{3,128}$`)

// RevokeRegistration revokes one immutable registration. It is idempotent for
// an already-revoked record and fails closed if persistence fails.
func (r *Registry) RevokeRegistration(appID, registrationID, reason string) error {
	if registrationID == "" {
		return invalidRequest("registration_id is required")
	}
	if !revocationReasonPattern.MatchString(reason) {
		return invalidRequest("revocation reason must contain 3-128 printable characters")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, records := range r.agents {
		for _, registration := range records {
			if registration.AppID != appID || registration.RegistrationID != registrationID {
				continue
			}
			if !registration.RevokedAt.IsZero() {
				if registration.RevocationReason == reason {
					return nil
				}
				return invalidRequest("registration is already revoked")
			}
			revokedAt := r.now().UTC()
			if r.store != nil {
				if err := r.store.RevokeRegistration(appID, registrationID, revokedAt, reason); err != nil {
					return fmt.Errorf("persist registration revocation: %w", err)
				}
			}
			key := registryKey{AppID: appID, AgentID: registration.AgentID}
			for index := range r.agents[key] {
				if r.agents[key][index].RegistrationID == registrationID {
					registration.RevokedAt = revokedAt
					registration.RevocationReason = reason
					r.agents[key][index] = registration
					return nil
				}
			}
			return fmt.Errorf("update revoked registration in memory")
		}
	}
	return ErrUnknownRegistration
}

// ValidateWorkflowDefinition enforces the draft's ordered workflow shape and
// approval-gate invariant. Ordered definitions cannot contain transition cycles.
func ValidateWorkflowDefinition(definition WorkflowDefinition) error {
	if definition.WorkflowID == "" {
		return invalidRequest("workflow_id is required")
	}
	if len(definition.Steps) == 0 {
		return invalidRequest("workflow must contain at least one step")
	}
	seen := make(map[string]struct{}, len(definition.Steps))
	approvalGateSeen := false
	for _, step := range definition.Steps {
		if step.StepID == "" {
			return invalidRequest("workflow step_id is required")
		}
		if _, exists := seen[step.StepID]; exists {
			return invalidRequest("workflow step IDs must be unique")
		}
		seen[step.StepID] = struct{}{}
		if step.RequiresApproval && !approvalGateSeen {
			return invalidRequest("approval-required workflow step must have a prior approval gate")
		}
		if step.ApprovalGate {
			approvalGateSeen = true
		}
	}
	return nil
}

// ValidateRequest performs the P0 ordered validation sequence.
func (r *Registry) ValidateRequest(appID string, request TokenRequest) (AgentRegistration, error) {
	if request.GrantType != "agent_checksum" && request.GrantType != "urn:ietf:params:oauth:grant-type:agent_checksum" {
		return AgentRegistration{}, ErrUnsupportedGrantType
	}
	if request.AgentID == "" {
		return AgentRegistration{}, invalidRequest("agent_id is required")
	}
	if err := ValidateChecksumFormat(request.ComputedChecksum); err != nil {
		return AgentRegistration{}, err
	}
	if request.WorkflowEnabled && (request.WorkflowID == "" || request.WorkflowStep == "") {
		return AgentRegistration{}, invalidRequest("workflow_id and workflow_step are required when workflow_enabled is true")
	}
	if len(request.RequestedScopes) == 0 {
		return AgentRegistration{}, invalidRequest("requested_scopes is required")
	}
	for _, scope := range request.RequestedScopes {
		if scope == "" {
			return AgentRegistration{}, invalidRequest("requested_scopes cannot contain an empty scope")
		}
	}
	if len(request.Audience) == 0 {
		return AgentRegistration{}, invalidRequest("audience is required")
	}
	for _, audience := range request.Audience {
		if audience == "" {
			return AgentRegistration{}, invalidRequest("audience cannot contain an empty value")
		}
	}

	registration, err := r.Latest(appID, request.AgentID)
	if err != nil {
		return AgentRegistration{}, err
	}
	if !checksumEqual(request.ComputedChecksum, registration.Checksum) {
		return AgentRegistration{}, ErrChecksumMismatch
	}
	if !registration.RevokedAt.IsZero() {
		return AgentRegistration{}, ErrRegistrationRevoked
	}
	if err := r.validateWorkflow(appID, registration.AgentID, request); err != nil {
		return AgentRegistration{}, err
	}
	return registration, nil
}

func (r *Registry) validateWorkflow(appID, agentID string, request TokenRequest) error {
	if !request.WorkflowEnabled {
		return nil
	}

	r.mu.RLock()
	definition, exists := r.workflows[workflowRegistryKey{AppID: appID, WorkflowID: request.WorkflowID}]
	r.mu.RUnlock()
	if !exists {
		return workflowUnauthorized("workflow is not registered")
	}

	targetIndex := -1
	for index, step := range definition.Steps {
		if step.StepID == request.WorkflowStep {
			targetIndex = index
			break
		}
	}
	if targetIndex < 0 {
		return workflowUnauthorized("workflow step is not registered")
	}
	target := definition.Steps[targetIndex]
	if target.AgentID != "" && target.AgentID != agentID {
		return workflowUnauthorized("agent is not authorized for workflow step")
	}

	var completed []string
	var chain []string
	if request.DelegationContext != nil {
		completed = request.DelegationContext.CompletedSteps
		chain = request.DelegationContext.Chain
	}
	completedIndexes := make(map[int]struct{}, len(completed))
	lastIndex := -1
	for _, stepID := range completed {
		index := -1
		for candidate, step := range definition.Steps {
			if step.StepID == stepID {
				index = candidate
				break
			}
		}
		if index < 0 {
			return workflowUnauthorized("completed workflow step is not registered")
		}
		if index >= targetIndex {
			return workflowUnauthorized("completed workflow step occurs at or after requested step")
		}
		if _, duplicate := completedIndexes[index]; duplicate {
			return workflowUnauthorized("completed workflow steps contain duplicates")
		}
		if index <= lastIndex {
			return workflowUnauthorized("completed workflow steps are out of order")
		}
		completedIndexes[index] = struct{}{}
		lastIndex = index
	}

	approvalPassed := false
	expectedChain := make([]string, 0, len(completed))
	for index, step := range definition.Steps[:targetIndex] {
		_, isCompleted := completedIndexes[index]
		if isCompleted {
			if step.ApprovalGate {
				approvalPassed = true
			}
			if step.AgentID != "" {
				expectedChain = append(expectedChain, step.AgentID)
			}
		}
		if step.Required && !isCompleted {
			return workflowUnauthorized("required workflow prerequisite is not completed")
		}
	}
	if target.RequiresApproval && !approvalPassed {
		return workflowUnauthorized("workflow approval gate has not passed")
	}
	if !equalStrings(chain, expectedChain) {
		return workflowUnauthorized("delegation chain does not match completed workflow agents")
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
