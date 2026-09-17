package agenticjwt

import (
	"fmt"

	"vaos-kernel/pkg/models"
)

// AuditEntry is the kernel's existing ALCOA+ audit record. The alias keeps the
// protocol package decoupled from the concrete ledger implementation.
type AuditEntry = models.AuditEntry

// AuditRecorder is the minimal dependency needed by the Agentic JWT authority.
type AuditRecorder interface {
	Record(entry AuditEntry) (AuditEntry, error)
}

// AuthorityOption configures optional authority dependencies.
type AuthorityOption func(*Authority) error

// WithAuditRecorder records registration, mint, checksum mismatch, and
// verification events in the kernel's hash-chained audit trail.
func WithAuditRecorder(recorder AuditRecorder) AuthorityOption {
	return func(authority *Authority) error {
		if recorder == nil {
			return invalidRequest("audit recorder is required")
		}
		authority.audit = recorder
		return nil
	}
}

func (a *Authority) recordAudit(entry AuditEntry) error {
	if a.audit == nil {
		return nil
	}
	if entry.Component == "" {
		entry.Component = "kernel.agentic_jwt"
	}
	_, err := a.audit.Record(entry)
	if err != nil {
		return fmt.Errorf("record agentic jwt audit entry: %w", err)
	}
	return nil
}

func serverError(error) *Error {
	return newError("server_error", "agentic jwt operation failed", 500)
}

func (a *Authority) mintAuditEntry(request TokenRequest, jti *string, err error) AuditEntry {
	entry := AuditEntry{
		AgentID:           request.AgentID,
		IntentFingerprint: request.ComputedChecksum,
		Action:            "agentic_token_minted",
		Status:            "success",
		Details: map[string]string{
			"workflow_id":   request.WorkflowID,
			"workflow_step": request.WorkflowStep,
		},
	}
	if jti != nil {
		entry.Details["jti"] = *jti
	}
	if err != nil {
		entry.Action = "agentic_token_mint_failed"
		entry.Status = "error"
		entry.Details["error"] = err.Error()
	}
	return entry
}

func (a *Authority) verifyAuditEntry(jti string, claims *Claims, err error) AuditEntry {
	entry := AuditEntry{
		Action: "agentic_token_verified",
		Status: "success",
		Details: map[string]string{
			"jti": jti,
		},
	}
	if claims != nil {
		entry.AgentID = claims.Subject
		entry.IntentFingerprint = claims.AgentProof.AgentChecksum
		entry.Details["registration_id"] = claims.AgentProof.RegistrationID
	}
	if err != nil {
		entry.Action = "agentic_token_verify_failed"
		entry.Status = "error"
		entry.Details["error"] = err.Error()
	}
	return entry
}

func registrationAuditEntry(spec AgentSpec, registration *AgentRegistration, err error) AuditEntry {
	entry := AuditEntry{
		AgentID: spec.AgentID,
		Action:  "agentic_agent_registered",
		Status:  "success",
	}
	if registration != nil {
		entry.IntentFingerprint = registration.Checksum
		entry.Details = map[string]string{
			"registration_id": registration.RegistrationID,
		}
	}
	if err != nil {
		entry.Action = "agentic_agent_registration_failed"
		entry.Status = "error"
		entry.Details = map[string]string{"error": err.Error()}
	}
	return entry
}

func workflowRegistrationAuditEntry(definition WorkflowDefinition, err error) AuditEntry {
	entry := AuditEntry{
		AgentID: "agentic_authority",
		Action:  "agentic_workflow_registered",
		Status:  "success",
		Details: map[string]string{
			"workflow_id": definition.WorkflowID,
			"step_count":  fmt.Sprintf("%d", len(definition.Steps)),
		},
	}
	if err != nil {
		entry.Action = "agentic_workflow_registration_failed"
		entry.Status = "error"
		entry.Details["error"] = err.Error()
	}
	return entry
}
