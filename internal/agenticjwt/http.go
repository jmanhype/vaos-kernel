package agenticjwt

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// HandleToken implements POST /v1/intent/token for the P0 profile.
//
// The endpoint must be wrapped by transport authentication in the host
// application. It deliberately performs no client-credential authentication so
// the protocol layer remains independently testable.
func (a *Authority) HandleToken(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		a.writeError(writer, newError("invalid_request", "method must be POST", http.StatusMethodNotAllowed))
		return
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var tokenRequest TokenRequest
	if err := decoder.Decode(&tokenRequest); err != nil {
		if auditErr := a.recordAudit(a.mintAuditEntry(tokenRequest, nil, err)); auditErr != nil {
			a.writeError(writer, serverError(auditErr))
			return
		}
		a.writeError(writer, invalidRequest("malformed token request JSON: "+err.Error()))
		return
	}
	response, _, err := a.Mint(a.appID, tokenRequest)
	if err != nil {
		a.writeError(writer, err)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(response)
}

// HandleRegistration implements POST /v1/intent/register/agent for the P0
// profile. Like HandleToken, it must be wrapped by host authentication.
func (a *Authority) HandleRegistration(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		a.writeError(writer, newError("invalid_request", "method must be POST", http.StatusMethodNotAllowed))
		return
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var registrationRequest AgentRegistrationRequest
	if err := decoder.Decode(&registrationRequest); err != nil {
		if auditErr := a.recordAudit(registrationAuditEntry(registrationRequest.AgentSpec, nil, err)); auditErr != nil {
			a.writeError(writer, serverError(auditErr))
			return
		}
		a.writeError(writer, invalidRequest("malformed registration request JSON: "+err.Error()))
		return
	}
	if registrationRequest.PublicKey == "" {
		err := invalidRequest("public_key is required")
		if auditErr := a.recordAudit(registrationAuditEntry(registrationRequest.AgentSpec, nil, err)); auditErr != nil {
			a.writeError(writer, serverError(auditErr))
			return
		}
		a.writeError(writer, invalidRequest("public_key is required"))
		return
	}
	rawPublic, err := base64.RawURLEncoding.DecodeString(registrationRequest.PublicKey)
	if err != nil {
		err = invalidRequest("public_key must be base64url without padding")
		if auditErr := a.recordAudit(registrationAuditEntry(registrationRequest.AgentSpec, nil, err)); auditErr != nil {
			a.writeError(writer, serverError(auditErr))
			return
		}
		a.writeError(writer, err)
		return
	}
	if len(rawPublic) != ed25519.PublicKeySize {
		err := invalidRequest("public_key must be a raw Ed25519 public key")
		if auditErr := a.recordAudit(registrationAuditEntry(registrationRequest.AgentSpec, nil, err)); auditErr != nil {
			a.writeError(writer, serverError(auditErr))
			return
		}
		a.writeError(writer, err)
		return
	}

	registration, err := a.registry.Register(a.appID, registrationRequest.AgentSpec, ed25519.PublicKey(rawPublic))
	if err != nil {
		if auditErr := a.recordAudit(registrationAuditEntry(registrationRequest.AgentSpec, nil, err)); auditErr != nil {
			a.writeError(writer, serverError(auditErr))
			return
		}
		a.writeError(writer, err)
		return
	}
	if err := a.recordAudit(registrationAuditEntry(registrationRequest.AgentSpec, &registration, nil)); err != nil {
		a.writeError(writer, serverError(err))
		return
	}
	response := AgentRegistrationResponse{
		AgentID:        registration.AgentID,
		RegistrationID: registration.RegistrationID,
		Checksum:       registration.Checksum,
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(response)
}

// HandleWorkflowRegistration implements POST /v1/intent/register/workflow. The
// host must wrap it with administrative authentication.
func (a *Authority) HandleWorkflowRegistration(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		a.writeError(writer, newError("invalid_request", "method must be POST", http.StatusMethodNotAllowed))
		return
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var definition WorkflowDefinition
	if err := decoder.Decode(&definition); err != nil {
		if auditErr := a.recordAudit(workflowRegistrationAuditEntry(definition, err)); auditErr != nil {
			a.writeError(writer, serverError(auditErr))
			return
		}
		a.writeError(writer, invalidRequest("malformed workflow registration JSON: "+err.Error()))
		return
	}
	if err := a.registry.RegisterWorkflow(a.appID, definition); err != nil {
		if auditErr := a.recordAudit(workflowRegistrationAuditEntry(definition, err)); auditErr != nil {
			a.writeError(writer, serverError(auditErr))
			return
		}
		a.writeError(writer, err)
		return
	}
	if err := a.recordAudit(workflowRegistrationAuditEntry(definition, nil)); err != nil {
		a.writeError(writer, serverError(err))
		return
	}
	response := WorkflowRegistrationResponse{Status: "registered", WorkflowID: definition.WorkflowID}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(response)
}

// HandleJWKS exposes the read-only public Authority signing key set.
func (a *Authority) HandleJWKS(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		a.writeError(writer, newError("invalid_request", "method must be GET", http.StatusMethodNotAllowed))
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "public, max-age=300")
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(a.JWKS())
}

func (a *Authority) writeError(writer http.ResponseWriter, err error) {
	protocolErr, ok := err.(*Error)
	if !ok {
		protocolErr = newError("server_error", "token request failed", http.StatusInternalServerError)
	}
	if protocolErr.HTTPStatus == 0 {
		protocolErr.HTTPStatus = http.StatusBadRequest
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.WriteHeader(protocolErr.HTTPStatus)
	_ = json.NewEncoder(writer).Encode(protocolErr)
}
