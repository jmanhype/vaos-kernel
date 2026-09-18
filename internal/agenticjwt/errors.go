package agenticjwt

import "errors"

// Error is an OAuth-shaped protocol error.
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	HTTPStatus  int    `json:"-"`
}

func (e *Error) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

func newError(code, description string, status int) *Error {
	return &Error{Code: code, Description: description, HTTPStatus: status}
}

// Sentinel error codes from draft sections 4.3 and 4.5.
var (
	ErrUnsupportedGrantType = newError("unsupported_grant_type", "Grant type must be 'agent_checksum'", 400)
	ErrInvalidRequest       = newError("invalid_request", "invalid token request", 400)
	ErrUnknownAgent         = newError("unknown_agent", "agent is not registered", 401)
	ErrUnknownRegistration  = newError("unknown_registration", "registration is not found", 404)
	ErrRegistrationRevoked  = newError("registration_revoked", "agent registration is revoked", 401)
	ErrChecksumMismatch     = newError("agent_checksum_mismatch", "agent checksum does not match registration", 401)
	ErrWorkflowUnauthorized = newError("workflow_step_unauthorized", "agent is not authorized for workflow step", 403)
)

func invalidRequest(description string) *Error {
	err := *ErrInvalidRequest
	err.Description = description
	return &err
}

func workflowUnauthorized(description string) *Error {
	err := *ErrWorkflowUnauthorized
	err.Description = description
	return &err
}

// IsCode reports whether err carries the requested OAuth error code.
func IsCode(err error, code string) bool {
	var protocolErr *Error
	if errors.As(err, &protocolErr) {
		return protocolErr.Code == code
	}
	return false
}
