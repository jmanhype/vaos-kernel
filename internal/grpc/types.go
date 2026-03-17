package grpc

// Request carries a single intent execution request over gRPC.
type Request struct {
	AgentID    string            `json:"agent_id"`
	Token      string            `json:"token"`
	Action     string            `json:"action"`
	Resource   string            `json:"resource"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

// Response is the common execution response shape used by all kernel services.
type Response struct {
	ExecutionID    string            `json:"execution_id"`
	Status         string            `json:"status"`
	Detail         string            `json:"detail,omitempty"`
	Attestation    string            `json:"attestation,omitempty"`
	RenderedOutput string            `json:"rendered_output,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

