package grpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	basegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"vaos-kernel/internal/audit"
	"vaos-kernel/internal/hash"
	kjwt "vaos-kernel/internal/jwt"
	"vaos-kernel/internal/nhi"
	"vaos-kernel/pkg/models"
)

// Dependencies contains the shared collaborators required by the service layer.
type Dependencies struct {
	Registry *nhi.Registry
	Issuer   *kjwt.Issuer
	Hasher   hash.Hasher
	Ledger   audit.Recorder
}

// Server owns the gRPC runtime and all registered services.
type Server struct {
	grpcServer *basegrpc.Server
	deps       Dependencies
	seq        atomic.Uint64
}

// NewServer wires the kernel service endpoints into a gRPC server.
func NewServer(deps Dependencies) (*Server, error) {
	if deps.Registry == nil {
		return nil, errors.New("new grpc server: registry is required")
	}
	if deps.Issuer == nil {
		return nil, errors.New("new grpc server: issuer is required")
	}
	if deps.Ledger == nil {
		return nil, errors.New("new grpc server: ledger is required")
	}

	s := &Server{
		grpcServer: basegrpc.NewServer(),
		deps:       deps,
	}
	
	// Register KernelService for VAS-Swarm communication
	ks := &kernelServiceServer{}
	s.grpcServer.RegisterService(&basegrpc.ServiceDesc{
		ServiceName: "vaos.kernel.KernelService",
		HandlerType: (*kernelService)(nil),
		Methods: []basegrpc.MethodDesc{
			{
				MethodName: "RequestToken",
				Handler:    s.wrapKernelUnary(s.handleRequestToken),
			},
			{
				MethodName: "SubmitTelemetry",
				Handler:    s.wrapKernelUnary(s.handleSubmitTelemetry),
			},
			{
				MethodName: "SubmitRoutingLog",
				Handler:    s.wrapKernelUnary(s.handleSubmitRoutingLog),
			},
			{
				MethodName: "ConfirmAudit",
				Handler:    s.wrapKernelUnary(s.handleConfirmAudit),
			},
			{
				MethodName: "ExecuteIntent",
				Handler:    s.wrapKernelUnary(s.handleExecuteIntent),
			},
		},
	}, ks)
	
	// Register SandboxControl service for VAS-Crucible communication
	sc := &sandboxControlServer{}
	s.grpcServer.RegisterService(&basegrpc.ServiceDesc{
		ServiceName: "vaos.kernel.crucible.v1.SandboxControl",
		HandlerType: (*sandboxControl)(nil),
		Methods: []basegrpc.MethodDesc{
			{
				MethodName: "CreateSandbox",
				Handler:    s.wrapCrucibleUnary(s.handleCreateSandbox),
			},
			{
				MethodName: "ExecuteCode",
				Handler:    s.wrapCrucibleUnary(s.handleExecuteCode),
			},
			{
				MethodName: "TerminateSandbox",
				Handler:    s.wrapCrucibleUnary(s.handleTerminateSandbox),
			},
			{
				MethodName: "Heartbeat",
				Handler:    s.wrapCrucibleUnary(s.handleHeartbeat),
			},
		},
	}, sc)
	
	return s, nil
}

type kernelService interface{}
type sandboxControl interface{}

type kernelServiceServer struct{}
type sandboxControlServer struct{}

// Request/Response types (in production, these would be generated from proto)
type TokenRequest struct {
	AgentID    string            `json:"agent_id"`
	IntentHash string            `json:"intent_hash"`
	ActionType string            `json:"action_type"`
	Metadata   map[string]string `json:"metadata"`
}

type TokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	Scope     string `json:"scope"`
	Error     string `json:"error,omitempty"`
}

type TelemetryRequest struct {
	AgentID        string            `json:"agent_id"`
	Timestamp      int64             `json:"timestamp"`
	Status         string            `json:"status"`
	CPUUsage       float32           `json:"cpu_usage"`
	MemoryUsage    float32           `json:"memory_usage"`
	TasksCompleted int32             `json:"tasks_completed"`
	TasksFailed    int32             `json:"tasks_failed"`
	AvgTaskDuration float32          `json:"avg_task_duration"`
	TokensUsed     int32             `json:"tokens_used"`
	CostEstimate   float32           `json:"cost_estimate"`
	CustomMetrics  map[string]string `json:"custom_metrics"`
}

type TelemetryResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type RoutingLogRequest struct {
	SessionID   string  `json:"session_id"`
	AgentID     string  `json:"agent_id"`
	Timestamp   int64   `json:"timestamp"`
	Mode        string  `json:"mode"`
	Genre       string  `json:"genre"`
	Type        string  `json:"type"`
	Format      string  `json:"format"`
	Weight      float32 `json:"weight"`
	Confidence  string  `json:"confidence"`
	Tier        string  `json:"tier"`
	Model       string  `json:"model"`
	Provider    string  `json:"provider"`
	IntentHash  string  `json:"intent_hash"`
}

type RoutingLogResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	CorrelationID string `json:"correlation_id"`
}

type AuditConfirmation struct {
	AgentID        string            `json:"agent_id"`
	ActionID       string            `json:"action_id"`
	IntentHash     string            `json:"intent_hash"`
	JWTToken       string            `json:"jwt_token"`
	Attributable   bool              `json:"attributable"`
	Legible        bool              `json:"legible"`
	Contemporaneous bool             `json:"contemporaneous"`
	Original       bool              `json:"original"`
	Accurate       bool              `json:"accurate"`
	PerformedAt    int64             `json:"performed_at"`
	PerformedBy    string            `json:"performed_by"`
	Method         string            `json:"method"`
	Context        map[string]string `json:"context"`
}

type AuditResponse struct {
	Confirmed bool   `json:"confirmed"`
	AuditID   string `json:"audit_id"`
	Error     string `json:"error,omitempty"`
}

type SwarmIntentRequest struct {
	AgentID    string            `json:"agent_id"`
	Token      string            `json:"token"`
	Action     string            `json:"action"`
	Resource   string            `json:"resource"`
	Parameters map[string]string `json:"parameters"`
}

type SwarmIntentResponse struct {
	ExecutionID string `json:"execution_id"`
	Status      string `json:"status"`
	Detail      string `json:"detail"`
}

// Crucible types
type CreateSandboxRequest struct {
	AgentID    string         `json:"agent_id"`
	JWT        string         `json:"jwt"`
	IntentHash string         `json:"intent_hash"`
	Limits     ResourceLimits `json:"limits"`
}

type ResourceLimits struct {
	CPUCores      int32 `json:"cpu_cores"`
	MemoryMB      int64 `json:"memory_mb"`
	NetworkEnabled bool  `json:"network_enabled"`
}

type CreateSandboxResponse struct {
	SandboxID string `json:"sandbox_id"`
	PTYPath   string `json:"pty_path"`
	CreatedAt int64  `json:"created_at"`
}

type ExecuteRequest struct {
	SandboxID string `json:"sandbox_id"`
	JWT       string `json:"jwt"`
	Code      string `json:"code"`
	Language  string `json:"language"`
}

type ExecuteResponse struct {
	ExitCode   int32  `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMS int64  `json:"duration_ms"`
}

type TerminateRequest struct {
	SandboxID string `json:"sandbox_id"`
	JWT       string `json:"jwt"`
}

type HeartbeatRequest struct {
	SandboxID string `json:"sandbox_id"`
	JWT       string `json:"jwt"`
}

type HeartbeatResponse struct {
	Alive    bool  `json:"alive"`
	LastSeen int64 `json:"last_seen"`
}

func (s *Server) wrapKernelUnary(fn func(context.Context, interface{}) (interface{}, error)) func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor basegrpc.UnaryServerInterceptor) (interface{}, error) {
	return func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor basegrpc.UnaryServerInterceptor) (interface{}, error) {
		var req interface{}
		if err := dec(&req); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "decode request: %v", err)
		}
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return fn(ctx, req)
		}
		if interceptor == nil {
			return handler(ctx, req)
		}
		info := &basegrpc.UnaryServerInfo{
			Server:     srv,
			FullMethod: "/vaos.kernel.KernelService/execute",
		}
		return interceptor(ctx, req, info, handler)
	}
}

func (s *Server) wrapCrucibleUnary(fn func(context.Context, interface{}) (interface{}, error)) func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor basegrpc.UnaryServerInterceptor) (interface{}, error) {
	return func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor basegrpc.UnaryServerInterceptor) (interface{}, error) {
		var req interface{}
		if err := dec(&req); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "decode request: %v", err)
		}
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return fn(ctx, req)
		}
		if interceptor == nil {
			return handler(ctx, req)
		}
		info := &basegrpc.UnaryServerInfo{
			Server:     srv,
			FullMethod: "/vaos.kernel.crucible.v1.SandboxControl/execute",
		}
		return interceptor(ctx, req, info, handler)
	}
}

// KernelService handlers

func (s *Server) handleRequestToken(ctx context.Context, req interface{}) (interface{}, error) {
	// Type assert to map for dynamic decoding
	reqMap, ok := req.(map[string]interface{})
	if !ok {
		return &TokenResponse{Error: "invalid request type"}, status.Errorf(codes.InvalidArgument, "invalid request type")
	}

	agentID, _ := reqMap["agent_id"].(string)
	intentHash, _ := reqMap["intent_hash"].(string)
	actionType, _ := reqMap["action_type"].(string)

	if agentID == "" || intentHash == "" {
		return &TokenResponse{Error: "agent_id and intent_hash are required"}, status.Errorf(codes.InvalidArgument, "agent_id and intent_hash are required")
	}

	// Hash the intent using the real hasher
	hashedIntent := s.deps.Hasher.HashRaw(intentHash)

	// Issue a real JWT via the Issuer
	token, record, err := s.deps.Issuer.Issue(agentID, hashedIntent)
	if err != nil {
		s.deps.Ledger.Record(models.AuditEntry{
			AgentID:           agentID,
			Component:         "kernel.grpc",
			Action:            "token_request_failed",
			Status:            "error",
			IntentFingerprint: intentHash,
			Details:           map[string]string{"error": err.Error()},
		})
		return &TokenResponse{Error: err.Error()}, status.Errorf(codes.Internal, "issue token: %v", err)
	}

	// Record successful issuance in audit ledger
	s.deps.Ledger.Record(models.AuditEntry{
		AgentID:           agentID,
		Component:         "kernel.grpc",
		Action:            "token_issued",
		Status:            "success",
		IntentFingerprint: hashedIntent,
		Details: map[string]string{
			"token_id":    record.TokenID,
			"action_type": actionType,
			"ttl":         "60s",
		},
	})

	return &TokenResponse{
		Token:     token,
		ExpiresAt: record.ExpiresAt.Unix(),
		Scope:     actionType,
	}, nil
}

func (s *Server) handleSubmitTelemetry(ctx context.Context, req interface{}) (interface{}, error) {
	reqMap, _ := req.(map[string]interface{})
	agentID, _ := reqMap["agent_id"].(string)

	s.deps.Ledger.Record(models.AuditEntry{
		AgentID:   agentID,
		Component: "kernel.grpc",
		Action:    "telemetry_received",
		Status:    "success",
	})

	return &TelemetryResponse{
		Success: true,
		Message: "telemetry received",
	}, nil
}

func (s *Server) handleSubmitRoutingLog(ctx context.Context, req interface{}) (interface{}, error) {
	reqMap, _ := req.(map[string]interface{})
	agentID, _ := reqMap["agent_id"].(string)
	correlationID := fmt.Sprintf("routing-%d", s.seq.Add(1))

	s.deps.Ledger.Record(models.AuditEntry{
		AgentID:   agentID,
		Component: "kernel.grpc",
		Action:    "routing_log_received",
		Status:    "success",
		Details:   map[string]string{"correlation_id": correlationID},
	})

	return &RoutingLogResponse{
		Success:       true,
		Message:       "routing log received",
		CorrelationID: correlationID,
	}, nil
}

func (s *Server) handleConfirmAudit(ctx context.Context, req interface{}) (interface{}, error) {
	reqMap, _ := req.(map[string]interface{})
	agentID, _ := reqMap["agent_id"].(string)
	auditID := fmt.Sprintf("audit-%d", s.seq.Add(1))

	s.deps.Ledger.Record(models.AuditEntry{
		AgentID:   agentID,
		Component: "kernel.grpc",
		Action:    "audit_confirmed",
		Status:    "success",
		Details:   map[string]string{"audit_id": auditID},
	})

	return &AuditResponse{
		Confirmed: true,
		AuditID:   auditID,
	}, nil
}

func (s *Server) handleExecuteIntent(ctx context.Context, req interface{}) (interface{}, error) {
	reqMap, _ := req.(map[string]interface{})
	agentID, _ := reqMap["agent_id"].(string)
	executionID := fmt.Sprintf("swarm-%d", s.seq.Add(1))

	s.deps.Ledger.Record(models.AuditEntry{
		AgentID:   agentID,
		Component: "kernel.grpc",
		Action:    "intent_executed",
		Status:    "success",
		Details:   map[string]string{"execution_id": executionID},
	})

	return &SwarmIntentResponse{
		ExecutionID: executionID,
		Status:      "coordinated",
		Detail:      "swarm intent accepted",
	}, nil
}

// SandboxControl handlers

func (s *Server) handleCreateSandbox(ctx context.Context, req interface{}) (interface{}, error) {
	// In production, type assert to CreateSandboxRequest
	sandboxID := fmt.Sprintf("sandbox-%d", s.seq.Add(1))
	return &CreateSandboxResponse{
		SandboxID: sandboxID,
		PTYPath:   "/dev/pts/" + sandboxID,
		CreatedAt: time.Now().Unix(),
	}, nil
}

func (s *Server) handleExecuteCode(ctx context.Context, req interface{}) (interface{}, error) {
	// In production, execute code in sandbox
	return &ExecuteResponse{
		ExitCode:   0,
		Stdout:     "code executed successfully",
		Stderr:     "",
		DurationMS: 100,
	}, nil
}

func (s *Server) handleTerminateSandbox(ctx context.Context, req interface{}) (interface{}, error) {
	// In production, terminate sandbox
	return &emptypb.Empty{}, nil
}

func (s *Server) handleHeartbeat(ctx context.Context, req interface{}) (interface{}, error) {
	// In production, check sandbox heartbeat
	return &HeartbeatResponse{
		Alive:    true,
		LastSeen: time.Now().Unix(),
	}, nil
}

// Serve starts the underlying gRPC server.
func (s *Server) Serve(lis net.Listener) error {
	return s.grpcServer.Serve(lis)
}

// Stop gracefully stops the server.
func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
}
