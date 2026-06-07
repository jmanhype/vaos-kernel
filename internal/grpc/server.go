package grpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	basegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"vaos-kernel/internal/audit"
	cruciblev1 "vaos-kernel/internal/grpc/gen/cruciblev1"
	interfacev1 "vaos-kernel/internal/grpc/gen/interfacev1"
	swarmv1 "vaos-kernel/internal/grpc/gen/swarmv1"
	"vaos-kernel/internal/hash"
	kjwt "vaos-kernel/internal/jwt"
	"vaos-kernel/internal/nhi"
	"vaos-kernel/internal/signing"
	"vaos-kernel/pkg/models"
)

// Dependencies contains the shared collaborators required by the service layer.
type Dependencies struct {
	Registry *nhi.Registry
	Issuer   *kjwt.Issuer
	Hasher   hash.Hasher
	Ledger   audit.Recorder
	Signer   *signing.Signer
	OnSigned func(entryID, sig string)
}

// Server owns the gRPC runtime and implements all generated services.
type Server struct {
	swarmv1.UnimplementedKernelServiceServer
	cruciblev1.UnimplementedSandboxControlServer
	interfacev1.UnimplementedInterfaceServiceServer

	grpcServer *basegrpc.Server
	deps       Dependencies
	seq        atomic.Uint64
	sandboxes  sync.Map // sandbox ID -> intent fingerprint
}

// NewServer wires the generated protobuf services into a gRPC server.
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
	swarmv1.RegisterKernelServiceServer(s.grpcServer, s)
	cruciblev1.RegisterSandboxControlServer(s.grpcServer, s)
	interfacev1.RegisterInterfaceServiceServer(s.grpcServer, s)
	return s, nil
}

func (s *Server) RequestToken(_ context.Context, req *swarmv1.TokenRequest) (*swarmv1.TokenResponse, error) {
	if req == nil || req.AgentId == "" || req.IntentHash == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_id and intent_hash are required")
	}

	token, record, err := s.deps.Issuer.Issue(req.AgentId, req.IntentHash)
	if err != nil {
		s.recordFailure(req.AgentId, req.IntentHash, "token_request_failed", err)
		if _, lookupErr := s.deps.Registry.GetAgent(req.AgentId); lookupErr != nil {
			return nil, status.Errorf(codes.NotFound, "agent: %v", lookupErr)
		}
		return nil, status.Errorf(codes.Internal, "issue token: %v", err)
	}

	if _, err := s.deps.Ledger.Record(models.AuditEntry{
		AgentID:           req.AgentId,
		Component:         "kernel.grpc",
		Action:            "token_issued",
		Status:            "success",
		IntentFingerprint: req.IntentHash,
		Details: map[string]string{
			"token_id":    record.TokenID,
			"action_type": req.ActionType,
			"ttl":         "60s",
		},
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit ledger: %v", err)
	}

	return &swarmv1.TokenResponse{
		Token:     token,
		ExpiresAt: record.ExpiresAt.Unix(),
		Scope:     req.ActionType,
	}, nil
}

func (s *Server) SubmitTelemetry(_ context.Context, req *swarmv1.TelemetryRequest) (*swarmv1.TelemetryResponse, error) {
	if req == nil || req.AgentId == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_id is required")
	}
	if _, err := s.deps.Ledger.Record(models.AuditEntry{
		AgentID:   req.AgentId,
		Component: "kernel.grpc",
		Action:    "telemetry_received",
		Status:    "success",
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit ledger: %v", err)
	}
	return &swarmv1.TelemetryResponse{Success: true, Message: "telemetry received"}, nil
}

func (s *Server) SubmitRoutingLog(_ context.Context, req *swarmv1.RoutingLogRequest) (*swarmv1.RoutingLogResponse, error) {
	if req == nil || req.AgentId == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_id is required")
	}
	correlationID := fmt.Sprintf("routing-%06d", s.seq.Add(1))
	if _, err := s.deps.Ledger.Record(models.AuditEntry{
		AgentID:   req.AgentId,
		Component: "kernel.grpc",
		Action:    "routing_log_received",
		Status:    "success",
		Details:   map[string]string{"correlation_id": correlationID},
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit ledger: %v", err)
	}
	return &swarmv1.RoutingLogResponse{
		Success:       true,
		Message:       "routing log received",
		CorrelationId: correlationID,
	}, nil
}

func (s *Server) ConfirmAudit(_ context.Context, req *swarmv1.AuditConfirmation) (*swarmv1.AuditResponse, error) {
	if req == nil || req.AgentId == "" || req.ActionId == "" || req.IntentHash == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_id, action_id, and intent_hash are required")
	}

	details := map[string]string{
		"action_id":       req.ActionId,
		"method":          req.Method,
		"performed_by":    req.PerformedBy,
		"attributable":    fmt.Sprintf("%t", req.Attributable),
		"legible":         fmt.Sprintf("%t", req.Legible),
		"contemporaneous": fmt.Sprintf("%t", req.Contemporaneous),
		"original":        fmt.Sprintf("%t", req.Original),
		"accurate":        fmt.Sprintf("%t", req.Accurate),
	}
	for key, value := range req.Context {
		details["ctx_"+key] = value
	}

	entry, err := s.deps.Ledger.Record(models.AuditEntry{
		AgentID:           req.AgentId,
		Component:         "kernel.grpc",
		Action:            "audit_confirmed",
		Status:            "success",
		IntentFingerprint: req.IntentHash,
		Details:           details,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "audit ledger: %v", err)
	}

	auditID := fmt.Sprintf("audit-%06d", s.seq.Add(1))
	var sig string
	if s.deps.Signer != nil {
		sig = s.deps.Signer.Sign([]byte(entry.Attestation))
		if s.deps.OnSigned != nil {
			s.deps.OnSigned(auditID, sig)
			s.deps.OnSigned(entry.ID, sig)
		}
	}
	return &swarmv1.AuditResponse{
		Confirmed:   true,
		AuditId:     auditID,
		Signature:   sig,
		Attestation: entry.Attestation,
	}, nil
}

func (s *Server) ExecuteIntent(ctx context.Context, req *swarmv1.SwarmIntentRequest) (*swarmv1.SwarmIntentResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	_, executionID, err := s.execute(ctx, "swarm", req.AgentId, req.Token, req.Action, req.Resource, req.Parameters)
	if err != nil {
		return nil, err
	}
	return &swarmv1.SwarmIntentResponse{
		ExecutionId: executionID,
		Status:      "coordinated",
		Detail:      "swarm intent accepted",
	}, nil
}

func (s *Server) CreateSandbox(_ context.Context, req *cruciblev1.CreateSandboxRequest) (*cruciblev1.CreateSandboxResponse, error) {
	if req == nil || req.AgentId == "" || req.IntentHash == "" || req.Jwt == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_id, jwt, and intent_hash are required")
	}
	if _, err := s.deps.Issuer.Verify(req.Jwt, req.IntentHash); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "verify token: %v", err)
	}
	sandboxID := fmt.Sprintf("sandbox-%06d", s.seq.Add(1))
	s.sandboxes.Store(sandboxID, req.IntentHash)
	return &cruciblev1.CreateSandboxResponse{
		SandboxId: sandboxID,
		PtyPath:   "/dev/pts/" + sandboxID,
		CreatedAt: time.Now().Unix(),
	}, nil
}

func (s *Server) ExecuteCode(_ context.Context, req *cruciblev1.ExecuteRequest) (*cruciblev1.ExecuteResponse, error) {
	if req == nil || req.SandboxId == "" || req.Jwt == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id and jwt are required")
	}
	if err := s.verifySandbox(req.SandboxId, req.Jwt); err != nil {
		return nil, err
	}
	return &cruciblev1.ExecuteResponse{
		ExitCode:   0,
		Stdout:     "code execution accepted",
		DurationMs: 100,
	}, nil
}

func (s *Server) TerminateSandbox(_ context.Context, req *cruciblev1.TerminateRequest) (*emptypb.Empty, error) {
	if req == nil || req.SandboxId == "" || req.Jwt == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id and jwt are required")
	}
	if err := s.verifySandbox(req.SandboxId, req.Jwt); err != nil {
		return nil, err
	}
	s.sandboxes.Delete(req.SandboxId)
	return &emptypb.Empty{}, nil
}

func (s *Server) Heartbeat(_ context.Context, req *cruciblev1.HeartbeatRequest) (*cruciblev1.HeartbeatResponse, error) {
	if req == nil || req.SandboxId == "" || req.Jwt == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id and jwt are required")
	}
	if err := s.verifySandbox(req.SandboxId, req.Jwt); err != nil {
		return nil, err
	}
	return &cruciblev1.HeartbeatResponse{Alive: true, LastSeen: time.Now().Unix()}, nil
}

func (s *Server) ExecuteTask(ctx context.Context, req *cruciblev1.CrucibleTaskRequest) (*cruciblev1.CrucibleTaskResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	entry, executionID, err := s.execute(ctx, "crucible", req.AgentId, req.Token, req.Action, req.Resource, req.Parameters)
	if err != nil {
		return nil, err
	}
	return &cruciblev1.CrucibleTaskResponse{
		ExecutionId: executionID,
		Status:      "processed",
		Attestation: entry.Attestation,
	}, nil
}

func (s *Server) Dispatch(ctx context.Context, req *interfacev1.InterfaceDispatchRequest) (*interfacev1.InterfaceDispatchResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	_, executionID, err := s.execute(ctx, "interface", req.AgentId, req.Token, req.Action, req.Resource, req.Parameters)
	if err != nil {
		return nil, err
	}
	return &interfacev1.InterfaceDispatchResponse{
		ExecutionId:    executionID,
		Status:         "dispatched",
		RenderedOutput: "intent dispatched to interface",
	}, nil
}

func (s *Server) execute(
	_ context.Context,
	component, agentID, token, action, resource string,
	parameters map[string]string,
) (models.AuditEntry, string, error) {
	intent := models.IntentRequest{
		AgentID:    agentID,
		Action:     action,
		Resource:   resource,
		Parameters: parameters,
	}
	fingerprint, err := s.deps.Hasher.HashIntent(intent)
	if err != nil {
		return models.AuditEntry{}, "", status.Errorf(codes.InvalidArgument, "hash intent: %v", err)
	}
	if _, err := s.deps.Issuer.Verify(token, fingerprint); err != nil {
		return models.AuditEntry{}, "", status.Errorf(codes.Unauthenticated, "verify token: %v", err)
	}

	executionID := fmt.Sprintf("%s-%06d", component, s.seq.Add(1))
	entry, err := s.deps.Ledger.Record(models.AuditEntry{
		ID:                executionID,
		AgentID:           agentID,
		IntentFingerprint: fingerprint,
		Action:            action,
		Component:         component,
		Status:            "success",
		Details: map[string]string{
			"resource": resource,
			"grpc":     "true",
		},
	})
	if err != nil {
		return models.AuditEntry{}, "", status.Errorf(codes.Internal, "audit ledger: %v", err)
	}
	return entry, executionID, nil
}

func (s *Server) recordFailure(agentID, fingerprint, action string, cause error) {
	if agentID == "" {
		return
	}
	_, _ = s.deps.Ledger.Record(models.AuditEntry{
		AgentID:           agentID,
		Component:         "kernel.grpc",
		Action:            action,
		Status:            "error",
		IntentFingerprint: fingerprint,
		Details:           map[string]string{"error": cause.Error()},
	})
}

func (s *Server) verifySandbox(sandboxID, token string) error {
	value, ok := s.sandboxes.Load(sandboxID)
	if !ok {
		return status.Error(codes.NotFound, "sandbox not found")
	}
	fingerprint, ok := value.(string)
	if !ok || fingerprint == "" {
		return status.Error(codes.Internal, "sandbox intent binding is invalid")
	}
	if _, err := s.deps.Issuer.Verify(token, fingerprint); err != nil {
		return status.Errorf(codes.Unauthenticated, "verify token: %v", err)
	}
	return nil
}

// Serve starts the underlying gRPC server.
func (s *Server) Serve(lis net.Listener) error {
	return s.grpcServer.Serve(lis)
}

// Stop gracefully stops the server.
func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
}
