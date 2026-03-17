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
	Ledger   *audit.Ledger
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
	sw := &swarmServiceServer{}
	s.grpcServer.RegisterService(&basegrpc.ServiceDesc{
		ServiceName: "vaos.kernel.swarm.v1.SwarmService",
		HandlerType: (*swarmService)(nil),
		Methods: []basegrpc.MethodDesc{{
			MethodName: "ExecuteIntent",
			Handler:    s.wrapUnary("swarm", s.handleSwarm),
		}},
	}, sw)
	cr := &crucibleServiceServer{}
	s.grpcServer.RegisterService(&basegrpc.ServiceDesc{
		ServiceName: "vaos.kernel.crucible.v1.CrucibleService",
		HandlerType: (*crucibleService)(nil),
		Methods: []basegrpc.MethodDesc{{
			MethodName: "ExecuteTask",
			Handler:    s.wrapUnary("crucible", s.handleCrucible),
		}},
	}, cr)
	in := &interfaceServiceServer{}
	s.grpcServer.RegisterService(&basegrpc.ServiceDesc{
		ServiceName: "vaos.kernel.interface.v1.InterfaceService",
		HandlerType: (*interfaceService)(nil),
		Methods: []basegrpc.MethodDesc{{
			MethodName: "Dispatch",
			Handler:    s.wrapUnary("interface", s.handleInterface),
		}},
	}, in)
	return s, nil
}

type swarmService interface{}
type crucibleService interface{}
type interfaceService interface{}

type swarmServiceServer struct{}
type crucibleServiceServer struct{}
type interfaceServiceServer struct{}

func (s *Server) wrapUnary(component string, fn func(context.Context, *Request) (*Response, error)) basegrpc.MethodHandler {
	return func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor basegrpc.UnaryServerInterceptor) (interface{}, error) {
		req := &Request{}
		if err := dec(req); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "decode request: %v", err)
		}
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			resp, err := fn(ctx, req.(*Request))
			if err != nil {
				return nil, err
			}
			return resp, nil
		}
		if interceptor == nil {
			return handler(ctx, req)
		}
		info := &basegrpc.UnaryServerInfo{
			Server:     srv,
			FullMethod: fmt.Sprintf("/vaos.kernel.%s/%s", component, "execute"),
		}
		return interceptor(ctx, req, info, handler)
	}
}

// Serve starts the underlying gRPC server.
func (s *Server) Serve(lis net.Listener) error {
	return s.grpcServer.Serve(lis)
}

// Stop gracefully stops the server.
func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
}

func (s *Server) handleSwarm(ctx context.Context, req *Request) (*Response, error) {
	return s.handleRequest(ctx, "swarm", req, func(id string, entry models.AuditEntry) *Response {
		return &Response{
			ExecutionID: id,
			Status:      "coordinated",
			Detail:      "swarm intent accepted",
			Metadata:    entry.Details,
		}
	})
}

func (s *Server) handleCrucible(ctx context.Context, req *Request) (*Response, error) {
	return s.handleRequest(ctx, "crucible", req, func(id string, entry models.AuditEntry) *Response {
		return &Response{
			ExecutionID: id,
			Status:      "processed",
			Attestation: entry.Attestation,
			Metadata:    entry.Details,
		}
	})
}

func (s *Server) handleInterface(ctx context.Context, req *Request) (*Response, error) {
	return s.handleRequest(ctx, "interface", req, func(id string, entry models.AuditEntry) *Response {
		return &Response{
			ExecutionID:    id,
			Status:         "dispatched",
			RenderedOutput: "intent dispatched to interface",
			Metadata:       entry.Details,
		}
	})
}

func (s *Server) handleRequest(ctx context.Context, component string, req *Request, toResponse func(string, models.AuditEntry) *Response) (*Response, error) {
	_ = ctx
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	intent := models.IntentRequest{
		AgentID:    req.AgentID,
		Action:     req.Action,
		Resource:   req.Resource,
		Parameters: req.Parameters,
		RequestedAt: time.Now().UTC(),
	}
	fingerprint, err := s.deps.Hasher.HashIntent(intent)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "hash intent: %v", err)
	}
	if _, err := s.deps.Issuer.Verify(req.Token, fingerprint); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "verify token: %v", err)
	}

	executionID := fmt.Sprintf("%s-%06d", component, s.seq.Add(1))
	entry, err := s.deps.Ledger.Record(models.AuditEntry{
		ID:                executionID,
		AgentID:           req.AgentID,
		IntentFingerprint: fingerprint,
		Action:            req.Action,
		Component:         component,
		Status:            "success",
		Details: map[string]string{
			"resource": req.Resource,
			"grpc":     "true",
		},
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "audit ledger: %v", err)
	}
	return toResponse(executionID, entry), nil
}
