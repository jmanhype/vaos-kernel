package grpc

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	basegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"vaos-kernel/internal/audit"
	cruciblev1 "vaos-kernel/internal/grpc/gen/cruciblev1"
	interfacev1 "vaos-kernel/internal/grpc/gen/interfacev1"
	swarmv1 "vaos-kernel/internal/grpc/gen/swarmv1"
	"vaos-kernel/internal/hash"
	kjwt "vaos-kernel/internal/jwt"
	"vaos-kernel/internal/nhi"
	"vaos-kernel/pkg/models"
)

func TestServicesIntegration(t *testing.T) {
	registry := nhi.NewRegistry()
	if err := registry.RegisterAgent(models.Agent{ID: "agent-1", Name: "Agent One"}); err != nil {
		t.Fatalf("register agent: %v", err)
	}
	issuer, err := kjwt.NewIssuer([]byte("integration-signing-key"), registry)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	srv, err := NewServer(Dependencies{
		Registry: registry,
		Issuer:   issuer,
		Hasher:   hash.Hasher{},
		Ledger:   audit.NewLedger(nil),
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	go func() {
		_ = srv.Serve(lis)
	}()
	defer srv.Stop()

	conn, err := basegrpc.DialContext(context.Background(), lis.Addr().String(),
		basegrpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	defer conn.Close()

	intent := models.IntentRequest{
		AgentID:    "agent-1",
		Action:     "deploy",
		Resource:   "cluster-a",
		Parameters: map[string]string{"region": "us-east-1"},
	}
	fingerprint, err := (hash.Hasher{}).HashIntent(intent)
	if err != nil {
		t.Fatalf("hash intent: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, 3)
	call := func(fn func(string) error) {
		defer wg.Done()
		token, _, err := issuer.Issue(intent.AgentID, fingerprint)
		if err == nil {
			err = fn(token)
		}
		if err != nil {
			errCh <- err
		}
	}

	wg.Add(3)
	go call(func(token string) error {
		resp, err := swarmv1.NewKernelServiceClient(conn).ExecuteIntent(ctx, &swarmv1.SwarmIntentRequest{
			AgentId: intent.AgentID, Token: token, Action: intent.Action,
			Resource: intent.Resource, Parameters: intent.Parameters,
		})
		if err == nil && (resp.ExecutionId == "" || resp.Status == "") {
			return fmt.Errorf("incomplete swarm response: %+v", resp)
		}
		return err
	})
	go call(func(token string) error {
		resp, err := cruciblev1.NewSandboxControlClient(conn).ExecuteTask(ctx, &cruciblev1.CrucibleTaskRequest{
			AgentId: intent.AgentID, Token: token, Action: intent.Action,
			Resource: intent.Resource, Parameters: intent.Parameters,
		})
		if err == nil && (resp.ExecutionId == "" || resp.Attestation == "") {
			return fmt.Errorf("incomplete crucible response: %+v", resp)
		}
		return err
	})
	go call(func(token string) error {
		resp, err := interfacev1.NewInterfaceServiceClient(conn).Dispatch(ctx, &interfacev1.InterfaceDispatchRequest{
			AgentId: intent.AgentID, Token: token, Action: intent.Action,
			Resource: intent.Resource, Parameters: intent.Parameters,
		})
		if err == nil && (resp.ExecutionId == "" || resp.RenderedOutput == "") {
			return fmt.Errorf("incomplete interface response: %+v", resp)
		}
		return err
	})
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("grpc call failed: %v", err)
		}
	}

	tokenResp, err := swarmv1.NewKernelServiceClient(conn).RequestToken(ctx, &swarmv1.TokenRequest{
		AgentId:    intent.AgentID,
		IntentHash: fingerprint,
		ActionType: intent.Action,
	})
	if err != nil {
		t.Fatalf("request token: %v", err)
	}
	if _, err := issuer.Verify(tokenResp.Token, fingerprint); err != nil {
		t.Fatalf("issued token did not preserve requested intent fingerprint: %v", err)
	}

	sandboxFingerprint := "sandbox-intent-fingerprint"
	sandboxToken, _, err := issuer.Issue(intent.AgentID, sandboxFingerprint)
	if err != nil {
		t.Fatalf("issue sandbox token: %v", err)
	}
	sandboxClient := cruciblev1.NewSandboxControlClient(conn)
	sandbox, err := sandboxClient.CreateSandbox(ctx, &cruciblev1.CreateSandboxRequest{
		AgentId:    intent.AgentID,
		Jwt:        sandboxToken,
		IntentHash: sandboxFingerprint,
	})
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	if _, err := sandboxClient.Heartbeat(ctx, &cruciblev1.HeartbeatRequest{
		SandboxId: sandbox.SandboxId,
		Jwt:       sandboxToken,
	}); err != nil {
		t.Fatalf("sandbox heartbeat with bound token: %v", err)
	}
}
