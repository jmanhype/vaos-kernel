package grpc

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	basegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"vaos-kernel/internal/audit"
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
		basegrpc.WithDefaultCallOptions(basegrpc.CallContentSubtype(jsonCodecName)),
	)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	defer conn.Close()

	client := NewClient(conn)
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
	token, _, err := issuer.Issue(intent.AgentID, fingerprint)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &Request{
		AgentID:    intent.AgentID,
		Token:      token,
		Action:     intent.Action,
		Resource:   intent.Resource,
		Parameters: intent.Parameters,
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 3)
	call := func(fn func(context.Context, *Request) (*Response, error)) {
		defer wg.Done()
		resp, err := fn(ctx, req)
		if err != nil {
			errCh <- err
			return
		}
		if resp.ExecutionID == "" || resp.Status == "" {
			errCh <- err
		}
	}

	wg.Add(3)
	go call(client.ExecuteSwarmIntent)
	go call(client.ExecuteCrucibleTask)
	go call(client.DispatchInterface)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("grpc call failed: %v", err)
		}
	}
}
