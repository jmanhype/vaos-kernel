package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"sync"

	"vaos-kernel/internal/audit"
	kgrpc "vaos-kernel/internal/grpc"
	"vaos-kernel/internal/hash"
	kjwt "vaos-kernel/internal/jwt"
	"vaos-kernel/internal/nhi"
	"vaos-kernel/internal/websocket"
	"vaos-kernel/pkg/models"
)

func main() {
	registry := nhi.NewRegistry()
	if err := registry.RegisterAgent(models.Agent{
		ID:   "bootstrap-agent",
		Name: "Bootstrap Agent",
		Roles: []models.Role{{
			Name:        "kernel",
			Description: "Kernel bootstrap role",
		}},
		ReputationScore: 1,
	}); err != nil {
		log.Fatalf("register bootstrap agent: %v", err)
	}

	issuer, err := kjwt.NewIssuer([]byte("vaos-kernel-dev-signing-key"), registry)
	if err != nil {
		log.Fatalf("create issuer: %v", err)
	}
	
	server, err := kgrpc.NewServer(kgrpc.Dependencies{
		Registry: registry,
		Issuer:   issuer,
		Hasher:   hash.Hasher{},
		Ledger:   audit.NewLedger(os.Stdout),
	})
	if err != nil {
		log.Fatalf("create grpc server: %v", err)
	}

	// Create WebSocket server
	wsServer := websocket.NewServer(registry)

	// Start both servers
	var wg sync.WaitGroup
	
	// gRPC server
	wg.Add(1)
	go func() {
		defer wg.Done()
		
		grpcAddr := os.Getenv("VAOS_KERNEL_GRPC_ADDR")
		if grpcAddr == "" {
			grpcAddr = "127.0.0.1:50051"
		}
		lis, err := net.Listen("tcp", grpcAddr)
		if err != nil {
			log.Fatalf("listen gRPC: %v", err)
		}
		log.Printf("VAOS-Kernel gRPC listening on %s", grpcAddr)
		if err := server.Serve(lis); err != nil {
			log.Fatalf("serve gRPC: %v", err)
		}
	}()
	
	// WebSocket server
	wg.Add(1)
	go func() {
		defer wg.Done()
		
		wsAddr := os.Getenv("VAOS_KERNEL_WS_ADDR")
		if wsAddr == "" {
			wsAddr = "127.0.0.1:8080"
		}
		
		http.HandleFunc("/ws", wsServer.HandleWebSocket)
		http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		})
		
		log.Printf("VAOS-Kernel WebSocket listening on http://%s", wsAddr)
		if err := http.ListenAndServe(wsAddr, nil); err != nil {
			log.Fatalf("serve WebSocket: %v", err)
		}
	}()
	
	wg.Wait()
}
