package main

import (
	"log"
	"net"
	"os"

	"vaos-kernel/internal/audit"
	"vaos-kernel/internal/grpc"
	"vaos-kernel/internal/hash"
	kjwt "vaos-kernel/internal/jwt"
	"vaos-kernel/internal/nhi"
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
	server, err := grpc.NewServer(grpc.Dependencies{
		Registry: registry,
		Issuer:   issuer,
		Hasher:   hash.Hasher{},
		Ledger:   audit.NewLedger(os.Stdout),
	})
	if err != nil {
		log.Fatalf("create grpc server: %v", err)
	}

	addr := os.Getenv("VAOS_KERNEL_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("VAOS-Kernel listening on %s", addr)
	if err := server.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

