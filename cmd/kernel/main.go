package main

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"

	kamqp "vaos-kernel/internal/amqp"
	"vaos-kernel/internal/audit"
	kgrpc "vaos-kernel/internal/grpc"
	"vaos-kernel/internal/hash"
	kjwt "vaos-kernel/internal/jwt"
	"vaos-kernel/internal/nhi"
	"vaos-kernel/internal/websocket"
	"vaos-kernel/pkg/db"
	"vaos-kernel/pkg/models"
)

func main() {
	// Try Postgres first, fall back to in-memory
	var registry *nhi.Registry
	var registryDB *nhi.RegistryDB
	var useDB bool

	database, err := db.New(db.DefaultConfig())
	if err != nil {
		log.Printf("WARNING: Postgres unavailable (%v), using in-memory registry", err)
		registry = nhi.NewRegistry()
		useDB = false
	} else {
		log.Printf("Connected to Postgres (xGraph)")
		registryDB = nhi.NewRegistryDB(database)
		useDB = true
	}

	// Register bootstrap agents
	bootstrapAgent := models.Agent{
		ID:    "bootstrap-agent",
		Name:  "Bootstrap Agent",
		State: models.AgentStateIdle,
		Roles: []models.Role{{
			Name:        "kernel",
			Description: "Kernel bootstrap role",
		}},
		ReputationScore: 1,
	}

	zoeAgent := models.Agent{
		ID:      "zoe",
		Name:    "Zoe",
		Persona: "AI orchestrator running an agent swarm",
		State:   models.AgentStateIdle,
		Roles: []models.Role{{
			Name:        "orchestrator",
			Description: "Routes tasks to specialist agents and manages the swarm",
		}},
		Capabilities: []models.Capability{
			{Name: "spawn-agents", Description: "Create new sub-agent processes"},
			{Name: "route-tasks", Description: "Delegate tasks to appropriate agents"},
			{Name: "manage-workspace", Description: "Read/write files and run commands"},
			{Name: "git-operations", Description: "Manage git repositories and PRs"},
			{Name: "web-browsing", Description: "Browse the web and fetch content"},
		},
		ReputationScore: 1,
		Metadata: map[string]string{
			"system": "true",
			"type":   "orchestrator",
		},
	}

	osaAgent := models.Agent{
		ID:      "osa",
		Name:    "OSA",
		Persona: "Signal Theory-grounded Optimal System Agent",
		State:   models.AgentStateIdle,
		Roles: []models.Role{{
			Name:        "brain",
			Description: "VAS-Swarm Pillar 2 — Signal Theory router and orchestrator",
		}},
		Capabilities: []models.Capability{
			{Name: "signal-classify", Description: "Classify messages with Signal Theory 5-tuple"},
			{Name: "orchestrate", Description: "Spawn parallel sub-agents for complex tasks"},
			{Name: "browser", Description: "Web browsing and automation"},
			{Name: "file-ops", Description: "Read, write, search files"},
			{Name: "shell-execute", Description: "Run shell commands"},
		},
		ReputationScore: 1,
		Metadata: map[string]string{
			"system":  "true",
			"type":    "brain",
			"pillar":  "2",
			"channel": "telegram",
		},
	}

	// Always use in-memory registry for servers (they expect *nhi.Registry)
	// Postgres is the persistent backing store (already seeded with agents)
	registry = nhi.NewRegistry()
	for _, agent := range []models.Agent{bootstrapAgent, zoeAgent, osaAgent} {
		if err := registry.RegisterAgent(agent); err != nil {
			log.Fatalf("register %s: %v", agent.ID, err)
		}
	}
	// Set up audit writer — stdout + Postgres if available
	var auditWriter io.Writer = os.Stdout
	if useDB {
		dbWriter := audit.NewDBWriter(database)
		auditWriter = io.MultiWriter(os.Stdout, dbWriter)
		log.Printf("Postgres connected — %d agents in DB, audit logging to DB", len(registryDB.ListAll()))
		_ = registryDB
	}

	issuer, err := kjwt.NewIssuer([]byte("vaos-kernel-dev-signing-key"), registry)
	if err != nil {
		log.Fatalf("create issuer: %v", err)
	}

	ledger := audit.NewLedger(auditWriter)

	server, err := kgrpc.NewServer(kgrpc.Dependencies{
		Registry: registry,
		Issuer:   issuer,
		Hasher:   hash.Hasher{},
		Ledger:   ledger,
	})
	if err != nil {
		log.Fatalf("create grpc server: %v", err)
	}

	wsServer := websocket.NewServer(registry)

	var wg sync.WaitGroup

	// gRPC server
	wg.Add(1)
	go func() {
		defer wg.Done()
		grpcAddr := os.Getenv("VAOS_KERNEL_GRPC_ADDR")
		if grpcAddr == "" {
			grpcAddr = "0.0.0.0:50051"
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
			wsAddr = "0.0.0.0:8080"
		}
		http.HandleFunc("/ws", wsServer.HandleWebSocket)
		http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		})
		// Token endpoint for Swarm HTTP fallback
		http.HandleFunc("/api/token", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				http.Error(w, "method not allowed", 405)
				return
			}
			var req struct {
				AgentID    string `json:"agent_id"`
				IntentHash string `json:"intent_hash"`
				ActionType string `json:"action_type"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", 400)
				return
			}
			token, record, err := issuer.Issue(req.AgentID, req.IntentHash)
			if err != nil {
				ledger.Record(models.AuditEntry{
					AgentID:           req.AgentID,
					Component:         "kernel.http",
					Action:            "token_request_failed",
					Status:            "error",
					IntentFingerprint: req.IntentHash,
					Details:           map[string]string{"error": err.Error()},
				})
				w.WriteHeader(500)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}

			// Record successful token issuance to audit ledger
			ledger.Record(models.AuditEntry{
				AgentID:           req.AgentID,
				Component:         "kernel.http",
				Action:            "token_issued",
				Status:            "success",
				IntentFingerprint: req.IntentHash,
				Details: map[string]string{
					"token_id":    record.TokenID,
					"action_type": req.ActionType,
					"ttl":         "60s",
				},
			})

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      token,
				"token_id":   record.TokenID,
				"agent_id":   record.AgentID,
				"expires_at": record.ExpiresAt,
				"ttl_seconds": 60,
			})
		})
		// Agent list endpoint
		http.HandleFunc("/api/agents", func(w http.ResponseWriter, r *http.Request) {
			agents := registry.ListAll()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"agents": agents})
		})
		log.Printf("VAOS-Kernel WebSocket listening on http://%s", wsAddr)
		if err := http.ListenAndServe(wsAddr, nil); err != nil {
			log.Fatalf("serve WebSocket: %v", err)
		}
	}()

	// AMQP consumer — subscribe to Swarm telemetry and forward to WebSocket clients
	amqpURL := os.Getenv("AMQP_URL")
	if amqpURL == "" {
		amqpURL = "amqp://guest:guest@localhost:5672"
	}
	consumer := kamqp.NewConsumer(amqpURL, func(exchange, routingKey string, body []byte) {
		event, err := kamqp.ParseTelemetryEvent(body)
		if err != nil {
			log.Printf("[AMQP] Failed to parse event: %v", err)
			return
		}
		// Forward to all WebSocket clients as telemetry/threat events
		wsServer.BroadcastEvent(exchange, routingKey, event)
	})
	if err := consumer.Start([]string{"miosa.events", "miosa.tasks"}); err != nil {
		log.Printf("WARNING: AMQP consumer failed to start: %v (telemetry forwarding disabled)", err)
	} else {
		log.Printf("AMQP consumer connected — forwarding miosa.events + miosa.tasks to WebSocket")
	}

	wg.Wait()
}
