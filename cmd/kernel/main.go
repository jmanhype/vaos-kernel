package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	kamqp "vaos-kernel/internal/amqp"
	"vaos-kernel/internal/audit"
	"vaos-kernel/internal/signing"
	kgrpc "vaos-kernel/internal/grpc"
	"vaos-kernel/internal/hash"
	kjwt "vaos-kernel/internal/jwt"
	"vaos-kernel/internal/nhi"
	"vaos-kernel/internal/websocket"
	"vaos-kernel/pkg/db"
	"vaos-kernel/pkg/models"
)

// sigStore holds signatures keyed by audit entry ID (computed after Ledger.Record).
type sigStore struct{ m sync.Map }

func (s *sigStore) Put(id, sig string) { s.m.Store(id, sig) }
func (s *sigStore) Get(id string) string {
	v, ok := s.m.Load(id)
	if !ok {
		return ""
	}
	return v.(string)
}

func parseIntParam(s string, def int) int {
	if s == "" {
		return def
	}
	n := 0
	for _, c := range s {
		if c < 0 || c > 9 {
			return def
		}
		n = n*10 + int(c-0)
	}
	if n <= 0 {
		return def
	}
	return n
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func filterEntries(all []models.AuditEntry, agentID, action, status, component string) []models.AuditEntry {
	if agentID == "" && action == "" && status == "" && component == "" {
		return all
	}
	var out []models.AuditEntry
	for _, e := range all {
		if agentID != "" && e.AgentID != agentID {
			continue
		}
		if action != "" && e.Action != action {
			continue
		}
		if status != "" && e.Status != status {
			continue
		}
		if component != "" && e.Component != component {
			continue
		}
		out = append(out, e)
	}
	return out
}

func main() {
	// Mode selection: "sync" (Mode A) or "async" (Mode B)
	mode := os.Getenv("VAOS_KERNEL_MODE")
	if mode == "" {
		mode = "sync"
	}
	log.Printf("VAOS-Kernel starting in %s mode", mode)

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

	// JWT signing key from env, or generate a random one for dev
	jwtSecret := os.Getenv("VAOS_JWT_SECRET")
	var signingKey []byte
	if jwtSecret != "" {
		signingKey = []byte(jwtSecret)
	} else {
		signingKey = make([]byte, 32)
		if _, err := rand.Read(signingKey); err != nil {
			log.Fatalf("generate random signing key: %v", err)
		}
		log.Printf("WARNING: VAOS_JWT_SECRET not set — using random ephemeral signing key (tokens will not survive restart)")
	}

	issuer, err := kjwt.NewIssuer(signingKey, registry)
	if err != nil {
		log.Fatalf("create issuer: %v", err)
	}

	dbDSN := os.Getenv("VAOS_DB_DSN")

	var ledger audit.Recorder
	switch mode {
	case "async":
		asyncLedger := audit.NewAsyncLedger(auditWriter, audit.DefaultAsyncConfig())
		ledger = asyncLedger
		log.Printf("Mode B: async write-behind in-memory (buffer=%d)",
			audit.DefaultAsyncConfig().BufferSize)
		defer asyncLedger.Close()

	case "db-sync":
		if dbDSN == "" {
			log.Fatal("db-sync mode requires VAOS_DB_DSN")
		}
		dbLedger, err := audit.NewDBLedger(dbDSN, auditWriter)
		if err != nil {
			log.Fatalf("create DB ledger: %v", err)
		}
		ledger = dbLedger
		log.Printf("Mode A+DB: synchronous attestation with Postgres fsync")
		defer dbLedger.Close()

	case "db-async":
		if dbDSN == "" {
			log.Fatal("db-async mode requires VAOS_DB_DSN")
		}
		asyncDB, err := audit.NewAsyncDBLedger(dbDSN, auditWriter, 10000)
		if err != nil {
			log.Fatalf("create async DB ledger: %v", err)
		}
		ledger = asyncDB
		log.Printf("Mode B+DB: async write-behind with Postgres batch")
		defer asyncDB.Close()

	default:
		ledger = audit.NewLedger(auditWriter)
		log.Printf("Mode A: synchronous attestation in-memory")
	}

	// Ed25519 signer for audit attestation signatures
	keyPath := filepath.Join(os.Getenv("HOME"), ".vaos-kernel", "signing.key")
	signer, err := signing.NewSigner(keyPath)
	if err != nil {
		log.Fatalf("create signer: %v", err)
	}
	log.Printf("Ed25519 signer ready (pubkey: %s...)", signer.PublicKeyHex()[:16])

	var sigs sigStore

	server, err := kgrpc.NewServer(kgrpc.Dependencies{
		Registry: registry,
		Issuer:   issuer,
		Hasher:   hash.Hasher{},
		Ledger:   ledger,
		Signer:   signer,
		OnSigned: func(entryID, sig string) { sigs.Put(entryID, sig) },
	})
	if err != nil {
		log.Fatalf("create grpc server: %v", err)
	}

	wsServer := websocket.NewServer(registry)

	// API auth middleware — checks Authorization: Bearer <VAOS_API_SECRET>
	apiSecret := os.Getenv("VAOS_API_SECRET")
	if apiSecret == "" {
		log.Printf("WARNING: VAOS_API_SECRET not set — HTTP API endpoints are unauthenticated (dev mode)")
	}
	requireAuth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if apiSecret != "" {
				auth := r.Header.Get("Authorization")
				if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != apiSecret {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			}
			next(w, r)
		}
	}

	// Graceful shutdown context
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	// WebSocket + HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", wsServer.HandleWebSocket)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	// Token endpoint for Swarm HTTP fallback — requires auth
	mux.HandleFunc("/api/token", requireAuth(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	// Public key endpoint — no auth required (public key is public)
	mux.HandleFunc("/api/audit/pubkey", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"public_key": signer.PublicKeyHex()})
	})
	// Audit confirmation endpoint - requires auth (receipt chain)
	mux.HandleFunc("/api/audit", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}
		var params map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			http.Error(w, "bad request", 400)
			return
		}

		agentID, _ := params["agent_id"].(string)
		actionID, _ := params["action_id"].(string)
		intentHash, _ := params["intent_hash"].(string)
		method, _ := params["method"].(string)
		performedBy, _ := params["performed_by"].(string)
		attributable, _ := params["attributable"].(bool)
		legible, _ := params["legible"].(bool)
		contemporaneous, _ := params["contemporaneous"].(bool)
		original, _ := params["original"].(bool)
		accurate, _ := params["accurate"].(bool)

		details := map[string]string{
			"action_id":       actionID,
			"method":          method,
			"performed_by":    performedBy,
			"attributable":    fmt.Sprintf("%t", attributable),
			"legible":         fmt.Sprintf("%t", legible),
			"contemporaneous": fmt.Sprintf("%t", contemporaneous),
			"original":        fmt.Sprintf("%t", original),
			"accurate":        fmt.Sprintf("%t", accurate),
		}

		if ctxMap, ok := params["context"].(map[string]interface{}); ok {
			for k, v := range ctxMap {
				if vs, ok := v.(string); ok {
					details["ctx_"+k] = vs
				}
			}
		}

		entry, err := ledger.Record(models.AuditEntry{
			AgentID:           agentID,
			Component:         "kernel.http",
			Action:            "audit_confirmed",
			Status:            "success",
			IntentFingerprint: intentHash,
			Details:           details,
		})
		if err != nil {
			w.WriteHeader(500)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		sig := signer.Sign([]byte(entry.Attestation))
		auditID := fmt.Sprintf("http-audit-%d", time.Now().UnixNano())
		sigs.Put(auditID, sig)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"confirmed":   true,
			"audit_id":    auditID,
			"signature":   sig,
			"attestation": entry.Attestation,
		})
	}))
	// Audit entries query endpoint — requires auth (paginated)
	mux.HandleFunc("/api/audit/entries", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", 405)
			return
		}
		q := r.URL.Query()
		page := parseIntParam(q.Get("page"), 1)
		perPage := clamp(parseIntParam(q.Get("per_page"), 20), 1, 100)

		all := ledger.Entries()
		filtered := filterEntries(all, q.Get("agent_id"), q.Get("action"), q.Get("status"), q.Get("component"))

		total := len(filtered)
		start := (page - 1) * perPage
		if start > total {
			start = total
		}
		end := start + perPage
		if end > total {
			end = total
		}
		pageEntries := filtered[start:end]

		pages := total / perPage
		if total%perPage != 0 {
			pages++
		}

		// Attach signature if available
		type entryWithSig struct {
			models.AuditEntry
			Signature string `json:"signature,omitempty"`
		}
		out := make([]entryWithSig, len(pageEntries))
		for i, e := range pageEntries {
			out[i] = entryWithSig{AuditEntry: e, Signature: sigs.Get(e.ID)}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"entries":  out,
			"total":    total,
			"page":     page,
			"per_page": perPage,
			"pages":    pages,
		})
	}))
	// Audit chain + signature replay verification — no auth (public verifiability)
	mux.HandleFunc("/api/audit/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", 405)
			return
		}
		entries := ledger.Entries()
		sigFn := func(e models.AuditEntry) string { return sigs.Get(e.ID) }
		verifyFn := func(data []byte, sigHex string) bool { return signer.Verify(data, sigHex) }
		result := audit.Replay(entries, sigFn, verifyFn)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
	// Agent list endpoint — requires auth
	mux.HandleFunc("/api/agents", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		agents := registry.ListAll()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"agents": agents})
	}))

	wsAddr := os.Getenv("VAOS_KERNEL_WS_ADDR")
	if wsAddr == "" {
		wsAddr = "0.0.0.0:8080"
	}
	httpServer := &http.Server{Addr: wsAddr, Handler: mux}

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("VAOS-Kernel WebSocket listening on http://%s", wsAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve WebSocket: %v", err)
		}
	}()

	// AMQP consumer — subscribe to Swarm telemetry and forward to WebSocket clients
	amqpURL := os.Getenv("AMQP_URL")
	if amqpURL == "" {
		amqpURL = "amqp://guest:guest@localhost:5672"
		log.Printf("WARNING: AMQP_URL not set — using default credentials (guest:guest). Set AMQP_URL for production.")
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

	// Wait for shutdown signal
	<-ctx.Done()
	log.Printf("Shutdown signal received, draining...")

	// Gracefully stop HTTP server
	httpServer.Shutdown(context.Background())

	// Gracefully stop gRPC server
	server.Stop()

	// Stop AMQP consumer
	consumer.Stop()

	// Wait for goroutines to finish
	wg.Wait()
	log.Printf("VAOS-Kernel shutdown complete")
}
