# vaos-kernel

[![CI](https://github.com/jmanhype/vaos-kernel/actions/workflows/ci.yml/badge.svg)](https://github.com/jmanhype/vaos-kernel/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.22-00ADD8.svg)](https://go.dev)

Intent-scoped credentials with hash-chained ALCOA+ audit for AI agents. Each credential is cryptographically bound to a declared action via BLAKE2b-256 fingerprinting, sealed in a 60-second JWT. Each audit entry chains to the previous one; modifying any record breaks the chain.

Submitted as a public comment to [NIST NCCoE](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization) on AI Agent Identity and Authorization. Implements the pattern from [IETF draft-goswami-agentic-jwt-00](https://datatracker.ietf.org/doc/draft-goswami-agentic-jwt/).

## Benchmark results

Mac Mini M4, Go 1.26, PostgreSQL 17, 1,000 concurrent agents:

| Configuration | Requests/sec | p99 latency |
|---|---|---|
| Baseline (no attestation) | 51,005 | 0.70 ms |
| Sync + ALCOA+ attestation | 50,774 | 1.69 ms |
| Async attestation | 32,827 | 87.86 ms |
| Sync + Postgres | 20,329 | 622 ms |
| Async + Postgres | 864 | 10,123 ms |

Sync ALCOA+ attestation (BLAKE2b fingerprint + JWT signing + hash chain append) adds 0.5% overhead versus no attestation. The async path is slower because channel coordination costs more than the sub-microsecond BLAKE2b computation itself.

## How it works

**Intent fingerprinting.** The agent declares what it plans to do: action, resource, parameters. Those fields are canonicalized and BLAKE2b-256 hashed into a deterministic fingerprint, then embedded in a 60-second JWT.

**Hash-chained audit.** Every audit entry includes the previous entry's hash: `H_n = BLAKE2b(canonical_fields_n || H_{n-1})`. Modifying any historical entry invalidates all subsequent entries. This is the same integrity pattern used for FDA 21 CFR Part 11 compliance (ALCOA+ standard).

**60-second TTL.** No standing privileges. The verifier rejects any token where `exp - iat != 60s`.

## Project structure

23 Go source files (excluding tests and generated protobuf), 5 test files, 3 proto definitions:

| Package | Files | Purpose |
|---|---|---|
| `cmd/kernel` | 1 | Main entrypoint: starts gRPC on :50051 and HTTP on :8080 |
| `cmd/benchmark` | 1 | Load generator with Poisson arrivals, connection pooling, CSV/JSON output |
| `internal/jwt` | 1 | 60-second JIT JWT issuer/verifier (HS256, `golang-jwt/jwt/v5`) |
| `internal/hash` | 1 | Deterministic BLAKE2b-256 intent fingerprinting (`golang.org/x/crypto/blake2b`) |
| `internal/audit` | 5 | Hash-chained ALCOA+ ledger, async variant, Postgres-backed recorder |
| `internal/nhi` | 2 | NHI registry: agent identity, roles, capabilities, reputation, token lifecycle |
| `internal/grpc` | 4 | Concurrent gRPC services (Swarm, Crucible, Interface) |
| `internal/amqp` | 1 | RabbitMQ consumer |
| `internal/websocket` | 1 | WebSocket server |
| `pkg/db` | 2 | PostgreSQL connection and NHI queries |
| `pkg/models` | 4 | Data types: agent, audit, intent, token |
| `proto/` | 3 | Protobuf definitions: crucible, interface, swarm |

Tests: `internal/audit/ledger_test.go`, `internal/grpc/server_test.go`, `internal/hash/hasher_test.go`, `internal/jwt/issuer_test.go`, `internal/nhi/registry_test.go`.

## Comparison

| | vaos-kernel | HashiCorp Vault | SPIFFE/SPIRE | OPA |
|---|---|---|---|---|
| Credential scope | Per-action (60s) | Session (minutes-hours) | Workload (minutes-hours) | N/A |
| Intent binding | BLAKE2b hash in JWT | None | None | Policy logic |
| Audit integrity | Hash-chained | Append-only log | Standard log | Mutable log |
| ALCOA+ compliance | Full (attributable, legible, contemporaneous, original, accurate, complete, consistent, enduring, available) | Partial | None | None |

## Dependencies

```
github.com/golang-jwt/jwt/v5   JWT signing/verification
golang.org/x/crypto             BLAKE2b-256
google.golang.org/grpc          gRPC server
google.golang.org/protobuf      Protobuf serialization
github.com/lib/pq               PostgreSQL driver (optional)
github.com/rabbitmq/amqp091-go  RabbitMQ client (optional)
github.com/gorilla/websocket    WebSocket server
```

## Quick start

```bash
go mod tidy
go build -o vaos-kernel ./cmd/kernel
./vaos-kernel
```

Starts gRPC on `:50051` and HTTP on `:8080`.

```bash
# Issue a token
curl -X POST http://localhost:8080/api/token \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "zoe", "intent_hash": "read-table-users", "action_type": "query"}'

# List agents
curl http://localhost:8080/api/agents
```

## Running benchmarks

```bash
go build -o benchmark ./cmd/benchmark
./benchmark
```

Writes `benchmark_results.csv` and `benchmark_results.json`.

Set `VAOS_KERNEL_MODE=async` for async mode. Set `VAOS_DB_DSN=...` for Postgres-backed modes.

## Design decisions

**BLAKE2b over SHA-256.** BLAKE2b-256 is faster on modern hardware (sub-microsecond on M4) while providing equivalent collision resistance. This keeps the attestation overhead under 1%.

**Sync over async by default.** The benchmarks show sync attestation is faster than async because the BLAKE2b computation is cheaper than the goroutine/channel coordination overhead. Async mode exists for Postgres-backed deployments where the write latency dominates.

**60-second hard TTL.** Fixed rather than configurable to prevent configuration drift toward long-lived tokens. The verifier enforces `exp - iat == 60s` exactly, rejecting both shorter and longer durations.

**Hash chain over Merkle tree.** Simpler to implement, simpler to verify (`VerifyChain()` is a linear scan), and sufficient for the audit volumes expected from individual agent deployments. A Merkle tree would be better for parallel verification at scale.

**In-memory ledger as default.** The in-memory ALCOA+ ledger handles 50,000+ RPS. Postgres-backed mode drops to 20,000 RPS (sync) or 864 RPS (async) due to write latency. Choose based on durability requirements.

## Regulatory context

- NIST NCCoE: seeking agent identity guidance (comments due April 2, 2026)
- EU AI Act: high-risk provisions effective August 2, 2026
- IETF: standardizing intent-scoped JWTs (draft-goswami-agentic-jwt-00)

## Known limitations

- The benchmark numbers are from a single Mac Mini M4. Server hardware and network latency will produce different results.
- The in-memory ledger loses audit history on process restart. Use the Postgres-backed recorder for durability.
- gRPC services (Swarm, Crucible, Interface) have protobuf definitions but limited test coverage.
- No TLS configuration in the default setup. The HTTP and gRPC endpoints run unencrypted.
- The NHI registry stores agent metadata in memory by default. The `registry_db.go` Postgres backend exists but is less tested.
- `bin/kernel.exe` is a committed Windows binary. It may be stale relative to the current source.

## Related

- [vaos.sh](https://vaos.sh) -- managed infrastructure
- [denario_ex](https://github.com/jmanhype/denario_ex) -- Elixir research pipeline that generated the companion paper
- [Paper: intent-scoped credentials for NHI](https://vaos.sh/blog/non-human-identity-ai-agents)

## License

GPL-3.0
