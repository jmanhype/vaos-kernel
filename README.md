# VAOS-Kernel
n[![CI](https://github.com/jmanhype/vaos-kernel/actions/workflows/ci.yml/badge.svg)](https://github.com/jmanhype/vaos-kernel/actions/workflows/ci.yml) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/Go-1.22-00ADD8.svg)](https://go.dev)

**Intent-scoped credentials with hash-chained ALCOA+ audit for AI agents.**

Every credential is cryptographically bound to the exact action the agent declares. Every audit entry chains to the previous one. Modify any record and the entire chain breaks. The compliance tax? **0.5% overhead.**

Submitted to [NIST NCCoE](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization) as a public comment on AI Agent Identity and Authorization. Implements the pattern described in [IETF draft-goswami-agentic-jwt-00](https://datatracker.ietf.org/doc/draft-goswami-agentic-jwt/).

## Benchmark Results (Mac Mini M4, Go 1.26, PostgreSQL 17)

| Configuration | RPS at 1,000 agents | p99 Latency |
|---|---|---|
| Baseline (no attestation) | 51,005 | 0.70ms |
| **Sync + ALCOA+ attestation** | **50,774** | **1.69ms** |
| Async attestation | 32,827 | 87.86ms |
| Sync + Postgres | 20,329 | 622ms |
| Async + Postgres | 864 | 10,123ms |

Full ALCOA+ attestation (BLAKE2b fingerprinting + JWT signing + hash chain) adds **0.5% overhead** versus doing nothing. Async write-behind is 35% slower due to channel coordination exceeding sub-microsecond BLAKE2b computation.

[Paper: "vaos-kernel: Intent-Scoped Credentials with Hash-Chained ALCOA+ Audit for Non-Human Identities"](https://vaos.sh/blog/non-human-identity-ai-agents) (15 citations, real hardware benchmarks)

## What It Does

**Intent-scoped credentials.** The agent declares what it plans to do — action, resource, parameters. That declaration gets BLAKE2b-256 hashed into a deterministic fingerprint, sealed inside a 60-second JWT. If the agent tries anything other than what it declared, the credential is mathematically invalid.

**Hash-chained ALCOA+ audit.** Every audit entry's attestation includes the previous entry's hash: `H_n = BLAKE2b(canonical_fields_n || H_{n-1})`. Modify any historical entry and the chain breaks for all subsequent entries. This is the same data integrity standard pharmaceutical companies use for FDA 21 CFR Part 11 — applied to AI agent actions.

**60-second ephemeral TTL.** Credentials self-destruct. No standing privileges. Verification rejects any token where `exp - iat ≠ 60s`.

## How It Differs

| | vaos-kernel | HashiCorp Vault | SPIFFE/SPIRE | OPA |
|---|---|---|---|---|
| Credential scope | Per-action (60s) | Session (min-hr) | Workload (min-hr) | N/A |
| Intent binding | BLAKE2b hash | None | None | Policy logic |
| Audit integrity | Hash-chained | Append-only | Standard log | Mutable log |
| ALCOA+ compliance | Full | Partial | None | None |

## Architecture

```
Request → JSON Parse → BLAKE2b Intent Fingerprint → 60s JWT Issue → Hash Chain Audit → Response
```

- `internal/jwt` — strict 60s JIT JWT issuer/verifier (HS256, `golang-jwt/jwt/v5`)
- `internal/hash` — deterministic BLAKE2b-256 intent fingerprinting (`golang.org/x/crypto/blake2b`)
- `internal/audit` — hash-chained ALCOA+ ledger with `VerifyChain()` integrity check
- `internal/nhi` — NHI registry (agent identity, roles, capabilities, reputation, token lifecycle)
- `internal/grpc` — concurrent gRPC services (Swarm, Crucible, Interface)
- `cmd/benchmark` — load generator with Poisson arrivals, connection pooling, CSV/JSON output

## Quick Start

```bash
go mod tidy
go build -o vaos-kernel ./cmd/kernel
./vaos-kernel
```

The kernel starts gRPC on `:50051` and HTTP on `:8080`.

```bash
# Issue a token
curl -X POST http://localhost:8080/api/token \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "zoe", "intent_hash": "read-table-users", "action_type": "query"}'

# List agents
curl http://localhost:8080/api/agents
```

## Run Benchmarks

```bash
go build -o benchmark ./cmd/benchmark
./benchmark
```

Outputs `benchmark_results.csv` and `benchmark_results.json`. Set `VAOS_KERNEL_MODE=async` for async mode, `VAOS_DB_DSN=...` for Postgres-backed modes.

## Why Now

- **NIST NCCoE** seeking agent identity guidance (comments due April 2, 2026)
- **EU AI Act** high-risk provisions effective August 2, 2026
- **IETF** standardizing intent-scoped JWTs (draft-goswami-agentic-jwt-00)
- **$21B NHI market** — 63% of orgs can't enforce agent purpose limits (CSA 2026)

## Related

- [vaos.sh](https://vaos.sh) — managed AI agent infrastructure
- [denario_ex](https://github.com/jmanhype/denario_ex) — Elixir research pipeline that generated the paper
- [Blog: The $21B Problem Nobody's Solving](https://vaos.sh/blog/non-human-identity-ai-agents)

## License

GPL-3.0
