# VAOS-Kernel

VAOS-Kernel is a Go-based coordination kernel for non-human identities (NHIs). It provides an in-memory NHI registry, deterministic intent hashing, 60-second just-in-time JWT issuance, an ALCOA+ style audit ledger, and concurrent gRPC endpoints for Swarm, Crucible, and Interface integrations.

## Architecture

```text
                 +-------------------+
                 |   User / Client   |
                 +---------+---------+
                           |
                           v
                 +-------------------+
                 |   VAOS-Kernel     |
                 | cmd/kernel        |
                 +---------+---------+
                           |
      +--------------------+--------------------+
      |                    |                    |
      v                    v                    v
+-------------+   +----------------+   +----------------+
| NHI Registry|   | JWT Issuer     |   | Audit Ledger   |
| internal/nhi|   | internal/jwt   |   | internal/audit |
+------+------+   +--------+-------+   +--------+-------+
       |                    |                    |
       +----------+---------+---------+----------+
                  |                   |
                  v                   v
           +-------------+     +--------------+
           | Intent Hash |     | gRPC Services|
           | internal/hash|    | internal/grpc|
           +------+------+     +------+-------+
                  |                   |
          +-------+-------+   +-------+-------+-------+
          |               |   |               |       |
          v               v   v               v       v
      swarm.proto   crucible.proto    interface.proto clients
```

## Project Overview

- `internal/nhi`: agent identity, role, capability, reputation, intent fingerprint, and token lifecycle registry.
- `internal/jwt`: strict 60-second JIT JWT issuer and verifier.
- `internal/hash`: deterministic cryptographic intent hashing using BLAKE2b-256 from `golang.org/x/crypto`.
- `internal/audit`: ALCOA+ aligned audit ledger with structured log emission and attestations.
- `internal/grpc`: concurrent gRPC services for Swarm, Crucible, and Interface traffic.
- `pkg/models`: shared models used across the kernel.

## Installation

1. Install Go 1.21 or newer.
2. Install `protoc` and the Go protobuf plugins if you plan to run `make proto`.
3. Clone the repository and fetch dependencies:

```bash
go mod tidy
```

4. Build the project:

```bash
make build
```

## Usage

Start the kernel server:

```bash
go run ./cmd/kernel
```

Override the listening address:

```bash
VAOS_KERNEL_ADDR=127.0.0.1:9090 go run ./cmd/kernel
```

## API Documentation

### NHI Registry

- Register and retrieve agents with roles, capabilities, and reputation scores.
- Store latest intent fingerprints used to scope JIT tokens.
- Track token issuance, use, and revocation states.

### JWT Issuer

- Issues HS256 signed JWTs.
- Enforces exactly one intent fingerprint per token.
- Rejects tokens whose `exp - iat` is not exactly 60 seconds.

### Audit Ledger

- Records agent actions with timestamps and cryptographic attestations.
- Produces structured JSON log lines.
- Supports gRPC execution evidence.

### gRPC Services

- `SwarmService.ExecuteIntent`
- `CrucibleService.ExecuteTask`
- `InterfaceService.Dispatch`

Each request includes:

- `agent_id`
- `token`
- `action`
- `resource`
- `parameters`

Each response includes an execution identifier and service-specific evidence.

## Testing

Run the full test suite:

```bash
make test
```

Unit tests cover hashing, registry operations, JWT issuance/verification, and the audit ledger. Integration tests start an in-memory gRPC server, issue real tokens, and exercise all three service endpoints concurrently.

## Protocol Buffers

Protocol definitions live in [proto/swarm.proto](/C:/Users/strau/.openclaw/workspace/VAOS-Kernel/proto/swarm.proto), [proto/crucible.proto](/C:/Users/strau/.openclaw/workspace/VAOS-Kernel/proto/crucible.proto), and [proto/interface.proto](/C:/Users/strau/.openclaw/workspace/VAOS-Kernel/proto/interface.proto).

Generate Go bindings with:

```bash
make proto
```

