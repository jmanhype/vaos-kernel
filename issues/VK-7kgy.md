---
id: VK-7kgy
title: "Harden VAOS Agentic JWT P1 persistence, OAuth transport, and verifier"
status: open
priority: 1
type: feature
created_at: 2026-09-17T20:07:16Z
created_by: speed
updated_at: 2026-09-17T20:08:00Z
content_hash: "sha256:a7b11cd4048cf280893d52d110908a1bbc15341ad8ed5d2385da92f4ba0c92a4"
assignee: dev-VK-7kgy
---

## Description
Harden the implemented Agentic JWT P0/P1 slice in `/Users/speed/vaos-kernel` for the next production increment.

## Scope
- Persist agent registrations and workflow definitions beyond process restart.
- Replace shared `VAOS_API_SECRET` transport with scoped OAuth client credentials.
- Add a standalone resource-server verifier using JWKS, `kid`, signature, claims, and proof checks.
- Add registration-level revocation and token invalidation.
- Add Authority signing-key rotation with overlap.
- Keep Jev outside VAOS Kernel as a separate semantic action gate.

## Acceptance Criteria
- [ ] AC #1: Agent registrations and workflow definitions survive a kernel restart, verified by an automated test or live smoke sequence.
- [ ] AC #2: Agentic JWT transport uses scoped OAuth client credentials and no unauthenticated production path.
- [ ] AC #3: A standalone resource-server verifier validates JWKS `kid`, Ed25519 signature, issuer, audience, expiry, agent proof, and required intent claims.
- [ ] AC #4: Registration revocation invalidates future token mints and existing tokens where required.
- [ ] AC #5: Authority signing-key rotation supports overlap so previously issued tokens verify during rotation.
- [ ] AC #6: `go test -race ./cmd/kernel ./internal/agenticjwt`, `go test ./...`, the live smoke test, build, and credential scan all pass.

## Out of Scope
- Moving Jev into VAOS Kernel.
- Merging or copying proprietary Auth51 code.
- Production deployment before IP/licensing boundaries are settled.

## Acceptance Criteria


## Design


## Notes
## nd_contract
status: in_progress

### evidence
- 2026-09-17: initialized `/Users/speed/vaos-kernel` with Paivot shared-vault mode.
- 2026-09-17: codebase-memory project `Users-speed-vaos-kernel` reindexed at generation 2026-09-17T19:59:33Z with 943 nodes and 3,597 edges.
- 2026-09-17: existing P0/P1 implementation evidence is in `/Users/speed/Jev/vaos-auth51-jev-fit/evidence/vaos-kernel-agenticjwt-p1-*`.

### proof
- [ ] AC #1: persistence survives restart.
- [ ] AC #2: scoped OAuth transport is enforced.
- [ ] AC #3: standalone verifier validates JWKS/kid/signature/claims.
- [ ] AC #4: registration revocation invalidates tokens.
- [ ] AC #5: signing-key rotation supports overlap.
- [ ] AC #6: race/full tests, smoke test, build, and credential scan pass.

## History
- 2026-09-17T20:07:16Z status: open -> in_progress
- 2026-09-17T20:07:16Z claimed by dev-VK-7kgy
- 2026-09-17T20:08:00Z status: in_progress -> open

## Links


## Comments
