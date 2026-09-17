---
id: VK-7kgy
title: "Harden VAOS Agentic JWT P1 persistence, OAuth transport, and verifier"
status: open
priority: 1
type: feature
created_at: 2026-09-17T20:07:16Z
created_by: speed
updated_at: 2026-09-17T20:07:16Z
content_hash: "sha256:34e58df235c028294af1f06fa659ddaad3b03150990da8a3c79cc23e461450b2"
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


## History


## Links


## Comments
