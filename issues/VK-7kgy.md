---
id: VK-7kgy
title: "Harden VAOS Agentic JWT P1 persistence, OAuth transport, and verifier"
status: closed
priority: 1
type: feature
created_at: 2026-09-17T20:07:16Z
created_by: speed
updated_at: 2026-09-17T23:12:55Z
content_hash: "sha256:7fb72db33702336800ed044f7cf4a357d16187a66ead2ed1a7fa790554fce304"
parent: VK-oidn
assignee: dev-VK-7kgy
labels: [delivered, accepted]
closed_at: 2026-09-17T23:12:55Z
close_reason: "Accepted: delivery proof passes 9/9; all six acceptance criteria are evidenced; local and GitHub CI gates pass."
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
RED-PROGRESS: Standalone resource-server verifier tests were added in `.claude/worktrees/dev-VK-7kgy/internal/agenticresource/verifier_test.go`. They currently define the expected JWKS/kid/Ed25519/signature/claims/proof middleware behavior; implementation is pending. Compiled debug binary `kernel` was removed.
### CI/Test Results

- `go test -race ./cmd/kernel ./internal/agenticjwt`: PASS
- `go test ./...`: PASS
- `go build -o /tmp/vk-7kgy-kernel-final ./cmd/kernel`: PASS
- `python3 scripts/agentic_jwt_smoke.py`: PASS, including registry restart persistence
- redacted `gitleaks detect --no-git`: PASS with two documented pre-existing draft-example allowlist entries

### AC Verification

[x] AC #1: persistence survives restart.
[x] AC #2: scoped OAuth transport is enforced.
[x] AC #3: standalone verifier validates JWKS/kid/signature/claims/proof.
[x] AC #4: registration revocation invalidates tokens where required.
[x] AC #5: signing-key rotation supports overlap.
[x] AC #6: all specified gates pass.
Commit SHA: 81d3289f7b78476fe882ecdf1042611fb4ba295a

Commit: `81d3289 feat: harden agentic jwt runtime`

Pushed branch: `origin/story/VK-7kgy`
Pull request: https://github.com/jmanhype/vaos-kernel/pull/1

PR title: Harden Agentic JWT persistence, OAuth transport, and verifier

PR branch: `story/VK-7kgy` -> `master`

GitHub CI: both required `test` checks passed.

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

## nd_contract
status: delivered

### evidence
- Transitioned via pvg story deliver on 2026-09-17.

### proof
- [ ] Developer evidence block must remain authoritative above this contract.


## Implementation Evidence

Summary: Implemented durable Agentic JWT registry restore, runtime scoped OAuth client-credential transport, standalone resource-server verification, registration revocation, and signing-key rotation in story worktree `/Users/speed/vaos-kernel/.claude/worktrees/dev-VK-7kgy`.

Commit SHA: 312c78fdac8a1acd06f535058ccd5fcd5b41eb52 (story branch HEAD; implementation files are present but not committed because commit/push authorization has not been given).

Evidence directory: `/Users/speed/Jev/vaos-auth51-jev-fit/evidence/vk-7kgy-20260917`

Commands run:
- `git diff --check`
- `go vet ./cmd/kernel ./internal/agenticjwt ./internal/agenticresource`
- `go test -race ./cmd/kernel ./internal/agenticjwt`
- `go test ./...`
- `go build -o /tmp/vk-7kgy-kernel-final ./cmd/kernel`
- `python3 scripts/agentic_jwt_smoke.py`
- `gitleaks detect --source . --no-git --redact --report-format json --report-path ... --gitleaks-ignore-path ... --exit-code 99`

## CI/Test Results

- Race gate: PASS (`race-test.txt`, SHA-256 `bcf7cfd81847e3dd67b32c08f148ed53d241736db551680457cdc160d4d86751`)
- Full Go suite: PASS (`full-test.txt`, SHA-256 `941eb761b5dc92d066b3e4f1e07c68d828d50b71bd2355189cc9d4f23f9be26f`)
- Build: PASS, exit 0 (`build.txt`, empty-output SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`)
- Live mounted smoke: PASS with `registry_restart_persisted: true` (`smoke.json`, SHA-256 `032bfad462b4d20bfa178f96fb40e36a4fcdb6d9f598db823dcd48a4b8606dae`)
- Credential scan: PASS, 1.04 MB scanned, no leaks after explicit allowlist of two redacted example JWTs in pre-existing IETF draft snapshots (`credential-scan.txt`, SHA-256 `ccf7b9fc2cfd282342b26415316ec771e7f644108dbbfd31aa4462ac1e8f26bd`)
- Static gates: PASS (`static-gates.txt`, SHA-256 `176342ef0dbb59ab11b2da236df8e20c25eb844b1200dac7415c97d0a05850c7`)

## nd_contract
status: delivered

### evidence
- Files on disk in `/Users/speed/vaos-kernel/.claude/worktrees/dev-VK-7kgy`: `cmd/kernel/agentic.go`, `cmd/kernel/agentic_test.go`, `cmd/kernel/main.go`, `.env.example`, `docs/AGENTIC_JWT_P0.md`, `scripts/agentic_jwt_smoke.py`, `internal/agenticjwt/*`, and `internal/agenticresource/verifier.go`.
- Final evidence and `SHA256SUMS` are stored in `/Users/speed/Jev/vaos-auth51-jev-fit/evidence/vk-7kgy-20260917`.
- OAuth client IDs are distinct and duplicate client secrets fail closed.
- The live smoke obtains scoped tokens, rejects the legacy shared bearer secret, restarts the kernel with the same registry path, and mints a distinct intent token from restored state.

### proof
- [x] AC #1: persistence survives restart — `TestAgenticJWTRuntimePersistsRegistrationsAcrossReopen`, `TestFileRegistryPersistsAcrossReopen`, and live `registry_restart_persisted: true`.
- [x] AC #2: scoped OAuth transport is enforced — `TestScopedOAuthClientCredentialsTransport`, `TestClientCredentialsEndpointFailsClosed`, `TestTransportClientsRejectSharedSecrets`, `TestMountAgenticJWT`, and live shared-secret rejection.
- [x] AC #3: standalone verifier validates JWKS/kid/signature/claims/proof — `TestStandaloneVerifierValidatesJWKSSignatureClaimsAndAgentProof`, `TestStandaloneVerifierRejectsTamperingAndWrongProof`, `TestStandaloneVerifierRejectsMissingIntentClaims`, and middleware tests.
- [x] AC #4: registration revocation invalidates future mints and existing Authority-verified tokens — `TestRegistrationRevocationInvalidatesMintAndExistingTokens`.
- [x] AC #5: signing-key rotation retains verification overlap — `TestSigningKeyRotationKeepsPreviousVerificationOverlap`.
- [x] AC #6: race/full tests, live smoke, build, and credential scan pass — evidence files and hashes above.

## History
- 2026-09-17T20:07:16Z status: open -> in_progress
- 2026-09-17T20:07:16Z claimed by dev-VK-7kgy
- 2026-09-17T20:08:00Z status: in_progress -> open
- 2026-09-17T20:09:08Z status: open -> in_progress
- 2026-09-17T20:09:08Z claimed by dev-VK-7kgy
- 2026-09-17T20:09:08Z status: in_progress -> open
- 2026-09-17T20:09:57Z status: open -> in_progress
- 2026-09-17T20:09:57Z claimed by dev-VK-7kgy
- 2026-09-17T20:23:29Z status: in_progress -> open
- 2026-09-17T20:23:29Z released by speed
- 2026-09-17T20:25:25Z status: open -> in_progress
- 2026-09-17T20:25:25Z claimed by dev-VK-7kgy
- 2026-09-17T20:56:27Z status: in_progress -> in_progress
- 2026-09-17T23:12:55Z status: in_progress -> closed

## Links
- Parent: [[VK-oidn]]

## Comments

### 2026-09-17T20:08:00Z speed
loop: reset orphaned in_progress to open (no developer worktree found; prior session presumed dead)

### 2026-09-17T20:09:08Z speed
loop: reset orphaned in_progress to open (no developer worktree found; prior session presumed dead)
