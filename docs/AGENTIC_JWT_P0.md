# Agentic JWT P0 compatibility profile

Status: **P0/P1 compatibility slice implemented and mounted**

Date: 2026-09-17

## Scope

`internal/agenticjwt` implements the first isolated compatibility slice for
[draft-goswami-agentic-jwt-01](https://datatracker.ietf.org/doc/draft-goswami-agentic-jwt/).
It intentionally does **not** modify the legacy 60-second action-token issuer.
That keeps protocol work independently testable while preserving the existing
VAOS enforcement and audit paths.

Implemented:

- draft-shaped agent specification;
- normalized, deterministic SHA-256 agent checksum using RFC 8785 JCS;
- checksum format validation;
- versioned, append-only agent registration;
- duplicate-checksum rejection;
- constant-time checksum comparison;
- `agent_checksum` token request validation;
- OAuth-shaped request errors;
- Ed25519-signed intent tokens;
- `iss`, `aud`, `sub`, `exp`, `iat`, `jti`, and `scope`;
- `cnf.jwk` proof-of-possession key confirmation;
- `intent` workflow/delegation hashes;
- `agent_proof` checksum and registration ID;
- OAuth-shaped token response;
- proof-of-possession challenge signing and verification;
- ordered workflow registration and prerequisite/approval/delegation validation;
- hash-chained audit entries for registration, workflow registration, mint, checksum mismatch, and verification;
- durable, owner-only, atomically replaced agent/workflow registry snapshots;
- scoped OAuth 2.0 client-credentials transport tokens;
- registration revocation that blocks future mints and existing Authority verification;
- signing-key rotation with overlapping verification keys;
- standalone resource-server JWKS, signature, claims, scope, and proof verification;
- HTTP agent registration;
- HTTP workflow registration;
- public Authority signing JWKS with RFC 7638 `kid`;
- optional mounting of:
  - `POST /v1/oauth/token`
  - `POST /v1/intent/register/agent`
  - `POST /v1/intent/register/workflow`
  - `POST /v1/intent/token`
  - `GET /.well-known/jwks.json`

## Current design boundary

The package has two key families:

- The **Authority signing key** signs intent tokens.
- Each **registered agent key** is used for proof-of-possession and embedded as
  `cnf.jwk`.

This separation prevents an agent's proof key from becoming the Authority token
signing key.

The protocol handlers implement their request and response shapes while
`cmd/kernel` owns runtime transport authorization. Enabling Agentic JWT requires
three OAuth clients with distinct IDs and unique secrets: agent registration,
workflow administration, and intent-token issuance. The public
client-credentials endpoint exchanges each client's secret for a short-lived
Ed25519 transport JWT with only that client's allowed scope. Mounted intent
endpoints reject the legacy shared
`VAOS_API_SECRET` and require the matching transport scope.

Enabled runtimes also require an owner-only registry file. Registration and
workflow writes are validated, serialized, atomically replaced, and restored on
the next kernel start.

The public JWKS endpoint is intentionally unauthenticated and exposes only the
Authority's Ed25519 public signing key. Its `kid` is the RFC 7638 thumbprint and
is also emitted in the JWT header.

The kernel injects its existing audit recorder. Agentic JWT registration, mint,
and verification fail closed if an audit entry cannot be recorded.

Run the mounted end-to-end smoke test with:

```bash
python3 scripts/agentic_jwt_smoke.py
```

The script builds an ephemeral kernel, generates an ephemeral Ed25519 key pair,
obtains scoped OAuth transport tokens, proves the legacy shared secret is
rejected, registers an agent and workflow, mints a token, checks the JWT `kid`
against JWKS, verifies the hash-chained audit trail, restarts the kernel on the
same registry file, and mints a second token from restored state. No credential
is written to the durable registry.

## Runtime configuration

```text
VAOS_AGENTIC_JWT_ENABLED=true
VAOS_AGENTIC_JWT_APP_ID=your-app
VAOS_AGENTIC_JWT_ISSUER=https://authority.example.com
VAOS_AGENTIC_JWT_SIGNING_KEY=<64-byte-private-key-or-seed:...>
VAOS_AGENTIC_JWT_TTL_SECONDS=300
VAOS_AGENTIC_JWT_REGISTRY_PATH=<owner-only-json-file>
VAOS_AGENTIC_JWT_REGISTRAR_CLIENT_ID=<client-id>
VAOS_AGENTIC_JWT_REGISTRAR_CLIENT_SECRET=<required-secret>
VAOS_AGENTIC_JWT_WORKFLOW_CLIENT_ID=<client-id>
VAOS_AGENTIC_JWT_WORKFLOW_CLIENT_SECRET=<required-secret>
VAOS_AGENTIC_JWT_TOKEN_CLIENT_ID=<client-id>
VAOS_AGENTIC_JWT_TOKEN_CLIENT_SECRET=<required-secret>
```

The signing key is a base64url 64-byte Ed25519 private key, or a 32-byte seed
encoded as `seed:<base64url>`. The explicit `seed:` prefix prevents an Ed25519
public key from being accepted as an ambiguous 32-byte seed.

## Example

```go
agentPublic, agentPrivate, _ := ed25519.GenerateKey(rand.Reader)
_, authorityPrivate, _ := ed25519.GenerateKey(rand.Reader)

spec := agenticjwt.AgentSpec{
    AgentID: "patcher-v1",
    Prompt:  "Patch verified vulnerabilities only.",
    Tools: []agenticjwt.Tool{{
        Name:        "create_patch",
        Signature:   "create_patch(patch Patch)",
        Description: "Create a reversible source patch",
    }},
    Configuration: map[string]any{"model_name": "example"},
}

checksum, _ := agenticjwt.CanonicalChecksum(spec)
registry := agenticjwt.NewRegistry(time.Now)
registration, _ := registry.Register("acme", spec, agentPublic)

authority, _ := agenticjwt.NewAuthority(
    "acme",
    "https://authority.example.test",
    authorityPrivate,
    registry,
    300*time.Second,
    time.Now,
)

response, _, _ := authority.Mint("acme", agenticjwt.TokenRequest{
    GrantType:        "agent_checksum",
    AgentID:          spec.AgentID,
    ComputedChecksum: checksum,
    RequestedScopes:  []string{"repo:write"},
    Audience:         agenticjwt.Audience{"https://api.example.test"},
})

claims, _ := authority.Verify(response.AccessToken, "https://api.example.test")
proof, _ := agenticjwt.SignProof(agentPrivate, []byte("challenge"))
_ = agenticjwt.VerifyProof(agentPublic, []byte("challenge"), proof)
```

## Known limitations

1. **Canonicalization**
   - Configuration is canonicalized with the RFC 8785 JCS rules.
   - The test suite pins the RFC's Appendix B number vectors, UTF-16 property
     ordering, primitive escaping, and non-finite/lone-surrogate rejection.

2. **Workflow authorization**
   - The registry stores ordered workflow definitions and enforces step
     existence, authorized agents, required prerequisites, approval gates,
     completion order, and delegation-chain consistency.
   - `/v1/intent/register/workflow` accepts both ordered-step arrays and the
     draft's step-object wire shape.
   - Workflow administration requires a client credential scoped only to
     `agentic:register-workflow`.

3. **Resource-server verification**
   - The Authority publishes a public Ed25519 signing key at
     `GET /.well-known/jwks.json`.
   - `internal/agenticresource` independently validates JWKS `kid`, Ed25519
     signature, issuer, audience, expiry, required intent claims, scope, and
     request-bound agent proof.

4. **Transport authentication**
   - The three static OAuth clients are configured by environment and have no
     dynamic registration, rotation, or revocation mechanism yet.

5. **Persistence**
   - Registry records use a local owner-only JSON snapshot. It is suitable for
     the current single-process kernel slice, not multi-writer federation.

6. **Legacy integration**
   - `cmd/kernel` still serves the existing action-token API.
   - The P0 endpoints are separately mounted and do not replace it.

## Next increment

1. Add durable OAuth client configuration and client-secret rotation.
2. Add bounded JWKS caching and stale-key fail-closed behavior for resource servers.
3. Move the registry snapshot to a multi-writer transactional store when needed.
