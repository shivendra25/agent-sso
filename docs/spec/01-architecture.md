# AgentSSO Architecture

## System Overview

```
                         ┌─────────────────────────────────────────────┐
                         │              AgentSSO Control Plane          │
                         │                                               │
    ┌────────────┐       │  ┌─────────┐  ┌──────────┐  ┌────────────┐  │
    │  Human     │───────┼─►│  aIdP   │  │  Policy  │  │   Audit    │  │
    │ (principal)│ OIDC  │  │  (IdP)  │──│  (OPA)   │  │   Log      │  │
    │  Okta/Entra│ ────► │  │         │  └──────────┘  └────────────┘  │
    └────────────┘       │  │         │                                   │
                         │  │  ┌──────┴────────┐                         │
    ┌────────────┐       │  │  │  Token       │                         │
    │  Agent      │ att. │  │  │  Exchange     │                         │
    │  Runtime    │─────►│  │  │  (RFC 8693)  │                         │
    │ (opencode)  │      │  │  └──────┬───────┘                         │
    │             │      │  │         │                                  │
    │  tool call  │      │  └─────────┼──────────────────────────────────┘
    │             │      │            │ JIT token (out-of-context)
    │             │      │            ▼
    │             │      │  ┌─────────────────────┐
    └──────┬──────┘      │  │ Credential Boundary  │
           │             │  │   Tool Gateway       │
           │ tool call   │  │                       │
           └─────────────┼─►│  injects:            │
                         │  │  Authorization:       │
                         │  │    Bearer <jit>      │
                         │  └──────────┬───────────┘
                         │             │
                         └─────────────┼──────────────────────────────
                                       │ authenticated request
                                       ▼
                              ┌─────────────────┐
                              │  MCP Server     │
                              │  (RFC 9728      │
                              │   resource)     │
                              │  — unchanged    │
                              └─────────────────┘
```

## Components

### 1. Agent Identity Provider (aIdP)

The aIdP is the core of AgentSSO. It is a single Go service (`cmd/aidp`) with three responsibilities:

- **OIDC inbound federation** — accepts OIDC ID tokens from Okta/Entra/Google
  to establish the human principal. The human's `sub` claim becomes the `act`
  (acting-on-behalf-of) chain root in every AIT.
- **Attestation verification** — validates the agent runtime's attestation
  document (codebase hash, runtime hash, host signature) against a trusted
  runtime registry.
- **AIT issuance** — issues a short-lived Agent Identity Token (RFC 9068 JWT)
  carrying the agent identity, human principal delegation chain, scopes, and
  attestation fingerprint.

### 2. Token Exchange Endpoint

Part of the aIdP, but logically distinct. Implements **RFC 8693 Token
Exchange**:

- Accepts an AIT (subject token) + `resource` (target MCP server URI) + `scope`.
- Validates the AIT (signature, audience=aIdP, expiry, `jti` not consumed).
- Runs the AIT through the **policy engine** to determine allowed scopes.
- Issues a **JIT token** — short-lived (5–10 min), audience-bound to the
  `resource`, scope-narrowed, carrying the `act` delegation chain, single-use `jti`.

### 3. Credential Boundary / Tool Gateway

A separate Go service (`cmd/gateway`) that **holds credentials out of LLM context**:

- The agent sends tool calls to the gateway by server alias and path.
- The gateway retrieves (or mints via token exchange) a JIT token for the
  target server.
- The gateway injects `Authorization: Bearer <jit>` and forwards to the
  MCP server.
- The **LLM context never contains a bearer token** — first-line defense
  against prompt-injection credential theft.
- mTLS from the agent runtime to the gateway; runtime attestation is the
  authentication (not a shared secret).

### 4. Policy Engine (OPA/Rego)

Evaluates whether a given `(agent_id, human_principal, scope, resource)`
combination is allowed. Rules are stored as Rego policies, evaluated
in-process via the OPA Go SDK. Default policy: **deny all, explicit allow
only**.

### 5. Audit Log

Append-only, hash-chained audit log in Postgres. Each entry:

```
(human_principal, agent_id, agent_session, delegated_scope, tool_resource,
 action, jti, timestamp, prev_hash, this_hash)
```

### 6. Attestation

The agent runtime produces a signed attestation document:

```json
{
  "agent_id": "uuid",
  "codebase_hash": "sha256:git-tree-sha",
  "runtime_hash": "sha256:runtime+builder-version",
  "started_at": "ISO8601",
  "host_sig": "ed25519:signed-by-hosting-platform"
}
```

The aIdP verifies `host_sig` against the **trusted runtime registry**. Every
N minutes, the aIdP requests re-attestation; a mismatch revokes the AIT
(its `jti` is blocklisted). Short TTL means ≤15 min of residual access.

## Data Flow: Complete Session

```
Step 1: Human login (one-time per session)
  Human ──OIDC──► Okta/Entra ──id_token──► aIdP
  aIdP stores: principal_id = OIDC sub

Step 2: Agent attestation (per session start)
  Agent Runtime ──attestation_doc──► aIdP
  aIdP verifies host_sig + codebase_hash + runtime_hash
  aIdP links agent_id to principal_id (delegation grant)
  aIdP issues AIT (sub=agent_id, act.sub=principal_id, TTL=15min)

Step 3: Tool call (per action)
  Agent Runtime ──tool call──► Gateway
  Gateway ──token_exchange(AIT, resource, scope)──► aIdP
  aIdP validates AIT → policy check → issues JIT (aud=resource, TTL=5min)
  Gateway ──Authorization: Bearer <jit>──► MCP Server
  MCP Server responds → Gateway streams back → Agent Runtime
  Gateway logs audit entry

Step 4: Continuous re-attestation (every N min)
  aIdP ──re-attest_request──► Agent Runtime
  Agent Runtime ──attestation_doc──► aIdP
  aIdP verifies → if drift: revoke AIT (jti blocklist)
```

## Trust Boundaries

```
TRUSTED:
  ┌─────────────┐   ┌─────────────┐   ┌──────────────┐
  │ AgentRuntime │   │   aIdP      │   │   Gateway    │
  │  (process)   │   │  (service)   │   │  (service)   │
  └──────┬───────┘   └──────┬──────┘   └──────┬───────┘
         │ mTLS              │ internal        │ mTLS
         │ +attestation      │ link            │
         ▼                   ▼                 ▼
  ┌─────────────────────────────────────────────────┐
  │              aIdP ↔ Gateway: internal             │
  │              (shared trust, same network)         │
  └─────────────────────────────────────────────────┘
UNTRUSTED:
  ┌─────────────┐
  │  LLM/Agent  │  ← token never enters this boundary
  │  Context    │
  └─────────────┘
  ┌─────────────┐
  │ MCP Server  │  ← standard OAuth resource server
  │ (remote)    │
  └─────────────┘
```

## Technology Stack

| Component | Technology |
|---|---|
| Language | Go 1.26 |
| Database | PostgreSQL 16 + pgx |
| Policy | OPA (Rego) via Go SDK |
| HTTP | net/http + chi |
| OIDC | coreos/go-oidc + golang.org/x/oauth2 |
| Crypto | crypto/ecdsa (ES256), crypto/ed25519 |
| JWT | github.com/golang-jwt/jwt/v5 (or crypto/jwt stdlib) |
| Migrations | golang-migrate |