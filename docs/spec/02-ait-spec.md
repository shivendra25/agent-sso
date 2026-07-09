# Agent Identity Token (AIT) Specification

## Overview

The **Agent Identity Token (AIT)** is the core credential of AgentSSO. It is
a **RFC 9068-compliant JWT access token** issued by the aIdP that represents
an agent's cryptographic identity and its delegated-from human principal.

The AIT is **never seen by the LLM** — it stays in the agent runtime process
memory and is presented to the aIdP's token exchange endpoint to obtain
per-tool JIT tokens. The LLM context only ever sees tool-call results, never
a bearer token.

## Token Format

```
<base64url-encoded header>.<base64url-encoded payload>.<base64url-encoded signature>
```

### Header

```json
{
  "alg": "ES256",
  "typ": "at+jwt",
  "kid": "2026-07-01-key-1"
}
```

- `alg`: ES256 (ECDSA P-256 / SHA-256)
- `typ`: `at+jwt` per RFC 9068 Section 2.1
- `kid`: Key ID, matches a key in the aIdP's JWKS (`/.well-known/jwks.json`)

### Payload — Standard Claims (RFC 9068 Section 2.2)

| Claim | RFC | Description | Example |
|---|---|---|---|
| `iss` | 9068 §2.2.1 | aIdP issuer URL | `https://aidp.agentsso.io` |
| `sub` | 9068 §2.2.2 | Agent identity (stable UUID) | `a:f3b7c1e2-...` |
| `aud` | 9068 §2.2.3 | Target audience = aIdP token exchange endpoint | `https://aidp.agentsso.io/oauth/token` |
| `exp` | 9068 §2.2.4 | Expiration (Unix epoch) | `1752280800` |
| `iat` | 9068 §2.2.5 | Issued at (Unix epoch) | `1752279900` |
| `nbf` | 9068 §2.2.6 | Not before (Unix epoch) | `1752279900` |
| `jti` | 9068 §2.2.7 | Unique token ID (UUID) — used for replay detection | `01HXYZ...` |
| `client_id` | 9068 §2.2.8 | Agent runtime's registered client_id (RFC 7591) | `agent-runtime-prod-1` |
| `scope` | 9068 §2.2.9 | Space-delimited approved scopes | `agent:attest tools:exchange` |

**Default TTL**: 15 minutes (`exp - iat = 900s`). Configurable per tenant,
max 30 minutes.

### Payload — Delegated Actor Claim (RFC 8693 §4.3)

| Claim | RFC | Description | Example |
|---|---|---|---|
| `act` | 8693 §4.3 | Acting-on-behalf-of: identifies the human principal | see below |

The `act` claim is an object containing:

```json
"act": {
  "sub": "oidc:okta:00u8f4jk2l...",  // human principal's OIDC subject
  "iss": "https://acme.okta.com",     // principal's issuing IdP
  "delegation_id": "del_8x2k..."      // AgentSSO delegation grant ID
}
```

This is the **delegation chain root**. Every downstream JIT token inherits
this `act` claim unchanged so that MCP servers and audit logs can trace every
action back to a human.

If the human principal was not established (e.g., unattended agent), `act` is
omitted and the AIT has zero scope-based access — the agent can only self-attest.

### Payload — Custom Claims (AgentSSO-specific)

These are namespaced with no prefix to keep payloads compact. They are
registered as extension claims and documented here as the authoritative
schema.

| Claim | Type | Description | Example |
|---|---|---|---|
| `cnp` | string | Codebase hash (git tree SHA-256) — the source code the agent is running | `sha256:abc123...` |
| `rtm` | string | Runtime hash (runtime version + builder identity) | `sha256:def456...` |
| `ses` | string | Agent session ID — groups all actions in one agent session | `ses_9a2b...` |
| `att_jti` | string | The attestation document's JTI — links AIT to a specific attestation | `att_3f1c...` |
| `tenant` | string | Tenant ID for multi-tenant isolation | `tnt_acme` |

### Complete Example Payload

```json
{
  "iss": "https://aidp.agentsso.io",
  "sub": "a:f3b7c1e2-89d4-4a6b-9c0e-7f2a1b8d3e5f",
  "aud": "https://aidp.agentsso.io/oauth/token",
  "exp": 1752280800,
  "iat": 1752279900,
  "nbf": 1752279900,
  "jti": "01HXYZF8K3VN5RWM2P9Q4T7J6M",
  "client_id": "agent-runtime-prod-1",
  "scope": "agent:attest tools:exchange",
  "act": {
    "sub": "oidc:okta:00u8f4jk2labCdEfGhIj",
    "iss": "https://acme.okta.com",
    "delegation_id": "del_8x2k9p..."
  },
  "cnp": "sha256:a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
  "rtm": "sha256:b2c3d4e5f67890123456789012345678901234567890abcdef123456789abcdef1",
  "ses": "ses_9a2b7c4d",
  "att_jti": "att_3f1c8d2e",
  "tenant": "tnt_acme"
}
```

## Token Lifecycle

```
        attestation verified
             │
             ▼
    ┌────────────────┐
    │ AIT ISSUED      │ iat = now, exp = now + 900s
    │ (aIdP)         │ jti = fresh UUID
    └───────┬────────┘
            │
            │ agent calls tool
            ▼
    ┌────────────────┐
    │ AIT PRESENTED   │ at /oauth/token (token exchange)
    │ to aIdP         │ jti checked against replay cache
    └───────┬────────┘
            │
            │ valid → issue JIT
            │ invalid/expired → 401
            ▼
    ┌────────────────┐
    │ AIT EXPIRES     │ exp reached, jti blocklisted
    │ (or revoked)   │ if drift: jti blocklisted early
    └────────────────┘
```

### Issuance Rules

1. AIT is **issued only after attestation verification succeeds**.
2. AIT `aud` is always the aIdP token exchange endpoint — it is **never** the
   MCP server. MCP-bound tokens are the JIT tokens minted via token exchange.
3. `scope` on the AIT is limited to meta-scopes (`agent:attest`,
   `tools:exchange`). Actual tool-level scopes are granted by the policy
   engine during token exchange, not self-asserted by the agent.
4. AIT `jti` is stored in a replay-prevention cache for the duration of its
   life. A replayed AIT (same `jti` used twice) returns 401 and triggers an
   audit alert.

### Validation Rules (at Token Exchange)

1. Verify ES256 signature against JWKS (`kid` match).
2. Verify `iss` matches expected aIdP issuer URL.
3. Verify `aud` contains the aIdP token exchange endpoint.
4. Verify `exp` not expired, `nbf` not yet active.
5. Verify `jti` not in replay/blocklist cache.
6. Verify `sub` (agent_id) is registered and active.
7. Verify `act` present (delegation chain established) for any scope-bearing
   request.
8. Verify `cnp`/`rtm` match last-known attestation (drift check).

## Scope Model

### Meta-Scopes (on AIT)

| Scope | Description |
|---|---|
| `agent:attest` | Agent can self-attest and request AIT issuance |
| `tools:exchange` | Agent can exchange AIT for JIT tokens |

### Tool-Scopes (on JIT, granted by policy)

Tool scopes follow the pattern `<server_alias>:<capability>`. Examples:

| Scope | Description |
|---|---|
| `github:prs:read` | Read pull requests from GitHub MCP server |
| `github:prs:write` | Create/update PRs on GitHub MCP server |
| `slack:messages:send` | Send messages via Slack MCP server |
| `jira:issues:read` | Read Jira issues |

Scope assignment is **policy-driven**, never agent-asserted. The agent
requests a scope; the policy engine allows or denies.

## Key Management

- Signing keys: ES256 (ECDSA P-256), rotated every 90 days.
- Active keys and next-active keys published at `/.well-known/jwks.json`.
- Key ID format: `YYYY-MM-DD-key-N`.
- Retired keys retained for verification only (no new signing) for 30 days after rotation.
```