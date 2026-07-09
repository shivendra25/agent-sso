# Token Exchange (RFC 8693)

## Overview

Token exchange is the federation mechanism that allows an agent to obtain a
per-tool, audience-bound, scope-narrowed **JIT token** by presenting its AIT.
It implements **RFC 8693 (OAuth 2.0 Token Exchange)** with strict extensions
for agent-specific semantics.

## Endpoint

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
```

## Request

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<AIT JWT>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&resource=https://mcp.github.example.com
&scope=github:prs:read
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
```

### Parameter Definitions

| Parameter | RFC | Required | Description |
|---|---|---|---|
| `grant_type` | 8693 §2.1 | Yes | Must be `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | 8693 §2.2.2 | Yes | The AIT JWT (compact serialization) |
| `subject_token_type` | 8693 §2.2.3 | Yes | `urn:ietf:params:oauth:token-type:access_token` |
| `resource` | 8707 §2 | Yes | Canonical URI of the target MCP server |
| `scope` | 8693 §2.2.4 | Yes | Space-delimited requested scopes |
| `requested_token_type` | 8693 §2.2.1 | No | Defaults to `access_token` |
| `audience` | 8693 §2.2.5 | No | Alias for `resource`; `resource` takes precedence |

## Validation Pipeline

```
1. Parse subject_token as JWT
2. Verify ES256 signature (JWKS lookup via kid)
3. Verify iss = aIdP issuer URL
4. Verify aud contains /oauth/token
5. Verify exp not expired, nbf not yet active
6. Check jti not in replay cache (blocklist)
7. Check jti not already consumed (if single-use AIT)
8. Verify sub (agent_id) is registered and active
9. Verify act present (delegation chain established)
10. Verify cnp/rtm match last-known attestation (drift check)
11. Parse resource → validate URI format (RFC 8707 §2)
12. Parse requested scope → pass to policy engine
13. Policy engine evaluates (agent_id, act.sub, scope, resource)
    → returns allowed_scope (may be subset of requested)
14. Issue JIT token (see below)
```

## JIT Token (Output)

The JIT token is an RFC 9068 JWT access token with the following claims:

| Claim | Source | Description |
|---|---|---|
| `iss` | aIdP | `https://aidp.agentsso.io` |
| `sub` | AIT `sub` | Agent identity |
| `aud` | `resource` param | **Target MCP server URI** (RFC 8707) |
| `exp` | now + TTL (5–10 min) | Short-lived |
| `iat` | now | Issued at |
| `jti` | fresh UUID | Single-use; consumed at MCP server or gateway |
| `client_id` | AIT `client_id` | Agent runtime client ID |
| `scope` | policy-approved | Space-delimited, **may be subset of requested** |
| `act` | AIT `act` | **Inherited verbatim** — delegation chain preserved |
| `ses` | AIT `ses` | Agent session ID |
| `tenant` | AIT `tenant` | Tenant ID |
| `ait_jti` | AIT `jti` | Links JIT back to its parent AIT for audit |

### Example JIT Payload

```json
{
  "iss": "https://aidp.agentsso.io",
  "sub": "a:f3b7c1e2-89d4-4a6b-9c0e-7f2a1b8d3e5f",
  "aud": "https://mcp.github.example.com",
  "exp": 1752279960,
  "iat": 1752279900,
  "jti": "01HXYZJ9L4WO6SXN3P0R5U8K7N",
  "client_id": "agent-runtime-prod-1",
  "scope": "github:prs:read",
  "act": {
    "sub": "oidc:okta:00u8f4jk2labCdEfGhIj",
    "iss": "https://acme.okta.com",
    "delegation_id": "del_8x2k9p..."
  },
  "ses": "ses_9a2b7c4d",
  "tenant": "tnt_acme",
  "ait_jti": "01HXYZF8K3VN5RWM2P9Q4T7J6M"
}
```

## Response

### Success (HTTP 200)

```json
{
  "access_token": "<JIT JWT>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "github:prs:read"
}
```

### Errors (per RFC 8693 §3.2 + OAuth 2.1)

| HTTP | Error | Description |
|---|---|---|
| 400 | `invalid_request` | Malformed request, missing required params |
| 401 | `invalid_token` | AIT signature/audience/expiry/jti validation failed |
| 403 | `invalid_scope` | Requested scope not allowed by policy |
| 403 | `insufficient_scope` | Policy narrowed scope to empty set |
| 400 | `invalid_target` | `resource` URI not registered or invalid |

```json
{
  "error": "invalid_token",
  "error_description": "AIT expired"
}
```

## Delegation Chain Semantics

The `act` claim is the **delegation chain** (RFC 8693 §4.3). In v1 the chain
is always exactly two levels:

```
act.sub (human principal, OIDC sub)
  └─ sub (agent)
```

In v2 (agent-to-agent), the chain can nest:

```
act.act.sub (human)
  └─ act.sub (orchestrator agent)
       └─ sub (sub-agent)
```

For v1, **no nesting** — the aIdP rejects any AIT or token-exchange request
where `act` already contains `act`.

## Single-Use Semantics

The JIT token's `jti` is marked single-use:

- The gateway consumes it on first call.
- A replayed JIT (same `jti` used twice) is rejected by the MCP server (if it
  enforces single-use) or by the gateway (which check...
...
```
(AIT replay is prevented by the replay cache.)
```

## Rate Limiting

Token exchange requests are rate-limited per:

- `agent_id`: max 60 exchanges/minute
- `act.sub` (human principal): max 200 exchanges/minute
- `tenant`: max 1000 exchanges/minute

Exceeding limits returns HTTP 429 with `Retry-After` header.