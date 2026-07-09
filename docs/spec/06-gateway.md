# Credential Boundary / Tool Gateway

## Overview

The Credential Boundary (Tool Gateway) is the defensive layer that ensures
**credentials never enter the LLM context**. It is the single most important
security property of AgentSSO: a prompt-injection attacker can make the agent
emit any tool call, but cannot extract a bearer token because the agent never
has one.

## Design Principle

```
┌─────────────────────────────────────────────────────┐
│  LLM/Agent Context          │   Credential Boundary  │
│  (UNTRUSTED)                │   (TRUSTED)            │
│                              │                        │
│  The agent sees:             │   The gateway holds:   │
│   - tool_call("github",      │    - AIT (attestation)  │
│      "GET /v1/prs/42")       │    - JIT tokens         │
│   - tool_result("...PR...")  │    - refresh tokens     │
│                              │                        │
│  The agent NEVER sees:        │   The gateway injects: │
│   - bearer tokens            │    Authorization:      │
│   - API keys                 │      Bearer <jit>      │
│   - credentials              │                        │
└──────────────────────────────┴────────────────────────┘
```

## Gateway Service

The gateway is a separate Go binary (`cmd/gateway`) that acts as a
**reverse proxy** for outbound tool calls.

### Architecture

```
Agent Runtime                    Gateway                    MCP Server
     │                             │                          │
     │  1. tool_call request       │                          │
     │     POST /v1/call/{alias}/* │                          │
     │     + AIT in auth context   │                          │
     │  ─────────────────────►    │                          │
     │                             │                          │
     │              2. Exchange AIT→JIT (token exchange)      │
     │              ───────────────► aIdP                     │
     │              ◄──── JIT ─────────                      │
     │                             │                          │
     │              3. Cache JIT (per server, per AIT)         │
     │                             │                          │
     │              4. Forward request with Authorization     │
     │                             │  Authorization: Bearer   │
     │                             │  ────────────────►       │
     │                             │  ◄── MCP response ──    │
     │                             │                          │
     │              5. Log audit entry                         │
     │                             │                          │
     │  6. Response (data only, no headers/token back)        │
     │  ◄─────────────────────   │                          │
     │                             │                          │
```

### API: Tool Call

```
POST /v1/call/{server_alias}/{path}
Content-Type: application/json
X-AIT: <Agent Identity Token JWT>
X-Session: <agent session ID>

{ ... request body ... }
```

- `X-AIT`: The agent's current AIT — validated by the gateway, used for
  token exchange. **Never logged. Never forwarded to MCP server.**
- `X-Session`: Agent session ID for audit correlation.
- `{server_alias}`: Maps to a server in the AgentSSO server registry (e.g.,
  `github` → `https://mcp.github.example.com`).
- `{path}`: Appended to the server's base URL.

### mTLS Authentication

The agent runtime authenticates to the gateway via **mTLS** (mutual TLS).
The client certificate is issued by the aIdP after attestation and is bound
to the agent's `agent_id`. This is separate from and complementary to the AIT:

- **mTLS** validates the *transport* identity (this connection is from a
  registered agent runtime).
- **AIT** validates the *session* identity and authorization (this agent,
  acting for this human, with these scopes).

No shared secret exists between the agent and gateway.

### Token Caching

The gateway caches JIT tokens to avoid re-exchanging per call:

```
cache_key = (agent_id, server_alias, scope_set)
cache_value = (JIT, expires_at)
TTL = JIT exp - 60s (refresh 1 min before expiry)
```

Cache is **per-agent-per-server-per-scope-set**, ensuring different agents
(and the same agent with different scopes) get distinct tokens.

### Single-Use Enforcement

At the gateway level, the JIT `jti` is tracked:

- First call with a given `jti`: forward, mark as consumed.
- Second call with same `jti`: if token still valid, forward (gateway-level
  caching reuses the same JIT for the same cache key). The MCP server
  enforces single-use if it supports it; the gateway defaults to
  multiple-use-within-TTL for caching.

If strict single-use is required (sensitive operations), the gateway
re-exchanges on every call with a `single_use=true` flag.

### Response Handling

The gateway returns:

```
HTTP/1.1 200 OK
Content-Type: application/json

{ ... MCP server response body ... }
```

- **Only the response body** is returned to the agent.
- All auth-related response headers from the MCP server (e.g.,
  `WWW-Authenticate`) are stripped — the agent cannot see auth metadata.
- Set-Cookie headers are consumed and translated to gateway-side session
  state if needed.

### Error Handling

| Scenario | Gateway Response |
|---|---|
| AIT invalid/expired | 401 `{"error":"ait_invalid"}` — agent must re-attest |
| Policy denies scope | 403 `{"error":"scope_denied"}` — agent receives denial, no token leaves boundary |
| MCP server returns 401 | Gateway attempts token refresh (once). If fails: 401 to agent. |
| MCP server returns 5xx | 502 `{"error":"upstream_error"}` with status code |
| Gateway unavailable | Agent sees connection error — no credential leak |
| mTLS failure | 403 `{"error":"transport_not_authenticated"}` |

## Deployment Model

```
                         ┌─────────────────────────────────┐
Agent Runtime (process)  │   AgentSSO Gateway (sidecar?)   │   MCP Server (remote)
                         │                                  │
   mTLS client cert   ──►├──►  validate cert              │   ^
      + AIT in header     ├──►  validate AIT              │──►│
                         │      exchange AIT→JIT            │   │ Authorization:
                         │      inject Bearer header        │   │ Bearer <jit>
                         │      forward to MCP server       │   │
                         │                                  │   │
                         │  ┌─────────────────────────────┐ │   │
                         │  │ Secret Store (encrypted)    │ │   │
                         │  │ - cached JITs               │ │   │
                         │  │ - per-agent session state   │ │   │
                         │  └─────────────────────────────┘ │   │
                         └──────────────────────────────────┘
```

In v1, the gateway runs as a **standalone service** the agent runtime calls.
Future: can be deployed as a sidecar for lower latency.