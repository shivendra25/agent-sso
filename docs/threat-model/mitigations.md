# AgentSSO Threat Model — Mitigations Summary

This document provides a concise mapping of each threat to its controls.

## Mitigation Matrix

| ID | Threat | Primary Control | Secondary Controls |
|---|---|---|---|
| T1 | Prompt injection exfiltration | Credential boundary (tokens outside LLM ctx) | Short TTL, gateway strips auth headers |
| T2 | Token theft at rest | No secrets stored (stateless JWTs) | Encrypted cache, replay cache stores only jti |
| T3 | Confused deputy | RFC 8707 audience binding | Token passthrough forbidden, server registry |
| T4 | Replay attack | jti replay cache + single-use JIT | Short TTL, HTTPS, no tokens in logs |
| T5 | Privilege escalation | OPA default-deny + scope narrowing | Policy audit, dry-run mode, suppress silent deny |
| T6 | Codebase/runtime drift | Continuous re-attestation (every 5 min) | Short AIT TTL, jti blocklist on drift |
| T7 | Stolen attestation key | Key registry + rotation + binding | Codebase pinning, attestation TTL |
| T8 | DoS via rate exhaustion | Per-agent/principal/tenant rate limits | Circuit breaker, exponential backoff |
| T9 | Audit log tampering | Hash-chained append-only log | No UPDATE/DELETE, external hash head (v2) |
| T10 | Tenant isolation failure | Postgres RLS + tenant claim in every token | WHERE clause defense-in-depth, integration tests |

## Control Inventory

### Credential Boundary (Gateway)

The single most impactful control. By design, **the LLM context never
contains a bearer token**. This defeats the highest-severity threat (T1) by
construction, not by configuration.

- **What it does**: holds JIT tokens in an encrypted secret store, injects
  `Authorization` headers at the network layer, strips auth headers from
  responses.
- **What it doesn't do**: return tokens to the agent, log tokens, expose
  token endpoints to the LLM.

### Short-Lived, Stateless Tokens

All tokens are JWTs with aggressive TTLs:

| Token | TTL | Storage |
|---|---|---|
| AIT | ≤15 min | Agent runtime memory only (never persisted) |
| JIT | ≤10 min | Gateway encrypted cache (never persisted to DB) |
| Attestation | ≤15 min | Ephemeral (re-issued on re-attestation) |

Stateless verification via JWKS means no database lookup is needed to
validate a token — reducing the attack surface of the verification path.

### Replay Prevention

Every token has a unique `jti` (UUID). The aIdP maintains a replay cache
(Redis or in-memory) that tracks:

- AIT `jti` values — consumed at token exchange, blocked if reused.
- JIT `jti` values — consumed at gateway call, blocked if reused.
- Drift-blocklisted `jti` values — AITs revoked due to drift.

Cache TTL = token TTL + 5 min grace period. After that, the entry is evicted
(the token is expired anyway).

### Policy Engine (OPA/Rego)

```rego
package agentsso.policy

default allow = false

allow {
  input.agent_id == registered_agent
  input.principal == delegated_principal
  input.scope == granted_scope
  input.resource == registered_resource
  input.scope in data.allowed_scopes[input.agent_id][input.resource]
}
```

- **Default deny**: `default allow = false`
- **Scope narrowing**: policy returns the intersection of requested and allowed scopes.
- **Per-tenant**: policies are namespaced by tenant.
- **Auditable**: every decision logs which rule fired.

### Continuous Attestation

A background worker in the aIdP:

1. Every 5 min, selects all active AITs.
2. For each, requests re-attestation from the agent runtime.
3. Compares new `codebase_hash` and `runtime_hash` to the original.
4. On match: refresh AIT (new `jti`, extended `exp`).
5. On mismatch: blocklist `jti`, log `DRIFT_DETECTED`, alert admin.

### Audit Chain

```
entry_1: (..., prev_hash=SHA256(""), this_hash=SHA256(entry_1_data + prev_hash))
entry_2: (..., prev_hash=entry_1.this_hash, this_hash=SHA256(entry_2_data + prev_hash))
entry_3: (..., prev_hash=entry_2.this_hash, this_hash=SHA256(entry_3_data + prev_hash))
```

Verification: recompute all hashes from entry_1 forward. Any modification to
an entry changes its `this_hash`, which breaks the chain for all subsequent
entries.

### Transport Security

- **All endpoints HTTPS** (OAuth 2.1 §1.5 requirement).
- **mTLS** between agent runtime and gateway (client cert bound to agent_id).
- **No token in URI** query string (always `Authorization` header).
- **No redirect with token** in fragment (token exchange uses back-channel only).

## v1 Limitations (Accepted Risks)

| Risk | v1 Mitigation | v2 Plan |
|---|---|---|
| Gateway cache is in-memory | Encrypted, ≤10 min TTL, process isolation | KMS-backed encryption |
| No step-up MFA | Sensitive scopes require explicit policy allow | Passkey/WebAuthn step-up |
| No SCIM | Manual principal registration | SCIM from Okta/Entra |
| Audit hash head not external | Hash chain is verifiable internally only | Publish hash head to external log |
| Rate limits in-process | Sufficient for v1 scale | Distributed rate limiting (Redis) |