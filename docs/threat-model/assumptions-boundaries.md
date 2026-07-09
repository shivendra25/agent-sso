# AgentSSO Threat Model — Assumptions & Boundaries

## Assumptions

### A1: Agent Runtime Process Integrity

AgentSSO assumes the agent runtime **process** (e.g., the opencode binary) is
trusted, even though the **LLM context** within that process is not. This is
the core trust boundary:

```
TRUSTED: agent runtime process (holds AIT in memory, performs mTLS)
UNTRUSTED: LLM context (generates tool calls, processes responses)
```

If the runtime process is fully compromised (shell access, memory dump), the
AIT can be extracted. AgentSSO mitigates this with short TTLs and replay
protection but does not protect against full process compromise — that is
the operating system's responsibility.

### A2: Corporate IdP Trust

AgentSSO trusts the corporate IdP (Okta, Entra, Google) for:

- Human principal identity (`sub` claim in OIDC ID token).
- Human principal attributes (email, groups — used for policy decisions).
- Human authentication (password, MFA, SSO).

AgentSSO does not re-authenticate the human; it federates the IdP's
authentication result via OIDC.

### A3: Hosting Platform Attestation

AgentSSO trusts the attestation key of the hosting platform (e.g., the
server/cloud instance running the agent runtime). If the hosting platform is
compromised, attestation can be forged. This is mitigated by:

- Key rotation.
- Codebase pinning (only specific git commits are allowed).
- Multi-platform attestation (v2: support for trusted execution environments).

### A4: Network Security

AgentSSO assumes HTTPS (TLS 1.3) for all external communication and mTLS
for agent-runtime-to-gateway communication. It does not protect against:

- TLS-stripping attacks (mitigated by HSTS on all endpoints).
- Certificate authority compromise (mitigated by cert pinning in v2).
- DNS spoofing (mitigated by DoH/DoT resolution in v2).

### A5: Database Integrity

AgentSSO assumes the Postgres database is trusted for data storage. A
database admin with full access can truncate the audit log (mitigated by
hash-chain external publication in v2).

## Scope Boundaries

### In Scope (v1)

| Area | Covered |
|---|---|
| Agent identity | AIT issuance with attestation verification |
| Human delegation | OIDC inbound, act claim chain |
| Token federation | RFC 8693 token exchange to MCP servers |
| Credential boundary | Gateway with out-of-context injection |
| Replay prevention | jti cache, single-use JIT |
| Scope policy | OPA/Rego, default deny |
| Drift detection | Continuous re-attestation |
| Audit | Hash-chained append-only log |
| Tenant isolation | Postgres RLS |
| MCP interop | RFC 9728 discovery, RFC 8707 audience |

### Out of Scope (v1)

| Area | Rationale | v2 |
|---|---|---|
| Step-up MFA for sensitive scopes | v1 relies on policy deny for sensitive scopes | Passkey/WebAuthn step-up |
| Verifiable Credentials (W3C VC) | Not needed for single-org v1 | Cross-org delegation |
| Agent-to-agent delegation | v1 is human→agent only | A2A protocol |
| SCIM provisioning | Manual registration acceptable for v1 | SCIM from IdP |
| BYOK/EKM | Enterprise customers only | KMS integration |
| Trusted execution (TEE) | Overkill for v1 launch | Intel SGX / AWS Nitro |
| Policy UI | v1 uses Rego files + admin API | Visual policy builder |
| Multi-region HA | v1 single-region | Active-active multi-region |

## Attack Surface Inventory

### Exposed Endpoints (aIdP)

| Endpoint | Auth | Rate Limited |
|---|---|---|
| `/.well-known/oauth-authorization-server` | None | No |
| `/.well-known/jwks.json` | None | No |
| `POST /v1/attest` | Attestation doc | Yes |
| `POST /v1/reattest` | AIT (Bearer) | Yes |
| `POST /oauth/token` | AIT (Bearer) | Yes |
| `POST /oauth/register` | None (RFC 7591) | Yes |
| `POST /oauth/revoke` | AIT (Bearer) | Yes |
| `POST /oauth/introspect` | Client credentials | Yes |
| `/login/oidc/{provider}` | None | Yes |
| `/callback/oidc/{provider}` | Session state | Yes |

### Exposed Endpoints (Gateway)

| Endpoint | Auth | Rate Limited |
|---|---|---|
| `POST /v1/call/{alias}/*` | AIT (X-AIT header) + mTLS | Yes |
| `GET /healthz` | None | No |

### Internal Interfaces

| Interface | Auth |
|---|---|
| aIdP ↔ Postgres | pgx connection, TLS, RLS |
| aIdP ↔ OPA | In-process (no network) |
| Gateway ↔ aIdP (token exchange) | HTTPS, service-to-service mTLS |
| Gateway ↔ MCP servers | JIT (Bearer) over HTTPS |