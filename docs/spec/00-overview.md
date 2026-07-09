# AgentSSO Specification Overview

## Purpose

AgentSSO is a federated SSO system for AI agents. It provides agents with
short-lived, identity-bound, delegation-chained tokens to access MCP servers
and arbitrary API resources — without ever holding a static secret in LLM
context.

## Problem Statement

Current agent authentication relies on long-lived API keys that:

1. **Live in LLM context** — prompt injection can exfiltrate credentials.
2. **Carry no identity** — no agent identity, no human principal, no delegation chain.
3. **Cannot be scoped per-call** — one key = full account access.
4. **Produce no audit trail** — no binding of "human X authorized agent Y to do Z."
5. **Break the human flow** — agents are forced through a human OAuth-with-browser-popup flow.

## Solution

AgentSSO introduces an **Agent Identity Provider (aIdP)** that sits between
the human's corporate IdP (Okta, Entra ID, Google) and the tools/MCP servers
an agent needs to call. The aIdP:

- Establishes the **human principal** via OIDC inbound federation.
- Verifies **agent runtime attestation** (codebase hash, runtime hash, host signature).
- Issues short-lived **Agent Identity Tokens (AIT)** bound to the human principal via RFC 8693 delegation (`act` claim).
- Exchanges AITs for **per-tool, audience-bound, scope-narrowed JIT tokens** via RFC 8693 token exchange.
- Routes tool calls through a **Credential Boundary Gateway** that injects credentials out-of-context — the LLM never sees a bearer token.

## v1 Scope (In)

| Pillar | Status | Description |
|---|---|---|
| Agent Identity Provider | v1 | Attestation verification + AIT issuance |
| Federated SSO | v1 | RFC 8693 token exchange to MCP servers |
| Credential Boundary Gateway | v1 | Out-of-context credential injection |
| Audit | v1 | Tamper-evident, hash-chained audit log |
| Attestation | v1 | Codebase + runtime hash, continuous re-attestation |
| Policy Engine | v1 | OPA/Rego, least-privilege defaults |
| Enterprise IdP | v1 | OIDC inbound (Okta, Entra, Google) |

## v2 Scope (Out)

| Pillar | Status | Description |
|---|---|---|
| Step-up MFA | v2 | Passkey/WebAuthn for sensitive scopes |
| Verifiable Credentials | v2 | W3C VC for cross-org delegation |
| Agent-to-Agent (A2A) | v2 | Agent-to-agent delegation chaining |
| SCIM | v2 | Automated user provisioning from IdP |
| BYOK/EKM | v2 | Bring-your-own-key for regulated industries |

## Standards Alignment

AgentSSO is built exclusively on existing IETF standards for interoperability:

| RFC | Title | Role in AgentSSO |
|---|---|---|
| RFC 8693 | Token Exchange v2 | Swap AIT → per-tool JIT with `act` delegation |
| RFC 8707 | Resource Indicators | Audience binding per MCP server URI |
| RFC 9068 | JWT Profile for OAuth 2.0 | AIT is a standards-compliant JWT |
| RFC 8414 | AS Metadata | aIdP endpoint discovery |
| RFC 9728 | Protected Resource Metadata | MCP server discovery (unchanged) |
| OAuth 2.1 draft | OAuth 2.1 | Base authorization protocol |
| MCP OAuth 2.1 | MCP Authorization | Compatible with MCP-specified OAuth flow |

No custom protocol formats. Every token is a standard JWT. Every endpoint is
a standard OAuth endpoint. Existing MCP servers work unchanged.

## Design Principles

1. **Zero static secrets** — no API key, no PAT, no long-lived credential is ever issued or stored by the agent.
2. **Identity, not keys** — every token carries `who (human) → what (agent) → why (scope) → where (audience)`.
3. **Credential boundary** — tokens live outside LLM context; the gateway holds and injects them.
4. **Least privilege** — default deny; scopes are policy-approved, not self-asserted.
5. **Short-lived everything** — AIT ≤15 min, JIT ≤10 min, attestation re-checked every N min.
6. **Audit by construction** — every action is logged with principal, agent, scope, tool, timestamp.
7. **Standards-first** — interop with existing OAuth/OIDC/MCP infrastructure, no vendor lock-in.