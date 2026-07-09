# AgentSSO

> Federated SSO for AI agents. Zero static secrets. OIDC-federated. Injection-proof credential boundary. RFC 8693 delegated tokens.

[![CI](https://github.com/shivendra25/agent-sso/actions/workflows/ci.yml/badge.svg)](https://github.com/shivendra25/agent-sso/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## What is AgentSSO?

AgentSSO brings the SSO experience humans enjoy to **AI agents**. Instead of
copying the human OAuth-with-a-popup flow, AgentSSO provides a purpose-built
identity layer for non-human principals that act **on behalf of a human**.

### The problem

Agents today authenticate with long-lived static API keys that:

- Live in `.env` files and LLM context (prompt-injection exfiltration risk).
- Carry no identity, no principal, no delegation chain.
- Cannot be scoped per-call or revoked per-action.
- Produce no audit trail tying a human to an agent action.

### The solution

AgentSSO provides five pillars (v1 ships the first three):

1. **Agent Identity Provider (aIdP)** — issues short-lived Agent Identity
   Tokens (AIT) bound to a human principal via RFC 8693 delegation.
2. **Federated SSO to every tool** — RFC 8693 token exchange swaps the AIT for
   audience-bound, scope-narrowed tokens per MCP server. One identity → many
   tools, same promise as enterprise SSO.
3. **Credential Boundary / Tool Gateway** — credentials never enter the LLM
   context; the gateway injects `Authorization` headers out-of-band.
4. *(v2)* Step-up MFA for sensitive scopes (passkey/WebAuthn).
5. *(v2)* Verifiable delegation chain + tamper-evident audit.

### Standards-first

AgentSSO is built on existing IETF standards for interoperability:

| Standard | Role in AgentSSO |
|---|---|
| RFC 8693 (Token Exchange) | Swap AIT → per-tool JIT tokens with `act` delegation chain |
| RFC 8707 (Resource Indicators) | Audience-bound tokens per MCP server URI |
| RFC 9068 (JWT Profile) | AIT is a standards-compliant JWT access token |
| RFC 8414 (AS Metadata) | aIdP advertises endpoints via standard discovery |
| RFC 9728 (Protected Resource Metadata) | MCP servers discovered unchanged |
| RFC 7591 (Dynamic Client Registration) | Agent runtimes register without manual setup |
| OAuth 2.1 draft | Base authorization protocol (aligned with MCP OAuth 2.1) |

## Repository layout

```
agent-sso/
├── cmd/                 # service binaries (aidp, gateway, admin)
├── internal/            # private packages
│   ├── attestation/     # attestation schema + verifier
│   ├── audit/           # hash-chained append-only audit log
│   ├── crypto/          # ES256 keypair, JWKS signer/verifier
│   ├── idp/             # OIDC inbound connector
│   ├── jwt/             # AIT struct + claim mapping
│   ├── policy/          # OPA/Rego policy engine
│   ├── registry/        # agent runtime + MCP server registries
│   └── server/          # HTTP routes, metadata, handlers
├── pkg/                 # public packages (agent SDK)
├── docs/
│   ├── spec/            # AIT/attestation specs, standards mapping
│   └── threat-model/    # STRIDE threats, mitigations, boundaries
├── policies/            # Rego policy files
├── examples/            # usage examples
├── scripts/             # dev/build helpers
└── deploy/              # Docker, k8s manifests
```

## Project status

**Phase 0 (current)** — Spec & threat model.

See [docs/spec/](docs/spec/) for the full design and
[docs/threat-model/](docs/threat-model/) for the threat model.

## Build

```
make build       # build all binaries
make test        # run all tests
make docs-lint   # lint markdown docs
make ci          # full CI pipeline locally
```

## License

Apache-2.0. See [LICENSE](LICENSE).