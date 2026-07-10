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

AgentSSO provides five pillars (v0.1 ships the first five):

1. **Agent Identity Provider (aIdP)** — issues short-lived Agent Identity
   Tokens (AIT) bound to a human principal via RFC 8693 delegation.
2. **Federated SSO to every tool** — RFC 8693 token exchange swaps the AIT for
   audience-bound, scope-narrowed tokens per MCP server. One identity → many
   tools, same promise as enterprise SSO.
3. **Credential Boundary / Tool Gateway** — credentials never enter the LLM
   context; the gateway injects `Authorization` headers out-of-band.
4. **Audit log** — hash-chained, tamper-evident log linking every action to a
   human principal.
5. **Continuous re-attestation** — codebase/runtime drift detection auto-revokes
   AITs on change.
6. *(v2)* Step-up MFA for sensitive scopes (passkey/WebAuthn).
7. *(v2)* Verifiable delegation chain (W3C VC) + agent-to-agent (A2A).

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
├── cmd/                 # service binaries
│   ├── aidp/            # Agent Identity Provider server
│   └── gateway/         # Credential Boundary Gateway server
├── internal/            # private packages
│   ├── attest/          # AIT issuance (attestation + OIDC → AIT)
│   ├── attestation/     # attestation schema, verifier, registry
│   ├── audit/           # hash-chained append-only audit log
│   ├── crypto/          # ES256 keypair, JWKS signer/verifier
│   ├── exchange/        # RFC 8693 token exchange
│   ├── gateway/         # credential boundary reverse proxy
│   ├── idp/             # OIDC inbound connector
│   ├── integration/     # end-to-end integration tests
│   ├── jwt/             # AIT/JIT structs + claim mapping
│   ├── policy/          # policy engine (default-deny scope eval)
│   ├── reattest/        # continuous re-attestation + drift detection
│   ├── registry/        # MCP server registry + RFC 9728 discovery
│   └── server/          # aIdP HTTP routes, metadata, handlers
├── pkg/agent/           # public agent SDK
├── docs/
│   ├── spec/            # AIT/attestation specs, standards mapping
│   ├── threat-model/    # STRIDE threats, mitigations, boundaries
│   └── quickstart.md    # getting started guide
├── policies/            # policy files
└── examples/            # usage examples
```

## Project status

**v0.1.0** — Working prototype with 115 tests passing.

All v1 pillars are implemented and verified by the end-to-end integration
test (`internal/integration/e2e_test.go`), which proves:
- Agent calls MCP server with zero static secrets
- OIDC-federated human identity via RFC 8693 delegation chain
- Audience-bound JIT tokens (RFC 8707)
- Injection-proof credential boundary (no tokens in LLM context)
- Policy engine blocks unauthorized scopes

See [docs/spec/](docs/spec/) for the full design,
[docs/threat-model/](docs/threat-model/) for the threat model, and
[docs/quickstart.md](docs/quickstart.md) to get started.

## Build

```
make build       # build all binaries
make test        # run all tests
make docs-lint   # lint markdown docs
make ci          # full CI pipeline locally
```

## License

Apache-2.0. See [LICENSE](LICENSE).