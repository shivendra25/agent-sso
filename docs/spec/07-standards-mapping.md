# Standards Mapping

This document maps every AgentSSO design decision to its authoritative RFC.

## RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens

| AgentSSO Use | RFC 9068 Ref | Notes |
|---|---|---|
| AIT `typ: at+jwt` | §2.1 | Media type for JWT access tokens |
| AIT standard claims (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `client_id`, `scope`) | §2.2 | Full compliance |
| AIT audience = aIdP token exchange endpoint (not MCP server) | §2.3 | AIT is validated by aIdP, not MCP servers |
| JIT standard claims | §2.2 | JIT is the token MCP servers validate |
| JIT audience = MCP server `resource` URI | §2.3 + RFC 8707 | MCP server must verify `aud` matches itself |
| ES256 signing | §3 | ECDSA P-256 / SHA-256 |
| JWKS publishing | §4 | `/.well-known/jwks.json` |

**Deviation**: AgentSSO adds custom claims (`act`, `cnp`, `rtm`, `ses`, `att_jti`, `tenant`, `ait_jti`). RFC 9068 §2.2 permits additional claims. Custom claim names are short (no prefix) for compactness; collision risk is low because AgentSSO controls both issuer and validator.

## RFC 8693 — OAuth 2.0 Token Exchange

| AgentSSO Use | RFC 8693 Ref | Notes |
|---|---|---|
| Token exchange endpoint | §2 | `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` |
| AIT as `subject_token` | §2.2.2 | Subject token = the agent's AIT |
| `subject_token_type=access_token` | §2.2.3 | AIT is an access token per RFC 9068 |
| `resource` parameter | §3.3 + RFC 8707 | Target MCP server canonical URI |
| `scope` parameter | §2.2.4 | Requested scopes — policy may narrow |
| `act` claim for delegation | §4.3 | Human principal acts on; agent is actor |
| `requested_token_type` | §2.2.1 | Defaults to `access_token` |
| Error response format | §3.2 | Standard OAuth error codes |

**Deviation**: AgentSSO adds `ait_jti` to the JIT to link it back to its
parent AIT for audit. This is an extension claim, not a semantic change.

## RFC 8707 — Resource Indicators for OAuth 2.0

| AgentSSO Use | RFC 8707 Ref | Notes |
|---|---|---|
| `resource` parameter in token exchange | §2 | Required in every token exchange request |
| Canonical URI format | §2 | `https://mcp.example.com` (no trailing slash) |
| JIT `aud` = `resource` value | §3 | Audience bound to specific MCP server |
| MCP server validates `aud` matches itself | §4 | Resource server must reject wrong audience |
| Multiple resources not supported v1 | §5 | One `resource` per exchange request |

## RFC 8414 — OAuth 2.0 Authorization Server Metadata

| AgentSSO Use | RFC 8414 Ref | Notes |
|---|---|---|
| aIdP publishes metadata at `/.well-known/oauth-authorization-server` | §3 | Standard endpoint |
| `issuer`, `token_endpoint`, `jwks_uri` | §2 | Required metadata fields |
| `grant_types_supported` includes token exchange | §2 | Advertises RFC 8693 support |
| `registration_endpoint` for RFC 7591 | §2 | Dynamic client registration |

## RFC 9728 — OAuth 2.0 Protected Resource Metadata

| AgentSSO Use | RFC 9728 Ref | Notes |
|---|---|---|
| MCP servers publish metadata (they already do per MCP spec) | §2 | Gateway consumes this |
| `WWW-Authenticate` header with resource metadata URI | §5.1 | Gateway parses on 401 |
| `authorization_servers` field | §4 | MCP server lists aIdP as trusted AS |
| Gateway validates resource metadata before call | §7 | Discovery before token exchange |

## RFC 7591 — OAuth 2.0 Dynamic Client Registration

| AgentSSO Use | RFC 7591 Ref | Notes |
|---|---|---|
| Agent runtime registers at `/oauth/register` | §3 | Once per host platform |
| No `client_secret` issued (public client) | §3.2.1 | Agent runtime uses attestation, not secrets |
| `client_id` used in AIT/JIT | §3.2.2 | Appears in RFC 9068 `client_id` claim |

## OAuth 2.1 (draft-ietf-oauth-v2-1-13)

| AgentSSO Use | OAuth 2.1 Ref | Notes |
|---|---|---|
| PKCE not needed for AIT (attestation replaces it) | §4.3 | Agent runtime is a public client using attestation |
| Short-lived tokens (≤15 min AIT, ≤10 min JIT) | §7.1.2 | Reduces token theft impact |
| No token in URI query string | §5.1.1 | Always `Authorization` header |
| HTTPS required | §1.5 | All endpoints HTTPS |
| Redirect URI validation | §7.12.2 | Only `localhost` or HTTPS (for OIDC callbacks) |

## MCP OAuth 2.1 Specification (2025-06-18)

| AgentSSO Use | MCP Spec Ref | Notes |
|---|---|---|
| MCP servers as OAuth resource servers | §Authorization/Roles | AgentSSO gateway is the client; MCP server is the resource server |
| RFC 9728 Protected Resource Metadata | §Authorization Server Discovery | MCP servers already implement this |
| RFC 8707 resource parameter | §Resource Parameter | Gateway sends `resource` in every exchange |
| Token audience binding | §Token Audience | MCP server validates JIT `aud` |
| No token passthrough | §Token Passthrough | Gateway exchanges for a new JIT; never passes through the AIT |
| Confused deputy prevention | §Confused Deputy | Each MCP server gets its own audience-bound JIT |

## Summary: No Custom Protocol Innovations

| Aspect | Standard Used |
|---|---|
| Token format | RFC 9068 JWT |
| Delegation | RFC 8693 `act` claim |
| Audience binding | RFC 8707 `resource` parameter |
| AS discovery | RFC 8414 |
| RS discovery | RFC 9728 |
| Client registration | RFC 7591 |
| Base authorization | OAuth 2.1 draft |
| MCP interop | MCP OAuth 2.1 spec |

**Every token is a JWT. Every endpoint is OAuth. Every MCP server works
unchanged.** AgentSSO's innovation is in *how* these standards are composed
for agent-specific semantics — not in inventing new formats.