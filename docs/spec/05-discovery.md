# Discovery (RFC 8414 / RFC 9728)

## Overview

AgentSSO uses standard OAuth/OIDC discovery mechanisms so that **existing MCP
servers and OAuth clients work unchanged**. The aIdP publishes its metadata
via RFC 8414, and the AgentSSO gateway consumes RFC 9728 Protected Resource
Metadata from MCP servers to discover their authorization requirements.

## aIdP: RFC 8414 Authorization Server Metadata

### Endpoint

```
GET /.well-known/oauth-authorization-server
```

### Response

```json
{
  "issuer": "https://aidp.agentsso.io",
  "token_endpoint": "https://aidp.agentsso.io/oauth/token",
  "jwks_uri": "https://aidp.agentsso.io/.well-known/jwks.json",
  "registration_endpoint": "https://aidp.agentsso.io/oauth/register",
  "response_types_supported": ["token"],
  "grant_types_supported": [
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
  "revocation_endpoint": "https://aidp.agentsso.io/oauth/revoke",
  "introspection_endpoint": "https://aidp.agentsso.io/oauth/introspect",
  "scopes_supported": [
    "agent:attest",
    "tools:exchange"
  ],
  "resource_documentation": "https://aidp.agentsso.io/docs/spec/05-discovery.md"
}
```

This tells any OAuth-compatible client: "I am an authorization server that
supports token exchange, here is my JWKS, here is my dynamic registration
endpoint."

## aIdP: JWKS Endpoint

### Endpoint

```
GET /.well-known/jwks.json
```

### Response

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "kid": "2026-07-01-key-1",
      "alg": "ES256",
      "x": "base64url-coordinate-x",
      "y": "base64url-coordinate-y"
    }
  ]
}
```

Standard RFC 7517 JWKS. MCP servers and the gateway use this to verify AIT/JIT
signatures.

## aIdP: Dynamic Client Registration (RFC 7591)

### Endpoint

```
POST /oauth/register
Content-Type: application/json
```

Agent runtimes register once (per host platform) to obtain a `client_id`.
No `client_secret` is issued (public client — agent runtime has no secure
storage for a secret; it uses attestation instead).

### Request

```json
{
  "client_name": "opencode-runtime-host-001",
  "token_endpoint_auth_method": "none",
  "grant_types": ["urn:ietf:params:oauth:grant-type:token-exchange"],
  "response_types": ["token"]
}
```

### Response

```json
{
  "client_id": "agent-runtime-prod-1",
  "client_name": "opencode-runtime-host-001",
  "token_endpoint_auth_method": "none",
  "client_id_issued_at": 1752279900
}
```

## MCP Server Discovery (RFC 9728)

MCP servers that implement the MCP OAuth 2.1 spec already publish **RFC 9728
Protected Resource Metadata** at:

```
GET /.well-known/oauth-protected-resource
```

This document tells the AgentSSO gateway:

- Which authorization server(s) the MCP server trusts.
- What scopes are required.
- What the canonical resource URI is (for RFC 8707 `resource` parameter).

### Example MCP Server Protected Resource Metadata

```json
{
  "resource": "https://mcp.github.example.com",
  "authorization_servers": ["https://aidp.agentsso.io"],
  "scopes_supported": ["github:prs:read", "github:prs:write"],
  "bearer_methods_supported": ["header"]
}
```

### Gateway Discovery Flow

```
Gateway                      MCP Server           Registry (aIdP)
   │                              │                      │
   │  1. resolve server_alias      │                      │
   │  ──────────────────────────────────────────────────►│
   │  ◄──server_config (base_url) │                      │
   │                              │                      │
   │  2. GET /.well-known/oauth-protected-resource        │
   │  ──────────────────────────►│                      │
   │  ◄──resource metadata       │                      │
   │                              │                      │
   │  3. Extract authorization_servers[]                 │
   │  4. Confirm aIdP is in list  │                      │
   │                              │                      │
   │  5. Exchange AIT for JIT     │                      │
   │  (see 04-token-exchange.md)  │                      │
   │                              │                      │
   │  6. Call MCP server with JIT │                      │
   │  Authorization: Bearer <jit> │                      │
   │  ──────────────────────────►│                      │
   │  ◄──MCP response            │                      │
   │                              │                      │
```

## AgentSSO Server Registry

For MCP servers that do **not** implement RFC 9728 (non-compliant or custom
servers), AgentSSO maintains its own server registry:

```
mcp_servers:
  tenant_id       | text
  server_alias    | text      -- "github", "slack", "jira"
  server_url      | text      -- canonical URI (RFC 8707)
  auth_server     | text      -- aIdP issuer (always AgentSSO aIdP in v1)
  required_scopes | text[]    -- scopes this server accepts
  rfc9728_enabled | boolean   -- whether server self-publishes metadata
  created_at      | timestamptz
```

When `rfc9728_enabled` is true, the gateway uses the server's own metadata.
When false, the gateway uses the registry's `server_url` and `required_scopes`
as the fallback resource metadata.