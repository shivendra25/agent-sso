# AgentSSO Quickstart

This guide walks through running a complete AgentSSO flow: attestation,
AIT issuance, token exchange, and injection-proof tool calls.

## Prerequisites

- Go 1.26+
- An AgentSSO aIdP instance running
- An AgentSSO Gateway instance running
- At least one MCP server registered in the gateway

## 1. Start the aIdP

```bash
go run ./cmd/aidp --addr :8443
```

The aIdP exposes:
- `/.well-known/oauth-authorization-server` (RFC 8414 metadata)
- `/.well-known/jwks.json` (signing keys)
- `POST /v1/attest` (AIT issuance)
- `POST /oauth/token` (RFC 8693 token exchange)

## 2. Start the Gateway

```bash
go run ./cmd/gateway --addr :8444 --aidp-url http://localhost:8443
```

Register MCP servers via the `AGENTSSO_MCP_SERVERS` environment variable:

```bash
export AGENTSSO_MCP_SERVERS='[
  {
    "tenant_id": "tnt_acme",
    "server_alias": "github",
    "server_url": "https://mcp.github.example.com",
    "auth_server": "http://localhost:8443",
    "required_scopes": ["github:read"],
    "rfc9728_enabled": false
  }
]'
```

## 3. Use the Agent SDK

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/shivendra25/agent-sso/pkg/agent"
)

func main() {
    client := agent.New(agent.Config{
        AIdPURL:    "http://localhost:8443",
        GatewayURL: "http://localhost:8444",
        TenantID:   "tnt_acme",
    })

    ctx := context.Background()

    // Attest: agent runtime signs attestation doc, human provides OIDC token
    ait, err := client.Attest(ctx, "signed-attestation", "oidc-id-token", "okta")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("AIT issued: agent=%s, principal=%s\n", ait.AgentID, ait.PrincipalSub)

    // Call: gateway injects JIT out-of-band — LLM never sees a token
    result, err := client.Call(ctx, ait.AIT, "github", "v1/prs/42", "GET", nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Response: %s\n", result.Body)
}
```

## 4. Run the integration test

```bash
go test ./internal/integration/ -v
```

This test proves the complete flow end-to-end, verifying:
- AIT is issued with correct claims (agent identity, delegation chain, attestation hash)
- JIT is audience-bound to the MCP server (RFC 8707)
- Delegation chain (`act.sub`) is preserved from AIT to JIT
- MCP server receives a JIT, never the AIT (no token passthrough)
- Response body contains no tokens (injection-proof)
- WWW-Authenticate headers are stripped from responses
- Policy engine blocks unauthorized scopes

## Architecture summary

```
Human (Okta OIDC)
  │
  ▼
Agent Runtime ──attest──► aIdP ──AIT──► Agent Runtime (memory)
                                ▲
                                │
Agent Runtime ──call──► Gateway ──token exchange──► aIdP
                           │                          │
                           │◄──JIT────────────────────┘
                           │
                           ├──Authorization: Bearer <jit>──► MCP Server
                           │◄──response data──────────────────┘
                           │
                           ▼
                    Agent Runtime (LLM context: data only, NO tokens)
```

## Security properties

| Property | How |
|---|---|
| Zero static secrets | AIT is short-lived (15 min), JIT is short-lived (5 min), no API keys |
| Injection-proof | Tokens live in gateway secret store, LLM context never sees a bearer |
| Delegation chain | Every token carries `act.sub` (human principal) via RFC 8693 |
| Audience-bound | JIT `aud` = MCP server URL (RFC 8707) |
| Policy-enforced | OPA/Rego policy narrows scopes per (agent, principal, resource) |
| Drift-detecting | Continuous re-attestation revokes AIT on codebase/runtime change |
| Audit-traceable | Hash-chained log links every action to a human principal |