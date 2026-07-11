export interface ProjectInfo {
  name: string;
  tagline: string;
  version: string;
  repo: string;
  description: string;
}

export interface Stats {
  totalTests: number;
  totalPackages: number;
  totalCommits: number;
  totalSpecDocs: number;
  totalThreats: number;
  coverage: string;
  rfcs: number;
}

export const projectInfo: ProjectInfo = {
  name: "AgentSSO",
  tagline: "Federated SSO for AI agents",
  version: "v0.1.0",
  repo: "https://github.com/shivendra25/agent-sso",
  description:
    "AgentSSO brings the SSO experience humans enjoy to AI agents — zero static secrets, OIDC-federated identity, RFC 8693 delegated tokens, and an injection-proof credential boundary.",
};

export const pillars = [
  {
    id: 1,
    title: "Agent Identity Provider",
    icon: "🔑",
    status: "v0.1",
    description:
      "Issues short-lived Agent Identity Tokens (AIT) bound to a human principal via RFC 8693 delegation. Verifies runtime attestation (codebase + runtime hash).",
    color: "cyan",
  },
  {
    id: 2,
    title: "Federated SSO",
    icon: "🌐",
    status: "v0.1",
    description:
      "RFC 8693 token exchange swaps AIT for audience-bound, scope-narrowed JIT tokens per MCP server. One identity → many tools.",
    color: "blue",
  },
  {
    id: 3,
    title: "Credential Boundary Gateway",
    icon: "🛡️",
    status: "v0.1",
    description:
      "Credentials never enter LLM context. The gateway injects Authorization headers out-of-band. Prompt-injection can't steal what the LLM never had.",
    color: "purple",
  },
  {
    id: 4,
    title: "Audit Log",
    icon: "📜",
    status: "v0.1",
    description:
      "Hash-chained, tamper-evident audit log linking every action to a human principal. Any tamper breaks the SHA-256 chain.",
    color: "amber",
  },
  {
    id: 5,
    title: "Continuous Re-Attestation",
    icon: "🔄",
    status: "v0.1",
    description:
      "Every N minutes, codebase/runtime hashes are re-verified. Drift triggers automatic AIT revocation. ≤15 min of residual access.",
    color: "green",
  },
  {
    id: 6,
    title: "Step-up MFA",
    icon: "🔐",
    status: "v2",
    description:
      "Passkey/WebAuthn step-up for sensitive scopes (deploy, delete, payment). Not in v0.1.",
    color: "red",
  },
];

export const components = [
  {
    name: "internal/crypto",
    file: "internal/crypto/keys.go",
    description:
      "ES256 (ECDSA P-256) keypair generation, JWK encoding (RFC 7517), public key reconstruction, PEM encoding, SHA-256 hashing.",
    tests: 7,
    coverage: 77.8,
    category: "foundation",
  },
  {
    name: "internal/jwt",
    file: "internal/jwt/ait.go",
    description:
      "Agent Identity Token (AIT) and JIT claims structs. RFC 9068 compliant JWT with RFC 8693 act delegation + custom cnp/rtm/ses claims. ES256 signer + verifier.",
    tests: 10,
    coverage: 79.2,
    category: "foundation",
  },
  {
    name: "internal/attestation",
    file: "internal/attestation/types.go",
    description:
      "Attestation document schema (agent_id, codebase_hash, runtime_hash, host_sig). Ed25519 signer, JWS-like serialization, registry, drift detection.",
    tests: 13,
    coverage: 89.7,
    category: "identity",
  },
  {
    name: "internal/idp",
    file: "internal/idp/verifier.go",
    description:
      "OIDC inbound federation. JWKSVerifier validates ID tokens from Okta/Entra/Google. ProviderRegistry for multi-IdP. Principal struct = delegation chain root.",
    tests: 10,
    coverage: 85.5,
    category: "identity",
  },
  {
    name: "internal/attest",
    file: "internal/attest/issuer.go",
    description:
      "AIT issuance flow: verifies attestation + OIDC ID token, builds AIT claims, signs with ES256. POST /v1/attest HTTP handler.",
    tests: 8,
    coverage: 92.6,
    category: "identity",
  },
  {
    name: "internal/exchange",
    file: "internal/exchange/exchanger.go",
    description:
      "RFC 8693 token exchange. Validates AIT, runs policy engine, issues audience-bound JIT (RFC 8707) with inherited act delegation. POST /oauth/token.",
    tests: 14,
    coverage: 92.8,
    category: "federation",
  },
  {
    name: "internal/registry",
    file: "internal/registry/mcp_servers.go",
    description:
      "MCP server registry + RFC 9728 Protected Resource Metadata discovery. Fetches /.well-known/oauth-protected-resource from MCP servers.",
    tests: 8,
    coverage: 90.9,
    category: "federation",
  },
  {
    name: "internal/policy",
    file: "internal/policy/engine.go",
    description:
      "Default-deny policy engine with explicit allow rules, scope intersection/narrowing, wildcard matching. JSON policy loading. v2: full OPA/Rego.",
    tests: 12,
    coverage: 89.5,
    category: "federation",
  },
  {
    name: "internal/gateway",
    file: "internal/gateway/gateway.go",
    description:
      "THE HEADLINE FEATURE: Credential Boundary Gateway. Reverse proxy that exchanges AIT→JIT, injects Authorization out-of-band, strips auth headers from response. LLM never sees a token.",
    tests: 13,
    coverage: 81.0,
    category: "gateway",
  },
  {
    name: "internal/audit",
    file: "internal/audit/audit.go",
    description:
      "Hash-chained, append-only, tamper-evident audit log. SHA-256 chain breaks on any modification. Thread-safe. Event types: AIT_ISSUED, TOKEN_EXCHANGE, DRIFT_DETECTED, etc.",
    tests: 7,
    coverage: 95.0,
    category: "security",
  },
  {
    name: "internal/reattest",
    file: "internal/reattest/manager.go",
    description:
      "Continuous re-attestation manager. Registers active sessions, periodically re-verifies, detects drift, auto-revokes AIT with audit alert.",
    tests: 8,
    coverage: 80.3,
    category: "security",
  },
  {
    name: "internal/server",
    file: "internal/server/server.go",
    description:
      "aIdP HTTP server. JWKS endpoint, RFC 8414 AS metadata, healthz, /v1/attest handler, /oauth/token handler. Structured logging, graceful shutdown.",
    tests: 8,
    coverage: 64.1,
    category: "foundation",
  },
  {
    name: "pkg/agent",
    file: "pkg/agent/client.go",
    description:
      "Agent SDK for Go. Attest() submits attestation+OIDC→AIT. Call() routes through gateway. CallJSON() convenience. GetJWKS(), GetASMetadata() discovery.",
    tests: 10,
    coverage: 82.2,
    category: "sdk",
  },
  {
    name: "internal/integration",
    file: "internal/integration/e2e_test.go",
    description:
      "End-to-end test proving: attest→exchange→gateway→MCP server. Verifies MCP server gets JIT not AIT, response has no tokens, WWW-Authenticate stripped, audience-bound, delegation preserved.",
    tests: 2,
    coverage: 0,
    category: "security",
  },
];

export const tokenFlow = [
  {
    step: 1,
    label: "Human Login",
    actor: "Human",
    description: "Human authenticates via corporate IdP (Okta/Entra/Google) using OIDC. Receives an OIDC ID token.",
    token: "OIDC ID Token",
    tokenColor: "#f59e0b",
  },
  {
    step: 2,
    label: "Agent Attestation",
    actor: "Agent Runtime",
    description: "Agent runtime produces a signed attestation document (codebase hash, runtime hash, host signature) via Ed25519.",
    token: "Attestation Doc",
    tokenColor: "#10b981",
  },
  {
    step: 3,
    label: "AIT Issuance",
    actor: "aIdP",
    description: "aIdP verifies attestation + OIDC ID token. Issues an Agent Identity Token (AIT) — RFC 9068 JWT with act delegation chain. TTL: 15 min.",
    token: "AIT (JWT)",
    tokenColor: "#3b82f6",
  },
  {
    step: 4,
    label: "Token Exchange",
    actor: "Gateway",
    description: "Gateway exchanges AIT for a JIT via RFC 8693. Policy engine narrows scopes. JIT is audience-bound to the MCP server (RFC 8707). TTL: 5 min.",
    token: "JIT (JWT)",
    tokenColor: "#a855f7",
  },
  {
    step: 5,
    label: "Authenticated Call",
    actor: "Gateway → MCP Server",
    description: "Gateway injects Authorization: Bearer <jit> out-of-band. MCP server validates audience + signature. Returns data.",
    token: "Bearer JIT",
    tokenColor: "#06b6d4",
  },
  {
    step: 6,
    label: "Response to Agent",
    actor: "Gateway → Agent",
    description: "Gateway strips all auth headers, returns ONLY the response body. LLM context never contained a bearer token. Injection-proof.",
    token: "Data Only",
    tokenColor: "#60a5fa",
  },
];

export const securityProperties = [
  {
    title: "Zero Static Secrets",
    icon: "🚫",
    description: "No API keys, no PATs, no long-lived credentials. AIT ≤15 min, JIT ≤5 min. Statelessness via JWKS.",
    proof: "AIT/JIT are short-lived JWTs verified statelessly. No secret is ever stored in the database.",
  },
  {
    title: "Injection-Proof",
    icon: "💉",
    description: "Prompt-injection cannot exfiltrate credentials because the LLM context never contains a bearer token.",
    proof: "E2E test verifies: response body contains no tokens, WWW-Authenticate stripped, AIT never passed to MCP server.",
  },
  {
    title: "Delegation Chain",
    icon: "🔗",
    description: "Every token carries act.sub (human principal). MCP servers and audit logs see who authorized each action.",
    proof: "JIT act.sub == 'oidc:okta:user-001' — inherited verbatim from AIT per RFC 8693 §4.3.",
  },
  {
    title: "Audience-Bound",
    icon: "🎯",
    description: "JIT aud = MCP server URL. A token for GitHub cannot be used for Slack. RFC 8707 compliant.",
    proof: "E2E test verifies JIT audience == MCP server URL. Token passthrough forbidden by spec.",
  },
  {
    title: "Policy-Enforced",
    icon: "⚖️",
    description: "Default-deny policy engine. Scopes are policy-approved, never self-asserted. Least-privilege defaults.",
    proof: "TestEndToEndPolicyDenial: agent requests github:admin:delete → policy narrows to empty → 403.",
  },
  {
    title: "Drift-Detecting",
    icon: "🔄",
    description: "Continuous re-attestation every 5 min. Codebase/runtime change → AIT revoked. ≤15 min residual.",
    proof: "reattest.Manager.VerifyDrift detects codebase/runtime hash change → Revokes AIT + logs DRIFT_DETECTED.",
  },
  {
    title: "Audit-Traceable",
    icon: "📜",
    description: "Hash-chained append-only log. Every action links (principal, agent, scope, tool, jti, timestamp).",
    proof: "audit.MemoryLogger.Verify() recomputes SHA-256 chain. Any tamper breaks all subsequent hashes.",
  },
  {
    title: "Standards-First",
    icon: "📋",
    description: "RFC 8693, 8707, 9068, 8414, 9728, 7591, OAuth 2.1, MCP OAuth 2.1. No custom protocol formats.",
    proof: "07-standards-mapping.md maps every claim and endpoint to its authorittitative RFC.",
  },
];

export const rfcMapping = [
  { rfc: "RFC 9068", title: "JWT Profile for OAuth 2.0", role: "AIT/JIT are RFC 9068-compliant JWT access tokens", icon: "📄" },
  { rfc: "RFC 8693", title: "Token Exchange v2", role: "Swap AIT → per-tool JIT with act delegation chain", icon: "🔄" },
  { rfc: "RFC 8707", title: "Resource Indicators", role: "Audience-bound tokens per MCP server URI", icon: "🎯" },
  { rfc: "RFC 8414", title: "AS Metadata", role: "aIdP advertises endpoints via /.well-known/oauth-authorization-server", icon: "📡" },
  { rfc: "RFC 9728", title: "Protected Resource Metadata", role: "MCP servers discovered unchanged via /.well-known/oauth-protected-resource", icon: "🔍" },
  { rfc: "RFC 7591", title: "Dynamic Client Registration", role: "Agent runtimes register without manual setup", icon: "📝" },
  { rfc: "OAuth 2.1", title: "Base Authorization Protocol", role: "Aligned with MCP OAuth 2.1 spec (2025-06-18)", icon: "⚙️" },
];

export const threatModel = [
  {
    id: "T1",
    title: "Prompt Injection Credential Exfiltration",
    severity: "Critical",
    icon: "💉",
    mitigation: "Credential Boundary — tokens live in gateway secret store, LLM context never has a bearer",
    status: "mitigated",
  },
  {
    id: "T2",
    title: "Token Theft at Rest",
    severity: "High",
    icon: "💾",
    mitigation: "No secrets stored (stateless JWTs), encrypted cache, replay cache stores only jti UUIDs",
    status: "mitigated",
  },
  {
    id: "T3",
    title: "Confused Deputy",
    severity: "High",
    icon: "🎭",
    mitigation: "RFC 8707 audience binding, token passthrough forbidden, server registry",
    status: "mitigated",
  },
  {
    id: "T4",
    title: "Replay Attack",
    severity: "High",
    icon: "🔁",
    mitigation: "jti replay cache + single-use JIT, short TTL, HTTPS, no tokens in logs",
    status: "mitigated",
  },
  {
    id: "T5",
    title: "Privilege Escalation via Scope Overgrant",
    severity: "High",
    icon: "⬆️",
    mitigation: "OPA default-deny + scope narrowing, no self-assertion, least-privilege defaults",
    status: "mitigated",
  },
  {
    id: "T6",
    title: "Codebase/Runtime Drift",
    severity: "High",
    icon: "🔄",
    mitigation: "Continuous re-attestation (5 min), drift detection auto-revokes AIT",
    status: "mitigated",
  },
  {
    id: "T7",
    title: "Stolen Attestation Key",
    severity: "Medium",
    icon: "🗝️",
    mitigation: "Key registry + rotation + binding, codebase pinning, attestation TTL",
    status: "mitigated",
  },
  {
    id: "T8",
    title: "DoS via Rate Limit Exhaustion",
    severity: "Medium",
    icon: "📊",
    mitigation: "Per-agent/principal/tenant rate limits, circuit breaker, exponential backoff",
    status: "planned",
  },
  {
    id: "T9",
    title: "Audit Log Tampering",
    severity: "High",
    icon: "📜",
    mitigation: "Hash-chained append-only log, no UPDATE/DELETE, external hash head (v2)",
    status: "mitigated",
  },
  {
    id: "T10",
    title: "Tenant Isolation Failure",
    severity: "Critical",
    icon: "🏢",
    mitigation: "Postgres RLS + tenant claim in every token, WHERE clause defense-in-depth",
    status: "planned",
  },
];

export const stats = {
  totalTests: 115,
  totalPackages: 15,
  totalCommits: 15,
  totalSpecDocs: 8,
  totalThreats: 10,
  coverage: "77-95%",
  rfcs: 7,
};

export const aitClaims = [
  { name: "iss", type: "string", rfc: "RFC 9068", description: "aIdP issuer URL", example: "https://aidp.agentsso.io" },
  { name: "sub", type: "string", rfc: "RFC 9068", description: "Agent identity (stable UUID)", example: "a:f3b7c1e2-..." },
  { name: "aud", type: "string", rfc: "RFC 9068", description: "Target = aIdP token exchange endpoint", example: "https://aidp.agentsso.io/oauth/token" },
  { name: "exp", type: "int64", rfc: "RFC 9068", description: "Expiration (≤15 min from iat)", example: "1752280800" },
  { name: "iat", type: "int64", rfc: "RFC 9068", description: "Issued at", example: "1752279900" },
  { name: "nbf", type: "int64", rfc: "RFC 9068", description: "Not before", example: "1752279900" },
  { name: "jti", type: "string", rfc: "RFC 9068", description: "Unique token ID (replay detection)", example: "01HXYZ..." },
  { name: "client_id", type: "string", rfc: "RFC 9068", description: "Agent runtime's registered client_id", example: "agent-runtime-prod-1" },
  { name: "scope", type: "string", rfc: "RFC 9068", description: "Meta-scopes only: agent:attest tools:exchange", example: "agent:attest tools:exchange" },
  { name: "act", type: "object", rfc: "RFC 8693", description: "Delegated-from human principal", example: "{sub, iss, delegation_id}", isCustom: false, isHighlight: true },
  { name: "cnp", type: "string", rfc: "Custom", description: "Codebase hash (git tree SHA)", example: "sha256:abc123...", isCustom: true },
  { name: "rtm", type: "string", rfc: "Custom", description: "Runtime hash (version + builder)", example: "sha256:def456...", isCustom: true },
  { name: "ses", type: "string", rfc: "Custom", description: "Agent session ID", example: "ses_9a2b...", isCustom: true },
  { name: "att_jti", type: "string", rfc: "Custom", description: "Links AIT to attestation document", example: "att_3f1c...", isCustom: true },
  { name: "tenant", type: "string", rfc: "Custom", description: "Tenant ID for multi-tenant isolation", example: "tnt_acme", isCustom: true },
];