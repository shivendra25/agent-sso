import { SectionHeader } from "./Sidebar";

export function Architecture() {
  return (
    <div>
      <SectionHeader
        icon="🏗️"
        title="System Architecture"
        subtitle="The complete component diagram showing trust boundaries, data flow, and the credential boundary that separates the LLM from credentials."
      />

      <div className="card p-6 overflow-x-auto">
        <div className="text-xs font-mono text-gray-400 mb-6">
          <div className="flex justify-center gap-4 mb-6">
            <Legend color="#10b981" label="Trusted" />
            <Legend color="#ef4444" label="Untrusted (LLM)" />
            <Legend color="#3b82f6" label="Internal Link" />
            <Legend color="#a855f7" label="Token Exchange" />
          </div>

          <pre className="text-[11px] leading-relaxed text-center">
{`                         ┌─────────────────────────────────────────────┐
                         │              AgentSSO Control Plane          │
                         │                                               │
    ┌────────────┐       │  ┌─────────┐  ┌──────────┐  ┌────────────┐  │
    │  Human     │───────┼─►│  aIdP   │  │  Policy  │  │   Audit    │  │
    │ (principal)│ OIDC  │  │  (IdP)  │──│  (OPA)   │  │   Log      │  │
    │  Okta/Entra│ ────► │  │         │  └──────────┘  └────────────┘  │
    └────────────┘       │  │         │                                   │
                         │  │  ┌──────┴────────┐                         │
    ┌────────────┐       │  │  │  Token       │                         │
    │  Agent      │ att. │  │  │  Exchange     │                         │
    │  Runtime    │─────►│  │  │  (RFC 8693)  │                         │
    │ (opencode)  │      │  │  └──────┬───────┘                         │
    │             │      │  └─────────┼──────────────────────────────────┘
    │  tool call  │      │            │ JIT token (out-of-context)
    │             │      │            ▼
    │             │      │  ┌─────────────────────┐
    └──────┬──────┘      │  │ Credential Boundary  │
           │             │  │   Tool Gateway       │
           │ tool call   │  │                       │
           └─────────────┼─►│  injects:            │
                         │  │  Authorization:       │
                         │  │    Bearer <jit>      │
                         │  └──────────┬───────────┘
                         │             │
                         └─────────────┼──────────────────────────────
                                       │ authenticated request
                                       ▼
                              ┌─────────────────┐
                              │  MCP Server     │
                              │  (RFC 9728      │
                              │   resource)     │
                              │  — unchanged    │
                              └─────────────────┘`}
          </pre>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
        <BoundaryCard
          title="Trust Boundary 1: LLM ↔ Runtime"
          description="The LLM context (prompt, completions) is untrusted. The agent runtime process (holds AIT in memory) is trusted. This is the core boundary."
          status="critical"
        />
        <BoundaryCard
          title="Trust Boundary 2: Runtime ↔ Gateway"
          description="Agent runtime calls gateway via mTLS. Runtime attestation = the authentication. No shared secrets."
          status="high"
        />
        <BoundaryCard
          title="Trust Boundary 3: Gateway ↔ MCP Server"
          description="Gateway injects JIT via Authorization: Bearer header over HTTPS. MCP server validates audience (RFC 8707)."
          status="high"
        />
      </div>

      <div className="mt-6 p-5 rounded-xl bg-surface-50/50 border border-surface-300">
        <h4 className="text-sm font-semibold text-brand-400 mb-3 flex items-center gap-2">
          <span>📁</span> Technology Stack
        </h4>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
          <StackItem name="Language" value="Go 1.26" />
          <StackItem name="Database" value="PostgreSQL 16" />
          <StackItem name="Policy" value="OPA / Rego" />
          <StackItem name="HTTP" value="net/http" />
          <StackItem name="OIDC" value="coreos/go-oidc" />
          <StackItem name="Crypto" value="ES256 (ECDSA P-256)" />
          <StackItem name="Attestation" value="Ed25519" />
          <StackItem name="JWT" value="RFC 9068" />
        </div>
      </div>
    </div>
  );
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className="w-3 h-3 rounded" style={{ backgroundColor: color }} />
      <span className="text-xs text-gray-500">{label}</span>
    </div>
  );
}

function BoundaryCard({ title, description, status }: { title: string; description: string; status: string }) {
  const statusColor = status === "critical" ? "accent-red" : status === "high" ? "accent-amber" : "accent-green";
  return (
    <div className="card p-5">
      <div className="flex items-center gap-2 mb-2">
        <div className={`w-2 h-2 rounded-full bg-${statusColor} animate-pulse`} />
        <h4 className="text-sm font-semibold text-gray-200">{title}</h4>
      </div>
      <p className="text-xs text-gray-500 leading-relaxed">{description}</p>
    </div>
  );
}

function StackItem({ name, value }: { name: string; value: string }) {
  return (
    <div className="px-3 py-2 rounded-lg bg-surface-100 border border-surface-300">
      <div className="text-xs text-gray-500">{name}</div>
      <div className="text-sm text-gray-200 font-mono">{value}</div>
    </div>
  );
}