import { rfcMapping } from "../data";
import { SectionHeader } from "./Sidebar";

export function RFCMapping() {
  return (
    <div>
      <SectionHeader
        icon="📋"
        title="Standards Alignment"
        subtitle="AgentSSO is built exclusively on existing IETF standards. No custom protocol formats. Every token is a JWT; every endpoint is OAuth."
      />

      <div className="space-y-3">
        {rfcMapping.map((rfc, idx) => (
          <div key={idx} className="card p-5 flex items-center gap-5">
            <div className="w-16 h-16 rounded-xl bg-surface-200 flex items-center justify-center text-3xl flex-shrink-0">
              {rfc.icon}
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-1">
                <span className="font-mono font-semibold text-brand-400">{rfc.rfc}</span>
                <h3 className="font-medium text-gray-200">{rfc.title}</h3>
              </div>
              <p className="text-sm text-gray-400">{rfc.role}</p>
            </div>
            <div className="hidden md:flex items-center gap-2 text-xs text-gray-500">
              <span className="w-2 h-2 rounded-full bg-accent-green" />
              <span>implemented</span>
            </div>
          </div>
        ))}
      </div>

      <div className="mt-6 p-5 rounded-xl bg-gradient-to-r from-brand-900/20 to-accent-purple/10 border border-brand-500/20">
        <h4 className="text-sm font-semibold text-brand-400 mb-2">✨ No Custom Protocol Innovations</h4>
        <p className="text-sm text-gray-400 leading-relaxed">
          Every token is a JWT (RFC 9068). Every delegation is RFC 8693 act. Every audience is RFC 8707 resource.
          Every discovery is RFC 8414/9728. Every client registration is RFC 7591. The innovation is in{" "}
          <span className="text-brand-400 font-medium">how these standards are composed</span> for agent-specific
          semantics — not in inventing new formats. Existing MCP servers work unchanged.
        </p>
      </div>
    </div>
  );
}