import { threatModel } from "../data";
import { SectionHeader } from "./Sidebar";

const severityColors: Record<string, string> = {
  Critical: "#ef4444",
  High: "#f59e0b",
  Medium: "#3b82f6",
  Low: "#10b981",
};

export function ThreatModel() {
  return (
    <div>
      <SectionHeader
        icon="⚠️"
        title="Threat Model — STRIDE Analysis"
        subtitle="10 threats identified across 6 trust boundaries. Each threat maps to a specific control in the AgentSSO architecture."
      />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {threatModel.map((threat) => {
          const sevColor = severityColors[threat.severity] || "#666";
          const isMitigated = threat.status === "mitigated";
          return (
            <div key={threat.id} className="card p-5">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-xl bg-surface-200 flex items-center justify-center text-2xl flex-shrink-0">
                  {threat.icon}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="font-mono text-xs text-gray-500">{threat.id}</span>
                    <span
                      className="text-xs font-medium px-2 py-0.5 rounded"
                      style={{ backgroundColor: `${sevColor}15`, color: sevColor, border: `1px solid ${sevColor}30` }}
                    >
                      {threat.severity}
                    </span>
                    <span
                      className={`text-xs font-medium px-2 py-0.5 rounded ${
                        isMitigated
                          ? "bg-accent-green/10 text-accent-green"
                          : "bg-accent-amber/10 text-accent-amber"
                      }`}
                    >
                      {isMitigated ? "✓ mitigated" : "⏳ planned"}
                    </span>
                  </div>
                  <h3 className="text-sm font-semibold text-gray-200 mb-2">{threat.title}</h3>
                  <div className="flex items-start gap-2 mt-2">
                    <span className="text-xs text-accent-cyan mt-0.5">🛡️</span>
                    <p className="text-xs text-gray-400 leading-relaxed">{threat.mitigation}</p>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}