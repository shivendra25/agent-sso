import { securityProperties } from "../data";
import { SectionHeader } from "./Sidebar";

export function SecurityProperties() {
  return (
    <div>
      <SectionHeader
        icon="🛡️"
        title="Security Properties — Proven by E2E Test"
        subtitle="Each property is verified by the end-to-end integration test (internal/integration/e2e_test.go). These are not claims — they are test assertions."
      />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {securityProperties.map((prop, idx) => (
          <div key={idx} className="card p-6 group">
            <div className="flex items-start gap-4">
              <div className="w-14 h-14 rounded-xl bg-surface-200 flex items-center justify-center text-3xl flex-shrink-0">
                {prop.icon}
              </div>
              <div className="flex-1">
                <h3 className="font-semibold text-gray-100 mb-2">{prop.title}</h3>
                <p className="text-sm text-gray-400 leading-relaxed mb-3">{prop.description}</p>
                <div className="p-3 rounded-lg bg-surface-100 border border-surface-300">
                  <div className="flex items-start gap-2">
                    <span className="text-xs font-mono text-accent-green mt-0.5">PROOF:</span>
                    <p className="text-xs text-gray-400 leading-relaxed font-mono">{prop.proof}</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}