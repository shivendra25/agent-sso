import { components, stats } from "../data";
import { SectionHeader } from "./Sidebar";

export function TestResults() {
  const packagesWithTests = components.filter((c) => c.tests > 0);
  const maxTests = Math.max(...components.map((c) => c.tests));

  return (
    <div>
      <SectionHeader
        icon="🧪"
        title="Test Results"
        subtitle="115 tests across 15 packages. Every component is independently tested. The E2E integration test proves all security properties."
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <MetricCard label="Total Tests" value={stats.totalTests} icon="✓" color="text-accent-green" />
        <MetricCard label="Packages" value={stats.totalPackages} icon="📦" color="text-brand-400" />
        <MetricCard label="Avg Coverage" value={stats.coverage} icon="📊" color="text-accent-purple" />
        <MetricCard label="E2E Tests" value={2} icon="🔗" color="text-accent-cyan" />
      </div>

      <div className="card p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-4">Tests per Package</h3>
        <div className="space-y-3">
          {packagesWithTests.map((comp) => {
            const width = (comp.tests / maxTests) * 100;
            const coverageColor = comp.coverage >= 90 ? "#10b981" : comp.coverage >= 80 ? "#3b82f6" : comp.coverage >= 70 ? "#f59e0b" : "#ef4444";
            return (
              <div key={comp.name} className="flex items-center gap-4">
                <div className="w-48 text-sm text-gray-400 font-mono truncate">{comp.name}</div>
                <div className="flex-1 h-7 bg-surface-200 rounded-lg overflow-hidden relative">
                  <div
                    className="h-full rounded-lg flex items-center justify-end pr-3 transition-all"
                    style={{
                      width: `${width}%`,
                      background: `linear-gradient(to right, ${coverageColor}40, ${coverageColor}80)`,
                    }}
                  >
                    <span className="text-xs font-mono text-white font-medium">{comp.tests}</span>
                  </div>
                </div>
                {comp.coverage > 0 && (
                  <div className="w-16 text-right">
                    <span className="text-xs font-mono" style={{ color: coverageColor }}>
                      {comp.coverage}%
                    </span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      <div className="mt-6 p-5 rounded-xl bg-gradient-to-r from-accent-green/10 to-brand-900/10 border border-accent-green/20">
        <h4 className="text-sm font-semibold text-accent-green mb-2 flex items-center gap-2">
          <span>✓</span> End-to-End Integration Test
        </h4>
        <p className="text-sm text-gray-400 mb-3">
          The E2E test (<span className="font-mono text-gray-300">internal/integration/e2e_test.go</span>) proves
          the complete flow and verifies these security properties:
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {[
            "MCP server received JIT, NOT the AIT (no passthrough)",
            "Response body contains no tokens (injection-proof)",
            "WWW-Authenticate header stripped from response",
            "JIT audience = MCP server URL (RFC 8707)",
            "Delegation chain preserved (act.sub = human principal)",
            "Audit chain (JIT parent_jti links to AIT jti)",
            "Policy correctly denies unauthorized scopes",
          ].map((prop, idx) => (
            <div key={idx} className="flex items-center gap-2 text-xs text-gray-400">
              <span className="text-accent-green">✓</span>
              <span>{prop}</span>
            </div>
          ))}
        </div>
        <div className="mt-4 p-3 rounded-lg bg-surface-0 border border-surface-300">
          <code className="text-xs font-mono text-accent-green">
            $ go test ./internal/integration/ -v<br />
            === RUN   TestEndToEndFlow<br />
            ✓ Step 1: AIT issued<br />
            ✓ Step 2: Gateway call succeeded<br />
            ✓ Step 3: MCP server returned 2 PRs<br />
            ✓ Step 4a: MCP server received JIT (not AIT)<br />
            ✓ Step 4b: No tokens in response body<br />
            ✓ Step 4c: WWW-Authenticate stripped<br />
            ✓ Step 4d: JIT audience = MCP server URL<br />
            ✓ Step 4e: Delegation chain preserved<br />
            ✓ Step 4f: Audit chain linked<br />
            --- PASS: TestEndToEndFlow (0.02s)<br />
            PASS
          </code>
        </div>
      </div>
    </div>
  );
}

function MetricCard({ label, value, icon, color }: { label: string; value: string | number; icon: string; color: string }) {
  return (
    <div className="card p-5 text-center">
      <div className="text-2xl mb-1">{icon}</div>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-gray-500 mt-1">{label}</div>
    </div>
  );
}