import { pillars } from "../data";
import { SectionHeader } from "./Sidebar";

export function Pillars() {
  return (
    <div>
      <SectionHeader
        icon="🏛️"
        title="The Five Pillars"
        subtitle="AgentSSO is built on five interoperable pillars. v0.1 ships the first five; step-up MFA is planned for v2."
      />
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {pillars.map((pillar) => {
          const isV2 = pillar.status === "v2";
          return (
            <div
              key={pillar.id}
              className={`card p-6 ${isV2 ? "opacity-60" : ""}`}
            >
              <div className="flex items-start justify-between mb-4">
                <div className={`w-12 h-12 rounded-xl flex items-center justify-center text-2xl bg-${pillar.color}-500/10`}>
                  {pillar.icon}
                </div>
                <span
                  className={`text-xs font-medium px-2 py-1 rounded-md ${
                    isV2
                      ? "bg-accent-red/10 text-accent-red border border-accent-red/20"
                      : "bg-accent-green/10 text-accent-green border border-accent-green/20"
                  }`}
                >
                  {pillar.status}
                </span>
              </div>
              <h3 className="text-lg font-semibold text-gray-100 mb-2">{pillar.title}</h3>
              <p className="text-sm text-gray-400 leading-relaxed">{pillar.description}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}