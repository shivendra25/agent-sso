import type { ProjectInfo, Stats } from "../data";

interface HeroProps {
  projectInfo: ProjectInfo;
  stats: Stats;
  onNavigate: (id: string) => void;
}

export function Hero({ projectInfo, stats, onNavigate }: HeroProps) {
  return (
    <div className="relative overflow-hidden border-b border-surface-300">
      <div className="absolute inset-0 bg-gradient-to-br from-brand-900/20 via-surface-0 to-accent-purple/10" />
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[800px] rounded-full bg-brand-500/5 blur-3xl" />

      <div className="relative max-w-7xl mx-auto px-6 md:px-10 py-20">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-brand-500 to-accent-purple flex items-center justify-center text-2xl font-bold">
            A
          </div>
          <div className="text-sm text-gray-400 font-mono">
            {projectInfo.version}
          </div>
          <div className="px-2 py-0.5 rounded-md bg-accent-green/10 text-accent-green text-xs font-medium border border-accent-green/20">
            PROTOTYPE WORKING
          </div>
        </div>

        <h1 className="text-5xl md:text-6xl font-extrabold tracking-tight mb-4">
          <span className="gradient-text">{projectInfo.name}</span>
        </h1>
        <p className="text-2xl md:text-3xl text-gray-300 font-light mb-3">
          {projectInfo.tagline}
        </p>
        <p className="text-lg text-gray-400 max-w-3xl mb-12 leading-relaxed">
          {projectInfo.description}
        </p>

        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4 mb-12">
          <StatCard label="Tests" value={stats.totalTests} color="text-accent-green" sublabel="passing" />
          <StatCard label="Packages" value={stats.totalPackages} color="text-brand-400" sublabel="Go modules" />
          <StatCard label="Commits" value={stats.totalCommits} color="text-accent-purple" sublabel="bricks shipped" />
          <StatCard label="Spec Docs" value={stats.totalSpecDocs} color="text-accent-cyan" sublabel="pages" />
          <StatCard label="Threats" value={stats.totalThreats} color="text-accent-amber" sublabel="modeled" />
          <StatCard label="RFCs" value={stats.rfcs} color="text-accent-red" sublabel="aligned" />
          <StatCard label="Coverage" value={stats.coverage} color="text-accent-green" sublabel="test coverage" />
        </div>

        <div className="flex flex-wrap gap-4">
          <NavigationButton label="🛡️ Security Properties" onClick={() => onNavigate("security")} primary />
          <NavigationButton label="🔄 Token Flow" onClick={() => onNavigate("flow")} />
          <NavigationButton label="🏗️ Architecture" onClick={() => onNavigate("architecture")} />
          <NavigationButton label="⚙️ Components" onClick={() => onNavigate("components")} />
          <NavigationButton label="🧪 Tests" onClick={() => onNavigate("tests")} />
          <a
            href={projectInfo.repo}
            target="_blank"
            rel="noreferrer"
            className="px-5 py-3 rounded-lg border border-surface-300 bg-surface-100 hover:border-brand-500/40 hover:bg-surface-200 transition-all text-sm font-medium"
          >
            📦 View Repo →
          </a>
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, color, sublabel }: { label: string; value: string | number; color: string; sublabel: string }) {
  return (
    <div className="card p-4 text-center">
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-gray-500 mt-1">{label}</div>
      <div className="text-[10px] text-gray-600">{sublabel}</div>
    </div>
  );
}

function NavigationButton({ label, onClick, primary }: { label: string; onClick: () => void; primary?: boolean }) {
  return (
    <button
      onClick={onClick}
      className={
        primary
          ? "px-5 py-3 rounded-lg bg-gradient-to-r from-brand-600 to-accent-purple text-white text-sm font-medium hover:shadow-lg hover:shadow-brand-900/30 transition-all"
          : "px-5 py-3 rounded-lg border border-surface-300 bg-surface-100 hover:border-brand-500/40 hover:bg-surface-200 transition-all text-sm font-medium"
      }
    >
      {label}
    </button>
  );
}