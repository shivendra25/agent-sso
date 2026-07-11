const sections = [
  { id: "hero", label: "Overview", icon: "🏠" },
  { id: "pillars", label: "Pillars", icon: "🏛️" },
  { id: "flow", label: "Token Flow", icon: "🔄" },
  { id: "architecture", label: "Architecture", icon: "🏗️" },
  { id: "components", label: "Components", icon: "⚙️" },
  { id: "security", label: "Security", icon: "🛡️" },
  { id: "ait-claims", label: "AIT Claims", icon: "🔑" },
  { id: "rfc", label: "RFCs", icon: "📋" },
  { id: "threats", label: "Threats", icon: "⚠️" },
  { id: "tests", label: "Tests", icon: "🧪" },
];

interface SidebarProps {
  activeSection: string;
  onNavigate: (id: string) => void;
}

export function Sidebar({ activeSection, onNavigate }: SidebarProps) {
  return (
    <aside className="fixed left-0 top-0 bottom-0 w-64 bg-surface-50/90 backdrop-blur-md border-r border-surface-300 z-50">
      <div className="p-6 border-b border-surface-300">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-brand-500 to-accent-purple flex items-center justify-center text-lg font-bold">
            A
          </div>
          <div>
            <div className="font-bold text-sm">AgentSSO</div>
            <div className="text-xs text-gray-500">v0.1.0</div>
          </div>
        </div>
      </div>

      <nav className="p-3 space-y-1">
        {sections.map((section) => (
          <button
            key={section.id}
            onClick={() => onNavigate(section.id)}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all ${
              activeSection === section.id
                ? "bg-brand-500/10 text-brand-400 border border-brand-500/20"
                : "text-gray-400 hover:text-gray-200 hover:bg-surface-200/50 border border-transparent"
            }`}
          >
            <span className="text-base">{section.icon}</span>
            <span className="font-medium">{section.label}</span>
          </button>
        ))}
      </nav>

      <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-surface-300">
        <div className="text-xs text-gray-500">
          <div className="flex justify-between">
            <span>Tests</span>
            <span className="text-accent-green font-mono">115 ✓</span>
          </div>
          <div className="flex justify-between mt-1">
            <span>Packages</span>
            <span className="text-brand-400 font-mono">15</span>
          </div>
          <div className="flex justify-between mt-1">
            <span>Commits</span>
            <span className="text-accent-purple font-mono">15</span>
          </div>
        </div>
      </div>
    </aside>
  );
}

export function SectionHeader({ title, subtitle, icon }: { title: string; subtitle: string; icon: string }) {
  return (
    <div className="mb-8">
      <div className="flex items-center gap-3 mb-2">
        <span className="text-3xl">{icon}</span>
        <h2 className="text-2xl font-bold text-gray-100">{title}</h2>
      </div>
      <p className="text-gray-500 max-w-3xl">{subtitle}</p>
    </div>
  );
}