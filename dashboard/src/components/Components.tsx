import { useState } from "react";
import { components } from "../data";
import { SectionHeader } from "./Sidebar";

const categoryColors: Record<string, string> = {
  foundation: "#3b82f6",
  identity: "#06b6d4",
  federation: "#a855f7",
  gateway: "#f59e0b",
  security: "#10b981",
  sdk: "#ef4444",
};

const categoryLabels: Record<string, string> = {
  foundation: "Foundation",
  identity: "Identity",
  federation: "Federation",
  gateway: "Gateway",
  security: "Security",
  sdk: "SDK",
};

export function Components() {
  const [filter, setFilter] = useState<string>("all");

  const filtered = filter === "all" ? components : components.filter((c) => c.category === filter);
  const categories = [...new Set(components.map((c) => c.category))];

  return (
    <div>
      <SectionHeader
        icon="⚙️"
        title="Components — 15 Go Packages"
        subtitle="Each package is independently testable and committable. Filter by category to explore the architecture."
      />

      <div className="flex flex-wrap gap-2 mb-6">
        <FilterButton
          label="All"
          active={filter === "all"}
          onClick={() => setFilter("all")}
          count={components.length}
        />
        {categories.map((cat) => (
          <FilterButton
            key={cat}
            label={categoryLabels[cat] || cat}
            active={filter === cat}
            onClick={() => setFilter(cat)}
            count={components.filter((c) => c.category === cat).length}
            color={categoryColors[cat]}
          />
        ))}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filtered.map((comp) => {
          const color = categoryColors[comp.category] || "#666";
          return (
            <div key={comp.name} className="card p-5 group">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <h3 className="font-semibold text-gray-100 group-hover:text-brand-400 transition-colors">
                    {comp.name}
                  </h3>
                  <p className="text-xs text-gray-500 font-mono mt-1">{comp.file}</p>
                </div>
                <span
                  className="text-xs font-medium px-2 py-1 rounded-md"
                  style={{ backgroundColor: `${color}15`, color, border: `1px solid ${color}30` }}
                >
                  {categoryLabels[comp.category] || comp.category}
                </span>
              </div>
              <p className="text-sm text-gray-400 leading-relaxed mb-4">{comp.description}</p>
              <div className="flex items-center gap-4 text-xs">
                <div className="flex items-center gap-1.5">
                  <span className="text-accent-green">✓</span>
                  <span className="text-gray-400">{comp.tests} tests</span>
                </div>
                {comp.coverage > 0 && (
                  <div className="flex items-center gap-1.5">
                    <span className="text-gray-500">📊</span>
                    <span className="text-gray-400">{comp.coverage}% coverage</span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function FilterButton({
  label,
  active,
  onClick,
  count,
  color,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  count: number;
  color?: string;
}) {
  return (
    <button
      onClick={onClick}
      className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all border ${
        active
          ? "bg-surface-200 border-brand-500/40 text-gray-100"
          : "bg-surface-100 border-surface-300 text-gray-500 hover:border-surface-400"
      }`}
    >
      {color && <span className="inline-block w-2 h-2 rounded-full mr-2" style={{ backgroundColor: color }} />}
      {label}
      <span className="ml-2 text-xs text-gray-600">{count}</span>
    </button>
  );
}