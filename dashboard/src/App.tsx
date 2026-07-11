import { useState } from "react";
import { projectInfo, stats } from "./data";
import { Hero } from "./components/Hero";
import { Pillars } from "./components/Pillars";
import { TokenFlow } from "./components/TokenFlow";
import { Architecture } from "./components/Architecture";
import { Components } from "./components/Components";
import { SecurityProperties } from "./components/SecurityProperties";
import { AITClaims } from "./components/AITClaims";
import { RFCMapping } from "./components/RFCMapping";
import { ThreatModel } from "./components/ThreatModel";
import { Sidebar } from "./components/Sidebar";
import { TestResults } from "./components/TestResults";

function App() {
  const [activeSection, setActiveSection] = useState("hero");

  const scrollTo = (id: string) => {
    setActiveSection(id);
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <div className="flex min-h-screen">
      <Sidebar activeSection={activeSection} onNavigate={scrollTo} />
      <main className="flex-1 ml-64">
        <div id="hero">
          <Hero projectInfo={projectInfo} stats={stats} onNavigate={scrollTo} />
        </div>
        <div className="max-w-7xl mx-auto px-6 md:px-10 py-16 space-y-24">
          <section id="pillars">
            <Pillars />
          </section>
          <section id="flow">
            <TokenFlow />
          </section>
          <section id="architecture">
            <Architecture />
          </section>
          <section id="components">
            <Components />
          </section>
          <section id="security">
            <SecurityProperties />
          </section>
          <section id="ait-claims">
            <AITClaims />
          </section>
          <section id="rfc">
            <RFCMapping />
          </section>
          <section id="threats">
            <ThreatModel />
          </section>
          <section id="tests">
            <TestResults />
          </section>
        </div>
        <footer className="border-t border-surface-300 py-8 px-10 text-center text-sm text-gray-500">
          <p>
            {projectInfo.name} {projectInfo.version} · Apache-2.0 ·{" "}
            <a
              href={projectInfo.repo}
              className="text-brand-400 hover:text-brand-500 transition-colors"
              target="_blank"
              rel="noreferrer"
            >
              {projectInfo.repo}
            </a>
          </p>
          <p className="mt-2">Built with Go · React · TailwindCSS · Zero static secrets</p>
        </footer>
      </main>
    </div>
  );
}

export default App;