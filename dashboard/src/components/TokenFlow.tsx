import { useState } from "react";
import { tokenFlow } from "../data";
import { SectionHeader } from "./Sidebar";

export function TokenFlow() {
  const [activeStep, setActiveStep] = useState(0);

  return (
    <div>
      <SectionHeader
        icon="🔄"
        title="Token Flow — How It Works"
        subtitle="The complete flow from human login to tool call response. Click a step to see details. The key insight: the LLM context never contains a bearer token."
      />

      <div className="space-y-4">
        {tokenFlow.map((step, idx) => (
          <div key={step.step} className="relative">
            {idx < tokenFlow.length - 1 && (
              <div className="absolute left-7 top-16 bottom-0 w-0.5 bg-gradient-to-b from-surface-400 to-surface-300" />
            )}
            <div
              className={`relative card p-5 cursor-pointer transition-all ${
                activeStep === idx ? "border-brand-500/50 shadow-lg shadow-brand-900/20" : ""
              }`}
              onClick={() => setActiveStep(idx)}
            >
              <div className="flex items-start gap-4">
                <div
                  className="w-14 h-14 rounded-xl flex items-center justify-center text-2xl font-bold flex-shrink-0"
                  style={{ backgroundColor: `${step.tokenColor}20`, color: step.tokenColor }}
                >
                  {step.step}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-1">
                    <h3 className="text-lg font-semibold text-gray-100">{step.label}</h3>
                    <span className="text-sm font-mono text-gray-500">{step.actor}</span>
                  </div>
                  <p className="text-sm text-gray-400 mb-3">{step.description}</p>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-500">Token:</span>
                    <span
                      className="px-2 py-1 rounded-md text-xs font-mono font-medium"
                      style={{
                        backgroundColor: `${step.tokenColor}15`,
                        color: step.tokenColor,
                        border: `1px solid ${step.tokenColor}30`,
                      }}
                    >
                      {step.token}
                    </span>
                  </div>
                </div>
                {activeStep === idx && (
                  <div className="text-brand-400 text-xl flex-shrink-0">●</div>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="mt-8 p-5 rounded-xl bg-surface-50/50 border border-surface-300">
        <h4 className="text-sm font-semibold text-accent-green mb-3 flex items-center gap-2">
          <span>✓</span> Critical Security Property
        </h4>
        <p className="text-sm text-gray-400 leading-relaxed">
          At Step 6, the gateway returns <span className="font-mono text-accent-green">ONLY the response body</span>.
          It strips <span className="font-mono text-accent-amber">WWW-Authenticate</span>,{" "}
          <span className="font-mono text-accent-amber">Set-Cookie</span>, and{" "}
          <span className="font-mono text-accent-amber">Authorization</span> headers.
          The LLM context never contains a bearer token —{" "}
          <span className="text-accent-green font-medium">prompt-injection cannot exfiltrate what the LLM never had.</span>
        </p>
      </div>
    </div>
  );
}