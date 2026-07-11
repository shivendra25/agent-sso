import { useState } from "react";
import { aitClaims } from "../data";
import { SectionHeader } from "./Sidebar";

export function AITClaims() {
  const [selected, setSelected] = useState(0);

  return (
    <div>
      <SectionHeader
        icon="🔑"
        title="Agent Identity Token (AIT) Claims"
        subtitle="The AIT is a RFC 9068-compliant JWT with RFC 8693 delegation (act) and custom AgentSSO claims. Click a claim to see details."
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card p-5">
          <h3 className="text-sm font-semibold text-gray-300 mb-4">Claim Dictionary</h3>
          <div className="space-y-1">
            {aitClaims.map((claim, idx) => (
              <button
                key={claim.name}
                onClick={() => setSelected(idx)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-left transition-all ${
                  selected === idx
                    ? "bg-brand-500/10 border border-brand-500/30"
                    : "hover:bg-surface-200/50 border border-transparent"
                }`}
              >
                <div className="flex items-center gap-3">
                  {claim.isHighlight && <span className="text-accent-purple">★</span>}
                  <span className={`font-mono text-sm ${claim.isCustom ? "text-accent-cyan" : "text-gray-200"}`}>
                    {claim.name}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-gray-500">{claim.rfc}</span>
                  {claim.isCustom && (
                    <span className="text-xs px-1.5 py-0.5 rounded bg-accent-cyan/10 text-accent-cyan">custom</span>
                  )}
                </div>
              </button>
            ))}
          </div>
        </div>

        <div className="card p-5">
          <h3 className="text-sm font-semibold text-gray-300 mb-4">Claim Details</h3>
          {aitClaims[selected] && (
            <div className="space-y-4">
              <div>
                <div className="text-xs text-gray-500 mb-1">Name</div>
                <div className="font-mono text-lg text-brand-400">{aitClaims[selected].name}</div>
              </div>
              <div>
                <div className="text-xs text-gray-500 mb-1">Type</div>
                <div className="font-mono text-sm text-gray-200">{aitClaims[selected].type}</div>
              </div>
              <div>
                <div className="text-xs text-gray-500 mb-1">RFC</div>
                <div className="font-mono text-sm text-gray-200">{aitClaims[selected].rfc}</div>
              </div>
              <div>
                <div className="text-xs text-gray-500 mb-1">Description</div>
                <p className="text-sm text-gray-300">{aitClaims[selected].description}</p>
              </div>
              <div>
                <div className="text-xs text-gray-500 mb-1">Example</div>
                <div className="p-3 rounded-lg bg-surface-0 border border-surface-300">
                  <code className="text-xs font-mono text-accent-green break-all">
                    {aitClaims[selected].example}
                  </code>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="mt-6 p-5 rounded-xl bg-surface-50/50 border border-surface-300">
        <h4 className="text-sm font-semibold text-gray-300 mb-3">Complete AIT Payload Example</h4>
        <pre className="text-xs font-mono text-gray-400 overflow-x-auto leading-relaxed p-4 rounded-lg bg-surface-0 border border-surface-300">
{`{
  "iss": "https://aidp.agentsso.io",
  "sub": "a:f3b7c1e2-89d4-4a6b-9c0e-7f2a1b8d3e5f",
  "aud": "https://aidp.agentsso.io/oauth/token",
  "exp": 1752280800,
  "iat": 1752279900,
  "nbf": 1752279900,
  "jti": "01HXYZF8K3VN5RWM2P9Q4T7J6M",
  "client_id": "agent-runtime-prod-1",
  "scope": "agent:attest tools:exchange",
  "act": {
    "sub": "oidc:okta:00u8f4jk2labCdEfGhIj",
    "iss": "https://acme.okta.com",
    "delegation_id": "del_8x2k9p..."
  },
  "cnp": "sha256:a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
  "rtm": "sha256:b2c3d4e5f67890123456789012345678901234567890abcdef123456789abcdef1",
  "ses": "ses_9a2b7c4d",
  "att_jti": "att_3f1c8d2e",
  "tenant": "tnt_acme"
}`}
        </pre>
      </div>
    </div>
  );
}