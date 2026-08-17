"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState } from "react";
import AppShell from "@/components/layout/AppShell";

interface WebhookConfig {
  id: string;
  provider: string;
  repo_name: string;
  webhook_url: string;
  secret: string;
  is_active: boolean;
  events: string[];
  created_at: string;
  last_delivery: string | null;
}

const PROVIDERS = [
  { id: "github", name: "GitHub", events: ["push", "pull_request"], color: "from-slate-600 to-slate-800", setupUrl: "Settings > Webhooks" },
  { id: "gitlab", name: "GitLab", events: ["Push Hook", "Merge Request Hook"], color: "from-orange-500 to-red-500", setupUrl: "Settings > Webhooks" },
  { id: "bitbucket", name: "Bitbucket", events: ["repo:push", "pullrequest:created"], color: "from-blue-500 to-indigo-500", setupUrl: "Repository settings > Webhooks" },
];

export default function WebhooksPage() {
  const [webhooks, setWebhooks] = useState<WebhookConfig[]>([]);
  const [showSetup, setShowSetup] = useState<string | null>(null);
  const [copied, setCopied] = useState("");

  const apiBaseUrl = typeof window !== "undefined" ? window.location.origin : "http://localhost:8001";

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(""), 2000);
  };

  const generateSecret = () => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, b => b.toString(16).padStart(2, "0")).join("");
  };

  return (
    <AppShell>
      <div className="space-y-6">
        <p className="text-sm text-slate-400">Configure webhooks to scan code in real-time on push and pull request events</p>

        {/* Provider Setup Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {PROVIDERS.map(p => (
            <div key={p.id} className="card">
              <div className="flex items-center gap-3 mb-4">
                <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${p.color} flex items-center justify-center`}>
                  <span className="text-sm font-bold text-white">{p.name[0]}</span>
                </div>
                <div>
                  <p className="text-sm font-medium text-white">{p.name}</p>
                  <p className="text-xs text-slate-500">{p.events.join(", ")}</p>
                </div>
              </div>
              <button onClick={() => setShowSetup(showSetup === p.id ? null : p.id)} className="btn-secondary w-full text-sm">
                {showSetup === p.id ? "Hide Setup" : "Setup Instructions"}
              </button>

              {showSetup === p.id && (
                <div className="mt-4 space-y-3 border-t border-white/[0.06] pt-4">
                  <div>
                    <label className="text-xs text-slate-400">Webhook URL</label>
                    <div className="flex gap-2 mt-1">
                      <code className="flex-1 text-xs bg-black/30 rounded px-3 py-2 text-red-400 font-mono truncate">
                        {apiBaseUrl}/api/v1/webhooks/{p.id}
                      </code>
                      <button onClick={() => copyToClipboard(`${apiBaseUrl}/api/v1/webhooks/${p.id}`, `url-${p.id}`)}
                        className="btn-secondary text-xs px-3">{copied === `url-${p.id}` ? "Copied" : "Copy"}</button>
                    </div>
                  </div>
                  <div>
                    <label className="text-xs text-slate-400">Webhook Secret</label>
                    <div className="flex gap-2 mt-1">
                      <button onClick={() => { const s = generateSecret(); copyToClipboard(s, `secret-${p.id}`); }}
                        className="btn-secondary text-xs">{copied === `secret-${p.id}` ? "Copied" : "Generate & Copy Secret"}</button>
                    </div>
                  </div>
                  <div>
                    <label className="text-xs text-slate-400">Content Type</label>
                    <code className="block text-xs bg-black/30 rounded px-3 py-2 text-slate-300 mt-1">application/json</code>
                  </div>
                  <div>
                    <label className="text-xs text-slate-400">Events to Subscribe</label>
                    <div className="flex gap-2 mt-1 flex-wrap">
                      {p.events.map(e => (
                        <span key={e} className="text-xs px-2 py-1 rounded bg-red-500/10 text-red-400 border border-red-500/20">{e}</span>
                      ))}
                    </div>
                  </div>
                  <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.06]">
                    <p className="text-xs text-slate-400">
                      Go to your repository's <strong className="text-slate-300">{p.setupUrl}</strong> and add a new webhook with the URL and secret above. Select the events listed and set content type to <code>application/json</code>.
                    </p>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* How It Works */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">How Real-Time Scanning Works</h3>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[
              { step: "1", title: "Push Event", desc: "Developer pushes code or opens a PR" },
              { step: "2", title: "Webhook Fires", desc: "Git provider sends event to Vooda AI" },
              { step: "3", title: "Diff Scan", desc: "Only changed files are scanned for secrets" },
              { step: "4", title: "Alert", desc: "Team notified if secrets detected" },
            ].map(s => (
              <div key={s.step} className="flex gap-3">
                <div className="w-8 h-8 rounded-full bg-red-500/15 text-red-400 flex items-center justify-center text-sm font-bold shrink-0">{s.step}</div>
                <div>
                  <p className="text-sm font-medium text-white">{s.title}</p>
                  <p className="text-xs text-slate-500 mt-0.5">{s.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Webhook Signature Verification */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Signature Verification</h3>
          <div className="text-xs text-slate-400 space-y-2">
            <p><strong className="text-slate-300">GitHub:</strong> Uses <code className="text-red-400">X-Hub-Signature-256</code> header with HMAC-SHA256</p>
            <p><strong className="text-slate-300">GitLab:</strong> Uses <code className="text-red-400">X-Gitlab-Token</code> header for secret verification</p>
            <p><strong className="text-slate-300">Bitbucket:</strong> Uses <code className="text-red-400">X-Hub-Signature</code> header with HMAC-SHA256</p>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
