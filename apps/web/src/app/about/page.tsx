"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import AppShell from "@/components/layout/AppShell";

const COMPONENTS = [
  { name: "Vooda AI Engine", desc: "Pattern-based security analysis engine", status: "Active", color: "text-red-400", bg: "bg-red-500/10" },
  { name: "AI Triage", desc: "False positive reduction with framework awareness", status: "Active", color: "text-purple-400", bg: "bg-purple-500/10" },
  { name: "AI Remediation", desc: "Secure code patch generation", status: "Active", color: "text-green-400", bg: "bg-green-500/10" },
  { name: "Scanner Bridge", desc: "Multi-scanner import and correlation", status: "Active", color: "text-orange-400", bg: "bg-orange-500/10" },
];

const LICENSES = [
  { name: "Tree-sitter", desc: "Incremental parsing for code context extraction", license: "MIT" },
  { name: "FastAPI", desc: "High-performance Python web framework", license: "MIT" },
  { name: "Next.js", desc: "React framework for the web application", license: "MIT" },
  { name: "PostgreSQL", desc: "Relational database", license: "PostgreSQL License" },
  { name: "Redis", desc: "In-memory cache and message broker", license: "BSD-3" },
  { name: "Celery", desc: "Distributed task queue", license: "BSD-3" },
  { name: "SQLAlchemy", desc: "Python SQL toolkit and ORM", license: "MIT" },
  { name: "Tailwind CSS", desc: "Utility-first CSS framework", license: "MIT" },
];

export default function AboutPage() {
  return (
    <AppShell>
      <div className="max-w-3xl mx-auto space-y-6">
        {/* Header */}
        <div className="card flex items-center gap-5">
          <div className="w-14 h-14 rounded-xl flex items-center justify-center shrink-0" style={{ background: "linear-gradient(135deg, #dc2626 0%, #ea580c 100%)", boxShadow: "0 4px 16px rgba(220,38,38,0.35)" }}>
            <svg className="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">Vooda AI AI Security Engine</h2>
            <p className="text-sm text-slate-400">Version 0.1.0</p>
          </div>
        </div>

        {/* Description */}
        <div className="card">
          <p className="text-sm text-slate-400 leading-relaxed">
            Vooda AI AI combines industry-leading static analysis detection engines with proprietary AI-powered
            false positive reduction and auto-remediation technology. The platform validates, correlates,
            and prioritizes findings from any scanner — then generates secure code fixes automatically.
          </p>
        </div>

        {/* Platform Components */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">Platform Components</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {COMPONENTS.map((c) => (
              <div key={c.name} className="flex items-center gap-3 p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
                <div className={`w-9 h-9 rounded-lg ${c.bg} flex items-center justify-center shrink-0`}>
                  <span className={`w-2 h-2 rounded-full ${c.color.replace("text-", "bg-")}`} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <p className={`text-sm font-medium ${c.color}`}>{c.name}</p>
                    <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-green-500/15 text-green-400 border border-green-500/20">{c.status}</span>
                  </div>
                  <p className="text-xs text-slate-500 mt-0.5">{c.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Open Source Licenses */}
        <div className="card" id="licenses">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">Open Source Acknowledgments</h3>
          <p className="text-xs text-slate-500 mb-4">
            Vooda AI AI is built on world-class open source technology. We gratefully acknowledge the following projects:
          </p>
          <div className="space-y-2">
            {LICENSES.map((lib) => (
              <div key={lib.name} className="flex items-center justify-between p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
                <div>
                  <p className="text-sm text-slate-300">{lib.name}</p>
                  <p className="text-xs text-slate-600">{lib.desc}</p>
                </div>
                <span className="text-xs text-slate-600 font-mono shrink-0 ml-3">{lib.license}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Legal */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Legal</h3>
          <div className="space-y-2 text-xs text-slate-500">
            <p>Vooda AI AI Security Engine &copy; 2024-2026. All rights reserved.</p>
            <p>
              All scanner product names (Checkmarx, Fortify, Veracode, SonarQube, Snyk, CodeQL)
              are trademarks of their respective owners. Vooda AI is not affiliated with or endorsed by these companies.
            </p>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
