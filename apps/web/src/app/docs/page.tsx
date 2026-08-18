"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect } from "react";
import Link from "next/link";
import { APP_VERSION } from "@/lib/constants";

// Governance-tier sections (policies, nhi, agents, supply-chain,
// quantum) removed from the docs 2026-05-15 alongside the
// corresponding product surfaces.  See Sidebar.tsx for the
// architectural rationale (refocus on secret-scanner core).
type DocSection =
  | "overview" | "quickstart" | "accuracy"
  | "auth" | "users" | "roles" | "repositories" | "sources"
  | "findings" | "ai-triage" | "detectors" | "remediation"
  | "integrations" | "notifications" | "reporting" | "api" | "cicd"
  | "admin" | "hardening" | "troubleshooting" | "faq" | "glossary" | "changelog"
  | "airgapped" | "backup" | "upgrade" | "config-ref" | "cli";

const SECTIONS: { key: DocSection; label: string; group: string; icon: React.ReactNode }[] = [
  { key: "overview", label: "Introduction", group: "Get started", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" /> },
  { key: "quickstart", label: "Quickstart", group: "Get started", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" /> },
  { key: "repositories", label: "Add a repository and scan", group: "How-to guides", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16l3.5-2 3.5 2 3.5-2 3.5 2z" /> },
  { key: "sources", label: "Connect a scan source", group: "How-to guides", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" /> },
  { key: "ai-triage", label: "Configure AI triage", group: "How-to guides", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" /> },
  { key: "findings", label: "Triage findings", group: "How-to guides", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /> },
  { key: "remediation", label: "Remediate and rotate secrets", group: "How-to guides", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /> },
  { key: "detectors", label: "Write a custom detector", group: "How-to guides", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /> },
  { key: "integrations", label: "Connect integrations", group: "How-to guides", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /> },
  { key: "notifications", label: "Set up notifications", group: "How-to guides", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" /> },
  { key: "reporting", label: "Generate reports", group: "How-to guides", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" /> },
  { key: "cicd", label: "Add Vooda to CI/CD", group: "How-to guides", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /> },
  { key: "users", label: "Manage users", group: "How-to guides", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" /> },
  { key: "roles", label: "Manage roles and permissions", group: "How-to guides", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /> },
  { key: "airgapped", label: "Install air-gapped", group: "How-to guides", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /> },
  { key: "backup", label: "Back up and restore", group: "How-to guides", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" /> },
  { key: "upgrade", label: "Upgrade Vooda", group: "How-to guides", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /> },
  { key: "accuracy", label: "How detection works", group: "Concepts", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" /> },
  { key: "auth", label: "Authentication and sessions", group: "Reference", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m0 0v2m0-2h2m-2 0h-2m9-9V6a3 3 0 00-3-3H8a3 3 0 00-3 3v2M5 20h14a2 2 0 002-2v-7a2 2 0 00-2-2H5a2 2 0 00-2 2v7a2 2 0 002 2z" /> },
  { key: "api", label: "API reference", group: "Reference", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /> },
  { key: "config-ref", label: "Configuration reference", group: "Reference", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /> },
  { key: "cli", label: "CLI reference", group: "Reference", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /> },
  { key: "admin", label: "Administration", group: "Reference", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /> },
  { key: "hardening", label: "Security hardening", group: "Reference", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /> },
  { key: "glossary", label: "Glossary", group: "Reference", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" /> },
  { key: "changelog", label: "Release notes", group: "Reference", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /> },
  { key: "troubleshooting", label: "Troubleshooting", group: "Troubleshooting", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /> },
  { key: "faq", label: "FAQ", group: "FAQ", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /> },
];

// ── Doc components ────────────────────────────────────
function H2({ children, id }: { children: React.ReactNode; id?: string }) { return <h2 id={id} className="text-xl font-bold text-white mt-10 mb-4 first:mt-0 scroll-mt-24">{children}</h2>; }
function H3({ children, id }: { children: React.ReactNode; id?: string }) { return <h3 id={id} className="text-base font-semibold text-slate-200 mt-7 mb-3 scroll-mt-24">{children}</h3>; }
function P({ children }: { children: React.ReactNode }) { return <p className="text-[15px] text-slate-400 leading-relaxed mb-3">{children}</p>; }
function Li({ children }: { children: React.ReactNode }) { return <li className="text-[15px] text-slate-400 leading-relaxed flex gap-2.5"><span className="text-red-400/50 mt-1 shrink-0">▸</span><span>{children}</span></li>; }
function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (<div className="flex gap-5 py-4 border-b border-white/[0.04] last:border-0"><div className="w-9 h-9 rounded-xl bg-gradient-to-br from-red-500/15 to-blue-500/15 text-red-400 flex items-center justify-center text-sm font-bold shrink-0 border border-red-500/15">{n}</div><div className="flex-1 pt-1"><p className="text-[15px] font-semibold text-slate-200 mb-1">{title}</p><div className="text-[15px] text-slate-400 leading-relaxed">{children}</div></div></div>);
}
function Tip({ children }: { children: React.ReactNode }) {
  return (<div className="flex gap-3 p-4 rounded-xl bg-red-500/[0.04] border border-red-500/10 my-5"><svg className="w-5 h-5 text-red-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" /></svg><p className="text-[14px] text-slate-300 leading-relaxed">{children}</p></div>);
}
function Note({ children }: { children: React.ReactNode }) {
  return (<div className="flex gap-3 p-4 rounded-xl bg-blue-500/[0.04] border border-blue-500/10 my-5"><span className="text-[11px] font-bold text-blue-300 mt-0.5 shrink-0">NOTE</span><p className="text-[14px] text-slate-300 leading-relaxed">{children}</p></div>);
}
function Warn({ children }: { children: React.ReactNode }) {
  return (<div className="flex gap-3 p-4 rounded-xl bg-orange-500/[0.06] border border-orange-500/15 my-5"><span className="text-[11px] font-bold text-orange-300 mt-0.5 shrink-0">WARNING</span><p className="text-[14px] text-slate-300 leading-relaxed">{children}</p></div>);
}
function RoleBox({ role, see }: { role: string; see?: string }) {
  return (<div className="flex flex-wrap gap-3 p-3 rounded-xl bg-purple-500/[0.04] border border-purple-500/15 mb-6 text-[13px]"><span className="font-semibold text-purple-300">Required role:</span><span className="text-slate-300">{role}</span>{see && <span className="ml-auto text-slate-500">API: <a href={`#${see}`} className="text-purple-300 hover:underline">see the API reference</a></span>}</div>);
}
function Code({ children }: { children: string }) { return <pre className="bg-[#0a0e1a] text-slate-300 p-5 rounded-xl text-[13px] overflow-x-auto my-4 font-mono border border-white/[0.06] leading-relaxed"><code>{children}</code></pre>; }
function Grid2({ children }: { children: React.ReactNode }) { return <div className="grid grid-cols-1 md:grid-cols-2 gap-3 my-5">{children}</div>; }
function InfoCard({ title, children, color = "red" }: { title: string; children: React.ReactNode; color?: string }) {
  const c: Record<string, string> = { purple: "border-purple-500/10 bg-purple-500/[0.03]", green: "border-green-500/10 bg-green-500/[0.03]", orange: "border-orange-500/10 bg-orange-500/[0.03]", red: "border-red-500/10 bg-red-500/[0.03]", blue: "border-blue-500/10 bg-blue-500/[0.03]" };
  return <div className={`rounded-xl border p-5 ${c[color] || c.red}`}><p className="text-sm font-semibold text-slate-200 mb-2">{title}</p><div className="text-[14px] text-slate-400 leading-relaxed">{children}</div></div>;
}
function Tbl({ headers, rows }: { headers: string[]; rows: (string | React.ReactNode)[][] }) {
  return (
    <div className="my-5 rounded-xl border border-white/[0.06] overflow-hidden">
      <table className="w-full text-[13px]">
        <thead className="bg-white/[0.03]"><tr>{headers.map((h) => <th key={h} className="px-4 py-2.5 text-left font-semibold text-slate-200">{h}</th>)}</tr></thead>
        <tbody>{rows.map((r, i) => <tr key={i} className="border-t border-white/[0.04]">{r.map((c, j) => <td key={j} className="px-4 py-2.5 text-slate-400 align-top">{c}</td>)}</tr>)}</tbody>
      </table>
    </div>
  );
}
function Endpoint({ method, path, desc }: { method: string; path: string; desc: string }) {
  const colors: Record<string, string> = { GET: "text-emerald-400 bg-emerald-500/10", POST: "text-blue-400 bg-blue-500/10", PUT: "text-orange-400 bg-orange-500/10", PATCH: "text-orange-400 bg-orange-500/10", DELETE: "text-red-400 bg-red-500/10" };
  return (
    <div className="flex items-start gap-3 py-2 border-b border-white/[0.04] last:border-0">
      <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold tracking-wide shrink-0 ${colors[method] || "text-slate-400 bg-slate-500/10"}`}>{method}</span>
      <code className="text-[12px] text-slate-300 font-mono shrink-0">{path}</code>
      <span className="text-[12px] text-slate-500 ml-auto text-right">{desc}</span>
    </div>
  );
}

// Live-fetched scanner-rule catalogue (Sprint-3 enhancement to the
// 19.11.A appendix).  Hits the public /api/v1/public/scanner-rules
// endpoint — no auth required, browser caches for 1 h via the
// endpoint's Cache-Control header.  Renders a searchable virtualised-
// looking table (no virtualisation library; just a cap at 100 rows
// with a count indicator above).
function LiveScannerRuleCatalog() {
  const [data, setData] = useState<{ total: number; items: any[] } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState("");

  useEffect(() => {
    let cancelled = false;
    fetch("/api/v1/public/scanner-rules")
      .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then((d) => { if (!cancelled) setData(d); })
      .catch((e) => { if (!cancelled) setErr(String(e)); });
    return () => { cancelled = true; };
  }, []);

  if (err) return <Note>Couldn&apos;t load the rule catalogue: <code>{err}</code>. The endpoint <code>/api/v1/public/scanner-rules</code> should always be reachable — check the API container is healthy.</Note>;
  if (!data) return <p className="text-[13px] text-slate-500 my-4">Loading scanner rule catalogue…</p>;

  const needle = q.trim().toLowerCase();
  const filtered = needle
    ? data.items.filter((r: any) =>
        (r.rule_id + " " + (r.name || "") + " " + (r.secret_type || "")).toLowerCase().includes(needle))
    : data.items;
  const shown = filtered.slice(0, 100);

  return (
    <div className="my-4">
      <div className="flex items-center gap-3 mb-3">
        <input
          type="text"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter by rule_id, name, or secret_type (e.g. aws, github, stripe)…"
          className="flex-1 px-3 py-2 bg-white/[0.04] border border-white/[0.08] rounded-lg text-[13px] text-slate-200 placeholder-slate-600 focus:outline-none focus:border-red-500/30"
        />
        <span className="text-[11px] text-slate-500 shrink-0">
          {filtered.length === data.total
            ? `${data.total} rules`
            : `${filtered.length} / ${data.total} match`}
        </span>
      </div>
      <Tbl
        headers={["rule_id", "Name", "Secret type", "Severity", "Verifier"]}
        rows={shown.map((r: any) => [
          <code key={r.rule_id} className="text-[12px] text-slate-200">{r.rule_id}</code>,
          r.name || "",
          <code key={r.rule_id + "_st"} className="text-[12px] text-slate-500">{r.secret_type || "—"}</code>,
          <span key={r.rule_id + "_sev"} className={`text-[11px] font-medium ${
            r.severity === "critical" ? "text-red-400" :
            r.severity === "high" ? "text-orange-400" :
            r.severity === "medium" ? "text-amber-400" :
            r.severity === "low" ? "text-slate-400" : "text-slate-500"
          }`}>{r.severity || "—"}</span>,
          r.verifier_available
            ? <span key={r.rule_id + "_v"} className="text-[11px] text-emerald-400">✓ live-verify</span>
            : <span key={r.rule_id + "_v"} className="text-[11px] text-slate-600">—</span>,
        ])}
      />
      {filtered.length > 100 && (
        <p className="text-[11.5px] text-slate-500 mt-2">
          Showing first 100 of {filtered.length} matches. Refine the filter to narrow.
        </p>
      )}
    </div>
  );
}

// Rich operation card — fully-documented endpoint with auth, params,
// schemas, errors, and examples.  Used for the top 30 critical
// endpoints in the 19.7 Operation Inventory subsection.  Collapsible
// by default to keep the page browseable; click to expand the full
// operation detail.
function Operation({
  id, method, path, summary, scope, params, request, response,
  errors, curl, exampleResp, defaultOpen = false,
}: {
  id: string; method: string; path: string; summary: string;
  scope?: string;
  params?: { in: string; name: string; type: string; required?: boolean; desc: string }[];
  request?: string;
  response: string;
  errors?: [string, string][];
  curl: string;
  exampleResp?: string;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const colors: Record<string, string> = { GET: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20", POST: "text-blue-400 bg-blue-500/10 border-blue-500/20", PUT: "text-orange-400 bg-orange-500/10 border-orange-500/20", PATCH: "text-orange-400 bg-orange-500/10 border-orange-500/20", DELETE: "text-red-400 bg-red-500/10 border-red-500/20" };
  return (
    <div className="my-4 rounded-xl border border-white/[0.06] bg-white/[0.01] overflow-hidden">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/[0.02] transition-colors">
        <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold tracking-wide shrink-0 border ${colors[method] || "text-slate-400 bg-slate-500/10 border-slate-500/20"}`}>{method}</span>
        <code className="text-[12.5px] text-slate-200 font-mono shrink-0">{path}</code>
        <span className="text-[12px] text-slate-500 truncate flex-1">{summary}</span>
        <span className="text-[11px] text-slate-600 font-mono shrink-0">{id}</span>
        <svg className={`w-3.5 h-3.5 text-slate-500 transition-transform shrink-0 ${open ? "rotate-180" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
      </button>
      {open && (
        <div className="px-4 pb-4 border-t border-white/[0.04]">
          <div className="flex flex-wrap gap-x-6 gap-y-1 py-3 text-[12px]">
            <span><span className="text-slate-500">Auth:</span> <span className="text-slate-300">Bearer JWT or API Key</span></span>
            {scope && <span><span className="text-slate-500">Scope:</span> <code className="text-purple-300">{scope}</code></span>}
          </div>
          {params && params.length > 0 && (
            <>
              <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mt-2 mb-1.5">Parameters</p>
              <Tbl headers={["In", "Name", "Type", "Required", "Description"]} rows={params.map(p => [p.in, <code key={p.name} className="text-slate-200">{p.name}</code>, <code key={p.name+"t"} className="text-slate-500">{p.type}</code>, p.required ? <span className="text-red-400 font-semibold">yes</span> : <span className="text-slate-500">no</span>, p.desc])} />
            </>
          )}
          {request && (
            <>
              <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mt-3 mb-1.5">Request body</p>
              <Code>{request}</Code>
            </>
          )}
          <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mt-3 mb-1.5">Response (200/201)</p>
          <Code>{response}</Code>
          {errors && errors.length > 0 && (
            <>
              <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mt-3 mb-1.5">Error responses</p>
              <Tbl headers={["Status", "Meaning"]} rows={errors} />
            </>
          )}
          <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mt-3 mb-1.5">Example request</p>
          <Code>{curl}</Code>
          {exampleResp && (
            <>
              <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mt-3 mb-1.5">Example response</p>
              <Code>{exampleResp}</Code>
            </>
          )}
        </div>
      )}
    </div>
  );
}
function Img({ src, alt, caption }: { src: string; alt: string; caption?: string }) {
  return (
    <figure className="my-6 rounded-xl border border-white/[0.06] overflow-hidden bg-[#0a0e1a]">
      <img src={src} alt={alt} className="w-full block" loading="lazy" />
      {caption && <figcaption className="px-4 py-2 text-[12px] text-slate-500 border-t border-white/[0.06] bg-white/[0.02]">{caption}</figcaption>}
    </figure>
  );
}
function ExtLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="text-red-400 hover:text-red-300 underline decoration-red-400/30 hover:decoration-red-300 inline-flex items-center gap-1">
      {children}
      <svg className="w-3 h-3 inline-block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
    </a>
  );
}
// Cross-section navigation footer.  Drops in at the bottom of major
// sections so a reader is never left at a dead end.  Default colour =
// neutral; pass color="red" for the section the reader is currently in
// to visually de-emphasise it.
function NextSteps({ items }: { items: { label: string; href: string; desc?: string }[] }) {
  return (
    <div className="mt-10 pt-6 border-t border-white/[0.06]">
      <p className="text-[11px] font-bold text-slate-500 uppercase tracking-widest mb-3">Where to next</p>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {items.map((it, i) => (
          <Link key={i} href={it.href} className="block p-3 rounded-xl border border-white/[0.06] bg-white/[0.01] hover:bg-white/[0.04] hover:border-red-500/20 transition-all group">
            <div className="flex items-center gap-2">
              <span className="text-[13px] font-semibold text-slate-200 group-hover:text-red-300">{it.label}</span>
              <svg className="w-3 h-3 text-slate-600 group-hover:text-red-400 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
            </div>
            {it.desc && <p className="text-[11.5px] text-slate-500 mt-1 leading-snug">{it.desc}</p>}
          </Link>
        ))}
      </div>
    </div>
  );
}


function FieldRef({ label, required, type, hint }: { label: string; required?: boolean; type?: string; hint?: string }) {
  return (
    <div className="py-2 border-b border-white/[0.04] last:border-0">
      <div className="flex items-baseline gap-2">
        <span className="text-[13px] font-semibold text-slate-200">{label}</span>
        {required && <span className="text-[10px] text-red-400 font-bold">REQUIRED</span>}
        {type && <code className="text-[11px] text-slate-500">{type}</code>}
      </div>
      {hint && <p className="text-[12.5px] text-slate-500 mt-0.5">{hint}</p>}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 1 — PLATFORM OVERVIEW
// ═══════════════════════════════════════════════════════════════
function OverviewContent() {
  return (
    <>
      <RoleBox role="any authenticated user" />


      {/* §3.1 — 5-minute Quickstart pointer.  Full path lives at
          /docs?section=quickstart so an evaluator who lands here can
          jump straight to "scan your first repo in 5 minutes". */}
      <div className="card border-red-500/20 bg-gradient-to-br from-red-500/[0.05] to-blue-500/[0.04] mb-6">
        <div className="flex items-start gap-4">
          <div className="w-11 h-11 rounded-xl bg-red-500/15 border border-red-500/25 flex items-center justify-center shrink-0">
            <svg className="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          </div>
          <div className="flex-1">
            <p className="text-[10px] font-bold text-red-300 uppercase tracking-widest mb-1">Quickstart — 5 minutes</p>
            <p className="text-base font-semibold text-slate-100 mb-1">From signup to first finding in three steps.</p>
            <p className="text-[13px] text-slate-400 mb-3">Connect a repo → watch the scan → triage your first finding. If any of these break, those are bugs we should fix, not docs gaps — open a ticket and we&apos;ll respond same business day.</p>
            <Link href="/docs?section=quickstart" className="inline-flex items-center gap-1.5 text-[13px] font-medium text-red-300 hover:text-red-200">
              Open the 5-minute Quickstart
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
            </Link>
          </div>
        </div>
      </div>

      <Note>
        <strong>About this documentation.</strong> This is the reference for Vooda. Every feature is
        documented here with the role required, step-by-step instructions, exact URLs and UI labels,
        and a curl example for the equivalent API call. Use the nav on the left or the search box to
        find a task; each page ends with suggested next steps.
      </Note>

      <H2>What Vooda Is</H2>
      <P>
        Vooda AI is an enterprise platform that combines four capabilities into a single workflow:
      </P>
      <Grid2>
        <InfoCard title="Secret Scanning" color="red">A comprehensive detection rule set, with a four-stage pipeline (regex → live verifier → AI triage → per-tenant calibration). Scans Git repositories plus non-Git sources — issue trackers (Jira, ServiceNow, Azure DevOps), cloud storage (S3, Azure Blob, GCS), and CI/CD logs & container registries.</InfoCard>
        <InfoCard title="AI Triage" color="orange">Reduces false positives using configurable LLMs (Claude, OpenAI, Gemini, Mistral). Every triage decision feeds a per-tenant calibration loop so accuracy improves with use.</InfoCard>
        <InfoCard title="Remediation Workflows" color="blue">One-click rotation playbooks, ticket creation (Jira / ServiceNow), and CI/CD blocking gates to drive findings to closure.</InfoCard>
        <InfoCard title="Compliance Reporting" color="green">Maps findings to SOC 2 Type II, PCI-DSS, ISO 27001, NIST CSF, and NIST 800-53. Exports auditor-ready evidence packages.</InfoCard>
      </Grid2>

      <Img src="/docs/screenshots/dashboard.png" alt="Vooda AI dashboard" caption="Figure 1.1 — The dashboard at /dashboard summarizes security score, findings by severity, MTTR, and remediation rate. Each tile links to the corresponding deep-dive page." />

      <H2>Core Concepts</H2>
      <Tbl headers={["Term", "Definition"]} rows={[
        [<strong key="1">Tenant</strong>, "Top-level isolation boundary. All data — repositories, findings, users — is scoped to one tenant. Most deployments run a single tenant; multi-tenant deployments are supported with strict tenant_id row-level scoping."],
        [<strong key="2">Organization</strong>, "Owner of all resources within a tenant. Owns billing, default settings, the audit log, and the SSO configuration."],
        [<strong key="3">Business Unit (BU)</strong>, "A group of repositories, sources, and users (engineering / platform / product). BUs nest. Roles can be inherited from a parent BU."],
        [<strong key="4">Repository</strong>, "A connected Git remote (GitHub / GitLab / Bitbucket / bare git URL). Owns its scan history, branch checkpoints, and findings."],
        [<strong key="5">Scan Source</strong>, "A non-Git scan target — a Jira site, an S3 bucket, a container registry. See the Connect a scan source guide."],
        [<strong key="6">Finding</strong>, "A detected leaked secret. Has severity, classification, review_status, remediation_status, and a full audit history."],
        [<strong key="7">Allowlist</strong>, "A scanner-level filter that suppresses known-safe matches (test fixtures, sample data, public keys) before they become findings."],
        [<strong key="8">Suppression</strong>, "An exception applied to an existing finding — by rule_id, file path glob, or time-bounded acceptance. See the Triage findings guide."],
      ]} />

      <H2>Architecture Overview</H2>
      <Tbl headers={["Component", "Technology", "Responsibility"]} rows={[
        ["API", "FastAPI (Python 3.12)", "REST + WebSocket. 250+ endpoints across 31 routers."],
        ["Worker", "Celery + Redis broker", "Scan execution, AI triage, scheduled jobs."],
        ["Web", "Next.js 15, React 19, Tailwind", "App Router UI, server components for static pages, client for interactive."],
        ["Database", "PostgreSQL 16", "52+ tables. SQLAlchemy 2 async, Alembic migrations."],
        ["Cache / queue", "Redis 7", "Celery broker, advisory locks, calibration cache, WebSocket pub/sub."],
        ["Real-time", "WebSocket via Redis pub/sub", "Live scan progress, finding stream."],
      ]} />
      <Tip>For a deeper architecture walk-through (dataflow diagrams, service modules, schema), see <code>docs/architecture.md</code> in the repository.</Tip>

      <H2>Deployment Models</H2>
      <Grid2>
        <InfoCard title="Docker Compose" color="red">Single-host install. Brings up <code>api</code>, <code>worker</code>, <code>web</code>, <code>postgres</code>, <code>redis</code>, plus optional <code>beat</code> scheduler. Recommended for proof-of-concept and team-scale use (≤500 repos).</InfoCard>
        <InfoCard title="Coolify / Kubernetes" color="purple">Per-service deployment with horizontal scaling. <code>WORKER_REPLICAS</code> and <code>API_REPLICAS</code> tuned per workload. Recommended for enterprise (1000+ repos).</InfoCard>
      </Grid2>
      <H3>Required environment variables</H3>
      <Code>{`# Required
SECRET_KEY=<32+ char random>            # JWT signing
DATABASE_URL=postgresql+asyncpg://...   # Primary DB
REDIS_URL=redis://redis:6379/0          # Broker + cache
CELERY_BROKER_URL=redis://redis:6379/1
WEB_BASE_URL=https://vooda.acme.com     # For email links + SAML ACS
LOG_LEVEL=INFO                          # DEBUG | INFO | WARN | ERROR

# AI providers (configure at least one)
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GOOGLE_API_KEY=...

# Scaling
CELERY_CONCURRENCY=4                    # Worker processes
API_WORKERS=4                           # Uvicorn workers`}</Code>

      <H2>Ready to start?</H2>
      <P>
        The <strong>Quickstart</strong> walks you through it end to end — install Vooda, connect your first
        repository, run a scan, and triage your first finding in about five minutes.
      </P>

      <NextSteps items={[
        { label: "Quickstart (5 min)", href: "/docs?section=quickstart", desc: "Connect a repo + see your first finding in three steps." },
        { label: "Detection Accuracy", href: "/docs?section=accuracy", desc: "How Vooda catches real secrets while cutting false positives." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 1.4 — QUICKSTART (5 minutes)
// ═══════════════════════════════════════════════════════════════
function QuickstartContent() {
  return (
    <>
      <RoleBox role="any (the first admin is created by the seed step; subsequent users are invited by an admin)" />

      <div className="card border-red-500/30 bg-gradient-to-br from-red-500/[0.05] to-blue-500/[0.04] mb-6">
        <p className="text-[10px] font-bold text-red-300 uppercase tracking-widest mb-1">Goal — under 5 minutes</p>
        <p className="text-lg font-semibold text-slate-100 mb-1">From signup to your first triaged finding.</p>
        <p className="text-[13.5px] text-slate-400">Three steps. Stop here if any of them break — those are bugs we should fix, not docs gaps.</p>
      </div>

      <H2>Step 1 — Connect a repository (≈ 60 s)</H2>
      <P>
        From the left nav go to <strong>Repositories → + Add Repository</strong>. Paste a Git URL and the
        Personal Access Token for that provider — the token needs <code>repo</code> scope on GitHub,
        <code> read_repository + read_api</code> on GitLab, or <code>repository:read</code> on Bitbucket.
      </P>
      <Step n={1} title="Pick how Vooda authenticates to git">
        For GitHub specifically, prefer the <strong>GitHub App</strong> (Settings → Integrations → GitHub App)
        over a PAT — App tokens auto-rotate, scope to specific repos, and survive team-member turnover. Skip
        the PAT route entirely for production.
      </Step>
      <Step n={2} title="Tick &lsquo;Scan on add&rsquo;">
        Enabled by default — kicks off the initial scan the moment you click Save. The UI auto-redirects to
        the repository detail page with a live progress bar (WebSocket-pushed, not polling).
      </Step>

      <H3>Equivalent cURL (skip the UI)</H3>
      <Code>{`curl -X POST https://api.vooda.ai/v1/repositories \\
  -H "Authorization: Bearer $VOODA_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "acme/payments-api",
    "url":  "https://github.com/acme/payments-api",
    "provider": "github",
    "auth": { "token": "ghp_xxxxxxxxxxxxxxxxxxxxxx" },
    "scan_on_add": true
  }'`}</Code>

      <H2>Step 2 — Watch the scan (≈ 90 s for a typical repo)</H2>
      <P>
        Phase indicators appear in order: <strong>queued → cloning → walking files → scanning → AI triaging
        → verifying live → persisting → done</strong>. The progress bar advances as each phase completes.
        Performance reference:
      </P>
      <Tbl headers={["Repo size", "Files", "Standalone scan", "Full-history scan"]} rows={[
        ["Small",      "≤ 5 k files",   "≈ 10 s",  "≈ 30 s"],
        ["Medium",     "≤ 50 k files",  "≈ 45 s",  "≈ 6 min"],
        ["Large",      "≤ 500 k files", "≈ 4 min", "≈ 25 min"],
        ["Monorepo",   "≥ 500 k files", "≈ 8 min", "≈ 1 h (raise default timeout)"],
      ]} />
      <Tip>The bar can sit at any single phase for &gt; 30 s without indicating a stall — AI triage on a CPU-bound provider often holds for ~2 min on the first batch then accelerates as the cache warms.</Tip>

      <H2>Step 3 — Triage your first finding (≈ 30 s)</H2>
      <P>
        The scan card flips to <em>Completed</em> with a per-severity count. Click any finding row — the
        side panel opens with:
      </P>
      <ul className="space-y-2 my-3">
        <Li><strong>The redacted match</strong> with file path, line, commit SHA, and a one-line evidence preview.</Li>
        <Li><strong>AI explanation</strong> — a 1-2 sentence rationale for the verdict (true positive vs false positive), with model name + token cost.</Li>
        <Li><strong>Live verifier status</strong> — green ✓ if Vooda authenticated against the upstream service successfully, red ✗ if the credential is dead, grey if no verifier exists for this rule.</Li>
        <Li><strong>Decision buttons</strong> — <em>Mark TP</em>, <em>Mark FP</em>, <em>Accept Risk</em>, <em>Request Review</em>, or <em>Comment</em>. Every click writes an audit row with the actor + reason.</Li>
      </ul>

      <H3>What to do if it&apos;s a real critical finding</H3>
      <ol className="space-y-2 my-3 list-decimal list-inside text-[15px] text-slate-400">
        <li>Click <strong>Remediate</strong> — Vooda drafts a rotation plan (rotate-via-vault, open PR removing the literal, notify owners).</li>
        <li>A security lead clicks <strong>Approve</strong>; the rotation event lands in <code>/rotation-events</code> for the audit trail.</li>
        <li>Vooda automatically re-verifies the credential after rotation — when verified-dead, the finding flips to <code>remediation_status=resolved</code>.</li>
      </ol>

      <H2>Step 4 — Add it to CI (≈ 2 min, optional but recommended)</H2>
      <P>
        Drop this into <code>.github/workflows/vooda-scan.yml</code> to fail any PR that introduces a new
        critical finding:
      </P>
      <Code>{`name: Vooda Secret Scan
on: [push, pull_request]
jobs:
  vooda:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Vooda gate
        env:
          VOODA_API_KEY: \${{ secrets.VOODA_API_KEY }}
          VOODA_REPO_ID: \${{ vars.VOODA_REPO_ID }}
        run: |
          curl -fsS -X POST "https://api.vooda.ai/v1/repositories/$VOODA_REPO_ID/scan" \\
            -H "Authorization: Bearer $VOODA_API_KEY" \\
            -H "Content-Type: application/json" \\
            -d '{"scan_type":"standalone"}'`}</Code>
      <P>
        Generate the <code>VOODA_API_KEY</code> via <strong>Settings → API Keys → + Generate Key</strong>
        — give it the <code>scan</code> scope and store it as a GitHub repository secret. The full integration
        recipe is in <Link href="/docs?section=cicd" className="text-red-400 hover:underline">the Add Vooda to CI/CD guide</Link>.
      </P>

      <H2>Step 5 — Invite your team (≈ 1 min)</H2>
      <P>
        <strong>Settings → Users → + Invite User</strong>. Default role suggestions:
      </P>
      <Tbl headers={["Role", "When to assign", "Scope"]} rows={[
        ["admin",             "You and one backup", "Everything, including key management + SSO config."],
        ["security_lead",     "AppSec engineers approving rotations", "All findings + remediation approval + rule overrides."],
        ["security_reviewer", "Triagers across the org", "Read findings, classify TP/FP, comment."],
        ["developer",         "Engineering team using push-protection + reading their team's findings", "Scoped to their Business Unit's repos."],
        ["viewer",            "Auditors, compliance staff", "Read-only, no triage power."],
      ]} />

      <Warn>SSO is recommended for any tenant with &gt; 5 users. Configure it at <strong>Settings → SSO</strong> — SAML + OIDC supported (Okta, Auth0, Azure Entra, Google Workspace).</Warn>

      <NextSteps items={[
        { label: "AI Triage Engine", href: "/docs?section=ai-triage", desc: "How the verdict gets made + how to tune the model selection." },
        { label: "CI/CD Integration", href: "/docs?section=cicd", desc: "Full recipes for GitHub Actions, GitLab CI, Jenkins, CircleCI." },
        { label: "API Reference", href: "/docs?section=api", desc: "Every endpoint with examples + Swagger UI." },
        { label: "Detection Accuracy", href: "/docs?section=accuracy", desc: "How Vooda catches real secrets while cutting false positives." },
        { label: "Troubleshooting", href: "/docs?section=troubleshooting", desc: "Error code catalog + step-1 fixes for common issues." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 1.5 — ACCURACY & BENCHMARKS
// ═══════════════════════════════════════════════════════════════
function AccuracyContent() {
  return (
    <>
      <RoleBox role="any" />

      <H2>Detection Accuracy</H2>
      <P>
        Detection quality is the single most-asked-about metric in commercial secret scanning. Vooda's
        pipeline is built to catch real secrets while an AI triage pass cuts the false positives that
        regex-only scanners drown teams in — so you review real exposures, not noise.
      </P>

      <H3>How accuracy is achieved</H3>
      <ul className="space-y-2 my-3">
        <Li><strong>Multi-stage pipeline</strong> — the rule engine flags candidates, a live verifier checks whether a credential still works, and an AI model classifies each finding as true or false positive with a confidence score.</Li>
        <Li><strong>Per-tenant calibration</strong> — every triage decision feeds a calibration loop, so precision improves on your own codebase the more you use it.</Li>
        <Li><strong>Conservative mode</strong> — for regulated environments with no acceptable miss rate, the AI engine can be set to favour recall under <strong>Settings → AI Models → Engine Settings</strong>.</Li>
        <Li><strong>Measured, not asserted</strong> — detection quality is tracked against an internal regression suite that is recomputed on every rule-pack release.</Li>
      </ul>

      <NextSteps items={[
        { label: "AI Triage Engine", href: "/docs?section=ai-triage", desc: "How the verdict gets made + how to tune model selection." },
        { label: "Custom Detectors", href: "/docs?section=detectors", desc: "Add your own regex rules to widen coverage." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 2 — AUTHENTICATION & SESSIONS
// ═══════════════════════════════════════════════════════════════
function AuthContent() {
  return (
    <>
      <RoleBox role="any user (login); org-admin (SSO/IdP setup)" see="api" />

      <H2>Email / Password Login</H2>
      <P>
        Username/password is the default identity backend. Credentials are validated against the local user table
        and a single JWT access token is issued.
      </P>
      <Code>{`curl -X POST https://vooda.acme.com/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"email":"alice@acme.com","password":"<password>"}'

# Response
{ "access_token": "eyJhbGc...", "token_type": "bearer" }`}</Code>
      <P>The access-token lifetime defaults to <strong>60 minutes</strong>, configurable via <code>ACCESS_TOKEN_EXPIRE_MINUTES</code>. Vooda issues a single bearer token — there are no refresh tokens.</P>

      <H2>Token Lifetime</H2>
      <P>
        There is no refresh-token endpoint. When a request returns <code>401</code> (the token has expired), the
        client re-authenticates with <code>POST /api/v1/auth/login</code>. Keep <code>ACCESS_TOKEN_EXPIRE_MINUTES</code>
        low for sensitive deployments.
      </P>

      <H2>Logout</H2>
      <P>
        Logout is client-side — discard the stored token. Vooda does not maintain a server-side token blacklist,
        so a token stays valid until it expires; that is why the lifetime is kept short.
      </P>

      <H2>Password Requirements</H2>
      <P>Enforced on every password set — self-service change, admin reset, and new-user creation:</P>
      <ul className="space-y-2 my-3">
        <Li>≥ 12 characters</Li>
        <Li>at least one uppercase, one lowercase, one digit, one symbol</Li>
        <Li>not on the bundled common / breached-password blocklist (checked offline, so it works in air-gapped deployments)</Li>
      </ul>
      <P>
        A self-service change (<code>POST /api/v1/auth/change-password</code>, or Profile → Change Password) additionally
        requires the current password, rejects reusing it, and rejects reusing any of your <strong>last 5 passwords</strong>.
        Administrative resets of other users (Settings → Users) do not need the old password. <em>A live HaveIBeenPwned
        lookup is on the roadmap; breach detection today uses the bundled offline blocklist.</em>
      </P>
      <P>
        SSO-only users cannot reset a local password (they have none).
      </P>

      <H2>Multi-Factor Authentication (TOTP)</H2>
      <P>
        TOTP-based MFA is available for local accounts. SSO-authenticated users should configure MFA at the IdP
        instead.
      </P>
      <Step n={1} title="Enable MFA">
        <strong>Settings → Profile → Security → Enable Multi-Factor Authentication</strong>. The platform displays
        a QR code (otpauth URI).
      </Step>
      <Step n={2} title="Scan the code">
        Use Google Authenticator, 1Password, or any RFC 6238 TOTP app to scan the QR code.
      </Step>
      <Step n={3} title="Confirm the 6-digit code">
        Enter the 6-digit code shown by the app. The platform issues 10 single-use backup codes — store them
        securely.
      </Step>
      <Warn>If you lose both your authenticator and your backup codes, an org-admin must reset MFA via <code>POST /api/v1/users/&#123;id&#125;/mfa-reset</code>. Recovery is logged to the audit trail.</Warn>

      <H2>SSO — SAML 2.0</H2>

      <Note><strong>⚠ SSO is temporarily disabled</strong> in this release; the SAML and OIDC endpoints below return <code>503</code>. It is being hardened before it can be safely re-enabled. Use JWT email/password login in the meantime. Sections 2.6 and 2.7 are retained for when SSO returns.</Note>

      <P>
        SAML 2.0 is the intended enterprise identity backend. Vooda is the Service Provider (SP); your IdP
        (Okta, Azure AD / Entra, Google, Ping, ADFS) is the Identity Provider.
      </P>
      <H3>Endpoints</H3>
      <Tbl headers={["Endpoint", "URL"]} rows={[
        ["SP metadata", <code key="m">https://vooda.acme.com/api/v1/sso/saml/metadata</code>],
        ["ACS (Assertion Consumer Service)", <code key="a">https://vooda.acme.com/api/v1/sso/saml/acs</code>],
      ]} />
      <H3>Configuration steps</H3>
      <Step n={1} title="Download SP metadata">
        From <strong>Settings → SSO → SAML</strong>, click <strong>Download SP metadata</strong>.
      </Step>
      <Step n={2} title="Configure your IdP">
        Upload the SP metadata to your IdP, or enter the ACS URL and SP Entity ID manually.
      </Step>
      <Step n={3} title="Map attributes">
        Map IdP attributes to Vooda fields:
        <ul className="space-y-1 mt-2">
          <Li><code>email</code> ← IdP <code>email</code> or <code>NameID</code></Li>
          <Li><code>first_name</code> ← <code>givenName</code></Li>
          <Li><code>last_name</code> ← <code>surname</code></Li>
          <Li><code>groups</code> ← <code>memberOf</code> (used for role mapping)</Li>
        </ul>
      </Step>
      <Step n={4} title="Upload IdP metadata to Vooda">
        Paste the IdP metadata XML or URL into <strong>Settings → SSO → SAML → IdP Metadata</strong>.
      </Step>
      <Step n={5} title="Test, then enforce">
        Click <strong>Test SSO login</strong>. Once a successful round-trip is verified, toggle
        <strong> Force SSO for all users</strong>. After enforcement, only org-admins retain a local-password
        fallback (configurable).
      </Step>
      <Tip>SAML supports both SP-initiated (user starts at Vooda) and IdP-initiated (user starts at the IdP dashboard) flows. RelayState round-trip is preserved for deep links.</Tip>

      <H2>SSO — OIDC / OAuth 2.0</H2>
      <P>OIDC is supported for Okta, Azure AD / Entra, Google, Auth0, and Ping. Authorization Code with PKCE is the only allowed flow.</P>
      <H3>Endpoints</H3>
      <Tbl headers={["Endpoint", "URL"]} rows={[
        ["Authorization start", <code key="1">https://vooda.acme.com/api/v1/sso/oidc/authorize?provider=&#123;name&#125;</code>],
        ["Callback", <code key="2">https://vooda.acme.com/api/v1/sso/oidc/callback</code>],
      ]} />
      <H3>Required scopes</H3>
      <P><code>openid profile email</code> at minimum. Add <code>groups</code> if you intend to map IdP groups to Vooda roles.</P>
      <H3>Claim mapping</H3>
      <Tbl headers={["Vooda field", "OIDC claim"]} rows={[
        ["email", "email"],
        ["first_name", "given_name"],
        ["last_name", "family_name"],
        ["external_id", "sub"],
        ["groups → roles", "groups (configurable mapping in Settings → SSO)"],
      ]} />

      <H2>API Key Authentication</H2>
      <P>API keys are the recommended credential for CI/CD pipelines, scripts, and external integrations.</P>
      <Step n={1} title="Create a key">
        <strong>Settings → API Keys → + Create API Key</strong>. Name the key, select scopes, and set an expiry
        (max 365 days).
      </Step>
      <Step n={2} title="Copy the key once">
        The key (format <code>vk_live_...</code>) is displayed once. Store it in your CI secret manager.
      </Step>
      <Step n={3} title="Use in requests">
        <Code>{`curl https://vooda.acme.com/api/v1/findings \\
  -H "Authorization: ApiKey vk_live_..."`}</Code>
      </Step>
      <Step n={4} title="Revoke">
        Revocation is immediate. <strong>Settings → API Keys → Revoke</strong> or
        <code> DELETE /api/v1/api-keys/&#123;id&#125;</code>.
      </Step>
      <Tbl headers={["Scope", "Allows"]} rows={[
        ["read:findings", "GET on findings, severities, tags"],
        ["write:findings", "PATCH triage status, add comments"],
        ["read:repos", "GET on repositories"],
        ["scan:trigger", "POST scan-trigger endpoints"],
        ["gates:check", "POST /gates/check (CI/CD gate)"],
        ["admin", "Full read/write — org-admin only"],
      ]} />

      <H2>Session Security</H2>
      <ul className="space-y-2 my-3">
        <Li><strong>Token storage</strong> — the access token is returned in the login JSON body; store it in memory only (never localStorage). Vooda does not set auth cookies and has no refresh tokens.</Li>
        <Li><strong>CORS</strong> — allowed origins are set via <code>CORS_ORIGINS</code> (comma-separated). Keep it to your Vooda host in production.</Li>
        <Li><strong>Token lifetime</strong> — the access token expires after <code>ACCESS_TOKEN_EXPIRE_MINUTES</code> (60 min default); the client re-authenticates via <code>/api/v1/auth/login</code>. There is no server-side session store or blacklist, so keep the lifetime short for sensitive deployments.</Li>
      </ul>

      <NextSteps items={[
        { label: "Users & Organization", href: "/docs?section=users", desc: "Invite teammates, assign roles, configure SSO." },
        { label: "Roles & Permissions", href: "/docs?section=roles", desc: "Permission model + how to grant scoped access." },
        { label: "API Reference — Authentication", href: "/docs?section=api", desc: "Programmatic auth: JWT + API keys + rotation." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 3 — USERS & ORGANIZATION
// ═══════════════════════════════════════════════════════════════
function UsersContent() {
  return (
    <>
      <RoleBox role="org-admin (most actions); any user (own profile)" see="api" />

      <H2>Tenant Model</H2>
      <P>
        Every row in the database is scoped by <code>tenant_id</code>. The default deployment runs a single tenant
        (the implicit <em>default</em> tenant created on first migration). Multi-tenant deployments — typical
        for MSPs — provision additional tenants via <code>POST /api/v1/admin/tenants</code> (root-only).
      </P>
      <Note>Cross-tenant API requests are rejected with HTTP 403, regardless of role. The check is enforced at the SQLAlchemy session level via tenant-aware row-level filters, not at the application layer alone.</Note>

      <H2>Creating and Inviting Users</H2>
      <Step n={1} title="Open the user list">
        <strong>Settings → Users → + Invite User</strong>.
      </Step>
      <Step n={2} title="Provide email + role">
        Enter the user's email, select one or more roles (the Manage roles and permissions reference), and optionally assign a Business Unit (the Manage users guide).
      </Step>
      <Step n={3} title="Send invite">
        The platform emails a single-use, 7-day-expiry link to set a password and complete first login. The user
        appears in the list with <em>Pending</em> status until they activate.
      </Step>
      <Step n={4} title="Resend or revoke">
        For pending users you can <strong>Resend invite</strong> or <strong>Revoke invite</strong>. Revocation
        invalidates the link.
      </Step>

      <H2>User Profile</H2>
      <P>
        Every user can update their own profile under <strong>Settings → Profile</strong>:
      </P>
      <ul className="space-y-2 my-3">
        <Li>Display name and email (email change requires re-verification)</Li>
        <Li>Password (subject to the rules in the Authentication and sessions reference)</Li>
        <Li>MFA enrolment / backup codes</Li>
        <Li>Notification preferences (per event type, per channel — the Set up notifications guide)</Li>
        <Li>Personal API keys (scoped to the user's role)</Li>
      </ul>

      <H2>User Lifecycle</H2>
      <Tbl headers={["State", "Meaning", "Effect"]} rows={[
        ["Pending", "Invited but not yet activated", "Cannot log in. 7-day expiry."],
        ["Active", "Normal user", "Full access per assigned roles."],
        ["Deactivated", "Suspended by org-admin", "Cannot log in. API keys revoked. Audit trail preserved."],
        ["Deleted (soft)", "Removed by org-admin", "Hidden from UI. tenant_id row preserved for 90 days for audit, then hard-deleted."],
      ]} />
      <Warn>Deletion is irreversible after the 90-day soft-delete window. To preserve historical findings owned by a user, deactivate instead of delete.</Warn>

      <H2>Service Accounts</H2>
      <P>
        Service accounts are users with <code>service_account=true</code>. They cannot log in via password or SSO —
        only via API key. Use them for CI/CD pipelines, scheduled jobs, and external integrations so that human
        offboarding doesn't break automation.
      </P>
      <Code>{`curl -X POST https://vooda.acme.com/api/v1/users \\
  -H "Authorization: Bearer $ADMIN_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "email": "ci-pipeline@acme.com",
    "service_account": true,
    "roles": ["developer"],
    "business_unit_id": "bu_01H..."
  }'`}</Code>

      <H2>Business Units</H2>
      <P>
        Business Units (BUs) are the unit of access scoping below the org level. They form a tree — for example,
        <em> Engineering → Platform → Search</em>.
      </P>
      <Step n={1} title="Create a BU">
        <strong>Settings → Business Units → + New BU</strong>. Provide a name and optional parent BU.
      </Step>
      <Step n={2} title="Assign repositories and sources">
        Each repository and scan source can be assigned to exactly one BU. Findings inherit the BU of their source.
      </Step>
      <Step n={3} title="Assign users / roles to a BU">
        Use Access Grants (the Manage users guide) to give a user a role within a specific BU.
      </Step>
      <Tip>Roles assigned at a parent BU are inherited by all descendants unless explicitly overridden.</Tip>

      <H2>User Access Grants</H2>
      <P>An access grant binds a (user, role, scope) triple. Scopes are stacked from broad to narrow:</P>
      <Tbl headers={["Scope", "Effect"]} rows={[
        ["org", "Role applies across the entire tenant. Reserved for security-leads / org-admins."],
        ["business_unit", "Role applies within one BU and all its descendants."],
        ["project", "Role applies to one repository or one scan source only."],
      ]} />
      <Code>{`# Grant a developer role on a single repo
curl -X POST https://vooda.acme.com/api/v1/access/grants \\
  -H "Authorization: Bearer $ADMIN_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "user_id": "u_01H...",
    "role": "developer",
    "scope_type": "project",
    "scope_id": "repo_01H..."
  }'`}</Code>
      <P>
        To revoke, <code>DELETE /api/v1/access/grants/&#123;id&#125;</code>. Revocation is immediate; the affected
        user's permission cache is invalidated within 30 seconds.
      </P>

      <NextSteps items={[
        { label: "Roles & Permissions", href: "/docs?section=roles", desc: "What each role can actually do." },
        { label: "Administration", href: "/docs?section=admin", desc: "Org-level settings: SSO, retention, branding." },
        { label: "Glossary", href: "/docs?section=glossary", desc: "Tenant vs Organization vs Business Unit — the precise distinctions." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 4 — ROLES & PERMISSIONS
// ═══════════════════════════════════════════════════════════════
function RolesContent() {
  return (
    <>
      <RoleBox role="org-admin" see="api" />

      <H2>Built-in Roles</H2>
      <Tbl headers={["Role", "Intended for", "Can do"]} rows={[
        ["org-admin", "Tenant administrators", "Everything: user management, SSO, billing, integrations, deletes."],
        ["security-lead", "Security & DevSecOps", "All scan/finding operations across the tenant, including allowlist and suppression management. Cannot manage users or billing."],
        ["developer", "Engineers", "View findings on their BU/repos, triage, request remediation. Cannot manage users."],
        ["auditor", "Compliance / external", "Read-only across findings, audit log, reports. No write."],
        ["agent", "Service accounts", "Programmatic scope for CI/CD: trigger scans, ingest findings via SARIF."],
      ]} />

      <H2>Custom Role Definitions</H2>
      <P>Custom roles let you compose any subset of permissions from the inventory in the Manage roles and permissions reference.</P>
      <Step n={1} title="Open the role editor">
        <strong>Settings → Roles → + New Role</strong>.
      </Step>
      <Step n={2} title="Pick permissions">
        Tick the permissions to include. Inherit-from-base is supported — start from <em>developer</em> and add
        a few additional rights, for example.
      </Step>
      <Step n={3} title="Save and assign">
        Save the role, then assign it via Access Grants (the Manage users guide) or via SSO group mapping (the Authentication and sessions reference).
      </Step>

      <H2>Permission Model</H2>
      <P>Permissions are namespaced as <code>resource:action</code>. Full inventory:</P>
      <Tbl headers={["Permission", "Description"]} rows={[
        ["repos:read", "List and view repositories."],
        ["repos:write", "Connect, edit, and delete repositories."],
        ["repos:scan", "Trigger scans on a repository."],
        ["sources:read", "List and view scan sources."],
        ["sources:write", "Connect, edit, and delete scan sources."],
        ["sources:scan", "Trigger source scans."],
        ["findings:read", "Read findings, including evidence."],
        ["findings:triage", "Mark findings as TP/FP/Test/Accepted Risk."],
        ["findings:export", "Export findings to CSV/JSON/SARIF."],
        ["findings:import", "Ingest external SARIF results."],
        ["allowlists:write", "Create and edit scanner allowlist entries."],
        ["suppressions:write", "Create suppression rules."],
        ["detectors:write", "Create custom detectors."],
        ["integrations:read", "View configured integrations."],
        ["integrations:write", "Configure / disconnect integrations."],
        ["users:read", "List users."],
        ["users:write", "Invite, deactivate, delete users."],
        ["roles:write", "Create and assign roles."],
        ["sso:write", "Configure SAML / OIDC."],
        ["billing:write", "Manage subscription and invoicing."],
        ["audit:read", "Read the audit log."],
        ["reports:read", "Generate compliance reports."],
        ["reports:write", "Customize report templates."],
        ["admin", "Implies all of the above. org-admin only."],
      ]} />

      <H2>Role Assignment & Inheritance</H2>
      <P>
        A user's effective permission set is the union of: (a) roles directly granted at the org scope, plus
        (b) roles granted on any BU that contains the resource being accessed, plus (c) roles granted on the
        specific resource. The permission model is strictly additive — denying a permission requires removing
        the granting role.
      </P>

      <H2>Least-Privilege Guidance</H2>
      <Tbl headers={["Team type", "Recommended role", "Scope"]} rows={[
        ["Engineering team (per BU)", "developer", "BU"],
        ["Security operations", "security-lead", "org"],
        ["Compliance / GRC", "auditor", "org"],
        ["External pen-test team", "auditor", "org, time-bounded grant"],
        ["CI/CD pipelines", "agent", "specific repos via API key with scopes:trigger + gates:check"],
        ["IT / platform admins", "org-admin", "org"],
      ]} />
      <Tip>For pen-test engagements, create a time-bounded access grant: <code>POST /api/v1/access/grants</code> with <code>expires_at</code>. The grant auto-revokes at the deadline, with an audit-log entry.</Tip>

      <H2>Viewing Effective Permissions</H2>
      <P>To audit what a user can actually do:</P>
      <Code>{`curl https://vooda.acme.com/api/v1/users/u_01H.../effective-permissions \\
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Response
{
  "user_id": "u_01H...",
  "permissions": ["repos:read", "findings:read", "findings:triage", "..."],
  "grants": [
    { "role": "developer", "scope_type": "business_unit", "scope_id": "bu_01H...", "source": "direct" },
    { "role": "auditor", "scope_type": "org", "source": "sso_group:Security" }
  ]
}`}</Code>
      <P>The same view is available in the UI under <strong>Settings → Users → &lt;user&gt; → Effective Permissions</strong>.</P>

      <NextSteps items={[
        { label: "Users & Organization", href: "/docs?section=users", desc: "Assign these roles to actual people." },
        { label: "API Reference — Roles", href: "/docs?section=api", desc: "Create + edit custom roles programmatically." },
        { label: "Security Hardening", href: "/docs?section=hardening", desc: "RBAC best practices for regulated environments." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 5 — REPOSITORIES
// ═══════════════════════════════════════════════════════════════
function RepositoriesContent() {
  return (
    <>
      <RoleBox role="security-lead or developer with repos:write on the target BU" see="api" />

      <Img src="/docs/screenshots/repositories.png" alt="Repositories list" caption="Figure 5.1 — The Repositories page at /repositories shows every connected repo with current scan status, last-scan date, and severity counts. Click + Add Repository to start the wizard." />

      <H2>Connecting a Repository</H2>
      <P>Vooda scans repositories from any of the supported providers below.</P>
      <Tbl headers={["Provider", "Auth method", "Org-level connector?"]} rows={[
        ["GitHub Cloud", "Personal Access Token (classic or fine-grained), or GitHub App", "Yes (App)"],
        ["GitHub Enterprise Server", "PAT or App, custom base URL", "Yes (App)"],
        ["GitLab", "Personal or Project Access Token", "Yes (group token)"],
        ["Bitbucket Cloud", "Workspace Access Token", "Yes (workspace token)"],
        ["Bitbucket Data Center", "HTTP token, custom base URL", "Yes"],
        ["Bare git (SSH/HTTPS)", "Deploy key or HTTPS basic auth", "No (per-repo only)"],
      ]} />
      <Step n={1} title="Open the repo wizard">
        <strong>Repositories → + Add Repository</strong>. Choose the provider.
      </Step>
      <Step n={2} title="Provide credentials">
        Paste the access token or upload the SSH deploy key. The required scope is read-only:
        GitHub <code>repo:read</code>, GitLab <code>read_repository</code>, Bitbucket <code>repository:read</code>.
      </Step>
      <Step n={3} title="Pick repositories">
        For org-level connectors, the wizard lists every repository the credentials can see. Tick the ones to
        onboard. Bulk import is supported (CSV upload of <code>https URL</code> per line).
      </Step>
      <Step n={4} title="Set defaults">
        Choose a default branch (default: HEAD), schedule (daily / weekly / on-push), and Business Unit.
      </Step>

      <H2>Repository Configuration</H2>
      <ul className="space-y-2 my-3">
        <Li><strong>Branches</strong> — scan one branch (HEAD), all default-branch + protected branches, or a custom allow-list.</Li>
        <Li><strong>Schedule</strong> — <code>manual</code> | <code>hourly</code> | <code>daily</code> | <code>weekly</code> | <code>cron(...)</code>.</Li>
        <Li><strong>Business Unit</strong> — drives access control and report attribution.</Li>
        <Li><strong>Tags</strong> — free-form labels; available as a filter facet on findings.</Li>
        <Li><strong>Path excludes</strong> — globs that the scanner skips (in addition to platform-wide vendored-file skips).</Li>
      </ul>

      <H2>Triggering Scans</H2>
      <Code>{`# Manual scan (full)
curl -X POST https://vooda.acme.com/api/v1/repositories/repo_01H.../scan \\
  -H "Authorization: Bearer $TOKEN"

# Scoped scan
curl -X POST https://vooda.acme.com/api/v1/repositories/repo_01H.../scan \\
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{"branch":"main","force_full":true}'

# Webhook trigger — see the Connect integrations guide for HMAC payload
POST /api/v1/webhooks/github`}</Code>

      <H2>Scan Types</H2>
      <Tbl headers={["Mode", "When", "Cost"]} rows={[
        ["Full", "First scan, force_full=true, force-push, or rule-pack version change", "All files × all rules"],
        ["Incremental", "Subsequent scans on the same branch", "Only files in the diff (last_scanned_commit..HEAD) — 5-15× faster"],
        ["Cache hit", "File content sha + rule_pack_version unchanged since previous scan", "Findings replayed from file_scan_cache, no detection cost"],
      ]} />
      <P>
        The file-level cache is keyed on <code>(content_sha, rule_pack_version, scan_scope)</code>. When a rule
        pack version changes (rules added / edited / removed), all cached entries for the old version are
        invalidated automatically — there is no risk of stale results.
      </P>

      <H2>Branch Checkpoints</H2>
      <P>
        Each (repository, branch) pair has its own watermark stored in <code>repo_branch_checkpoints</code>.
        On every successful scan the watermark is updated to <code>HEAD</code>. The next incremental scan only
        examines commits in <code>last_scanned_commit..HEAD</code>.
      </P>
      <Note>Force-pushed branches are detected automatically: when the prior <code>last_scanned_commit</code> is no longer reachable from <code>HEAD</code>, the scan falls back to a full scan on that branch.</Note>

      <H2>Viewing Scan History</H2>
      <P>
        Open the repository and click the <strong>Scans</strong> tab. Each row shows <em>scan job ID, trigger,
        status, duration, files scanned, new findings, resolved findings (tombstones)</em>.
      </P>
      <Endpoint method="GET" path="/api/v1/repositories/{id}/scans" desc="Paginated scan history" />
      <Endpoint method="GET" path="/api/v1/scan-jobs/{id}" desc="Detailed job record incl. logs" />
      <Endpoint method="WS" path="/api/v1/ws/scan/{scan_job_id}" desc="Live progress stream (token via ?token=<jwt>)" />

      <H2>Removing a Repository</H2>
      <Step n={1} title="Disconnect">
        <strong>Repositories → &lt;repo&gt; → Settings → Disconnect</strong>. Stops future scans. All findings
        and history remain readable; the repo is marked <em>archived</em>.
      </Step>
      <Step n={2} title="Delete (irreversible)">
        From the archived state, <strong>Delete</strong> hard-deletes the repository, its scans, and its findings.
        A summary record is preserved in the audit log.
      </Step>
      <Warn>Deleting a repository removes all of its findings. If a finding is referenced by a compliance report or external ticket, archive instead.</Warn>

      <NextSteps items={[
        { label: "Findings", href: "/docs?section=findings", desc: "What comes back after a scan and how to triage it." },
        { label: "CI/CD Integration", href: "/docs?section=cicd", desc: "Automate scans on every push + fail PRs on critical." },
        { label: "API Reference — Repositories", href: "/docs?section=api", desc: "Connect + scan + retrieve via API." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 6 — SCAN SOURCES (SaaS, non-Git)
// ═══════════════════════════════════════════════════════════════
function SourcesContent() {
  return (
    <>
      <RoleBox role="security-lead or developer with sources:write" see="api" />

      <H2>Supported Source Types</H2>
      <P>
        Beyond Git repositories, Vooda scans non-Git source types. The community edition ships <strong>three
        families</strong>; the Sources catalog at <ExtLink href="http://localhost:3000/sources">/sources</ExtLink>
        shows them grouped by family.
      </P>

      <Img src="/docs/screenshots/sources-catalog.png" alt="Sources catalog" caption="Figure 6.1 — The Sources catalog at /sources. Each tile drills into a sub-catalog of providers in that family. Click any provider tile to launch the connection wizard." />

      <Tbl headers={["Family", "Sub-catalog URL", "Source types"]} rows={[
        ["Issue Tracking", <code key="1">/sources/issue-tracking</code>, "Jira, ServiceNow, Azure DevOps Boards"],
        ["Cloud Storage", <code key="2">/sources/cloud-storage</code>, "Amazon S3, Azure Blob Storage, Google Cloud Storage"],
        ["DevOps", <code key="3">/sources/devops</code>, "CI/CD Logs, Container Registry, Terraform State"],
      ]} />
      <Note><strong>Enterprise-only source families.</strong> Team chat (Slack, Microsoft Teams), wikis (Confluence, Notion, SharePoint), and additional ticketing and object-store connectors are part of the Enterprise edition — not the community catalog. GitHub / GitLab / Bitbucket <em>code</em> is always scannable via the repository scan path.</Note>

      <H2>The Connection Wizard — General Flow</H2>
      <Step n={1} title="Open the catalog">
        Click <strong>Sources</strong> in the left sidebar (icon: stacked database). Pick a family tile, then a provider tile.
      </Step>
      <Step n={2} title="Fill in credentials">
        Required fields show a red asterisk and a "Required" tooltip on hover. Field labels match upstream provider
        terminology — e.g. Jira uses an <em>API Token</em>, AWS uses <em>Access Key ID</em>.
      </Step>
      <Step n={3} title="Set scope">
        Pick channels / projects / buckets / spaces. <code>*</code> means "everything I have access to".
        Comma-separated lists are accepted.
      </Step>
      <Step n={4} title="Test connection">
        Click <strong>Test Connection</strong>. Vooda calls the provider's auth endpoint with your credentials and reports
        back either ✓ "Connection OK" or the literal error message returned by the provider (e.g. <code>401 Unauthorized</code>
        for Atlassian, <code>AccessDenied</code> for AWS).
      </Step>
      <Step n={5} title="Set the schedule">
        Choose <em>on demand</em>, <em>hourly</em>, <em>daily</em>, or <em>weekly</em>.
      </Step>
      <Step n={6} title="Save">
        Click <strong>Save</strong>. Vooda runs an initial baseline scan immediately and then follows the schedule.
        Live progress streams in the source row and on the WebSocket at <code>/api/v1/ws/scan/&#123;scan_job_id&#125;?token=&lt;jwt&gt;</code>.
      </Step>

      <H2>Jira (Atlassian)</H2>
      <P>One Atlassian API token authenticates to Jira on your Atlassian Cloud site. Vooda uses Basic auth (<code>email + token</code>) directly against the legacy REST APIs — same pattern Atlassian recommends for "scripts and automations" (server-to-server).</P>

      <Warn>
        Atlassian now offers <strong>two</strong> token types. Vooda only accepts <strong>classic</strong> tokens.
        The newer <em>"Create API token with scopes"</em> option produces credentials for OAuth 2.0 (3LO) apps — they
        require an authorization-code exchange Vooda's adapter does not yet implement. Pick the button labeled
        simply <strong>"Create API token"</strong>, not the one with "with scopes" in the name. If you only see the
        scoped option in your tenant, OAuth 3LO support is on the Vooda roadmap; in the meantime, contact your
        Atlassian admin to provision a service account with classic-token access.
      </Warn>

      <H3>Service-Account Pattern (recommended)</H3>
      <P>
        Create a dedicated Atlassian user (e.g. <code>vooda-scanner@acme.com</code>) instead of using a human's
        account. Why this matters:
      </P>
      <ul className="space-y-2 my-3">
        <Li>Token rotation cadence is decoupled from HR processes — when a human leaves the team, the scanner keeps working.</Li>
        <Li>The token has well-defined permissions you can audit at one place: that user's Jira project membership.</Li>
        <Li>If the token leaks, revoking impacts only this scanner, not a real human's session.</Li>
      </ul>

      <H3>Generate an API Token</H3>
      <Step n={1} title="Sign in as the service-account user">
        Open <ExtLink href="https://id.atlassian.com/manage-profile/security/api-tokens">https://id.atlassian.com/manage-profile/security/api-tokens</ExtLink>
        as the user whose email you'll use for auth.
      </Step>
      <Step n={2} title="Click 'Create API token' — NOT 'with scopes'">
        Label: <code>Vooda Secret Scanner</code>. Click <strong>Create</strong>. Copy the token immediately —
        Atlassian only shows it once. Classic tokens look like <code>ATATT3xFf…=XXXXXXXX</code> (192 chars).
      </Step>
      <Step n={3} title="Grant the user the permissions Vooda needs">
        Vooda's adapter is <strong>read-only</strong>. The user account must have:
        <ul className="space-y-1 mt-2">
          <Li><strong>Jira:</strong> <em>Browse Projects</em> permission on every project you want scanned.</Li>
        </ul>
        No write/admin permissions required. Jira admins can grant Browse via project role membership.
      </Step>

      <H3>Connect Jira in Vooda</H3>
      <Step n={1} title="Open Sources → Issue Tracking → Jira">
        Direct link: <ExtLink href="http://localhost:3000/sources/issue-tracking">/sources/issue-tracking</ExtLink>.
        Fill in the Atlassian Cloud Workspace URL, the account email, the classic API token, and a
        <strong>Projects</strong> scope filter (project keys, e.g. <code>DEVOPS,SEC,PLATFORM</code>; <code>*</code> for all).
      </Step>

      <H3>Atlassian Troubleshooting (Observed Errors)</H3>
      <Tbl headers={["Symptom", "Likely cause", "Fix"]} rows={[
        ["401 + x-seraph-loginreason: AUTHENTICATED_FAILED", "Token rejected at Atlassian's edge — most often the token was auto-revoked by Atlassian's leak scanner because it passed through a public-facing channel (chat, paste site, log)", "Generate a fresh classic token. Don't paste it into untrusted channels — use the Vooda wizard directly."],
        ["401 + x-failure-category: FAILURE_CLIENT_AUTH_MISMATCH", "Scoped token (the 'with scopes' variant) used against Basic auth — Atlassian only accepts these via OAuth 3LO", "Revoke and create a classic token instead (the 'Create API token' button without 'with scopes')."],
        ["Test Connection passes but scan returns 0 items", "Two-stage probe was added 2026-05-08, so this should be rare. Older instances may pass on /spaces but fail on /pages.", "Re-run Test Connection — the new probe will surface the page-read failure with an explicit error."],
      ]} />

      <H2>AWS S3</H2>

      <H3>Create a Read-Only IAM User</H3>
      <P>
        For least-privilege, create a dedicated IAM user with read-only access. Open the
        <ExtLink href="https://us-east-1.console.aws.amazon.com/iam/home#/users">IAM console → Users</ExtLink>.
      </P>
      <Step n={1} title="Click 'Create user'">
        Username: <code>vooda-s3-reader</code>. Do <strong>not</strong> tick "Provide user access to the AWS Management Console".
      </Step>
      <Step n={2} title="Attach policy">
        On the permissions step, choose <em>Attach policies directly</em> → <em>Create policy</em>. Use this JSON:
        <Code>{`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:GetObject"],
      "Resource": [
        "arn:aws:s3:::acme-backups",
        "arn:aws:s3:::acme-backups/*",
        "arn:aws:s3:::acme-artifacts",
        "arn:aws:s3:::acme-artifacts/*"
      ]
    },
    { "Effect": "Allow", "Action": ["s3:ListAllMyBuckets"], "Resource": "*" }
  ]
}`}</Code>
        Name the policy <code>VoodaS3Reader</code>. Attach it to the user.
      </Step>
      <Step n={3} title="Create access key">
        After the user is created, open the user → <em>Security credentials</em> → <em>Create access key</em>
        → use case <em>Application running outside AWS</em>. Copy <strong>Access key ID</strong> and
        <strong> Secret access key</strong>. AWS only shows the secret once.
      </Step>

      <H3>Connect S3 in Vooda</H3>
      <Step n={1} title="Open Sources → Cloud Storage → AWS S3">
        Direct link: <ExtLink href="http://localhost:3000/sources/cloud-storage">/sources/cloud-storage</ExtLink>.
      </Step>
      <Step n={2} title="Fill the wizard">
        <div className="mt-3">
          <FieldRef label="Access Key ID" required type="AKIA..." />
          <FieldRef label="Secret Access Key" required type="40 chars" hint="Stored encrypted at rest in Vooda." />
          <FieldRef label="Region" required type="e.g. us-east-1" hint="The region of the buckets you intend to scan. Multi-region scans run separate sources." />
          <FieldRef label="Buckets" required type="* or comma-separated names" hint="* lists every bucket the IAM user can see (uses s3:ListAllMyBuckets)." />
          <FieldRef label="Prefix glob" type="prod/**" hint="Optional. Limits scan to objects whose key matches the prefix." />
          <FieldRef label="Max object size (MB)" type="integer, default 50" hint="Objects larger than this are skipped (raise carefully — large files inflate scan time)." />
        </div>
      </Step>
      <Tip>Prefer assume-role over long-lived access keys. Vooda supports providing a role ARN + external ID — the worker assumes the role at scan time. This eliminates static-key rotation.</Tip>

      <H2>Other Source Types — Quick Reference</H2>
      <Tbl headers={["Source", "Auth method", "Where to generate the credential"]} rows={[
        ["Google Cloud Storage", "HMAC keys (S3-compatible) — access_key_id + secret_access_key", <ExtLink key="gcs" href="https://console.cloud.google.com/storage/settings">console.cloud.google.com/storage/settings</ExtLink>],
        ["Terraform State (request access)", "Backend-specific (S3 access key / TF Cloud token / GCS HMAC / Azure access key)", "Depends on backend — e.g. S3 IAM user with s3:GetObject on the state bucket, or app.terraform.io → Settings → Tokens for TF Cloud. Adapter on roadmap — see the community-catalog note above."],
        ["Kubernetes Secrets (request access)", "ServiceAccount token + cluster CA cert + namespace scope", "kubectl create + RoleBinding granting secrets.get + secrets.list on target namespaces. Adapter on roadmap — see the community-catalog note above."],
        ["Datadog Logs (request access)", "API Key + Application Key + site (datadoghq.com / .eu / us5 / ap1)", "Datadog → Organization Settings → API Keys + Application Keys. Adapter on roadmap — see the community-catalog note above. Splunk + Sumo Logic to follow when demand surfaces."],
        ["ServiceNow", "Basic auth or OAuth client_credentials", "ServiceNow → System OAuth → Application Registry"],
        ["Azure DevOps Boards", "Personal Access Token, Work Items (Read) scope", "dev.azure.com/{org}/_usersSettings/tokens"],
        ["Generic webhook", "HMAC shared secret (you generate)", "Vooda generates a receiver URL and you POST to it from any system"],
      ]} />
      <H2>Scheduling &amp; Incremental Behavior</H2>
      <Tbl headers={["Schedule", "When to use"]} rows={[
        ["manual", "On-demand only — useful during onboarding to validate scope before turning on automation."],
        ["hourly", "High-velocity sources (prod CI/CD logs, active issue trackers)."],
        ["daily", "The recommended default for most SaaS sources."],
        ["weekly", "Slow-moving wikis, archives."],
        [<code key="c">cron(0 */6 * * *)</code>, "Custom cadence. Standard 5-field cron expression."],
      ]} />
      <P>
        After the baseline scan, every subsequent scan is <strong>incremental</strong> — Vooda only fetches content created
        or modified since the last successful run, using the source's native cursor (Slack <code>oldest</code>,
        Atlassian <code>updated &gt;= last_run</code>, S3 <code>LastModified</code>, etc.).
      </P>

      <H2>Weekly Full Sweep</H2>
      <P>
        Independent of the chosen schedule, Vooda runs a <strong>full sweep</strong> every 7 days on each source.
        The sweep ignores the incremental cursor and re-fetches everything within the configured scope. This catches:
      </P>
      <ul className="space-y-2 my-3">
        <Li><strong>Back-edited content</strong> — many SaaS APIs don't return back-edited items in incremental queries (some SaaS sources). The sweep catches edits to old content.</Li>
        <Li><strong>Deleted content</strong> — items that previously had a finding but have since been deleted upstream are auto-resolved as <code>RESOLVED_ITEM_DELETED</code>, so your finding queue stays accurate.</Li>
      </ul>
      <Note>The sweep runs as a Celery beat task (<code>weekly_source_full_sweep_task</code>, 6 h cadence — gated per-source by <code>last_full_sweep_at</code>). No configuration required.</Note>

      <H2>Viewing Source Scan Results</H2>
      <P>
        Findings from sources show a <em>Source</em> badge in the Findings list. The detail panel shows the
        upstream URL (Slack permalink, Jira ticket URL, S3 object key) so you can pivot directly to the leaked content.
      </P>
      <Code>{`# Filter the finding list to one source type
GET /api/v1/findings?source_type=slack&severity=critical

# Get the upstream URL for a finding
GET /api/v1/findings/finding_01H...
# Response includes source_metadata.permalink, e.g.
# "https://acme.slack.com/archives/C012/p1714765432000400"`}</Code>

      <NextSteps items={[
        { label: "Findings", href: "/docs?section=findings", desc: "How source findings render alongside git findings." },
        { label: "Integrations", href: "/docs?section=integrations", desc: "Configure the upstream connectors these sources rely on." },
        { label: "API Reference — Scan Sources", href: "/docs?section=api", desc: "Create + trigger source scans programmatically." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 7 — FINDINGS
// ═══════════════════════════════════════════════════════════════
function FindingsContent() {
  return (
    <>
      <RoleBox role="developer (read + triage own scope); security-lead (any)" see="api" />

      <H2>Finding Lifecycle</H2>
      <Code>{`new → triaged → remediated
                  → suppressed
                  → false_positive
                  → accepted_risk
        ↘ tombstone (item deleted upstream)`}</Code>
      <P>Two parallel state machines apply:</P>
      <Tbl headers={["Field", "Values"]} rows={[
        ["review_status", "UNREVIEWED → REVIEWED → ACCEPTED_RISK"],
        ["classification", "TRUE_POSITIVE | FALSE_POSITIVE | TEST_CREDENTIAL | RESOLVED_FILE_DELETED | RESOLVED_ITEM_DELETED"],
        ["remediation_status", "NONE → IN_PROGRESS → ROTATED | REVOKED"],
      ]} />

      <H2>Finding Attributes</H2>
      <Tbl headers={["Attribute", "Description"]} rows={[
        ["severity", "critical | high | medium | low | info"],
        ["rule_id", "Stable identifier of the detector (e.g. AWS-001, GH-003)"],
        ["classification", "TP / FP / Test / tombstone family — see the Triage findings guide"],
        ["review_status", "UNREVIEWED | REVIEWED | ACCEPTED_RISK"],
        ["remediation_status", "NONE | IN_PROGRESS | ROTATED | REVOKED"],
        ["ai_confidence", "0.0–1.0, post-calibration"],
        ["ai_confidence_raw", "0.0–1.0, pre-calibration (debug)"],
        ["validation_status", "active | inactive | not_validated | error"],
        ["tags", "Free-form labels (string[])"],
        ["source_metadata", "Provider-specific: { repo, branch, commit_sha, file, line, slack_channel_id, jira_issue, s3_key, ... }"],
      ]} />

      <H2>Finding List</H2>
      <P>Filterable on every attribute above, plus date range, business unit, and source type. URL-shareable filters.</P>
      <Img src="/docs/screenshots/findings.png" alt="Findings list" caption="Figure 7.3 — The Findings list at /findings. Each row shows masked value, severity, validity (verifier result), status (UNREVIEWED / REVIEWED / triage classification), and post-calibration confidence." />
      <Code>{`GET /api/v1/findings?
  severity=critical,high
  &review_status=UNREVIEWED
  &repo_id=repo_01H...
  &since=2026-04-01
  &limit=100&offset=0`}</Code>
      <P>Results are paginated (<code>limit</code> max 200). Sortable on <code>severity</code>, <code>created_at</code>, <code>ai_confidence</code>.</P>

      <H2>Finding Detail</H2>
      <P>Click any row in the list. The detail panel has five tabs:</P>
      <Grid2>
        <InfoCard title="Overview">Severity, rule, masked value, validation status, calibrated and raw confidence, BU.</InfoCard>
        <InfoCard title="Code" color="orange">Source-file context, secret highlighted, commit & blame info.</InfoCard>
        <InfoCard title="AI Analysis" color="purple">Reasoning, evidence, and confidence. Verifier-bypass findings show the explicit reason "Credential authenticated against &lt;provider&gt; API".</InfoCard>
        <InfoCard title="Rotation" color="red">Provider-specific rotation playbook (the Remediate and rotate secrets guide).</InfoCard>
        <InfoCard title="History" color="green">Every state change, comment, and audit event for this finding.</InfoCard>
      </Grid2>

      <H2>Manual Triage</H2>
      <Step n={1} title="Open the finding">From the list, click any row.</Step>
      <Step n={2} title="Choose a classification">Click <strong>True Positive</strong>, <strong>False Positive</strong>, <strong>Test Credential</strong>, or <strong>Accepted Risk</strong>.</Step>
      <Step n={3} title="Add a justification (Accepted Risk only)">A free-text justification is required for Accepted Risk and is logged for auditors.</Step>
      <Endpoint method="PATCH" path="/api/v1/findings/{id}" desc="Body: { classification, review_status, comment }" />

      <H2>Bulk Actions</H2>
      <P>Select multiple findings via checkbox or <em>Select all matching filter</em>. Bulk operations:</P>
      <ul className="space-y-2 my-3">
        <Li><strong>Bulk triage</strong> — apply the same classification to all selected.</Li>
        <Li><strong>Bulk tag / untag</strong> — add or remove labels.</Li>
        <Li><strong>Bulk assign</strong> — assign owner / Business Unit.</Li>
        <Li><strong>Bulk export</strong> — download in CSV / JSON / SARIF.</Li>
      </ul>
      <Endpoint method="POST" path="/api/v1/findings/bulk" desc="Body: { ids[] | filter, action, payload }" />

      <H2>Tags</H2>
      <P>Tags are free-form, tenant-scoped labels. Create them on the fly during triage. The finding list and the dashboard support filter-by-tag.</P>

      <H2>Saved Views</H2>
      <P>
        Any combination of filters can be saved as a Saved View. Views can be private, shared with a BU, or
        org-wide. Set a view as <em>default</em> to land on it whenever you open the Findings page.
      </P>
      <Endpoint method="POST" path="/api/v1/saved-views" desc="Body: { name, filters, scope, default }" />

      <H2>Finding Export</H2>
      <Tbl headers={["Format", "Endpoint", "Use"]} rows={[
        ["CSV", "GET /api/v1/findings/export?format=csv", "Spreadsheets, BI"],
        ["JSON", "GET /api/v1/findings/export?format=json", "Programmatic"],
        ["SARIF 2.1", "GET /api/v1/findings/export?format=sarif", "GitHub code scanning, Azure DevOps Advanced Security"],
      ]} />

      <H2>Finding Import</H2>
      <P>
        Push results from external scanners into Vooda using SARIF. The import normalizes external rule IDs,
        deduplicates against existing findings, and enriches with Vooda metadata.
      </P>
      <Code>{`curl -X POST https://vooda.acme.com/api/v1/findings/import \\
  -H "Authorization: ApiKey vk_live_..." \\
  -H "Content-Type: application/sarif+json" \\
  --data-binary @results.sarif

# Response
{ "imported": 142, "deduplicated": 18, "errors": 0 }`}</Code>

      <H2>Correlations</H2>
      <P>
        The same secret appearing in multiple files, branches, or sources is grouped under a single
        <em> correlation</em>. Triage decisions on the correlation propagate to all members. The correlation
        key is a SHA-256 of the masked secret value plus the rule_id.
      </P>
      <Tip>If you rotate a secret, its correlation marks every member as <code>ROTATED</code> in one operation.</Tip>

      <NextSteps items={[
        { label: "AI Triage Engine", href: "/docs?section=ai-triage", desc: "How verdicts and confidence scores get computed." },
        { label: "Remediation & Rotation", href: "/docs?section=remediation", desc: "Fix what's found — rotation playbooks + PR-on-approve." },
        { label: "Glossary", href: "/docs?section=glossary", desc: "TP / FP / Incident / Verified-live — the precise definitions." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 8 — AI TRIAGE ENGINE
// ═══════════════════════════════════════════════════════════════
function AiTriageContent() {
  return (
    <>
      <RoleBox role="security-lead (configuration); any user (review AI decisions)" see="api" />

      <H2>How AI Triage Works</H2>
      <P>The AI engine runs as the third stage of the four-stage pipeline. Inputs to the LLM:</P>
      <ul className="space-y-2 my-3">
        <Li>Masked secret value + rule_id</Li>
        <Li>50 lines of surrounding code context (anchored on the match line)</Li>
        <Li>Verifier signal (<em>active</em> / <em>inactive</em> / <em>not validated</em>)</Li>
        <Li>Pattern catalog excerpt + 14 gold-derived few-shot examples</Li>
        <Li>Per-tenant calibration table for the (scanner, rule, category) tuple</Li>
      </ul>
      <P>
        Findings are processed in batches (default 20). Identical (rule, file, snippet-fingerprint) tuples
        deduplicate into a single LLM call so noisy patterns don't compound cost.
      </P>

      <H2>Supported AI Providers</H2>
      <Tbl headers={["Provider", "Recommended models", "Notes"]} rows={[
        ["Anthropic", "claude-sonnet-4.5, claude-opus-4", "Highest accuracy on code context."],
        ["OpenAI", "gpt-4o, gpt-4-turbo", "Lowest latency at high concurrency."],
        ["Google", "gemini-2.5-pro, gemini-flash", "Strong cost-per-finding."],
        ["Mistral / OpenAI-compatible", "mistral-small-3.2-24b, mixtral", "Self-host friendly. Default in benchmark."],
        ["Azure OpenAI / OpenRouter", "any deployment id", "OpenAI-compatible endpoint pattern."],
      ]} />

      <H2>Configuring an AI Provider</H2>
      <Step n={1} title="Open AI Models">
        <strong>Settings → Integrations → AI Providers → + New Provider</strong>.
      </Step>
      <Step n={2} title="Enter credentials and discover models">
        Pick the provider, paste the API key, optionally set a custom base URL. Click <strong>Discover Models</strong> —
        Vooda calls the provider's <code>GET /models</code> and lists what you can use.
      </Step>
      <Step n={3} title="Pick model + role">
        Each provider can hold multiple models, each routed to one or more <em>tasks</em>:
        <code> triage</code>, <code>verifier-fallback</code>, <code>remediation</code>, <code>rotation-playbook</code>.
      </Step>
      <Step n={4} title="Set rate limits">
        <strong>Max requests / min</strong> and <strong>Max tokens / min</strong> are enforced per provider to
        prevent runaway cost. The worker queues over-limit calls.
      </Step>

      <H2>Accuracy Feedback (Calibration Loop)</H2>
      <P>
        Every TP/FP correction your team makes feeds the per-tenant calibration table, keyed on
        <code> (scanner, rule_id, category)</code>. After ≥10 corrections per key, the AI's raw confidence is
        multiplied by the learned factor (clipped to [0.30, 1.30]).
      </P>
      <Note>The calibration cache is stored in Redis and refreshes within seconds of a correction. No prompt edits, model retraining, or restart required.</Note>

      <H2>AI Engine Settings</H2>
      <Tbl headers={["Setting", "Default", "Effect"]} rows={[
        ["batch_size", "20", "Findings per LLM call. Larger = cheaper, higher latency, higher max-token risk."],
        ["timeout_seconds", "60", "Per-call timeout."],
        ["retry_attempts", "3", "Exponential backoff on 429 / 5xx."],
        ["concurrency_per_provider", "8", "Max in-flight LLM calls per provider."],
        ["confidence_threshold_tp", "0.65", "Auto-mark TP if calibrated confidence ≥ this and verifier is active."],
        ["confidence_threshold_fp", "0.20", "Auto-mark FP if calibrated confidence ≤ this. Else surface to human."],
      ]} />

      <H2>False-Positive Reduction</H2>
      <P>
        FPs are eliminated at four layers, in order: (1) scanner path-skip for vendored files;
        (2) per-rule path exclusions; (3) pre-AI deduplication of identical snippets;
        (4) AI triage with per-tenant calibration. Tuning guidance:
      </P>
      <ul className="space-y-2 my-3">
        <Li><strong>Too many FPs surfaced</strong> — raise <code>confidence_threshold_fp</code> from 0.20 to 0.30. The AI auto-suppresses more.</Li>
        <Li><strong>Suspect TPs being suppressed</strong> — lower <code>confidence_threshold_fp</code> to 0.10, or add a custom detector (the Write a custom detector guide) so the rule fires explicitly.</Li>
        <Li><strong>Specific repo is noisy</strong> — set a path-glob suppression for that repo.</Li>
      </ul>

      <H2>AI Triage Audit Trail</H2>
      <P>Every AI decision is recorded in <code>ai_triage_events</code> with:</P>
      <ul className="space-y-2 my-3">
        <Li>Provider, model, prompt version</Li>
        <Li>Raw confidence, calibrated confidence, calibration factor applied</Li>
        <Li>LLM reasoning text (cap 4000 chars)</Li>
        <Li>Tokens in / out, latency_ms</Li>
        <Li>Subsequent human override, if any</Li>
      </ul>
      <Endpoint method="GET" path="/api/v1/findings/{id}/ai-events" desc="Per-finding AI decision log" />
      <Endpoint method="GET" path="/api/v1/audit?event=ai_triage" desc="Org-wide AI audit stream" />

      <NextSteps items={[
        { label: "Detection Accuracy", href: "/docs?section=accuracy", desc: "How the pipeline catches real secrets while cutting false positives." },
        { label: "Findings", href: "/docs?section=findings", desc: "Where AI verdicts surface in the UI + how to override." },
        { label: "Custom Detectors", href: "/docs?section=detectors", desc: "Add your own regex rules — triaged through the same AI pipeline." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// PLACEHOLDER for sections 9-22 — added in subsequent edits
// ═══════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════
// SECTION 9 — POLICIES & GATES
// ═══════════════════════════════════════════════════════════════
function DetectorsContent() {
  return (
    <>
      <RoleBox role="security-lead with detectors:write" see="api" />

      <H2>When to Use Custom Detectors</H2>
      <P>
        Use a custom detector when your organization issues credentials in a proprietary format that the
        built-in rule pack does not yet cover. Examples: internal SSO bearer tokens, machine-to-machine HMAC
        signing keys, vendor-specific API keys you've negotiated as a private contract.
      </P>

      <H2>Creating a Detector</H2>
      <Step n={1} title="Open the detector editor">
        <strong>Settings → Custom Detectors → + New Detector</strong>.
      </Step>
      <Step n={2} title="Provide identification">
        <ul className="space-y-1 mt-2">
          <Li><code>rule_id</code> — stable identifier, e.g. <code>ACME-CUSTOM-001</code>. Required.</Li>
          <Li><code>name</code> — human-readable label.</Li>
          <Li><code>provider</code> — the provider tag (used in the dashboard).</Li>
          <Li><code>severity</code> — <em>critical / high / medium / low</em>.</Li>
        </ul>
      </Step>
      <Step n={3} title="Define the pattern">
        <ul className="space-y-1 mt-2">
          <Li><code>regex</code> — Python-flavoured regex. Use a non-capturing group around the secret value.</Li>
          <Li><code>keywords</code> (optional, recommended) — list of strings that must also appear within 200 characters of the match. Drastically reduces false positives.</Li>
          <Li><code>entropy_min</code> (optional) — Shannon entropy floor on the matched value.</Li>
          <Li><code>confidence</code> — base confidence 0.0–1.0 before AI triage.</Li>
        </ul>
      </Step>
      <Step n={4} title="Test cases">
        Provide ≥1 positive test case and ≥1 negative test case. Save is blocked until both pass.
      </Step>
      <Step n={5} title="Activate">
        Toggle <strong>Active</strong>. Newly active detectors apply on the next scan; previously cached files are
        force-rescanned (file-cache invalidates on rule_pack_version change).
      </Step>

      <H2>Validating a Pattern</H2>
      <Code>{`curl -X POST https://vooda.acme.com/api/v1/detectors/validate \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "regex": "acme_(?:live|test)_[A-Za-z0-9]{32}",
    "keywords": ["acme", "API_KEY"],
    "entropy_min": 4.0,
    "test_cases": [
      { "input": "acme_live_AbCd...", "expect": "match" },
      { "input": "acme_demo_123",     "expect": "no_match" }
    ]
  }'

# Response
{ "valid": true, "test_results": [{"expected":"match","actual":"match"},{"expected":"no_match","actual":"no_match"}] }`}</Code>

      <H2>Enabling and Disabling Detectors</H2>
      <P>Activation scope is configurable:</P>
      <Tbl headers={["Scope", "Effect"]} rows={[
        ["org", "Active across the entire tenant. Default."],
        ["business_unit", "Active only on repositories and sources within the BU."],
        ["repo glob", "Active only on matching repos (e.g. acme/payments-*)."],
      ]} />
      <Endpoint method="POST" path="/api/v1/detectors" desc="Create custom detector" />
      <Endpoint method="PATCH" path="/api/v1/detectors/{id}" desc="Edit (active toggle, scope, regex)" />
      <Endpoint method="DELETE" path="/api/v1/detectors/{id}" desc="Permanently remove" />

      <H2>Detector Precedence</H2>
      <P>Resolution order when multiple detectors match the same string:</P>
      <ol className="space-y-2 my-3 list-decimal list-inside text-[15px] text-slate-400">
        <li>Verifier-active findings always win (provider confirmed the credential).</li>
        <li>Built-in provider-specific rule with format check (highest specificity).</li>
        <li>Custom detector with keywords required and matched.</li>
        <li>Custom detector without keywords.</li>
        <li>Generic entropy-based detection.</li>
      </ol>
      <Tip>If a custom detector and a built-in detector both fire on the same string, only the highest-specificity finding is recorded — but both rule_ids are stored in <code>matched_rules</code> for audit transparency.</Tip>

      <NextSteps items={[
        { label: "AI Triage Engine", href: "/docs?section=ai-triage", desc: "How your custom detector's findings get classified." },
        { label: "API Reference — Custom Detectors", href: "/docs?section=api", desc: "CRUD + the test-regex endpoint." },
        { label: "Detection Accuracy", href: "/docs?section=accuracy", desc: "How Vooda catches real secrets while cutting false positives." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 11 — REMEDIATION & ROTATION
// ═══════════════════════════════════════════════════════════════
function RemediationContent() {
  return (
    <>
      <RoleBox role="developer (initiate); security-lead (approve, bulk, credential rotation)" see="api" />

      <H2>Remediation Workflow</H2>
      <Code>{`finding (TP) → plan_created → patch_generated → approval_pending → applied → verified
                                                   ↘ rejected → re-plan`}</Code>
      <P>
        Each finding can produce a remediation plan. The plan covers what to remove from code (or rotate at
        the provider), and contains the AI-generated patch and the rotation playbook.
      </P>

      <H2>Auto-Patch Generation</H2>
      <P>
        Vooda generates a Pull Request that removes the leaked secret and replaces it with an environment-variable
        reference. The PR description includes the finding ID, masked value, recommended vault path, and
        rotation guidance.
      </P>
      <Code>{`curl -X POST https://vooda.acme.com/api/v1/findings/finding_01H.../auto-patch \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{ "branch": "vooda/remove-secret-finding-01H...", "open_pr": true }'

# Response
{ "patch_id": "p_01H...", "pr_url": "https://github.com/acme/repo/pull/4242", "status": "pr_open" }`}</Code>
      <Warn>The auto-patch removes the secret from the working tree at <em>HEAD</em>. It does <strong>not</strong> rewrite history. Always rotate the credential in addition to removing the source-tree reference.</Warn>

      <H2>Approval Flow</H2>
      <P>
        Auto-patches require approval before merging. The approver must hold <code>findings:triage</code> on the
        repo's BU. The approval is recorded with actor, timestamp, and the patch diff hash so it cannot be
        forged retroactively.
      </P>

      <H2>Bulk Remediation</H2>
      <P>Group findings by correlation (the Triage findings guide) and apply the same patch across all members:</P>
      <Endpoint method="POST" path="/api/v1/correlations/{id}/bulk-remediate" desc="Generate one patch per affected file across all correlated findings" />

      <H2>MTTR Metrics</H2>
      <P>Mean Time to Remediate is calculated as <code>mean(remediated_at − detected_at)</code> across all findings remediated in the chosen window. Available per severity, per BU, per repo.</P>
      <Endpoint method="GET" path="/api/v1/metrics/mttr?window=30d&group_by=severity" desc="MTTR breakdown" />
      <Tip>The dashboard's MTTR card shows current vs prior 30-day windows so you can track whether your team is improving.</Tip>

      <H2>Credential Rotation</H2>
      <P>
        Vooda provides provider-specific rotation playbooks for 15+ providers. Rotation happens in the
        provider's console or API — Vooda guides the human operator and tracks status. Supported playbooks:
      </P>
      <Tbl headers={["Provider", "Method", "Rollback"]} rows={[
        ["AWS IAM access keys", "Create new key → deploy → delete old", "Yes (re-enable old key while still in 'created' state)"],
        ["GCP service account keys", "Create JSON key → deploy → delete old", "Yes"],
        ["Azure AD app secrets", "Add new client secret → deploy → remove old", "Yes"],
        ["GitHub PAT", "Generate new → deploy → revoke old", "No (revocation is permanent)"],
        ["GitLab token", "Same pattern as GitHub", "No"],
        ["Stripe API key", "Roll → deploy → previous key invalidates within 12h", "No"],
        ["Slack tokens", "Regenerate → reinstall app", "No"],
        ["Twilio / SendGrid / Datadog / NPM / PyPI / Database / Atlassian / Generic", "Provider-specific playbook in the finding detail panel", "Provider-dependent"],
      ]} />
      <H3>Initiating rotation</H3>
      <Endpoint method="POST" path="/api/v1/findings/{id}/rotate" desc="Mark rotation in progress; surfaces playbook" />
      <Endpoint method="POST" path="/api/v1/findings/{id}/rotation/complete" desc="Mark rotated; auto-resolves finding" />
      <Endpoint method="POST" path="/api/v1/findings/{id}/rotation/rollback" desc="Restore prior state (provider permitting)" />

      <H3>Git history warning</H3>
      <P>Rotating a credential does not remove it from git history. Use a history-rewriting tool to purge the secret from prior commits:</P>
      <Code>{`# Recommended: git filter-repo
git filter-repo --replace-text expressions.txt
# Or BFG
bfg --replace-text passwords.txt repo.git
git reflog expire --expire=now --all && git gc --prune=now --aggressive`}</Code>

      <NextSteps items={[
        { label: "Findings", href: "/docs?section=findings", desc: "Find what needs remediating." },
        { label: "Integrations", href: "/docs?section=integrations", desc: "Where rotation events get auto-routed (Jira, Slack, PagerDuty)." },
        { label: "API Reference — Remediation", href: "/docs?section=api", desc: "Programmatic remediation + rotation-event ledger." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 11 — INTEGRATIONS
// ═══════════════════════════════════════════════════════════════
function IntegrationsContent() {
  return (
    <>
      <RoleBox role="security-lead with integrations:write" see="api" />

      <Note>This section covers <strong>outbound integrations</strong> — destinations Vooda sends data to (alerts, tickets) — plus <strong>inbound non-source connectors</strong> like AI providers and webhook receivers. For <strong>inbound scan sources</strong> (Jira tickets, S3 buckets to be scanned), see <strong>the Connect a scan source guide — Scan Sources</strong>.</Note>

      <Img src="/docs/screenshots/integrations.png" alt="Integrations page" caption="Figure 16.1 — The Integrations hub at /integrations. Four categories in the community edition: AI Provider, Notifications, Webhooks (Inbound), and Ticketing. (Vault & Secret Managers and SIEM forwarding are Enterprise-only.)" />

      <H2>GitHub — Repository Scanner Integration</H2>
      <P><strong>Purpose:</strong> Clone repositories over HTTPS, receive push/PR webhook events, post commit-status checks, and (optionally) open auto-remediation PRs.</P>

      <H3>Choose: GitHub App vs Personal Access Token</H3>
      <Tbl headers={["Auth method", "When to use", "Trade-offs"]} rows={[
        ["GitHub App (recommended)", "Production / org-wide", "Per-repo permissions, auto-rotated installation tokens, fine-grained scopes, survives user offboarding"],
        ["Personal Access Token (PAT)", "Single user, dev only", "Simple to set up; tied to one user; revoked on offboarding; classic PATs grant broad access"],
        ["Fine-grained PAT", "Single repo, dev only", "Per-repo scoping; still tied to one user"],
      ]} />

      <H3>Option A — Install the Vooda GitHub App</H3>
      <Step n={1} title="Open the app's install page">
        Go to <ExtLink href="https://github.com/apps/vooda-secret-scanner">https://github.com/apps/vooda-secret-scanner</ExtLink>
        (replace with your private deployment's app URL if self-hosted). Click <strong>Install</strong>.
      </Step>
      <Step n={2} title="Pick the org and the repos">
        Choose your org. Select <em>All repositories</em> for org-wide coverage, or <em>Only select repositories</em>
        for a per-repo allowlist. Click <strong>Install</strong>.
      </Step>
      <Step n={3} title="Approve the requested permissions">
        The app requests:
        <ul className="space-y-1 mt-2">
          <Li><strong>Contents:Read</strong> — clone repository content for scanning</Li>
          <Li><strong>Metadata:Read</strong> — required automatically by GitHub</Li>
          <Li><strong>Pull requests:Write</strong> — open auto-remediation PRs (optional; only requested if Auto-Patch is enabled)</Li>
          <Li><strong>Commit statuses:Write</strong> — post the gate-check status on PRs</Li>
          <Li><strong>Webhooks:Read</strong> — receive push and pull-request events</Li>
        </ul>
        Click <strong>Approve &amp; install</strong>.
      </Step>
      <Step n={4} title="Capture the installation ID">
        After install, GitHub redirects to <code>https://github.com/settings/installations/&lt;installation_id&gt;</code>.
        Copy the numeric installation ID from the URL.
      </Step>
      <Step n={5} title="Connect in Vooda">
        Open <strong>Integrations → Webhooks (Inbound) → GitHub</strong>. Paste the installation ID.
        Click <strong>Test Connection</strong>. Vooda calls the GitHub App API to validate.
      </Step>

      <H3>Option B — Personal Access Token</H3>
      <Step n={1} title="Generate a fine-grained PAT">
        Go to <ExtLink href="https://github.com/settings/personal-access-tokens/new">https://github.com/settings/personal-access-tokens/new</ExtLink>.
        Token name: <code>vooda-scanner</code>. Expiration: 90 days max (rotation reminder).
      </Step>
      <Step n={2} title="Pick repository access">
        Choose <em>Only select repositories</em> and tick the repos to scan.
      </Step>
      <Step n={3} title="Pick repository permissions">
        Set:
        <ul className="space-y-1 mt-2">
          <Li><strong>Contents</strong> → Read</Li>
          <Li><strong>Metadata</strong> → Read (auto)</Li>
          <Li><strong>Pull requests</strong> → Write (only if Auto-Patch is enabled)</Li>
          <Li><strong>Commit statuses</strong> → Write</Li>
        </ul>
      </Step>
      <Step n={4} title="Generate and copy">
        Click <strong>Generate token</strong>. Copy immediately — GitHub only shows it once.
      </Step>
      <Step n={5} title="Add to Vooda">
        <strong>Repositories → + Add Repository</strong>. Paste the PAT. Test connection. Save.
      </Step>

      <H3>Webhook Setup (push and PR events)</H3>
      <P>
        GitHub Apps register webhooks automatically. For PAT-based integrations, configure a webhook manually:
      </P>
      <Step n={1} title="In your repo settings, open Webhooks">
        <code>https://github.com/&lt;org&gt;/&lt;repo&gt;/settings/hooks/new</code>.
      </Step>
      <Step n={2} title="Configure">
        <div className="mt-3">
          <FieldRef label="Payload URL" required type="url" hint="https://vooda.acme.com/api/v1/webhooks/github" />
          <FieldRef label="Content type" required type="application/json" />
          <FieldRef label="Secret" required type="HMAC shared secret" hint="Generate a 32+ char random string. Configure the same value in Integrations → Webhooks → GitHub." />
          <FieldRef label="Which events?" required type="Just push and pull request" />
        </div>
        Click <strong>Add webhook</strong>. GitHub immediately delivers a ping; Vooda's audit log shows the verification.
      </Step>

      <H3>GitHub Troubleshooting</H3>
      <Tbl headers={["Symptom", "Cause", "Fix"]} rows={[
        ["403 on clone", "App or PAT missing Contents:Read", "Reinstall app with corrected permissions, or regenerate PAT."],
        ["Webhook ping fails with 401", "HMAC secret mismatch", "Re-copy the secret from GitHub into Integrations → Webhooks → GitHub."],
        ["No PR commit-status appearing", "Commit statuses:Write missing", "Add the permission and reinstall."],
        ["Auto-PR fails with 403", "Pull requests:Write missing or branch protection blocks app", "Add app to bypass list in branch protection rules, or disable Auto-Patch."],
      ]} />

      <H2>GitLab</H2>
      <P><strong>Purpose:</strong> Repository scanning, MR scanning, push protection.</P>
      <P><strong>Auth:</strong> Personal or Group Access Token.</P>
      <P><strong>Required scopes:</strong> <code>read_repository</code>, <code>read_api</code>, <code>read_user</code>.</P>
      <P><strong>Setup:</strong> Generate a group token at <em>Group Settings → Access Tokens</em>, paste into <strong>Integrations → GitLab</strong>.</P>
      <P><strong>Revoke:</strong> revoke the token in GitLab; Vooda disconnects on next sync.</P>

      <H2>Bitbucket</H2>
      <P><strong>Purpose:</strong> Repository and pull-request scanning.</P>
      <P><strong>Auth:</strong> Workspace Access Token (Cloud) or HTTP token (Data Center).</P>
      <P><strong>Required scopes:</strong> <code>repository:read</code>, <code>pullrequest:read</code>.</P>

      <H2>Slack</H2>
      <P><strong>Purpose:</strong> outbound — finding alerts and optional slash commands. Configured as a notification channel.</P>
      <P><strong>Auth:</strong> Bot User OAuth Token (<code>xoxb-</code>).</P>
      <P><strong>Required scopes:</strong></P>
      <ul className="space-y-1 my-3">
        <Li><code>chat:write</code> — post alerts</Li>
        <Li><code>commands</code> — receive slash commands (optional)</Li>
      </ul>
      <P><strong>Setup:</strong> add a Slack channel under <strong>Integrations → Notifications</strong>.</P>

      <H2>Microsoft Teams</H2>
      <P><strong>Purpose:</strong> outbound finding alerts via Incoming Webhook.</P>
      <P><strong>Auth:</strong> webhook URL.</P>
      <P><strong>Setup:</strong> in Teams, <em>Channel → Connectors → Incoming Webhook → Configure</em>. Copy the URL into <strong>Integrations → Microsoft Teams</strong>.</P>
      <P><strong>Revoke:</strong> remove the connector in Teams.</P>

      <H2>Jira</H2>
      <P><strong>Purpose:</strong> outbound — auto-create issues from findings; inbound (the Connect a scan source guide) — scan tickets for secrets.</P>
      <P><strong>Auth:</strong> Atlassian API token (Basic over HTTPS).</P>
      <P><strong>Required scopes:</strong> the user must have <em>Browse Projects</em>, <em>Create Issues</em>, and <em>Edit Issues</em> on each target project.</P>
      <P><strong>Setup:</strong> generate a token at <code>id.atlassian.com/manage-profile/security/api-tokens</code>; configure project + issue type mapping in Vooda. Full walk-through in <code>docs/jira-integration.md</code>.</P>
      <P><strong>Status sync:</strong> Vooda pushes finding-state changes to Jira (TP → ticket created, ROTATED → ticket transitioned to <em>Done</em>). Reverse sync from Jira is opt-in.</P>

      <H2>ServiceNow</H2>
      <P><strong>Purpose:</strong> incident creation, CMDB attribute mapping for affected assets.</P>
      <P><strong>Auth:</strong> Basic auth or OAuth client_credentials.</P>
      <P><strong>Setup:</strong> in ServiceNow, create a service-account user with the <em>itil</em> role plus <em>cmdb_read</em>. Provide the instance URL and credentials in <strong>Integrations → ServiceNow</strong>.</P>

      <H2>Webhook Receivers (Inbound)</H2>
      <Tbl headers={["Receiver", "Endpoint", "Signature header"]} rows={[
        ["GitHub", "POST /api/v1/webhooks/github", "X-Hub-Signature-256 (HMAC-SHA256)"],
        ["GitLab", "POST /api/v1/webhooks/gitlab", "X-Gitlab-Token"],
        ["Bitbucket", "POST /api/v1/webhooks/bitbucket", "X-Hub-Signature"],
        ["Generic", "POST /api/v1/webhooks/generic/{slug}", "X-Vooda-Signature (HMAC-SHA256)"],
      ]} />
      <P>Each receiver verifies the signature using the shared secret configured at integration time. Signature mismatches return HTTP 401 and increment a Prometheus counter.</P>
      <Code>{`# Example: GitHub push event
POST /api/v1/webhooks/github
X-Hub-Signature-256: sha256=...
X-GitHub-Event: push
{
  "ref": "refs/heads/main",
  "after": "abc123...",
  "repository": { "full_name": "acme/api" }
}`}</Code>

      <H2>AI Providers — Detailed Walkthrough</H2>
      <P>
        Vooda's AI triage engine accepts any of the providers below. You can configure several at once and route
        different tasks (triage, verifier-fallback, remediation, rotation playbook) to different providers.
      </P>

      <Img src="/docs/screenshots/integrations-ai.png" alt="AI Provider integration page" caption="Figure 16.16 — The AI Provider page at /integrations/ai. Click any provider tile to add a new connection." />

      <H3>Anthropic (Claude)</H3>
      <Step n={1} title="Get an API key">
        Sign up at <ExtLink href="https://console.anthropic.com">console.anthropic.com</ExtLink>.
        Open <em>Settings → API Keys → Create Key</em>. Name: <code>vooda-prod</code>. Copy the key (<code>sk-ant-...</code>).
      </Step>
      <Step n={2} title="Add in Vooda">
        <strong>Integrations → AI Provider → Anthropic → + Add</strong>. Paste the key.
        Optional fields:
        <div className="mt-3">
          <FieldRef label="Display name" type="string" hint="Free-form label (e.g. 'Anthropic Production')." />
          <FieldRef label="Base URL override" type="url" hint="Leave blank for default https://api.anthropic.com. Set if you proxy through Cloudflare Workers / Bedrock." />
          <FieldRef label="Max requests per minute" type="integer, default 60" />
          <FieldRef label="Max tokens per minute" type="integer, default 100000" />
        </div>
      </Step>
      <Step n={3} title="Discover models">
        Click <strong>Discover Models</strong>. Vooda calls the Anthropic API and lists every model you have access to
        (claude-sonnet-4.5, claude-opus-4, claude-haiku, etc.).
      </Step>
      <Step n={4} title="Pick a model and route tasks">
        For each model row, tick the tasks to route to it. Recommended:
        <ul className="space-y-1 mt-2">
          <Li><strong>claude-sonnet-4.5</strong> → triage (best accuracy)</Li>
          <Li><strong>claude-haiku</strong> → verifier-fallback (cheap, fast for simple decisions)</Li>
        </ul>
      </Step>

      <H3>OpenAI</H3>
      <Step n={1} title="Get an API key">
        <ExtLink href="https://platform.openai.com/api-keys">platform.openai.com/api-keys</ExtLink> → <em>Create new secret key</em>.
        Project: pick a dedicated project so you can see Vooda's usage separately. Permissions: <em>Restricted</em>
        with <strong>Model capabilities → All</strong> + <strong>Threads → None</strong>.
      </Step>
      <Step n={2} title="Add in Vooda">
        Same pattern as Anthropic — paste key, discover, pick model. Route to <strong>gpt-4o</strong> for triage at
        high concurrency, <strong>gpt-4o-mini</strong> for verifier-fallback.
      </Step>

      <H3>Google Gemini</H3>
      <Step n={1} title="Get an API key">
        <ExtLink href="https://aistudio.google.com/app/apikey">aistudio.google.com/app/apikey</ExtLink> →
        <em>Create API key</em>. Choose an existing GCP project or create a new one.
      </Step>
      <Step n={2} title="Add in Vooda">
        Paste key. Discover. Recommended models: <strong>gemini-2.5-pro</strong> for triage, <strong>gemini-flash</strong> for verifier-fallback.
      </Step>

      <H3>Self-hosted / OpenAI-compatible (Ollama, vLLM, OpenRouter, Azure OpenAI)</H3>
      <P>Any endpoint that implements the OpenAI <code>/v1/chat/completions</code> shape works.</P>
      <Tbl headers={["Endpoint", "Base URL", "Auth"]} rows={[
        ["Ollama (local)", "http://localhost:11434/v1", "Authorization: Bearer ollama (any non-empty token)"],
        ["vLLM", "http://your-host:8000/v1", "Authorization: Bearer <your token>"],
        ["OpenRouter", "https://openrouter.ai/api/v1", "Authorization: Bearer sk-or-..."],
        ["Azure OpenAI", "https://<resource>.openai.azure.com/openai/deployments/<deployment>", "api-key header"],
      ]} />
      <Step n={1} title="Add via 'OpenAI-compatible'">
        <strong>Integrations → AI Provider → OpenAI-compatible → + Add</strong>.
        <div className="mt-3">
          <FieldRef label="Display name" required hint="e.g. 'Ollama Local'" />
          <FieldRef label="Base URL" required type="url" hint="Including /v1 suffix where applicable" />
          <FieldRef label="API key" required hint="For Ollama, any non-empty string works" />
        </div>
      </Step>
      <Step n={2} title="Discover models">
        Vooda calls <code>GET /models</code>. For Ollama, this returns your locally-pulled models (<code>ollama pull mistral</code>).
      </Step>

      <H3>AI Provider Troubleshooting</H3>
      <Tbl headers={["Error", "Likely cause", "Fix"]} rows={[
        ["401 invalid_api_key", "Key revoked or copied wrong", "Re-issue at the provider; paste fresh."],
        ["429 rate_limit_exceeded", "Provider rate limit hit", "Lower max requests/min in Vooda, or split across multiple keys (one per environment)."],
        ["500 from triage worker, traceback shows 'context length exceeded'", "File context too large for chosen model", "Switch to a model with larger context (gpt-4o has 128k, claude-sonnet-4.5 has 200k) or lower batch_size."],
        ["Discover Models returns []", "Permissions on the API key are too narrow", "OpenAI: ensure key has Models:Read. Anthropic: account is in correct organization."],
      ]} />

      <H2>Identity &amp; SSO — Okta SAML 2.0 Walkthrough</H2>

      <Note><strong>⚠ Temporarily disabled.</strong> SSO login (SAML/OIDC) is off in this release and every SSO endpoint returns <code>503</code>. It is being hardened before it can be safely re-enabled. The <em>Identity &amp; SSO</em> tile has been removed from the Integrations hub in the meantime, and JWT email/password remains the login method. <strong>The walkthrough below does not work today</strong> — it is retained so the wiring is ready when SSO returns.</Note>

      <P>
        SAML 2.0 is the intended enterprise auth backend. This walkthrough uses Okta — adapt the IdP-specific
        steps for Azure AD / Entra, Google, Auth0, or Ping.
      </P>

      <H3>In Vooda — Get the SP Metadata</H3>
      <Step n={1} title="Open Integrations → Identity & SSO → SAML">
        Direct link: <ExtLink href="http://localhost:3000/integrations/identity-sso">/integrations/identity-sso</ExtLink>.
      </Step>
      <Step n={2} title="Copy the SP details">
        From the Vooda SAML config card, copy:
        <ul className="space-y-1 mt-2">
          <Li><strong>SP Entity ID</strong> — <code>https://vooda.acme.com/api/v1/sso/saml/metadata</code></Li>
          <Li><strong>ACS URL</strong> — <code>https://vooda.acme.com/api/v1/sso/saml/acs</code></Li>
          <Li><strong>NameID format</strong> — <code>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</code></Li>
        </ul>
        Or click <strong>Download SP metadata</strong> for a single XML file you can upload to Okta.
      </Step>

      <H3>In Okta — Create the SAML Application</H3>
      <Step n={1} title="Open the Okta admin console">
        <ExtLink href="https://acme-admin.okta.com">https://&lt;your-org&gt;-admin.okta.com</ExtLink> →
        <em>Applications → Applications → Create App Integration → SAML 2.0</em>. Click <strong>Next</strong>.
      </Step>
      <Step n={2} title="General Settings">
        App name: <code>Vooda AI</code>. Logo (optional): upload <code>vooda-logo.png</code>. Click <strong>Next</strong>.
      </Step>
      <Step n={3} title="Configure SAML">
        <div className="mt-3">
          <FieldRef label="Single sign on URL" required hint="Paste the ACS URL from the SSO metadata step above. Tick 'Use this for Recipient URL and Destination URL'." />
          <FieldRef label="Audience URI (SP Entity ID)" required hint="Paste the SP Entity ID from the SSO metadata step above." />
          <FieldRef label="Default RelayState" type="(leave blank)" />
          <FieldRef label="Name ID format" required type="EmailAddress" />
          <FieldRef label="Application username" required type="Email" />
          <FieldRef label="Update application username on" type="Create and update" />
        </div>
      </Step>
      <Step n={4} title="Attribute Statements">
        Map these attributes (Name → Value):
        <Tbl headers={["Name", "Name format", "Value"]} rows={[
          ["email", "Basic", "user.email"],
          ["first_name", "Basic", "user.firstName"],
          ["last_name", "Basic", "user.lastName"],
        ]} />
      </Step>
      <Step n={5} title="Group Attribute (optional, for role mapping)">
        Name: <code>groups</code>. Filter: <em>Matches regex</em> <code>.*</code>. This sends every Okta group the user
        belongs to in the SAML assertion.
      </Step>
      <Step n={6} title="Finish">
        Feedback tab → <em>I'm an Okta customer adding an internal app</em> → click <strong>Finish</strong>.
      </Step>

      <H3>In Okta — Assign Users / Groups</H3>
      <P>By default no one has access. Assign:</P>
      <Step n={1} title="Open the Vooda app in Okta">
        Applications → Applications → click <em>Vooda AI</em> → <strong>Assignments</strong> tab.
      </Step>
      <Step n={2} title="Assign groups">
        Click <strong>Assign → Assign to Groups</strong>. Pick the Okta groups that should have access (e.g. <code>vooda-users</code>,
        <code>security-team</code>).
      </Step>

      <H3>In Okta — Get the IdP Metadata</H3>
      <Step n={1} title="Sign On tab → SAML 2.0 → 'View SAML setup instructions'">
        Copy <strong>Identity Provider Issuer</strong>, <strong>Identity Provider Single Sign-On URL</strong>, and the X.509 certificate.
        Or use the metadata URL: <code>https://&lt;your-org&gt;.okta.com/app/&lt;app_id&gt;/sso/saml/metadata</code>.
      </Step>

      <H3>Back in Vooda — Wire It Up</H3>
      <Step n={1} title="Paste IdP metadata">
        <strong>Integrations → Identity &amp; SSO → SAML</strong>. Paste either the metadata XML or the metadata URL.
        Save.
      </Step>
      <Step n={2} title="Map groups to roles">
        In the <strong>Group Mapping</strong> table, add rows. Example:
        <Tbl headers={["Okta group", "Vooda role"]} rows={[
          ["vooda-admins", "org-admin"],
          ["security-team", "security-lead"],
          ["engineering-eng-platform", "developer (BU: Platform)"],
          ["compliance", "auditor"],
        ]} />
      </Step>
      <Step n={3} title="Test SSO login">
        In Vooda, go to <strong>Settings → SSO → SAML</strong> and click <strong>Test SSO login</strong> (or open the
        Vooda tile from your Okta dashboard for an IdP-initiated login). Okta authenticates you and posts the assertion
        to the ACS URL; verify your assigned role on the dashboard.
      </Step>
      <Step n={4} title="Enforce">
        Once tested, toggle <strong>Force SSO for all users</strong>. After enforcement, only org-admins can fall back to
        local password (configurable via <code>SSO_LOCAL_FALLBACK_ROLES</code>).
      </Step>

      <H3>SAML Troubleshooting</H3>
      <Tbl headers={["Symptom", "Cause", "Fix"]} rows={[
        ["AuthnFailed: Audience mismatch", "SP Entity ID in Okta doesn't exactly match Vooda's", "Re-copy from Vooda — including https:// and trailing path."],
        ["AuthnFailed: Invalid signature", "Wrong IdP cert or cert rotated", "Re-fetch IdP metadata; Vooda auto-extracts the cert."],
        ["User logs in but lands on 'no role assigned'", "Group mapping didn't match any group the user belongs to", "Confirm the SAML response carries the 'groups' attribute (use SAML-tracer Firefox extension)."],
        ["Clock skew error", "IdP and Vooda clocks more than 60s apart", "Sync NTP on the Vooda host."],
        ["Loop redirect after login", "RelayState not preserved by Okta", "Set Default RelayState to /dashboard in Okta SAML settings."],
      ]} />

      <H2>Webhook Receivers — Detailed</H2>
      <P>Vooda's inbound webhook receivers live at <code>/api/v1/webhooks/&#123;type&#125;</code>. All require HMAC-signed payloads.</P>
      <Tbl headers={["Receiver", "Endpoint", "Signature header", "Algorithm"]} rows={[
        ["GitHub", "/api/v1/webhooks/github", "X-Hub-Signature-256", "HMAC-SHA256 hex, prefixed with 'sha256='"],
        ["GitLab", "/api/v1/webhooks/gitlab", "X-Gitlab-Token", "Plain shared secret comparison (constant-time)"],
        ["Bitbucket", "/api/v1/webhooks/bitbucket", "X-Hub-Signature", "HMAC-SHA256 hex"],
        ["Generic", "/api/v1/webhooks/generic/{slug}", "X-Vooda-Signature", "HMAC-SHA256 hex of timestamp + body"],
      ]} />
      <H3>Generic webhook example (other CI / SaaS systems)</H3>
      <Code>{`# Configure in Vooda: Integrations → Webhooks (Inbound) → Generic
# Vooda gives you a slug (e.g. 'jenkins-prod') and a 32-char shared secret.

# Sender side (curl example):
TS=$(date +%s)
BODY='{"event":"build.failed","repo":"acme/api","commit":"abc..."}'
SIG=$(echo -n "$TS.$BODY" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')

curl -X POST https://vooda.acme.com/api/v1/webhooks/generic/jenkins-prod \\
  -H "X-Vooda-Timestamp: $TS" \\
  -H "X-Vooda-Signature: $SIG" \\
  -H "Content-Type: application/json" \\
  -d "$BODY"

# 200 if accepted; 401 if signature mismatch; 410 if timestamp older than 5 min.`}</Code>

      <NextSteps items={[
        { label: "Notifications & Alerts", href: "/docs?section=notifications", desc: "Routing rules + per-user delivery preferences." },
        { label: "Remediation & Rotation", href: "/docs?section=remediation", desc: "Where ticket-creation + chat-notify happen from." },
        { label: "API Reference — Webhook Events", href: "/docs?section=api", desc: "Full outbound payload schemas + HMAC signing." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 17 — NOTIFICATIONS & ALERTS
// ═══════════════════════════════════════════════════════════════
function NotificationsContent() {
  return (
    <>
      <RoleBox role="security-lead (rules); any user (own preferences)" see="api" />

      <H2>Notification Rules</H2>
      <P>A notification rule is a (trigger, scope, channel, audience) tuple. Triggers are platform events:</P>
      <Tbl headers={["Trigger", "Fires when"]} rows={[
        ["finding.created.critical", "A new critical-severity finding is created."],
        ["finding.created.high", "A new high-severity finding is created."],
        ["finding.tp.confirmed", "A finding is classified as TRUE_POSITIVE."],
        ["gate.failed", "A CI/CD gate-check returns fail."],
        ["scan.failed", "A scan job exits with non-zero status."],
        ["sla.breached", "A finding exceeds its remediation SLA timer."],
      ]} />
      <P>Scopes: <code>org</code>, <code>business_unit</code>, <code>repo</code>. Multiple rules can match the same event — each fires independently.</P>

      <H2>Notification Channels</H2>
      <Tbl headers={["Channel", "Setup"]} rows={[
        ["Slack", "Existing Slack integration (under Connect integrations → Slack) + target channel ID."],
        ["Microsoft Teams", "Incoming webhook URL."],
        ["Email (SMTP)", "SMTP host, port, auth, from address — set at org level."],
        ["PagerDuty", "Service Integration Key."],
        ["Webhook (Outbound)", "URL + optional HMAC secret."],
      ]} />

      <H2>Notification History</H2>
      <P>Every notification dispatch is logged (timestamp, rule_id, event, channel, recipient, delivery status). Failed deliveries retry with exponential backoff up to 5 attempts; persistent failures surface as a dashboard alert.</P>
      <Endpoint method="GET" path="/api/v1/notifications" desc="List dispatched notifications, filterable by status, channel, date" />

      <H2>User Notification Preferences</H2>
      <P>Users can opt-in / opt-out of any event type per channel under <strong>Settings → Profile → Notifications</strong>. The user preference is the most-specific override over org rules.</P>
      <Tip>For paging-grade alerts (PagerDuty), org-admins can lock the rule so individual users cannot opt out. Compliance-critical channels stay reliable.</Tip>

      <NextSteps items={[
        { label: "Integrations", href: "/docs?section=integrations", desc: "Configure the destinations notifications flow to." },
        { label: "API Reference — Webhook Events", href: "/docs?section=api", desc: "Outbound payload schemas + retry semantics." },
        { label: "Administration", href: "/docs?section=admin", desc: "Org-level notification-rule locking + retention." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 18 — REPORTING & COMPLIANCE
// ═══════════════════════════════════════════════════════════════
function ReportingContent() {
  return (
    <>
      <RoleBox role="auditor (read), security-lead (write), org-admin (export)" see="api" />

      <H2>Built-in Compliance Frameworks</H2>
      <P>Findings and audit events are mapped to controls in five frameworks:</P>
      <Tbl headers={["Framework", "Mapped controls", "Use"]} rows={[
        ["SOC 2 Type II", "CC6.1, CC6.6, CC6.7, CC7.2, CC7.3", "Trust Services Criteria evidence pack."],
        ["PCI-DSS v4.0", "Req 3, Req 6, Req 8, Req 10", "Cardholder-data-environment credential audit."],
        ["ISO 27001 / 27002", "A.5.15, A.5.17, A.8.2, A.8.4, A.12.4", "ISMS Annex A evidence."],
        ["NIST CSF 2.0", "GV.RR, ID.AM, PR.AA, PR.DS, DE.CM", "Cybersecurity Framework alignment."],
        ["NIST 800-53 Rev 5", "AC-2, IA-2, IA-5, AU-2, AU-12", "Federal control mapping."],
      ]} />

      <H2>Generating a Report</H2>
      <Step n={1} title="Pick framework and scope">
        <strong>Reports → + New Report</strong>. Choose framework, BU scope, and date range.
      </Step>
      <Step n={2} title="Customize">
        Optionally include or exclude specific control families.
      </Step>
      <Step n={3} title="Generate">
        Click <strong>Generate</strong>. Reports up to ~50 pages render in &lt;30s; longer reports queue as a Celery
        job and notify when ready.
      </Step>
      <Step n={4} title="Export">
        Download as PDF (signed) or JSON (machine-readable for GRC tooling).
      </Step>
      <Endpoint method="POST" path="/api/v1/reports" desc="Generate a report" />
      <Endpoint method="GET" path="/api/v1/reports/{id}.pdf" desc="Download PDF" />
      <Endpoint method="GET" path="/api/v1/reports/{id}.json" desc="Download JSON" />

      <H2>Metrics Dashboard</H2>
      <P>The dashboard at <code>/dashboard</code> aggregates real-time KPIs:</P>
      <Grid2>
        <InfoCard title="Security Score" color="red">Composite 0–100 score weighted by open critical/high findings and remediation velocity.</InfoCard>
        <InfoCard title="Open findings" color="orange">Counts by severity. Trend chart vs prior 30 days.</InfoCard>
        <InfoCard title="MTTR" color="purple">Mean time to remediate, current vs prior period, broken down by severity.</InfoCard>
        <InfoCard title="AI accuracy">Per-tenant AI precision and recall versus team feedback.</InfoCard>
        <InfoCard title="Remediation rate" color="blue">Percentage of TPs remediated within their SLA window.</InfoCard>
      </Grid2>
      <Endpoint method="GET" path="/api/v1/metrics/snapshot" desc="Single-call dashboard snapshot" />
      <Endpoint method="GET" path="/api/v1/metrics/trends?metric=mttr&window=90d&bucket=day" desc="Time-series for one metric" />

      <H2>Audit Log</H2>
      <P>Every state-changing operation writes an audit record:</P>
      <Tbl headers={["Field", "Description"]} rows={[
        ["event_type", "Verb-noun (e.g. user.invited, finding.classified, gate.checked)"],
        ["actor", "user_id or api_key_id"],
        ["resource", "type + id of affected object"],
        ["ip_address", "Source IP"],
        ["user_agent", "HTTP User-Agent"],
        ["before / after", "JSON diff for state changes"],
        ["timestamp", "UTC, microsecond precision"],
      ]} />
      <Endpoint method="GET" path="/api/v1/audit?event=finding.classified&since=2026-04-01" desc="Filter audit log" />
      <Endpoint method="GET" path="/api/v1/audit/export?format=csv" desc="CSV export (org-admin)" />
      <P><strong>Retention:</strong> default 365 days; configurable up to 7 years via <code>AUDIT_RETENTION_DAYS</code>. For longer retention, forward events to your SIEM via a webhook notification channel.</P>

      <H2>Custom Report Queries</H2>
      <P>For BI tooling, use the metrics + findings APIs with API-key auth:</P>
      <Code>{`# Example: weekly TP rate by BU
curl https://vooda.acme.com/api/v1/metrics/findings?group_by=business_unit,classification&window=7d \\
  -H "Authorization: ApiKey vk_live_..."`}</Code>
      <Tip>The metrics API returns Prometheus-compatible time-series at <code>/api/v1/metrics/prometheus</code> — scrape directly into your existing Grafana stack.</Tip>

      <NextSteps items={[
        { label: "API Reference — Metrics", href: "/docs?section=api", desc: "All metric endpoints with query params + response shapes." },
        { label: "Detection Accuracy", href: "/docs?section=accuracy", desc: "How Vooda catches real secrets while cutting false positives." },
        { label: "Administration", href: "/docs?section=admin", desc: "Retention windows, compliance framework toggles, export schedules." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 19 — API REFERENCE
// ═══════════════════════════════════════════════════════════════
function ApiContent() {
  return (
    <>
      <RoleBox role="varies per endpoint — see permission column" />

      {/* QW-5 — prominent OpenAPI / Swagger UI button so an evaluator
          can hit "Try it out" without scrolling to the bottom of 19.6
          to find the tip line. */}
      <div className="flex flex-wrap gap-3 my-5">
        <a href="/api/docs" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-red-500/[0.08] border border-red-500/25 text-red-300 hover:bg-red-500/[0.12] hover:border-red-500/40 transition-all text-[13px] font-medium">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          Open interactive Swagger UI →
        </a>
        <a href="/api/openapi.json" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-white/[0.04] border border-white/[0.08] text-slate-300 hover:bg-white/[0.07] transition-all text-[13px] font-medium">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          OpenAPI 3.1 spec (JSON)
        </a>
      </div>

      <H2>Authentication</H2>
      <P>The API accepts two credential schemes:</P>
      <Tbl headers={["Scheme", "Header", "Use"]} rows={[
        ["JWT Bearer", "Authorization: Bearer eyJhbGc...", "Interactive sessions; obtained via /auth/login."],
        ["API Key", "Authorization: ApiKey vk_live_...", "CI/CD, scripts, external integrations."],
      ]} />
      <P>Both schemes resolve to a (user / service-account) and the request inherits that principal's permissions.</P>

      <H2>Pagination</H2>
      <P>List endpoints accept <code>limit</code> (max 200, default 50) and <code>offset</code> (default 0).</P>
      <Code>{`{
  "items": [ { "id": "...", ... }, ... ],
  "total": 4321,
  "limit": 50,
  "offset": 100
}`}</Code>

      <H2>Error Responses</H2>
      <Tbl headers={["Status", "Meaning", "Body"]} rows={[
        ["400", "Validation error", '{"detail":[{"loc":["body","email"],"msg":"value is not a valid email address"}]}'],
        ["401", "Auth missing or invalid", '{"detail":"unauthorized"}'],
        ["403", "Auth ok but lacks permission", '{"detail":"forbidden","required":"findings:triage"}'],
        ["404", "Resource not found (or hidden by tenant scope)", '{"detail":"not found"}'],
        ["409", "Conflict (duplicate, race)", '{"detail":"already exists","resource_id":"..."}'],
        ["422", "Schema/business-rule violation", '{"detail":"...specific message..."}'],
        ["429", "Rate limit", "see the rate-limiting section"],
        ["500", "Server error", '{"detail":"internal error","trace_id":"..."}'],
      ]} />

      <H2>Rate Limiting</H2>
      <P>Limits per principal per minute (defaults; configurable):</P>
      <Tbl headers={["Endpoint group", "Limit", "Burst"]} rows={[
        ["/auth/login", "10", "3 in 5s"],
        ["/findings (read)", "600", "60 in 10s"],
        ["/findings (write)", "120", "20 in 10s"],
        ["/scan/inline (push protection)", "120", "20 in 10s"],
        ["/repositories/{id}/scan (manual scan)", "30", "5 in 30s"],
        ["/gates/check", "300", "50 in 10s"],
      ]} />
      <Code>{`# 429 response includes retry guidance
HTTP/1.1 429 Too Many Requests
Retry-After: 23
{"detail":"rate limit exceeded","limit":120,"window":"1m"}`}</Code>

      <H2>Versioning</H2>
      <P>Current version is <strong>v1</strong>; all endpoints live under <code>/api/v1/</code>. Breaking changes will land under <code>/api/v2/</code> with a 12-month overlap period. The <code>X-Vooda-API-Version</code> response header reports the running version on every call.</P>

      <H2>Endpoint Reference</H2>
      <P>Endpoints below are grouped by router. Permissions follow the model in the Manage roles and permissions reference.</P>

      <H3>Auth</H3>
      <Endpoint method="POST" path="/api/v1/auth/login" desc="Email/password login. Returns a bearer access token." />
      <Endpoint method="GET" path="/api/v1/auth/me" desc="Current user + roles." />
      <Endpoint method="POST" path="/api/v1/auth/change-password" desc="Change own password (requires the current password)." />

      <H3>Repositories</H3>
      <Endpoint method="GET" path="/api/v1/repositories" desc="List (repos:read)" />
      <Endpoint method="POST" path="/api/v1/repositories" desc="Connect (repos:write)" />
      <Endpoint method="GET" path="/api/v1/repositories/{id}" desc="Detail (repos:read)" />
      <Endpoint method="PATCH" path="/api/v1/repositories/{id}" desc="Edit (repos:write)" />
      <Endpoint method="DELETE" path="/api/v1/repositories/{id}" desc="Disconnect/delete (repos:write)" />
      <Endpoint method="POST" path="/api/v1/repositories/{id}/scan" desc="Trigger scan (repos:scan)" />
      <Endpoint method="GET" path="/api/v1/repositories/{id}/scans" desc="Scan history" />

      <H3>Findings</H3>
      <Endpoint method="GET" path="/api/v1/findings" desc="List, with filters (findings:read)" />
      <Endpoint method="GET" path="/api/v1/findings/{id}" desc="Detail" />
      <Endpoint method="PATCH" path="/api/v1/findings/{id}" desc="Triage (findings:triage)" />
      <Endpoint method="POST" path="/api/v1/findings/bulk" desc="Bulk operations" />
      <Endpoint method="POST" path="/api/v1/findings/import" desc="Ingest SARIF (findings:import)" />
      <Endpoint method="GET" path="/api/v1/findings/export" desc="CSV/JSON/SARIF (findings:export)" />
      <Endpoint method="GET" path="/api/v1/findings/{id}/ai-events" desc="AI triage history" />

      <H3>Push Protection</H3>
      <Endpoint method="POST" path="/api/v1/push-protection/scan" desc="Pre-commit/pre-push inline scan" />
      <Endpoint method="POST" path="/api/v1/push-protection/bypass" desc="Record an authorized bypass" />

      <H3>Suppressions</H3>
      <Endpoint method="GET" path="/api/v1/suppressions" desc="List" />
      <Endpoint method="POST" path="/api/v1/suppressions" desc="Create (suppressions:write)" />
      <Endpoint method="DELETE" path="/api/v1/suppressions/{id}" desc="Remove" />

      <H3>Custom Detectors</H3>
      <Endpoint method="GET" path="/api/v1/detectors" desc="List" />
      <Endpoint method="POST" path="/api/v1/detectors" desc="Create (detectors:write)" />
      <Endpoint method="POST" path="/api/v1/detectors/validate" desc="Validate without saving" />
      <Endpoint method="PATCH" path="/api/v1/detectors/{id}" desc="Edit" />
      <Endpoint method="DELETE" path="/api/v1/detectors/{id}" desc="Delete" />

      <H3>Metrics</H3>
      <Endpoint method="GET" path="/api/v1/metrics/snapshot" desc="Dashboard KPIs" />
      <Endpoint method="GET" path="/api/v1/metrics/mttr" desc="Mean time to remediate" />
      <Endpoint method="GET" path="/api/v1/metrics/trends" desc="Time-series" />
      <Endpoint method="GET" path="/api/v1/metrics/prometheus" desc="Prometheus text exposition" />

      <H3>Reports</H3>
      <Endpoint method="POST" path="/api/v1/reports" desc="Generate (reports:write)" />
      <Endpoint method="GET" path="/api/v1/reports" desc="List" />
      <Endpoint method="GET" path="/api/v1/reports/{id}.pdf" desc="Download" />

      <H3>Audit</H3>
      <Endpoint method="GET" path="/api/v1/audit" desc="Filtered event stream (audit:read)" />
      <Endpoint method="GET" path="/api/v1/audit/export" desc="CSV export" />

      <H3>Integrations</H3>
      <Endpoint method="GET" path="/api/v1/integrations" desc="List configured integrations" />
      <Endpoint method="POST" path="/api/v1/integrations/{type}" desc="Configure (integrations:write)" />
      <Endpoint method="POST" path="/api/v1/integrations/{type}/test" desc="Test connection" />
      <Endpoint method="DELETE" path="/api/v1/integrations/{id}" desc="Disconnect" />

      <H3>AI Models</H3>
      <Endpoint method="GET" path="/api/v1/ai-models" desc="List configured providers" />
      <Endpoint method="POST" path="/api/v1/ai-models/discover" desc="Discover models for a provider" />
      <Endpoint method="POST" path="/api/v1/ai-models" desc="Add model" />
      <Endpoint method="PATCH" path="/api/v1/ai-models/{id}" desc="Edit (rate limits, task routing)" />

      <H3>Users / Roles / SSO</H3>
      <Endpoint method="GET" path="/api/v1/users" desc="List (users:read)" />
      <Endpoint method="POST" path="/api/v1/users" desc="Invite or create (users:write)" />
      <Endpoint method="GET" path="/api/v1/users/{id}/effective-permissions" desc="Audit permissions" />
      <Endpoint method="GET" path="/api/v1/roles" desc="List roles" />
      <Endpoint method="POST" path="/api/v1/roles" desc="Create custom role (roles:write)" />
      <Endpoint method="GET" path="/api/v1/sso/providers" desc="List configured SSO providers" />
      <Endpoint method="POST" path="/api/v1/sso/configure" desc="Configure a SAML/OIDC provider (org-admin)" />
      <Endpoint method="POST" path="/api/v1/sso/saml/acs" desc="SAML ACS (assertion consumer service)" />
      <Endpoint method="GET" path="/api/v1/sso/saml/metadata" desc="SP metadata" />
      <Endpoint method="GET" path="/api/v1/sso/oidc/authorize" desc="OIDC authorization start" />
      <Endpoint method="GET" path="/api/v1/sso/oidc/callback" desc="OIDC callback" />

      <H3>API Keys</H3>
      <Endpoint method="GET" path="/api/v1/api-keys" desc="List (own keys)" />
      <Endpoint method="POST" path="/api/v1/api-keys" desc="Create (returns plaintext once)" />
      <Endpoint method="DELETE" path="/api/v1/api-keys/{id}" desc="Revoke" />

      <H3>WebSocket</H3>
      <Endpoint method="WS" path="/api/v1/ws/scan/{scan_job_id}" desc="Live scan progress (token via ?token=<jwt>)" />
      {/* /api/v1/ws/findings (live finding stream) is on the roadmap; not yet implemented. */}

      <H3>Saved Views / Access / Notifications / Webhooks</H3>
      <Endpoint method="GET" path="/api/v1/saved-views" desc="List" />
      <Endpoint method="POST" path="/api/v1/saved-views" desc="Create" />
      <Endpoint method="GET" path="/api/v1/access/business-units" desc="BU tree" />
      <Endpoint method="POST" path="/api/v1/access/grants" desc="Create grant" />
      <Endpoint method="DELETE" path="/api/v1/access/grants/{id}" desc="Revoke grant" />
      <Endpoint method="GET" path="/api/v1/notifications/rules" desc="List rules" />
      <Endpoint method="POST" path="/api/v1/notifications/rules" desc="Create rule" />
      <Endpoint method="POST" path="/api/v1/webhooks/github" desc="GitHub webhook receiver" />
      <Endpoint method="POST" path="/api/v1/webhooks/gitlab" desc="GitLab receiver" />
      <Endpoint method="POST" path="/api/v1/webhooks/bitbucket" desc="Bitbucket receiver" />
      <Endpoint method="POST" path="/api/v1/webhooks/generic/{slug}" desc="Generic HMAC-signed receiver" />

      <H3>Allowlists</H3>
      <Endpoint method="GET" path="/api/v1/allowlists" desc="List allowlist entries" />
      <Endpoint method="POST" path="/api/v1/allowlists" desc="Create (allowlists:write)" />
      <Endpoint method="DELETE" path="/api/v1/allowlists/{id}" desc="Remove" />

      <H3>Scan Sources</H3>
      <Endpoint method="GET" path="/api/v1/scan-sources" desc="List" />
      <Endpoint method="POST" path="/api/v1/scan-sources" desc="Connect" />
      <Endpoint method="POST" path="/api/v1/scan-sources/test-connection" desc="Test before save" />
      <Endpoint method="POST" path="/api/v1/scan-sources/{id}/scan" desc="Trigger scan" />
      <Endpoint method="DELETE" path="/api/v1/scan-sources/{id}" desc="Remove" />

      <Tip>The full OpenAPI schema is at <code>/api/openapi.json</code>; an interactive Swagger UI is at <code>/api/docs</code>. The cards below add operation-level detail (auth, params, schemas, examples) for the most-used endpoints.</Tip>

      {/* 19.7 — Full reference: live Swagger (never drifts from the build) */}
      <H2>Full API reference</H2>
      <P>
        The complete, always-current endpoint reference — every operation with its parameters,
        request and response schemas, and error codes — is served by the running API itself:
      </P>
      <ul className="space-y-2 my-3">
        <Li><strong>Interactive Swagger UI</strong> — <code>/api/docs</code> — try requests in the browser.</Li>
        <Li><strong>Machine-readable OpenAPI</strong> — <code>/api/openapi.json</code> — import into Postman or generate clients.</Li>
      </ul>
      <Note>Because the reference is generated from the running build, it never drifts from the deployed API. The quick reference in the endpoint reference above covers the most-used endpoints; use Swagger for the full contract.</Note>

      {/* ─────────────────────────────────────────────────────────
          19.8 — Webhook Event Reference
          ───────────────────────────────────────────────────────── */}
      <H2>Webhook Event Reference</H2>
      <P>
        Outbound webhooks are delivered as JSON POSTs with an <code>X-Vooda-Signature</code>
        header (HMAC-SHA256 of <code>timestamp + body</code>, hex). Subscribe at
        <em> Settings → Notifications → Add Webhook</em>. Every payload shares an envelope:
      </P>
      <Code>{`{
  "event_id":   "evt_01H...",        // unique per delivery (retry-safe idempotency)
  "event_type": "scan.completed",    // verb-noun
  "timestamp":  "2026-05-24T17:11:24Z",
  "tenant_id":  "tenant_01H...",
  "data":       { /* event-specific payload — see below */ }
}`}</Code>

      <H3>scan.started</H3>
      <P><strong>Trigger:</strong> a scan job transitions from <code>pending</code> to <code>running</code>.</P>
      <Code>{`{
  "event_type": "scan.started",
  "data": {
    "scan_id": "scan_01H...",
    "repository_id": "repo_01H...",
    "repository_name": "acme/payments-api",
    "scan_type": "standalone",
    "branch": "main",
    "commit_sha": "f3a9c2b...",
    "triggered_by": "user_01H...",
    "trigger_source": "webhook"   // webhook | manual | schedule | ci
  }
}`}</Code>

      <H3>scan.completed</H3>
      <P><strong>Trigger:</strong> scan finishes successfully (status=completed). Carries the result summary so consumers can branch without a follow-up GET.</P>
      <Code>{`{
  "event_type": "scan.completed",
  "data": {
    "scan_id": "scan_01H...",
    "repository_id": "repo_01H...",
    "duration_seconds": 47,
    "files_scanned": 1247,
    "findings_total": 3,
    "findings_critical": 1,
    "findings_high": 2,
    "findings_medium": 0,
    "findings_low": 0,
    "ai_triaged": 2
  }
}`}</Code>

      <H3>scan.failed</H3>
      <Code>{`{
  "event_type": "scan.failed",
  "data": {
    "scan_id": "scan_01H...",
    "repository_id": "repo_01H...",
    "error_code": "clone_failed",      // clone_failed | timeout | quota_exceeded | internal
    "error_message": "Authentication failed for https://github.com/acme/payments-api",
    "retryable": true
  }
}`}</Code>

      <H3>finding.detected</H3>
      <P><strong>Trigger:</strong> a new finding is created (during scan). Coalesced — one webhook per <em>incident</em>, not one per location.</P>
      <Code>{`{
  "event_type": "finding.detected",
  "data": {
    "finding_id": "finding_01H...",
    "incident_id": "incident_01H...",
    "repository_id": "repo_01H...",
    "scan_id": "scan_01H...",
    "severity": "critical",
    "secret_type": "aws_access_key",
    "scanner_rule_id": "aws-access-key-id",
    "file_path": "src/aws_client.py",
    "line_start": 42,
    "confidence": 0.97,
    "is_new_incident": true
  }
}`}</Code>

      <H3>finding.status_changed</H3>
      <Code>{`{
  "event_type": "finding.status_changed",
  "data": {
    "finding_id": "finding_01H...",
    "previous_classification": "needs_review",
    "new_classification": "true_positive",
    "previous_review_status": "unreviewed",
    "new_review_status": "reviewed",
    "changed_by": "user_01H...",
    "reason": "STS verified key is live."
  }
}`}</Code>

      <H3>finding.assigned</H3>
      <Code>{`{
  "event_type": "finding.assigned",
  "data": {
    "finding_id": "finding_01H...",
    "assigned_to": "user_02H...",
    "assigned_by": "user_01H..."
  }
}`}</Code>

      <H3>triage.completed</H3>
      <P><strong>Trigger:</strong> AI triage finishes for a finding (sync or batch).</P>
      <Code>{`{
  "event_type": "triage.completed",
  "data": {
    "finding_id": "finding_01H...",
    "ai_event_id": "ai_event_01H...",
    "model": "claude-4.7-sonnet",
    "verdict": "true_positive",
    "confidence": 0.93,
    "tokens_used": 1240,
    "duration_ms": 1820
  }
}`}</Code>

      <H3>remediation.started / completed / failed</H3>
      <Code>{`{
  "event_type": "remediation.completed",
  "data": {
    "finding_id": "finding_01H...",
    "plan_id": "plan_01H...",
    "rotation_event_id": "rot_01H...",
    "pr_url": "https://github.com/acme/payments-api/pull/4271",
    "verified_dead_after": true,
    "duration_seconds": 132
  }
}`}</Code>

      <H3>policy.violated</H3>
      <P><strong>Trigger:</strong> a push-protection check or rule-override gate denies an action.</P>
      <Code>{`{
  "event_type": "policy.violated",
  "data": {
    "policy_type": "push_protection",   // push_protection | gate_check
    "repository_id": "repo_01H...",
    "commit_sha": "f3a9c2b...",
    "actor": "alice@acme.com",
    "violations": [
      {
        "rule_id": "aws-access-key-id",
        "file_path": "src/aws_client.py",
        "line_start": 42,
        "severity": "critical"
      }
    ],
    "action_taken": "blocked"          // blocked | warned | bypassed
  }
}`}</Code>

      <Warn>
        Webhooks are delivered at-least-once. Use <code>event_id</code> for idempotency; retries
        use exponential backoff (1m → 2m → 4m → 8m → 16m → 32m → 1h → drop). Recent attempts
        are visible at <em>Settings → Notifications → Delivery Log</em>.
      </Warn>

      {/* ─────────────────────────────────────────────────────────
          19.9 — Common Data Models
          ───────────────────────────────────────────────────────── */}
      <H2>Common Data Models</H2>
      <P>Shared schemas referenced across operations. Fields marked <span className="text-red-400 font-semibold">required</span> are always present on responses; optional fields may be <code>null</code> or omitted.</P>

      <H3>Finding</H3>
      <Tbl headers={["Field", "Type", "Required", "Description"]} rows={[
        ["id", "uuid", "yes", "Primary key (canonical: per-location)."],
        ["incident_id", "uuid", "yes", "FK to SecretIncident — one row per unique credential."],
        ["scan_job_id", "uuid", "yes", "The scan that produced this finding."],
        ["repository_id", "uuid", "no", "NULL for non-git source findings (Slack, Jira, etc.)."],
        ["title", "string", "yes", "Human-readable summary."],
        ["severity", "enum", "yes", "critical | high | medium | low | info"],
        ["vulnerability_category", "string", "yes", "Always 'secret' today."],
        ["cwe", "string", "no", "e.g. 'CWE-798'."],
        ["classification", "enum", "yes", "unreviewed | true_positive | false_positive | accepted_risk | needs_review"],
        ["review_status", "enum", "yes", "unreviewed | reviewed | suppressed"],
        ["remediation_status", "enum", "yes", "open | in_progress | rotated | resolved | wontfix"],
        ["scanner_name", "string", "yes", "vooda-builtin | custom | semgrep-import | trivy-import | …"],
        ["scanner_rule_id", "string", "no", "e.g. 'aws-access-key-id'."],
        ["file_path", "string", "yes", "Relative to the repo root."],
        ["line_start / line_end", "integer", "no", "Line numbers in the file (1-indexed)."],
        ["commit_sha", "string", "no", "Discovery commit when scan_type=history."],
        ["confidence", "float (0–1)", "yes", "Rule-engine confidence before AI."],
        ["ai_confidence", "float (0–1)", "no", "Post-AI confidence."],
        ["code_snippet", "string", "no", "Redacted source context."],
        ["assigned_to", "uuid", "no", "User assigned to triage / fix."],
        ["tags", "string[]", "yes", "Free-form labels."],
        ["version", "integer", "yes", "Optimistic-lock token."],
        ["created_at", "iso-8601", "yes", "Discovery time."],
        ["updated_at", "iso-8601", "yes", "Last mutation."],
      ]} />

      <H3>Scan (ScanJob)</H3>
      <Tbl headers={["Field", "Type", "Required", "Description"]} rows={[
        ["id", "uuid", "yes", "Primary key."],
        ["repository_id", "uuid", "yes", "Parent repo."],
        ["scan_type", "enum", "yes", "standalone | history | import"],
        ["status", "enum", "yes", "pending | running | completed | failed | cancelled"],
        ["progress_pct", "integer (0–100)", "yes", "Current progress."],
        ["status_message", "string", "no", "Human-readable phase, e.g. '[6/8] AI triaging 23 findings...'"],
        ["stats", "object", "yes", "files_scanned, findings_total, findings_critical, ai_triaged, duration_seconds, ..."],
        ["config", "object", "yes", "skip_ai, force_full, branch, …"],
        ["celery_task_id", "string", "no", "Internal worker reference."],
        ["created_at / updated_at", "iso-8601", "yes", ""],
      ]} />

      <H3>Repository</H3>
      <Tbl headers={["Field", "Type", "Required", "Description"]} rows={[
        ["id", "uuid", "yes", ""],
        ["name", "string", "yes", "Display name."],
        ["url", "string", "no", "Git URL. NULL for upload-mode repos."],
        ["source_type", "enum", "yes", "git_url | upload | github_app"],
        ["provider", "string", "no", "github | gitlab | bitbucket | azure_devops | generic"],
        ["default_branch", "string", "yes", "Default 'main'."],
        ["is_active", "boolean", "yes", "False = archived."],
        ["languages / frameworks", "string[]", "yes", "Detected from manifest files."],
        ["business_unit_id", "uuid", "no", "Org-level grouping for access control."],
        ["push_scan_enabled", "boolean", "yes", "Honour push webhooks?"],
        ["pr_scan_enabled", "boolean", "yes", "Honour PR/MR webhooks?"],
        ["branch_patterns", "string[]", "no", "fnmatch globs — NULL = scan every branch."],
        ["last_webhook_event_at", "iso-8601", "no", ""],
        ["last_webhook_event_status", "string", "no", "success | failed"],
        ["created_at", "iso-8601", "yes", ""],
      ]} />

      <H3>APIKey</H3>
      <Tbl headers={["Field", "Type", "Required", "Description"]} rows={[
        ["id", "uuid", "yes", ""],
        ["name", "string (1–255)", "yes", "Label."],
        ["key_prefix", "string", "yes", "First 12 chars of the raw key, e.g. 'vooda_iNOtv54'."],
        ["scopes", "string[]", "yes", "Subset of [scan, findings, gate, reports, admin]."],
        ["is_active", "boolean", "yes", "False = revoked."],
        ["status", "enum", "yes", "active | rotating | expired | revoked (computed)."],
        ["last_used_at", "iso-8601", "no", "Updated on every successful auth."],
        ["expires_at", "iso-8601", "no", "NULL = never expires."],
        ["rotated_at / rotated_to_id", "iso-8601, uuid", "no", "Set during the rotation grace window."],
        ["rotation_grace_until", "iso-8601", "no", "When the rotating key auto-expires."],
        ["allowed_ip_cidrs", "string[]", "no", "Source-IP allowlist. NULL = unrestricted."],
        ["created_at", "iso-8601", "yes", ""],
      ]} />

      <H3>User / Member</H3>
      <Tbl headers={["Field", "Type", "Required", "Description"]} rows={[
        ["id", "uuid", "yes", ""],
        ["email", "email", "yes", "Unique within tenant."],
        ["full_name", "string", "yes", ""],
        ["is_active", "boolean", "yes", "False = deactivated."],
        ["roles", "string[]", "yes", "admin | security_lead | security_reviewer | developer | viewer | <custom>"],
        ["created_at", "iso-8601", "yes", ""],
      ]} />

      <H3>Triage Result (AI Event)</H3>
      <Tbl headers={["Field", "Type", "Required", "Description"]} rows={[
        ["id", "uuid", "yes", ""],
        ["finding_id", "uuid", "yes", ""],
        ["model", "string", "yes", "Provider model id, e.g. 'claude-4.7-sonnet'."],
        ["verdict", "enum", "yes", "true_positive | false_positive | insufficient_evidence"],
        ["confidence", "float (0–1)", "yes", ""],
        ["reasoning", "string", "yes", "Free-form rationale; safe to display to users."],
        ["tokens_used", "integer", "no", ""],
        ["duration_ms", "integer", "yes", ""],
        ["created_at", "iso-8601", "yes", ""],
      ]} />

      <H3>Audit Event</H3>
      <Tbl headers={["Field", "Type", "Required", "Description"]} rows={[
        ["id", "uuid", "yes", ""],
        ["tenant_id", "uuid", "yes", ""],
        ["user_id", "uuid", "no", "NULL for system-initiated events (anonymous login_failed, etc.)."],
        ["action", "string", "yes", "snake_case verb_noun, e.g. 'api_key_revoked'."],
        ["resource_type", "string", "yes", "api_key | user | repository | finding | …"],
        ["resource_id", "string", "no", "Stringified ID of the affected resource."],
        ["detail", "string", "no", "Human-readable description."],
        ["metadata", "object", "no", "Structured JSONB for filterable queries."],
        ["ip_address", "string", "no", "Best-effort source IP via X-Forwarded-For chain."],
        ["user_agent", "string", "no", ""],
        ["created_at", "iso-8601", "yes", ""],
      ]} />

      {/* ─────────────────────────────────────────────────────────
          19.10 — SDK & Integration Quickstart
          ───────────────────────────────────────────────────────── */}
      <H2>SDK & Integration Quickstart</H2>
      <P>No official SDKs are required — every endpoint is a plain HTTPS call. The snippets below cover the canonical "first scan + read findings" flow in the three languages we see in 80% of customer integrations.</P>

      <H3>Python (requests)</H3>
      <Code>{`# pip install requests
import os, requests, time

VOODA = os.environ["VOODA_URL"]            # e.g. https://api.vooda.ai/v1
KEY   = os.environ["VOODA_API_KEY"]
REPO  = os.environ["VOODA_REPO_ID"]

s = requests.Session()
s.headers["Authorization"] = f"Bearer {KEY}"

# 1. Smoke-test auth
me = s.get(f"{VOODA}/auth/me").json()
print(f"Authenticated as {me['email']}")

# 2. Trigger a scan
scan = s.post(f"{VOODA}/repositories/{REPO}/scan",
              json={"scan_type": "standalone"}).json()
scan_id = scan["id"]
print(f"Scan queued: {scan_id}")

# 3. Poll until done (or use WebSocket /ws/scan/{id} for push)
while True:
    s_obj = s.get(f"{VOODA}/repositories/{REPO}/scans/{scan_id}").json()
    if s_obj["status"] in {"completed", "failed", "cancelled"}:
        break
    time.sleep(10)

# 4. Read critical findings
findings = s.get(f"{VOODA}/findings",
                 params={"repository_id": REPO,
                         "severity": "critical",
                         "review_status": "unreviewed"}).json()
for f in findings["items"]:
    print(f"[{f['severity']}] {f['title']}  →  {f['file_path']}:{f['line_start']}")`}</Code>

      <H3>Node.js (axios)</H3>
      <Code>{`// npm i axios
import axios from "axios";

const VOODA = process.env.VOODA_URL;          // https://api.vooda.ai/v1
const KEY   = process.env.VOODA_API_KEY;
const REPO  = process.env.VOODA_REPO_ID;

const api = axios.create({
  baseURL: VOODA,
  headers: { Authorization: \`Bearer \${KEY}\` },
});

// 1. Smoke
const { data: me } = await api.get("/auth/me");
console.log(\`Authenticated as \${me.email}\`);

// 2. Trigger
const { data: scan } = await api.post(\`/repositories/\${REPO}/scan\`,
  { scan_type: "standalone" });
console.log(\`Scan queued: \${scan.id}\`);

// 3. Poll
let status;
do {
  await new Promise(r => setTimeout(r, 10000));
  const { data } = await api.get(\`/repositories/\${REPO}/scans/\${scan.id}\`);
  status = data.status;
} while (!["completed", "failed", "cancelled"].includes(status));

// 4. Read findings
const { data: findings } = await api.get("/findings", {
  params: { repository_id: REPO, severity: "critical", review_status: "unreviewed" },
});
findings.items.forEach(f =>
  console.log(\`[\${f.severity}] \${f.title} -> \${f.file_path}:\${f.line_start}\`));`}</Code>

      <H3>GitHub Actions (scan on push, fail PR on critical)</H3>
      <Code>{`# .github/workflows/vooda-scan.yml
name: Vooda Secret Scan
on:
  push:
  pull_request:

jobs:
  vooda:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Trigger Vooda scan + gate
        env:
          VOODA_URL:     \${{ vars.VOODA_URL }}        # https://api.vooda.ai/v1
          VOODA_API_KEY: \${{ secrets.VOODA_API_KEY }}
          VOODA_REPO_ID: \${{ vars.VOODA_REPO_ID }}
        run: |
          set -e
          SCAN=$(curl -fsS -X POST \\
            "$VOODA_URL/repositories/$VOODA_REPO_ID/scan" \\
            -H "Authorization: Bearer $VOODA_API_KEY" \\
            -H "Content-Type: application/json" \\
            -d '{"scan_type":"standalone"}')
          SCAN_ID=$(echo "$SCAN" | jq -r .id)

          for i in $(seq 1 60); do
            STATUS=$(curl -fsS \\
              "$VOODA_URL/repositories/$VOODA_REPO_ID/scans/$SCAN_ID" \\
              -H "Authorization: Bearer $VOODA_API_KEY" | jq -r .status)
            [[ "$STATUS" == "completed" ]] && break
            [[ "$STATUS" == "failed"    ]] && { echo "scan failed"; exit 2; }
            sleep 10
          done

          # Fail the PR on any new critical
          CRIT=$(curl -fsS \\
            "$VOODA_URL/findings?repository_id=$VOODA_REPO_ID&severity=critical&review_status=unreviewed" \\
            -H "Authorization: Bearer $VOODA_API_KEY" | jq -r '.total // 0')
          if [[ "$CRIT" -gt 0 ]]; then
            echo "::error::Vooda found $CRIT unreviewed critical findings"
            exit 1
          fi`}</Code>

      <H3>Jira — auto-create a ticket on new critical finding</H3>
      <P>Wire it via the in-product Integration (Settings → Integrations → Jira), or do it yourself with a webhook listener:</P>
      <Code>{`# Express-like pseudo-handler subscribed to finding.detected
app.post("/vooda-hook", verifyHmac, async (req, res) => {
  const { event_type, data } = req.body;
  if (event_type === "finding.detected" && data.severity === "critical") {
    await jira.createIssue({
      fields: {
        project:    { key: "SEC" },
        issuetype:  { name: "Bug" },
        summary:    \`[Vooda CRITICAL] \${data.scanner_rule_id} in \${data.file_path}:\${data.line_start}\`,
        description: \`Repo: \${data.repository_id}\\nIncident: \${data.incident_id}\\nVooda link: https://app.vooda.ai/findings/\${data.finding_id}\`,
        labels:     ["vooda", data.secret_type],
        priority:   { name: "Highest" },
      },
    });
  }
  res.sendStatus(204);
});`}</Code>

      {/* ─────────────────────────────────────────────────────────
          19.11 — Appendix
          ───────────────────────────────────────────────────────── */}
      <H2>Appendix</H2>

      <H3>A. Scanner rule catalogue (live)</H3>
      <P>
        Fetched live from <code>GET /api/v1/public/scanner-rules</code> on every page load — no auth required.
        Numbers reflect the rule pack currently running in this Vooda instance. Use the search box to
        filter by name, secret type, or rule_id.
      </P>
      <LiveScannerRuleCatalog />

      <H3>B. Severity definitions</H3>
      <Tbl headers={["Level", "Definition", "Typical SLA"]} rows={[
        ["critical", "Live credential to a production system with broad blast radius (cloud root, prod DB, payment processor).", "4 hours"],
        ["high", "Live credential to a non-production system OR scoped credential to production.", "24 hours"],
        ["medium", "Credential of uncertain liveness OR scoped non-prod credential.", "7 days"],
        ["low", "Inert match (placeholder, test fixture, archived branch).", "30 days"],
        ["info", "Informational — not a credential but worth surfacing (e.g. exposed config file).", "Backlog"],
      ]} />

      <H3>C. Finding status transition diagram</H3>
      <P>Allowed transitions on <code>review_status</code> and <code>classification</code> (enforced by the triage endpoint):</P>
      <Tbl headers={["From", "Action", "To (review_status)", "To (classification)"]} rows={[
        ["unreviewed", "mark_tp", "reviewed", "true_positive"],
        ["unreviewed", "mark_fp", "reviewed", "false_positive"],
        ["unreviewed", "accept_risk", "reviewed", "accepted_risk"],
        ["unreviewed", "request_review", "unreviewed", "needs_review"],
        ["reviewed (any)", "mark_tp / mark_fp / accept_risk", "reviewed", "<new classification>"],
        ["reviewed", "add_comment", "(no change)", "(no change)"],
        ["any", "suppress (via /suppressions)", "suppressed", "(unchanged)"],
        ["resolved (remediation_status)", "verify dead", "reviewed", "true_positive"],
      ]} />
      <P>Notes:</P>
      <ul className="space-y-2 my-3">
        <Li><code>remediation_status</code> is independent: <code>open → in_progress → rotated → resolved</code> (or <code>wontfix</code>) — flips automatically when a rotation event lands or manually via the Remediation Approve flow.</Li>
        <Li>Every transition writes an <code>audit_events</code> row with the actor, before/after values, and the optimistic-lock version.</Li>
        <Li>Concurrent edits raise <code>409 stale_version</code>; clients must reload and re-issue with the new <code>expected_version</code>.</Li>
      </ul>

      <H3>D. API changelog</H3>
      <Tbl headers={["Version / date", "Change", "Migration impact"]} rows={[
        ["v1.0 — 2025 GA", "Initial public API.", "—"],
        ["v1.1 — 2026-05-24 (Sprint 0)", "Fixed dispatcher bug — API keys now successfully authenticate (previously 401 for every vooda_ key).", "Existing keys begin working — no migration."],
        ["v1.1 — 2026-05-24 (Sprint 1)", "Added per-key scope enforcement, per-principal rate limiting, API-key status badges, last-used display.", "Keys without admin scope are now denied at admin endpoints (was previously a no-op)."],
        ["v1.2 — 2026-05-24 (Sprint 2)", "Added key rotation with grace period (/api-keys/{id}/rotate), per-key usage analytics (/api-keys/{id}/usage), X-API-Key alternate header.", "Additive."],
        ["v1.3 — 2026-05-24 (Sprint 3)", "Added per-key IP allowlist (allowed_ip_cidrs on create + PATCH endpoint) + new api_key_ip_blocked audit action. Migration b5c6d7e8f9a0 + c6d7e8f9a0b1.", "Additive — existing keys default to unrestricted."],
        ["v1.4 — 2026-05-24 (QA fixes)", "Tightened name validation (1–255 chars); fixed login_failed audit for unknown emails; OIDC callback now returns directive 501 with IdP quickstart hints.", "Empty / 300+ char names now 422 (was 201 / 500). API-key list endpoint now returns Active + Expired + Revoked (was filtered to active only)."],
      ]} />

      <Tip>The next planned changes (Q2): <code>vooda_live_</code> / <code>vooda_test_</code> environment-namespaced prefixes, and a defence-in-depth swap from SHA-256 to bcrypt(sha256(raw)) for key hashing. Both are additive — no breaking changes planned.</Tip>
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 20 — CI/CD INTEGRATION
// ═══════════════════════════════════════════════════════════════
function CicdContent() {
  return (
    <>
      <RoleBox role="developer (use); security-lead (configure); agent (API key in pipeline)" see="api" />

      <H2>Pre-commit Hook Setup</H2>
      <P>Install the Vooda pre-commit hook either via the <em>pre-commit</em> framework or as a raw git hook.</P>
      <Code>{`# Option A — pre-commit framework (.pre-commit-config.yaml)
repos:
  - repo: https://github.com/vooda-ai/pre-commit-hook
    rev: v1.0.0
    hooks:
      - id: vooda-push-protection
        env:
          VOODA_API_URL: https://vooda.acme.com
          VOODA_API_KEY: \${VOODA_API_KEY}

# Then activate
pre-commit install --hook-type pre-push`}</Code>
      <H3>Handling blocked pushes</H3>
      <P>When a push is blocked, the developer sees the offending file, line, rule_id, and a remediation hint. Bypassing requires the org-policy bypass flow.</P>

      <H2>GitHub Actions Example</H2>
      <Code>{`# .github/workflows/vooda.yml
name: Vooda Secret Scan
on:
  pull_request:
  push:
    branches: [main]

jobs:
  vooda-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }

      - name: Vooda gate check
        env:
          VOODA_API_URL: \${{ vars.VOODA_API_URL }}
          VOODA_API_KEY: \${{ secrets.VOODA_API_KEY }}
          REPO_ID: \${{ vars.VOODA_REPO_ID }}
        run: |
          set -e
          # Trigger scan on this commit
          scan=$(curl -sf -X POST "$VOODA_API_URL/api/v1/repositories/$REPO_ID/scan" \\
            -H "Authorization: ApiKey $VOODA_API_KEY" -H "Content-Type: application/json" \\
            -d "{\\"branch\\":\\"$GITHUB_REF_NAME\\",\\"commit_sha\\":\\"$GITHUB_SHA\\"}")
          job_id=$(echo "$scan" | jq -r .scan_job_id)

          # Poll for completion (max 10 min)
          for i in $(seq 1 60); do
            status=$(curl -sf "$VOODA_API_URL/api/v1/scan-jobs/$job_id" -H "Authorization: ApiKey $VOODA_API_KEY" | jq -r .status)
            [ "$status" = "completed" ] && break
            [ "$status" = "failed" ]    && { echo "Scan failed"; exit 2; }
            sleep 10
          done

          # Gate check
          gate=$(curl -sf -X POST "$VOODA_API_URL/api/v1/gates/check" \\
            -H "Authorization: ApiKey $VOODA_API_KEY" -H "Content-Type: application/json" \\
            -d "{\\"repo_id\\":\\"$REPO_ID\\",\\"commit_sha\\":\\"$GITHUB_SHA\\"}")
          if [ "$(echo $gate | jq -r .status)" != "pass" ]; then
            echo "::error::Vooda gate failed:"
            echo "$gate" | jq .findings_summary
            exit 1
          fi`}</Code>

      <H2>GitLab CI Example</H2>
      <Code>{`# .gitlab-ci.yml
vooda_scan:
  stage: test
  image: alpine:3
  before_script: [apk add --no-cache curl jq]
  script:
    - |
      scan=$(curl -sf -X POST "$VOODA_API_URL/api/v1/repositories/$VOODA_REPO_ID/scan" \\
        -H "Authorization: ApiKey $VOODA_API_KEY" -H "Content-Type: application/json" \\
        -d "{\\"branch\\":\\"$CI_COMMIT_REF_NAME\\",\\"commit_sha\\":\\"$CI_COMMIT_SHA\\"}")
      # Poll + gate check (same pattern as 20.2)
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'`}</Code>

      <H2>Jenkins Example</H2>
      <Code>{`// Jenkinsfile
pipeline {
  agent any
  environment {
    VOODA_API_URL = credentials('vooda-url')
    VOODA_API_KEY = credentials('vooda-api-key')
    VOODA_REPO_ID = 'repo_01H...'
  }
  stages {
    stage('Vooda gate') {
      steps {
        sh '''
          set -e
          # Trigger + poll + gate-check (same pattern as 20.2)
          gate=$(curl -sf -X POST "$VOODA_API_URL/api/v1/gates/check" \\
            -H "Authorization: ApiKey $VOODA_API_KEY" \\
            -H "Content-Type: application/json" \\
            -d "{\\\\"repo_id\\\\":\\\\"$VOODA_REPO_ID\\\\",\\\\"commit_sha\\\\":\\\\"$GIT_COMMIT\\\\"}")
          [ "$(echo $gate | jq -r .status)" = "pass" ] || exit 1
        '''
      }
    }
  }
}`}</Code>

      <H2>IDE integration</H2>
      <P>
        We get this question every week: <em>"where&apos;s the VS Code / JetBrains plugin?"</em>
        The honest answer: Vooda intentionally doesn&apos;t ship one, because the IDE is the wrong
        intervention point.
      </P>
      <H3>Why not an IDE plugin?</H3>
      <ul className="space-y-2 my-3">
        <Li><strong>Coverage is fragile.</strong> A linter that runs while you type misses secrets in files you didn&apos;t open this session, in branches you haven&apos;t checked out, and in history.</Li>
        <Li><strong>Latency budget is tiny.</strong> Editor plugins need to respond in &lt; 100 ms; full secret-pattern matching + verifier round-trips can&apos;t fit in that envelope.</Li>
        <Li><strong>It moves enforcement to the developer&apos;s laptop</strong> — easily disabled, easily out-of-date.</Li>
      </ul>
      <H3>What to use instead — pre-commit + push-protection</H3>
      <P>
        Vooda&apos;s push-protection hook gives you the same "blocked before it leaves my laptop" UX
        as an IDE plugin, but enforced by git rather than by a settings checkbox the developer can toggle off.
        It also catches secrets in commits you didn&apos;t hand-write (cherry-picks, merge artefacts, generated files).
      </P>

      <H3>Install with the pre-commit framework</H3>
      <Code>{`# .pre-commit-config.yaml
repos:
  - repo: https://github.com/vooda-ai/pre-commit-hook
    rev: v1.0.0
    hooks:
      - id: vooda-push-protection
        env:
          VOODA_API_URL: https://api.vooda.ai/v1
          VOODA_API_KEY: \${VOODA_API_KEY}

# then activate
pre-commit install --hook-type pre-push
pre-commit install --hook-type pre-commit`}</Code>

      <H3>Install as a raw git hook (no framework)</H3>
      <Code>{`# .git/hooks/pre-push (chmod +x after creating)
#!/usr/bin/env bash
set -e
DIFF=$(git diff --cached --no-color | base64)
RESP=$(curl -fsS -X POST "$VOODA_API_URL/scan/inline" \\
  -H "Authorization: Bearer $VOODA_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d "{\\"diff_base64\\":\\"$DIFF\\"}")
STATUS=$(echo "$RESP" | jq -r .status)
if [ "$STATUS" != "pass" ]; then
  echo "🛑 Vooda blocked the push — secret detected:"
  echo "$RESP" | jq .findings
  exit 1
fi`}</Code>

      <H3>When the dev needs an IDE-level lookup (no commit involved)</H3>
      <P>
        Use the <code>scan/inline</code> endpoint from any editor that supports a custom external command.
        Working examples:
      </P>
      <Tbl headers={["Editor", "How", "Latency"]} rows={[
        ["VS Code",      "Run a Task that pipes the selection through curl /scan/inline.", "~200 ms for &lt; 5 KB selection"],
        ["JetBrains",    "External Tools → custom action invoking the same curl.",        "~200 ms"],
        ["Neovim",       "<code>:!curl … &lt; %</code> mapped to a keybinding.",          "~150 ms"],
      ]} />

      <Tip>If you genuinely want a Vooda-branded IDE plugin, tell us why — open a feature request. We&apos;ll build it when there&apos;s a strong product case beyond "GitGuardian has one."</Tip>

      <H2>Generic Pipeline Pattern</H2>
      <ol className="space-y-2 my-3 list-decimal list-inside text-[15px] text-slate-400">
        <li>Authenticate with API key (<code>Authorization: ApiKey vk_live_...</code>)</li>
        <li>Trigger a scan with <code>POST /repositories/&#123;id&#125;/scan</code> — capture <code>scan_job_id</code></li>
        <li>Poll <code>GET /scan-jobs/&#123;id&#125;</code> until <code>status=completed</code> (timeout suggested: 10 min)</li>
        <li>Call <code>POST /gates/check</code> with the commit SHA</li>
        <li>If body <code>status != "pass"</code>, fail the pipeline and surface the violations</li>
      </ol>
      <Tip>Need lower latency? Skip step 2's polling by listening to the WebSocket (<code>/api/v1/ws/scan/&#123;scan_job_id&#125;?token=&lt;jwt&gt;</code>) — most pipeline runners support this with <code>websocat</code>.</Tip>

      <H2>SARIF Import</H2>
      <P>Push results from external scanners (Semgrep, Trivy, Snyk) into Vooda for unified triage:</P>
      <Code>{`semgrep --config p/secrets --sarif > results.sarif
curl -X POST $VOODA_API_URL/api/v1/findings/import \\
  -H "Authorization: ApiKey $VOODA_API_KEY" \\
  -H "Content-Type: application/sarif+json" \\
  --data-binary @results.sarif`}</Code>

      <NextSteps items={[
        { label: "API Reference", href: "/docs?section=api", desc: "Every endpoint your pipeline can hit." },
        { label: "Quickstart", href: "/docs?section=quickstart", desc: "From signup to first finding in 5 minutes." },
        { label: "Troubleshooting", href: "/docs?section=troubleshooting", desc: "Error code catalog + common pipeline issues." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 21 — ADMINISTRATION
// ═══════════════════════════════════════════════════════════════
function AdminContent() {
  return (
    <>
      <RoleBox role="org-admin" />

      <H2>Organization Settings</H2>
      <ul className="space-y-2 my-3">
        <Li><strong>Display name + logo</strong> — branded headers and PDF reports.</Li>
        <Li><strong>Default scan schedule</strong> — applied to new repositories unless overridden.</Li>
        <Li><strong>Retention policies</strong> — finding history (default 5 years), audit log (default 365 days), AI triage events (default 365 days).</Li>
        <Li><strong>Default policy</strong> — the policy applied when none is specified on a gate-check.</Li>
        <Li><strong>Time zone</strong> — affects schedule expressions and report date ranges.</Li>
      </ul>

      <H2>Database Migrations</H2>
      <P>Schema migrations are managed by Alembic. Migrations run automatically on API startup unless <code>SKIP_AUTO_MIGRATE=1</code>.</P>
      <Code>{`# Run migrations manually
docker compose exec api alembic upgrade head

# Inspect current revision
docker compose exec api alembic current

# Roll back one revision (only if safe — see migration notes)
docker compose exec api alembic downgrade -1`}</Code>
      <Warn>Rolling back across migrations that drop columns or types is irreversible. Take a database snapshot before any downgrade.</Warn>

      <H2>Scaling</H2>
      <Tbl headers={["Knob", "Variable", "Default", "Effect"]} rows={[
        ["Worker concurrency", "CELERY_CONCURRENCY", "4", "Parallel scans per worker container."],
        ["Worker replicas", "WORKER_REPLICAS", "1", "Horizontal scale of the worker service (Compose / K8s)."],
        ["API workers", "API_WORKERS", "4", "Uvicorn workers per API container."],
        ["API replicas", "API_REPLICAS", "1", "Horizontal scale of the API service."],
        ["Beat scheduler", "Single instance only", "—", "Run exactly one beat to avoid duplicate task fan-out."],
        ["Redis memory", "REDIS_MAXMEMORY", "1gb", "Redis cache + broker memory cap."],
        ["Postgres connections", "DB_POOL_SIZE", "20", "SQLAlchemy pool per API worker."],
      ]} />
      <Tip>For 1000+ repositories, run 4–8 worker replicas (each with concurrency=4), 2 API replicas, and a Redis with 4 GB memory and AOF persistence enabled.</Tip>

      <H2>Backup &amp; Recovery</H2>
      <ul className="space-y-2 my-3">
        <Li><strong>PostgreSQL</strong> — nightly <code>pg_dump</code> + WAL archiving for point-in-time recovery. Encrypt at rest.</Li>
        <Li><strong>Redis</strong> — enable AOF (<code>appendonly yes, appendfsync everysec</code>). Calibration cache loss only impacts triage accuracy briefly; the broker queue is reconstructed from the DB.</Li>
        <Li><strong>Object storage</strong> — if integrations include S3 / GCS / Azure Blob caches, snapshot bucket policies and lifecycle rules.</Li>
        <Li><strong>Restore drill</strong> — quarterly: restore the latest dump to a sandbox, verify migrations apply cleanly, run a representative scan.</Li>
      </ul>

      <H2>Log Management</H2>
      <P>All services emit <strong>structured JSON</strong> logs (one event per line) via <code>structlog</code>. Set <code>LOG_LEVEL</code> to <em>DEBUG / INFO / WARNING / ERROR</em>. Pipe logs to your collector of choice:</P>
      <Code>{`# Vector example: forward to Splunk HEC
[sources.vooda]
type = "docker_logs"
include_containers = ["vooda-api", "vooda-worker", "vooda-web"]

[sinks.splunk]
type = "splunk_hec"
inputs = ["vooda"]
endpoint = "https://splunk.acme.com:8088"
default_token = "$SPLUNK_HEC_TOKEN"
encoding.codec = "json"`}</Code>

      <H2>Health Checks</H2>
      <Tbl headers={["Endpoint", "Returns", "Use"]} rows={[
        ["GET /api/health", "200 if API + DB reachable", "Load-balancer liveness / readiness."],
        ["GET /healthz", "200 process liveness", "Lightweight liveness probe."],
      ]} />

      <H2>Upgrading Vooda</H2>
      <Step n={1} title="Read the release notes">
        Each release ships a <code>CHANGELOG.md</code> entry — note any breaking-migration warnings.
      </Step>
      <Step n={2} title="Snapshot the database">
        <code>pg_dump -Fc -f vooda-pre-upgrade-&lt;date&gt;.dump</code>.
      </Step>
      <Step n={3} title="Pull and rebuild">
        <code>./install.sh update</code> (or manually: <code>git pull &amp;&amp; docker compose build &amp;&amp; docker compose up -d</code>).
        Data volumes are preserved and migrations run on API startup. No prebuilt image is published, so
        <code>docker compose pull</code> will not fetch new code — you must rebuild.
      </Step>
      <Step n={4} title="Verify">
        Hit <code>/api/health</code>; run a smoke scan; check <code>alembic current</code>.
      </Step>
      <Step n={5} title="Roll back (if needed)">
        Restore the database snapshot and pin the previous image tag. Forward-only migrations may require restoring before re-applying.
      </Step>

      <NextSteps items={[
        { label: "Security Hardening", href: "/docs?section=hardening", desc: "TLS, network policies, secret-at-rest, audit retention." },
        { label: "Users & Organization", href: "/docs?section=users", desc: "User lifecycle + SSO + SCIM (Q3 2026)." },
        { label: "Troubleshooting", href: "/docs?section=troubleshooting", desc: "Error code catalog + scaling diagnostics." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 22 — SECURITY HARDENING
// ═══════════════════════════════════════════════════════════════
function HardeningContent() {
  return (
    <>
      <RoleBox role="org-admin + infrastructure team" />

      <H2>Network Isolation</H2>
      <P>Recommended firewall topology for a production install:</P>
      <Tbl headers={["Component", "Listens", "Ingress", "Egress"]} rows={[
        ["Reverse proxy (NGINX / Caddy / ALB)", "443", "Public, TLS only", "→ web (3000), api (8000)"],
        ["web", "3000", "Reverse proxy only", "→ api"],
        ["api", "8000", "Reverse proxy + worker only", "→ db, redis, AI providers, integrations"],
        ["worker", "—", "—", "→ db, redis, git providers, AI, integrations"],
        ["postgres", "5432", "api + worker only (private network)", "—"],
        ["redis", "6379", "api + worker + beat only (private)", "—"],
      ]} />
      <Tip>In Kubernetes, encode this with NetworkPolicy. In Docker Compose, place <code>db</code> and <code>redis</code> on an internal network with <code>internal: true</code>.</Tip>

      <H2>Secrets Management for Vooda Itself</H2>
      <P>Never commit <code>.env</code> with real values. Source secrets at runtime from one of:</P>
      <ul className="space-y-2 my-3">
        <Li><strong>Cloud secret manager</strong> (AWS Secrets Manager / GCP Secret Manager / Azure Key Vault) — inject as env via the orchestrator's secret-mounting feature.</Li>
        <Li><strong>HashiCorp Vault</strong> — agent-injector or sidecar pattern.</Li>
        <Li><strong>Encrypted SOPS files</strong> — committed alongside config but decrypted at deploy time with a KMS key.</Li>
      </ul>
      <P>Vooda's required secrets:</P>
      <Tbl headers={["Variable", "Sensitivity", "Rotation cadence"]} rows={[
        ["SECRET_KEY", "Critical — JWT signing", "Annually, with rolling JWK support"],
        ["DATABASE_URL", "Critical — DB password", "Quarterly"],
        ["REDIS_URL", "High — Redis auth", "Quarterly"],
        ["ANTHROPIC_API_KEY / OPENAI_API_KEY / etc.", "High", "Quarterly, or on suspected compromise"],
        ["Integration credentials (vault, IAM)", "High", "Per integration's own policy"],
      ]} />

      <H2>TLS Configuration</H2>
      <P>Terminate TLS at your reverse proxy. Recommended posture:</P>
      <ul className="space-y-2 my-3">
        <Li>TLS 1.3 only (TLS 1.2 acceptable as a transition); disable TLS 1.0/1.1.</Li>
        <Li>Cipher suites: AEAD only (AES-GCM, ChaCha20-Poly1305).</Li>
        <Li>Strict-Transport-Security: <code>max-age=63072000; includeSubDomains; preload</code>.</Li>
        <Li>Certificate transparency monitoring enabled (e.g. via Cloudflare or your CA).</Li>
        <Li>Hybrid X25519 + ML-KEM key exchange where the proxy supports it (NGINX 1.27+ / OpenSSL 3.5+).</Li>
      </ul>

      <H2>Credential Encryption at Rest</H2>
      <P>
        Integration credentials (Slack tokens, vault tokens, AWS access keys) are encrypted at rest with
        AES-256-GCM. The data-encryption key is wrapped by a tenant-scoped KEK derived from
        <code> SECRET_KEY</code>. Database backups inherit the encryption — restoring without the original
        <code> SECRET_KEY</code> yields unreadable credentials, by design.
      </P>
      <Warn>If <code>SECRET_KEY</code> is lost without prior re-keying, all stored integration credentials become unrecoverable. Maintain at least two operators with KMS access to the SECRET_KEY storage.</Warn>

      <H2>Audit Log Integrity</H2>
      <P>The audit table includes a <code>chain_hash</code> column — each record's hash is the SHA-256 of the previous record's hash plus the canonicalized current record. Any retroactive deletion or modification breaks the chain. Periodically:</P>
      <ul className="space-y-2 my-3">
        <Li>Verify the chain end-to-end: <code>POST /api/v1/audit/verify-chain</code>.</Li>
        <Li>Ship audit events to an append-only SIEM / object store (S3 with Object Lock) for tamper-evident archival.</Li>
        <Li>Snapshot the chain head daily to an external system; mismatch on next verification flags tampering.</Li>
      </ul>

      <H2>Penetration Testing Guidance</H2>
      <P>Areas to focus a pen-test engagement on:</P>
      <ul className="space-y-2 my-3">
        <Li>Auth boundary — token forgery, refresh-token replay, SSO assertion injection (XML-Sig wrapping for SAML).</Li>
        <Li>Authorization — cross-tenant access attempts, BU-scope bypass, permission elevation via SSO group.</Li>
        <Li>Webhook receivers — HMAC bypass, replay, payload size DoS.</Li>
        <Li>SSRF — any place the platform fetches a user-supplied URL (custom AI base URL, custom webhook destination, integration test endpoints). Egress should be allowlisted.</Li>
        <Li>Push-protection bypass — verify bypass requires permission + justification + audit entry.</Li>
        <Li>Integration credential exfiltration — confirm decrypted values never leave server memory in logs / errors.</Li>
      </ul>
      <Tip>Use <code>auditor</code>-role API keys (read-only, time-bounded) for external testers. Revoke immediately after engagement; the audit log preserves all access for review.</Tip>

      <NextSteps items={[
        { label: "Administration", href: "/docs?section=admin", desc: "Operational settings that complement the hardening rules above." },
        { label: "Reporting & Compliance", href: "/docs?section=reporting", desc: "SOC 2 / ISO 27001 / PCI-DSS mappings + evidence packs." },
        { label: "API Reference — Authentication", href: "/docs?section=api", desc: "Per-key IP allowlist + scope + rotation." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// TROUBLESHOOTING
// ═══════════════════════════════════════════════════════════════
function TroubleshootingContent() {
  return (
    <>
      <H2>Login &amp; Sessions</H2>
      <ul className="space-y-2 my-3">
        <Li><strong>"401 unauthorized" immediately after login</strong> — clock skew &gt; 60s between client and server. Sync NTP on both ends.</Li>
        <Li><strong>SSO: "RelayState" error</strong> — your IdP is dropping RelayState on the redirect. Configure RelayState forwarding (Okta: enable in app settings; Azure AD: native).</Li>
        <Li><strong>Repeated forced logouts</strong> — the access token expired mid-session. Ensure the client re-authenticates via <code>/api/v1/auth/login</code> on a 401 instead of looping, and consider raising <code>ACCESS_TOKEN_EXPIRE_MINUTES</code>.</Li>
      </ul>

      <H2>Scans</H2>
      <ul className="space-y-2 my-3">
        <Li><strong>Scan stuck in <em>queued</em></strong> — no worker is processing the queue. <code>docker compose logs worker --tail=100</code>; verify Redis connectivity.</Li>
        <Li><strong>Repeated full scans on every run</strong> — branch checkpoint not being updated. Inspect <code>repo_branch_checkpoints</code> table; check if force-push is happening (the platform falls back to full scan when prior commit is unreachable).</Li>
        <Li><strong>"Repository clone failed: authentication required"</strong> — token expired or insufficient scope. Reissue with the scopes listed in the Add a repository and scan guide.</Li>
        <Li><strong>OOM during scan</strong> — large repos (&gt;1 GB) exceed default worker memory. Set <code>mem_limit: 4g</code> on the worker service.</Li>
      </ul>

      <H2>Findings &amp; AI</H2>
      <ul className="space-y-2 my-3">
        <Li><strong>AI triage stuck on "pending"</strong> — provider rate-limit hit. Check <code>/api/v1/ai-models</code>; raise rate limits or add a second provider for failover.</Li>
        <Li><strong>"AI confidence is the same as raw"</strong> — calibration table empty. Need ≥10 corrections per (scanner, rule, category) for calibration to engage.</Li>
        <Li><strong>Verifier always returns inactive</strong> — likely network egress blocked. Worker needs outbound HTTPS to provider auth endpoints.</Li>
      </ul>

      <H2>Sources</H2>
      <ul className="space-y-2 my-3">
        <Li><strong>Slack: <code>missing_scope</code></strong> — bot token lacks a required scope (under Connect integrations → Slack). Add the scope, reinstall the app, update the token.</Li>
        <Li><strong>Slack: <code>not_in_channel</code></strong> — invite the bot: <code>/invite @Vooda Secret Scanner</code>.</Li>
        <Li><strong>Atlassian: 401 / 403</strong> — token expired or user lacks project access.</Li>
        <Li><strong>S3: <code>AccessDenied</code></strong> — IAM user missing <code>s3:ListBucket</code> or <code>s3:GetObject</code>.</Li>
        <Li><strong>Test Connection passes but scan returns 0 items</strong> — scope filter too narrow; verify channel IDs / project keys / bucket names.</Li>
      </ul>

      <H2>Performance</H2>
      <ul className="space-y-2 my-3">
        <Li><strong>Slow API</strong> — index <code>findings(tenant_id, severity, created_at)</code> if missing; enable PgBouncer; raise <code>API_WORKERS</code>.</Li>
        <Li><strong>Slow finding queries</strong> — too many filters on JSONB <code>source_metadata</code>. Add a GIN index for the keys you commonly filter on.</Li>
        <Li><strong>WebSocket disconnects</strong> — proxy idle timeout shorter than ping interval. Set NGINX <code>proxy_read_timeout 120s;</code>.</Li>
      </ul>

      <H2>Error code catalog</H2>
      <P>
        Every Vooda 4xx / 5xx response carries an actionable string in the body (or in <code>detail.error</code>
        for structured errors). Search this table by the exact code your client received.
      </P>
      <Tbl headers={["Code", "Where it surfaces", "Meaning", "Resolution"]} rows={[
        ["E_AUTH_MISSING",        "401 on any authenticated endpoint", "No Authorization header AND no X-API-Key header.", "Supply Authorization: Bearer <jwt> OR X-API-Key: <vooda_…>."],
        ["E_AUTH_INVALID",        "401",                            "Token signature invalid, expired, or malformed.", "Re-login via POST /auth/login. For API keys, confirm it wasn't revoked: GET /api-keys."],
        ["E_AUTH_KEY_EXPIRED",    "401 detail='API key expired'",   "expires_at is in the past.", "Rotate the key: POST /api-keys/{id}/rotate."],
        ["E_AUTH_IP_BLOCKED",     "403 detail='not permitted from this source IP'", "Source IP not in the key's allowed_ip_cidrs.", "Add your egress IP to the allowlist via PATCH /api-keys/{id} — or contact your admin."],
        ["E_SCOPE_MISSING",       "403 detail='missing required scope'", "API key lacks the required scope for this endpoint.", "Detail message names the required + granted scopes. Create a key with the right scope OR use an admin-scope key."],
        ["E_RATE_LIMITED",        "429 with Retry-After header",    "Per-principal rate limit exceeded.", "Wait Retry-After seconds; login attempts are rate-limited more strictly than API calls."],
        ["E_REPO_CLONE_FAILED",   "scan.failed webhook + scan_jobs.error_code", "Git clone returned non-zero — usually auth or network.", "Re-test the credential: POST /repositories/probe. If GitHub App, check installation hasn't been revoked."],
        ["E_REPO_TIMEOUT",        "scan.failed",                    "Clone or scan exceeded the 2-hour soft limit.", "For monorepos: enable shallow history-mode, restrict branch_patterns, or raise the limit under Settings → AI Engine Settings."],
        ["E_AI_QUOTA_EXCEEDED",   "scan completes but ai_triaged=0; stats.ai_skip_reason='quota_exceeded'", "Configured AI provider returned 429.", "Increase the provider's rate-limit (e.g., upgrade Anthropic tier), or add a fallback model in Settings → AI Models."],
        ["E_AI_NOT_CONFIGURED",   "ai_triaged=0; stats.ai_skip_reason='not_configured'", "No active AI provider.", "Settings → AI Models → + Add Provider. Mistral-small via OpenRouter is the cheapest production-ready option."],
        ["E_STALE_VERSION",       "409",                            "Optimistic-lock failure — another writer updated the resource between your GET and PATCH.", "Re-fetch the resource, copy the new version field, retry the write."],
        ["E_WEBHOOK_SIGNATURE_INVALID", "401 from inbound webhook receivers", "HMAC signature doesn't match the configured secret.", "Re-copy the secret from /webhooks/config, set it in the provider's webhook config, click Test in the provider's UI."],
        ["E_INTEGRATION_AUTH_FAILED", "Integration test card shows 'Auth failed'", "Stored credential is expired or revoked at the provider.", "Re-authenticate: Settings → Integrations → [name] → Edit credentials. For OAuth integrations, disconnect + reconnect."],
        ["E_VALIDATION_CIDR",     "422 on POST/PATCH /api-keys with allowlist", "Invalid CIDR entry.", "Detail names the offending entry. Use forms like 203.0.113.0/24 or 2001:db8::/32; a bare IP is treated as /32."],
        ["E_NAME_LENGTH",         "422 on POST/PATCH /api-keys, /users, /custom-detectors", "name field empty or > 255 chars.", "Trim or shorten the name."],
      ]} />

      <H3>Where to find the request_id for support escalation</H3>
      <P>Every 5xx response includes an <code>X-Request-ID</code> response header AND a <code>trace_id</code> in the body. Quote either when filing a support ticket — we can pull the full request + downstream call chain from observability with that ID.</P>

      <H2>Getting Help</H2>
      <P>If the above doesn't resolve the issue:</P>
      <ul className="space-y-2 my-3">
        <Li>Check structured logs: <code>docker compose logs api --tail=200 | grep ERROR</code></Li>
        <Li>Inspect the audit log under <strong>Settings → Audit</strong> for failed operations.</Li>
        <Li>Open the Swagger UI at <code>/api/docs</code> to test endpoints directly and isolate the issue.</Li>
        <Li>For commercial-support customers: open a ticket with the <code>trace_id</code> from the failing request.</Li>
      </ul>

      <NextSteps items={[
        { label: "API Reference", href: "/docs?section=api", desc: "Full operation cards + Swagger UI." },
        { label: "FAQ", href: "/docs?section=faq", desc: "Pricing, support tiers, data residency." },
        { label: "Glossary", href: "/docs?section=glossary", desc: "Canonical terminology — what each word actually means in Vooda." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// GLOSSARY (Reference)
// ═══════════════════════════════════════════════════════════════
function GlossaryContent() {
  return (
    <>
      <RoleBox role="any" />

      <H2>Glossary</H2>
      <P>
        Vooda uses precise terminology — these definitions are canonical. When something in the UI
        or API says "secret" it always means this, not the broader colloquial sense of "anything
        sensitive". Use this page to resolve any ambiguity when reading other sections of the docs
        or talking to support.
      </P>

      <H3>Credentials & detections</H3>
      <Tbl headers={["Term", "Definition", "Not to be confused with"]} rows={[
        ["Secret",        "A literal credential string that grants access to a system — API key, token, certificate, password, connection string.", "PII (names, addresses), business-sensitive data, intellectual property."],
        ["Credential",    "Synonym for secret in Vooda's vocabulary.", "Used interchangeably with secret."],
        ["Token",         "A specific class of secret with a bounded lifetime (OAuth tokens, JWTs, session tokens).", "API keys (long-lived, not tokens)."],
        ["API key",       "A specific class of secret used as the static authenticator for a service.", "User passwords."],
        ["Finding",       "ONE detection at ONE location (file + line). The same secret in 30 files = 30 findings.", "Incident."],
        ["Incident",      "ONE unique credential, regardless of how many locations expose it. Findings roll up to incidents via secret_hash.", "Finding."],
        ["Verified live", "Vooda made an authenticated call against the upstream service and got a 2xx — the credential currently grants access.", "Verified valid (we don't use that term)."],
        ["Verified dead", "Same call returned 401/403 — the credential has been revoked.", "False positive (a dead key is still a TP if it was real once)."],
      ]} />

      <H3>Triage & classification</H3>
      <Tbl headers={["Term", "Definition", "Not to be confused with"]} rows={[
        ["True Positive (TP)",  "A real, possibly-exploitable credential discovered in code.", "Verified live (a TP can be dead — was real, now revoked)."],
        ["False Positive (FP)", "A scanner match that is NOT a real credential — test fixture, doc example, random hex string.", "Suppressed (suppression is a decision; FP is a classification)."],
        ["Accepted Risk",       "A real credential the org has decided to leave in place (e.g. demo key in /examples, hardcoded by design).", "False positive."],
        ["Needs Review",        "AI triage was inconclusive — confidence below the auto-classify threshold. Awaiting human decision.", "Unreviewed (just means no decision yet)."],
        ["Suppression",         "A pattern-based rule that auto-classifies future matches as FP without human review.", "Rule Override."],
        ["Rule Override",       "A proactive disable of a built-in scanner rule org-wide or per-repo. Prevents the finding from being created at all.", "Suppression."],
      ]} />

      <H3>Scanning surfaces</H3>
      <Tbl headers={["Term", "Definition", "Not to be confused with"]} rows={[
        ["Push Protection",  "Pre-commit / pre-push inline scan that blocks the push if a critical secret is detected.", "Gate check (PR-time)."],
        ["Gate Check",       "PR-time scan that fails the CI pipeline if a new critical finding lands.", "Push Protection (developer-laptop time)."],
        ["Standalone scan",  "Scan of HEAD on one branch — the default scan_type.", "History scan."],
        ["History scan",     "Scan across all commits in the repo. Slower but catches secrets that were committed and later removed.", "Standalone scan."],
        ["Scan Source",      "A non-git location Vooda scans — a Jira project, an S3 bucket, or a container registry.", "Repository (always git)."],
        ["Repository",       "A connected Git remote (GitHub / GitLab / Bitbucket / bare URL).", "Scan Source."],
      ]} />

      <H3>Org structure & remediation</H3>
      <Tbl headers={["Term", "Definition", "Not to be confused with"]} rows={[
        ["Tenant",           "One isolated customer organization in Vooda's multi-tenant database.", "Business Unit."],
        ["Business Unit (BU)", "Org-level grouping for access control and metrics. Repos + Sources + Users can be tagged.", "Tenant (we are multi-tenant, but BU is intra-tenant)."],
        ["Rotation Event",   "An audit-logged record that a specific secret was rotated, by whom, when, and verified-dead-after.", "Remediation Plan."],
        ["Remediation Plan", "An AI-generated step-by-step rotation playbook — must be approved before execution.", "Rotation Event."],
        ["Audit Event",      "A row in audit_events recording any state-changing action (auth, triage, rotation, config change).", "Rotation Event (which is a specific kind of audit event)."],
        ["Verifier",         "A small adapter that calls the upstream service to confirm a credential is live. 90+ secret types have one.", "AI triage (verifier is deterministic, doesn't use an LLM)."],
      ]} />

      <NextSteps items={[
        { label: "Findings", href: "/docs?section=findings", desc: "How TP / FP / Accepted Risk get applied in the UI." },
        { label: "AI Triage Engine", href: "/docs?section=ai-triage", desc: "The verdict + reasoning + confidence pipeline." },
        { label: "API Reference", href: "/docs?section=api", desc: "Every endpoint that mutates the things defined here." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// FAQ
// ═══════════════════════════════════════════════════════════════
function FaqContent() {
  return (
    <>
      <H2>General</H2>
      <ul className="space-y-3 my-3">
        <Li><strong>How accurate is Vooda?</strong> The multi-stage pipeline (rules → live verifier → AI triage → per-tenant calibration) is built to catch real secrets while cutting the false positives regex-only scanners produce. The most meaningful measure is a benchmark on a repo you control — we&apos;ll run one against your current tool on request.</Li>
        <Li><strong>Does the AI triage send my source code to a third party?</strong> Only if you configure a hosted AI provider. Self-host an OpenAI-compatible endpoint to keep code on-prem.</Li>
        <Li><strong>How is the rule pack updated?</strong> Rules ship with each Vooda release. Custom detectors (the Write a custom detector guide) are tenant-scoped and don't depend on releases.</Li>
        <Li><strong>How is finding deduplication handled across re-scans?</strong> By correlation key — see the Triage findings guide.</Li>
      </ul>

      <H2>Security</H2>
      <ul className="space-y-3 my-3">
        <Li><strong>Where are integration credentials stored?</strong> Encrypted at rest (AES-256-GCM, key wrapped by SECRET_KEY). See 22.4.</Li>
        <Li><strong>Are AI prompts logged?</strong> Yes, in <code>ai_triage_events</code> with retention default 365 days (configurable).</Li>
        <Li><strong>Can I run Vooda fully air-gapped?</strong> Yes — disable hosted AI providers and configure only self-hosted models + on-prem vault + on-prem git providers.</Li>
      </ul>

      <H2>Operations</H2>
      <ul className="space-y-3 my-3">
        <Li><strong>What's the recommended scaling for 5000 repos?</strong> 8 worker replicas × concurrency 4, 4 API replicas, Redis 8 GB AOF, Postgres 16 with 32 GB RAM and a 200 GB SSD.</Li>
        <Li><strong>Is HA/multi-region supported?</strong> Active-active multi-region is on the roadmap. Today: active-passive with PG read-replica + Redis Sentinel + warm-spare worker fleet.</Li>
        <Li><strong>What's the migration path from another secret scanner?</strong> Import existing findings via SARIF (the Triage findings guide), then re-scan to populate fresh evidence.</Li>
      </ul>

      <H2>Pricing &amp; Licensing</H2>
      <ul className="space-y-3 my-3">
        <Li><strong>Open source?</strong> The platform is proprietary. Detector rule pack is shipped as part of the licensed product.</Li>
        <Li><strong>What does enterprise support include?</strong> 24/7 incident response, named CSM, custom detector authoring, quarterly business review.</Li>
      </ul>

      <NextSteps items={[
        { label: "Quickstart", href: "/docs?section=quickstart", desc: "Try it yourself in 5 minutes." },
        { label: "Detection Accuracy", href: "/docs?section=accuracy", desc: "How Vooda catches real secrets while cutting false positives." },
      ]} />
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// CHANGELOG
// ═══════════════════════════════════════════════════════════════
function ChangelogContent() {
  return (
    <>
      <H2>Release notes</H2>
      <P>
        The Vooda community edition ships on a monthly cadence. Each release&apos;s changes —
        new detectors, source connectors, fixes, and any migration steps — are published with
        its GitHub release.
      </P>
      <P>
        You are running <strong>v{APP_VERSION}</strong>. To move to the latest release, run
        <code> ./install.sh update</code>, which pulls the new code and rebuilds without touching
        your data (it takes a database backup first).
      </P>
      <Note>Enterprise customers receive continuous detector and signature updates ahead of the monthly community cut, with release notes delivered through their support channel.</Note>
    </>
  );
}


// ═══════════════════════════════════════════════════════════════
// NEW PAGES (cold-start verified against the running instance)
// ═══════════════════════════════════════════════════════════════
function AirgappedContent() {
  return (
    <>
      <RoleBox role="operator (host shell + Vooda org-admin)" see="config-ref" />
      <H2>Install air-gapped with a local model</H2>
      <P>
        Vooda runs fully offline. The rule engine and detectors need no network, AI triage can run against a
        model you host, and the one outbound step — live credential verification — can be switched off. Nothing
        about a scan leaves your network.
      </P>
      <Note><strong>Prerequisites.</strong> Docker and Docker Compose on the target host, the Vooda repository
        (or its images) transferred in, and a local model runner such as <ExtLink href="https://ollama.com">Ollama</ExtLink>
        reachable from the host.</Note>
      <H3>Step 1 — Bring up the stack</H3>
      <Step n={1} title="Transfer the repository or images">
        On a connected machine, either clone the repository or <code>docker save</code> the built images and copy
        them to the air-gapped host. The stack itself pulls nothing at runtime.
      </Step>
      <Step n={2} title="Start Vooda in production mode">
        Run <code>./install.sh install --prod</code>. It generates secrets, starts the stack, and seeds the admin
        account. <em>Result:</em> the UI answers at <code>http://localhost:3000</code>.
      </Step>
      <H3>Step 2 — Turn off outbound verification</H3>
      <Step n={1} title="Set the flag in .env">
        Add <code>VERIFICATION_ENABLED=false</code> to <code>.env</code> and restart the API
        (<code>docker compose up -d api worker worker-scans</code>).
        <em> Result:</em> scans still complete; findings stay <code>not_validated</code> instead of calling provider APIs.
      </Step>
      <Warn>Live verification is the only step that reaches the internet. Leave it off in a true air-gapped
        deployment — otherwise the verifier will try to reach provider endpoints and time out.</Warn>
      <H3>Step 3 — Point AI triage at your local model</H3>
      <Step n={1} title="Run a model with Ollama">
        On the host, run e.g. <code>ollama run mistral-small</code>. Note the address the host exposes
        (Ollama defaults to <code>http://localhost:11434</code>).
      </Step>
      <Step n={2} title="Add the provider in Vooda">
        Go to <strong>Integrations &rarr; AI Provider &rarr; Add Provider</strong>, choose <strong>Ollama (Local)</strong>,
        and set the endpoint to <code>http://host.docker.internal:11434</code> (containers reach the host at
        <code> host.docker.internal</code>, not <code>localhost</code>). Leave the API key blank. Click
        <strong> Validate &amp; Load Models</strong> and pick your model. <em>Result:</em> the provider shows
        <strong> Triage</strong> and <strong>Remediation</strong> enabled.
      </Step>
      <Step n={3} title="Verify end to end">
        Add a repository, run a scan, and open a finding. <em>Result:</em> the finding shows an AI verdict and
        confidence with no outbound calls, and its validity stays <code>Unverified</code>.
      </Step>
      <Tip>Prefer another OpenAI-compatible runner (vLLM, LM Studio, LocalAI)? Choose <strong>Custom / Self-Hosted</strong>
        and set the endpoint URL — the flow is identical.</Tip>
      <NextSteps items={[
        { label: "Configure AI triage", href: "/docs?section=ai-triage", desc: "Tune context, batching, and confidence thresholds." },
        { label: "Back up and restore", href: "/docs?section=backup", desc: "Protect your data with scheduled dumps." },
        { label: "Configuration reference", href: "/docs?section=config-ref", desc: "Every environment variable, grouped." },
      ]} />
    </>
  );
}

function BackupContent() {
  return (
    <>
      <RoleBox role="operator (host shell)" />
      <H2>Back up and restore</H2>
      <P>
        All durable state lives in three Docker volumes: <code>pgdata</code> (Postgres — findings, config, users),
        <code> storage_data</code> (scan evidence and artifacts), and <code>redis_data</code> (transient queues,
        safe to lose). A database dump plus the storage volume is a complete backup.
      </P>
      <Note><strong>Prerequisites.</strong> A shell on the host running Docker Compose, from the repository root.</Note>
      <H3>Back up the database</H3>
      <Step n={1} title="Write a SQL dump">
        <Code>{`docker compose exec -T db sh -lc \\
  'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \\
  > vooda-db-$(date +%Y%m%d-%H%M%S).sql`}</Code>
        <em>Result:</em> a plain-SQL file you can restore into any Postgres 16 instance.
      </Step>
      <Step n={2} title="Back up the storage volume">
        <Code>{`docker run --rm -v vooda_storage_data:/data -v "$PWD:/backup" \\
  alpine tar czf /backup/vooda-storage-$(date +%Y%m%d).tar.gz -C /data .`}</Code>
      </Step>
      <H3>Restore</H3>
      <Step n={1} title="Restore the database">
        With the stack up and the database empty (fresh install), pipe the dump back in:
        <Code>{`docker compose exec -T db sh -lc \\
  'PGPASSWORD="$POSTGRES_PASSWORD" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \\
  < vooda-db-20260101-120000.sql`}</Code>
      </Step>
      <Step n={2} title="Restore storage">
        <Code>{`docker run --rm -v vooda_storage_data:/data -v "$PWD:/backup" \\
  alpine sh -c 'cd /data && tar xzf /backup/vooda-storage-20260101.tar.gz'`}</Code>
      </Step>
      <Tip><code>./install.sh update</code> takes a database dump automatically before every upgrade, so routine
        upgrades already leave you a restore point in <code>backups/</code>.</Tip>
      <NextSteps items={[
        { label: "Upgrade Vooda", href: "/docs?section=upgrade", desc: "Pull the latest release without losing data." },
        { label: "Configuration reference", href: "/docs?section=config-ref", desc: "Where each volume and path is set." },
      ]} />
    </>
  );
}

function UpgradeContent() {
  return (
    <>
      <RoleBox role="operator (host shell)" />
      <H2>Upgrade Vooda</H2>
      <P>
        Upgrades preserve your data volumes and run any pending database migrations automatically on API startup.
        The installer also snapshots the database first as a safety net.
      </P>
      <Note><strong>Prerequisites.</strong> A git checkout of the repository and a shell on the host.</Note>
      <H3>Recommended: the installer</H3>
      <Step n={1} title="Run the updater">
        <Code>{`./install.sh update`}</Code>
        It pulls the latest release, writes a database backup to <code>backups/</code>, rebuilds the images, and
        recreates the containers. <em>Result:</em> the stack comes back healthy on the same ports, with
        <code> pgdata</code>, <code>storage_data</code>, and <code>redis_data</code> untouched.
      </Step>
      <H3>Manual alternative</H3>
      <Step n={1} title="Pull, build, recreate">
        <Code>{`git pull --ff-only
docker compose build
docker compose up -d`}</Code>
        Migrations run on API startup — no separate migrate step is needed.
      </Step>
      <Warn>Never run <code>docker compose down -v</code> during an upgrade: the <code>-v</code> flag deletes the
        data volumes. Plain <code>up -d</code> recreates containers while keeping volumes.</Warn>
      <NextSteps items={[
        { label: "Back up and restore", href: "/docs?section=backup", desc: "Take a manual snapshot before a major upgrade." },
        { label: "Release notes", href: "/docs?section=changelog", desc: "What changed in this release." },
      ]} />
    </>
  );
}

function ConfigRefContent() {
  return (
    <>
      <RoleBox role="operator (edits .env)" />
      <H2>Configuration reference</H2>
      <P>
        Vooda is configured through environment variables, set in <code>.env</code> (copied from
        <code> .env.example</code> by the installer). The installer auto-generates <code>SECRET_KEY</code> and
        <code> POSTGRES_PASSWORD</code>; the rest have safe defaults. Restart the affected services after a change.
      </P>
      <H3>Core</H3>
      <Tbl headers={["Variable", "Default", "Purpose"]} rows={[
        ["SECRET_KEY", "(generated)", "Signs JWTs and encrypts stored credentials. Never share or reuse."],
        ["POSTGRES_PASSWORD", "(generated)", "Database password (also POSTGRES_USER / POSTGRES_DB)."],
        ["LOG_LEVEL", "INFO", "DEBUG | INFO | WARNING | ERROR."],
        ["DEBUG", "false", "Verbose errors. Keep false in production."],
      ]} />
      <H3>URLs and CORS</H3>
      <Tbl headers={["Variable", "Default", "Purpose"]} rows={[
        ["WEB_BASE_URL", "http://localhost:3000", "Public URL of the web UI (prod). Dev uses :3001."],
        ["CORS_ORIGINS", "http://localhost:3000", "Comma-separated origins allowed to call the API."],
        ["OAUTH_REDIRECT_BASE", "http://localhost:8000/...", "Base for integration OAuth callbacks."],
      ]} />
      <H3>AI triage</H3>
      <Tbl headers={["Variable", "Default", "Purpose"]} rows={[
        ["AI_PROVIDER", "claude", "Default frontier provider (claude | openai). Local models are set in the UI."],
        ["AI_MODEL", "claude-sonnet-4-20250514", "Default model id for the frontier provider."],
        ["ANTHROPIC_API_KEY / OPENAI_API_KEY", "(unset)", "Frontier keys. Leave unset for local-only triage."],
        ["AI_MAX_TOKENS", "4096", "Max tokens per finding analysis."],
        ["AI_TRIAGE_BATCH_SIZE", "5", "Findings grouped into one AI call."],
        ["AI_RATE_LIMIT_RPM", "60", "Cap on AI requests per minute."],
      ]} />
      <H3>Credential verification</H3>
      <Tbl headers={["Variable", "Default", "Purpose"]} rows={[
        ["VERIFICATION_ENABLED", "true", "Live-checks whether found secrets still work. Set false for air-gapped."],
        ["VERIFICATION_CONCURRENCY", "8", "Parallel verification workers."],
        ["VERIFICATION_ABS_BUDGET_S", "120", "Hard time budget per scan for verification."],
      ]} />
      <H3>Auth, storage, and limits</H3>
      <Tbl headers={["Variable", "Default", "Purpose"]} rows={[
        ["ACCESS_TOKEN_EXPIRE_MINUTES", "60", "JWT lifetime. Re-login to rotate."],
        ["AUTH_LOGIN_RATE_LIMIT", "10/minute", "Brute-force guard on the login endpoint."],
        ["STORAGE_BACKEND / STORAGE_PATH", "local / ./storage", "Where scan evidence is stored."],
        ["RATE_LIMIT_PER_MINUTE", "120", "Global API rate limit per tenant."],
        ["GIT_FETCH_TIMEOUT_SECONDS", "1800", "Clone/fetch timeout for large repos."],
      ]} />
      <Note>The full, authoritative set is defined in <code>apps/api/app/core/config.py</code>; the keys most
        deployments touch are pre-listed in <code>.env.example</code>.</Note>
      <NextSteps items={[
        { label: "Install air-gapped", href: "/docs?section=airgapped", desc: "Uses VERIFICATION_ENABLED and a local model." },
        { label: "Security hardening", href: "/docs?section=hardening", desc: "Production-safe settings." },
      ]} />
    </>
  );
}

function CliContent() {
  return (
    <>
      <RoleBox role="developer (local shell / CI)" see="cicd" />
      <H2>CLI reference</H2>
      <P>
        The <code>vooda</code> CLI scans a working tree or git history locally and can push results to the platform
        for a CI gate. It ships as a container image.
      </P>
      <Note><strong>Prerequisites.</strong> Docker. Build the image once, then alias it.</Note>
      <H3>Install</H3>
      <Step n={1} title="Build and alias">
        <Code>{`docker build -f infra/docker/Dockerfile.cli -t vooda/cli:latest .
alias vooda='docker run --rm -v "$PWD:/work" -w /work vooda/cli:latest'`}</Code>
        <em>Result:</em> <code>vooda --help</code> lists the commands below.
      </Step>
      <H3>Commands</H3>
      <Tbl headers={["Command", "What it does"]} rows={[
        ["vooda scan [path]", "Scan a path for secrets (default: current directory)."],
        ["vooda monitor [path]", "CI/CD mode: scan, sync results to the platform, and gate the build."],
        ["vooda auth login", "Authenticate the CLI to a Vooda API."],
        ["vooda findings list | resolve", "List or resolve findings via the API."],
        ["vooda hook install", "Install a git pre-commit hook that blocks committing secrets."],
        ["vooda config", "Show the current CLI configuration."],
      ]} />
      <H3>Scan options</H3>
      <Tbl headers={["Flag", "Effect"]} rows={[
        ["--history", "Scan the full git history, not just the working tree."],
        ["--staged", "Scan only staged changes (fast pre-commit check)."],
        ["--diff base..head", "Scan the diff between two refs (fast PR check)."],
        ["--all-branches", "Scan every branch."],
        ["--max-commits N", "Cap history depth (default 1000)."],
        ["--repo URL", "Clone and scan a remote repository."],
        ["--format table|json|sarif", "Output format. sarif for CI code-scanning."],
      ]} />
      <H3>Examples</H3>
      <Code>{`vooda scan .                     # working tree
vooda scan . --history           # full git history
vooda scan . --format sarif > results.sarif   # for CI code-scanning`}</Code>
      <Tip>Machine output (<code>--format json|sarif</code>) goes to stdout; status lines go to stderr, so
        <code> vooda scan . --format json | jq</code> stays clean.</Tip>
      <NextSteps items={[
        { label: "Add Vooda to CI/CD", href: "/docs?section=cicd", desc: "Wire the CLI into Actions, GitLab CI, or Jenkins." },
      ]} />
    </>
  );
}

const CONTENT: Record<DocSection, React.ReactNode> = {
  overview: <OverviewContent />,
  // Sections 1.4 / 1.5 / 1.6 — added 2026-05-25 as part of the
  // commercial-grade documentation audit.  Quickstart sits near the
  // top of the nav so first-touch evaluators land on the 5-minute
  // onboarding path immediately.
  quickstart: <QuickstartContent />,
  accuracy: <AccuracyContent />,
  auth: <AuthContent />,
  users: <UsersContent />,
  roles: <RolesContent />,
  repositories: <RepositoriesContent />,
  sources: <SourcesContent />,
  findings: <FindingsContent />,
  "ai-triage": <AiTriageContent />,
  // policies / nhi / agents / supply-chain / quantum entries removed
  // 2026-05-15 — see DocSection comment for rationale.
  detectors: <DetectorsContent />,
  remediation: <RemediationContent />,
  integrations: <IntegrationsContent />,
  notifications: <NotificationsContent />,
  reporting: <ReportingContent />,
  api: <ApiContent />,
  cicd: <CicdContent />,
  admin: <AdminContent />,
  hardening: <HardeningContent />,
  troubleshooting: <TroubleshootingContent />,
  faq: <FaqContent />,
  // Glossary — canonical terminology reference, added 2026-05-25.
  glossary: <GlossaryContent />,
  changelog: <ChangelogContent />,
  airgapped: <AirgappedContent />,
  backup: <BackupContent />,
  upgrade: <UpgradeContent />,
  "config-ref": <ConfigRefContent />,
  cli: <CliContent />,
};

// ═══════════════════════════════════════════════════════════════
//  STANDALONE DOCS PAGE — Microsoft Learn / AWS Docs style
// ═══════════════════════════════════════════════════════════════
const STORAGE_KEY = "vooda-docs-collapsed-groups";
const STORAGE_KEY_SIDEBAR = "vooda-docs-sidebar-collapsed";

export default function DocsPage() {
  const params = typeof window !== "undefined" ? new URLSearchParams(window.location.search) : null;
  const sectionFromUrl = params?.get("section") as DocSection | null;
  const validSections = SECTIONS.map((s) => s.key);
  const initialSection = sectionFromUrl && validSections.includes(sectionFromUrl) ? sectionFromUrl : "overview";

  const [active, setActive] = useState<DocSection>(initialSection);
  const [search, setSearch] = useState("");

  const groups = Array.from(new Set(SECTIONS.map((s) => s.group)));

  // Group collapse state — persisted in localStorage. Default: only "Reference" collapsed.
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>(() => {
    if (typeof window === "undefined") return { Reference: true };
    try {
      const raw = window.localStorage.getItem(STORAGE_KEY);
      if (raw) return JSON.parse(raw);
    } catch {}
    return { Reference: true };
  });
  const toggleGroup = (g: string) => {
    setCollapsed((prev) => {
      const next = { ...prev, [g]: !prev[g] };
      try { window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next)); } catch {}
      return next;
    });
  };

  // Whole-sidebar collapse — for AWS-style reading-mode
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(() => {
    if (typeof window === "undefined") return false;
    try { return window.localStorage.getItem(STORAGE_KEY_SIDEBAR) === "1"; } catch { return false; }
  });
  const toggleSidebar = () => {
    setSidebarCollapsed((prev) => {
      const next = !prev;
      try { window.localStorage.setItem(STORAGE_KEY_SIDEBAR, next ? "1" : "0"); } catch {}
      return next;
    });
  };

  // Expand-all / collapse-all helpers (MS Learn pattern)
  const expandAll = () => {
    const next: Record<string, boolean> = {};
    groups.forEach((g) => (next[g] = false));
    setCollapsed(next);
    try { window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next)); } catch {}
  };
  const collapseAll = () => {
    const next: Record<string, boolean> = {};
    groups.forEach((g) => (next[g] = true));
    setCollapsed(next);
    try { window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next)); } catch {}
  };

  // When searching, force-expand all groups so matches are visible
  const isSearching = search.trim().length > 0;
  const matchesSearch = (label: string) => !isSearching || label.toLowerCase().includes(search.toLowerCase());

  // When the user picks an active section, auto-expand its group
  const activeGroup = SECTIONS.find((s) => s.key === active)?.group;

  return (
    <div className="min-h-screen bg-[#07091a] text-slate-100 flex">
      {/* ── Docs Sidebar ── */}
      <aside className={`${sidebarCollapsed ? "w-12" : "w-72"} bg-gradient-to-b from-[#1a2138] to-[#111828] border-r border-white/[0.06] flex flex-col shrink-0 sticky top-0 h-screen overflow-hidden transition-all duration-200 ease-out`}>
        {sidebarCollapsed ? (
          // Collapsed mini-rail (AWS Docs style)
          <div className="flex flex-col items-center pt-4 gap-3">
            <button onClick={toggleSidebar} className="p-1.5 rounded-lg hover:bg-white/[0.06] transition-colors" title="Expand sidebar">
              <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5l7 7-7 7" /></svg>
            </button>
            <div className="w-8 h-8 rounded-lg flex items-center justify-center overflow-hidden shrink-0"
              style={{ background: "#080808", boxShadow: "0 2px 12px rgba(220,38,38,0.35), 0 0 0 1px rgba(239,68,68,0.2)" }}>
              <img src="/logo-icon.svg" alt="Vooda AI" className="w-7 h-7" />
            </div>
            <div className="text-[9px] text-slate-700 -rotate-90 mt-8 whitespace-nowrap tracking-wider uppercase">Docs v1.0</div>
          </div>
        ) : (
          <>
            <div className="px-4 py-4 flex items-center justify-between border-b border-white/[0.06]">
              <div className="flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-lg flex items-center justify-center overflow-hidden shrink-0"
                  style={{ background: "#080808", boxShadow: "0 2px 12px rgba(220,38,38,0.35), 0 0 0 1px rgba(239,68,68,0.2)" }}>
                  <img src="/logo-icon.svg" alt="Vooda AI" className="w-6 h-6" />
                </div>
                <div>
                  <p className="text-[13px] font-bold text-white leading-tight">Vooda AI</p>
                  <p className="text-[9px] text-slate-500 leading-tight">Documentation v1.0</p>
                </div>
              </div>
              <div className="flex items-center gap-0.5">
                <button onClick={toggleSidebar} className="p-1 rounded hover:bg-white/[0.06] transition-colors" title="Collapse sidebar">
                  <svg className="w-3.5 h-3.5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 19l-7-7 7-7" /></svg>
                </button>
                <Link href="/dashboard" className="p-1 rounded hover:bg-white/[0.06] transition-colors" title="Back to app">
                  <svg className="w-3.5 h-3.5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6 18L18 6M6 6l12 12" /></svg>
                </Link>
              </div>
            </div>

            <div className="px-3 pt-3 pb-2 space-y-2">
              <div className="relative">
                <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
                <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search docs…" className="w-full pl-9 pr-3 py-1.5 bg-white/[0.04] border border-white/[0.06] rounded-lg text-xs text-slate-300 placeholder-slate-600 focus:outline-none focus:border-red-500/30" />
              </div>
              <div className="flex items-center justify-between px-1 text-[10px] text-slate-600">
                <button onClick={expandAll} className="hover:text-slate-400 transition-colors uppercase tracking-wider">Expand all</button>
                <button onClick={collapseAll} className="hover:text-slate-400 transition-colors uppercase tracking-wider">Collapse all</button>
              </div>
            </div>

            <nav className="flex-1 overflow-y-auto px-2 py-1 space-y-0.5">
              {groups.map((g) => {
                const items = SECTIONS.filter((s) => s.group === g && matchesSearch(s.label));
                if (items.length === 0) return null;
                const isCollapsed = isSearching ? false : (g !== activeGroup && !!collapsed[g]);
                return (
                  <div key={g} className="select-none">
                    <button
                      onClick={() => toggleGroup(g)}
                      className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md hover:bg-white/[0.03] text-left group"
                    >
                      <svg className={`w-3 h-3 text-slate-600 transition-transform duration-150 ${isCollapsed ? "" : "rotate-90"}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                      </svg>
                      <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 group-hover:text-slate-400">{g}</span>
                      <span className="ml-auto text-[10px] text-slate-700">{items.length}</span>
                    </button>
                    {!isCollapsed && (
                      <div className="ml-3 border-l border-white/[0.04] pl-1 space-y-0.5 my-1">
                        {items.map((s) => (
                          <button
                            key={s.key}
                            onClick={() => setActive(s.key)}
                            className={`w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-md text-[12px] transition-all text-left ${
                              active === s.key
                                ? "bg-red-500/10 text-red-400 font-medium border-l-2 border-red-400 -ml-[2px] pl-[10px]"
                                : "text-slate-400 hover:bg-white/[0.03] hover:text-slate-200"
                            }`}
                          >
                            <svg className={`w-3 h-3 shrink-0 ${active === s.key ? "text-red-400" : "text-slate-600"}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">{s.icon}</svg>
                            <span className="leading-tight">{s.label}</span>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </nav>

            <div className="px-4 py-3 border-t border-white/[0.06] flex items-center justify-between text-[10px] text-slate-600">
              <Link href="/dashboard" className="flex items-center gap-1.5 hover:text-slate-300 transition-colors">
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 19l-7-7m0 0l7-7m-7 7h18" /></svg>
                Back to app
              </Link>
              <span>App v{APP_VERSION}</span>
            </div>
          </>
        )}
      </aside>

      {/* ── Content ── */}
      <main className="flex-1 overflow-y-auto">
        <div className="max-w-[860px] mx-auto px-10 py-10">
          {/* Breadcrumbs (MS Learn style) */}
          <div className="flex items-center gap-2 text-[12px] text-slate-600 mb-6">
            <Link href="/dashboard" className="hover:text-slate-400 transition-colors">Vooda AI</Link>
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
            <span className="text-slate-500">Docs</span>
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
            <span className="text-slate-500">{SECTIONS.find((s) => s.key === active)?.group}</span>
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
            <span className="text-red-400">{SECTIONS.find((s) => s.key === active)?.label}</span>
          </div>

          {CONTENT[active]}

          <div className="mt-16 pt-6 border-t border-white/[0.06] text-[12px] text-slate-600 flex items-center justify-between">
            <span>Vooda AI Documentation • v1.0 • App {APP_VERSION} • Updated 2026-05-07</span>
            <a href="#" onClick={(e) => { e.preventDefault(); window.scrollTo({ top: 0, behavior: "smooth" }); }} className="hover:text-slate-400">Back to top ↑</a>
          </div>
        </div>
      </main>
    </div>
  );
}
