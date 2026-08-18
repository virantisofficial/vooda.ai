"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

// ═══════════════════════════════════════════════════════════════
//  AUDIT LOG STREAMING — org-level setting
//  ─────────────────────────────────────────────────────────────
//  Lives under Settings → Audit & Compliance.  Lets the org's
//  security admin forward audit + finding events to their SIEM /
//  log platform (Splunk, Elastic, Sentinel, custom HTTPS).
//
//  Historically this lived under Integrations → "SIEM & Analytics".
//  Moved here 2026-05-19 because:
//    • It's an org-wide compliance setting, not a per-scanner
//      integration.  Putting it next to Slack/Jira/etc. confused
//      users about which audience receives what.
//    • Peers (GitHub Advanced Security, GitGuardian's Splunk app)
//      ship audit-log streaming as a settings page, not an
//      integration tile.
//    • Removing the SIEM tile lands the Integrations hub at a
//      clean 3×2 grid.
//
//  Backend storage is unchanged — same `integrations` table with
//  `integration_type = "siem"`.  That keeps the existing _mask_
//  response, encryption-at-rest, and test-connection pipeline
//  working without a migration.
// ═══════════════════════════════════════════════════════════════

import { useEffect, useState } from "react";
import api from "@/lib/api";

// Destinations supported at launch.  Add new ones by appending to
// this array — the component picks up fields, labels, icons, and
// auth requirements automatically from the descriptor.
const STREAM_DESTINATIONS = [
  {
    name: "Splunk",
    provider: "splunk",
    description: "Forward audit events via HTTP Event Collector",
    color: "from-green-500 to-emerald-500",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M4 6h16M4 12h16M4 18h16" strokeLinecap="round" /><circle cx="8" cy="6" r="1" fill="currentColor" /><circle cx="14" cy="12" r="1" fill="currentColor" /><circle cx="10" cy="18" r="1" fill="currentColor" /></svg>),
    fields: [
      { key: "hec_url", label: "HEC Endpoint URL", type: "url", required: true, placeholder: "https://splunk.company.com:8088/services/collector" },
      { key: "hec_token", label: "HEC Token", type: "password", required: true },
      { key: "index", label: "Index", type: "text", required: false, placeholder: "vooda_audit" },
      { key: "source_type", label: "Source Type", type: "text", required: false, placeholder: "_json" },
    ],
  },
  {
    name: "Elastic / ELK",
    provider: "elastic",
    description: "Index audit events into Elasticsearch",
    color: "from-yellow-500 to-orange-500",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M21 12c0-4.97-4.03-9-9-9s-9 4.03-9 9 4.03 9 9 9" /><path d="M3 12h18" /><path d="M12 3c-2.5 2.5-4 5.5-4 9s1.5 6.5 4 9" /></svg>),
    fields: [
      { key: "elasticsearch_url", label: "Elasticsearch URL", type: "url", required: true, placeholder: "https://elastic.company.com:9200" },
      { key: "api_key", label: "API Key", type: "password", required: true },
      { key: "index_pattern", label: "Index Pattern", type: "text", required: false, placeholder: "vooda-audit-{yyyy.MM}" },
    ],
  },
  {
    name: "Microsoft Sentinel",
    provider: "sentinel",
    description: "Send to Log Analytics workspace",
    color: "from-blue-500 to-indigo-500",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="M12 8v4l2 2" strokeLinecap="round" /></svg>),
    fields: [
      { key: "workspace_id", label: "Workspace ID", type: "text", required: true },
      { key: "shared_key", label: "Primary/Secondary Key", type: "password", required: true },
      { key: "log_type", label: "Custom Log Type", type: "text", required: false, placeholder: "VoodaAuditEvents" },
    ],
  },
  {
    name: "Custom Syslog / HTTPS",
    provider: "custom_siem",
    description: "Forward to any SIEM via syslog or HTTPS endpoint",
    color: "from-slate-500 to-slate-600",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="4" y="4" width="16" height="16" rx="2" /><path d="M9 9l3 3-3 3M13 15h3" strokeLinecap="round" strokeLinejoin="round" /></svg>),
    fields: [
      { key: "endpoint_url", label: "Endpoint URL", type: "url", required: true, placeholder: "https://siem.company.com/api/events" },
      { key: "auth_header", label: "Authorization Header", type: "password", required: false, placeholder: "Bearer your-token" },
      { key: "format", label: "Payload Format", type: "text", required: false, placeholder: "json (default) or cef" },
    ],
  },
];

interface SavedIntegration {
  id: string;
  provider: string;
  integration_type: string;
  config: Record<string, string>;
  is_active: boolean;
}

export function AuditLogStreaming() {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [configs, setConfigs] = useState<Record<string, SavedIntegration>>({});
  const [form, setForm] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ status: "ok" | "err"; msg: string } | null>(null);

  // Load existing destinations.  We filter on integration_type=="siem"
  // OR provider matching one of the known destinations so this picks
  // up records created under the old "SIEM & Analytics" integrations
  // tile — keeping migration trivial.
  const reload = async () => {
    try {
      const r = await api.get("/integrations");
      const items = r.data?.items || r.data || [];
      const byProvider: Record<string, SavedIntegration> = {};
      for (const item of (Array.isArray(items) ? items : [])) {
        if (item.integration_type === "siem" || STREAM_DESTINATIONS.some((d) => d.provider === item.provider)) {
          byProvider[item.provider] = item;
        }
      }
      setConfigs(byProvider);
    } catch { /* ignore */ }
  };

  useEffect(() => { reload(); }, []);

  const handleSave = async (provider: string) => {
    setSaving(true);
    setTestResult(null);
    try {
      const destDef = STREAM_DESTINATIONS.find((d) => d.provider === provider);
      const config: Record<string, string> = {};
      (destDef?.fields || []).forEach((f) => {
        if (form[f.key]) config[f.key] = form[f.key];
      });
      // Streaming preferences — underscore prefix marks them as
      // non-credential settings (the backend's sensitive-key matcher
      // ignores them).
      if (form._min_severity) config._min_severity = form._min_severity;
      if (form._forward_frequency) config._forward_frequency = form._forward_frequency;
      if (form._event_format) config._event_format = form._event_format;
      if (form._include_audit !== undefined) config._include_audit = form._include_audit;
      if (form._include_findings !== undefined) config._include_findings = form._include_findings;

      const existing = configs[provider];
      if (existing) {
        await api.put(`/integrations/${existing.id}`, { config, is_active: true });
      } else {
        await api.post("/integrations", {
          name: `${destDef?.name || provider} Audit Stream`,
          provider,
          integration_type: "siem",
          config,
          is_active: true,
        });
      }
      await reload();
      setForm({});
      setTestResult({ status: "ok", msg: "Saved" });
    } catch (e: any) {
      setTestResult({ status: "err", msg: e?.response?.data?.detail || "Save failed" });
    } finally { setSaving(false); }
  };

  const handleDelete = async (provider: string) => {
    const existing = configs[provider];
    if (!existing) return;
    if (!window.confirm("Remove this audit-stream destination? In-flight events will stop forwarding immediately.")) return;
    try {
      await api.delete(`/integrations/${existing.id}`);
      setConfigs((c) => { const n = { ...c }; delete n[provider]; return n; });
    } catch { /* ignore */ }
  };

  const handleTest = async (provider: string) => {
    const existing = configs[provider];
    if (!existing) return;
    setTesting(provider);
    setTestResult(null);
    try {
      const r = await api.post(`/integrations/${existing.id}/test`);
      setTestResult({ status: r.data?.status === "ok" ? "ok" : "err", msg: r.data?.message || "Test sent" });
    } catch (e: any) {
      setTestResult({ status: "err", msg: e?.response?.data?.detail || "Test failed" });
    } finally { setTesting(null); }
  };

  return (
    <div>
      {/* ── Stream Destinations card ───────────────────────────
          Mirrors the design language used in /integrations (card +
          uppercase section header) so admins moving between the two
          surfaces see consistent chrome. */}
      <div className="card mb-5">
        <div className="flex items-center justify-between mb-1 gap-3">
          <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Audit Log Streaming</h4>
        </div>
        <p className="text-[11px] text-slate-500 mb-4">
          Forward audit events and confirmed findings to your SIEM or log platform. Org-wide setting — affects every tenant user.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {STREAM_DESTINATIONS.map((d) => {
            const isExpanded = expandedId === d.provider;
            const isConfigured = !!configs[d.provider];
            return (
              <button
                key={d.provider}
                onClick={() => {
                  setExpandedId(isExpanded ? null : d.provider);
                  setTestResult(null);
                  if (!isExpanded && isConfigured) setForm(configs[d.provider]?.config || {});
                  else if (!isExpanded) setForm({});
                }}
                className={`relative text-left rounded-xl border p-4 transition-all duration-200 ${
                  isExpanded
                    ? "border-red-500/30 bg-red-500/5 ring-1 ring-red-500/20"
                    : isConfigured
                      ? "border-green-500/20 bg-white/[0.02] hover:border-green-500/30 hover:bg-white/[0.04]"
                      : "border-white/[0.06] bg-white/[0.02] hover:border-white/[0.12] hover:bg-white/[0.04]"
                }`}>
                <div className="absolute top-3 right-3 pointer-events-none">
                  {isConfigured ? (
                    <span className="text-[8px] px-1.5 py-0.5 rounded-full bg-green-500/15 text-green-400 border border-green-500/20 flex items-center gap-1">
                      <span className="w-1 h-1 rounded-full bg-green-400" />Active
                    </span>
                  ) : (
                    <span className="text-[8px] px-1.5 py-0.5 rounded-full bg-slate-500/10 text-slate-500 border border-slate-500/20">Not connected</span>
                  )}
                </div>
                <div className="flex items-center gap-3 pr-16">
                  <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${d.color} flex items-center justify-center text-white shrink-0`}>
                    {d.icon}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-white">{d.name}</p>
                    <p className="text-[10px] text-slate-600 mt-0.5">{isConfigured ? d.description : "Click to configure"}</p>
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {expandedId && (() => {
        const d = STREAM_DESTINATIONS.find((dest) => dest.provider === expandedId);
        if (!d) return null;
        const isConfigured = !!configs[d.provider];

        return (
          <div className="bg-white/[0.02] border border-red-500/20 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`w-8 h-8 rounded-lg bg-gradient-to-br ${d.color} flex items-center justify-center text-white`}>{d.icon}</div>
                <div>
                  <h4 className="text-sm font-semibold text-white">{d.name}</h4>
                  <p className="text-[10px] text-slate-500">{d.description}</p>
                </div>
              </div>
              {isConfigured && (
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleTest(d.provider)}
                    disabled={testing === d.provider}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-red-400 border border-red-500/20 hover:bg-red-500/10 transition-all disabled:opacity-50"
                  >
                    {testing === d.provider ? "Testing..." : "Send Test Event"}
                  </button>
                  <button
                    onClick={() => handleDelete(d.provider)}
                    className="px-3 py-1.5 rounded-lg text-xs font-medium text-red-400 border border-red-500/20 hover:bg-red-500/10 transition-all"
                  >
                    Remove
                  </button>
                </div>
              )}
            </div>

            {/* Test / save status chip — colour reflects the outcome
                so admins don't have to look at the toast tray to know
                whether the last action succeeded. */}
            {testResult && (
              <div className={`text-[11px] px-3 py-2 rounded-md border ${
                testResult.status === "ok"
                  ? "border-green-500/20 bg-green-500/5 text-green-400"
                  : "border-red-500/20 bg-red-500/5 text-red-400"
              }`}>
                {testResult.msg}
              </div>
            )}

            {/* Connection fields */}
            <div className="border border-white/[0.06] bg-white/[0.01] rounded-lg p-4 space-y-3">
              <p className="text-[10px] text-slate-500 uppercase tracking-wider font-medium">Connection</p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {d.fields.map((field) => (
                  <div key={field.key}>
                    <label className="text-[10px] text-slate-500 block mb-1">
                      {field.label} {field.required && <span className="text-red-400">*</span>}
                    </label>
                    <input
                      type={field.type === "password" ? "password" : "text"}
                      value={form[field.key] || ""}
                      onChange={(e) => { setForm((f) => ({ ...f, [field.key]: e.target.value })); setTestResult(null); }}
                      placeholder={field.placeholder || ""}
                      className="input-dark text-xs w-full"
                    />
                  </div>
                ))}
              </div>
            </div>

            {/* Streaming rules — same options the old SIEM section
                exposed, plus event-source toggles so admins can
                choose audit-only vs. findings-only vs. both. */}
            <div className="border border-white/[0.06] bg-white/[0.01] rounded-lg p-4 space-y-3">
              <p className="text-[10px] text-slate-500 uppercase tracking-wider font-medium">Streaming Rules</p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form._include_audit !== "false"}
                    onChange={(e) => setForm((f) => ({ ...f, _include_audit: e.target.checked ? "true" : "false" }))}
                    className="rounded border-white/20 bg-white/5"
                  />
                  Include audit events (login, role changes, etc.)
                </label>
                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form._include_findings !== "false"}
                    onChange={(e) => setForm((f) => ({ ...f, _include_findings: e.target.checked ? "true" : "false" }))}
                    className="rounded border-white/20 bg-white/5"
                  />
                  Include security findings (confirmed only)
                </label>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1">Minimum Severity</label>
                  <select value={form._min_severity || "medium"} onChange={(e) => setForm((f) => ({ ...f, _min_severity: e.target.value }))} className="select-dark text-xs w-full">
                    <option value="critical">Critical only</option>
                    <option value="high">High and above</option>
                    <option value="medium">Medium and above</option>
                    <option value="low">All severities</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1">Forward Frequency</label>
                  <select value={form._forward_frequency || "realtime"} onChange={(e) => setForm((f) => ({ ...f, _forward_frequency: e.target.value }))} className="select-dark text-xs w-full">
                    <option value="realtime">Real-time (on event)</option>
                    <option value="batch_5m">Batch (every 5 min)</option>
                    <option value="batch_1h">Batch (hourly)</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1">Event Format</label>
                  <select value={form._event_format || "json"} onChange={(e) => setForm((f) => ({ ...f, _event_format: e.target.value }))} className="select-dark text-xs w-full">
                    <option value="json">JSON</option>
                    <option value="cef">CEF (Common Event Format)</option>
                    <option value="leef">LEEF (Log Event Extended Format)</option>
                  </select>
                </div>
              </div>
              <p className="text-[9px] text-slate-600">
                Only confirmed True Positives are forwarded for findings. False Positives, Test Credentials, and Accepted Risks are excluded.
                Audit events include all user and system actions captured in this organization's activity log.
              </p>
            </div>

            <div className="flex gap-2">
              <button
                onClick={() => handleSave(d.provider)}
                disabled={saving}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/15 text-red-400 hover:bg-red-500/25 transition-all disabled:opacity-50"
              >
                {saving ? "Saving..." : isConfigured ? "Update" : "Connect"}
              </button>
              <button onClick={() => { setExpandedId(null); setTestResult(null); }} className="btn-secondary-sm">
                Cancel
              </button>
            </div>
          </div>
        );
      })()}
    </div>
  );
}
