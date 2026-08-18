"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect, useCallback, useMemo, useRef, Suspense } from "react";
import { useSearchParams } from "next/navigation";

import AppShell from "@/components/layout/AppShell";
import { useAuthStore } from "@/lib/store";
import { getAIModels, createAIModel, updateAIModel, deleteAIModel, testAIModel, getAITaskRouting, getUsers, createUser, updateUser, deleteUser, activateUser, changeMyPassword, getRoles, getPermissions, createRole, updateRole, deleteRole, resetRole, getBusinessUnits, createBusinessUnit, updateBusinessUnit, deleteBusinessUnit, getAccessGrants, createAccessGrant, deleteAccessGrant, getRepositories, getAPIKeys, getAPIKeyScopes, createAPIKey, revokeAPIKey, rotateAPIKey, getAPIKeyUsage, updateAPIKey, getAuditEvents, exportAuditCSV, enforceRetention, getAuditStats, getIntegrations, deleteIntegration, updateIntegration } from "@/lib/api";
// PoliciesContent import removed 2026-05-16 — governance components/governance/
// directory was deleted to refocus on the secret-scanner core.
import { SuppressionsContent } from "@/components/secrets/SuppressionsContent";
import { SchedulesContent } from "@/components/secrets/SchedulesContent";
import { CustomDetectorsContent } from "@/components/secrets/CustomDetectorsContent";
// Proactive scanner-rule muting (per-repo / org-wide).  Distinct from
// Suppressions which is the reactive post-finding triage surface.  See
// apps/api/app/models/rule_override.py for the rationale.
import { RuleOverridesContent } from "@/components/secrets/RuleOverridesContent";
// Org-level destination for forwarding audit + finding events to a
// SIEM / log platform.  Lives here (Settings → Audit & Compliance)
// rather than in the Integrations hub so the audience is clearly
// the org's security/compliance owner, not a per-scanner
// configurator.  See AuditLogStreaming.tsx header for the move
// rationale.
import { AuditLogStreaming } from "@/components/secrets/AuditLogStreaming";

// ── Tab types ────────────────────────────────────────
// AI Models, Notifications, SSO moved to Integrations Hub
type SettingsTab = "ai" | "users" | "roles" | "access_control" | "sso" | "notifications" | "api_keys" | "audit" | "suppressions" | "rule_overrides" | "custom_detectors" | "schedules" | "reports" | "organization" | "integrations";

const TABS: { key: SettingsTab; label: string; description: string; icon: React.ReactNode; color: string }[] = [
  { key: "users", label: "Users", description: "Manage team members and invitations", color: "from-red-500 to-orange-500",
    icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" /> },
  { key: "roles", label: "Roles & Permissions", description: "Define access levels and permissions", color: "from-emerald-500 to-green-500",
    icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /> },
  { key: "access_control", label: "Access Control", description: "Business units, user scopes and permissions", color: "from-amber-500 to-orange-500",
    icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3.75 21h16.5M4.5 3h15M5.25 3v18m13.5-18v18M9 6.75h1.5m-1.5 3h1.5m-1.5 3h1.5m3-6H15m-1.5 3H15m-1.5 3H15M9 21v-3.375c0-.621.504-1.125 1.125-1.125h3.75c.621 0 1.125.504 1.125 1.125V21" /> },
  { key: "api_keys", label: "API Keys", description: "CI/CD integration and programmatic access", color: "from-red-500 to-indigo-500",
    icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /> },
  { key: "audit", label: "Audit & Compliance", description: "Activity logs and compliance settings", color: "from-slate-500 to-slate-600",
    icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" /> },
  // "Policies" tab removed 2026-05-16 alongside the governance product surface.
  { key: "suppressions", label: "Suppressions", description: "Manage false positive suppression rules", color: "from-orange-500 to-amber-500",
    icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /> },
  // Proactive (pre-persist) counterpart to Suppressions.  Distinct tile so
  // the audit / lifecycle differences are obvious — see RuleOverridesContent
  // and apps/api/app/models/rule_override.py for the rationale.
  { key: "rule_overrides", label: "Rule Overrides", description: "Mute specific scanner rules per repo or org-wide", color: "from-violet-500 to-fuchsia-500",
    icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.542-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.542 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" /> },
  { key: "custom_detectors", label: "Custom Detectors", description: "Define org-specific secret detection regex rules", color: "from-red-500 to-orange-500",
    icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10.5 6h9.75M10.5 6a1.5 1.5 0 11-3 0m3 0a1.5 1.5 0 10-3 0M3.75 6H7.5m3 12h9.75m-9.75 0a1.5 1.5 0 01-3 0m3 0a1.5 1.5 0 00-3 0m-3.75 0H7.5m9-6h3.75m-3.75 0a1.5 1.5 0 01-3 0m3 0a1.5 1.5 0 00-3 0m-9.75 0h9.75" /> },
  { key: "schedules", label: "Scan Schedules", description: "Configure automatic scan schedules per repository", color: "from-red-500 to-blue-500",
    icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /> },
  { key: "reports", label: "Reports & Exports", description: "Generate and export security reports", color: "from-indigo-500 to-orange-500",
    icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" /> },
  { key: "organization", label: "Organization", description: "Company profile, branding and data policies", color: "from-pink-500 to-rose-500",
    icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" /> },
];

// ── Sub-components for each section ──────────────────

function SectionHeader({ title, description }: { title: string; description: string }) {
  // Single-source-of-truth: section name comes from the AppShell
  // breadcrumb (passed via pageBreadcrumb prop on the outer page).
  // Rendering the same name again here stacked it three deep with
  // the global breadcrumb + the previous body-level back bar — see
  // 2026-05-19 cleanup comments on the outer page.
  //
  // The `description` text was redundant context that mostly repeated
  // what the section's own controls already explained.  Dropped to
  // give the section content more breathing room.  If a future
  // section genuinely needs a sub-header, render the heading
  // directly in that section's JSX rather than re-introducing this
  // helper.
  void title; void description;  // intentionally unused — kept for API compatibility with existing call sites
  return null;
}

function FieldGroup({ label, description, children }: { label: string; description?: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-start gap-2 sm:gap-6 py-4 border-b border-white/[0.04]">
      <div className="sm:w-1/3 shrink-0">
        <label className="text-sm font-medium text-slate-300">{label}</label>
        {description && <p className="text-xs text-slate-600 mt-0.5">{description}</p>}
      </div>
      <div className="flex-1">{children}</div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════
   COLLAPSIBLE SEARCHABLE CHECKLIST
   Collapsed: shows tags + click-to-open trigger
   Expanded: search bar + scrollable checkbox list
   Closes on outside click
   ═══════════════════════════════════════════════════════ */
function SearchableChecklist({ label, placeholder, items, selectedIds, onChange, color = "violet", emptyText, maxHeight = "10rem" }: {
  label: string; placeholder?: string;
  items: { id: string; name: string; detail?: string }[];
  selectedIds: string[]; onChange: (ids: string[]) => void;
  color?: "violet" | "amber"; emptyText?: string; maxHeight?: string;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const filtered = items.filter(i => i.name.toLowerCase().includes(search.toLowerCase()));
  const toggle = (id: string) => onChange(selectedIds.includes(id) ? selectedIds.filter(x => x !== id) : [...selectedIds, id]);
  const nameMap = Object.fromEntries(items.map(i => [i.id, i.name]));

  const accentTag = color === "amber" ? "bg-amber-500/15 border-amber-500/30 text-amber-300" : "bg-red-500/15 border-red-500/30 text-red-300";
  const accentHover = color === "amber" ? "hover:bg-amber-500/10" : "hover:bg-red-500/10";
  const accentCheck = color === "amber" ? "bg-amber-500/20 border-amber-500/40 text-amber-400" : "bg-red-500/20 border-red-500/40 text-red-400";
  const accentCount = color === "amber" ? "text-amber-400/70" : "text-red-400/70";
  const accentBorder = color === "amber" ? "border-amber-500/20" : "border-red-500/20";

  return (
    <div ref={containerRef}>
      <label className="text-xs text-slate-500 mb-1.5 block">{label}</label>

      {/* Collapsed state: trigger + tags */}
      {!open && (
        <div>
          <button type="button" onClick={() => { setOpen(true); setSearch(""); }}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-lg border border-white/[0.08] bg-white/[0.02] hover:border-white/[0.15] text-xs text-left transition-all"
          >
            <svg className="w-3.5 h-3.5 text-slate-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <span className="text-slate-500 flex-1">{selectedIds.length > 0 ? `${selectedIds.length} selected` : placeholder || "Click to select..."}</span>
            <svg className="w-3 h-3 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
          </button>
          {selectedIds.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mt-2">
              {selectedIds.map(id => (
                <span key={id} className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-medium border ${accentTag}`}>
                  {nameMap[id] || id.slice(0, 8)}
                  <button type="button" onClick={(e) => { e.stopPropagation(); toggle(id); }} className="opacity-60 hover:opacity-100">&times;</button>
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Expanded state: search + checklist */}
      {open && (
        <div className={`rounded-lg border ${selectedIds.length > 0 ? accentBorder : "border-white/[0.1]"} bg-[#1a2332] overflow-hidden shadow-lg`}>
          {/* Search bar */}
          <div className="px-3 py-2 border-b border-white/[0.06]">
            <div className="flex items-center gap-2">
              <svg className="w-3.5 h-3.5 text-slate-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <input value={search} onChange={(e) => setSearch(e.target.value)} autoFocus
                placeholder={placeholder || "Search..."} className="flex-1 bg-transparent text-xs text-slate-200 placeholder-slate-500 outline-none" />
              {search && (
                <button type="button" onClick={() => setSearch("")} className="text-slate-500 hover:text-slate-300">
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                </button>
              )}
            </div>
          </div>

          {/* Checklist */}
          <div className="overflow-y-auto" style={{ maxHeight }}>
            {items.length === 0 ? (
              <div className="px-3 py-4 text-xs text-slate-500 text-center">{emptyText || "No items available"}</div>
            ) : filtered.length === 0 ? (
              <div className="px-3 py-4 text-xs text-slate-500 text-center">No matches for &ldquo;{search}&rdquo;</div>
            ) : filtered.map(item => {
              const checked = selectedIds.includes(item.id);
              return (
                <button key={item.id} type="button" onClick={() => toggle(item.id)}
                  className={`w-full flex items-center gap-2.5 px-3 py-1.5 text-left text-xs transition-colors ${accentHover} ${checked ? "bg-white/[0.02]" : ""}`}
                >
                  <span className={`w-3.5 h-3.5 rounded border flex items-center justify-center shrink-0 transition-colors ${checked ? accentCheck : "border-white/[0.15] bg-white/[0.02]"}`}>
                    {checked && <svg className="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" /></svg>}
                  </span>
                  <span className={`truncate ${checked ? "text-slate-200 font-medium" : "text-slate-400"}`}>{item.name}</span>
                  {item.detail && <span className="ml-auto text-[10px] text-slate-600 shrink-0">{item.detail}</span>}
                </button>
              );
            })}
          </div>

          {/* Footer */}
          <div className="px-3 py-1.5 border-t border-white/[0.06] flex items-center justify-between">
            <span className={`text-[10px] ${selectedIds.length > 0 ? accentCount : "text-slate-600"}`}>
              {selectedIds.length > 0 ? `${selectedIds.length} of ${items.length} selected` : `${items.length} available`}
            </span>
            <div className="flex items-center gap-3">
              {selectedIds.length > 0 && (
                <button type="button" onClick={() => onChange([])} className="text-[10px] text-slate-500 hover:text-red-400">Clear all</button>
              )}
              <button type="button" onClick={() => setOpen(false)} className="text-[10px] text-slate-400 hover:text-red-400">Done</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════
   AI MODELS SECTION
   ═══════════════════════════════════════════════════════ */
function AIModelsSection() {
  const [models, setModels] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingModel, setEditingModel] = useState<any>(null);
  const [form, setForm] = useState({
    name: "", provider: "anthropic", model_id: "", api_key: "", endpoint_url: "", tasks: [] as string[], is_primary: false,
    max_tokens: 4096, temperature: 0.1, context_window: 4096, stop_sequences: [] as string[],
    supports_json_mode: false, system_prompt_override: "", use_compact_prompt: false,
  });
  const [testResult, setTestResult] = useState<{ status: string; message: string; latency_ms?: number } | null>(null);
  const [testLoading, setTestLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [menuOpen, setMenuOpen] = useState<string | null>(null);
  const [discoveredModels, setDiscoveredModels] = useState<string[]>([]);
  const [discovering, setDiscovering] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  const PROVIDERS = [
    { value: "anthropic", label: "Anthropic (Claude)", models: ["claude-sonnet-4-20250514", "claude-opus-4-20250514", "claude-3.5-haiku-20241022"], color: "bg-orange-500/10 text-orange-400",
      icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3L4 9v6l8 6 8-6V9l-8-6z" strokeLinejoin="round" /><path d="M12 9v6M9 12h6" strokeLinecap="round" /></svg>),
    },
    { value: "openai", label: "OpenAI", models: ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o1-preview"], color: "bg-green-500/10 text-green-400",
      icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="3" /><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" strokeLinecap="round" /></svg>),
    },
    { value: "azure_openai", label: "Azure OpenAI", models: [], color: "bg-blue-500/10 text-blue-400",
      icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M3 17l6-12h6l6 12" strokeLinecap="round" strokeLinejoin="round" /><path d="M7.5 17h9" strokeLinecap="round" /><path d="M12 5l-3 6h6l-3-6z" fill="currentColor" stroke="none" opacity="0.3" /></svg>),
    },
    { value: "aws_bedrock", label: "AWS Bedrock", models: [], color: "bg-yellow-500/10 text-yellow-400",
      icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 3v18M3 12h18" strokeLinecap="round" /><path d="M12 3l-5 5M12 3l5 5M12 21l-5-5M12 21l5-5M3 12l5-5M3 12l5 5M21 12l-5-5M21 12l-5 5" strokeLinecap="round" strokeLinejoin="round" opacity="0.5" /></svg>),
    },
    { value: "google", label: "Google (Gemini)", models: ["gemini-2.0-flash", "gemini-1.5-pro"], color: "bg-red-500/10 text-red-400",
      icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 2a10 10 0 100 20 10 10 0 000-20z" /><path d="M12 7l3 5-3 5-3-5 3-5z" fill="currentColor" stroke="none" opacity="0.3" /><path d="M12 7v10M7 12h10" strokeLinecap="round" /></svg>),
    },
    { value: "ollama", label: "Ollama (Local)", models: [], color: "bg-cyan-500/10 text-cyan-400", noApiKey: true, showEndpoint: true, defaultEndpoint: "http://localhost:11434",
      icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="8" r="4" /><path d="M5 20v-2a7 7 0 0114 0v2" strokeLinecap="round" /><path d="M12 12v4" strokeLinecap="round" opacity="0.5" /></svg>),
    },
    { value: "custom", label: "Custom / Self-Hosted", models: [], color: "bg-purple-500/10 text-purple-400", showEndpoint: true,
      icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="4" y="4" width="16" height="16" rx="2" /><path d="M9 9l3 3-3 3M13 15h3" strokeLinecap="round" strokeLinejoin="round" /></svg>),
    },
  ];

  // Only the two tasks the worker actually dispatches on are shown —
  // `code_analysis` and `summarization` were aspirational placeholders that
  // no code path calls. Kept out of the UI to avoid false promises.
  const TASKS = [
    { key: "triage", label: "AI Triage", description: "False positive reduction and finding classification" },
    { key: "remediation", label: "Auto Remediation", description: "Secure code patch generation" },
  ];

  const loadModels = useCallback(() => {
    getAIModels().then((r) => setModels(r.data || [])).catch(() => {}).finally(() => setLoading(false));
  }, []);
  useEffect(() => { loadModels(); }, [loadModels]);

  const selectedProviderDef = PROVIDERS.find((p) => p.value === form.provider);
  const providerFor = (p: string) => PROVIDERS.find((pr) => pr.value === p);

  const resetForm = () => {
    setForm({ name: "", provider: "anthropic", model_id: "", api_key: "", endpoint_url: "", tasks: [], is_primary: false, max_tokens: 4096, temperature: 0.1, context_window: 4096, stop_sequences: [], supports_json_mode: false, system_prompt_override: "", use_compact_prompt: false });
    setEditingModel(null); setTestResult(null); setShowForm(false); setDiscoveredModels([]);
  };

  const openEdit = (model: any) => {
    setForm({ name: model.name, provider: model.provider, model_id: model.model_id, api_key: "", endpoint_url: model.endpoint_url || "", tasks: model.tasks || [], is_primary: model.is_primary, max_tokens: model.max_tokens || 4096, temperature: model.temperature || 0.1, context_window: model.context_window || 4096, stop_sequences: model.stop_sequences || [], supports_json_mode: model.supports_json_mode || false, system_prompt_override: model.system_prompt_override || "", use_compact_prompt: model.use_compact_prompt || false });
    setEditingModel(model); setShowForm(true); setTestResult(null); setMenuOpen(null);
  };

  const discoverModels = async () => {
    setDiscovering(true); setDiscoveredModels([]);
    try {
      const endpoint = form.endpoint_url || (form.provider === "ollama" ? "http://localhost:11434" : "");
      if (!endpoint) return;
      const r = await fetch(`${endpoint}/api/tags`).then(res => res.json());
      const models = (r.models || []).map((m: any) => m.name || m.model);
      setDiscoveredModels(models);
    } catch {
      // Try OpenAI-compatible /v1/models
      try {
        const endpoint = form.endpoint_url || "";
        const r = await fetch(`${endpoint}/v1/models`).then(res => res.json());
        const models = (r.data || []).map((m: any) => m.id);
        setDiscoveredModels(models);
      } catch { setDiscoveredModels([]); }
    } finally { setDiscovering(false); }
  };

  const toggleTask = (taskKey: string) => {
    setForm((f) => ({ ...f, tasks: f.tasks.includes(taskKey) ? f.tasks.filter((t) => t !== taskKey) : [...f.tasks, taskKey] }));
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const payload: any = { ...form };
      if (!payload.api_key) delete payload.api_key;
      if (!payload.endpoint_url) delete payload.endpoint_url;
      if (editingModel) {
        await updateAIModel(editingModel.id, payload);
      } else {
        await createAIModel(payload);
      }
      resetForm(); loadModels();
    } catch { /* toast error */ } finally { setSaving(false); }
  };

  const handleTest = async () => {
    setTestLoading(true); setTestResult(null);
    try {
      const payload: any = editingModel
        ? { model_config_id: editingModel.id }
        : { provider: form.provider, model_id: form.model_id, api_key: form.api_key, endpoint_url: form.endpoint_url || undefined };
      const r = await testAIModel(payload);
      setTestResult(r.data);
    } catch { setTestResult({ status: "error", message: "Request failed" }); }
    finally { setTestLoading(false); }
  };

  const handleDelete = async () => {
    if (!confirmDelete) return;
    await deleteAIModel(confirmDelete).catch(() => {});
    setConfirmDelete(null); loadModels();
  };

  const handleSetPrimary = async (id: string) => {
    await updateAIModel(id, { is_primary: true }).catch(() => {});
    setMenuOpen(null); loadModels();
  };

  return (
    <div>
      <SectionHeader title="AI Model Configuration" description="Configure AI models for different security analysis tasks. Assign specific models to specific tasks for cost optimization and compliance." />

      {/* Task routing overview */}
      <div className="card mb-5">
        <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">Task Routing</h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {TASKS.map((task) => {
            const assigned = models.filter((m: any) => m.is_active && (m.tasks || []).includes(task.key));
            return (
              <div key={task.key} className="bg-white/[0.02] border border-white/[0.04] rounded-lg p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-slate-200">{task.label}</span>
                  {assigned.length > 0 ? (
                    <span className="text-xs px-2 py-0.5 rounded-full bg-green-500/15 text-green-400 border border-green-500/20">Active</span>
                  ) : (
                    <span className="text-xs px-2 py-0.5 rounded-full bg-yellow-500/15 text-yellow-400 border border-yellow-500/20">Not configured</span>
                  )}
                </div>
                <p className="text-xs text-slate-500">{task.description}</p>
                {assigned.length > 0 && (
                  <div className="mt-2 flex gap-1.5 flex-wrap">
                    {assigned.map((m: any) => (
                      <span key={m.id} className="text-xs px-2 py-0.5 rounded bg-red-500/10 text-red-400">{m.name}</span>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Registered models */}
      <div className="card mb-5">
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Registered Models</h4>
          <button onClick={() => { resetForm(); setShowForm(true); }} className="btn-primary text-xs px-3 py-1.5">+ Add Model</button>
        </div>
        {loading ? (
          <div className="text-center py-8"><div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin mx-auto" /></div>
        ) : models.length === 0 ? (
          <div className="text-center py-10">
            <p className="text-sm text-slate-500">No models configured</p>
            <p className="text-xs text-slate-600 mt-1">Add an AI model to enable triage and remediation</p>
          </div>
        ) : (
          <div className="space-y-3">
            {models.map((model: any) => {
              const pDef = providerFor(model.provider);
              return (
                <div key={model.id} className={`bg-white/[0.02] border rounded-lg p-4 flex items-center gap-4 ${model.is_active ? "border-white/[0.04]" : "border-white/[0.02] opacity-50"}`}>
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${pDef?.color || "bg-slate-500/10 text-slate-400"}`}>
                    {pDef?.icon || <span className="text-sm font-bold">?</span>}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium text-slate-200">{model.name}</span>
                      {model.is_primary && <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/20">Primary</span>}
                      {!model.is_active && <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-500/15 text-slate-500 border border-slate-500/20">Disabled</span>}
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5 font-mono">{model.model_id}</p>
                    <div className="flex gap-1.5 mt-1.5 flex-wrap">
                      {(model.tasks || []).map((t: string) => (
                        <span key={t} className="text-[10px] px-2 py-0.5 rounded bg-white/[0.04] text-slate-400 capitalize">{t.replace("_", " ")}</span>
                      ))}
                    </div>
                    {/* Usage stats */}
                    {model.total_requests > 0 && (
                      <div className="flex gap-4 mt-2 text-[10px] text-slate-600">
                        <span>{model.total_requests.toLocaleString()} requests</span>
                        <span>{((model.total_input_tokens + model.total_output_tokens) / 1000).toFixed(0)}K tokens</span>
                        {model.total_cost_usd > 0 && <span>${model.total_cost_usd.toFixed(2)}</span>}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {model.api_key_set ? (
                      <span className="text-xs text-green-400 flex items-center gap-1">
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                        Key set
                      </span>
                    ) : (
                      <span className="text-xs text-yellow-400">Key needed</span>
                    )}
                    {model.last_error && (
                      <span className="text-xs text-red-400" title={model.last_error}>Error</span>
                    )}
                    {/* Actions menu */}
                    <div className="relative">
                      <button onClick={() => setMenuOpen(menuOpen === model.id ? null : model.id)} className="p-1.5 rounded hover:bg-white/[0.06]">
                        <svg className="w-4 h-4 text-slate-500" fill="currentColor" viewBox="0 0 20 20"><path d="M10 6a2 2 0 110-4 2 2 0 010 4zM10 12a2 2 0 110-4 2 2 0 010 4zM10 18a2 2 0 110-4 2 2 0 010 4z" /></svg>
                      </button>
                      {menuOpen === model.id && (
                        <>
                          <div className="fixed inset-0 z-10" onClick={() => setMenuOpen(null)} />
                          <div className="absolute right-0 top-8 z-20 w-44 py-1 rounded-xl border border-white/[0.08] shadow-2xl overflow-hidden" style={{ background: "rgba(8,11,28,0.95)",  }}>
                            <button onClick={() => openEdit(model)} className="block w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-white/[0.04]">Edit</button>
                            <button onClick={() => { handleTest(); setMenuOpen(null); }} className="block w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-white/[0.04]">Test Connection</button>
                            {!model.is_primary && (
                              <button onClick={() => handleSetPrimary(model.id)} className="block w-full text-left px-4 py-2 text-sm text-red-400 hover:bg-white/[0.04]">Set as Primary</button>
                            )}
                            <button onClick={() => updateAIModel(model.id, { is_active: !model.is_active }).then(loadModels)} className="block w-full text-left px-4 py-2 text-sm text-yellow-400 hover:bg-white/[0.04]">
                              {model.is_active ? "Disable" : "Enable"}
                            </button>
                            <div className="border-t border-white/[0.06] my-1" />
                            <button onClick={() => { setConfirmDelete(model.id); setMenuOpen(null); }} className="block w-full text-left px-4 py-2 text-sm text-red-400 hover:bg-red-500/5">Delete</button>
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Add/Edit model form */}
      {showForm && (
        <div className="card border-red-500/20">
          <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">{editingModel ? "Edit Model" : "Add New Model"}</h4>
          <div className="space-y-4">
            <FieldGroup label="Provider">
              <select value={form.provider} onChange={(e) => setForm((f) => ({ ...f, provider: e.target.value, model_id: "" }))} className="select-dark w-full" disabled={!!editingModel}>
                {PROVIDERS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
              </select>
            </FieldGroup>
            <FieldGroup label="Display Name" description="Friendly name for this model">
              <input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} placeholder="e.g. Claude Sonnet (Production)" className="input-dark" />
            </FieldGroup>
            <FieldGroup label="Model ID" description="API model identifier">
              {selectedProviderDef && selectedProviderDef.models.length > 0 ? (
                <select value={form.model_id} onChange={(e) => setForm((f) => ({ ...f, model_id: e.target.value }))} className="select-dark w-full">
                  <option value="">Select model...</option>
                  {selectedProviderDef.models.map((m) => <option key={m} value={m}>{m}</option>)}
                </select>
              ) : (
                <input value={form.model_id} onChange={(e) => setForm((f) => ({ ...f, model_id: e.target.value }))} placeholder="Model ID or deployment name" className="input-dark" />
              )}
            </FieldGroup>
            {["azure_openai", "aws_bedrock", "custom", "ollama"].includes(form.provider) && (
              <FieldGroup label="API Endpoint" description={form.provider === "ollama" ? "Ollama server URL (default: http://localhost:11434)" : "Base URL for the model API (OpenAI-compatible)"}>
                <div className="flex gap-2">
                  <input value={form.endpoint_url} onChange={(e) => setForm((f) => ({ ...f, endpoint_url: e.target.value }))} placeholder={form.provider === "ollama" ? "http://localhost:11434" : "https://your-model.internal.com/v1"} className="input-dark flex-1" />
                  {["ollama", "custom"].includes(form.provider) && (
                    <button onClick={discoverModels} disabled={discovering} className="btn-secondary text-xs px-3 whitespace-nowrap">
                      {discovering ? "Discovering..." : "Discover Models"}
                    </button>
                  )}
                </div>
                {discoveredModels.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {discoveredModels.map((m) => (
                      <button key={m} onClick={() => setForm((f) => ({ ...f, model_id: m }))} className={`text-xs px-2 py-1 rounded border transition-all ${form.model_id === m ? "bg-cyan-500/15 text-cyan-400 border-cyan-500/30" : "bg-white/[0.02] text-slate-400 border-white/[0.06] hover:border-white/[0.12]"}`}>
                        {m}
                      </button>
                    ))}
                  </div>
                )}
              </FieldGroup>
            )}
            {!(selectedProviderDef as any)?.noApiKey && (
              <FieldGroup label="API Key" description={editingModel ? "Leave empty to keep existing key" : "Encrypted at rest, never exposed in UI"}>
                <input type="password" value={form.api_key} onChange={(e) => setForm((f) => ({ ...f, api_key: e.target.value }))} placeholder={editingModel ? "••••••••  (unchanged)" : "sk-..."} className="input-dark" />
              </FieldGroup>
            )}
            <FieldGroup label="Assign Tasks" description="Which AI tasks should use this model">
              <div className="flex flex-wrap gap-2">
                {TASKS.map((t) => (
                  <label key={t.key} onClick={() => toggleTask(t.key)} className={`flex items-center gap-2 text-sm cursor-pointer rounded-lg px-3 py-2 border transition-all ${form.tasks.includes(t.key) ? "bg-red-500/10 text-red-400 border-red-500/20" : "bg-white/[0.02] text-slate-400 border-white/[0.04] hover:border-white/[0.08]"}`}>
                    <svg className={`w-4 h-4 ${form.tasks.includes(t.key) ? "text-red-400" : "text-slate-600"}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      {form.tasks.includes(t.key) ? <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /> : <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 12H4" />}
                    </svg>
                    {t.label}
                  </label>
                ))}
              </div>
            </FieldGroup>
            <FieldGroup label="Model Parameters">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div>
                  <label className="text-xs text-slate-500 mb-1 block">Max Tokens</label>
                  <input type="number" value={form.max_tokens} onChange={(e) => setForm((f) => ({ ...f, max_tokens: parseInt(e.target.value) || 4096 }))} className="input-dark" />
                </div>
                <div>
                  <label className="text-xs text-slate-500 mb-1 block">Temperature</label>
                  <input type="number" step="0.05" min="0" max="2" value={form.temperature} onChange={(e) => setForm((f) => ({ ...f, temperature: parseFloat(e.target.value) || 0.1 }))} className="input-dark" />
                </div>
                <div>
                  <label className="text-xs text-slate-500 mb-1 block">Context Window</label>
                  <input type="number" value={form.context_window} onChange={(e) => setForm((f) => ({ ...f, context_window: parseInt(e.target.value) || 4096 }))} className="input-dark" />
                </div>
                <div>
                  <label className="text-xs text-slate-500 mb-1 block">Stop Sequences</label>
                  <input value={(form.stop_sequences || []).join(", ")} onChange={(e) => setForm((f) => ({ ...f, stop_sequences: e.target.value ? e.target.value.split(",").map((s) => s.trim()) : [] }))} placeholder='e.g. }, \n\n' className="input-dark" />
                </div>
              </div>
            </FieldGroup>
            <FieldGroup label="Output Control">
              <div className="space-y-3">
                <label className="flex items-center gap-2 text-sm text-slate-400 cursor-pointer" onClick={() => setForm((f) => ({ ...f, supports_json_mode: !f.supports_json_mode }))}>
                  <div className={`w-9 h-5 rounded-full transition-colors relative ${form.supports_json_mode ? "bg-cyan-500" : "bg-slate-600"}`}>
                    <div className={`w-4 h-4 rounded-full bg-white absolute top-0.5 transition-transform ${form.supports_json_mode ? "left-[18px]" : "left-0.5"}`} />
                  </div>
                  <div>
                    <span className="block">JSON Mode</span>
                    <span className="text-[10px] text-slate-600">Force structured JSON output (supported by Ollama, OpenAI, Gemini)</span>
                  </div>
                </label>
                <label className="flex items-center gap-2 text-sm text-slate-400 cursor-pointer" onClick={() => setForm((f) => ({ ...f, use_compact_prompt: !f.use_compact_prompt }))}>
                  <div className={`w-9 h-5 rounded-full transition-colors relative ${form.use_compact_prompt ? "bg-cyan-500" : "bg-slate-600"}`}>
                    <div className={`w-4 h-4 rounded-full bg-white absolute top-0.5 transition-transform ${form.use_compact_prompt ? "left-[18px]" : "left-0.5"}`} />
                  </div>
                  <div>
                    <span className="block">Compact Prompt</span>
                    <span className="text-[10px] text-slate-600">Use simplified prompt for small models (&lt;7B params). Reduces token usage by ~80%</span>
                  </div>
                </label>
              </div>
            </FieldGroup>
            <FieldGroup label="Custom System Prompt" description="Override the default triage system prompt (leave empty to use default)">
              <textarea value={form.system_prompt_override} onChange={(e) => setForm((f) => ({ ...f, system_prompt_override: e.target.value }))} placeholder="You are a security scanner false positive analyzer..." className="input-dark h-24 resize-y font-mono text-xs" />
            </FieldGroup>
            <FieldGroup label="Options">
              <label className="flex items-center gap-2 text-sm text-slate-400 cursor-pointer" onClick={() => setForm((f) => ({ ...f, is_primary: !f.is_primary }))}>
                <div className={`w-9 h-5 rounded-full transition-colors relative ${form.is_primary ? "bg-red-500" : "bg-slate-600"}`}>
                  <div className={`w-4 h-4 rounded-full bg-white absolute top-0.5 transition-transform ${form.is_primary ? "left-[18px]" : "left-0.5"}`} />
                </div>
                Set as primary model (fallback for all tasks)
              </label>
            </FieldGroup>

            {/* Test connection result */}
            {testResult && (
              <div className={`p-3 rounded-lg border text-sm ${testResult.status === "success" ? "bg-green-500/5 border-green-500/20 text-green-400" : "bg-red-500/5 border-red-500/20 text-red-400"}`}>
                <div className="flex items-center gap-2">
                  {testResult.status === "success" ? (
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                  ) : (
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                  )}
                  <span>{testResult.message}</span>
                  {testResult.latency_ms && <span className="text-xs text-slate-500 ml-auto">{testResult.latency_ms}ms</span>}
                </div>
              </div>
            )}

            <div className="flex gap-3 pt-2">
              <button onClick={handleSave} disabled={saving || !form.name || !form.model_id} className="btn-primary text-sm">
                {saving ? "Saving..." : editingModel ? "Update Model" : "Save Model"}
              </button>
              <button onClick={handleTest} disabled={testLoading || (!editingModel && (!form.api_key || !form.model_id))} className="btn-secondary text-sm">
                {testLoading ? "Testing..." : "Test Connection"}
              </button>
              <button onClick={resetForm} className="text-sm text-slate-400 hover:text-slate-200 px-3">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirmation */}
      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="card border-red-500/20 max-w-md w-full mx-4">
            <h3 className="text-base font-semibold text-white mb-2">Delete AI Model?</h3>
            <p className="text-sm text-slate-400 mb-5">This will permanently remove the model configuration. Tasks using this model will fall back to the primary model.</p>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setConfirmDelete(null)} className="btn-secondary text-sm">Cancel</button>
              <button onClick={handleDelete} className="btn-danger text-sm">Delete Model</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════
   USERS SECTION
   ═══════════════════════════════════════════════════════ */
function UsersSection() {
  const { user: currentUser } = useAuthStore();
  const [users, setUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingUser, setEditingUser] = useState<any>(null);
  const [form, setForm] = useState({ full_name: "", email: "", password: "", current: "", confirm: "", role: "viewer" });
  const [accessLevel, setAccessLevel] = useState("organization");
  const [accessRole, setAccessRole] = useState("member");
  const [selectedBUs, setSelectedBUs] = useState<string[]>([]);
  const [selectedProjects, setSelectedProjects] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [confirmDelete, setConfirmDelete] = useState<any>(null);
  const [menuOpen, setMenuOpen] = useState<string | null>(null);
  const [buList, setBuList] = useState<any[]>([]);
  const [repoList, setRepoList] = useState<any[]>([]);
  const [grantsMap, setGrantsMap] = useState<Record<string, any[]>>({});

  const ROLE_COLORS: Record<string, string> = {
    admin: "bg-red-500/15 text-red-400 border-red-500/20",
    security_engineer: "bg-purple-500/15 text-purple-400 border-purple-500/20",
    developer: "bg-red-500/15 text-red-400 border-red-500/20",
    viewer: "bg-slate-500/15 text-slate-400 border-slate-500/20",
  };

  const AVATAR_COLORS = [
    "from-red-400 to-orange-500", "from-purple-400 to-pink-500", "from-orange-400 to-red-500",
    "from-green-400 to-emerald-500", "from-yellow-400 to-orange-500", "from-rose-400 to-pink-500",
  ];

  const loadUsers = useCallback(async () => {
    try {
      const [userR, buR, repoR, grantR] = await Promise.all([
        getUsers().catch(() => ({ data: [] })),
        getBusinessUnits().catch(() => ({ data: [] })),
        getRepositories({ page_size: 200 }).catch(() => ({ data: [] })),
        getAccessGrants().catch(() => ({ data: [] })),
      ]);
      setUsers(userR.data || []);
      setBuList(buR.data || []);
      const rd = repoR.data;
      setRepoList(rd?.items ?? (Array.isArray(rd) ? rd : []));
      // Build grants map: user_id → array of grants (supports multiple)
      const gm: Record<string, any[]> = {};
      for (const g of (grantR.data || [])) {
        if (!gm[g.user_id]) gm[g.user_id] = [];
        gm[g.user_id].push(g);
      }
      setGrantsMap(gm);
    } finally { setLoading(false); }
  }, []);
  useEffect(() => { loadUsers(); }, [loadUsers]);

  const resetForm = () => {
    setForm({ full_name: "", email: "", password: "", current: "", confirm: "", role: "viewer" });
    setAccessLevel("organization"); setAccessRole("member");
    setSelectedBUs([]); setSelectedProjects([]);
    setEditingUser(null); setShowForm(false); setError("");
  };

  const openEdit = (u: any) => {
    setForm({ full_name: u.full_name, email: u.email, password: "", current: "", confirm: "", role: u.roles?.[0] || "viewer" });
    const grants = grantsMap[u.id] || [];
    if (grants.length > 0) {
      const lvl = grants[0].access_level;
      setAccessLevel(lvl);
      setAccessRole(grants[0].role || "member");
      if (lvl === "business_unit") setSelectedBUs(grants.map((g: any) => g.business_unit_id).filter(Boolean));
      else if (lvl === "project") setSelectedProjects(grants.map((g: any) => g.repository_id).filter(Boolean));
    } else {
      setAccessLevel("organization"); setAccessRole("member");
      setSelectedBUs([]); setSelectedProjects([]);
    }
    setEditingUser(u); setShowForm(true); setError(""); setMenuOpen(null);
  };

  const toggleBU = (id: string) => setSelectedBUs(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  const toggleProject = (id: string) => setSelectedProjects(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);

  const handleSave = async () => {
    setSaving(true); setError("");
    try {
      let userId: string;
      if (editingUser) {
        const selfEdit = !!(currentUser && editingUser.email === currentUser.email);
        // Password change validation (only when a new password is entered).
        if (form.password) {
          if (form.password !== form.confirm) {
            setError("New password and confirmation do not match."); setSaving(false); return;
          }
          if (selfEdit) {
            // Changing your OWN password requires the current one — route it
            // through the verified endpoint, not the admin PUT.
            if (!form.current) {
              setError("Enter your current password to change it."); setSaving(false); return;
            }
            try {
              await changeMyPassword({ current_password: form.current, new_password: form.password });
            } catch (e: any) {
              setError(e.response?.data?.detail || "Could not change password."); setSaving(false); return;
            }
          }
        }
        const payload: any = { full_name: form.full_name, email: form.email, role: form.role };
        // Only include the password in the admin PUT when resetting ANOTHER
        // user (an administrative reset). A self change went through the
        // verified endpoint above.
        if (form.password && !selfEdit) payload.password = form.password;
        await updateUser(editingUser.id, payload);
        userId = editingUser.id;
        // Delete all existing grants and recreate
        for (const g of (grantsMap[userId] || [])) {
          await deleteAccessGrant(g.id).catch(() => {});
        }
      } else {
        if (!form.password) { setError("Password is required"); setSaving(false); return; }
        if (form.password !== form.confirm) { setError("Password and confirmation do not match."); setSaving(false); return; }
        const res = await createUser({ full_name: form.full_name, email: form.email, password: form.password, role: form.role });
        userId = res.data?.id;
      }

      // Create grants based on selection
      if (userId) {
        if (accessLevel === "organization") {
          await createAccessGrant({ user_id: userId, access_level: "organization", role: accessRole }).catch(() => {});
        } else if (accessLevel === "business_unit") {
          for (const buId of selectedBUs) {
            await createAccessGrant({ user_id: userId, access_level: "business_unit", role: accessRole, business_unit_id: buId }).catch(() => {});
          }
        } else if (accessLevel === "project") {
          for (const repoId of selectedProjects) {
            await createAccessGrant({ user_id: userId, access_level: "project", role: accessRole, repository_id: repoId }).catch(() => {});
          }
        }
      }

      resetForm(); loadUsers();
    } catch (e: any) {
      setError(e.response?.data?.detail || "Failed to save user");
    } finally { setSaving(false); }
  };

  const handleToggleActive = async (u: any) => {
    if (u.is_active) {
      await deleteUser(u.id).catch(() => {});
    } else {
      await activateUser(u.id).catch(() => {});
    }
    setMenuOpen(null); loadUsers();
  };

  const handleChangeRole = async (userId: string, newRole: string) => {
    await updateUser(userId, { role: newRole }).catch(() => {});
    setMenuOpen(null); loadUsers();
  };

  const isSelf = (u: any) => currentUser && u.email === currentUser.email;

  return (
    <div>
      <SectionHeader title="User Management" description="Manage users, invite team members, and assign roles." />

      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <span className="text-sm text-slate-400">{users.length} users</span>
          <span className="text-xs text-slate-600">({users.filter((u) => u.is_active).length} active)</span>
        </div>
        <button onClick={() => { resetForm(); setShowForm(true); }} className="btn-primary text-xs px-3 py-1.5">+ Add User</button>
      </div>

      {/* Add/Edit Form */}
      {showForm && (
        <div className="card border-red-500/20 mb-5">
          <h4 className="text-sm font-semibold text-slate-300 mb-4">{editingUser ? "Edit User" : "Add New User"}</h4>
          {error && (
            <div className="bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-2 rounded-lg text-sm mb-4">{error}</div>
          )}
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-slate-500 mb-1.5 block">Full Name</label>
                <input value={form.full_name} onChange={(e) => setForm((f) => ({ ...f, full_name: e.target.value }))} placeholder="John Smith" className="input-dark" />
              </div>
              <div>
                <label className="text-xs text-slate-500 mb-1.5 block">Email</label>
                <input value={form.email} onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))} type="email" placeholder="john@company.com" className="input-dark" />
              </div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {editingUser && isSelf(editingUser) && (
                <div>
                  <label className="text-xs text-slate-500 mb-1.5 block">Current Password</label>
                  <input value={form.current} onChange={(e) => setForm((f) => ({ ...f, current: e.target.value }))} type="password" placeholder="Required to change your own password" className="input-dark" />
                </div>
              )}
              <div className={editingUser && isSelf(editingUser) ? "" : "sm:col-span-2"}>
                <label className="text-xs text-slate-500 mb-1.5 block">Role</label>
                <select value={form.role} onChange={(e) => setForm((f) => ({ ...f, role: e.target.value }))} className="select-dark w-full">
                  <option value="viewer">Viewer (Read-only)</option>
                  <option value="developer">Developer</option>
                  <option value="security_engineer">Security Engineer</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-slate-500 mb-1.5 block">{editingUser ? "New Password (leave empty to keep)" : "Password"}</label>
                <input value={form.password} onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))} type="password" placeholder={editingUser ? "••••••••  (unchanged)" : "Minimum 12 characters"} className="input-dark" />
              </div>
              <div>
                <label className="text-xs text-slate-500 mb-1.5 block">{editingUser ? "Confirm New Password" : "Confirm Password"}</label>
                <input value={form.confirm} onChange={(e) => setForm((f) => ({ ...f, confirm: e.target.value }))} type="password" placeholder="Re-enter the password" className="input-dark" />
              </div>
            </div>
            <p className="text-[11px] text-slate-600 mt-1">At least 12 characters with an uppercase, lowercase, number, and symbol.</p>

            {/* Access Scope — clean single section */}
            <div className="border-t border-white/[0.06] pt-4 mt-2">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Access Scope</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
                <div>
                  <label className="text-xs text-slate-500 mb-1.5 block">Access Level</label>
                  <select value={accessLevel} onChange={(e) => { setAccessLevel(e.target.value); setSelectedBUs([]); setSelectedProjects([]); }} className="select-dark w-full">
                    <option value="organization">Organization (all projects)</option>
                    <option value="business_unit">Business Unit(s)</option>
                    <option value="project">Project(s)</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-slate-500 mb-1.5 block">Permission Level</label>
                  <select value={accessRole} onChange={(e) => setAccessRole(e.target.value)} className="select-dark w-full">
                    <option value="admin">Admin (full control)</option>
                    <option value="member">Member (read & write)</option>
                    <option value="viewer">Viewer (read-only)</option>
                  </select>
                </div>
              </div>

              {accessLevel === "business_unit" && (
                <SearchableChecklist
                  label="Business Units"
                  placeholder="Select business units..."
                  color="amber"
                  items={buList.map((b: any) => ({ id: b.id, name: b.name, detail: `${b.project_count || 0} projects` }))}
                  selectedIds={selectedBUs}
                  onChange={setSelectedBUs}
                  emptyText="No business units yet. Create them in Settings → Access Control."
                />
              )}

              {accessLevel === "project" && (
                <SearchableChecklist
                  label="Projects"
                  placeholder="Select projects..."
                  color="violet"
                  items={repoList.map((r: any) => ({ id: r.id, name: r.name }))}
                  selectedIds={selectedProjects}
                  onChange={setSelectedProjects}
                  emptyText="No projects found."
                />
              )}

              {accessLevel === "organization" && (
                <p className="text-xs text-slate-600">This user will have access to all business units and projects.</p>
              )}
            </div>

            <div className="flex gap-3 pt-3">
              <button onClick={handleSave} disabled={saving || !form.full_name || !form.email} className="btn-primary text-sm">
                {saving ? "Saving..." : editingUser ? "Update User" : "Create User"}
              </button>
              <button onClick={resetForm} className="btn-secondary text-sm">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* User Table */}
      <div className="card p-0 overflow-visible">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/[0.06]">
              <th className="px-5 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-widest">User</th>
              <th className="px-5 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-widest">Role</th>
              <th className="px-5 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-widest">Access Scope</th>
              <th className="px-5 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-widest">Status</th>
              <th className="px-5 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-widest hidden lg:table-cell">Created</th>
              <th className="px-5 py-3 text-right text-[10px] font-semibold text-slate-500 uppercase tracking-widest">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.04]">
            {loading ? (
              <tr><td colSpan={6} className="px-5 py-8 text-center"><div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin mx-auto" /></td></tr>
            ) : users.length === 0 ? (
              <tr><td colSpan={6} className="px-5 py-8 text-center text-slate-500">No users found</td></tr>
            ) : users.map((u, idx) => {
              const role = u.roles?.[0] || "viewer";
              return (
                <tr key={u.id} className={`hover:bg-white/[0.02] ${!u.is_active ? "opacity-50" : ""}`}>
                  <td className="px-5 py-3">
                    <div className="flex items-center gap-3">
                      <div className={`w-8 h-8 rounded-full bg-gradient-to-br ${AVATAR_COLORS[idx % AVATAR_COLORS.length]} flex items-center justify-center text-xs font-bold text-white shrink-0`}>
                        {u.full_name?.charAt(0)?.toUpperCase() || "?"}
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <p className="text-sm font-medium text-slate-200 truncate">{u.full_name}</p>
                          {isSelf(u) && <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/20">You</span>}
                        </div>
                        <p className="text-xs text-slate-500 truncate">{u.email}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-5 py-3">
                    <span className={`text-xs px-2.5 py-1 rounded-full border capitalize ${ROLE_COLORS[role] || ROLE_COLORS.viewer}`}>
                      {role.replace("_", " ")}
                    </span>
                  </td>
                  <td className="px-5 py-3">
                    {(() => {
                      const grants = grantsMap[u.id] || [];
                      if (grants.length === 0) return <span className="text-xs text-slate-600">No grant (full access)</span>;
                      const SCOPE_COLORS: Record<string, string> = {
                        organization: "text-purple-400", business_unit: "text-amber-400", project: "text-red-400"
                      };
                      const icons: Record<string, string> = { organization: "\u{1F3E2}", business_unit: "\u{1F3D7}\u{FE0F}", project: "\u{1F4C1}" };
                      return (
                        <div className="flex flex-col gap-1">
                          {grants.map((grant: any, gi: number) => {
                            const lvl = grant.access_level;
                            return (
                              <div key={gi} className="flex items-center gap-1.5">
                                <span className={`text-xs font-medium ${SCOPE_COLORS[lvl] || "text-slate-400"}`}>
                                  {icons[lvl] || ""} {grant.scope_name || (lvl === "organization" ? "Organization" : lvl.replace("_", " "))}
                                </span>
                                <span className="text-[10px] text-slate-500 capitalize">({grant.role})</span>
                              </div>
                            );
                          })}
                        </div>
                      );
                    })()}
                  </td>
                  <td className="px-5 py-3">
                    {u.is_active ? (
                      <span className="flex items-center gap-1.5 text-xs"><span className="w-2 h-2 rounded-full bg-green-400" /><span className="text-green-400">Active</span></span>
                    ) : (
                      <span className="flex items-center gap-1.5 text-xs"><span className="w-2 h-2 rounded-full bg-slate-500" /><span className="text-slate-500">Inactive</span></span>
                    )}
                  </td>
                  <td className="px-5 py-3 text-xs text-slate-500 hidden lg:table-cell">{new Date(u.created_at).toLocaleDateString()}</td>
                  <td className="px-5 py-3 text-right">
                    <div className="relative inline-block">
                      <button onClick={() => setMenuOpen(menuOpen === u.id ? null : u.id)} className="p-1.5 rounded hover:bg-white/[0.06]">
                        <svg className="w-4 h-4 text-slate-500" fill="currentColor" viewBox="0 0 20 20"><path d="M10 6a2 2 0 110-4 2 2 0 010 4zM10 12a2 2 0 110-4 2 2 0 010 4zM10 18a2 2 0 110-4 2 2 0 010 4z" /></svg>
                      </button>
                      {menuOpen === u.id && (
                        <>
                          <div className="fixed inset-0 z-10" onClick={() => setMenuOpen(null)} />
                          <div className="absolute right-0 top-8 z-20 w-48 py-1 rounded-xl border border-white/[0.08] shadow-2xl overflow-hidden" style={{ background: "rgba(8,11,28,0.95)",  }}>
                            <button onClick={() => openEdit(u)} className="block w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-white/[0.04]">Edit User</button>

                            {/* Role change submenu */}
                            {!isSelf(u) && (
                              <div className="border-t border-white/[0.06] my-1">
                                <p className="px-4 py-1.5 text-[10px] text-slate-600 uppercase tracking-wider">Change Role</p>
                                {["admin", "security_engineer", "developer", "viewer"].map((r) => (
                                  <button
                                    key={r}
                                    onClick={() => handleChangeRole(u.id, r)}
                                    className={`block w-full text-left px-4 py-1.5 text-xs hover:bg-white/[0.04] capitalize ${role === r ? "text-red-400 font-medium" : "text-slate-400"}`}
                                  >
                                    {r === role ? "✓ " : "  "}{r.replace("_", " ")}
                                  </button>
                                ))}
                              </div>
                            )}

                            {!isSelf(u) && (
                              <>
                                <div className="border-t border-white/[0.06] my-1" />
                                <button
                                  onClick={() => handleToggleActive(u)}
                                  className={`block w-full text-left px-4 py-2 text-sm ${u.is_active ? "text-yellow-400 hover:bg-yellow-500/5" : "text-green-400 hover:bg-green-500/5"}`}
                                >
                                  {u.is_active ? "Deactivate" : "Activate"}
                                </button>
                              </>
                            )}
                          </div>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════
   ROLES & PERMISSIONS SECTION
   ═══════════════════════════════════════════════════════ */
function RolesSection() {
  const [roles, setRoles] = useState<any[]>([]);
  const [allPerms, setAllPerms] = useState<any[]>([]);
  const [permGroups, setPermGroups] = useState<Record<string, any[]>>({});
  const [loading, setLoading] = useState(true);
  const [editingRole, setEditingRole] = useState<any>(null);
  const [editPerms, setEditPerms] = useState<string[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [newRole, setNewRole] = useState({ name: "", slug: "", description: "", color: "slate", permissions: [] as string[] });
  const [saving, setSaving] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<any>(null);

  const COLOR_MAP: Record<string, string> = {
    red: "text-red-400", purple: "text-purple-400", cyan: "text-red-400",
    slate: "text-slate-400", green: "text-green-400", orange: "text-orange-400",
    blue: "text-blue-400", pink: "text-pink-400", yellow: "text-yellow-400",
  };

  const loadData = useCallback(() => {
    getRoles().then((r) => setRoles(r.data || [])).catch(() => {}).finally(() => setLoading(false));
    getPermissions().then((r) => {
      setAllPerms(r.data.permissions || []);
      setPermGroups(r.data.groups || {});
    }).catch(() => {});
  }, []);
  useEffect(() => { loadData(); }, [loadData]);

  const startEdit = (role: any) => {
    setEditingRole(role);
    setEditPerms([...(role.permissions || [])]);
    setShowCreate(false);
  };

  const togglePerm = (perms: string[], key: string) =>
    perms.includes(key) ? perms.filter((p) => p !== key) : [...perms, key];

  const handleSaveEdit = async () => {
    if (!editingRole) return;
    setSaving(true);
    try {
      await updateRole(editingRole.id, { permissions: editPerms });
      setEditingRole(null); loadData();
    } finally { setSaving(false); }
  };

  const handleCreate = async () => {
    setSaving(true);
    try {
      await createRole(newRole);
      setShowCreate(false);
      setNewRole({ name: "", slug: "", description: "", color: "slate", permissions: [] });
      loadData();
    } finally { setSaving(false); }
  };

  const handleDelete = async () => {
    if (!confirmDelete) return;
    await deleteRole(confirmDelete.id).catch(() => {});
    setConfirmDelete(null); loadData();
  };

  const handleReset = async (id: string) => {
    await resetRole(id).catch(() => {});
    setEditingRole(null); loadData();
  };

  // Permission group renderer (used in both edit and create)
  const PermissionEditor = ({ perms, setPerms }: { perms: string[]; setPerms: (p: string[]) => void }) => (
    <div className="space-y-4">
      {Object.entries(permGroups).map(([group, groupPerms]) => (
        <div key={group}>
          <h5 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">{group}</h5>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {groupPerms.map((p: any) => {
              const active = perms.includes(p.key);
              return (
                <label
                  key={p.key}
                  onClick={() => setPerms(togglePerm(perms, p.key))}
                  className={`flex items-start gap-3 p-2.5 rounded-lg border cursor-pointer transition-all ${active ? "bg-green-500/5 border-green-500/20" : "bg-white/[0.01] border-white/[0.04] hover:border-white/[0.08]"}`}
                >
                  <div className={`w-5 h-5 rounded flex items-center justify-center shrink-0 mt-0.5 ${active ? "bg-green-500/20" : "bg-white/[0.04]"}`}>
                    {active && <svg className="w-3 h-3 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" /></svg>}
                  </div>
                  <div>
                    <p className={`text-sm font-medium ${active ? "text-green-400" : "text-slate-300"}`}>{p.label}</p>
                    {p.description && <p className="text-[10px] text-slate-600 mt-0.5">{p.description}</p>}
                  </div>
                </label>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );

  return (
    <div>
      <SectionHeader title="Roles & Permissions" description="Configure role-based access control. Each role defines what users can see and do." />

      <div className="flex items-center justify-between mb-4">
        <span className="text-sm text-slate-400">{roles.length} roles</span>
        <button onClick={() => { setShowCreate(true); setEditingRole(null); }} className="btn-primary text-xs px-3 py-1.5">+ Create Role</button>
      </div>

      {/* Create custom role form */}
      {showCreate && (
        <div className="card border-red-500/20 mb-5">
          <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">Create Custom Role</h4>
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="text-xs text-slate-500 mb-1 block">Name</label>
                <input value={newRole.name} onChange={(e) => setNewRole((f) => ({ ...f, name: e.target.value, slug: e.target.value.toLowerCase().replace(/\s+/g, "_").replace(/[^a-z0-9_]/g, "") }))} placeholder="e.g. Security Champion" className="input-dark" />
              </div>
              <div>
                <label className="text-xs text-slate-500 mb-1 block">Slug</label>
                <input value={newRole.slug} onChange={(e) => setNewRole((f) => ({ ...f, slug: e.target.value }))} placeholder="security_champion" className="input-dark font-mono text-xs" />
              </div>
              <div>
                <label className="text-xs text-slate-500 mb-1 block">Color</label>
                <div className="flex gap-1.5 mt-1">
                  {["red", "purple", "cyan", "green", "orange", "blue", "pink", "yellow", "slate"].map((c) => (
                    <button key={c} onClick={() => setNewRole((f) => ({ ...f, color: c }))}
                      className={`w-6 h-6 rounded-full bg-${c}-500 border-2 transition-all ${newRole.color === c ? "border-white scale-110" : "border-transparent opacity-50 hover:opacity-75"}`} />
                  ))}
                </div>
              </div>
            </div>
            <div>
              <label className="text-xs text-slate-500 mb-1 block">Description</label>
              <input value={newRole.description} onChange={(e) => setNewRole((f) => ({ ...f, description: e.target.value }))} placeholder="Role description" className="input-dark" />
            </div>
            <div>
              <label className="text-xs text-slate-500 mb-2 block">Permissions</label>
              <PermissionEditor perms={newRole.permissions} setPerms={(p) => setNewRole((f) => ({ ...f, permissions: p }))} />
            </div>
            <div className="flex gap-3 pt-2">
              <button onClick={handleCreate} disabled={saving || !newRole.name || !newRole.slug} className="btn-primary text-sm">
                {saving ? "Creating..." : "Create Role"}
              </button>
              <button onClick={() => setShowCreate(false)} className="btn-secondary text-sm">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Role list */}
      {loading ? (
        <div className="text-center py-8"><div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin mx-auto" /></div>
      ) : (
        <div className="space-y-4">
          {roles.map((role) => {
            const isEditing = editingRole?.id === role.id;
            return (
              <div key={role.id} className={`card ${isEditing ? "border-red-500/20" : ""}`}>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <h4 className={`text-base font-semibold ${COLOR_MAP[role.color] || "text-slate-400"}`}>{role.name}</h4>
                        {role.is_builtin && <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/[0.04] text-slate-600 border border-white/[0.04]">Built-in</span>}
                        {role.user_count > 0 && <span className="text-[10px] text-slate-600">{role.user_count} user{role.user_count > 1 ? "s" : ""}</span>}
                      </div>
                      <p className="text-xs text-slate-500 mt-0.5">{role.description}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {isEditing ? (
                      <>
                        <button onClick={handleSaveEdit} disabled={saving} className="btn-primary text-xs px-3 py-1.5">{saving ? "Saving..." : "Save"}</button>
                        {role.is_builtin && <button onClick={() => handleReset(role.id)} className="text-xs text-yellow-400 hover:text-yellow-300 px-2">Reset Default</button>}
                        <button onClick={() => setEditingRole(null)} className="text-xs text-slate-400 hover:text-slate-200 px-2">Cancel</button>
                      </>
                    ) : (
                      <>
                        <button onClick={() => startEdit(role)} className="text-xs text-slate-400 hover:text-slate-200 px-3 py-1.5 rounded-lg hover:bg-white/[0.04]">Edit</button>
                        {!role.is_builtin && (
                          <button onClick={() => setConfirmDelete(role)} className="text-xs text-red-400 hover:text-red-300 px-2 py-1.5 rounded-lg hover:bg-red-500/5">Delete</button>
                        )}
                      </>
                    )}
                  </div>
                </div>

                {/* View mode: permission badges */}
                {!isEditing && (
                  <div className="flex flex-wrap gap-2">
                    {allPerms.map((p) => (
                      <span key={p.key} className={`text-[10px] px-2.5 py-1 rounded-full border ${(role.permissions || []).includes(p.key) ? "bg-green-500/10 text-green-400 border-green-500/20" : "bg-white/[0.02] text-slate-600 border-white/[0.04] line-through"}`}>
                        {p.label}
                      </span>
                    ))}
                  </div>
                )}

                {/* Edit mode: permission matrix */}
                {isEditing && (
                  <div className="mt-3 pt-3 border-t border-white/[0.06]">
                    <PermissionEditor perms={editPerms} setPerms={setEditPerms} />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Delete confirmation */}
      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="card border-red-500/20 max-w-md w-full mx-4">
            <h3 className="text-base font-semibold text-white mb-2">Delete &ldquo;{confirmDelete.name}&rdquo; role?</h3>
            <p className="text-sm text-slate-400 mb-5">Users with this role will need to be reassigned. This cannot be undone.</p>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setConfirmDelete(null)} className="btn-secondary text-sm">Cancel</button>
              <button onClick={handleDelete} className="btn-danger text-sm">Delete Role</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════
   SSO & IDENTITY SECTION
   ═══════════════════════════════════════════════════════ */
function SSOSection() {
  const PROVIDERS = [
    { name: "SAML 2.0", description: "Enterprise SSO via SAML protocol", color: "from-blue-500 to-indigo-500", fields: ["Entity ID", "SSO URL", "Certificate"],
      icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" /><rect x="3" y="5" width="18" height="14" rx="2" /><path d="M3 9h18" /></svg>),
    },
    { name: "OpenID Connect (OIDC)", description: "OAuth 2.0 / OIDC standard protocol", color: "from-purple-500 to-pink-500", fields: ["Client ID", "Client Secret", "Issuer URL", "Redirect URI"],
      icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="9" /><path d="M12 3v18" /><ellipse cx="12" cy="12" rx="4" ry="9" /></svg>),
    },
    { name: "Okta", description: "Okta workforce identity", color: "from-blue-500 to-blue-600", fields: ["Okta Domain", "Client ID", "Client Secret"],
      icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="3" fill="currentColor" stroke="none" opacity="0.4" /></svg>),
    },
    { name: "Azure AD / Entra ID", description: "Microsoft identity platform", color: "from-blue-500 to-indigo-500", fields: ["Tenant ID", "Client ID", "Client Secret"],
      icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M3 17l6-12h6l6 12" strokeLinecap="round" strokeLinejoin="round" /><path d="M7.5 17h9" strokeLinecap="round" /></svg>),
    },
    { name: "Google Workspace", description: "Google Cloud Identity", color: "from-red-500 to-yellow-500", fields: ["Client ID", "Client Secret", "Domain"],
      icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="9" /><path d="M12 7v5l4 2" strokeLinecap="round" /><path d="M16.5 7.5A7 7 0 0019 12" strokeLinecap="round" opacity="0.5" /></svg>),
    },
    { name: "OneLogin", description: "OneLogin identity provider", color: "from-emerald-500 to-green-600", fields: ["Client ID", "Client Secret", "Region"],
      icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="10" r="3" /><path d="M12 13v5" strokeLinecap="round" /><path d="M5 20c0-4 3-7 7-7s7 3 7 7" strokeLinecap="round" /></svg>),
    },
    { name: "PingIdentity", description: "Ping identity platform", color: "from-red-500 to-red-600", fields: ["Environment ID", "Client ID", "Client Secret"],
      icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="2" fill="currentColor" stroke="none" /><circle cx="12" cy="12" r="5" /><circle cx="12" cy="12" r="9" opacity="0.4" /></svg>),
    },
    { name: "LDAP / Active Directory", description: "On-premise directory service", color: "from-slate-500 to-slate-600", fields: ["Server URL", "Base DN", "Bind DN", "Bind Password", "Search Filter"],
      icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="6" y="3" width="12" height="5" rx="1" /><rect x="6" y="10" width="12" height="5" rx="1" /><rect x="6" y="17" width="12" height="4" rx="1" /><circle cx="15" cy="5.5" r="1" fill="currentColor" stroke="none" /><circle cx="15" cy="12.5" r="1" fill="currentColor" stroke="none" /></svg>),
    },
    { name: "Custom OIDC Provider", description: "Any OIDC-compliant identity provider", color: "from-red-500 to-orange-600", fields: ["Issuer URL", "Client ID", "Client Secret", "Scopes"],
      icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><circle cx="12" cy="12" r="3" /></svg>),
    },
  ];

  const [configuring, setConfiguring] = useState<string | null>(null);

  return (
    <div>
      <SectionHeader title="SSO & Identity" description="Configure single sign-on for your organization. Supports SAML, OIDC, and all major enterprise identity providers." />

      <div className="card mb-5 bg-yellow-500/[0.03] border-yellow-500/10">
        <div className="flex items-start gap-3">
          <svg className="w-5 h-5 text-yellow-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          <div>
            <p className="text-sm text-yellow-400 font-medium">SSO is currently using local authentication</p>
            <p className="text-xs text-slate-500 mt-0.5">Configure an identity provider below to enable enterprise SSO. Local authentication will remain as fallback.</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {PROVIDERS.map((p) => (
          <div key={p.name} className="card card-hover cursor-pointer" onClick={() => setConfiguring(configuring === p.name ? null : p.name)}>
            <div className="flex items-center gap-3 mb-2">
              <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${p.color} flex items-center justify-center text-white`}>{p.icon}</div>
              <div>
                <h4 className="text-sm font-semibold text-slate-200">{p.name}</h4>
                <p className="text-[10px] text-slate-500">{p.description}</p>
              </div>
            </div>
            {configuring === p.name && (
              <div className="mt-3 pt-3 border-t border-white/[0.06] space-y-3" onClick={(e) => e.stopPropagation()}>
                {p.fields.map((field) => (
                  <div key={field}>
                    <label className="text-xs text-slate-400 mb-1 block">{field}</label>
                    <input type={field.toLowerCase().includes("secret") || field.toLowerCase().includes("password") ? "password" : "text"} placeholder={field} className="input-dark text-xs" />
                  </div>
                ))}
                <div className="flex gap-2 pt-1">
                  <button className="btn-primary text-xs px-3 py-1.5">Test & Save</button>
                  <button onClick={() => setConfiguring(null)} className="btn-secondary text-xs px-3 py-1.5">Cancel</button>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════
   NOTIFICATIONS SECTION
   ═══════════════════════════════════════════════════════ */
function NotificationsSection() {
  const CHANNELS = [
    { name: "Slack", key: "slack", color: "bg-[#4A154B]/20", borderColor: "border-[#4A154B]/30", configured: false,
      fields: ["Webhook URL", "Channel"],
      icon: (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
          <path d="M6 15a2 2 0 01-2 2 2 2 0 01-2-2 2 2 0 012-2h2v2zm1 0a2 2 0 012-2 2 2 0 012 2v5a2 2 0 01-2 2 2 2 0 01-2-2v-5zm2-8a2 2 0 01-2-2 2 2 0 012-2 2 2 0 012 2v2H9zm0 1a2 2 0 012 2 2 2 0 01-2 2H4a2 2 0 01-2-2 2 2 0 012-2h5zm8 2a2 2 0 012-2 2 2 0 012 2 2 2 0 01-2 2h-2v-2zm-1 0a2 2 0 01-2 2 2 2 0 01-2-2V5a2 2 0 012-2 2 2 0 012 2v5zm-2 8a2 2 0 012 2 2 2 0 01-2 2 2 2 0 01-2-2v-2h2zm0-1a2 2 0 01-2-2 2 2 0 012-2h5a2 2 0 012 2 2 2 0 01-2 2h-5z" />
        </svg>
      ),
    },
    { name: "Microsoft Teams", key: "teams", color: "bg-[#464EB8]/20", borderColor: "border-[#464EB8]/30", configured: false,
      fields: ["Webhook URL"],
      icon: (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <rect x="3" y="5" width="12" height="14" rx="1.5" />
          <path d="M15 8h3.5A1.5 1.5 0 0120 9.5v5a1.5 1.5 0 01-1.5 1.5H15" />
          <circle cx="18" cy="5.5" r="2" />
          <path d="M7 10h4M7 13h3" strokeLinecap="round" />
        </svg>
      ),
    },
    { name: "Email (SMTP)", key: "email", color: "bg-red-500/15", borderColor: "border-red-500/20", configured: false,
      fields: ["SMTP Host", "Port", "Username", "Password", "From Address"],
      icon: (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <rect x="3" y="5" width="18" height="14" rx="2" />
          <path d="M3 7l9 6 9-6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      ),
    },
    { name: "Webhook", key: "webhook", color: "bg-orange-500/15", borderColor: "border-orange-500/20", configured: false,
      fields: ["Endpoint URL", "Secret Token", "Headers (JSON)"],
      icon: (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <circle cx="12" cy="5" r="2.5" />
          <circle cx="5" cy="18" r="2.5" />
          <circle cx="19" cy="18" r="2.5" />
          <path d="M12 7.5V12l-5.5 3.2M12 12l5.5 3.2" strokeLinecap="round" />
        </svg>
      ),
    },
    { name: "PagerDuty", key: "pagerduty", color: "bg-[#06AC38]/15", borderColor: "border-[#06AC38]/20", configured: false,
      fields: ["Integration Key", "Severity Mapping"],
      icon: (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
          <path d="M12 3v4M12 17v4M5.636 5.636l2.828 2.828M15.536 15.536l2.828 2.828M3 12h4M17 12h4M5.636 18.364l2.828-2.828M15.536 8.464l2.828-2.828" strokeLinecap="round" />
          <circle cx="12" cy="12" r="3" />
        </svg>
      ),
    },
    { name: "Jira", key: "jira", color: "bg-[#0052CC]/20", borderColor: "border-[#0052CC]/30", configured: false,
      fields: ["Server URL", "Project Key", "API Token", "Assignee"],
      icon: (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path d="M12 3l9 9-9 9" strokeLinecap="round" strokeLinejoin="round" />
          <path d="M12 3l-9 9 9 9" strokeLinecap="round" strokeLinejoin="round" opacity="0.5" />
          <circle cx="12" cy="12" r="2" fill="currentColor" stroke="none" />
        </svg>
      ),
    },
  ];

  return (
    <div>
      <SectionHeader title="Notification Channels" description="Configure where to send alerts for new findings, scan completions, and remediation updates." />
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {CHANNELS.map((ch) => (
          <div key={ch.name} className={`card card-hover border ${ch.borderColor}`}>
            <div className="flex items-center gap-3 mb-3">
              <div className={`w-10 h-10 rounded-lg ${ch.color} flex items-center justify-center text-slate-200`}>{ch.icon}</div>
              <div>
                <h4 className="text-sm font-semibold text-slate-200">{ch.name}</h4>
                <span className={`text-[10px] ${ch.configured ? "text-green-400" : "text-slate-600"}`}>{ch.configured ? "Connected" : "Not configured"}</span>
              </div>
            </div>
            <div className="flex gap-1.5 flex-wrap mb-3">
              {ch.fields.map((f) => (
                <span key={f} className="text-[9px] px-1.5 py-0.5 rounded bg-white/[0.03] text-slate-600 border border-white/[0.04]">{f}</span>
              ))}
            </div>
            <button className="btn-secondary w-full text-xs py-1.5">Configure</button>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════
   API KEYS SECTION
   ═══════════════════════════════════════════════════════ */
function APIKeysSection() {
  const [keys, setKeys] = useState<any[]>([]);
  const [scopes, setScopes] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: "", scopes: ["scan", "findings", "gate"] as string[], expires_in_days: 365 as number | null, allowed_ip_cidrs: "" });
  const [saving, setSaving] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null); // shown once after creation
  const [newKeyLabel, setNewKeyLabel] = useState<string>("API Key Generated");
  const [copied, setCopied] = useState(false);
  const [confirmRevoke, setConfirmRevoke] = useState<any>(null);
  // Rotation confirmation modal — distinct from revoke because
  // rotation is non-destructive; the dialog clarifies the grace window
  // and lets the operator override the default.
  const [confirmRotate, setConfirmRotate] = useState<any>(null);
  const [rotateGraceDays, setRotateGraceDays] = useState<number>(7);
  const [rotating, setRotating] = useState(false);
  // Edit modal — Sprint 3 / GAP-10.  Editable fields are deliberately
  // narrow: name + allowlist.  Scope changes go through "create new"
  // (changing scope == changing blast radius), expiry edits via rotate.
  const [editing, setEditing] = useState<any>(null);
  const [editForm, setEditForm] = useState({ name: "", allowed_ip_cidrs: "" });
  const [editSaving, setEditSaving] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);
  // SDK snippet language picker for the show-once banner (Sprint 4 /
  // GAP-12).  Default: cURL — universally understood + fastest for
  // an "is it working?" smoke test.
  type SnippetLang = "curl" | "github" | "gitlab" | "python" | "node" | "go";
  const [snippetLang, setSnippetLang] = useState<SnippetLang>("curl");
  const [snippetCopied, setSnippetCopied] = useState<SnippetLang | null>(null);
  // Usage drawer state — null when no row is expanded.
  const [usageKeyId, setUsageKeyId] = useState<string | null>(null);
  const [usageData, setUsageData] = useState<any>(null);
  const [usageLoading, setUsageLoading] = useState(false);
  // Status filter — defaults to "active" so the operator's first view
  // matches the pre-Sprint-1 behaviour (Active Keys only).  Switching
  // to All / Expired / Revoked / Rotating lets us inspect dormant,
  // soon-to-expire, or terminated keys without leaving the page.
  const [statusFilter, setStatusFilter] = useState<"active" | "rotating" | "expired" | "revoked" | "all">("active");

  const loadData = useCallback(async () => {
    try {
      const [keysR, scopesR] = await Promise.all([
        getAPIKeys().catch(() => ({ data: [] })),
        getAPIKeyScopes().catch(() => ({ data: [] })),
      ]);
      setKeys(keysR.data || []);
      setScopes(scopesR.data || []);
    } finally { setLoading(false); }
  }, []);
  useEffect(() => { loadData(); }, [loadData]);

  const resetForm = () => { setForm({ name: "", scopes: ["scan", "findings", "gate"], expires_in_days: 365, allowed_ip_cidrs: "" }); setShowForm(false); setNewKey(null); setCopied(false); };

  // Parse the textarea content into an array of CIDR strings.
  // Accepts comma OR newline separated; trims; drops blanks.
  // Returns null when input is empty so we POST allowed_ip_cidrs: null
  // (unrestricted) — matches backend triple-state semantics.
  const parseCidrInput = (raw: string): string[] | null => {
    const items = raw
      .split(/[,\n]/)
      .map((s) => s.trim())
      .filter(Boolean);
    return items.length > 0 ? items : null;
  };

  const handleCreate = async () => {
    setSaving(true);
    setNewKeyLabel("API Key Generated");
    try {
      const res = await createAPIKey({
        name: form.name,
        scopes: form.scopes,
        expires_in_days: form.expires_in_days,
        allowed_ip_cidrs: parseCidrInput(form.allowed_ip_cidrs),
      });
      setNewKey(res.data.api_key);
      setShowForm(false);
      loadData();
    } catch (e: any) {
      // 422 from CIDR validation — surface the offending entry.
      alert(e?.response?.data?.detail || "Create failed");
    } finally { setSaving(false); }
  };

  const handleRevoke = async () => {
    if (!confirmRevoke) return;
    await revokeAPIKey(confirmRevoke.id).catch(() => {});
    setConfirmRevoke(null);
    loadData();
  };

  const handleCopy = () => {
    if (newKey) { navigator.clipboard.writeText(newKey); setCopied(true); setTimeout(() => setCopied(false), 2000); }
  };

  const toggleScope = (s: string) => setForm(f => ({ ...f, scopes: f.scopes.includes(s) ? f.scopes.filter(x => x !== s) : [...f.scopes, s] }));

  // Resolve a status for older API responses that haven't been upgraded
  // to return `status` yet — keeps the UI working during partial rollout.
  const resolveStatus = (k: any): "active" | "rotating" | "expired" | "revoked" => {
    if (k.status) return k.status as any;
    if (!k.is_active) return "revoked";
    if (k.rotation_grace_until && new Date(k.rotation_grace_until).getTime() > Date.now()) return "rotating";
    if (k.expires_at && new Date(k.expires_at).getTime() < Date.now()) return "expired";
    return "active";
  };

  const STATUS_META: Record<string, { label: string; classes: string }> = {
    active:   { label: "Active",   classes: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30" },
    rotating: { label: "Rotating", classes: "bg-blue-500/15 text-blue-300 border-blue-500/30" },
    expired:  { label: "Expired",  classes: "bg-amber-500/15 text-amber-300 border-amber-500/30" },
    revoked:  { label: "Revoked",  classes: "bg-red-500/15 text-red-300 border-red-500/30" },
  };

  // Render "Last used" — relative ("2h ago", "4d ago") to make dormant
  // keys obvious at a glance.  Null → "Never used" in muted red so an
  // unused-for-a-long-time key visually stands out (it's likely either
  // misconfigured or a forgotten credential ripe for leakage).
  const formatLastUsed = (iso: string | null | undefined): { text: string; muted: boolean } => {
    if (!iso) return { text: "Never used", muted: true };
    const t = new Date(iso).getTime();
    const ageMs = Date.now() - t;
    if (ageMs < 0) return { text: "just now", muted: false };
    const mins = Math.floor(ageMs / 60_000);
    if (mins < 1) return { text: "just now", muted: false };
    if (mins < 60) return { text: `${mins}m ago`, muted: false };
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return { text: `${hrs}h ago`, muted: false };
    const days = Math.floor(hrs / 24);
    if (days < 30) return { text: `${days}d ago`, muted: days > 14 };
    const months = Math.floor(days / 30);
    return { text: `${months}mo ago`, muted: true };
  };

  const filteredKeys = statusFilter === "all"
    ? keys
    : keys.filter((k: any) => resolveStatus(k) === statusFilter);
  const counts = {
    active:   keys.filter((k: any) => resolveStatus(k) === "active").length,
    rotating: keys.filter((k: any) => resolveStatus(k) === "rotating").length,
    expired:  keys.filter((k: any) => resolveStatus(k) === "expired").length,
    revoked:  keys.filter((k: any) => resolveStatus(k) === "revoked").length,
    all:      keys.length,
  };

  // Map from id → name for "rotated → [successor]" labels on rotating rows.
  const keyNameById = useMemo(() => {
    const m: Record<string, string> = {};
    keys.forEach((k: any) => { m[k.id] = k.name; });
    return m;
  }, [keys]);

  const handleRotate = async () => {
    if (!confirmRotate) return;
    setRotating(true);
    try {
      const res = await rotateAPIKey(confirmRotate.id, rotateGraceDays);
      setNewKey(res.data.api_key);
      setNewKeyLabel(`Key Rotated — successor for "${confirmRotate.name}"`);
      setConfirmRotate(null);
      setRotateGraceDays(7);
      loadData();
    } catch (e: any) {
      // Surface the server's 409 detail to the operator — already-rotated
      // and revoked rejection messages are useful diagnostics.
      alert(e?.response?.data?.detail || "Rotation failed");
    } finally {
      setRotating(false);
    }
  };

  const openEdit = (k: any) => {
    setEditing(k);
    setEditForm({
      name: k.name,
      allowed_ip_cidrs: (k.allowed_ip_cidrs || []).join("\n"),
    });
    setEditError(null);
  };

  const handleEdit = async () => {
    if (!editing) return;
    setEditSaving(true);
    setEditError(null);
    try {
      await updateAPIKey(editing.id, {
        name: editForm.name,
        // [] means "clear restriction".  parseCidrInput returns null
        // for empty input which the API treats as "leave unchanged" —
        // so when the operator clears the textarea entirely, send an
        // explicit empty array.
        allowed_ip_cidrs: parseCidrInput(editForm.allowed_ip_cidrs) ?? [],
      });
      setEditing(null);
      loadData();
    } catch (e: any) {
      setEditError(e?.response?.data?.detail || "Update failed");
    } finally {
      setEditSaving(false);
    }
  };

  // SDK snippet generator (Sprint 4 / GAP-12).  Each language returns
  // a ready-to-paste integration block with the live key pre-filled.
  // Showcases the simplest possible call (GET /auth/me) so a customer's
  // first cURL just works.  When the example needs a real endpoint
  // (CI YAML), we use /api/v1/repositories which is the most common
  // production caller.  The base-URL is resolved from the browser's
  // current host so localhost development AND production both render
  // accurate snippets.
  const renderSnippet = (lang: SnippetLang, key: string): string => {
    const base = typeof window !== "undefined"
      ? `${window.location.protocol}//${window.location.host.replace(/:\d+$/, ":8001")}/api/v1`
      : "https://api.vooda.ai/v1";
    switch (lang) {
      case "curl":
        return `# Quick smoke test — confirm the key works
curl -sS ${base}/auth/me \\
  -H "Authorization: Bearer ${key}"

# Trigger a scan on a repository
curl -sS -X POST ${base}/repositories/<REPO_ID>/scan \\
  -H "Authorization: Bearer ${key}" \\
  -H "Content-Type: application/json" \\
  -d '{"scan_type":"standalone"}'`;
      case "github":
        return `# .github/workflows/vooda-scan.yml
name: Vooda Secret Scan
on: [push, pull_request]

jobs:
  vooda-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Trigger Vooda scan
        env:
          # Store the key as a repo secret named VOODA_API_KEY:
          # Settings → Secrets and variables → Actions → New repository secret
          VOODA_API_KEY: \${{ secrets.VOODA_API_KEY }}
        run: |
          curl -fsS -X POST ${base}/repositories/\${{ vars.VOODA_REPO_ID }}/scan \\
            -H "Authorization: Bearer $VOODA_API_KEY" \\
            -H "Content-Type: application/json" \\
            -d '{"scan_type":"standalone"}'`;
      case "gitlab":
        return `# .gitlab-ci.yml
vooda_scan:
  stage: test
  image: alpine:latest
  before_script:
    - apk add --no-cache curl jq
  script:
    # Add VOODA_API_KEY as a masked, protected CI/CD variable:
    # Settings → CI/CD → Variables → Add
    - |
      curl -fsS -X POST "${base}/repositories/$VOODA_REPO_ID/scan" \\
        -H "Authorization: Bearer $VOODA_API_KEY" \\
        -H "Content-Type: application/json" \\
        -d '{"scan_type":"standalone"}'`;
      case "python":
        return `# requirements: requests>=2.31
import os, requests

VOODA_API_KEY = os.environ["VOODA_API_KEY"]  # set in CI secrets
BASE_URL = "${base}"

session = requests.Session()
session.headers.update({"Authorization": f"Bearer {VOODA_API_KEY}"})

# Smoke test
me = session.get(f"{BASE_URL}/auth/me").json()
print(f"Authenticated as {me['email']}")

# Trigger a scan
resp = session.post(
    f"{BASE_URL}/repositories/<REPO_ID>/scan",
    json={"scan_type": "standalone"},
)
resp.raise_for_status()
print(f"Scan queued: {resp.json()['id']}")`;
      case "node":
        return `// package.json: "axios": "^1.7.0"
import axios from "axios";

const VOODA_API_KEY = process.env.VOODA_API_KEY; // CI secret
const api = axios.create({
  baseURL: "${base}",
  headers: { Authorization: \`Bearer \${VOODA_API_KEY}\` },
});

// Smoke test
const { data: me } = await api.get("/auth/me");
console.log(\`Authenticated as \${me.email}\`);

// Trigger a scan
const { data: scan } = await api.post(
  "/repositories/<REPO_ID>/scan",
  { scan_type: "standalone" },
);
console.log(\`Scan queued: \${scan.id}\`);`;
      case "go":
        return `// go.mod requires: go 1.21+
package main

import (
    "bytes"
    "fmt"
    "net/http"
    "os"
)

const baseURL = "${base}"

func main() {
    apiKey := os.Getenv("VOODA_API_KEY")
    req, _ := http.NewRequest("POST",
        baseURL+"/repositories/<REPO_ID>/scan",
        bytes.NewBufferString(\`{"scan_type":"standalone"}\`))
    req.Header.Set("Authorization", "Bearer "+apiKey)
    req.Header.Set("Content-Type", "application/json")

    resp, err := http.DefaultClient.Do(req)
    if err != nil { panic(err) }
    defer resp.Body.Close()
    fmt.Printf("Scan queued: HTTP %d\\n", resp.StatusCode)
}`;
    }
  };

  const copySnippet = (lang: SnippetLang, text: string) => {
    navigator.clipboard.writeText(text);
    setSnippetCopied(lang);
    setTimeout(() => setSnippetCopied(null), 2000);
  };

  const toggleUsage = async (keyId: string) => {
    if (usageKeyId === keyId) {
      setUsageKeyId(null); setUsageData(null); return;
    }
    setUsageKeyId(keyId);
    setUsageData(null);
    setUsageLoading(true);
    try {
      const res = await getAPIKeyUsage(keyId, 7);
      setUsageData(res.data);
    } catch {
      setUsageData({ error: "Failed to load usage data" });
    } finally {
      setUsageLoading(false);
    }
  };

  const EXPIRY_OPTIONS = [
    { value: 30, label: "30 days" }, { value: 90, label: "90 days" },
    { value: 180, label: "6 months" }, { value: 365, label: "1 year" }, { value: null, label: "Never" },
  ];

  return (
    <div>
      <SectionHeader title="API Keys" description="Manage API keys for CI/CD pipeline integration, webhook callbacks, and programmatic access." />

      {/* New key created banner */}
      {newKey && (
        <div className="card border-green-500/30 bg-green-500/5 mb-5">
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 rounded-lg bg-green-500/20 flex items-center justify-center shrink-0 mt-0.5">
              <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-green-400 mb-1">{newKeyLabel}</p>
              <p className="text-xs text-slate-400 mb-3">Copy this key now. It won&apos;t be shown again.</p>
              <div className="flex items-center gap-2 mb-4">
                <code className="flex-1 bg-[#0d1117] rounded-lg px-4 py-2.5 font-mono text-xs text-red-300 select-all overflow-x-auto">{newKey}</code>
                <button onClick={handleCopy} className={`shrink-0 px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${copied ? "bg-green-500/20 text-green-400" : "bg-white/[0.06] text-slate-300 hover:bg-white/[0.1]"}`}>
                  {copied ? "Copied!" : "Copy"}
                </button>
              </div>

              {/* SDK snippets (Sprint 4 / GAP-12) — ready-to-paste
                  integration code for the major CI/CD platforms +
                  languages.  The key is pre-filled so the first
                  copy-paste just works; subsequent calls should use
                  an environment variable (every snippet demonstrates
                  this pattern). */}
              <div className="border-t border-white/[0.06] pt-3">
                <div className="flex items-center justify-between gap-2 mb-2 flex-wrap">
                  <p className="text-[11px] font-medium text-slate-300">
                    Quick-start integration snippets
                  </p>
                  <div className="flex gap-1 flex-wrap">
                    {(["curl", "github", "gitlab", "python", "node", "go"] as const).map((lang) => {
                      const label = {
                        curl: "cURL", github: "GitHub Actions", gitlab: "GitLab CI",
                        python: "Python", node: "Node.js", go: "Go",
                      }[lang];
                      const active = snippetLang === lang;
                      return (
                        <button
                          key={lang}
                          onClick={() => setSnippetLang(lang)}
                          className={`px-2 py-1 rounded text-[10px] font-medium border transition-all ${
                            active
                              ? "bg-white/[0.08] text-slate-200 border-white/[0.15]"
                              : "bg-white/[0.02] text-slate-500 border-white/[0.04] hover:bg-white/[0.05]"
                          }`}
                        >
                          {label}
                        </button>
                      );
                    })}
                  </div>
                </div>
                <div className="relative">
                  <pre className="bg-[#0d1117] rounded-lg p-3 font-mono text-[11px] text-slate-300 overflow-x-auto whitespace-pre max-h-72 leading-snug">
                    {renderSnippet(snippetLang, newKey)}
                  </pre>
                  <button
                    onClick={() => copySnippet(snippetLang, renderSnippet(snippetLang, newKey))}
                    className={`absolute top-2 right-2 px-2 py-1 rounded text-[10px] font-medium transition-all ${
                      snippetCopied === snippetLang
                        ? "bg-green-500/20 text-green-400"
                        : "bg-white/[0.08] text-slate-300 hover:bg-white/[0.15]"
                    }`}
                  >
                    {snippetCopied === snippetLang ? "Copied!" : "Copy"}
                  </button>
                </div>
                <p className="text-[10px] text-slate-600 mt-1.5">
                  After closing this banner, the raw key is gone — these snippets show the
                  key NOW so you can paste them straight into CI. The env-var pattern in
                  each snippet (<code className="text-slate-400">$VOODA_API_KEY</code>) is
                  the recommended steady-state.
                </p>
              </div>
            </div>
            <button onClick={() => setNewKey(null)} className="text-slate-500 hover:text-slate-300 shrink-0">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          </div>
        </div>
      )}

      {/* Create form */}
      {showForm && (
        <div className="card border-red-500/20 mb-5">
          <h4 className="text-sm font-semibold text-slate-300 mb-4">Generate New API Key</h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
            <div>
              <label className="text-xs text-slate-500 mb-1.5 block">Key Name</label>
              <input value={form.name} onChange={(e) => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. CI/CD Pipeline, GitHub Actions" className="input-dark" />
            </div>
            <div>
              <label className="text-xs text-slate-500 mb-1.5 block">Expires In</label>
              <select value={form.expires_in_days === null ? "null" : String(form.expires_in_days)} onChange={(e) => setForm(f => ({ ...f, expires_in_days: e.target.value === "null" ? null : Number(e.target.value) }))} className="select-dark w-full">
                {EXPIRY_OPTIONS.map(o => <option key={String(o.value)} value={String(o.value)}>{o.label}</option>)}
              </select>
            </div>
          </div>
          <div className="mb-4">
            <label className="text-xs text-slate-500 mb-2 block">Scopes</label>
            <div className="flex flex-wrap gap-2">
              {scopes.map((s: any) => {
                const active = form.scopes.includes(s.scope);
                return (
                  <button key={s.scope} type="button" onClick={() => toggleScope(s.scope)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${active ? "bg-red-500/20 text-red-300 border-red-500/40" : "bg-white/[0.03] text-slate-400 border-white/[0.08] hover:border-red-500/30"}`}
                  >
                    {active && <span className="mr-1">&#10003;</span>}{s.scope}
                  </button>
                );
              })}
            </div>
            <p className="text-[10px] text-slate-600 mt-1.5">{form.scopes.length} scope{form.scopes.length !== 1 ? "s" : ""} selected</p>
          </div>
          {/* IP allowlist — optional source-network restriction.
              Enterprise SOC 2 / FedRAMP requirement; commonly used to
              lock a CI key to GitHub Actions' egress ranges or a VPN
              CIDR.  Leaving blank = unrestricted (matches the pre-
              Sprint-3 default).  CIDR entries are server-canonicalized
              so "192.168.1.5/24" reads back as "192.168.1.0/24". */}
          <div className="mb-4">
            <label className="text-xs text-slate-500 mb-1.5 block">
              IP allowlist <span className="text-slate-600">(optional, one CIDR per line)</span>
            </label>
            <textarea
              value={form.allowed_ip_cidrs}
              onChange={(e) => setForm(f => ({ ...f, allowed_ip_cidrs: e.target.value }))}
              placeholder="e.g.&#10;203.0.113.0/24&#10;192.168.0.0/16&#10;2001:db8::/32"
              rows={3}
              className="input-dark font-mono text-xs w-full resize-y"
            />
            <p className="text-[10px] text-slate-600 mt-1.5">
              Leave empty for no restriction. Both IPv4 + IPv6 supported. Max 50 entries.
              Block requests from outside these networks even with a valid key.
            </p>
          </div>
          <div className="flex gap-3">
            <button onClick={handleCreate} disabled={saving || !form.name} className="btn-primary text-sm">{saving ? "Generating..." : "Generate Key"}</button>
            <button onClick={resetForm} className="btn-secondary text-sm">Cancel</button>
          </div>
        </div>
      )}

      {/* Keys list */}
      <div className="card mb-5">
        <div className="flex items-center justify-between mb-4 gap-3 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <h4 className="text-sm font-semibold text-slate-300">API Keys</h4>
            {/* Status filter chips — counts make the operator's choice
                concrete (e.g. "23 active, 2 expired, 5 revoked"). */}
            {(["active", "rotating", "expired", "revoked", "all"] as const).map((f) => {
              const isActive = statusFilter === f;
              const meta = f === "all"
                ? { label: "All", count: counts.all }
                : { label: STATUS_META[f].label, count: (counts as any)[f] };
              return (
                <button
                  key={f}
                  onClick={() => setStatusFilter(f)}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-medium border transition-all ${
                    isActive
                      ? "bg-white/[0.08] text-slate-200 border-white/[0.15]"
                      : "bg-white/[0.02] text-slate-500 border-white/[0.04] hover:bg-white/[0.05]"
                  }`}
                >
                  {meta.label} <span className="text-slate-600 font-normal">({meta.count})</span>
                </button>
              );
            })}
          </div>
          {!showForm && <button onClick={() => { resetForm(); setShowForm(true); setNewKey(null); }} className="btn-primary text-xs px-3 py-1.5">+ Generate Key</button>}
        </div>

        {loading ? (
          <div className="flex justify-center py-8"><div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" /></div>
        ) : filteredKeys.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-sm text-slate-500">
              {statusFilter === "active" && counts.all === 0 && "No API keys generated yet"}
              {statusFilter === "active" && counts.all > 0 && `No active keys — ${counts.expired} expired, ${counts.revoked} revoked`}
              {statusFilter !== "active" && `No ${statusFilter === "all" ? "" : statusFilter} keys`}
            </p>
            <p className="text-xs text-slate-600 mt-1">Generate a key to integrate Vooda AI into your CI/CD pipeline</p>
          </div>
        ) : (
          <div className="space-y-3">
            {filteredKeys.map((k: any) => {
              const status = resolveStatus(k);
              const statusMeta = STATUS_META[status];
              const lastUsed = formatLastUsed(k.last_used_at);
              const isTerminal = status === "expired" || status === "revoked";
              const isExpanded = usageKeyId === k.id;
              return (
                <div key={k.id}>
                  <div
                    className={`flex items-center gap-4 px-4 py-3 rounded-lg bg-white/[0.02] border border-white/[0.04] ${isTerminal ? "opacity-60" : ""} ${isExpanded ? "rounded-b-none" : ""}`}
                  >
                    <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-red-500 to-orange-500 flex items-center justify-center shrink-0">
                      <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="text-sm font-medium text-slate-200">{k.name}</p>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border ${statusMeta.classes}`}>{statusMeta.label}</span>
                        <code className="text-[10px] text-slate-500 font-mono">{k.key_prefix}...</code>
                        {/* Rotation linkage — points operators to the
                            successor so they know which key to update
                            in CI before this row's grace window ends. */}
                        {status === "rotating" && k.rotated_to_id && (
                          <span className="text-[10px] text-blue-300/80">
                            → {keyNameById[k.rotated_to_id] || k.rotated_to_id.slice(0, 8)}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-3 mt-1 flex-wrap">
                        <div className="flex gap-1">
                          {(k.scopes || []).map((s: string) => (
                            <span key={s} className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">{s}</span>
                          ))}
                        </div>
                        {/* During rotation grace, surface the cutover
                            deadline distinctly — "Cutover in 4d" reads
                            differently from a regular "Expires" line. */}
                        {status === "rotating" && k.rotation_grace_until && (
                          <span className="text-[10px] text-blue-300/80">
                            Cutover {new Date(k.rotation_grace_until).toLocaleDateString()}
                          </span>
                        )}
                        {status !== "rotating" && k.expires_at && (
                          <span className="text-[10px] text-slate-500">Expires {new Date(k.expires_at).toLocaleDateString()}</span>
                        )}
                        {!k.expires_at && <span className="text-[10px] text-slate-600">No expiry</span>}
                        {/* IP-allowlist indicator — surfaces at-a-glance
                            which keys have a source-network restriction
                            so an operator can spot an unrestricted
                            "everywhere" key without opening the editor. */}
                        {k.allowed_ip_cidrs && k.allowed_ip_cidrs.length > 0 && (
                          <span
                            className="text-[10px] text-emerald-300/80 inline-flex items-center gap-0.5"
                            title={`IP allowlist:\n${k.allowed_ip_cidrs.join("\n")}`}
                          >
                            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
                            {k.allowed_ip_cidrs.length === 1
                              ? "1 IP rule"
                              : `${k.allowed_ip_cidrs.length} IP rules`}
                          </span>
                        )}
                        {/* Last used — relative time; mutes when very old
                            so a stale key visually stands out from active
                            rotation.  "Never used" in muted red flags an
                            unused credential that could leak unnoticed. */}
                        <span className={`text-[10px] ${lastUsed.muted ? "text-slate-600" : "text-slate-400"}`}>
                          · {lastUsed.text === "Never used" ? <span className="text-amber-400/80">Never used</span> : `Last used ${lastUsed.text}`}
                        </span>
                        <button
                          onClick={() => toggleUsage(k.id)}
                          className="text-[10px] text-slate-500 hover:text-slate-300 underline-offset-2 hover:underline"
                        >
                          {isExpanded ? "Hide usage ↑" : "View usage ↓"}
                        </button>
                      </div>
                    </div>
                    <div className="text-right shrink-0 flex flex-col gap-1 items-end">
                      <p className="text-[10px] text-slate-500">Created {new Date(k.created_at).toLocaleDateString()}</p>
                      <div className="flex gap-2">
                        {/* Edit — name + IP allowlist only.  Hidden
                            on terminal-state rows since there's no
                            useful change to make on an expired/revoked
                            key (rotation grace counts as active). */}
                        {(status === "active" || status === "rotating") && (
                          <button
                            onClick={() => openEdit(k)}
                            className="text-[10px] text-slate-400 hover:text-slate-200"
                            title="Edit name or IP allowlist."
                          >
                            Edit
                          </button>
                        )}
                        {/* Rotate is only meaningful on an "active" key.
                            Hide on rotating/expired/revoked rows where
                            the action would be a no-op or a 409. */}
                        {status === "active" && (
                          <button
                            onClick={() => { setConfirmRotate(k); setRotateGraceDays(7); }}
                            className="text-[10px] text-blue-400/70 hover:text-blue-300"
                            title="Issue a successor key with a grace window — zero-downtime cutover for CI."
                          >
                            Rotate
                          </button>
                        )}
                        {(status === "active" || status === "rotating") && (
                          <button onClick={() => setConfirmRevoke(k)} className="text-[10px] text-red-400/60 hover:text-red-400">Revoke</button>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Usage drawer — sparkline + leaderboards.  Renders
                      inline so the operator's context isn't lost.  The
                      shape matches /api-keys/{id}/usage exactly so a
                      SIEM operator looking at this view can map fields
                      1:1 to the payload they'd pull programmatically. */}
                  {isExpanded && (
                    <div className="px-4 py-3 rounded-b-lg border border-t-0 border-white/[0.04] bg-white/[0.01]">
                      {usageLoading && (
                        <div className="text-xs text-slate-500">Loading usage…</div>
                      )}
                      {usageData?.error && (
                        <div className="text-xs text-red-400">{usageData.error}</div>
                      )}
                      {usageData && !usageData.error && (
                        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs">
                          <div>
                            <p className="text-[10px] text-slate-500 uppercase tracking-wider">Calls (7d)</p>
                            <p className="text-2xl font-semibold text-slate-200">{usageData.total_calls.toLocaleString()}</p>
                            <p className="text-[10px] text-slate-600 mt-0.5">
                              {usageData.first_call_at && `since ${new Date(usageData.first_call_at).toLocaleDateString()}`}
                              {!usageData.first_call_at && "no activity"}
                            </p>
                          </div>
                          <div>
                            <p className="text-[10px] text-slate-500 uppercase tracking-wider">Unique IPs</p>
                            <p className="text-2xl font-semibold text-slate-200">{usageData.unique_ips}</p>
                            <p className="text-[10px] text-slate-600 mt-0.5">{usageData.unique_endpoints} endpoints</p>
                          </div>
                          <div className="md:col-span-1">
                            <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Top endpoints</p>
                            {usageData.top_endpoints.slice(0, 3).map((ep: any, i: number) => (
                              <div key={i} className="flex justify-between gap-2 text-[11px]">
                                <code className="text-slate-400 truncate font-mono">{ep.endpoint}</code>
                                <span className="text-slate-500 shrink-0">{ep.count}</span>
                              </div>
                            ))}
                            {usageData.top_endpoints.length === 0 && <p className="text-[10px] text-slate-600">none</p>}
                          </div>
                          <div className="md:col-span-1">
                            <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Top IPs</p>
                            {usageData.top_ips.slice(0, 3).map((ip: any, i: number) => (
                              <div key={i} className="flex justify-between gap-2 text-[11px]">
                                <code className="text-slate-400 truncate font-mono">{ip.ip}</code>
                                <span className="text-slate-500 shrink-0">{ip.count}</span>
                              </div>
                            ))}
                            {usageData.top_ips.length === 0 && <p className="text-[10px] text-slate-600">none</p>}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Revoke confirm */}
      {confirmRevoke && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="card max-w-sm mx-auto">
            <h4 className="text-sm font-semibold text-white mb-2">Revoke API Key?</h4>
            <p className="text-xs text-slate-400 mb-1">This will permanently disable &quot;{confirmRevoke.name}&quot;.</p>
            <p className="text-xs text-red-400/80 mb-4">Any CI/CD pipelines using this key will stop working.</p>
            <div className="flex gap-3">
              <button onClick={handleRevoke} className="bg-red-500/20 text-red-400 border border-red-500/30 text-xs px-4 py-2 rounded-lg hover:bg-red-500/30">Revoke Key</button>
              <button onClick={() => setConfirmRevoke(null)} className="btn-secondary text-xs">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Edit modal (Sprint 3) — name + IP allowlist.  Scope changes
          intentionally not offered here; they're better expressed as
          "issue a new key" because they change the blast radius. */}
      {editing && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="card max-w-md mx-auto w-full">
            <h4 className="text-sm font-semibold text-white mb-3">Edit API Key</h4>
            <div className="mb-3">
              <label className="text-xs text-slate-500 mb-1.5 block">Name</label>
              <input
                value={editForm.name}
                onChange={(e) => setEditForm(f => ({ ...f, name: e.target.value }))}
                className="input-dark w-full"
              />
            </div>
            <div className="mb-3">
              <label className="text-xs text-slate-500 mb-1.5 block">
                IP allowlist <span className="text-slate-600">(one CIDR per line)</span>
              </label>
              <textarea
                value={editForm.allowed_ip_cidrs}
                onChange={(e) => setEditForm(f => ({ ...f, allowed_ip_cidrs: e.target.value }))}
                placeholder="Leave empty to remove restriction.&#10;e.g. 203.0.113.0/24"
                rows={4}
                className="input-dark font-mono text-xs w-full resize-y"
              />
              <p className="text-[10px] text-slate-600 mt-1.5">
                Empty = unrestricted. Both IPv4 + IPv6. Server canonicalizes (e.g.
                <code className="mx-1 text-slate-400">192.168.1.5/24</code> → <code className="text-slate-400">192.168.1.0/24</code>).
              </p>
            </div>
            {editError && (
              <p className="text-xs text-red-400 mb-3">{editError}</p>
            )}
            <div className="flex gap-3">
              <button
                onClick={handleEdit}
                disabled={editSaving || !editForm.name.trim()}
                className="btn-primary text-xs px-4 py-2 disabled:opacity-50"
              >
                {editSaving ? "Saving…" : "Save"}
              </button>
              <button
                onClick={() => { setEditing(null); setEditError(null); }}
                className="btn-secondary text-xs"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Rotate confirm — non-destructive cousin of revoke.  Operator
          chooses the grace window during which BOTH keys are valid;
          enterprise CI/CD typically wants 7 days to redeploy. */}
      {confirmRotate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="card max-w-md mx-auto">
            <h4 className="text-sm font-semibold text-white mb-2">Rotate API Key?</h4>
            <p className="text-xs text-slate-400 mb-3">
              A brand-new key will be issued, shown <strong>once</strong>.
              The current key &quot;{confirmRotate.name}&quot; will keep working for the grace period below — long enough for CI to redeploy with the new key — then auto-expire.
            </p>
            <div className="mb-3">
              <label className="text-[10px] text-slate-500 uppercase tracking-wider mb-1.5 block">Grace period (days)</label>
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min={0}
                  max={30}
                  value={rotateGraceDays}
                  onChange={(e) => setRotateGraceDays(Math.max(0, Math.min(30, Number(e.target.value) || 0)))}
                  className="input-dark w-24"
                />
                <span className="text-[11px] text-slate-500">
                  {rotateGraceDays === 0
                    ? "Immediate cutover — old key revoked NOW (no grace)."
                    : `Old key expires on ${new Date(Date.now() + rotateGraceDays * 86400000).toLocaleDateString()}.`}
                </span>
              </div>
              <p className="text-[10px] text-slate-600 mt-1.5">0–30 days. Default 7 covers most CI redeploy windows.</p>
            </div>
            <div className="flex gap-3">
              <button
                onClick={handleRotate}
                disabled={rotating}
                className="bg-blue-500/20 text-blue-300 border border-blue-500/30 text-xs px-4 py-2 rounded-lg hover:bg-blue-500/30 disabled:opacity-50"
              >
                {rotating ? "Rotating…" : "Issue New Key"}
              </button>
              <button onClick={() => { setConfirmRotate(null); setRotateGraceDays(7); }} className="btn-secondary text-xs">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Integration Examples — static reference section.  The
          per-key snippets in the show-once banner are pre-filled with
          a real key; THIS section uses the $VOODA_API_KEY env-var form
          so operators returning to the page later still see usable
          examples without exposing a key. */}
      <div className="card bg-white/[0.01]">
        <h4 className="text-sm font-semibold text-slate-300 mb-3">Integration Examples</h4>
        <p className="text-[11px] text-slate-500 mb-3">
          Generate a new key above to get full pre-filled snippets for cURL, GitHub Actions,
          GitLab CI, Python, Node.js, and Go. The blocks below use{" "}
          <code className="text-slate-400">$VOODA_API_KEY</code> for ongoing reference.
        </p>
        <div className="space-y-3 text-xs text-slate-500">
          <div className="bg-[#0d1117] rounded-lg p-4 font-mono text-slate-400 whitespace-pre overflow-x-auto">
{`# Smoke test (any platform)
curl -sS \${VOODA_BASE_URL}/auth/me \\
  -H "Authorization: Bearer $VOODA_API_KEY"`}
          </div>
          <div className="bg-[#0d1117] rounded-lg p-4 font-mono text-slate-400 whitespace-pre overflow-x-auto">
{`# GitHub Actions
- name: Vooda Secret Scan
  env:
    VOODA_API_KEY: \${{ secrets.VOODA_API_KEY }}
  run: |
    curl -fsS -X POST \${{ vars.VOODA_BASE_URL }}/repositories/\${{ vars.VOODA_REPO_ID }}/scan \\
      -H "Authorization: Bearer $VOODA_API_KEY" \\
      -H "Content-Type: application/json" \\
      -d '{"scan_type":"standalone"}'`}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════
   RETENTION & COMPLIANCE SETTINGS (persisted in localStorage)
   ═══════════════════════════════════════════════════════ */
const COMPLIANCE_DEFAULTS: Record<string, boolean> = {
  "SOC 2 Type II": true, "ISO 27001": true, "NIST CSF": false,
  "PCI DSS": false, "HIPAA": false, "GDPR": true,
};

function RetentionAndCompliance() {
  const [auditRetention, setAuditRetention] = useState("365");
  const [findingRetention, setFindingRetention] = useState("1095");
  const [frameworks, setFrameworks] = useState<Record<string, boolean>>(COMPLIANCE_DEFAULTS);
  const [saved, setSaved] = useState(false);

  // Load from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem("vooda_compliance_settings");
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.auditRetention) setAuditRetention(parsed.auditRetention);
        if (parsed.findingRetention) setFindingRetention(parsed.findingRetention);
        if (parsed.frameworks) setFrameworks(parsed.frameworks);
      }
    } catch {}
  }, []);

  const save = (ar: string, fr: string, fw: Record<string, boolean>) => {
    localStorage.setItem("vooda_compliance_settings", JSON.stringify({
      auditRetention: ar, findingRetention: fr, frameworks: fw,
    }));
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleAuditChange = (v: string) => { setAuditRetention(v); save(v, findingRetention, frameworks); };
  const handleFindingChange = (v: string) => { setFindingRetention(v); save(auditRetention, v, frameworks); };
  const toggleFramework = (name: string) => {
    const updated = { ...frameworks, [name]: !frameworks[name] };
    setFrameworks(updated);
    save(auditRetention, findingRetention, updated);
  };

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-sm font-semibold text-slate-300">Log Retention</h4>
          {saved && <span className="text-[10px] text-green-400">Saved</span>}
        </div>
        <FieldGroup label="Audit Log Retention" description="How long to keep audit logs">
          <select value={auditRetention} onChange={(e) => handleAuditChange(e.target.value)} className="select-dark w-full">
            <option value="90">90 days</option>
            <option value="180">180 days</option>
            <option value="365">1 year</option>
            <option value="730">2 years</option>
            <option value="1095">3 years</option>
            <option value="0">Indefinite</option>
          </select>
        </FieldGroup>
        <FieldGroup label="Finding History" description="Retain historical finding data">
          <select value={findingRetention} onChange={(e) => handleFindingChange(e.target.value)} className="select-dark w-full">
            <option value="365">1 year</option>
            <option value="730">2 years</option>
            <option value="1095">3 years</option>
            <option value="1825">5 years</option>
            <option value="0">Indefinite</option>
          </select>
        </FieldGroup>
        {auditRetention !== "0" && (
          <button onClick={async () => {
            if (!confirm(`Permanently delete all audit events older than ${auditRetention} days?`)) return;
            try {
              const r = await enforceRetention(Number(auditRetention));
              alert(`Purged ${r.data.purged} events older than ${auditRetention} days.`);
            } catch { alert("Failed to enforce retention."); }
          }} className="btn-secondary text-xs mt-3">Enforce Retention Now</button>
        )}
      </div>
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-sm font-semibold text-slate-300">Compliance Frameworks</h4>
          {saved && <span className="text-[10px] text-green-400">Saved</span>}
        </div>
        <div className="space-y-2">
          {Object.entries(frameworks).map(([name, enabled]) => (
            <button key={name} type="button" onClick={() => toggleFramework(name)}
              className="flex items-center justify-between w-full p-2.5 rounded-lg bg-white/[0.02] border border-white/[0.04] hover:bg-white/[0.04] transition-colors text-left"
            >
              <span className="text-sm text-slate-300">{name}</span>
              <div className={`w-9 h-5 rounded-full transition-colors ${enabled ? "bg-red-500" : "bg-slate-600"} relative`}>
                <div className={`w-4 h-4 rounded-full bg-white absolute top-0.5 transition-transform ${enabled ? "left-[18px]" : "left-0.5"}`} />
              </div>
            </button>
          ))}
        </div>
        <div className="mt-4 pt-3 border-t border-white/[0.06]">
          <a href="/reports" className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1.5">
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
            View Compliance Reports (OWASP, PCI DSS)
          </a>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════
   AUDIT & COMPLIANCE SECTION
   ═══════════════════════════════════════════════════════ */
function AuditSection() {
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);
  const [filterAction, setFilterAction] = useState("");
  const [filterResource, setFilterResource] = useState("");
  const [filterSearch, setFilterSearch] = useState("");
  const [filterDays, setFilterDays] = useState("");

  const PAGE_SIZE = 20;

  const loadEvents = useCallback(async (pageNum: number, reset = false) => {
    setLoading(true);
    try {
      const params: Record<string, string> = { page: String(pageNum), page_size: String(PAGE_SIZE) };
      if (filterAction) params.action = filterAction;
      if (filterResource) params.resource_type = filterResource;
      if (filterSearch) params.search = filterSearch;
      if (filterDays) params.days = filterDays;
      const r = await getAuditEvents(params);
      const newEvents = r.data || [];
      setEvents(prev => reset ? newEvents : [...prev, ...newEvents]);
      setHasMore(newEvents.length === PAGE_SIZE);
    } finally { setLoading(false); }
  }, [filterAction, filterResource, filterSearch, filterDays]);

  useEffect(() => { setPage(1); loadEvents(1, true); }, [filterAction, filterResource, filterSearch, filterDays, loadEvents]);

  const loadMore = () => { const next = page + 1; setPage(next); loadEvents(next); };

  const ACTION_COLORS: Record<string, string> = {
    login_success: "text-green-400", login_failed: "text-red-400", login_blocked: "text-red-400",
    user_created: "text-green-400", user_updated: "text-blue-400", user_deactivated: "text-yellow-400", user_activated: "text-green-400",
    finding_triaged: "text-purple-400", remediation_requested: "text-orange-400", patch_approved: "text-green-400", patch_rejected: "text-red-400",
    finding_assigned: "text-red-400", batch_remediation: "text-orange-400",
    scan_started: "text-red-400", scan_completed: "text-green-400", scan_cancelled: "text-yellow-400",
    repo_created: "text-green-400", repo_deleted: "text-red-400",
    bu_created: "text-amber-400", bu_updated: "text-blue-400", bu_deleted: "text-red-400",
    grant_created: "text-green-400", grant_revoked: "text-red-400",
    api_key_created: "text-green-400", api_key_revoked: "text-red-400",
    role_created: "text-green-400", role_updated: "text-blue-400", role_deleted: "text-red-400", role_reset: "text-yellow-400",
    import_completed: "text-red-400",
  };

  const RESOURCE_ICONS: Record<string, string> = {
    user: "\u{1F464}", finding: "\u{1F50D}", scan_job: "\u{1F504}", repository: "\u{1F4C2}",
    business_unit: "\u{1F3D7}\u{FE0F}", access_grant: "\u{1F511}", api_key: "\u{1F510}", role: "\u{1F6E1}\u{FE0F}", import: "\u{1F4E5}", policy: "\u{1F4CB}", auth: "\u{1F512}", integration: "\u{1F517}",
  };

  const ACTIONS = ["login_success","login_failed","login_blocked","user_created","user_updated","user_deactivated","user_activated","finding_triaged","remediation_requested","patch_approved","batch_remediation","finding_assigned","comment_added","tags_updated","scan_started","scan_cancelled","repo_created","repo_updated","repo_archived","repo_uploaded","repo_deleted","integration_created","integration_deleted","notification_rules_updated","grant_created","grant_revoked","api_key_created","api_key_revoked","role_created","role_updated","role_deleted","role_reset","bu_created","bu_updated","bu_deleted","import_completed"];
  const RESOURCES = ["auth","user","finding","scan_job","repository","business_unit","access_grant","api_key","role","import","policy","integration","notification_rule"];

  const timeAgo = (ts: string) => {
    const diff = Date.now() - new Date(ts).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
  };

  return (
    <div className="space-y-6">
      <SectionHeader title="Audit & Compliance" description="Activity log, compliance frameworks, and data retention." />

      {/* Audit Log */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-base font-semibold text-white">Audit Log</h3>
          <button onClick={async () => {
            try {
              const params: Record<string, string> = {};
              if (filterAction) params.action = filterAction;
              if (filterResource) params.resource_type = filterResource;
              if (filterSearch) params.search = filterSearch;
              if (filterDays) params.days = filterDays;
              const r = await exportAuditCSV(params);
              const url = window.URL.createObjectURL(new Blob([r.data]));
              const a = document.createElement("a"); a.href = url; a.download = `vooda_audit_log.csv`; a.click();
              window.URL.revokeObjectURL(url);
            } catch {}
          }} className="btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5">
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
            Export CSV
          </button>
        </div>
        <div className="flex flex-wrap gap-2 mb-3">
          <div className="flex items-center gap-2 flex-1 min-w-[200px] max-w-sm px-3 py-1.5 rounded-lg border border-white/[0.08] bg-white/[0.02]">
            <svg className="w-3.5 h-3.5 text-slate-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
            <input value={filterSearch} onChange={(e) => setFilterSearch(e.target.value)} placeholder="Search events..." className="flex-1 bg-transparent text-xs text-slate-200 placeholder-slate-500 outline-none" />
            {filterSearch && <button onClick={() => setFilterSearch("")} className="text-slate-500 hover:text-slate-300"><svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg></button>}
          </div>
          <select value={filterDays} onChange={(e) => setFilterDays(e.target.value)} className="select-dark text-xs w-32">
            <option value="">All Time</option>
            <option value="1">Last 24h</option>
            <option value="7">Last 7 days</option>
            <option value="30">Last 30 days</option>
            <option value="90">Last 90 days</option>
          </select>
          <select value={filterAction} onChange={(e) => setFilterAction(e.target.value)} className="select-dark text-xs w-36">
            <option value="">All Actions</option>
            {ACTIONS.map(a => <option key={a} value={a}>{a.replace(/_/g, " ")}</option>)}
          </select>
          <select value={filterResource} onChange={(e) => setFilterResource(e.target.value)} className="select-dark text-xs w-36">
            <option value="">All Resources</option>
            {RESOURCES.map(r => <option key={r} value={r}>{r.replace(/_/g, " ")}</option>)}
          </select>
        </div>

        <div className="card p-0 overflow-hidden">
          {loading && events.length === 0 ? (
            <div className="flex justify-center py-10"><div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" /></div>
          ) : events.length === 0 ? (
            <div className="text-center py-10">
              <p className="text-sm text-slate-500">No audit events found</p>
              <p className="text-xs text-slate-600 mt-1">Events will appear here as users perform actions</p>
            </div>
          ) : (
            <div className="divide-y divide-white/[0.04] overflow-y-auto" style={{ maxHeight: "16rem" }}>
              {events.map((e: any) => (
                <div key={e.id} className="flex items-start gap-3 px-4 py-3 hover:bg-white/[0.02]">
                  <div className="w-8 h-8 rounded-lg bg-white/[0.04] flex items-center justify-center text-sm shrink-0 mt-0.5">
                    {RESOURCE_ICONS[e.resource_type] || "\u{1F4CB}"}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-medium text-slate-300">{e.user_name || "System"}</span>
                      <span className={`text-xs font-medium ${ACTION_COLORS[e.action] || "text-slate-400"}`}>{e.action.replace(/_/g, " ")}</span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/[0.04] text-slate-500">{e.resource_type.replace(/_/g, " ")}</span>
                    </div>
                    {e.detail && <p className="text-xs text-slate-500 mt-0.5 truncate">{e.detail}</p>}
                  </div>
                  <div className="text-right shrink-0 mt-1">
                    <span className="text-[10px] text-slate-600">{timeAgo(e.created_at)}</span>
                    {e.ip_address && <p className="text-[9px] text-slate-700 font-mono">{e.ip_address}</p>}
                  </div>
                </div>
              ))}
            </div>
          )}
          {hasMore && events.length > 0 && (
            <div className="px-4 py-3 border-t border-white/[0.06] text-center">
              <button onClick={loadMore} disabled={loading} className="text-xs text-red-400 hover:text-red-300">
                {loading ? "Loading..." : "Load more"}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Retention & Compliance — persisted in localStorage */}
      <RetentionAndCompliance />

      {/* Audit Log Streaming — replaces the old Integrations → SIEM
          tile (removed 2026-05-19).  Backend storage is shared
          (`integrations` table with integration_type="siem"), so
          configs created under the old surface keep working. */}
      <AuditLogStreaming />
    </div>
  );
}

/* ═══════════════════════════════════════════════════════
   REPORTS & EXPORTS SECTION
   ═══════════════════════════════════════════════════════ */
// Governance + Quantum Safety report tiles removed 2026-05-16 along with the
// governance surfaces (their backend endpoints no longer exist).
const REPORT_TYPES: { key: string; title: string; description: string; icon: string; color: string }[] = [
  { key: "executive", title: "Executive Summary", description: "High-level security posture overview with grade, score, and key metrics for leadership", icon: "M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z", color: "violet" },
  { key: "secrets_inventory", title: "Secrets Inventory", description: "Complete inventory of detected secrets, credentials, and tokens across all repositories", icon: "M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z", color: "amber" },
  { key: "compliance", title: "Compliance Report", description: "Framework-aligned compliance status including SOC2, ISO 27001, PCI DSS mappings", icon: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z", color: "blue" },
  { key: "aging", title: "Aging Report", description: "Secret rotation SLA tracking, overdue credentials, and time-to-remediation analysis", icon: "M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z", color: "orange" },
];

const EXPORT_FORMAT_OPTIONS = [
  { key: "csv", label: "CSV" },
  { key: "json", label: "JSON" },
  { key: "pdf", label: "PDF" },
  { key: "sarif", label: "SARIF" },
];

function ReportsSection() {
  const [repos, setRepos] = useState<any[]>([]);
  const [selectedRepo, setSelectedRepo] = useState("");
  const [generating, setGenerating] = useState<string | null>(null);
  const [formats, setFormats] = useState<Record<string, string>>(
    Object.fromEntries(REPORT_TYPES.map(r => [r.key, "pdf"]))
  );

  useEffect(() => {
    getRepositories({ page_size: 200 }).then(r => {
      const d = r.data;
      setRepos(d?.items ?? (Array.isArray(d) ? d : []));
    }).catch(() => {});
  }, []);

  const handleGenerate = async (reportKey: string) => {
    const format = formats[reportKey] || "pdf";
    setGenerating(reportKey);
    try {
      const token = localStorage.getItem("vooda_token");
      const apiBase = typeof window !== "undefined" ? (window.location.port === "3000" ? "http://localhost:8000" : "") : "";
      const params = new URLSearchParams({ report_type: reportKey, days: "30" });
      if (selectedRepo) params.set("repository_id", selectedRepo);
      const response = await fetch(`${apiBase}/api/v1/reports/export/${format}?${params}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        if (errorData?.error) { alert(errorData.error); return; }
        alert(`Export failed: ${response.status}`);
        return;
      }

      const disposition = response.headers.get("content-disposition");
      const filenameMatch = disposition?.match(/filename=(.+)/);
      const filename = filenameMatch ? filenameMatch[1] : `vooda-${reportKey}-report.${format === "sarif" ? "sarif" : format}`;

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      alert("Export failed. Check your connection.");
    } finally {
      setGenerating(null);
    }
  };

  const colorMap: Record<string, { bg: string; text: string; border: string }> = {
    cyan:    { bg: "bg-red-500/10",  text: "text-red-400",  border: "border-red-500/20" },
    amber:   { bg: "bg-amber-500/10",   text: "text-amber-400",   border: "border-amber-500/20" },
    emerald: { bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/20" },
    blue:    { bg: "bg-blue-500/10",    text: "text-blue-400",    border: "border-blue-500/20" },
    orange:  { bg: "bg-orange-500/10",  text: "text-orange-400",  border: "border-orange-500/20" },
    violet:  { bg: "bg-red-500/10",  text: "text-red-400",  border: "border-red-500/20" },
  };

  return (
    <div>
      <SectionHeader title="Reports & Exports" description="Generate and download security reports in multiple formats. Use these for compliance audits, executive briefings, and security reviews." />

      {/* Repository filter */}
      <div className="mb-6 flex items-center gap-3">
        <label className="text-sm font-medium text-slate-400">Filter by Repository</label>
        <select
          className="select-dark w-64"
          value={selectedRepo}
          onChange={e => setSelectedRepo(e.target.value)}
        >
          <option value="">All Repositories</option>
          {repos.map(r => (
            <option key={r.id} value={r.id}>{r.name}</option>
          ))}
        </select>
      </div>

      {/* Report cards grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {REPORT_TYPES.map(rt => {
          const c = colorMap[rt.color] || colorMap.cyan;
          return (
            <div key={rt.key} className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-5 flex flex-col gap-4">
              <div className="flex items-start gap-3">
                <div className={`w-10 h-10 rounded-lg ${c.bg} flex items-center justify-center shrink-0`}>
                  <svg className={`w-5 h-5 ${c.text}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d={rt.icon} />
                  </svg>
                </div>
                <div className="flex-1 min-w-0">
                  <h4 className="text-sm font-semibold text-white">{rt.title}</h4>
                  <p className="text-xs text-slate-500 mt-1 leading-relaxed">{rt.description}</p>
                </div>
              </div>
              <div className="flex items-center gap-2 mt-auto">
                <select
                  className="select-dark text-xs h-8 w-24"
                  value={formats[rt.key]}
                  onChange={e => setFormats(prev => ({ ...prev, [rt.key]: e.target.value }))}
                >
                  {EXPORT_FORMAT_OPTIONS.map(f => (
                    <option key={f.key} value={f.key}>{f.label}</option>
                  ))}
                </select>
                <button
                  onClick={() => handleGenerate(rt.key)}
                  disabled={generating === rt.key}
                  className={`btn-primary text-xs h-8 px-4 flex items-center gap-2 ${generating === rt.key ? "opacity-50 cursor-not-allowed" : ""}`}
                >
                  {generating === rt.key ? (
                    <>
                      <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      Generating...
                    </>
                  ) : (
                    <>
                      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                      </svg>
                      Generate
                    </>
                  )}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Link to full reports page */}
      <div className="mt-6 p-4 bg-white/[0.02] border border-white/[0.06] rounded-xl flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-slate-300">Need detailed analytics?</p>
          <p className="text-xs text-slate-500 mt-0.5">View interactive dashboards with charts and trends on the full Reports page.</p>
        </div>
        <a href="/reports" className="btn-primary text-xs h-8 px-4 flex items-center gap-2 shrink-0">
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
          </svg>
          Open Reports
        </a>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════
   ORGANIZATION SECTION
   ═══════════════════════════════════════════════════════ */
function OrganizationSection() {
  const { user } = useAuthStore();
  return (
    <div>
      <SectionHeader title="Organization" description="Manage your organization profile, branding, and data policies." />
      <div className="card">
        <div className="space-y-0">
          <FieldGroup label="Organization Name" description="Displayed across the platform">
            <input defaultValue="Default Org" className="input-dark" />
          </FieldGroup>
          <FieldGroup label="Slug" description="Used in URLs and API calls">
            <input defaultValue="default" className="input-dark font-mono" />
          </FieldGroup>
          <FieldGroup label="Primary Contact">
            <input defaultValue={user?.email || ""} className="input-dark" />
          </FieldGroup>
          <FieldGroup label="Data Region" description="Where your data is stored">
            <select className="select-dark w-full">
              <option>US East (Virginia)</option>
              <option>EU West (Ireland)</option>
              <option>AP Southeast (Singapore)</option>
            </select>
          </FieldGroup>
          <FieldGroup label="Data Retention Policy" description="Auto-delete scan artifacts after">
            <select className="select-dark w-full" defaultValue="90 days">
              <option>30 days</option>
              <option>90 days</option>
              <option>180 days</option>
              <option>1 year</option>
              <option>Never delete</option>
            </select>
          </FieldGroup>
        </div>
        <div className="pt-4 mt-2">
          <button className="btn-primary text-sm">Save Changes</button>
        </div>
      </div>

      {/* About & Open Source Attribution */}
      <div className="mt-6">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">About Vooda AI</h3>
        <div className="card space-y-5">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-red-500 to-orange-600 flex items-center justify-center shrink-0">
              <svg className="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div>
              <h4 className="text-base font-bold text-white">Vooda AI Security Engine</h4>
              <p className="text-sm text-slate-400">Version 0.1.0</p>
            </div>
          </div>

          <div>
            <p className="text-sm text-slate-400 leading-relaxed">
              Vooda AI is a self-hosted secret scanner. It finds leaked credentials across your code and
              connected sources, verifies whether each one is still live, and runs an AI triage pass to cut
              false positives — then generates secure fixes automatically.
            </p>
          </div>

          <div className="pt-4 border-t border-white/[0.06]">
            <h5 className="text-sm font-semibold text-slate-300 mb-3">Platform Components</h5>
            <div className="space-y-2">
              <div className="flex items-start gap-3 p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
                <div className="w-8 h-8 rounded-lg bg-red-500/10 flex items-center justify-center shrink-0 mt-0.5">
                  <svg className="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-medium text-slate-200">Vooda AI Detection Engine</p>
                  <p className="text-xs text-slate-500 mt-0.5">Detection rules and regex with entropy analysis and live credential verification</p>
                </div>
                <span className="text-xs px-2 py-0.5 rounded-full bg-red-500/10 text-red-400 border border-red-500/20 shrink-0">Source-available</span>
              </div>
              <div className="flex items-start gap-3 p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
                <div className="w-8 h-8 rounded-lg bg-purple-500/10 flex items-center justify-center shrink-0 mt-0.5">
                  <svg className="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-medium text-slate-200">Vooda AI Triage Engine</p>
                  <p className="text-xs text-slate-500 mt-0.5">AI-powered false positive reduction with evidence-grounded classification</p>
                </div>
                <span className="text-xs px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/20 shrink-0">Source-available</span>
              </div>
              <div className="flex items-start gap-3 p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
                <div className="w-8 h-8 rounded-lg bg-green-500/10 flex items-center justify-center shrink-0 mt-0.5">
                  <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-medium text-slate-200">Vooda AI Remediation Engine</p>
                  <p className="text-xs text-slate-500 mt-0.5">Automatic secure code patch generation with validation and PR delivery</p>
                </div>
                <span className="text-xs px-2 py-0.5 rounded-full bg-green-500/10 text-green-400 border border-green-500/20 shrink-0">Source-available</span>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════
   ACCESS CONTROL SECTION
   ═══════════════════════════════════════════════════════ */
function AccessControlSection() {
  const [bus, setBus] = useState<any[]>([]);
  const [grants, setGrants] = useState<any[]>([]);
  const [users, setUsers] = useState<any[]>([]);
  const [repos, setRepos] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  // BU form
  const [showBUForm, setShowBUForm] = useState(false);
  const [editingBU, setEditingBU] = useState<any>(null);
  const [buForm, setBuForm] = useState({ name: "", description: "" });
  const [buSaving, setBuSaving] = useState(false);

  // Grant form
  const [showGrantForm, setShowGrantForm] = useState(false);
  const [grantForm, setGrantForm] = useState({ access_level: "organization", role: "member" });
  const [grantUserIds, setGrantUserIds] = useState<string[]>([]);
  const [grantBUs, setGrantBUs] = useState<string[]>([]);
  const [grantProjects, setGrantProjects] = useState<string[]>([]);
  const [grantSaving, setGrantSaving] = useState(false);

  const [confirmDeleteBU, setConfirmDeleteBU] = useState<any>(null);

  const loadAll = useCallback(async () => {
    try {
      const [buR, grantR, userR, repoR] = await Promise.all([
        getBusinessUnits().catch(() => ({ data: [] })),
        getAccessGrants().catch(() => ({ data: [] })),
        getUsers().catch(() => ({ data: [] })),
        getRepositories({ page_size: 200 }).catch(() => ({ data: [] })),
      ]);
      setBus(buR.data || []);
      setGrants(grantR.data || []);
      setUsers(userR.data || []);
      const rd2 = repoR.data;
      setRepos(rd2?.items ?? (Array.isArray(rd2) ? rd2 : []));
    } finally { setLoading(false); }
  }, []);
  useEffect(() => { loadAll(); }, [loadAll]);

  // ── BU handlers ──
  const resetBUForm = () => { setBuForm({ name: "", description: "" }); setEditingBU(null); setShowBUForm(false); };
  const openEditBU = (bu: any) => { setBuForm({ name: bu.name, description: bu.description || "" }); setEditingBU(bu); setShowBUForm(true); };
  const handleSaveBU = async () => {
    setBuSaving(true);
    try {
      if (editingBU) { await updateBusinessUnit(editingBU.id, buForm); }
      else { await createBusinessUnit(buForm); }
      resetBUForm(); loadAll();
    } finally { setBuSaving(false); }
  };
  const handleDeleteBU = async () => {
    if (!confirmDeleteBU) return;
    await deleteBusinessUnit(confirmDeleteBU.id).catch(() => {});
    setConfirmDeleteBU(null); loadAll();
  };

  // ── Grant handlers ──
  const resetGrantForm = () => { setGrantForm({ access_level: "organization", role: "member" }); setGrantUserIds([]); setGrantBUs([]); setGrantProjects([]); setShowGrantForm(false); };
  const handleSaveGrant = async () => {
    setGrantSaving(true);
    try {
      // Create grants for every selected user × every selected scope
      for (const userId of grantUserIds) {
        if (grantForm.access_level === "organization") {
          await createAccessGrant({ user_id: userId, access_level: "organization", role: grantForm.role });
        } else if (grantForm.access_level === "business_unit") {
          for (const buId of grantBUs) {
            await createAccessGrant({ user_id: userId, access_level: "business_unit", role: grantForm.role, business_unit_id: buId });
          }
        } else if (grantForm.access_level === "project") {
          for (const repoId of grantProjects) {
            await createAccessGrant({ user_id: userId, access_level: "project", role: grantForm.role, repository_id: repoId });
          }
        }
      }
      resetGrantForm(); loadAll();
    } finally { setGrantSaving(false); }
  };
  const handleDeleteGrant = async (id: string) => {
    await deleteAccessGrant(id).catch(() => {});
    loadAll();
  };

  const LEVEL_COLORS: Record<string, string> = {
    organization: "bg-purple-500/15 text-purple-400 border-purple-500/20",
    business_unit: "bg-amber-500/15 text-amber-400 border-amber-500/20",
    project: "bg-red-500/15 text-red-400 border-red-500/20",
  };
  const LEVEL_ICONS: Record<string, string> = { organization: "\u{1F3E2}", business_unit: "\u{1F3D7}\u{FE0F}", project: "\u{1F4C1}" };
  const ROLE_COLORS: Record<string, string> = {
    admin: "bg-red-500/15 text-red-400", member: "bg-blue-500/15 text-blue-400", viewer: "bg-slate-500/15 text-slate-400",
  };

  if (loading) return <div className="flex justify-center py-12"><div className="w-6 h-6 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" /></div>;

  return (
    <div className="space-y-8">
      {/* ── Business Units ── */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-lg font-semibold text-white">Business Units</h3>
            <p className="text-sm text-slate-500 mt-0.5">Organize projects into business units for hierarchical access control</p>
          </div>
          <button onClick={() => { resetBUForm(); setShowBUForm(true); }} className="btn-primary text-xs px-3 py-1.5">+ Add Business Unit</button>
        </div>

        {/* BU Create/Edit Form */}
        {showBUForm && (
          <div className="card border-amber-500/20 mb-4">
            <h4 className="text-sm font-semibold text-slate-300 mb-3">{editingBU ? "Edit Business Unit" : "New Business Unit"}</h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-slate-500 mb-1.5 block">Name</label>
                <input value={buForm.name} onChange={(e) => setBuForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. Engineering" className="input-dark" />
              </div>
              <div>
                <label className="text-xs text-slate-500 mb-1.5 block">Description</label>
                <input value={buForm.description} onChange={(e) => setBuForm(f => ({ ...f, description: e.target.value }))} placeholder="Optional description" className="input-dark" />
              </div>
            </div>
            <div className="flex gap-3 pt-3">
              <button onClick={handleSaveBU} disabled={buSaving || !buForm.name} className="btn-primary text-sm">{buSaving ? "Saving..." : editingBU ? "Update" : "Create"}</button>
              <button onClick={resetBUForm} className="btn-secondary text-sm">Cancel</button>
            </div>
          </div>
        )}

        {/* BU Table */}
        <div className="card p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/[0.06]">
                <th className="px-5 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-widest">Business Unit</th>
                <th className="px-5 py-3 text-center text-[10px] font-semibold text-slate-500 uppercase tracking-widest">Projects</th>
                <th className="px-5 py-3 text-center text-[10px] font-semibold text-slate-500 uppercase tracking-widest">Members</th>
                <th className="px-5 py-3 text-right text-[10px] font-semibold text-slate-500 uppercase tracking-widest">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {bus.length === 0 ? (
                <tr><td colSpan={4} className="px-5 py-8 text-center text-slate-500">No business units. Create one to organize projects.</td></tr>
              ) : bus.map((bu: any) => (
                <tr key={bu.id} className="hover:bg-white/[0.02]">
                  <td className="px-5 py-3">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-amber-500 to-orange-500 flex items-center justify-center text-xs font-bold text-white">{bu.name?.charAt(0)}</div>
                      <div>
                        <p className="text-sm font-medium text-slate-200">{bu.name}</p>
                        {bu.description && <p className="text-xs text-slate-500">{bu.description}</p>}
                      </div>
                    </div>
                  </td>
                  <td className="px-5 py-3 text-center"><span className="text-sm text-slate-300">{bu.project_count || 0}</span></td>
                  <td className="px-5 py-3 text-center"><span className="text-sm text-slate-300">{bu.member_count || 0}</span></td>
                  <td className="px-5 py-3 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button onClick={() => openEditBU(bu)} className="text-xs text-slate-400 hover:text-red-400 px-2 py-1 rounded hover:bg-white/[0.04]">Edit</button>
                      <button onClick={() => setConfirmDeleteBU(bu)} className="text-xs text-slate-400 hover:text-red-400 px-2 py-1 rounded hover:bg-white/[0.04]">Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* BU Delete Confirm */}
        {confirmDeleteBU && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
            <div className="card max-w-sm mx-auto">
              <h4 className="text-sm font-semibold text-white mb-2">Delete Business Unit?</h4>
              <p className="text-xs text-slate-400 mb-4">This will deactivate &quot;{confirmDeleteBU.name}&quot;. Projects within it will become unscoped.</p>
              <div className="flex gap-3">
                <button onClick={handleDeleteBU} className="bg-red-500/20 text-red-400 border border-red-500/30 text-xs px-4 py-2 rounded-lg hover:bg-red-500/30">Delete</button>
                <button onClick={() => setConfirmDeleteBU(null)} className="btn-secondary text-xs">Cancel</button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── User Access Grants ── */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-lg font-semibold text-white">User Access Grants</h3>
            <p className="text-sm text-slate-500 mt-0.5">Assign users to organization, business unit, or project-level access</p>
          </div>
          <button onClick={() => { resetGrantForm(); setShowGrantForm(true); }} className="btn-primary text-xs px-3 py-1.5">+ Add Grant</button>
        </div>

        {/* Grant Create Form */}
        {showGrantForm && (
          <div className="card border-red-500/20 mb-4">
            <h4 className="text-sm font-semibold text-slate-300 mb-4">New Access Grant</h4>

            {/* Row 1: Config dropdowns */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
              <div>
                <label className="text-xs text-slate-500 mb-1.5 block">Access Level</label>
                <select value={grantForm.access_level} onChange={(e) => { setGrantForm(f => ({ ...f, access_level: e.target.value })); setGrantBUs([]); setGrantProjects([]); }} className="select-dark w-full">
                  <option value="organization">Organization (all projects)</option>
                  <option value="business_unit">Business Unit(s)</option>
                  <option value="project">Project(s)</option>
                </select>
              </div>
              <div>
                <label className="text-xs text-slate-500 mb-1.5 block">Permission Level</label>
                <select value={grantForm.role} onChange={(e) => setGrantForm(f => ({ ...f, role: e.target.value }))} className="select-dark w-full">
                  <option value="admin">Admin (full control)</option>
                  <option value="member">Member (read & write)</option>
                  <option value="viewer">Viewer (read-only)</option>
                </select>
              </div>
            </div>

            {/* Row 2: Pickers side by side */}
            <div className={`grid grid-cols-1 ${grantForm.access_level !== "organization" ? "sm:grid-cols-2" : ""} gap-4 mb-4`}>
              <SearchableChecklist label="Users" placeholder="Search users..."
                items={users.map((u: any) => ({ id: u.id, name: u.full_name, detail: u.email }))}
                selectedIds={grantUserIds}
                onChange={setGrantUserIds}
                emptyText="No users found." maxHeight="10rem" />
              {grantForm.access_level === "business_unit" && (
                <SearchableChecklist label="Business Units" placeholder="Search business units..." color="amber"
                  items={bus.map((b: any) => ({ id: b.id, name: b.name, detail: `${b.project_count || 0} proj` }))}
                  selectedIds={grantBUs} onChange={setGrantBUs} emptyText="No business units yet." maxHeight="10rem" />
              )}
              {grantForm.access_level === "project" && (
                <SearchableChecklist label="Projects" placeholder="Search projects..." color="violet"
                  items={repos.map((r: any) => ({ id: r.id, name: r.name }))}
                  selectedIds={grantProjects} onChange={setGrantProjects} emptyText="No projects found." maxHeight="10rem" />
              )}
            </div>

            {grantForm.access_level === "organization" && (
              <p className="text-xs text-slate-600 mb-4">Selected users will have full access to all business units and projects.</p>
            )}

            {/* Row 3: Actions */}
            <div className="flex gap-3">
              <button onClick={handleSaveGrant} disabled={grantSaving || grantUserIds.length === 0 || (grantForm.access_level === "business_unit" && grantBUs.length === 0) || (grantForm.access_level === "project" && grantProjects.length === 0)} className="btn-primary text-sm">
                {grantSaving ? "Saving..." : "Create Grant"}
              </button>
              <button onClick={resetGrantForm} className="btn-secondary text-sm">Cancel</button>
            </div>
          </div>
        )}

        {/* Grants Table */}
        <div className="card p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/[0.06]">
                <th className="px-5 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-widest">User</th>
                <th className="px-5 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-widest">Access Level</th>
                <th className="px-5 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-widest">Scope</th>
                <th className="px-5 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-widest">Role</th>
                <th className="px-5 py-3 text-right text-[10px] font-semibold text-slate-500 uppercase tracking-widest">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {grants.length === 0 ? (
                <tr><td colSpan={5} className="px-5 py-8 text-center text-slate-500">No access grants configured. Users without grants have full organization access by default.</td></tr>
              ) : grants.map((g: any) => (
                <tr key={g.id} className="hover:bg-white/[0.02]">
                  <td className="px-5 py-3">
                    <p className="text-sm text-slate-200">{g.user_name || "Unknown"}</p>
                  </td>
                  <td className="px-5 py-3">
                    <span className={`text-xs px-2.5 py-1 rounded-full border capitalize ${LEVEL_COLORS[g.access_level] || ""}`}>
                      {LEVEL_ICONS[g.access_level] || ""} {g.access_level?.replace("_", " ")}
                    </span>
                  </td>
                  <td className="px-5 py-3">
                    <span className="text-sm text-slate-300">{g.scope_name || "Organization-wide"}</span>
                  </td>
                  <td className="px-5 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded capitalize ${ROLE_COLORS[g.role] || ""}`}>{g.role}</span>
                  </td>
                  <td className="px-5 py-3 text-right">
                    <button onClick={() => handleDeleteGrant(g.id)} className="text-xs text-slate-400 hover:text-red-400 px-2 py-1 rounded hover:bg-white/[0.04]">Revoke</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Help text ── */}
      <div className="card bg-amber-500/5 border-amber-500/20">
        <h4 className="text-sm font-semibold text-amber-400 mb-2">How Access Control Works</h4>
        <div className="text-xs text-slate-400 space-y-1.5">
          <p><span className="text-purple-400 font-medium">Organization</span> &mdash; User sees all business units and all repositories across the org.</p>
          <p><span className="text-amber-400 font-medium">Business Unit</span> &mdash; User sees only repositories assigned to their business unit.</p>
          <p><span className="text-red-400 font-medium">Repository</span> &mdash; User sees only the specific repository they are granted access to.</p>
          <p className="pt-1 text-slate-500">Users without any access grant default to full organization access (backward compatible).</p>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════
   INTEGRATIONS SECTION (embedded from /integrations)
   ═══════════════════════════════════════════════════════ */
function IntegrationsSection() {
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getIntegrations()
      .then((r: any) => setIntegrations(r.data?.items || r.data || []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const handleDelete = async (id: string) => {
    if (!confirm("Remove this integration?")) return;
    try {
      await deleteIntegration(id);
      setIntegrations((prev) => prev.filter((i) => i.id !== id));
    } catch (e) {
      console.error(e);
    }
  };

  const handleToggle = async (id: string, currentActive: boolean) => {
    try {
      await updateIntegration(id, { is_active: !currentActive });
      setIntegrations((prev) =>
        prev.map((i) => (i.id === id ? { ...i, is_active: !currentActive } : i))
      );
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div>
      <SectionHeader title="Integrations" description="Manage webhooks, SCM connectors, and notification channels" />

      <div className="flex justify-end mb-4">
        <a href="/integrations" className="btn-primary flex items-center gap-2 text-xs">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" /></svg>
          Manage Integrations
        </a>
      </div>

      {loading ? (
        <div className="flex justify-center py-12">
          <div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" />
        </div>
      ) : integrations.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-14 h-14 rounded-xl bg-red-500/10 flex items-center justify-center mx-auto mb-4">
            <svg className="w-7 h-7 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
            </svg>
          </div>
          <p className="text-sm text-slate-400">No integrations configured</p>
          <p className="text-xs text-slate-600 mt-1">Connect SCM providers, webhooks, and notification channels</p>
        </div>
      ) : (
        <div className="space-y-2">
          {integrations.map((integration: any) => (
            <div key={integration.id} className="flex items-center justify-between py-3 px-4 rounded-lg bg-white/[0.02] border border-white/[0.04] hover:bg-white/[0.03] transition-colors">
              <div className="flex items-center gap-3">
                <div className={`w-8 h-8 rounded-md flex items-center justify-center ${integration.is_active ? "bg-green-500/15" : "bg-slate-500/10"}`}>
                  <span className={`text-[10px] font-bold ${integration.is_active ? "text-green-400" : "text-slate-500"}`}>
                    {(integration.provider || integration.integration_type || "?")[0]?.toUpperCase()}
                  </span>
                </div>
                <div>
                  <p className="text-sm text-slate-200 font-medium">{integration.name || integration.provider}</p>
                  <p className="text-[10px] text-slate-500">{integration.integration_type || integration.provider} {integration.base_url ? `\u2022 ${integration.base_url}` : ""}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-[10px] px-2 py-0.5 rounded ${integration.is_active ? "bg-green-500/15 text-green-400" : "bg-slate-500/10 text-slate-500"}`}>
                  {integration.is_active ? "Active" : "Inactive"}
                </span>
                <button
                  onClick={() => handleToggle(integration.id, integration.is_active)}
                  className="text-[10px] text-slate-400 hover:text-slate-200 px-2 py-1 rounded hover:bg-white/[0.04]"
                >
                  {integration.is_active ? "Disable" : "Enable"}
                </button>
                <button
                  onClick={() => handleDelete(integration.id)}
                  className="text-[10px] text-red-400 hover:text-red-300 px-2 py-1 rounded hover:bg-red-500/5"
                >
                  Remove
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════
   MAIN SETTINGS PAGE
   ═══════════════════════════════════════════════════════ */
function AdminSettingsPage() {
  return (
    <Suspense fallback={<AppShell><div className="flex justify-center py-20"><div className="w-6 h-6 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" /></div></AppShell>}>
      <AdminSettingsContent />
    </Suspense>
  );
}

// PoliciesSettingsSection removed 2026-05-16 alongside the governance surface.

function SuppressionsSettingsSection() {
  return <SuppressionsContent />;
}

function RuleOverridesSettingsSection() {
  return <RuleOverridesContent />;
}

function CustomDetectorsSettingsSection() {
  return <CustomDetectorsContent />;
}

function SchedulesSettingsSection() {
  return <SchedulesContent />;
}

function AdminSettingsContent() {
  const [activeTab, setActiveTab] = useState<SettingsTab | null>(null);
  const validTabs: SettingsTab[] = ["users", "roles", "access_control", "api_keys", "audit", "suppressions", "rule_overrides", "custom_detectors", "schedules", "reports", "organization"];

  // Tabs that moved to Integrations Hub — redirect if deep-linked
  const movedTabs: Record<string, string> = {
    "ai": "/integrations?category=ai_models",
    "sso": "/integrations?category=identity",
    "notifications": "/integrations?category=notifications",
  };

  // Sync tab state with URL search params — reacts to sidebar clicks and deep links
  const searchParams = useSearchParams();
  useEffect(() => {
    const tab = searchParams.get("tab");
    if (tab && movedTabs[tab]) {
      window.location.href = movedTabs[tab];
      return;
    }
    if (tab && validTabs.includes(tab as SettingsTab)) {
      setActiveTab(tab as SettingsTab);
    } else {
      setActiveTab(null); // No tab param = show tile grid
    }
  }, [searchParams]);

  const SECTION_MAP: Record<SettingsTab, React.ReactNode> = {
    ai: <AIModelsSection />,
    users: <UsersSection />,
    roles: <RolesSection />,
    access_control: <AccessControlSection />,
    sso: <SSOSection />,
    notifications: <NotificationsSection />,
    api_keys: <APIKeysSection />,
    audit: <AuditSection />,
    suppressions: <SuppressionsSettingsSection />,
    rule_overrides: <RuleOverridesSettingsSection />,
    custom_detectors: <CustomDetectorsSettingsSection />,
    schedules: <SchedulesSettingsSection />,
    reports: <ReportsSection />,
    organization: <OrganizationSection />,
    integrations: <IntegrationsSection />,
  };

  const goBack = () => {
    setActiveTab(null);
    window.history.replaceState(null, "", "/settings/admin");
  };

  const openSection = (key: SettingsTab) => {
    setActiveTab(key);
    window.history.replaceState(null, "", `/settings/admin?tab=${key}`);
  };

  const activeTabInfo = TABS.find((t) => t.key === activeTab);

  // Single-source breadcrumb — passed to AppShell so it renders in
  // the global header band (same row as bell + avatar) instead of
  // the page body.  Matches the Integrations / Sources pattern.
  // 2026-05-19 cleanup: replaces the previous body-level back bar +
  // duplicate SectionHeader title that stacked 3 "Roles &
  // Permissions" headings on top of each other.
  const shellBreadcrumb = activeTabInfo
    ? [
        { label: "Settings", href: "/settings/admin" },
        { label: activeTabInfo.label },
      ]
    : undefined;

  return (
    <AppShell pageBreadcrumb={shellBreadcrumb}>
      <div className="max-w-[1200px]">

        {/* ═══ TILE GRID — shown when no section is selected ═══ */}
        {!activeTab && (
          <>
            <p className="text-sm text-slate-400 mb-6">Platform configuration and administration</p>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
              {TABS.filter((t) => t.key !== "organization").map((tab) => (
                <button
                  key={tab.key}
                  onClick={() => openSection(tab.key)}
                  className="card card-hover group text-left p-5 pb-10 relative overflow-hidden min-h-[140px] flex flex-col"
                >
                  {/* Gradient accent bar at top */}
                  <div className={`absolute top-0 left-0 right-0 h-1 bg-gradient-to-r ${tab.color} opacity-0 group-hover:opacity-100 transition-opacity`} />

                  <div className={`w-11 h-11 rounded-xl bg-gradient-to-br ${tab.color} flex items-center justify-center mb-3 opacity-90 group-hover:opacity-100 transition-opacity text-white shrink-0`}>
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      {tab.icon}
                    </svg>
                  </div>
                  <h3 className="text-sm font-semibold text-slate-200 group-hover:text-white transition-colors">{tab.label}</h3>
                  <p className="text-xs text-slate-500 mt-1 leading-relaxed line-clamp-2">{tab.description}</p>

                  {/* Arrow */}
                  <svg className="absolute bottom-4 right-4 w-4 h-4 text-slate-700 group-hover:text-slate-400 group-hover:translate-x-0.5 transition-all" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </button>
              ))}
            </div>
          </>
        )}

        {/* ═══ SECTION DETAIL — shown when a tile is selected ═══
            Body-level back bar removed 2026-05-19; the breadcrumb
            now lives in AppShell's global header (see
            `pageBreadcrumb` prop above) so the page no longer
            stacks three "<section>" headings on top of each other. */}
        {activeTab && activeTabInfo && (
          <div>
            {SECTION_MAP[activeTab]}
          </div>
        )}
      </div>
    </AppShell>
  );
}

export default function Page() {
  return <Suspense fallback={null}><AdminSettingsPage /></Suspense>;
}
