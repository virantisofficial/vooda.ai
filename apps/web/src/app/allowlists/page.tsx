"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect, useCallback } from "react";
import AppShell from "@/components/layout/AppShell";
import { getSuppressionRules, createSuppressionRule, deleteSuppressionRule } from "@/lib/api";

interface AllowlistEntry {
  id: string;
  pattern: string;
  match_type: string; // exact, regex, glob
  scope: string; // global, repo, file_path
  description: string;
  created_by: string | null;
  created_at: string;
  is_active: boolean;
  matches_count: number;
}

export default function AllowlistPage() {
  const [entries, setEntries] = useState<AllowlistEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ pattern: "", match_type: "exact", scope: "global", description: "" });

  const fetchEntries = useCallback(async () => {
    try {
      setLoading(true);
      // Allowlists are stored as suppression rules with type=ALLOWLIST
      const res = await getSuppressionRules({ suppression_type: "manual" });
      const data = res.data?.rules || res.data || [];
      setEntries(data.map((r: any) => ({
        id: r.id,
        pattern: r.scanner_rule_id || r.file_path_pattern || r.pattern_hash || "",
        match_type: r.file_path_pattern ? "glob" : r.pattern_hash ? "hash" : "exact",
        scope: r.file_path_pattern ? "file_path" : "global",
        description: r.vulnerability_category || "",
        created_by: r.created_by,
        created_at: r.created_at,
        is_active: r.is_active,
        matches_count: r.times_applied || 0,
      })));
    } catch { setEntries([]); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchEntries(); }, [fetchEntries]);

  const handleCreate = async () => {
    try {
      // Field names must match SuppressionRuleCreate: `name` is required
      // and `suppression_type` is the field — an earlier version sent
      // `type` with no name, so every save was rejected 422 and the only
      // sign was a console line the user never sees.
      await createSuppressionRule({
        name: form.description || `Allowlist: ${form.pattern}`,
        description: form.description || "Allowlisted pattern",
        suppression_type: "manual",
        scanner_rule_id: form.match_type === "exact" ? form.pattern : null,
        file_path_pattern: form.match_type === "glob" ? form.pattern : null,
      });
      setShowCreate(false);
      setForm({ pattern: "", match_type: "exact", scope: "global", description: "" });
      fetchEntries();
    } catch (e: any) {
      // Surface it. A silent console.error meant a rejected save looked
      // identical to a successful one that simply showed nothing.
      setError(e?.response?.data?.detail
        ? String(e.response.data.detail)
        : "Could not save this allowlist entry.");
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Remove this allowlist entry?")) return;
    try {
      await deleteSuppressionRule(id);
      fetchEntries();
    } catch (e) { console.error(e); }
  };

  // Page title now lives in the breadcrumb terminal in the header;
  // primary action ("New Entry") promotes up alongside it.
  const headerAction = (
    <button onClick={() => setShowCreate(true)} className="btn-primary-sm">+ New Entry</button>
  );

  return (
    <AppShell pageActions={headerAction}>
      <div className="space-y-6">
        <p className="text-sm text-slate-400">Patterns that are known-safe and should never be flagged as secrets</p>

        {/* Common Allowlist Suggestions */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Common Patterns to Allowlist</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            {[
              { label: "Test keys (sk_test_*)", pattern: "sk_test_" },
              { label: "Placeholder values", pattern: "your_api_key" },
              { label: "Example domains", pattern: "example.com" },
              { label: "CI test fixtures", pattern: "tests/fixtures/**" },
            ].map(s => (
              <button key={s.pattern}
                onClick={() => { setForm(f => ({ ...f, pattern: s.pattern, description: s.label })); setShowCreate(true); }}
                className="text-left p-3 rounded-lg bg-white/[0.02] border border-white/[0.06] hover:border-red-500/30 transition-colors">
                <p className="text-xs text-slate-300">{s.label}</p>
                <code className="text-[10px] text-red-400 mt-1 block">{s.pattern}</code>
              </button>
            ))}
          </div>
        </div>

        {/* Create form. Grid is `grid-cols-1 md:grid-cols-3` so
            mobile stacks vertically, desktop fills 3 columns. Each
            field carries a one-line hint mirroring the integrations
            page polish standard. */}
        {error && (
        <div className="card border-red-500/30 bg-red-500/5">
          <p className="text-xs text-red-400">{error}</p>
        </div>
      )}
      {showCreate && (
          <div className="card border-red-500/20">
            <h3 className="text-sm font-semibold text-white mb-4">New Allowlist Entry</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="text-xs text-slate-400">
                  Match Type <span className="text-red-400">*</span>
                </label>
                <select value={form.match_type} onChange={e => setForm(f => ({ ...f, match_type: e.target.value }))} className="input-dark mt-1 w-full">
                  <option value="exact">Exact Value</option>
                  <option value="glob">Glob Pattern (file path)</option>
                  <option value="regex">Regex Pattern</option>
                </select>
                <p className="text-[11px] text-slate-600 mt-1 leading-snug">
                  {form.match_type === "exact" ? "Literal string match — fastest, used for known test keys."
                  : form.match_type === "glob" ? "File-path glob like tests/** or fixtures/*.yaml."
                  : "Full regular expression — only when exact / glob aren't enough."}
                </p>
              </div>
              <div>
                <label className="text-xs text-slate-400">
                  Pattern <span className="text-red-400">*</span>
                </label>
                <input value={form.pattern} onChange={e => setForm(f => ({ ...f, pattern: e.target.value }))} className="input-dark mt-1 w-full" placeholder={form.match_type === "glob" ? "tests/**" : "sk_test_*"} />
                <p className="text-[11px] text-slate-600 mt-1">The value or path that should never raise a finding.</p>
              </div>
              <div>
                <label className="text-xs text-slate-400">Description</label>
                <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} className="input-dark mt-1 w-full" placeholder="Why this is safe" />
                <p className="text-[11px] text-slate-600 mt-1">Why this pattern is known-safe — shown in audit history.</p>
              </div>
            </div>
            <div className="flex gap-2 mt-4">
              <button onClick={handleCreate} className="btn-primary">Save</button>
              <button onClick={() => setShowCreate(false)} className="btn-secondary">Cancel</button>
            </div>
          </div>
        )}

        {/* Entries Table */}
        <div className="card">
          {loading ? (
            <div className="text-center py-12 text-slate-500">Loading...</div>
          ) : entries.length === 0 ? (
            <div className="text-center py-12 text-slate-500">No allowlist entries yet. Add patterns for known-safe values like test keys and placeholders.</div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/[0.06]">
                  <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Pattern</th>
                  <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Type</th>
                  <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Description</th>
                  <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Matches</th>
                  <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody>
                {entries.map(e => (
                  <tr key={e.id} className="border-b border-white/[0.03] hover:bg-white/[0.02]">
                    <td className="py-2.5 px-3 font-mono text-xs text-red-400">{e.pattern}</td>
                    <td className="py-2.5 px-3"><span className="text-xs px-2 py-0.5 rounded bg-white/[0.04] text-slate-400">{e.match_type}</span></td>
                    <td className="py-2.5 px-3 text-slate-400 text-xs">{e.description}</td>
                    <td className="py-2.5 px-3 text-slate-500">{e.matches_count}x</td>
                    <td className="py-2.5 px-3">
                      <button onClick={() => handleDelete(e.id)} className="text-xs text-red-400 hover:text-red-300">Remove</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </AppShell>
  );
}
