"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect, useCallback, useMemo } from "react";
import { getSuppressionRules, createSuppressionRule, updateSuppressionRule, deleteSuppressionRule } from "@/lib/api";

interface SuppressionRule {
  id: string;
  name: string;
  type: string;
  suppression_type: string;
  scanner_rule_id: string | null;
  pattern_hash: string | null;
  vulnerability_category: string | null;
  cwe: string | null;
  file_path_pattern: string | null;
  reason: string | null;
  description: string | null;
  confidence: number;
  is_active: boolean;
  evidence_count: number;
  times_applied: number;
  created_by: string | null;
  created_at: string;
  // Note: scope_level + repository_id used to live here as a half-built
  // "per-repo suppression" idea.  Those columns never existed on the
  // backend SuppressionRule model — they were dead form fields.  Per-repo
  // rule muting now lives on its own surface (Rule Overrides) because
  // proactive scanner-rule muting and reactive finding suppression have
  // different audit / lifecycle semantics.  See
  // components/secrets/RuleOverridesContent.tsx and
  // apps/api/app/models/rule_override.py.
}

const TYPE_STYLE: Record<string, { bg: string; text: string; label: string }> = {
  LEARNED: { bg: "bg-purple-500/15", text: "text-purple-400", label: "Auto-Learned" },
  MANUAL: { bg: "bg-red-500/15", text: "text-red-400", label: "Manual" },
  SCANNER_RULE: { bg: "bg-orange-500/15", text: "text-orange-400", label: "Rule-Based" },
  ALLOWLIST: { bg: "bg-green-500/15", text: "text-green-400", label: "Allowlist" },
  manual: { bg: "bg-red-500/15", text: "text-red-400", label: "Manual" },
  scanner_rule: { bg: "bg-orange-500/15", text: "text-orange-400", label: "Rule-Based" },
  learned: { bg: "bg-purple-500/15", text: "text-purple-400", label: "Auto-Learned" },
};

type SortField = "name" | "type" | "times_applied" | "created_at" | "is_active";
type SortDir = "asc" | "desc";

// Form shape mirrors the backend SuppressionRuleCreate schema — no
// scope_level (see the interface comment for why).  Per-repo muting
// is the Rule Overrides surface.
const emptyForm = { name: "", type: "MANUAL", scanner_rule_id: "", file_path_pattern: "", vulnerability_category: "", reason: "" };

export function SuppressionsContent() {
  const [rules, setRules] = useState<SuppressionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState({ ...emptyForm });

  // Enterprise features
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [sortField, setSortField] = useState<SortField>("created_at");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 25;

  const fetchRules = useCallback(async () => {
    try {
      setLoading(true);
      const res = await getSuppressionRules();
      setRules(res.data?.rules || res.data || []);
    } catch { setRules([]); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchRules(); }, [fetchRules]);

  // Filtered + sorted + paginated rules
  const processed = useMemo(() => {
    let items = [...rules];

    // Search
    if (search) {
      const q = search.toLowerCase();
      items = items.filter(r =>
        (r.name || "").toLowerCase().includes(q) ||
        (r.scanner_rule_id || "").toLowerCase().includes(q) ||
        (r.file_path_pattern || "").toLowerCase().includes(q) ||
        (r.reason || "").toLowerCase().includes(q)
      );
    }

    // Filter by type
    if (filterType) {
      items = items.filter(r => (r.type || r.suppression_type || "").toLowerCase() === filterType.toLowerCase());
    }

    // Filter by status
    if (filterStatus === "active") items = items.filter(r => r.is_active);
    if (filterStatus === "disabled") items = items.filter(r => !r.is_active);

    // Sort
    items.sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case "name": cmp = (a.name || "").localeCompare(b.name || ""); break;
        case "type": cmp = (a.type || "").localeCompare(b.type || ""); break;
        case "times_applied": cmp = (a.times_applied || 0) - (b.times_applied || 0); break;
        case "created_at": cmp = (a.created_at || "").localeCompare(b.created_at || ""); break;
        case "is_active": cmp = (a.is_active ? 1 : 0) - (b.is_active ? 1 : 0); break;
      }
      return sortDir === "desc" ? -cmp : cmp;
    });

    return items;
  }, [rules, search, filterType, filterStatus, sortField, sortDir]);

  const totalPages = Math.ceil(processed.length / PAGE_SIZE);
  const paginated = processed.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const handleCreate = async () => {
    if (!form.name.trim()) return;
    try {
      await createSuppressionRule({
        name: form.name, type: form.type,
        scanner_rule_id: form.scanner_rule_id || null,
        file_path_pattern: form.file_path_pattern || null,
        vulnerability_category: form.vulnerability_category || null,
        reason: form.reason || null,
      });
      setShowCreate(false);
      setForm({ ...emptyForm });
      fetchRules();
    } catch (e) { console.error(e); }
  };

  const handleUpdate = async () => {
    if (!editingId) return;
    try {
      await updateSuppressionRule(editingId, {
        scanner_rule_id: form.scanner_rule_id || null,
        file_path_pattern: form.file_path_pattern || null,
        vulnerability_category: form.vulnerability_category || null,
        reason: form.reason || null,
      });
      setEditingId(null);
      setForm({ ...emptyForm });
      fetchRules();
    } catch (e) { console.error(e); }
  };

  const handleToggle = async (id: string, active: boolean) => {
    try {
      await updateSuppressionRule(id, { is_active: !active });
      fetchRules();
    } catch (e) { console.error(e); }
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this suppression rule? This cannot be undone.")) return;
    try { await deleteSuppressionRule(id); fetchRules(); } catch (e) { console.error(e); }
  };

  const handleBulkToggle = async (activate: boolean) => {
    for (const id of selected) {
      try { await updateSuppressionRule(id, { is_active: activate }); } catch {}
    }
    setSelected(new Set());
    fetchRules();
  };

  const handleBulkDelete = async () => {
    if (!confirm(`Delete ${selected.size} suppression rule(s)? This cannot be undone.`)) return;
    for (const id of selected) {
      try { await deleteSuppressionRule(id); } catch {}
    }
    setSelected(new Set());
    fetchRules();
  };

  const startEdit = (r: SuppressionRule) => {
    setEditingId(r.id);
    setShowCreate(false);
    setForm({
      name: r.name || "", type: r.type || r.suppression_type || "MANUAL",
      scanner_rule_id: r.scanner_rule_id || "", file_path_pattern: r.file_path_pattern || "",
      vulnerability_category: r.vulnerability_category || "", reason: r.reason || "",
    });
  };

  const toggleSelect = (id: string) => {
    const next = new Set(selected);
    next.has(id) ? next.delete(id) : next.add(id);
    setSelected(next);
  };

  const toggleSelectAll = () => {
    if (selected.size === paginated.length) { setSelected(new Set()); }
    else { setSelected(new Set(paginated.map(r => r.id))); }
  };

  const handleSort = (field: SortField) => {
    if (sortField === field) { setSortDir(d => d === "asc" ? "desc" : "asc"); }
    else { setSortField(field); setSortDir("desc"); }
  };

  const handleExport = () => {
    const csv = ["Name,Type,Matcher,Reason,Status,Applied,Created"]
      .concat(rules.map(r => `"${r.name}","${r.type || r.suppression_type}","${r.scanner_rule_id || r.file_path_pattern || ""}","${r.reason || ""}","${r.is_active ? "active" : "disabled"}","${r.times_applied}","${r.created_at}"`))
      .join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = "suppression_rules.csv"; a.click();
  };

  const active = rules.filter(r => r.is_active).length;
  const learned = rules.filter(r => (r.type || r.suppression_type || "").toLowerCase().includes("learned")).length;
  const totalApplied = rules.reduce((s, r) => s + (r.times_applied || 0), 0);

  return (
    <div className="space-y-5 max-w-[1600px]">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Suppression Rules</h1>
          <p className="text-sm text-slate-400 mt-1">Manage rules that automatically dismiss known false positives and allowlisted patterns</p>
        </div>
        <div className="flex gap-2">
          <button onClick={handleExport} className="btn-secondary text-xs">Export CSV</button>
          <button onClick={() => { setShowCreate(true); setEditingId(null); setForm({ ...emptyForm }); }} className="btn-primary">Create Rule</button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="card p-4"><p className="text-xs text-slate-500 uppercase">Total Rules</p><p className="text-2xl font-bold text-white mt-1">{rules.length}</p></div>
        <div className="card p-4"><p className="text-xs text-green-400 uppercase">Active</p><p className="text-2xl font-bold text-green-400 mt-1">{active}</p></div>
        <div className="card p-4"><p className="text-xs text-purple-400 uppercase">Auto-Learned</p><p className="text-2xl font-bold text-purple-400 mt-1">{learned}</p></div>
        <div className="card p-4"><p className="text-xs text-red-400 uppercase">Total Suppressions</p><p className="text-2xl font-bold text-red-400 mt-1">{totalApplied}</p></div>
      </div>

      {/* Create / Edit Form */}
      {(showCreate || editingId) && (
        <div className="card border-red-500/20">
          <h3 className="text-sm font-semibold text-white mb-4">{editingId ? "Edit Suppression Rule" : "New Suppression Rule"}</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="md:col-span-2">
              <label className="text-xs text-slate-400 block mb-1">Name *</label>
              <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} className="input-dark w-full" placeholder="e.g. Suppress test file secrets" disabled={!!editingId} />
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Type</label>
              <select value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value }))} className="input-dark w-full" disabled={!!editingId}>
                <option value="MANUAL">Manual</option>
                <option value="SCANNER_RULE">Rule-Based (by Rule ID)</option>
                <option value="ALLOWLIST">Allowlist Pattern</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Secret Type / Rule ID</label>
              <input value={form.scanner_rule_id} onChange={e => setForm(f => ({ ...f, scanner_rule_id: e.target.value }))} className="input-dark w-full" placeholder="e.g. VOODA-SEC-GEN-003 or aws_access_key" />
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">File Path Pattern (glob)</label>
              <input value={form.file_path_pattern} onChange={e => setForm(f => ({ ...f, file_path_pattern: e.target.value }))} className="input-dark w-full" placeholder="e.g. tests/**, *.test.*, fixtures/" />
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Category</label>
              <input value={form.vulnerability_category} onChange={e => setForm(f => ({ ...f, vulnerability_category: e.target.value }))} className="input-dark w-full" placeholder="e.g. Hardcoded Secret" />
            </div>
            <div className="md:col-span-2">
              <label className="text-xs text-slate-400 block mb-1">Reason / Description</label>
              <textarea value={form.reason} onChange={e => setForm(f => ({ ...f, reason: e.target.value }))} className="input-dark w-full h-16 resize-none" placeholder="Why this pattern should be suppressed — visible to all team members" />
            </div>
          </div>
          <div className="flex gap-2 mt-4">
            <button onClick={editingId ? handleUpdate : handleCreate} className="btn-primary">{editingId ? "Save Changes" : "Create Rule"}</button>
            <button onClick={() => { setShowCreate(false); setEditingId(null); setForm({ ...emptyForm }); }} className="btn-secondary">Cancel</button>
          </div>
        </div>
      )}

      {/* Search + Filters + Bulk Actions */}
      <div className="card">
        <div className="flex gap-3 items-center flex-wrap mb-4">
          <div className="relative flex-1 max-w-xs">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
            <input type="text" value={search} onChange={e => { setSearch(e.target.value); setPage(1); }} className="input-dark pl-10 w-full" placeholder="Search rules..." />
          </div>
          <select value={filterType} onChange={e => { setFilterType(e.target.value); setPage(1); }} className="select-dark text-xs">
            <option value="">All Types</option>
            <option value="MANUAL">Manual</option>
            <option value="SCANNER_RULE">Rule-Based</option>
            <option value="ALLOWLIST">Allowlist</option>
            <option value="LEARNED">Auto-Learned</option>
          </select>
          <select value={filterStatus} onChange={e => { setFilterStatus(e.target.value); setPage(1); }} className="select-dark text-xs">
            <option value="">All Statuses</option>
            <option value="active">Active</option>
            <option value="disabled">Disabled</option>
          </select>
          <div className="flex-1" />
          <span className="text-[10px] text-slate-500">{processed.length} rule{processed.length !== 1 ? "s" : ""}</span>
        </div>

        {/* Bulk Actions Bar */}
        {selected.size > 0 && (
          <div className="flex items-center gap-3 mb-3 px-3 py-2 rounded-lg bg-red-500/5 border border-red-500/10">
            <span className="text-xs text-red-400 font-medium">{selected.size} selected</span>
            <button onClick={() => handleBulkToggle(true)} className="text-xs text-green-400 hover:text-green-300">Enable All</button>
            <button onClick={() => handleBulkToggle(false)} className="text-xs text-slate-400 hover:text-slate-300">Disable All</button>
            <button onClick={handleBulkDelete} className="text-xs text-red-400 hover:text-red-300">Delete All</button>
            <div className="flex-1" />
            <button onClick={() => setSelected(new Set())} className="text-xs text-slate-500 hover:text-slate-300">Clear</button>
          </div>
        )}

        {/* Table */}
        {loading ? (
          <div className="text-center py-12 text-slate-500">Loading rules...</div>
        ) : processed.length === 0 ? (
          <div className="text-center py-12 text-slate-500">
            {rules.length === 0 ? "No suppression rules yet. Create one or let the AI auto-learn from your triage decisions." : "No rules match your filters."}
          </div>
        ) : (
          <>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/[0.06]">
                  <th className="py-3 px-3 w-8">
                    <input type="checkbox" checked={selected.size === paginated.length && paginated.length > 0} onChange={toggleSelectAll}
                      className="w-3.5 h-3.5 rounded border-slate-600 bg-dark-950 text-red-500 cursor-pointer" />
                  </th>
                  <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase cursor-pointer hover:text-slate-300" onClick={() => handleSort("name")}>
                    Name {sortField === "name" && (sortDir === "asc" ? "↑" : "↓")}
                  </th>
                  <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase cursor-pointer hover:text-slate-300" onClick={() => handleSort("type")}>
                    Type {sortField === "type" && (sortDir === "asc" ? "↑" : "↓")}
                  </th>
                  <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Matcher</th>
                  <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Reason</th>
                  <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase cursor-pointer hover:text-slate-300" onClick={() => handleSort("times_applied")}>
                    Applied {sortField === "times_applied" && (sortDir === "asc" ? "↑" : "↓")}
                  </th>
                  <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Created</th>
                  <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase cursor-pointer hover:text-slate-300" onClick={() => handleSort("is_active")}>
                    Status {sortField === "is_active" && (sortDir === "asc" ? "↑" : "↓")}
                  </th>
                  <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody>
                {paginated.map(r => {
                  const rType = r.type || r.suppression_type || "manual";
                  const ts = TYPE_STYLE[rType] || TYPE_STYLE.MANUAL;
                  const matcher = r.scanner_rule_id || r.file_path_pattern || r.vulnerability_category || r.pattern_hash?.slice(0, 16) || "—";
                  const createdDate = r.created_at ? new Date(r.created_at).toLocaleDateString() : "—";
                  return (
                    <tr key={r.id} className={`border-b border-white/[0.03] hover:bg-white/[0.02] ${selected.has(r.id) ? "bg-red-500/5" : ""}`}>
                      <td className="py-2.5 px-3">
                        <input type="checkbox" checked={selected.has(r.id)} onChange={() => toggleSelect(r.id)}
                          className="w-3.5 h-3.5 rounded border-slate-600 bg-dark-950 text-red-500 cursor-pointer" />
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="text-xs text-slate-300 font-medium block truncate max-w-[180px]" title={r.name}>{r.name || "—"}</span>
                        <span className="text-[9px] text-slate-600">{r.created_by || "system"}</span>
                      </td>
                      <td className="py-2.5 px-3"><span className={`text-[10px] px-2 py-0.5 rounded ${ts.bg} ${ts.text}`}>{ts.label}</span></td>
                      <td className="py-2.5 px-3 font-mono text-[10px] text-red-400/80 max-w-[200px] truncate" title={matcher}>{matcher}</td>
                      <td className="py-2.5 px-3 text-[10px] text-slate-500 max-w-[160px] truncate" title={r.reason || r.description || ""}>{r.reason || r.description || "—"}</td>
                      <td className="py-2.5 px-3">
                        <span className="text-xs text-slate-400">{r.times_applied || 0}x</span>
                      </td>
                      <td className="py-2.5 px-3 text-[10px] text-slate-600">{createdDate}</td>
                      <td className="py-2.5 px-3">
                        <button onClick={() => handleToggle(r.id, r.is_active)}
                          className={`text-[10px] px-2.5 py-1 rounded cursor-pointer transition-all ${r.is_active ? "bg-green-500/15 text-green-400 hover:bg-green-500/25" : "bg-slate-500/10 text-slate-500 hover:bg-slate-500/20"}`}>
                          {r.is_active ? "Active" : "Disabled"}
                        </button>
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="flex gap-2">
                          <button onClick={() => startEdit(r)} className="text-[10px] text-red-400 hover:text-red-300 transition-colors">Edit</button>
                          <button onClick={() => handleDelete(r.id)} className="text-[10px] text-red-400 hover:text-red-300 transition-colors">Delete</button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between pt-4 px-3 border-t border-white/[0.04]">
                <span className="text-[10px] text-slate-500">
                  {((page - 1) * PAGE_SIZE) + 1}–{Math.min(page * PAGE_SIZE, processed.length)} of {processed.length}
                </span>
                <div className="flex gap-1">
                  <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                    className="px-2.5 py-1 rounded text-[10px] text-slate-400 hover:bg-white/[0.06] disabled:opacity-30">← Prev</button>
                  {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => i + 1).map(p => (
                    <button key={p} onClick={() => setPage(p)}
                      className={`px-2.5 py-1 rounded text-[10px] ${p === page ? "bg-red-500/20 text-red-400" : "text-slate-400 hover:bg-white/[0.06]"}`}>{p}</button>
                  ))}
                  <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                    className="px-2.5 py-1 rounded text-[10px] text-slate-400 hover:bg-white/[0.06] disabled:opacity-30">Next →</button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
