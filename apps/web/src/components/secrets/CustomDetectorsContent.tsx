"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect, useCallback, useMemo } from "react";
import { getCustomDetectors, createCustomDetector, updateCustomDetector, deleteCustomDetector, toggleCustomDetector, testCustomDetectorRegex, getCustomDetectorStats } from "@/lib/api";

interface CustomDetector {
  id: string;
  rule_id: string;
  title: string;
  secret_type: string;
  severity: string;
  pattern: string;
  keywords: string[];
  confidence: number;
  description: string;
  fix_hint: string;
  cwe: string;
  multiline: boolean;
  is_enabled: boolean;
  created_by: string;
  test_cases: Array<{ input: string; should_match: boolean }>;
  match_count: number;
  created_at: string;
  updated_at: string;
}

interface TestResult {
  input: string;
  matched: boolean;
  match_text?: string;
  groups: string[];
}

const SEVERITY_STYLE: Record<string, { bg: string; text: string }> = {
  critical: { bg: "bg-red-500/15", text: "text-red-400" },
  high: { bg: "bg-orange-500/15", text: "text-orange-400" },
  medium: { bg: "bg-yellow-500/15", text: "text-yellow-400" },
  low: { bg: "bg-blue-500/15", text: "text-blue-400" },
};

type SortField = "rule_id" | "title" | "severity" | "match_count" | "created_at" | "is_enabled";
type SortDir = "asc" | "desc";

const emptyForm = {
  rule_id: "", title: "", secret_type: "", severity: "high", pattern: "",
  keywords: "", confidence: 0.9, description: "", fix_hint: "", cwe: "CWE-798", multiline: false,
};

export function CustomDetectorsContent() {
  const [detectors, setDetectors] = useState<CustomDetector[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState({ ...emptyForm });
  const [stats, setStats] = useState({ total_detectors: 0, active_detectors: 0, total_matches: 0 });

  // Regex tester
  const [testInput, setTestInput] = useState("");
  const [testResults, setTestResults] = useState<TestResult[]>([]);
  const [testError, setTestError] = useState("");
  const [testing, setTesting] = useState(false);

  // Enterprise features
  const [search, setSearch] = useState("");
  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [sortField, setSortField] = useState<SortField>("created_at");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [page, setPage] = useState(1);
  const [saving, setSaving] = useState(false);
  const PAGE_SIZE = 25;

  const fetchDetectors = useCallback(async () => {
    try {
      setLoading(true);
      const [detRes, statsRes] = await Promise.all([getCustomDetectors(), getCustomDetectorStats()]);
      setDetectors(detRes.data?.detectors || detRes.data || []);
      setStats(statsRes.data || { total_detectors: 0, active_detectors: 0, total_matches: 0 });
    } catch { setDetectors([]); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchDetectors(); }, [fetchDetectors]);

  // Filtered + sorted + paginated
  const processed = useMemo(() => {
    let items = [...detectors];
    if (search) {
      const q = search.toLowerCase();
      items = items.filter(d =>
        d.rule_id.toLowerCase().includes(q) ||
        d.title.toLowerCase().includes(q) ||
        d.pattern.toLowerCase().includes(q) ||
        d.secret_type.toLowerCase().includes(q)
      );
    }
    if (filterSeverity) items = items.filter(d => d.severity === filterSeverity);
    if (filterStatus === "active") items = items.filter(d => d.is_enabled);
    else if (filterStatus === "disabled") items = items.filter(d => !d.is_enabled);

    items.sort((a, b) => {
      let cmp = 0;
      if (sortField === "match_count") cmp = a.match_count - b.match_count;
      else if (sortField === "is_enabled") cmp = (a.is_enabled ? 1 : 0) - (b.is_enabled ? 1 : 0);
      else cmp = String(a[sortField] || "").localeCompare(String(b[sortField] || ""));
      return sortDir === "asc" ? cmp : -cmp;
    });

    const total = items.length;
    const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    const start = (page - 1) * PAGE_SIZE;
    return { items: items.slice(start, start + PAGE_SIZE), total, totalPages };
  }, [detectors, search, filterSeverity, filterStatus, sortField, sortDir, page]);

  const handleSort = (field: SortField) => {
    if (sortField === field) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortField(field); setSortDir("asc"); }
  };

  const handleTestRegex = async () => {
    if (!form.pattern || !testInput.trim()) return;
    setTesting(true); setTestError(""); setTestResults([]);
    try {
      const strings = testInput.split("\n").filter(s => s.trim());
      const res = await testCustomDetectorRegex({ pattern: form.pattern, test_strings: strings, multiline: form.multiline });
      if (res.data.valid) { setTestResults(res.data.results); setTestError(""); }
      else { setTestError(res.data.error || "Invalid regex"); setTestResults([]); }
    } catch (e: any) { setTestError(e?.response?.data?.detail || "Test failed"); }
    finally { setTesting(false); }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const data = {
        rule_id: form.rule_id, title: form.title, secret_type: form.secret_type,
        severity: form.severity, pattern: form.pattern,
        keywords: form.keywords ? form.keywords.split(",").map((k: string) => k.trim()).filter(Boolean) : [],
        confidence: Number(form.confidence), description: form.description,
        fix_hint: form.fix_hint, cwe: form.cwe, multiline: form.multiline,
      };
      if (editingId) { await updateCustomDetector(editingId, data); }
      else { await createCustomDetector(data); }
      setShowCreate(false); setEditingId(null); setForm({ ...emptyForm });
      setTestInput(""); setTestResults([]); setTestError("");
      fetchDetectors();
    } catch (e: any) { alert(e?.response?.data?.detail || "Failed to save"); }
    finally { setSaving(false); }
  };

  const handleEdit = (d: CustomDetector) => {
    setForm({
      rule_id: d.rule_id, title: d.title, secret_type: d.secret_type,
      severity: d.severity, pattern: d.pattern,
      keywords: (d.keywords || []).join(", "), confidence: d.confidence,
      description: d.description, fix_hint: d.fix_hint, cwe: d.cwe, multiline: d.multiline,
    });
    setEditingId(d.id); setShowCreate(true); setTestInput(""); setTestResults([]); setTestError("");
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this custom detector?")) return;
    try { await deleteCustomDetector(id); fetchDetectors(); } catch { alert("Delete failed"); }
  };

  const handleToggle = async (id: string) => {
    try { await toggleCustomDetector(id); fetchDetectors(); } catch { alert("Toggle failed"); }
  };

  const severityCount = (sev: string) => detectors.filter(d => d.severity === sev && d.is_enabled).length;

  return (
    <div className="space-y-6">
      {/* KPI Cards */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Total Detectors", value: stats.total_detectors, color: "text-white" },
          { label: "Active", value: stats.active_detectors, color: "text-emerald-400" },
          { label: "Total Matches", value: stats.total_matches, color: "text-red-400" },
          { label: "Critical / High", value: `${severityCount("critical")} / ${severityCount("high")}`, color: "text-red-400" },
        ].map((kpi, i) => (
          <div key={i} className="card p-4">
            <p className="text-xs text-slate-500 uppercase tracking-wider">{kpi.label}</p>
            <p className={`text-2xl font-bold mt-1 ${kpi.color}`}>{kpi.value}</p>
          </div>
        ))}
      </div>

      {/* Header + Create Button */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="relative">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
            <input type="text" placeholder="Search detectors..." value={search} onChange={e => { setSearch(e.target.value); setPage(1); }}
              className="input-dark w-64 pl-9" />
          </div>
          <select value={filterSeverity} onChange={e => { setFilterSeverity(e.target.value); setPage(1); }}
            className="select-dark">
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select value={filterStatus} onChange={e => { setFilterStatus(e.target.value); setPage(1); }}
            className="select-dark">
            <option value="">All Status</option>
            <option value="active">Active</option>
            <option value="disabled">Disabled</option>
          </select>
        </div>
        <button onClick={() => { setShowCreate(!showCreate); setEditingId(null); setForm({ ...emptyForm }); setTestInput(""); setTestResults([]); setTestError(""); }}
          className="btn-primary">
          {showCreate ? "Cancel" : "+ Create Detector"}
        </button>
      </div>

      {/* Create/Edit Form */}
      {showCreate && (
        <div className="card border-red-500/30 p-6 space-y-4">
          <h3 className="text-lg font-semibold text-white">{editingId ? "Edit" : "Create"} Custom Detector</h3>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Rule ID</label>
              <input type="text" value={form.rule_id} onChange={e => setForm({ ...form, rule_id: e.target.value })}
                placeholder="e.g. MYCOMPANY-API-KEY" disabled={!!editingId}
                className="input-dark w-full font-mono disabled:opacity-50" />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Title</label>
              <input type="text" value={form.title} onChange={e => setForm({ ...form, title: e.target.value })}
                placeholder="e.g. MyCompany API Key"
                className="input-dark w-full" />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Secret Type</label>
              <input type="text" value={form.secret_type} onChange={e => setForm({ ...form, secret_type: e.target.value })}
                placeholder="e.g. mycompany_api_key"
                className="input-dark w-full" />
            </div>
          </div>

          <div className="grid grid-cols-4 gap-4">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Severity</label>
              <select value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })}
                className="input-dark w-full">
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Confidence (0-1)</label>
              <input type="number" step="0.05" min="0" max="1" value={form.confidence}
                onChange={e => setForm({ ...form, confidence: parseFloat(e.target.value) || 0.9 })}
                className="input-dark w-full" />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">CWE</label>
              <input type="text" value={form.cwe} onChange={e => setForm({ ...form, cwe: e.target.value })}
                className="input-dark w-full" />
            </div>
            <div className="flex items-end gap-3">
              <label className="flex items-center gap-2 text-sm text-slate-300 cursor-pointer">
                <input type="checkbox" checked={form.multiline} onChange={e => setForm({ ...form, multiline: e.target.checked })}
                  className="rounded border-slate-600 bg-slate-800 text-red-500" />
                Multiline
              </label>
            </div>
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">Regex Pattern</label>
            <textarea value={form.pattern} onChange={e => setForm({ ...form, pattern: e.target.value })}
              placeholder="e.g. mycompany_sk_[a-zA-Z0-9]{32}" rows={2}
              className="input-dark w-full font-mono" />
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">Keywords (comma-separated, for pre-filtering)</label>
            <input type="text" value={form.keywords} onChange={e => setForm({ ...form, keywords: e.target.value })}
              placeholder="e.g. mycompany_sk_, mycompany"
              className="input-dark w-full" />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Description</label>
              <textarea value={form.description} onChange={e => setForm({ ...form, description: e.target.value })}
                placeholder="What does this detector find?" rows={2}
                className="input-dark w-full" />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Fix Hint</label>
              <textarea value={form.fix_hint} onChange={e => setForm({ ...form, fix_hint: e.target.value })}
                placeholder="How should the developer fix this?" rows={2}
                className="input-dark w-full" />
            </div>
          </div>

          {/* Regex Tester */}
          <div className="rounded-lg p-4 space-y-3 border border-white/[0.06]" style={{ background: "rgba(8,11,28,0.6)" }}>
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-semibold text-slate-300">Regex Tester</h4>
              <button onClick={handleTestRegex} disabled={testing || !form.pattern}
                className="btn-primary text-xs py-1.5 px-3 disabled:opacity-40">
                {testing ? "Testing..." : "Test Pattern"}
              </button>
            </div>
            <textarea value={testInput} onChange={e => setTestInput(e.target.value)}
              placeholder="Paste test strings here (one per line)..." rows={3}
              className="input-dark w-full font-mono" />
            {testError && <p className="text-sm text-red-400">{testError}</p>}
            {testResults.length > 0 && (
              <div className="space-y-1">
                {testResults.map((r, i) => (
                  <div key={i} className={`flex items-center gap-2 px-3 py-1.5 rounded text-sm font-mono ${r.matched ? "bg-emerald-500/10 text-emerald-400" : "bg-red-500/10 text-red-400"}`}>
                    <span>{r.matched ? "\u2714" : "\u2718"}</span>
                    <span className="truncate">{r.input}</span>
                    {r.matched && r.match_text && <span className="ml-auto text-xs text-slate-400">captured: {r.match_text}</span>}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="flex justify-end gap-3">
            <button onClick={() => { setShowCreate(false); setEditingId(null); }}
              className="btn-secondary">Cancel</button>
            <button onClick={handleSave} disabled={saving || !form.rule_id || !form.title || !form.pattern}
              className="btn-primary disabled:opacity-40">
              {saving ? "Saving..." : editingId ? "Update Detector" : "Create Detector"}
            </button>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="card p-0 overflow-hidden">
        <table className="glass-table w-full">
          <thead>
            <tr className="border-b border-white/[0.06] text-xs text-slate-400 uppercase tracking-wider">
              {[
                { key: "rule_id" as SortField, label: "Rule ID" },
                { key: "title" as SortField, label: "Title" },
                { key: "severity" as SortField, label: "Severity" },
                { key: "match_count" as SortField, label: "Matches" },
                { key: "is_enabled" as SortField, label: "Status" },
                { key: "created_at" as SortField, label: "Created" },
              ].map(col => (
                <th key={col.key} className="px-4 py-3 text-left cursor-pointer hover:text-white transition-colors" onClick={() => handleSort(col.key)}>
                  {col.label} {sortField === col.key && (sortDir === "asc" ? "\u25B2" : "\u25BC")}
                </th>
              ))}
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.04]">
            {loading ? (
              <tr><td colSpan={7} className="px-4 py-12 text-center text-slate-500">Loading...</td></tr>
            ) : processed.items.length === 0 ? (
              <tr><td colSpan={7} className="px-4 py-12 text-center text-slate-500">
                {detectors.length === 0 ? "No custom detectors yet. Click \"+ Create Detector\" to add one." : "No detectors match your filters."}
              </td></tr>
            ) : processed.items.map(d => {
              const sev = SEVERITY_STYLE[d.severity] || SEVERITY_STYLE.medium;
              return (
                <tr key={d.id} className="hover:bg-white/[0.02] transition-colors">
                  <td className="px-4 py-3 text-sm font-mono text-red-400">{d.rule_id}</td>
                  <td className="px-4 py-3">
                    <div className="text-sm text-white">{d.title}</div>
                    <div className="text-xs text-slate-500 font-mono truncate max-w-xs" title={d.pattern}>{d.pattern}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${sev.bg} ${sev.text}`}>{d.severity}</span>
                  </td>
                  <td className="px-4 py-3 text-sm text-slate-300">{d.match_count.toLocaleString()}</td>
                  <td className="px-4 py-3">
                    <button onClick={() => handleToggle(d.id)}
                      className={`px-2.5 py-0.5 rounded text-xs font-medium transition-colors cursor-pointer ${d.is_enabled ? "bg-emerald-500/15 text-emerald-400 hover:bg-emerald-500/25" : "bg-slate-600/30 text-slate-500 hover:bg-slate-600/50"}`}>
                      {d.is_enabled ? "Active" : "Disabled"}
                    </button>
                  </td>
                  <td className="px-4 py-3 text-sm text-slate-400">{new Date(d.created_at).toLocaleDateString()}</td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button onClick={() => handleEdit(d)} className="text-xs text-red-400 hover:text-red-300 transition-colors">Edit</button>
                      <button onClick={() => handleDelete(d.id)} className="text-xs text-red-400 hover:text-red-300 transition-colors">Delete</button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {/* Pagination */}
        {processed.totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-white/[0.06]">
            <span className="text-xs text-slate-500">{processed.total} detectors</span>
            <div className="flex items-center gap-1">
              {Array.from({ length: processed.totalPages }, (_, i) => (
                <button key={i} onClick={() => setPage(i + 1)}
                  className={`px-2.5 py-1 text-xs rounded ${page === i + 1 ? "bg-red-600 text-white" : "text-slate-400 hover:text-white hover:bg-slate-700/50"}`}>
                  {i + 1}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
