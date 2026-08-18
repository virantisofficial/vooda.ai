"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * Rule Overrides admin surface.
 *
 * Proactive counterpart to Suppressions: muting a scanner_rule_id for
 * one repo (or org-wide) so it never produces a finding in the first
 * place.  See apps/api/app/models/rule_override.py for the lifecycle
 * + audit reasoning behind splitting this from Suppressions.
 *
 * UX choices that mirror Snyk Code "Security Policies" and GHAS
 * "Custom Patterns":
 *   - Catalogue-driven picker (typeahead over GET /available-rules)
 *     so admins don't have to memorise rule IDs.
 *   - Required reason field.  We rely on the audit log to answer
 *     "why is rule X muted for repo Y?" months from now.
 *   - Soft-disable via is_active toggle is the default "un-mute"
 *     path; hard-delete is for cleaning up mistakes.
 *
 * The component is rendered both by /settings/admin?tab=rule_overrides
 * (full table) and embedded under the repo detail Settings tab via
 * a `repositoryFilter` prop that scopes the table + create form to a
 * single repo.
 */

import { useCallback, useEffect, useMemo, useState } from "react";

import {
  createRuleOverride,
  deleteRuleOverride,
  getAvailableRules,
  getRepositories,
  getRuleOverrideStats,
  getRuleOverrides,
  updateRuleOverride,
} from "@/lib/api";
import { Repository } from "@/types";

// ── Types ────────────────────────────────────────────────────────────

interface RuleOverride {
  id: string;
  scanner_rule_id: string;
  repository_id: string | null;
  repository_name: string | null;
  // Source-scope fields (added 2026-05-17 alongside the per-source
  // surface).  At most one of repository_* and scan_source_* is set
  // per row — mirrors the DB XOR constraint.
  scan_source_id: string | null;
  source_name: string | null;
  source_type: string | null;
  mode: string;
  reason: string | null;
  created_by: string | null;
  created_by_email: string | null;
  is_active: boolean;
  times_blocked: number;
  created_at: string;
  updated_at: string;
}

interface AvailableRule {
  rule_id: string;
  name: string;
  category: string | null;
  severity: string | null;
  description: string | null;
}

interface Stats {
  total_active: number;
  total_inactive: number;
  org_wide_active: number;
  repo_scoped_active: number;
  source_scoped_active: number;
  total_findings_blocked: number;
}

interface Props {
  /**
   * When provided, the table + Create modal are scoped to one repo.
   * The /repositories/[id] page passes this so the embedded card
   * shows only that repo's overrides + any org-wide overrides that
   * also apply to it.  Mutually exclusive with sourceFilter.
   */
  repositoryFilter?: { id: string; name: string };
  /**
   * When provided, the table + Create modal are scoped to one scan
   * source.  The /sources page passes this from the side-drawer so the
   * embedded card shows only that source's overrides + any org-wide
   * overrides that also apply to it.  Mutually exclusive with
   * repositoryFilter.
   */
  sourceFilter?: { id: string; name: string };
  /**
   * Embedded mode (per-repo / per-source card) hides the page header
   * to avoid a duplicate "Rule Overrides" title above the card frame.
   */
  embedded?: boolean;
}

const SEVERITY_STYLE: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10",
  high: "text-orange-400 bg-orange-500/10",
  medium: "text-yellow-400 bg-yellow-500/10",
  low: "text-blue-400 bg-blue-500/10",
  info: "text-slate-400 bg-slate-500/10",
};

// ── Component ────────────────────────────────────────────────────────

export function RuleOverridesContent({
  repositoryFilter,
  sourceFilter,
  embedded,
}: Props) {
  const [rules, setRules] = useState<RuleOverride[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [repos, setRepos] = useState<Repository[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters.  filterScope adds 'source' when not pre-filtered to a
  // specific repo/source.
  const [search, setSearch] = useState("");
  const [filterStatus, setFilterStatus] = useState<"" | "active" | "disabled">("");
  const [filterScope, setFilterScope] = useState<"" | "org" | "repo" | "source">("");

  // Create / edit modal state.  Empty formRepoId / formSourceId = org-wide.
  const [showCreate, setShowCreate] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [formRuleId, setFormRuleId] = useState("");
  const [formRepoId, setFormRepoId] = useState<string>("");
  const [formSourceId, setFormSourceId] = useState<string>("");
  const [formReason, setFormReason] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  // Rule picker typeahead
  const [picker, setPicker] = useState<AvailableRule[]>([]);
  const [pickerQuery, setPickerQuery] = useState("");
  const [pickerLoading, setPickerLoading] = useState(false);

  const fetchAll = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const params: Record<string, string | boolean> = {};
      if (repositoryFilter) {
        params.repository_id = repositoryFilter.id;
        params.include_org_wide = true;
      }
      if (sourceFilter) {
        params.scan_source_id = sourceFilter.id;
        params.include_org_wide = true;
      }
      // Only load the repo list for the picker if we're in the full-page
      // admin view (no pre-applied filter).  Embedded mode never needs it.
      const needRepoList = !repositoryFilter && !sourceFilter;
      const [rRules, rStats, rRepos] = await Promise.all([
        getRuleOverrides(params),
        getRuleOverrideStats(),
        needRepoList ? getRepositories() : Promise.resolve(null),
      ]);
      setRules(rRules.data || []);
      setStats(rStats.data || null);
      if (rRepos) {
        const data = rRepos.data;
        setRepos(
          Array.isArray(data)
            ? data
            : data?.items || data?.repositories || [],
        );
      }
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to load rule overrides.");
    } finally {
      setLoading(false);
    }
  }, [repositoryFilter, sourceFilter]);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  // Debounced typeahead for the rule picker
  useEffect(() => {
    if (!showCreate) return;
    const handle = setTimeout(async () => {
      try {
        setPickerLoading(true);
        const params: { q?: string } = {};
        if (pickerQuery.trim()) params.q = pickerQuery.trim();
        const r = await getAvailableRules(params);
        // Cap to 50 so the dropdown stays usable on slow machines.
        setPicker((r.data || []).slice(0, 50));
      } catch {
        setPicker([]);
      } finally {
        setPickerLoading(false);
      }
    }, 200);
    return () => clearTimeout(handle);
  }, [pickerQuery, showCreate]);

  const filtered = useMemo(() => {
    let items = [...rules];
    if (search) {
      const q = search.toLowerCase();
      items = items.filter(
        (r) =>
          r.scanner_rule_id.toLowerCase().includes(q) ||
          (r.reason || "").toLowerCase().includes(q) ||
          (r.repository_name || "").toLowerCase().includes(q) ||
          (r.source_name || "").toLowerCase().includes(q),
      );
    }
    if (filterStatus === "active") items = items.filter((r) => r.is_active);
    if (filterStatus === "disabled") items = items.filter((r) => !r.is_active);
    if (filterScope === "org") {
      // Org-wide = both target columns NULL.  Important to AND both,
      // not just check repository_id, else source-scoped rows would
      // leak in here when the FE forgets a column.
      items = items.filter(
        (r) => r.repository_id === null && r.scan_source_id === null,
      );
    } else if (filterScope === "repo") {
      items = items.filter((r) => r.repository_id !== null);
    } else if (filterScope === "source") {
      items = items.filter((r) => r.scan_source_id !== null);
    }
    // Stable order: org-wide first, then repo-scoped, then source-scoped,
    // each section newest-first by created_at.  Gives admins a
    // predictable "broadest impact at the top" reading order.
    const scopeRank = (r: RuleOverride): number =>
      r.repository_id === null && r.scan_source_id === null
        ? 0
        : r.repository_id !== null
          ? 1
          : 2;
    items.sort((a, b) => {
      const sr = scopeRank(a) - scopeRank(b);
      if (sr !== 0) return sr;
      return b.created_at.localeCompare(a.created_at);
    });
    return items;
  }, [rules, search, filterStatus, filterScope]);

  const resetForm = () => {
    setFormRuleId("");
    setFormRepoId(repositoryFilter?.id || "");
    setFormSourceId(sourceFilter?.id || "");
    setFormReason("");
    setFormError(null);
    setPickerQuery("");
    setEditingId(null);
  };

  const openCreate = () => {
    resetForm();
    setShowCreate(true);
  };

  const startEdit = (r: RuleOverride) => {
    setEditingId(r.id);
    setFormRuleId(r.scanner_rule_id);
    setFormRepoId(r.repository_id || "");
    setFormSourceId(r.scan_source_id || "");
    setFormReason(r.reason || "");
    setFormError(null);
    setShowCreate(true);
  };

  const handleSubmit = async () => {
    setFormError(null);
    const ruleId = formRuleId.trim();
    const reason = formReason.trim();
    if (!ruleId) {
      setFormError("Pick a scanner rule to mute.");
      return;
    }
    if (!reason) {
      setFormError("Reason is required so the audit trail is useful.");
      return;
    }
    try {
      if (editingId) {
        // Only `reason` and `is_active` are editable for an existing
        // override — rule_id + scope are immutable to keep the audit
        // log on a single row.
        await updateRuleOverride(editingId, { reason });
      } else {
        // Scope is determined by which target id (if any) is set.
        // The Pydantic model_validator on the API side rejects the
        // both-set case so we don't have to guard it again here, but
        // do it defensively anyway.
        if (formRepoId && formSourceId) {
          setFormError(
            "An override can scope to a repository OR a scan source, not both.",
          );
          return;
        }
        await createRuleOverride({
          scanner_rule_id: ruleId,
          repository_id: formRepoId || null,
          scan_source_id: formSourceId || null,
          mode: "disabled",
          reason,
        });
      }
      setShowCreate(false);
      resetForm();
      fetchAll();
    } catch (e: any) {
      setFormError(e?.response?.data?.detail || "Save failed.");
    }
  };

  const handleToggle = async (r: RuleOverride) => {
    try {
      await updateRuleOverride(r.id, { is_active: !r.is_active });
      fetchAll();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Toggle failed.");
    }
  };

  const handleDelete = async (r: RuleOverride) => {
    if (
      !confirm(
        `Permanently delete the override for ${r.scanner_rule_id}? ` +
          `Prefer the toggle above if you want to keep the audit trail.`,
      )
    ) {
      return;
    }
    try {
      await deleteRuleOverride(r.id);
      fetchAll();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Delete failed.");
    }
  };

  return (
    <div className="space-y-5 max-w-[1600px]">
      {/* Page header — hidden in embedded (per-repo card) mode. */}
      {!embedded && (
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <h1 className="text-2xl font-bold text-white">Rule Overrides</h1>
            <p className="text-sm text-slate-400 mt-1">
              Stop a specific scanner rule from firing — for one repo, or org-wide.
              Different from Suppressions (which mute findings <em>after</em> they land).
            </p>
          </div>
          <button onClick={openCreate} className="btn-primary">
            Add Override
          </button>
        </div>
      )}

      {/* Embedded mode: header lives inside the card.  Copy adapts to
          whichever scope filter is in effect. */}
      {embedded && (
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">Rule Overrides</h3>
            <p className="text-xs text-slate-500 mt-0.5">
              {sourceFilter
                ? `Mute specific scanner rules for ${sourceFilter.name}. Org-wide overrides also shown.`
                : `Mute specific scanner rules for ${repositoryFilter?.name || "this target"}. Org-wide overrides also shown.`}
            </p>
          </div>
          <button onClick={openCreate} className="btn-secondary text-xs">
            Add Override
          </button>
        </div>
      )}

      {/* KPI cards — full-page mode only */}
      {!embedded && stats && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
          <div className="card p-4">
            <p className="text-xs text-slate-500 uppercase">Active Overrides</p>
            <p className="text-2xl font-bold text-white mt-1">{stats.total_active}</p>
          </div>
          <div className="card p-4">
            <p className="text-xs text-amber-400 uppercase">Org-wide</p>
            <p className="text-2xl font-bold text-amber-400 mt-1">{stats.org_wide_active}</p>
          </div>
          <div className="card p-4">
            <p className="text-xs text-violet-400 uppercase">Per-repo</p>
            <p className="text-2xl font-bold text-violet-400 mt-1">{stats.repo_scoped_active}</p>
          </div>
          <div className="card p-4">
            <p className="text-xs text-cyan-400 uppercase">Per-source</p>
            <p className="text-2xl font-bold text-cyan-400 mt-1">
              {stats.source_scoped_active ?? 0}
            </p>
          </div>
          <div className="card p-4">
            <p className="text-xs text-emerald-400 uppercase">Findings Blocked</p>
            <p className="text-2xl font-bold text-emerald-400 mt-1">
              {stats.total_findings_blocked.toLocaleString()}
            </p>
          </div>
        </div>
      )}

      {error && (
        <div className="card border-red-500/30 bg-red-500/5 text-xs text-red-300 px-4 py-2">
          {error}
        </div>
      )}

      {/* Create / edit form */}
      {showCreate && (
        <div className="card border-violet-500/20">
          <h3 className="text-sm font-semibold text-white mb-4">
            {editingId ? "Edit Override" : "New Override"}
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="md:col-span-2">
              <label className="text-xs text-slate-400 block mb-1">Scanner Rule *</label>
              <input
                value={pickerQuery || formRuleId}
                onChange={(e) => {
                  setPickerQuery(e.target.value);
                  setFormRuleId("");
                }}
                disabled={!!editingId}
                className="input-dark w-full"
                placeholder="Search by rule ID or name (e.g. AWS or VOODA-SEC-AWS-001)"
              />
              {!editingId && pickerQuery && (
                <div className="mt-1 max-h-60 overflow-y-auto rounded border border-white/[0.06] bg-dark-900">
                  {pickerLoading ? (
                    <div className="px-3 py-2 text-xs text-slate-500">Loading…</div>
                  ) : picker.length === 0 ? (
                    <div className="px-3 py-2 text-xs text-slate-500">No matching rules.</div>
                  ) : (
                    picker.map((r) => (
                      <button
                        key={r.rule_id}
                        type="button"
                        onClick={() => {
                          setFormRuleId(r.rule_id);
                          setPickerQuery(r.rule_id);
                        }}
                        className="w-full text-left px-3 py-2 hover:bg-white/[0.04] border-b border-white/[0.03] last:border-0"
                      >
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[10px] text-violet-400">
                            {r.rule_id}
                          </span>
                          {r.severity && (
                            <span
                              className={`text-[9px] px-1.5 py-0.5 rounded ${
                                SEVERITY_STYLE[r.severity] || "text-slate-400 bg-slate-500/10"
                              }`}
                            >
                              {r.severity}
                            </span>
                          )}
                        </div>
                        <div className="text-xs text-slate-300 mt-0.5">{r.name}</div>
                      </button>
                    ))
                  )}
                </div>
              )}
              {formRuleId && !pickerQuery && (
                <p className="text-[10px] text-slate-500 mt-1">
                  Selected: <span className="font-mono text-violet-400">{formRuleId}</span>
                </p>
              )}
            </div>

            <div>
              <label className="text-xs text-slate-400 block mb-1">Scope</label>
              {/* Embedded mode (per-repo OR per-source card): the scope
                  is locked to the surrounding context.  Show a single
                  disabled select that reads back the pre-filled target. */}
              {sourceFilter ? (
                <select
                  value={formSourceId}
                  onChange={(e) => setFormSourceId(e.target.value)}
                  disabled
                  className="input-dark w-full"
                >
                  <option value={sourceFilter.id}>
                    Source: {sourceFilter.name}
                  </option>
                </select>
              ) : repositoryFilter ? (
                <select
                  value={formRepoId}
                  onChange={(e) => setFormRepoId(e.target.value)}
                  disabled
                  className="input-dark w-full"
                >
                  <option value={repositoryFilter.id}>
                    Repository: {repositoryFilter.name}
                  </option>
                </select>
              ) : (
                /* Full-page admin view: pick org-wide OR any repo (the
                    source picker isn't exposed here yet — admins reach
                    per-source overrides from the source detail drawer). */
                <select
                  value={formRepoId}
                  onChange={(e) => {
                    setFormRepoId(e.target.value);
                    // Repos and sources are mutually exclusive; clear
                    // the other.
                    if (e.target.value) setFormSourceId("");
                  }}
                  disabled={!!editingId}
                  className="input-dark w-full"
                >
                  <option value="">Org-wide (every scan target)</option>
                  {repos.map((r) => (
                    <option key={r.id} value={r.id}>
                      Repository: {r.name}
                    </option>
                  ))}
                </select>
              )}
              {editingId && (
                <p className="text-[10px] text-slate-500 mt-1">
                  Scope is immutable — delete + recreate to move an override.
                </p>
              )}
            </div>

            <div className="md:col-span-2">
              <label className="text-xs text-slate-400 block mb-1">Reason *</label>
              <textarea
                value={formReason}
                onChange={(e) => setFormReason(e.target.value)}
                className="input-dark w-full h-20 resize-none"
                placeholder="Why is this rule muted?  Visible in the audit log."
              />
            </div>
          </div>

          {formError && (
            <p className="text-xs text-red-400 mt-3">{formError}</p>
          )}

          <div className="flex gap-2 mt-4">
            <button onClick={handleSubmit} className="btn-primary">
              {editingId ? "Save Changes" : "Create Override"}
            </button>
            <button
              onClick={() => {
                setShowCreate(false);
                resetForm();
              }}
              className="btn-secondary"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Filter strip */}
      <div className="card">
        <div className="flex gap-3 items-center flex-wrap mb-4">
          <div className="relative flex-1 max-w-xs">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input-dark w-full"
              placeholder="Search rule ID, reason, repo…"
            />
          </div>
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value as any)}
            className="select-dark text-xs"
          >
            <option value="">All Statuses</option>
            <option value="active">Active</option>
            <option value="disabled">Disabled</option>
          </select>
          {!repositoryFilter && !sourceFilter && (
            <select
              value={filterScope}
              onChange={(e) => setFilterScope(e.target.value as any)}
              className="select-dark text-xs"
            >
              <option value="">All Scopes</option>
              <option value="org">Org-wide</option>
              <option value="repo">Per-repo</option>
              <option value="source">Per-source</option>
            </select>
          )}
          <div className="flex-1" />
          <span className="text-[10px] text-slate-500">
            {filtered.length} override{filtered.length !== 1 ? "s" : ""}
          </span>
        </div>

        {/* Table */}
        {loading ? (
          <div className="text-center py-12 text-slate-500">Loading overrides…</div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-12 text-slate-500">
            {rules.length === 0
              ? "No rule overrides yet.  Add one to silence a noisy scanner rule."
              : "No overrides match the filters."}
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/[0.06]">
                <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Rule</th>
                <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Scope</th>
                <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Reason</th>
                <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Blocked</th>
                <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Created</th>
                <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Status</th>
                <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r) => {
                // Three scope cases: org-wide (both target columns NULL),
                // repo-scoped, source-scoped.  The pill colour + label
                // doubles as visual at-a-glance grouping.
                let scopeLabel: string;
                let scopeClass: string;
                if (r.repository_id !== null) {
                  scopeLabel =
                    "Repo: " +
                    (r.repository_name || r.repository_id.slice(0, 8));
                  scopeClass = "bg-violet-500/15 text-violet-400";
                } else if (r.scan_source_id !== null) {
                  const typeLabel = r.source_type
                    ? r.source_type.replace(/_/g, " ")
                    : "Source";
                  scopeLabel =
                    `${typeLabel}: ` +
                    (r.source_name || r.scan_source_id.slice(0, 8));
                  scopeClass = "bg-cyan-500/15 text-cyan-400";
                } else {
                  scopeLabel = "Org-wide";
                  scopeClass = "bg-amber-500/15 text-amber-400";
                }
                const created = r.created_at
                  ? new Date(r.created_at).toLocaleDateString()
                  : "—";
                return (
                  <tr
                    key={r.id}
                    className="border-b border-white/[0.03] hover:bg-white/[0.02]"
                  >
                    <td className="py-2.5 px-3 font-mono text-[11px] text-violet-400">
                      {r.scanner_rule_id}
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded ${scopeClass}`}
                      >
                        {scopeLabel}
                      </span>
                    </td>
                    <td
                      className="py-2.5 px-3 text-[11px] text-slate-400 max-w-[260px] truncate"
                      title={r.reason || ""}
                    >
                      {r.reason || "—"}
                    </td>
                    <td className="py-2.5 px-3 text-xs text-emerald-400 font-mono">
                      {r.times_blocked.toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3 text-[10px] text-slate-600">
                      <div>{created}</div>
                      <div className="text-slate-700">{r.created_by_email || ""}</div>
                    </td>
                    <td className="py-2.5 px-3">
                      <button
                        onClick={() => handleToggle(r)}
                        className={`text-[10px] px-2.5 py-1 rounded cursor-pointer ${
                          r.is_active
                            ? "bg-green-500/15 text-green-400 hover:bg-green-500/25"
                            : "bg-slate-500/10 text-slate-500 hover:bg-slate-500/20"
                        }`}
                      >
                        {r.is_active ? "Active" : "Disabled"}
                      </button>
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="flex gap-2">
                        <button
                          onClick={() => startEdit(r)}
                          className="text-[10px] text-violet-400 hover:text-violet-300"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleDelete(r)}
                          className="text-[10px] text-red-400 hover:text-red-300"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
