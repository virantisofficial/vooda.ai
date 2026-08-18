"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * IncidentsView — alternate render of /findings page when the user
 * toggles "Incidents" view.
 *
 * Same conceptual data as findings, but aggregated: 1 row per unique
 * credential (vs. 1 row per location).  Sourced from GET /incidents
 * (not /findings) so the row carries SecretIncident-specific fields
 * (occurrence_count, rotation_status, rotated_at, severity_max).
 *
 * Designed to live as a sibling render in /findings — it reads the
 * parent's filter state for the filters it can honor, manages its own
 * selection + pagination, and opens IncidentDetailDrawer for row
 * clicks.  Mark-rotated bulk action lives in this component because
 * "rotation" is per-credential, not per-location.
 */

import { useCallback, useEffect, useMemo, useState } from "react";

import { IncidentDetailDrawer } from "@/components/incidents/IncidentDetailDrawer";
import { ExportDropdown } from "@/components/findings/ExportDropdown";
import { useToast } from "@/components/ui/Toast";
import { bulkMarkIncidentsRotated, bulkTriageIncidents, getIncidents } from "@/lib/api";

// Bulk-triage action vocabulary — same 6 actions as the
// IncidentDetailDrawer's status dropdown, in the same order, with
// the same colour palette.  Keeps the two surfaces visually
// consistent so the user doesn't have to relearn what each action
// does when switching between drawer triage and bulk triage.
//
// `confirm` flags the action as needing the inline two-step
// confirmation pattern (rotate-once-kill-many is irreversible at
// MTTR-event scale; reopen is a "go back to inbox" action that's
// easy to do by accident).  Other actions commit immediately on
// click — comment is optional, count is shown, no friction needed.
const INCIDENT_BULK_ACTIONS: ReadonlyArray<{
  action: string;
  label: string;
  color: string;
  confirm?: boolean;
}> = [
  { action: "mark_tp",      label: "True Positive",       color: "bg-red-500/15 text-red-300 hover:bg-red-500/25 border-red-500/30" },
  { action: "mark_fp",      label: "False Positive",      color: "bg-slate-500/15 text-slate-300 hover:bg-slate-500/25 border-slate-500/30" },
  { action: "mark_test",    label: "Test Credential",     color: "bg-blue-500/15 text-blue-300 hover:bg-blue-500/25 border-blue-500/30" },
  { action: "accept_risk",  label: "Accepted Risk",       color: "bg-orange-500/15 text-orange-300 hover:bg-orange-500/25 border-orange-500/30" },
  { action: "mark_rotated", label: "Rotated / Revoked",   color: "bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25 border-emerald-500/30", confirm: true },
  { action: "reopen",       label: "Re-open",             color: "bg-yellow-500/15 text-yellow-300 hover:bg-yellow-500/25 border-yellow-500/30", confirm: true },
];

interface Incident {
  id: string;
  title: string;
  secret_type: string | null;
  masked_value: string | null;
  severity_max: string;
  occurrence_count: number;
  classification: string;
  review_status: string;
  validation_status: string | null;
  rotation_status: string | null;
  rotated_at: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
}

interface Props {
  /** Initial filter seed bubbled up from /findings page.  IncidentsView
   *  manages its own filter state from here on so it can render the
   *  filter strip inside the Incidents surface (the parent's filter
   *  bar is Findings-specific and lives below the gate). */
  filters: {
    severity?: string;
    classification?: string;
    validation_status?: string;
    search?: string;
  };
  /** Re-fetch trigger from parent (e.g. when filters change). */
  refreshKey?: number;
  /** Optional View button slot — the parent /findings page constructs
   *  the View dropdown (which contains the Findings/Incidents radio)
   *  and passes it down so it appears INLINE at the end of the
   *  Incidents filter strip, matching the position it occupies in
   *  Findings view.  Without this, users would have no in-page way to
   *  switch back to Findings without editing the URL. */
  viewButton?: React.ReactNode;
  /** Mirrors the Findings page toggle.  When true, includes incidents
   *  whose occurrences sit in archived repos / sources (which are
   *  hidden by default to keep the working surface focused on active
   *  risk).  Wired to the /incidents endpoint's include_archived_sources
   *  query param. */
  includeArchivedSources?: boolean;
  /** Per-column visibility map from the parent's View menu.  Lets
   *  users hide table columns they don't care about — same pattern
   *  as the Findings table.  When omitted, all columns are shown. */
  visibleColumns?: {
    severity?: boolean;
    occurrences?: boolean;
    status?: boolean;
    validity?: boolean;
    rotation?: boolean;
    last_seen?: boolean;
  };
}

const SEVERITY_PILL: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/20",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/20",
  medium: "bg-amber-500/15 text-amber-400 border-amber-500/20",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/20",
  info: "bg-slate-500/15 text-slate-400 border-slate-500/20",
};

function fmtAge(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return "—";
  const diff = (Date.now() - t) / 1000;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 86400 * 7) return `${Math.floor(diff / 86400)}d ago`;
  return new Date(iso).toLocaleDateString();
}

export function IncidentsView({
  filters: seedFilters,
  refreshKey,
  viewButton,
  includeArchivedSources = false,
  visibleColumns,
}: Props) {
  // Normalise the visibility map so undefined keys (e.g. caller passes
  // only `severity`) default to true.  Keeps the conditional column
  // renders below readable.
  const cols = {
    severity:    visibleColumns?.severity    ?? true,
    occurrences: visibleColumns?.occurrences ?? true,
    status:      visibleColumns?.status      ?? true,
    validity:    visibleColumns?.validity    ?? true,
    rotation:    visibleColumns?.rotation    ?? true,
    last_seen:   visibleColumns?.last_seen   ?? true,
  };
  const [items, setItems] = useState<Incident[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(50);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Self-managed filter state.  Seeded from the parent's Findings
  // filter state on first mount so a user toggling Findings → Incidents
  // doesn't lose their search/severity choices, but rendered + edited
  // inside this component so the filter UI is actually visible (the
  // parent's findings filter strip is gated to viewMode === "findings"
  // and would otherwise hide while Incidents is active).
  const [search, setSearch] = useState(seedFilters.search || "");
  const [severity, setSeverity] = useState(seedFilters.severity || "");
  const [classification, setClassification] = useState(seedFilters.classification || "");
  const [validation, setValidation] = useState(seedFilters.validation_status || "");
  const [rotation, setRotation] = useState<string>("");
  // "Show dead credentials" — when off (default), the server hides incidents
  // whose credential was verified DEAD (validation_status="inactive"). The
  // hiddenInactive count surfaces how many are hidden so the suppression is
  // transparent rather than findings silently vanishing.
  const [showDead, setShowDead] = useState(false);
  const [hiddenInactive, setHiddenInactive] = useState(0);

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [openIncident, setOpenIncident] = useState<string | null>(null);
  const [bulkBusy, setBulkBusy] = useState(false);
  // Optional comment ridden along to each per-incident audit entry —
  // gives compliance the "why" for bulk decisions ("marked 200 as FP
  // because the auto-detection rule was updated to ignore staging").
  const [bulkComment, setBulkComment] = useState("");
  // Two-step confirmation for irreversible bulk actions (mark_rotated,
  // reopen).  Holds the action that's awaiting confirm; null means
  // nothing pending.  First click flips this; second click commits.
  // Replaces the native window.confirm() that broke automation +
  // looked unstyled.
  const [pendingBulk, setPendingBulk] = useState<string | null>(null);
  const { toast } = useToast();

  const fetchItems = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const params: Record<string, string | number | boolean> = {
        page,
        page_size: pageSize,
      };
      if (severity) params.severity_max = severity;
      if (classification) params.classification = classification;
      if (validation) params.validation_status = validation;
      if (rotation) params.rotation_status = rotation;
      if (search) params.search = search;
      // Default is server-side false (hide archived); we only set it
      // when the user has explicitly toggled it on so the URL stays
      // clean in the common case.
      if (includeArchivedSources) params.include_archived_sources = true;
      // Default false: server hides verified-dead incidents. Only set when the
      // user opts in, so the URL stays clean in the common case.
      if (showDead) params.include_inactive = true;
      const r = await getIncidents(params);
      const d = r.data as { items: Incident[]; total: number; hidden_inactive?: number };
      setItems(d.items || []);
      setTotal(d.total || 0);
      setHiddenInactive(d.hidden_inactive || 0);
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to load incidents.");
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, severity, classification, validation, rotation, search, includeArchivedSources, showDead]);

  useEffect(() => {
    fetchItems();
  }, [fetchItems, refreshKey]);

  // Reset page + selection when filters change.
  useEffect(() => {
    setPage(1);
    setSelected(new Set());
    setBulkComment("");
    setPendingBulk(null);
  }, [severity, classification, validation, rotation, search]);

  // Also reset the pending-confirm state when the selection itself
  // empties out (user clicked Clear or finished a successful action)
  // so the inline confirm UI doesn't survive into the next selection.
  useEffect(() => {
    if (selected.size === 0) {
      setPendingBulk(null);
      setBulkComment("");
    }
  }, [selected.size]);

  const allOnPageSelected = items.length > 0 && items.every((i) => selected.has(i.id));

  const toggleSelectAll = () => {
    if (allOnPageSelected) {
      setSelected(new Set());
    } else {
      setSelected(new Set(items.map((i) => i.id)));
    }
  };

  const toggleOne = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // Bulk triage handler — single entry point for all 6 actions in
  // the action bar.  Two-step confirm for actions marked
  // confirm=true (mark_rotated, reopen); direct commit for the rest
  // (with the optional comment field giving the user a moment to
  // think regardless).  mark_rotated routes through the dedicated
  // /bulk-mark-rotated endpoint so MTTR analytics + per-incident
  // CredentialRotationEvent rows still get written — the generic
  // /bulk-triage endpoint deliberately does not.
  const handleBulkAction = async (action: string) => {
    const ids = Array.from(selected);
    if (!ids.length) return;
    const spec = INCIDENT_BULK_ACTIONS.find((a) => a.action === action);
    if (!spec) return;

    // First click on a confirm-required action: stage the confirm.
    if (spec.confirm && pendingBulk !== action) {
      setPendingBulk(action);
      return;
    }

    try {
      setBulkBusy(true);
      const trimmedComment = bulkComment.trim() || undefined;
      if (action === "mark_rotated") {
        // Route through the MTTR-aware endpoint — same as the
        // dedicated "Mark rotated" path used to do.  Note doubles as
        // both the bulk comment + the MTTR-event "note".
        const r = await bulkMarkIncidentsRotated(ids, trimmedComment);
        const d = r.data as { rotated: number; already_rotated: number; not_found: number };
        toast(
          "success",
          "Incidents marked as rotated",
          `${d.rotated} newly rotated`
            + (d.already_rotated ? ` · ${d.already_rotated} already rotated` : "")
            + (d.not_found ? ` · ${d.not_found} not found` : ""),
        );
      } else {
        const r = await bulkTriageIncidents(ids, action, trimmedComment);
        const d = r.data as {
          updated: number;
          unchanged: number;
          not_found: number;
          cascaded_findings: number;
        };
        toast(
          "success",
          `Bulk ${spec.label}`,
          `${d.updated} updated`
            + (d.unchanged ? ` · ${d.unchanged} already in state` : "")
            + (d.not_found ? ` · ${d.not_found} not found` : "")
            + (d.cascaded_findings ? ` · ${d.cascaded_findings} occurrences cascaded` : ""),
        );
      }
      setSelected(new Set());
      setBulkComment("");
      setPendingBulk(null);
      fetchItems();
    } catch (e: any) {
      toast("error", "Bulk action failed", e?.response?.data?.detail || "Could not apply triage.");
    } finally {
      setBulkBusy(false);
    }
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const startIdx = total > 0 ? (page - 1) * pageSize + 1 : 0;
  const endIdx = Math.min(page * pageSize, total);

  const anyFilterActive = !!(search || severity || classification || validation || rotation);

  return (
    <div className="space-y-3">
      {error && (
        <div className="rounded border border-red-500/30 bg-red-500/[0.06] px-3 py-2 text-xs text-red-300">
          {error}
        </div>
      )}

      {/* Sub-header — result count + clear-filters link.  Always shown
          so the user can see how many incidents the current filters
          return (the Findings view has this; Incidents was missing it
          when totalPages == 1, which made the page feel empty). */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <p className="text-sm text-slate-400">
          {total > 0
            ? `${startIdx}–${endIdx} of ${total} incident${total === 1 ? "" : "s"}`
            : "0 incidents"}
        </p>
        <div className="flex items-center gap-3">
          {/* Verified-dead suppression transparency: surface how many
              incidents are hidden because their credential was confirmed DEAD,
              with a one-click toggle to reveal/hide them. Shown whenever there
              are hidden dead credentials OR the user has revealed them. */}
          {(hiddenInactive > 0 || showDead) && (
            <button
              onClick={() => { setShowDead((v) => !v); setPage(1); }}
              className="inline-flex items-center gap-1.5 text-xs px-2 py-1 rounded-md border border-slate-700 text-slate-300 hover:bg-slate-800 transition-colors"
              title="Incidents whose credential was verified dead (inactive) are hidden from the active-risk view by default."
            >
              {showDead
                ? "Hide dead credentials"
                : `Show ${hiddenInactive} dead credential${hiddenInactive === 1 ? "" : "s"}`}
            </button>
          )}
          {anyFilterActive && (
            <button
              onClick={() => {
                setSearch("");
                setSeverity("");
                setClassification("");
                setValidation("");
                setRotation("");
              }}
              className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
            >
              Clear all filters
            </button>
          )}
        </div>
      </div>

      {/* Filter strip — Incidents-specific axes.  Mirrors the
          Findings filter strip shape (search + selects) so the two
          views look like siblings rather than separate products. */}
      <div className="flex gap-3 items-center flex-wrap">
        <div className="relative flex-1 max-w-xs">
          <svg
            className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            placeholder="Search secrets..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input-dark pl-10"
          />
        </div>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="select-dark">
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select value={classification} onChange={(e) => setClassification(e.target.value)} className="select-dark">
          <option value="">All Statuses</option>
          <option value="needs_review">Needs Review</option>
          <option value="true_positive">True Positive</option>
          <option value="false_positive">False Positive</option>
          <option value="accepted_risk">Accepted Risk</option>
        </select>
        <select value={validation} onChange={(e) => setValidation(e.target.value)} className="select-dark">
          <option value="">All Validity</option>
          <option value="active">Active</option>
          <option value="inactive">Inactive</option>
        </select>
        <select value={rotation} onChange={(e) => setRotation(e.target.value)} className="select-dark">
          <option value="">All Rotation</option>
          <option value="not_rotated">Not rotated</option>
          <option value="rotated">Rotated</option>
        </select>
        {/* View + Export — inline at the end of the filter strip,
            matching the position they occupy in Findings view.
            View comes from the parent (so the dropdown state lives at
            the page level); Export is mounted here with the LIVE
            local filter state so the CSV reflects exactly what the
            user sees on screen. */}
        <div className="ml-auto flex items-center gap-2">
          {viewButton}
          <ExportDropdown
            kind="incidents"
            filters={{
              severity_max: severity,
              classification,
              validation_status: validation,
              rotation_status: rotation,
              search,
            }}
          />
        </div>
      </div>

      {/* Bulk-actions bar — only shown when something's selected.
          Mirrors the IncidentDetailDrawer's triage vocabulary so the
          two surfaces commit identical state for the same action.
          Two rows so the comment field has room to breathe and the
          six action buttons don't get cramped at narrow viewports. */}
      {selected.size > 0 && (
        <div className="px-3 py-2.5 rounded-lg bg-red-500/[0.04] border border-red-500/15 space-y-2">
          {/* Row 1: count + optional comment + clear */}
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-xs text-red-300 font-semibold shrink-0">{selected.size} selected</span>
            <input
              type="text"
              value={bulkComment}
              onChange={(e) => setBulkComment(e.target.value)}
              placeholder="Add a comment (optional) — joins the audit log"
              disabled={bulkBusy}
              className="input-dark text-xs flex-1 min-w-[200px]"
            />
            <button
              onClick={() => setSelected(new Set())}
              className="text-[11px] text-slate-500 hover:text-slate-300 shrink-0"
              disabled={bulkBusy}
            >
              Clear selection
            </button>
          </div>

          {/* Pending-confirm notice — only when the user clicked a
              confirm-required action.  Amber to draw the eye; the
              same button click commits on the second press. */}
          {pendingBulk && (() => {
            const spec = INCIDENT_BULK_ACTIONS.find((a) => a.action === pendingBulk);
            const isRotate = pendingBulk === "mark_rotated";
            return (
              <div className="rounded border border-amber-500/30 bg-amber-500/[0.06] px-3 py-2 text-[11px] text-amber-200 leading-relaxed flex items-center gap-3">
                <span className="flex-1">
                  About to mark <span className="font-semibold">{selected.size}</span> incident{selected.size === 1 ? "" : "s"} as{" "}
                  <span className="font-semibold">{spec?.label}</span>.{" "}
                  {isRotate && "Each will record a CredentialRotationEvent for MTTR analytics. "}
                  Click <span className="font-semibold">{spec?.label}</span> again to commit.
                </span>
                <button
                  onClick={() => setPendingBulk(null)}
                  className="text-[11px] text-slate-400 hover:text-slate-200 shrink-0"
                  disabled={bulkBusy}
                >
                  Cancel
                </button>
              </div>
            );
          })()}

          {/* Row 2: six action buttons */}
          <div className="flex items-center gap-2 flex-wrap">
            {INCIDENT_BULK_ACTIONS.map((a) => {
              const isPending = pendingBulk === a.action;
              return (
                <button
                  key={a.action}
                  onClick={() => handleBulkAction(a.action)}
                  disabled={bulkBusy}
                  className={`inline-flex items-center gap-1.5 text-[11px] px-2.5 py-1.5 rounded-md border font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${a.color} ${
                    isPending ? "ring-1 ring-amber-500/50 [border-style:dashed]" : ""
                  }`}
                >
                  {bulkBusy && isPending && (
                    <span className="w-2.5 h-2.5 border-[1.5px] border-current/30 border-t-current rounded-full animate-spin" />
                  )}
                  {isPending ? `Confirm ${a.label}` : a.label}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Table */}
      <div className="card overflow-hidden p-0">
        {loading ? (
          <p className="text-xs text-slate-500 text-center py-16">Loading incidents…</p>
        ) : items.length === 0 ? (
          <p className="text-xs text-slate-500 text-center py-16">
            No incidents match the current filters.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/[0.06]">
                <th className="py-3 px-3 w-8">
                  <input
                    type="checkbox"
                    checked={allOnPageSelected}
                    onChange={toggleSelectAll}
                    className="w-3.5 h-3.5 rounded border-slate-600 bg-dark-950 text-emerald-500 cursor-pointer"
                  />
                </th>
                {/* Secret column is always visible — it's the primary
                    row identifier (same contract as the Findings table
                    where the Secret column isn't toggleable either). */}
                <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Secret</th>
                {cols.severity && <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Severity</th>}
                {cols.occurrences && <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Occurrences</th>}
                {cols.status && <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Status</th>}
                {cols.validity && <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Validity</th>}
                {cols.rotation && <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Rotation</th>}
                {cols.last_seen && <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Last seen</th>}
              </tr>
            </thead>
            <tbody>
              {items.map((inc) => {
                const sevPill = SEVERITY_PILL[inc.severity_max.toLowerCase()] || SEVERITY_PILL.info;
                const rotated = (inc.rotation_status || "").toLowerCase() === "rotated";
                return (
                  <tr
                    key={inc.id}
                    onClick={() => setOpenIncident(inc.id)}
                    className={`border-b border-white/[0.03] hover:bg-white/[0.02] cursor-pointer transition-colors ${
                      selected.has(inc.id) ? "bg-emerald-500/[0.04]" : ""
                    }`}
                  >
                    <td className="py-2.5 px-3" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selected.has(inc.id)}
                        onChange={() => toggleOne(inc.id)}
                        className="w-3.5 h-3.5 rounded border-slate-600 bg-dark-950 text-emerald-500 cursor-pointer"
                      />
                    </td>
                    <td className="py-2.5 px-3 max-w-[300px]">
                      <p className="text-xs font-mono text-slate-200 truncate" title={inc.masked_value || inc.title}>
                        {inc.masked_value || inc.title}
                      </p>
                      {inc.secret_type && (
                        <p className="text-[10px] text-slate-500 mt-0.5 truncate">{inc.secret_type}</p>
                      )}
                    </td>
                    {cols.severity && (
                      <td className="py-2.5 px-3">
                        <span className={`text-[10px] px-2 py-0.5 rounded border uppercase ${sevPill}`}>
                          {inc.severity_max}
                        </span>
                      </td>
                    )}
                    {cols.occurrences && (
                      <td className="py-2.5 px-3">
                        <span className="text-xs text-slate-300 font-medium">
                          {inc.occurrence_count}
                        </span>
                        <span className="text-[10px] text-slate-500 ml-1">
                          location{inc.occurrence_count === 1 ? "" : "s"}
                        </span>
                      </td>
                    )}
                    {cols.status && (
                      <td className="py-2.5 px-3">
                        <span className="text-[10px] text-slate-400 capitalize">
                          {(inc.classification || "").replace(/_/g, " ")}
                        </span>
                      </td>
                    )}
                    {cols.validity && (
                      <td className="py-2.5 px-3">
                        {inc.validation_status === "active" ? (
                          <span className="text-[10px] px-2 py-0.5 rounded bg-red-500/15 text-red-400 uppercase">Active</span>
                        ) : inc.validation_status === "inactive" ? (
                          <span className="text-[10px] px-2 py-0.5 rounded bg-slate-500/10 text-slate-500 uppercase">Inactive</span>
                        ) : (
                          <span className="text-[10px] text-slate-600">—</span>
                        )}
                      </td>
                    )}
                    {cols.rotation && (
                      <td className="py-2.5 px-3">
                        {rotated ? (
                          <span className="inline-flex items-center gap-1 text-[10px] text-emerald-400">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                            Rotated · {fmtAge(inc.rotated_at)}
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[10px] text-amber-400">
                            <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                            Not rotated
                          </span>
                        )}
                      </td>
                    )}
                    {cols.last_seen && (
                      <td className="py-2.5 px-3 text-[10px] text-slate-500">
                        {fmtAge(inc.last_seen_at || inc.first_seen_at)}
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination footer */}
      {!loading && items.length > 0 && totalPages > 1 && (
        <div className="flex items-center justify-between px-3 pt-1">
          <p className="text-[11px] text-slate-500">
            {startIdx}–{endIdx} of {total} incident{total === 1 ? "" : "s"}
          </p>
          <div className="flex gap-1">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="text-[11px] px-2.5 py-1 rounded text-slate-400 hover:bg-white/[0.06] disabled:opacity-30"
            >
              ← Prev
            </button>
            <span className="text-[11px] text-slate-500 px-2 py-1">
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="text-[11px] px-2.5 py-1 rounded text-slate-400 hover:bg-white/[0.06] disabled:opacity-30"
            >
              Next →
            </button>
          </div>
        </div>
      )}

      {/* Detail drawer */}
      <IncidentDetailDrawer
        incidentId={openIncident}
        onClose={() => setOpenIncident(null)}
        onMutate={() => fetchItems()}
      />
    </div>
  );
}
