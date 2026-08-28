"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import React, { useEffect, useState, useCallback, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";

import Link from "next/link";
import AppShell from "@/components/layout/AppShell";
import FindingPanel from "@/components/findings/FindingPanel";
import { ExportDropdown } from "@/components/findings/ExportDropdown";
// Incidents view — alternate render of this page when the user toggles
// to "Incidents".  Aggregates findings into one row per unique
// credential (vs. one row per location).  See IncidentsView for the
// rotate-once-kill-many UX rationale.
import { IncidentsView } from "@/components/incidents/IncidentsView";
import { getFindings, getRepository, getFinding, triageFinding, getScanSources, bulkTriageFindings, getRepositories } from "@/lib/api";

// Bulk-triage action vocabulary — must match the Findings drawer's
// status dropdown AND the IncidentsView bulk bar so the user sees
// the same names + colours regardless of which surface they're
// triaging from.  `confirm` flips the two-step inline pattern for
// irreversible actions; the others commit immediately on click.
const FINDING_BULK_ACTIONS: ReadonlyArray<{
  action: string;
  label: string;
  color: string;
  confirm?: boolean;
}> = [
  { action: "mark_tp",      label: "True Positive",      color: "bg-red-500/15 text-red-300 hover:bg-red-500/25 border-red-500/30" },
  { action: "mark_fp",      label: "False Positive",     color: "bg-slate-500/15 text-slate-300 hover:bg-slate-500/25 border-slate-500/30" },
  { action: "mark_test",    label: "Test Credential",    color: "bg-blue-500/15 text-blue-300 hover:bg-blue-500/25 border-blue-500/30" },
  { action: "accept_risk",  label: "Accepted Risk",      color: "bg-orange-500/15 text-orange-300 hover:bg-orange-500/25 border-orange-500/30" },
  { action: "mark_rotated", label: "Rotated / Revoked",  color: "bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25 border-emerald-500/30", confirm: true },
  { action: "reopen",       label: "Re-open",            color: "bg-yellow-500/15 text-yellow-300 hover:bg-yellow-500/25 border-yellow-500/30", confirm: true },
];
import { brandScannerName, getScannerColor, isVoodaEngine } from "@/lib/branding";
import { findingName } from "@/lib/titleUtils";
import { useToast } from "@/components/ui/Toast";
import { Skeleton } from "@/components/ui/Skeleton";
import { getFindingTags } from "@/lib/api";
import type { FindingListItem, FindingDetail } from "@/types";

import api from "@/lib/api";

// Suppressions and Schedules moved to Settings

// ── Constants ─────────────────────────────────────────
const PAGE_SIZE = 50;

// ExportDropdown extracted to components/findings/ExportDropdown.tsx
// so IncidentsView can mount it with its own filter state.  See that
// file for the implementation + the `kind` prop that toggles between
// findings (/reports/export/{format}) and incidents (/incidents/export/csv).

type SortField = "priority" | "created_at" | "severity" | "classification" | "ai_confidence" | "title" | "remediation_status";
type SortDir = "asc" | "desc";

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// ── Relative time ─────────────────────────────────────
function relativeTime(dateStr: string): string {
  const now = Date.now();
  const d = new Date(dateStr).getTime();
  const diff = now - d;
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

// ── SLA status ────────────────────────────────────────
const SLA_THRESHOLDS: Record<string, number> = { critical: 7, high: 30, medium: 90, low: 180, info: 365 };

function getSlaStatus(severity: string, createdAt: string): { color: string; label: string; overdue: boolean } {
  const days = Math.floor((Date.now() - new Date(createdAt).getTime()) / 86400000);
  const threshold = SLA_THRESHOLDS[severity] || 90;
  if (days > threshold) return { color: "bg-red-400", label: `${days - threshold}d overdue`, overdue: true };
  if (days > threshold * 0.8) return { color: "bg-yellow-400", label: `${threshold - days}d left`, overdue: false };
  return { color: "bg-green-400", label: `${threshold - days}d left`, overdue: false };
}

// ── Remediation status icon ───────────────────────────
function RemediationIcon({ status }: { status: string }) {
  if (status === "patch_generated" || status === "proposed") return (
    <span className="flex items-center gap-1 text-[10px] text-red-400" title="Patch ready">
      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /></svg>
    </span>
  );
  if (status === "approved") return (
    <span className="flex items-center gap-1 text-[10px] text-green-400" title="Approved">
      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
    </span>
  );
  if (status === "applied") return (
    <span className="flex items-center gap-1 text-[10px] text-green-400" title="Applied">
      <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" /></svg>
    </span>
  );
  if (status === "rejected") return (
    <span className="flex items-center gap-1 text-[10px] text-red-400" title="Rejected">
      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
    </span>
  );
  if (status === "pending" || status === "in_progress") return (
    <span className="flex items-center gap-1 text-[10px] text-yellow-400" title="Generating...">
      <div className="w-3 h-3 border border-yellow-400/50 border-t-yellow-400 rounded-full animate-spin" />
    </span>
  );
  return <span className="text-[10px] text-slate-700" title="No fix">—</span>;
}

// ── Sort header ───────────────────────────────────────
function SortableHeader({ label, field, currentSort, currentDir, onSort, className = "", style }: {
  label: string; field: SortField; currentSort: SortField; currentDir: SortDir; onSort: (f: SortField) => void; className?: string; style?: React.CSSProperties;
}) {
  const active = currentSort === field;
  return (
    <th
      onClick={() => onSort(field)}
      className={`px-3 py-2.5 text-[10px] font-semibold uppercase tracking-widest cursor-pointer hover:text-slate-300 transition-colors select-none whitespace-nowrap ${className}`}
      style={{ color: "#475569", ...style }}
    >
      <span className="flex items-center gap-1">
        {label}
        {active && (
          <svg className={`w-3 h-3 ${currentDir === "asc" ? "rotate-180" : ""}`} style={{ color: "#ef4444" }} fill="currentColor" viewBox="0 0 20 20">
            <path d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" />
          </svg>
        )}
      </span>
    </th>
  );
}

// ═══════════════════════════════════════════════════════
//  MAIN PAGE
// ═══════════════════════════════════════════════════════
// Inner component reads useSearchParams. Next.js 15 requires the
// useSearchParams() consumer to be wrapped in <Suspense> so SSR can
// suspend on the bailout boundary while the client hydrates.
function FindingsPageInner() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const repoIdFromUrl = searchParams?.get("repository_id") || "";
  const classificationFromUrl = searchParams?.get("classification") || "";
  const scanSourceIdFromUrl = searchParams?.get("scan_source_id") || "";
  // Dashboard Quick Actions deeplink here with ?validation_status=active
  // (Active Credentials) and ?remediation_status=PATCH_GENERATED (Pending
  // Patches). Both URL filters need to be honored on the initial render
  // so the Quick Action lands on a pre-filtered list, not "all findings".
  const validationStatusFromUrl = searchParams?.get("validation_status") || "";
  const remediationStatusFromUrl = searchParams?.get("remediation_status") || "";
  // Tab state removed — Suppressions and Schedules moved to Settings

  const [findings, setFindings] = useState<FindingListItem[]>([]);
  const [total, setTotal] = useState(0);
  // Global count of unique credentials matching the current filters
  // (server-computed by COUNT(DISTINCT secret_hash)).  The old code
  // derived this from `groupedFindings.length` which is per-PAGE and
  // therefore wrong on multi-page results — a 50-finding page might
  // show "40 unique" even though there are 47 unique across all 61
  // findings.  Server value is authoritative.
  const [uniqueCount, setUniqueCount] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({
    severity: "",
    classification: classificationFromUrl,
    search: "",
    repository_id: repoIdFromUrl,
    scan_source_id: scanSourceIdFromUrl,
    tag: "",
    scanner_name: "",
    validation_status: validationStatusFromUrl,
    remediation_status: remediationStatusFromUrl,
  });
  // List of connected sources (id + name + source_type) — populated
  // once on mount and used to render the "Source" filter dropdown.
  // Keeps the dropdown in sync with whatever the user has configured
  // in /sources without requiring a hard-coded provider list.
  const [availableSources, setAvailableSources] = useState<Array<{ id: string; name: string; source_type: string }>>([]);
  // Repositories for the "Project" filter. The repository_id filter already
  // existed but was only reachable by drilling in from a repository page —
  // this makes it selectable from the findings list itself.
  const [availableRepos, setAvailableRepos] = useState<Array<{ id: string; name: string }>>([]);
  // Project picker is a typeahead, not a <select>: an enterprise tenant can
  // have hundreds of repositories, well past the API's 200-row page cap, so
  // matching happens server-side rather than over a pre-loaded list.
  const [repoQuery, setRepoQuery] = useState("");
  const [repoPickerOpen, setRepoPickerOpen] = useState(false);
  const [repoLoading, setRepoLoading] = useState(false);
  // Default sort = classification-priority (Confirmed-TP -> Likely-TP ->
  // Needs-Review -> Likely-FP -> Confirmed-FP, then severity). No filter is
  // applied; the FP tiers just sort to the bottom so nothing is ever hidden.
  const [sortBy, setSortBy] = useState<SortField>("priority");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [loading, setLoading] = useState(true);
  const [repoName, setRepoName] = useState<string | null>(null);
  const [availableTags, setAvailableTags] = useState<{ tag: string; count: number }[]>([]);
  // View menu — folds the two view-mode toggles (Grouped + Active only)
  // that previously sat in the filter row as standalone buttons.  Reduces
  // filter-row chrome and matches the pattern Linear / Notion / GitHub
  // use for view-mode settings (Sort, Group, Show-archived all live in
  // one menu so they don't pad the primary filter chips).  Added 2026-05-14.
  const [viewMenuOpen, setViewMenuOpen] = useState(false);

  // Close the View menu on outside click — standard popover hygiene.
  // No portal needed; menu is small enough that click-outside is fine.
  useEffect(() => {
    if (!viewMenuOpen) return;
    const onClick = (e: MouseEvent) => {
      const t = e.target as HTMLElement | null;
      if (t && !t.closest("[data-view-menu]")) setViewMenuOpen(false);
    };
    window.addEventListener("mousedown", onClick);
    return () => window.removeEventListener("mousedown", onClick);
  }, [viewMenuOpen]);

  // ── Column visibility ─────────────────────────────────────────
  // Commercial scanners (GitGuardian, Linear, Jira, Wiz) all let
  // analysts hide columns they don't use.  Default state shows every
  // column so the out-of-box experience is informative; analysts can
  // untick anything they don't need.  Persisted to localStorage so
  // the preference survives across sessions.
  //
  // Width weights are normalized at render time — when columns are
  // hidden, the visible ones expand proportionally to fill the table.
  // The checkbox column has a fixed pixel width (40px) and isn't part
  // of the weight pool.  Secret is mandatory (always visible) since
  // it's the primary row identifier.
  //
  // Added 2026-05-14 alongside restoring the Confidence column —
  // see thread context for why the default-on / hide-via-View pattern
  // is the right choice for a commercial scanner serving varied apps.
  type ColumnKey = "masked_value" | "severity" | "validity" | "status" | "confidence" | "found";
  const ALL_COLUMNS: { key: ColumnKey; label: string; weight: number }[] = [
    { key: "masked_value", label: "Masked Value", weight: 14 },
    { key: "severity",     label: "Severity",     weight: 10 },
    { key: "validity",     label: "Validity",     weight: 10 },
    { key: "status",       label: "Status",       weight: 14 },
    { key: "confidence",   label: "Confidence",   weight: 12 },
    { key: "found",        label: "Found",        weight: 10 },
  ];
  // Secret column is always visible; its weight is included in the
  // total so the relative proportions stay stable when other columns
  // are hidden.
  const SECRET_COLUMN_WEIGHT = 28;
  // Bumped to v2 on 2026-05-14 when Confidence's default flipped from
  // visible → hidden.  Existing users had `confidence: true` already
  // persisted (because the column was default-on for a brief window),
  // so the new default couldn't take effect on a same-key read.
  // Bumping the key invalidates the old storage exactly once; users
  // who customised other columns will need to re-tick them, which is
  // a fair tradeoff for a one-time correction.  Keep bumping the
  // suffix if future default changes hit the same migration scenario.
  const LS_KEY_COLUMNS = "vooda_findings_visible_columns_v2";

  const [visibleColumns, setVisibleColumns] = useState<Record<ColumnKey, boolean>>(() => {
    // Hydrate from localStorage on mount.  Tolerant of malformed
    // values — falls back to the default-visibility map if anything
    // looks wrong.  Confidence defaults to FALSE (added 2026-05-14):
    // values are typically clustered tightly around 80-95% which
    // makes the column low-information at a glance.  Analysts who
    // want it can opt in via View ▾ → Columns.  All other columns
    // default to true so the out-of-box view is informative.
    const DEFAULTS: Record<ColumnKey, boolean> = {
      masked_value: true,
      severity: true,
      validity: true,
      status: true,
      confidence: false,  // ← off by default
      found: true,
    };
    if (typeof window === "undefined") return DEFAULTS;
    try {
      const raw = localStorage.getItem(LS_KEY_COLUMNS);
      if (!raw) return DEFAULTS;
      const parsed = JSON.parse(raw);
      // Defensive: only accept booleans.  Missing keys fall back to
      // DEFAULTS[key], so an existing user who has a saved preference
      // for everything BUT confidence will still see confidence hidden
      // (rather than silently flipped on by a per-key default).
      return {
        masked_value: typeof parsed.masked_value === "boolean" ? parsed.masked_value : DEFAULTS.masked_value,
        severity:     typeof parsed.severity     === "boolean" ? parsed.severity     : DEFAULTS.severity,
        validity:     typeof parsed.validity     === "boolean" ? parsed.validity     : DEFAULTS.validity,
        status:       typeof parsed.status       === "boolean" ? parsed.status       : DEFAULTS.status,
        confidence:   typeof parsed.confidence   === "boolean" ? parsed.confidence   : DEFAULTS.confidence,
        found:        typeof parsed.found        === "boolean" ? parsed.found        : DEFAULTS.found,
      };
    } catch {
      return DEFAULTS;
    }
  });

  const toggleColumn = (key: ColumnKey) => {
    setVisibleColumns((cols) => {
      const next = { ...cols, [key]: !cols[key] };
      if (typeof window !== "undefined") {
        try { localStorage.setItem(LS_KEY_COLUMNS, JSON.stringify(next)); } catch {}
      }
      return next;
    });
  };

  // ── Incidents view column visibility ────────────────────────────
  // Separate state from findings columns because the two tables have
  // different schemas (incidents columns: severity, occurrences,
  // status, validity, rotation, last_seen).  Same localStorage
  // persistence pattern as findings so the user's choice survives
  // reload — uses a distinct key so future schema changes can rev
  // independently per table.
  type IncidentColumnKey = "severity" | "occurrences" | "status" | "validity" | "rotation" | "last_seen";
  const INCIDENT_COLUMNS: { key: IncidentColumnKey; label: string }[] = [
    { key: "severity", label: "Severity" },
    { key: "occurrences", label: "Occurrences" },
    { key: "status", label: "Status" },
    { key: "validity", label: "Validity" },
    { key: "rotation", label: "Rotation" },
    { key: "last_seen", label: "Last seen" },
  ];
  const LS_KEY_INCIDENT_COLUMNS = "vooda_incidents_visible_columns_v1";
  const [visibleIncidentColumns, setVisibleIncidentColumns] = useState<Record<IncidentColumnKey, boolean>>(() => {
    const DEFAULTS: Record<IncidentColumnKey, boolean> = {
      severity: true,
      occurrences: true,
      status: true,
      validity: true,
      rotation: true,
      last_seen: true,
    };
    if (typeof window === "undefined") return DEFAULTS;
    try {
      const raw = localStorage.getItem(LS_KEY_INCIDENT_COLUMNS);
      if (!raw) return DEFAULTS;
      const parsed = JSON.parse(raw);
      return {
        severity:    typeof parsed.severity    === "boolean" ? parsed.severity    : DEFAULTS.severity,
        occurrences: typeof parsed.occurrences === "boolean" ? parsed.occurrences : DEFAULTS.occurrences,
        status:      typeof parsed.status      === "boolean" ? parsed.status      : DEFAULTS.status,
        validity:    typeof parsed.validity    === "boolean" ? parsed.validity    : DEFAULTS.validity,
        rotation:    typeof parsed.rotation    === "boolean" ? parsed.rotation    : DEFAULTS.rotation,
        last_seen:   typeof parsed.last_seen   === "boolean" ? parsed.last_seen   : DEFAULTS.last_seen,
      };
    } catch {
      return DEFAULTS;
    }
  });
  const toggleIncidentColumn = (key: IncidentColumnKey) => {
    setVisibleIncidentColumns((cols) => {
      const next = { ...cols, [key]: !cols[key] };
      if (typeof window !== "undefined") {
        try { localStorage.setItem(LS_KEY_INCIDENT_COLUMNS, JSON.stringify(next)); } catch {}
      }
      return next;
    });
  };

  // Compute width strings for each column based on currently-visible
  // columns + their weights.  Visible weights are normalized against
  // the total (Secret 28 + sum of visible optional weights) and the
  // result is scaled to 98% (the remaining 2% is the checkbox column).
  const columnWidths = (() => {
    const visibleOptional = ALL_COLUMNS.filter(c => visibleColumns[c.key]);
    const totalWeight = SECRET_COLUMN_WEIGHT + visibleOptional.reduce((s, c) => s + c.weight, 0);
    const scale = 98 / totalWeight;
    const widths: Record<string, string> = {
      secret: `${(SECRET_COLUMN_WEIGHT * scale).toFixed(2)}%`,
    };
    for (const c of visibleOptional) widths[c.key] = `${(c.weight * scale).toFixed(2)}%`;
    return widths;
  })();

  // colSpan for full-row cells (empty state, expanded code preview,
  // no-snippet placeholder).  Always = 1 (checkbox) + 1 (Secret) +
  // count of visible optional columns.
  const visibleColumnCount = 2 + Object.values(visibleColumns).filter(Boolean).length;

  // Load available tags
  useEffect(() => { getFindingTags().then((r) => setAvailableTags(r.data || [])).catch(() => {}); }, []);

  // Load connected sources for the Source filter dropdown.  Best-effort:
  // a fetch failure leaves the dropdown empty (the column degrades to
  // an "All sources" placeholder), never blocks the rest of the page.
  useEffect(() => {
    // Debounced server-side search — the list is matched by the API, so it
    // works past the 200-row page cap. Fires once on mount with an empty
    // query to populate the initial list.
    const handle = setTimeout(async () => {
      try {
        setRepoLoading(true);
        const params: Record<string, string | number> = { page_size: 50 };
        if (repoQuery.trim()) params.search = repoQuery.trim();
        const r = await getRepositories(params);
        const list = r.data?.items || r.data || [];
        setAvailableRepos(
          (Array.isArray(list) ? list : [])
            .map((x: any) => ({ id: x.id, name: x.name }))
            .filter((x) => x.id && x.name)
            .sort((a, b) => a.name.localeCompare(b.name)),
        );
      } catch {
        setAvailableRepos([]);
      } finally {
        setRepoLoading(false);
      }
    }, 200);
    return () => clearTimeout(handle);
  }, [repoQuery]);

  useEffect(() => {
    getScanSources()
      .then((r) => {
        const list = r.data?.items || r.data || [];
        setAvailableSources(
          (Array.isArray(list) ? list : [])
            .map((s: any) => ({ id: s.id, name: s.name, source_type: s.source_type }))
            .filter((s) => s.id && s.name),
        );
      })
      .catch(() => {});
  }, []);

  // Selection
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  // Compliance / power-user toggle — when ON the list includes findings
  // whose parent (repo or scan_source) is archived.  Default OFF so the
  // working surface reflects active risk only.  Persisted in localStorage
  // so the user's choice survives reload — same UX pattern as Snyk's
  // "Show inactive projects" checkbox.
  const [includeArchivedSources, setIncludeArchivedSources] = useState<boolean>(() => {
    if (typeof window === "undefined") return false;
    return localStorage.getItem("vooda_findings_include_archived") === "1";
  });

  // ── View mode: "findings" (per-occurrence) vs "incidents" (per-secret)
  // Sourced from a different endpoint each (/findings vs /incidents).
  // Incidents view powers the rotate-once-kill-many UX that's uniquely
  // secret-scanner-specific.  URL-synced via ?view=findings or
  // ?view=incidents so links are shareable.
  //
  // Default flipped from "findings" → "incidents" on 2026-05-24
  // (Vooda Scan Intelligence audit follow-up).  Rationale: the
  // incidents view collapses N findings for the same credential
  // (e.g. 3 files containing the same Postgres URL) into 1 row, so
  // triagers act once instead of N times.  On the pulumi/pulumi
  // production data this drops the visible item count from 550
  // findings → 239 incidents — a 57% reduction in triage volume
  // with no loss of actionability (per-location detail is still one
  // click away on the incident-detail page, AND users can still
  // click View → Findings to restore the per-location layout).
  //
  // Reverted 2026-05-25 — default back to "findings" per product request.
  // The earlier "default to incidents" change (commit 14a8e68) was rolled
  // back; explicit `?view=incidents` URLs still work, and the View menu
  // still lets users switch.  Cross-count nudges remain intact.
  const [viewMode, setViewMode] = useState<"findings" | "incidents">(() => {
    if (typeof window === "undefined") return "findings";
    const url = new URL(window.location.href);
    const v = url.searchParams.get("view");
    if (v === "incidents") return "incidents";
    if (v === "findings") return "findings";
    return "findings";  // default for users without explicit view choice
  });
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());

  // Findings table renders one row per location (no FE-side grouping).
  // Aggregation by secret_hash is now done server-side via the Incidents
  // view (toggle in View menu); the legacy `groupBySecret` toggle was
  // removed because it was a presentation-only hack on the same data.
  type FindingGroup = { key: string; primary: FindingListItem; members: FindingListItem[]; count: number };
  const groupedFindings: FindingGroup[] = findings.map((f) => ({
    key: f.id,
    primary: f,
    members: [f],
    count: 1,
  }));

  // Slide-out panel
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [panelFinding, setPanelFinding] = useState<FindingDetail | null>(null);
  const [panelLoading, setPanelLoading] = useState(false);

  // Bulk action loading + optional comment + two-step confirm.
  // Mirrors the Incidents view's bulk-action pattern so the two
  // surfaces feel identical (same vocabulary, same colours, same
  // confirm UX).  Comment rides along to the audit log; pendingBulk
  // holds the action name awaiting a second-click commit.
  const [bulkLoading, setBulkLoading] = useState(false);
  const [bulkComment, setBulkComment] = useState("");
  const [pendingBulk, setPendingBulk] = useState<string | null>(null);
  // Toast handle for the bulk-action result banners.  The hook was
  // already imported at module-level but never called from this
  // component until the bulk-triage rewrite needed result toasts.
  const { toast } = useToast();

  // Load repo name
  useEffect(() => {
    if (repoIdFromUrl) getRepository(repoIdFromUrl).then((r) => setRepoName(r.data.name)).catch(() => {});
  }, [repoIdFromUrl]);

  const fetchFindings = useCallback(() => {
    setLoading(true);
    const params: Record<string, string> = { page: String(page), page_size: String(PAGE_SIZE), sort_by: sortBy, sort_dir: sortDir };
    if (filters.severity) params.severity = filters.severity;
    if (filters.classification) params.classification = filters.classification;
    if (filters.search) params.search = filters.search;
    if (filters.repository_id) params.repository_id = filters.repository_id;
    if (filters.scan_source_id) params.scan_source_id = filters.scan_source_id;
    if (filters.tag) params.tag = filters.tag;
    if (filters.validation_status) params.validation_status = filters.validation_status;
    if (filters.remediation_status) params.remediation_status = filters.remediation_status;
    if (includeArchivedSources) params.include_archived_sources = "true";

    getFindings(params)
      .then((r) => {
        // Handle both paginated response {items, total} and plain array
        if (r.data?.items) {
          setFindings(r.data.items);
          setTotal(r.data.total || 0);
          // unique_count is the server-computed global distinct-by-
          // secret_hash count.  Fall back to total when missing (older
          // backends or non-secret findings sets).
          setUniqueCount(r.data.unique_count ?? r.data.total ?? 0);
          setTotalPages(r.data.total_pages || 1);
        } else if (Array.isArray(r.data)) {
          setFindings(r.data);
          setTotal(r.data.length);
          setUniqueCount(r.data.length);
          setTotalPages(1);
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [page, sortBy, sortDir, filters, includeArchivedSources]);

  useEffect(() => { fetchFindings(); }, [fetchFindings]);

  // ── Panel ──
  const openPanel = useCallback((id: string) => {
    setSelectedFindingId(id);
    setPanelLoading(true);
    getFinding(id).then((r) => setPanelFinding(r.data)).catch(() => {}).finally(() => setPanelLoading(false));
  }, []);

  const closePanel = () => { setSelectedFindingId(null); setPanelFinding(null); };

  const refreshPanel = () => {
    if (selectedFindingId) getFinding(selectedFindingId).then((r) => setPanelFinding(r.data)).catch(() => {});
    fetchFindings();
  };

  // ── Keyboard navigation ──
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && selectedFindingId) { closePanel(); return; }
      if (!selectedFindingId || !findings.length) return;
      const currentIdx = findings.findIndex((f) => f.id === selectedFindingId);
      if (e.key === "ArrowDown" && currentIdx < findings.length - 1) {
        e.preventDefault();
        openPanel(findings[currentIdx + 1].id);
      } else if (e.key === "ArrowUp" && currentIdx > 0) {
        e.preventDefault();
        openPanel(findings[currentIdx - 1].id);
      }
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [selectedFindingId, findings, openPanel]);

  // ── Sort ──
  const handleSort = (field: SortField) => {
    if (sortBy === field) {
      setSortDir((d) => d === "asc" ? "desc" : "asc");
    } else {
      setSortBy(field);
      setSortDir("desc");
    }
    setPage(1);
  };

  // ── Selection ──
  const toggleExpand = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setExpanded((prev) => { const n = new Set(prev); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  };
  const toggleSelect = (id: string) => {
    setSelected((prev) => { const n = new Set(prev); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  };
  const toggleSelectAll = () => {
    if (selected.size === findings.length) setSelected(new Set());
    else setSelected(new Set(findings.map((f) => f.id)));
  };

  // ── Bulk actions ──
  // Single entry point for all 6 triage actions in the bulk bar.
  // Two-step confirm for actions marked confirm=true (mark_rotated,
  // reopen).  Replaces the previous JS fan-out
  // (Promise.all of N triageFinding calls — slow + non-atomic) with
  // a single POST /findings/bulk-triage round trip.  At 500 selected
  // findings the wall-clock drops from ~25s to ~1s and the audit
  // trail goes from N decision rows to N + 1 (per-finding decisions
  // plus a single bulk summary entry).
  const handleBulkAction = async (action: string) => {
    if (selected.size === 0) return;
    const spec = FINDING_BULK_ACTIONS.find((a) => a.action === action);
    if (!spec) return;

    // First click on a confirm-required action: stage the confirm.
    if (spec.confirm && pendingBulk !== action) {
      setPendingBulk(action);
      return;
    }

    setBulkLoading(true);
    try {
      const trimmedComment = bulkComment.trim() || undefined;
      const r = await bulkTriageFindings(Array.from(selected), action, trimmedComment);
      const d = r.data as {
        updated: number;
        unchanged: number;
        not_found: number;
        incidents_cascaded: number;
        siblings_cascaded: number;
      };
      toast(
        "success",
        `Bulk ${spec.label}`,
        `${d.updated} updated`
          + (d.unchanged ? ` · ${d.unchanged} already in state` : "")
          + (d.not_found ? ` · ${d.not_found} not found` : "")
          + (d.incidents_cascaded ? ` · ${d.incidents_cascaded} incidents cascaded` : ""),
      );
      setSelected(new Set());
      setBulkComment("");
      setPendingBulk(null);
      fetchFindings();
    } catch (e: any) {
      toast("error", "Bulk action failed", e?.response?.data?.detail || "Could not apply triage.");
    } finally {
      setBulkLoading(false);
    }
  };

  // Reset pending-confirm + comment when the selection empties so
  // stale state doesn't carry over into the next selection cycle.
  useEffect(() => {
    if (selected.size === 0) {
      setPendingBulk(null);
      setBulkComment("");
    }
  }, [selected.size]);

  // ── Filters ──
  // Single place that applies a project selection: filter state, the name
  // chip, pagination reset and the shareable URL move together. Both the
  // picker and the chip's clear button go through it.
  const applyRepoFilter = (id: string, name: string | null) => {
    setFilters((f) => ({ ...f, repository_id: id }));
    setRepoName(name);
    setPage(1);
    const url = new URL(window.location.href);
    if (id) url.searchParams.set("repository_id", id);
    else url.searchParams.delete("repository_id");
    window.history.replaceState(null, "", url.pathname + url.search);
  };
  const clearRepoFilter = () => applyRepoFilter("", null);

  const startIdx = (page - 1) * PAGE_SIZE + 1;
  const endIdx = Math.min(page * PAGE_SIZE, total);

  // Single shared View-button element rendered inline at the end of
  // the filter strip in BOTH Findings and Incidents views.  Same
  // dropdown state (viewMenuOpen) drives both mounts — but since
  // only one view renders at a time, only one button is visible.
  // This is the fix for the "View button buried in findings gate"
  // trap WITHOUT adding a wasted standalone action row above the
  // filter strip.
  const viewButtonEl = (
        <div className="relative" data-view-menu>
          <button
            onClick={() => setViewMenuOpen((v) => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
              viewMenuOpen
                ? "text-slate-200 border-white/[0.15] bg-white/[0.06]"
                : "text-slate-400 border-white/[0.07] hover:bg-white/[0.04]"
            }`}
            title="View settings"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 6h16M4 12h16M4 18h7" />
            </svg>
            View
            <svg className={`w-3 h-3 transition-transform ${viewMenuOpen ? "rotate-180" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {viewMenuOpen && (
            <div
              className="absolute right-0 mt-1.5 w-64 rounded-lg border border-white/[0.08] shadow-xl z-20"
              style={{ background: "rgba(10,14,26,0.98)", backdropFilter: "blur(6px)" }}
            >
              <div className="px-3 py-2 text-[10px] text-slate-500 uppercase tracking-widest border-b border-white/[0.05]">
                View options
              </div>
              {/* View mode radio — always available regardless of mode. */}
              <div className="px-3 pt-2.5 pb-1 text-[10px] text-slate-500 uppercase tracking-widest">
                View
              </div>
              {([
                { key: "findings", label: "Findings", desc: "One row per location" },
                { key: "incidents", label: "Incidents", desc: "One row per credential — rotate once to clear all linked findings" },
              ] as const).map((opt) => (
                <button
                  key={opt.key}
                  onClick={() => {
                    setViewMode(opt.key);
                    const url = new URL(window.location.href);
                    if (opt.key === "incidents") url.searchParams.set("view", "incidents");
                    else url.searchParams.delete("view");
                    window.history.replaceState(null, "", url.toString());
                    setViewMenuOpen(false);
                  }}
                  className="w-full flex items-start gap-2.5 px-3 py-2 text-xs text-slate-300 hover:bg-white/[0.04] transition-colors text-left"
                  aria-pressed={viewMode === opt.key}
                >
                  <span className="mt-0.5 inline-flex w-3.5 h-3.5 items-center justify-center rounded-full border border-white/[0.18] shrink-0">
                    {viewMode === opt.key && (
                      <span className="w-2 h-2 rounded-full bg-red-400" />
                    )}
                  </span>
                  <span className="flex-1 min-w-0">
                    <span className="block font-medium">{opt.label}</span>
                    <span className="block text-[10px] text-slate-500 mt-0.5">{opt.desc}</span>
                  </span>
                </button>
              ))}
              {/* Include archived sources — available in both views.
                  Findings: drives the `include_archived` query param on
                  /findings.  Incidents: drives `include_archived_sources`
                  on /incidents.  Same localStorage key so the user's
                  preference carries across view toggles. */}
              <button
                onClick={() => {
                  const next = !includeArchivedSources;
                  setIncludeArchivedSources(next);
                  if (typeof window !== "undefined") {
                    if (next) localStorage.setItem("vooda_findings_include_archived", "1");
                    else localStorage.removeItem("vooda_findings_include_archived");
                  }
                }}
                className="w-full flex items-center justify-between px-3 py-2.5 text-xs text-slate-300 hover:bg-white/[0.04] transition-colors border-t border-white/[0.04]"
              >
                <div className="text-left">
                  <div className="font-medium">Include archived sources</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    {viewMode === "incidents"
                      ? "Show incidents whose occurrences all sit in archived repos / sources"
                      : "Show findings from paused / archived sources"}
                  </div>
                </div>
                <span className={`relative inline-flex h-4 w-7 shrink-0 cursor-pointer rounded-full transition-colors ${includeArchivedSources ? "bg-amber-500/60" : "bg-white/[0.08]"}`}>
                  <span className={`inline-block h-3 w-3 transform rounded-full bg-white shadow transition-transform ${includeArchivedSources ? "translate-x-3.5" : "translate-x-0.5"}`} style={{ marginTop: "2px" }} />
                </span>
              </button>

              {/* Columns — render the toggle list for the current view's
                  table schema (findings columns vs incidents columns). */}
              <div className="px-3 pt-3 pb-1.5 text-[10px] text-slate-500 uppercase tracking-widest border-t border-white/[0.05]">
                Columns
              </div>
              {viewMode === "findings" && ALL_COLUMNS.map((col) => (
                <button
                  key={col.key}
                  onClick={() => toggleColumn(col.key)}
                  className="w-full flex items-center justify-between px-3 py-2 text-xs text-slate-300 hover:bg-white/[0.04] transition-colors"
                >
                  <span>{col.label}</span>
                  <span className={`inline-flex w-4 h-4 items-center justify-center rounded border ${visibleColumns[col.key] ? "border-red-500/40 bg-red-500/15" : "border-white/[0.12] bg-transparent"}`}>
                    {visibleColumns[col.key] && (
                      <svg className="w-3 h-3 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                      </svg>
                    )}
                  </span>
                </button>
              ))}
              {viewMode === "incidents" && INCIDENT_COLUMNS.map((col) => (
                <button
                  key={col.key}
                  onClick={() => toggleIncidentColumn(col.key)}
                  className="w-full flex items-center justify-between px-3 py-2 text-xs text-slate-300 hover:bg-white/[0.04] transition-colors"
                >
                  <span>{col.label}</span>
                  <span className={`inline-flex w-4 h-4 items-center justify-center rounded border ${visibleIncidentColumns[col.key] ? "border-red-500/40 bg-red-500/15" : "border-white/[0.12] bg-transparent"}`}>
                    {visibleIncidentColumns[col.key] && (
                      <svg className="w-3 h-3 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                      </svg>
                    )}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      );

  return (
    <AppShell>
      <div className="space-y-4">
        {/* Incidents view takes over the page body when toggled on
            from the View menu (right end of the filter strip).  All
            the existing filter / table / panel logic below is gated
            on viewMode === "findings" so the two surfaces don't
            interleave their state. */}
        {viewMode === "incidents" && (
          <IncidentsView
            filters={{
              severity: filters.severity,
              classification: filters.classification,
              validation_status: filters.validation_status,
              search: filters.search,
            }}
            includeArchivedSources={includeArchivedSources}
            visibleColumns={visibleIncidentColumns}
            viewButton={viewButtonEl}
          />
        )}

        {viewMode === "findings" && (<>

        {/* Breadcrumb */}
        {repoName && repoIdFromUrl && (
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <Link href="/repositories" className="hover:text-slate-300 transition-colors">Projects & Scans</Link>
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
            <Link href={`/repositories/${repoIdFromUrl}`} className="hover:text-slate-300 transition-colors">{repoName}</Link>
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
            <span className="text-slate-300">Secrets</span>
          </div>
        )}

        {/* Sub-header */}
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <p className="text-sm text-slate-400">
                {total > 0 ? `${startIdx}–${endIdx} of ${total}` : "0 results"}
                {/* Cross-view count hint (2026-05-24 Vooda Scan Intel
                    audit follow-up): when the user is in the Findings
                    view AND there are duplicate-secret groupings to
                    speak of (uniqueCount differs from total), surface
                    the Incidents count alongside so the relationship
                    is visible without opening the View menu.  Clickable
                    — switching to the Incidents view is one tap. */}
                {viewMode === "findings" && uniqueCount > 0 && uniqueCount !== total && (
                  <button
                    type="button"
                    className="ml-2 text-slate-500 hover:text-slate-300 transition-colors"
                    onClick={() => {
                      setViewMode("incidents");
                      const url = new URL(window.location.href);
                      url.searchParams.set("view", "incidents");
                      window.history.replaceState(null, "", url.toString());
                    }}
                    title="Switch to Incidents view"
                  >
                    · {uniqueCount.toLocaleString()} unique credential{uniqueCount === 1 ? "" : "s"} →
                  </button>
                )}
              </p>
              {repoName && (
                <span className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border" style={{ background: "rgba(239,68,68,0.1)", color: "#f87171", borderColor: "rgba(239,68,68,0.2)" }}>
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" /></svg>
                  {repoName}
                  <button onClick={clearRepoFilter} className="ml-1 hover:text-white"><svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg></button>
                </span>
              )}
              {filters.classification && (
                <span className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full bg-yellow-500/10 text-yellow-400 border border-yellow-500/20">
                  {filters.classification.replace(/_/g, " ")}
                  <button onClick={() => { setFilters((f) => ({ ...f, classification: "" })); setPage(1); }} className="ml-1 hover:text-white"><svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg></button>
                </span>
              )}
              {filters.tag && (
                <span className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/20">
                  {filters.tag}
                  <button onClick={() => { setFilters((f) => ({ ...f, tag: "" })); setPage(1); }} className="ml-1 hover:text-white"><svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg></button>
                </span>
              )}
              {filters.scan_source_id && (() => {
                const s = availableSources.find((x) => x.id === filters.scan_source_id);
                return (
                  <span className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
                    Source: {s?.name || filters.scan_source_id.slice(0, 8)}
                    <button onClick={() => { setFilters((f) => ({ ...f, scan_source_id: "" })); setPage(1); }} className="ml-1 hover:text-white"><svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg></button>
                  </span>
                );
              })()}
              {filters.validation_status && (
                <span className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full bg-red-500/15 text-red-400 border border-red-500/20 font-medium">
                  Verifier: {filters.validation_status}
                  <button onClick={() => { setFilters((f) => ({ ...f, validation_status: "" })); setPage(1); window.history.replaceState(null, "", "/findings"); }} className="ml-1 hover:text-white"><svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg></button>
                </span>
              )}
              {filters.remediation_status && (
                <span className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full bg-purple-500/15 text-purple-400 border border-purple-500/20 font-medium">
                  Remediation: {filters.remediation_status.replace(/_/g, " ").toLowerCase()}
                  <button onClick={() => { setFilters((f) => ({ ...f, remediation_status: "" })); setPage(1); window.history.replaceState(null, "", "/findings"); }} className="ml-1 hover:text-white"><svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg></button>
                </span>
              )}
            </div>
          </div>
          {(repoName || filters.classification || filters.severity || filters.tag || filters.validation_status || filters.remediation_status || filters.scan_source_id) && (
            <button onClick={() => { setFilters({ severity: "", classification: "", search: "", repository_id: "", scan_source_id: "", tag: "", scanner_name: "", validation_status: "", remediation_status: "" }); setRepoName(null); setPage(1); window.history.replaceState(null, "", "/findings"); }}
              className="text-xs text-slate-500 hover:text-slate-300 transition-colors">Clear all filters</button>
          )}
        </div>

        {/* Filters + Bulk actions bar */}
        <div className="flex gap-3 items-center flex-wrap">
          <div className="relative flex-1 max-w-xs">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
            <input type="text" placeholder="Search secrets..." value={filters.search}
              onChange={(e) => setFilters((f) => ({ ...f, search: e.target.value }))}
              onKeyDown={(e) => { if (e.key === "Enter") { setPage(1); fetchFindings(); } }}
              className="input-dark pl-10" />
          </div>
          <select value={filters.severity} onChange={(e) => { setFilters((f) => ({ ...f, severity: e.target.value })); setPage(1); }} className="select-dark">
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select value={filters.classification} onChange={(e) => { setFilters((f) => ({ ...f, classification: e.target.value })); setPage(1); }} className="select-dark">
            <option value="">All Statuses</option>
            <option value="likely_true_positive">True Positive</option>
            <option value="likely_false_positive">False Positive</option>
            <option value="needs_review">Needs Review</option>
            <option value="confirmed_true_positive">Confirmed True Positive</option>
            <option value="confirmed_false_positive">Confirmed False Positive</option>
            <option value="accepted_risk">Accepted Risk</option>
          </select>
          {/* Project filter — scopes the list to one repository. Shares the
               `repository_id` filter that drill-through from a repository
               page already sets, so both entry points stay consistent. */}
          {/* Project picker — looks and behaves like the other dropdowns
               (same `select-dark` trigger, same chevron), but opens a panel
               with a search field instead of a plain option list. A native
               <select> is unusable once a tenant has more than a few dozen
               repositories, and matching is done server-side so it works
               past the API's page cap. Selection writes `repository_id`, so
               this and drill-through from a repository page are
               interchangeable. */}
          <div
            className="relative"
            onBlur={(e) => {
              // Close only when focus actually leaves the picker — moving
              // between the trigger, the search box and an option all stay
              // inside, so the panel must not collapse mid-interaction.
              if (!e.currentTarget.contains(e.relatedTarget as Node)) setRepoPickerOpen(false);
            }}
          >
            <button
              type="button"
              onClick={() => { setRepoPickerOpen((o) => !o); setRepoQuery(""); }}
              className="select-dark w-44 text-left truncate"
              title={repoName || "Filter by project / repository"}
              aria-haspopup="listbox"
              aria-expanded={repoPickerOpen}
            >
              <span className={repoName ? "" : "text-slate-500"}>{repoName || "All Projects"}</span>
            </button>
            {repoPickerOpen && (
              <div className="absolute z-30 mt-1 w-64 rounded-lg border border-slate-700/60 bg-[#0e1228] shadow-xl overflow-hidden">
                <div className="relative border-b border-slate-700/50">
                  <svg className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
                  <input
                    type="text"
                    autoFocus
                    value={repoQuery}
                    placeholder="Search projects…"
                    onChange={(e) => setRepoQuery(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Escape") setRepoPickerOpen(false); }}
                    className="w-full bg-transparent pl-8 pr-3 py-2 text-xs text-slate-200 placeholder-slate-600 outline-none"
                  />
                </div>
                <div className="max-h-64 overflow-auto py-1" role="listbox">
                  <button
                    onMouseDown={(e) => { e.preventDefault(); clearRepoFilter(); setRepoPickerOpen(false); }}
                    className={`w-full text-left px-3 py-2 text-xs hover:bg-slate-800/60 ${!filters.repository_id ? "text-red-400" : "text-slate-400"}`}
                  >
                    All Projects
                  </button>
                  {repoLoading && availableRepos.length === 0 && (
                    <p className="px-3 py-2 text-xs text-slate-600">Searching…</p>
                  )}
                  {!repoLoading && availableRepos.length === 0 && (
                    <p className="px-3 py-2 text-xs text-slate-600">No projects match</p>
                  )}
                  {availableRepos.map((x) => (
                    <button
                      key={x.id}
                      role="option"
                      aria-selected={filters.repository_id === x.id}
                      onMouseDown={(e) => { e.preventDefault(); applyRepoFilter(x.id, x.name); setRepoPickerOpen(false); }}
                      className={`w-full text-left px-3 py-2 text-xs truncate hover:bg-slate-800/60 ${filters.repository_id === x.id ? "text-red-400" : "text-slate-300"}`}
                      title={x.name}
                    >
                      {x.name}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
          {/* Single-option filters are hidden: a dropdown whose only choice
               is "all" or one value cannot change the result set, so it is
               chrome. Both this and the Project filter render only at >1. */}
          {/* Source filter — drills findings to a specific source instance
               (e.g. "Confluence" / "Notion" / "#engineering Slack channel").
               The previously-separate "All Providers" filter was removed
               2026-05-14: Source already covers the same axis (each source
               instance has exactly one detector family), and the duplication
               was padding the filter row without adding pivot value. */}
          {availableSources.length > 1 && (
            <select value={filters.scan_source_id} onChange={(e) => { setFilters((f) => ({ ...f, scan_source_id: e.target.value })); setPage(1); }} className="select-dark" title="Filter by source">
              <option value="">All Sources</option>
              {availableSources.map((s) => (
                <option key={s.id} value={s.id}>{s.name}</option>
              ))}
            </select>
          )}
          {/* Tag filter — already conditional on tagged findings existing,
              so the dropdown auto-hides on tenants that don't use tags
              (industry pattern: Linear / Notion / Jira do this).  Nothing
              to change in this iteration. */}
          {availableTags.length > 1 && (
            <select value={filters.tag} onChange={(e) => { setFilters((f) => ({ ...f, tag: e.target.value })); setPage(1); }} className="select-dark">
              <option value="">All Tags</option>
              {availableTags.map((t) => (
                <option key={t.tag} value={t.tag}>{t.tag} ({t.count})</option>
              ))}
            </select>
          )}

          {/* View + Export — right aligned at the end of the filter
              strip (inline with Search + selects, no wasted vertical
              row).  The same viewButtonEl JSX node is also passed to
              IncidentsView so it appears inline at the end of the
              Incidents filter strip — the user always has View access
              right next to the search bar regardless of mode. */}
          <div className="flex items-center gap-2 ml-auto">
            {viewButtonEl}
            {total > 0 && <ExportDropdown filters={filters} />}
          </div>

        </div>

        {/* Bulk-actions bar — full width, sits between the filter
            strip and the table.  Mirrors the IncidentsView bulk bar
            in vocabulary + colour + two-step confirm so the user
            sees the same triage UX on both surfaces.  Replaces the
            previous 3-button inline strip that competed with View +
            Export for ml-auto space and only offered half the
            actions the drawer's status dropdown does. */}
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
                disabled={bulkLoading}
                className="input-dark text-xs flex-1 min-w-[200px]"
              />
              <button
                onClick={() => setSelected(new Set())}
                className="text-[11px] text-slate-500 hover:text-slate-300 shrink-0"
                disabled={bulkLoading}
              >
                Clear selection
              </button>
            </div>

            {/* Pending-confirm notice for irreversible actions. */}
            {pendingBulk && (() => {
              const spec = FINDING_BULK_ACTIONS.find((a) => a.action === pendingBulk);
              return (
                <div className="rounded border border-amber-500/30 bg-amber-500/[0.06] px-3 py-2 text-[11px] text-amber-200 leading-relaxed flex items-center gap-3">
                  <span className="flex-1">
                    About to mark <span className="font-semibold">{selected.size}</span> finding{selected.size === 1 ? "" : "s"} as{" "}
                    <span className="font-semibold">{spec?.label}</span>.{" "}
                    The action also cascades to each finding&apos;s parent incident + sibling occurrences.
                    Click <span className="font-semibold">{spec?.label}</span> again to commit.
                  </span>
                  <button
                    onClick={() => setPendingBulk(null)}
                    className="text-[11px] text-slate-400 hover:text-slate-200 shrink-0"
                    disabled={bulkLoading}
                  >
                    Cancel
                  </button>
                </div>
              );
            })()}

            {/* Row 2: six action buttons */}
            <div className="flex items-center gap-2 flex-wrap">
              {FINDING_BULK_ACTIONS.map((a) => {
                const isPending = pendingBulk === a.action;
                return (
                  <button
                    key={a.action}
                    onClick={() => handleBulkAction(a.action)}
                    disabled={bulkLoading}
                    className={`inline-flex items-center gap-1.5 text-[11px] px-2.5 py-1.5 rounded-md border font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${a.color} ${
                      isPending ? "ring-1 ring-amber-500/50 [border-style:dashed]" : ""
                    }`}
                  >
                    {bulkLoading && isPending && (
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
        <div className="card p-0 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="glass-table w-full text-sm table-fixed">
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                  <th className="px-3 py-2.5 w-10">
                    <input type="checkbox" checked={selected.size === findings.length && findings.length > 0} onChange={toggleSelectAll}
                      className="w-3.5 h-3.5 rounded border-slate-600 bg-dark-950 cursor-pointer" style={{ accentColor: "#ef4444" }} />
                  </th>
                  {/* Columns are user-configurable via the View menu —
                       each <th>/<td> is gated on visibleColumns[<key>]
                       and the widths are computed at render time so
                       the table re-flows cleanly when columns toggle.
                       Secret is the only column that's always shown
                       (it's the primary row identifier).  Added
                       2026-05-14 alongside restoring Confidence. */}
                  <SortableHeader label="Secret" field="title" currentSort={sortBy} currentDir={sortDir} onSort={handleSort} className="text-left" style={{ width: columnWidths.secret }} />
                  {visibleColumns.masked_value && (
                    <th className="px-3 py-2.5 text-[10px] font-semibold uppercase tracking-widest text-left" style={{ color: "#475569", width: columnWidths.masked_value }}>Masked Value</th>
                  )}
                  {visibleColumns.severity && (
                    <SortableHeader label="Severity" field="severity" currentSort={sortBy} currentDir={sortDir} onSort={handleSort} className="text-left" style={{ width: columnWidths.severity }} />
                  )}
                  {visibleColumns.validity && (
                    <th className="px-3 py-2.5 text-[10px] font-semibold uppercase tracking-widest text-left" style={{ color: "#475569", width: columnWidths.validity }}>Validity</th>
                  )}
                  {visibleColumns.status && (
                    <SortableHeader label="Status" field="classification" currentSort={sortBy} currentDir={sortDir} onSort={handleSort} className="text-left whitespace-nowrap" style={{ width: columnWidths.status }} />
                  )}
                  {visibleColumns.confidence && (
                    <th className="px-3 py-2.5 text-[10px] font-semibold uppercase tracking-widest text-left" style={{ color: "#475569", width: columnWidths.confidence }}>Confidence</th>
                  )}
                  {visibleColumns.found && (
                    <SortableHeader label="Found" field="created_at" currentSort={sortBy} currentDir={sortDir} onSort={handleSort} className="text-left" style={{ width: columnWidths.found }} />
                  )}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.03]">
                {loading ? (
                  // Skeleton rows mirror the visible-column count so the
                  // table doesn't reflow when real rows paint in.  Each
                  // optional column's skeleton is gated on the same
                  // visibility flag as the real row.
                  Array.from({ length: 8 }).map((_, i) => (
                    <tr key={`sk-${i}`}>
                      <td className="px-3 py-3"><Skeleton w={14} h={14} radius={3} /></td>
                      <td className="px-3 py-3"><Skeleton w="85%" h={16} radius={4} /></td>
                      {visibleColumns.masked_value && <td className="px-3 py-3"><Skeleton w={70} h={12} /></td>}
                      {visibleColumns.severity     && <td className="px-3 py-3"><Skeleton w={60} h={16} radius={4} /></td>}
                      {visibleColumns.validity     && <td className="px-3 py-3"><Skeleton w={40} h={12} /></td>}
                      {visibleColumns.status       && <td className="px-3 py-3"><Skeleton w={50} h={12} /></td>}
                      {visibleColumns.confidence   && <td className="px-3 py-3"><Skeleton w={50} h={12} /></td>}
                      {visibleColumns.found        && <td className="px-3 py-3"><Skeleton w={48} h={10} /></td>}
                    </tr>
                  ))
                ) : findings.length === 0 ? (
                  <tr><td colSpan={visibleColumnCount} className="px-5 py-12 text-center text-slate-500">No findings match your filters.</td></tr>
                ) : groupedFindings.map((group) => {
                  const f = group.primary;
                  const isGrouped = group.count > 1;
                  const isGroupExpanded = expandedGroups.has(group.key);
                  return (
                  <React.Fragment key={group.key}>
                  <tr
                    onClick={() => openPanel(f.id)}
                    className={`transition-colors group cursor-pointer ${selectedFindingId === f.id ? "border-l-2" : ""}`}
                    style={{
                      background: selectedFindingId === f.id
                        ? "rgba(239,68,68,0.06)"
                        : selected.has(f.id)
                        ? "rgba(239,68,68,0.03)"
                        : undefined,
                      borderLeftColor: selectedFindingId === f.id ? "#ef4444" : undefined,
                    }}
                    onMouseEnter={(e) => { if (selectedFindingId !== f.id) (e.currentTarget as HTMLTableRowElement).style.background = "rgba(255,255,255,0.02)"; }}
                    onMouseLeave={(e) => { (e.currentTarget as HTMLTableRowElement).style.background = selectedFindingId === f.id ? "rgba(239,68,68,0.06)" : selected.has(f.id) ? "rgba(239,68,68,0.03)" : ""; }}
                  >
                    {/* Expand + Checkbox */}
                    <td className="px-3 py-3" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center gap-1.5">
                        {isGrouped ? (
                          <button onClick={(e) => { e.stopPropagation(); setExpandedGroups(prev => { const n = new Set(prev); n.has(group.key) ? n.delete(group.key) : n.add(group.key); return n; }); }}
                            className="p-0.5 rounded hover:bg-white/[0.06] transition-colors" title={`${group.count} locations — click to expand`}>
                            <svg className={`w-3 h-3 text-red-400 transition-transform ${isGroupExpanded ? "rotate-90" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                            </svg>
                          </button>
                        ) : (
                          <button onClick={(e) => toggleExpand(f.id, e)} className="p-0.5 rounded hover:bg-white/[0.06] transition-colors" title="Preview code">
                            <svg className={`w-3 h-3 text-slate-600 transition-transform ${expanded.has(f.id) ? "rotate-90" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                            </svg>
                          </button>
                        )}
                        <input type="checkbox" checked={selected.has(f.id)} onChange={() => toggleSelect(f.id)}
                          className="w-3.5 h-3.5 rounded border-slate-600 bg-dark-950 cursor-pointer" style={{ accentColor: "#ef4444" }} />
                      </div>
                    </td>
                    {/* Secret Name + Provider + File */}
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-2">
                        {(() => { const sm = (f as any).source_metadata || {}; const p = sm.provider || "unknown"; const colors: Record<string, string> = { aws: "bg-orange-500", gcp: "bg-blue-500", azure: "bg-blue-600", github: "bg-slate-600", gitlab: "bg-orange-500", stripe: "bg-purple-500", slack: "bg-purple-600", twilio: "bg-red-500", database: "bg-green-500", npm: "bg-red-700", docker: "bg-blue-500", unknown: "bg-slate-600" }; return <span className={`w-6 h-6 rounded-md ${colors[p] || colors.unknown} flex items-center justify-center shrink-0`}><span className="text-[8px] font-bold text-white">{p[0]?.toUpperCase()}</span></span>; })()}
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="text-sm text-slate-200 font-medium transition-colors line-clamp-1 group-hover:text-red-400">
                              {findingName(f.title, f.vulnerability_category)}
                            </span>
                            {isGrouped && (
                              <span className="text-[8px] px-1.5 py-0.5 rounded-full bg-red-500/10 text-red-400 border border-red-500/20 font-bold whitespace-nowrap">{group.count} locations</span>
                            )}
                          </div>
                          <div className="flex items-center gap-1.5">
                            <span className="text-[10px] text-slate-600 truncate max-w-[200px]">{f.file_path}{f.line_start ? `:${f.line_start}` : ""}</span>
                            {(f as any).is_archived_parent && (
                              <span
                                className="text-[8px] px-1 py-0.5 rounded font-semibold whitespace-nowrap uppercase tracking-wider"
                                style={{ background: "rgba(245, 158, 11, 0.12)", color: "#fbbf24", border: "1px solid rgba(245, 158, 11, 0.3)" }}
                                title="This finding belongs to an archived source — scanning is paused, data is preserved. Surfaced because 'Including archived' is on (or you're on a bypass route)."
                              >Archived source</span>
                            )}
                            {(f as any).source_metadata?.detection_engine === "secret_scan_history" && (
                              <span className="text-[8px] px-1 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-medium whitespace-nowrap" title="Found in git history — secret was deleted from current code but still exists in commit history. Rotate the credential.">History</span>
                            )}
                            {(f as any).source_metadata?.is_placeholder && (
                              <span className="text-[8px] px-1 py-0.5 rounded bg-slate-500/10 text-slate-400 border border-slate-500/20 font-medium whitespace-nowrap" title="Known placeholder/example value from documentation">Placeholder</span>
                            )}
                            {(f as any).source_metadata?.file_context === "test_file" && (
                              <span className="text-[8px] px-1 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-medium whitespace-nowrap" title="Finding is in a test/spec file — typically lower production priority">Test</span>
                            )}
                            {(f as any).source_metadata?.validation_status === "active" && (
                              <span className="text-[8px] px-1 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30 font-bold whitespace-nowrap" title="Live credential — verified active against the provider API. Rotate immediately.">● Live</span>
                            )}
                            {(f as any).source_metadata?.validation_status === "inactive" && (
                              <span className="text-[8px] px-1 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium whitespace-nowrap" title="Verified inactive — credential rejected by provider. Still remove from code for hygiene.">✓ Rotated</span>
                            )}
                            {(f as any).source_metadata?.validation_status === "error" && (
                              <span className="text-[8px] px-1 py-0.5 rounded bg-slate-500/10 text-slate-400 border border-slate-500/20 font-medium whitespace-nowrap" title="Verification could not complete (network error). Status unknown.">? Unverified</span>
                            )}
                            {(f as any).source_metadata?._pair_key && (
                              <span className="text-[8px] px-1 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20 font-medium whitespace-nowrap" title="Multi-credential finding — this secret was verified in combination with its paired credential (access_key+secret, client_id+secret, etc.)">Paired</span>
                            )}
                          </div>
                        </div>
                      </div>
                    </td>
                    {/* Body cells — each gated on its column-visibility
                         flag.  Order must match the header above. */}
                    {visibleColumns.masked_value && (
                      <td className="px-3 py-3">
                        <span className="font-mono text-[10px] px-1.5 py-0.5 rounded" style={{ color: "#f87171", background: "rgba(239,68,68,0.08)" }}>
                          {(f as any).source_metadata?.masked_value || "****"}
                        </span>
                      </td>
                    )}
                    {visibleColumns.severity && (
                      <td className="px-3 py-3"><span className={`severity-badge severity-${f.severity} text-[10px]`}>{f.severity}</span></td>
                    )}
                    {visibleColumns.validity && (
                      <td className="px-3 py-3">
                        {(() => { const vs = (f as any).source_metadata?.validation_status || "not_validated"; const styles: Record<string, string> = { active: "bg-red-500/15 text-red-400 border-red-500/20", inactive: "bg-green-500/15 text-green-400 border-green-500/20", revoked: "bg-green-500/15 text-green-400 border-green-500/20", unknown: "bg-slate-500/10 text-slate-400 border-slate-500/20", not_validated: "bg-slate-500/5 text-slate-500 border-slate-500/10" }; const labels: Record<string, string> = { active: "Active", inactive: "Inactive", revoked: "Revoked", unknown: "Unknown", not_validated: "Unverified" }; return <span className={`text-[9px] px-1.5 py-0.5 rounded border font-medium ${styles[vs] || styles.not_validated}`}>{labels[vs] || vs}</span>; })()}
                      </td>
                    )}
                    {visibleColumns.status && (
                      <td className="px-3 py-3">
                        <span className={`inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded whitespace-nowrap ${
                          f.classification.includes("true_positive") ? "bg-red-500/10 text-red-400"
                          : f.classification.includes("false_positive") ? "bg-green-500/10 text-green-400"
                          : f.classification === "accepted_risk" ? "bg-orange-500/10 text-orange-400"
                          : "bg-yellow-500/10 text-yellow-400"
                        }`}>
                          <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                            f.classification.includes("true_positive") ? "bg-red-400"
                            : f.classification.includes("false_positive") ? "bg-green-400"
                            : f.classification === "accepted_risk" ? "bg-orange-400"
                            : "bg-yellow-400"
                          }`} />
                          {f.classification === "needs_review" ? "Needs Review"
                            : f.classification === "likely_true_positive" ? "True Positive"
                            : f.classification === "likely_false_positive" ? "False Positive"
                            : f.classification === "confirmed_true_positive" ? "Confirmed TP"
                            : f.classification === "confirmed_false_positive" ? "Confirmed FP"
                            : f.classification === "accepted_risk" ? "Accepted Risk"
                            : f.classification?.replace(/_/g, " ")}
                        </span>
                      </td>
                    )}
                    {/* Confidence — restored 2026-05-14 as a default-on
                        column gated on user preference.  Commercial
                        scanners (GitGuardian, Wiz, Snyk) all surface
                        a confidence-like signal inline; analysts use
                        it to fast-dismiss low-confidence findings and
                        deep-dive high-confidence ones.  Users who want
                        a leaner view can hide it via View ▾ → Columns. */}
                    {visibleColumns.confidence && (
                      <td className="px-3 py-3">
                        {(f.ai_confidence ?? f.confidence ?? 0) > 0 ? (
                          <div className="flex items-center gap-1.5">
                            <div className="w-10 rounded-full h-1.5" style={{ background: "rgba(255,255,255,0.06)" }}>
                              <div className={`h-1.5 rounded-full ${(f.ai_confidence ?? f.confidence ?? 0) > 0.7 ? "bg-green-400" : (f.ai_confidence ?? f.confidence ?? 0) > 0.4 ? "bg-yellow-400" : "bg-red-400"}`}
                                style={{ width: `${(f.ai_confidence ?? f.confidence ?? 0) * 100}%` }} />
                            </div>
                            <span className="text-[10px] text-slate-500 w-6">{((f.ai_confidence ?? f.confidence ?? 0) * 100).toFixed(0)}%</span>
                          </div>
                        ) : <span className="text-[10px] text-slate-700">—</span>}
                      </td>
                    )}
                    {visibleColumns.found && (
                      <td className="px-3 py-3">
                        {(() => {
                          const sla = getSlaStatus(f.severity, f.created_at);
                          return (
                            <div className="flex items-center gap-1.5" title={sla.overdue ? `SLA breached: ${sla.label}` : `SLA: ${sla.label}`}>
                              <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${sla.color}`} />
                              <span className={`text-[10px] whitespace-nowrap ${sla.overdue ? "text-red-400" : "text-slate-500"}`}>{relativeTime(f.created_at)}</span>
                            </div>
                          );
                        })()}
                      </td>
                    )}
                  </tr>
                  {/* Inline code preview — expandable.  colSpan binds to
                       the live visible-column count so the preview row
                       always stretches the full table width regardless
                       of which columns the user has toggled. */}
                  {expanded.has(f.id) && f.code_snippet && (
                    <tr style={{ background: "rgba(7,9,26,0.8)" }}>
                      <td colSpan={visibleColumnCount} className="px-0 py-0">
                        <div className="relative">
                          <div className="absolute top-2 right-3 flex gap-2 z-10">
                            <span className="text-[9px] px-2 py-0.5 rounded font-mono" style={{ background: "rgba(255,255,255,0.06)", color: "#94a3b8" }}>{f.file_path}:{f.line_start}</span>
                            <button onClick={(e) => { e.stopPropagation(); toggleExpand(f.id, e); }} className="text-[9px] px-2 py-0.5 rounded text-slate-500 hover:text-slate-300 transition-colors" style={{ background: "rgba(255,255,255,0.06)" }}>Collapse</button>
                          </div>
                          <pre className="text-xs text-slate-300 px-6 py-4 overflow-x-auto leading-relaxed max-h-[250px] overflow-y-auto"><code>{f.code_snippet}</code></pre>
                        </div>
                      </td>
                    </tr>
                  )}
                  {expanded.has(f.id) && !f.code_snippet && (
                    <tr style={{ background: "rgba(7,9,26,0.8)" }}>
                      <td colSpan={visibleColumnCount} className="px-6 py-4 text-xs text-slate-600 italic">No code snippet available for this finding</td>
                    </tr>
                  )}
                  {/* Expanded group sub-rows — additional locations for the same secret */}
                  {isGrouped && isGroupExpanded && group.members.slice(1).map((sub) => (
                    <tr key={sub.id} onClick={() => openPanel(sub.id)}
                      className="cursor-pointer hover:bg-white/[0.02] transition-colors"
                      style={{ background: "rgba(239,68,68,0.02)" }}>
                      <td className="px-3 py-2" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center gap-1.5 pl-4">
                          <span className="text-[10px] text-slate-700">├</span>
                          <input type="checkbox" checked={selected.has(sub.id)} onChange={() => toggleSelect(sub.id)}
                            className="w-3 h-3 rounded border-slate-700 bg-dark-950 cursor-pointer" style={{ accentColor: "#ef4444" }} />
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-1.5 pl-4">
                          <span className="text-[10px] text-slate-500 truncate max-w-[280px]">{sub.file_path}{sub.line_start ? `:${sub.line_start}` : ""}</span>
                          {(sub as any).source_metadata?.detection_engine === "secret_scan_history" && (
                            <span className="text-[7px] px-1 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-medium">History</span>
                          )}
                          {(sub as any).source_metadata?.file_context === "test_file" && (
                            <span className="text-[7px] px-1 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-medium">Test</span>
                          )}
                        </div>
                      </td>
                      {/* Sub-row cells — same visibility flags as the
                          parent row so the columns stay aligned when
                          the user toggles column visibility. */}
                      {visibleColumns.masked_value && (
                        <td className="px-3 py-2">
                          <span className="font-mono text-[9px] text-slate-600">{(sub as any).source_metadata?.masked_value || "****"}</span>
                        </td>
                      )}
                      {visibleColumns.severity && (
                        <td className="px-3 py-2"><span className={`severity-badge severity-${sub.severity} text-[9px]`}>{sub.severity}</span></td>
                      )}
                      {visibleColumns.validity && (
                        <td className="px-3 py-2">
                          {(() => { const vs = (sub as any).source_metadata?.validation_status || "not_validated"; const labels: Record<string,string> = { active: "Active", inactive: "Inactive", not_validated: "Unverified" }; const styles: Record<string,string> = { active: "text-red-400", inactive: "text-green-400", not_validated: "text-slate-600" }; return <span className={`text-[8px] ${styles[vs] || styles.not_validated}`}>{labels[vs] || vs}</span>; })()}
                        </td>
                      )}
                      {visibleColumns.status && (
                        <td className="px-3 py-2">
                          <span className={`text-[9px] ${sub.classification.includes("true_positive") ? "text-red-400" : sub.classification.includes("false_positive") ? "text-green-400" : "text-yellow-400"}`}>
                            {sub.classification === "needs_review" ? "Review" : sub.classification.includes("true_positive") ? "TP" : sub.classification.includes("false_positive") ? "FP" : sub.classification.replace(/_/g," ")}
                          </span>
                        </td>
                      )}
                      {visibleColumns.confidence && (
                        <td className="px-3 py-2">
                          <span className="text-[9px] text-slate-600">{sub.confidence ? `${Math.round((sub.confidence || 0) * 100)}%` : ""}</span>
                        </td>
                      )}
                      {visibleColumns.found && <td className="px-3 py-2"></td>}
                    </tr>
                  ))}
                  </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-3" style={{ borderTop: "1px solid rgba(255,255,255,0.05)" }}>
              <p className="text-xs text-slate-500">
                Showing {startIdx}–{endIdx} of {total} findings
              </p>
              <div className="flex items-center gap-1">
                <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}
                  className="px-2.5 py-1.5 rounded-md text-xs text-slate-400 hover:bg-white/[0.04] disabled:opacity-30 disabled:hover:bg-transparent transition-colors">
                  Previous
                </button>
                {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
                  let pageNum: number;
                  if (totalPages <= 7) pageNum = i + 1;
                  else if (page <= 4) pageNum = i + 1;
                  else if (page >= totalPages - 3) pageNum = totalPages - 6 + i;
                  else pageNum = page - 3 + i;

                  return (
                    <button key={pageNum} onClick={() => setPage(pageNum)}
                      className={`w-8 h-8 rounded-md text-xs transition-colors ${page === pageNum ? "border" : "text-slate-400 hover:bg-white/[0.04]"}`}
                      style={page === pageNum ? { background: "rgba(239,68,68,0.15)", color: "#f87171", borderColor: "rgba(239,68,68,0.2)" } : undefined}>
                      {pageNum}
                    </button>
                  );
                })}
                <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}
                  className="px-2.5 py-1.5 rounded-md text-xs text-slate-400 hover:bg-white/[0.04] disabled:opacity-30 disabled:hover:bg-transparent transition-colors">
                  Next
                </button>
              </div>
            </div>
          )}
        </div>

        </>)}
      </div>

      {/* Slide-out panel */}
      {selectedFindingId && panelFinding && !panelLoading && (
        <FindingPanel finding={panelFinding} onClose={closePanel} onUpdate={refreshPanel} />
      )}
      {selectedFindingId && panelLoading && (
        <div className="fixed inset-0 z-40 flex justify-end" onClick={closePanel}>
          <div className="absolute inset-0 bg-black/40 backdrop-blur-[2px]" />
          <div className="relative w-full max-w-[680px] h-full flex items-center justify-center border-l border-white/[0.07]"
            style={{ background: "rgba(14,18,40,0.95)",  }}>
            <div className="w-5 h-5 rounded-full animate-spin" style={{ border: "2px solid rgba(239,68,68,0.2)", borderTopColor: "#ef4444" }} />
          </div>
        </div>
      )}
    </AppShell>
  );
}

// Default export wraps the inner component in <Suspense>. The
// fallback renders a minimal shell so the page doesn't flash.
export default function FindingsPage() {
  return (
    <Suspense fallback={<AppShell><div className="flex justify-center py-20"><div className="w-6 h-6 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" /></div></AppShell>}>
      <FindingsPageInner />
    </Suspense>
  );
}

// Title shortening now in @/lib/titleUtils.ts
