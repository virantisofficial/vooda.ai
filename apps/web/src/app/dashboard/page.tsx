"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect } from "react";
import Link from "next/link";
import AppShell from "@/components/layout/AppShell";
import {
  getMetricsOverview, getFindingsMetrics, getRemediationMetrics,
  getRepositories, getMTTRMetrics, getTrendData,
  getFindingsByCategory, getTopLeakingRepos,
  getFindingsBreakdown, getAIAccuracy, getAuditEvents,
} from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import { Skeleton, SkeletonKpiTile, SkeletonCard } from "@/components/ui/Skeleton";

/* ═══════════════════════════════════════════════════════════
   SYMMETRIC 6-ROW DASHBOARD  (2026-05-16)

   Layout — 5-column grid base.  Rows 1-4 fit a 900px viewport above
   the fold; Rows 5-6 are Vooda differentiator widgets below the fold.

     Row 1 (48px)  Posture banner          col-span 5
     Row 2 (120px) KPI strip × 5           col-span 1 × 5
     Row 3 (260px) Trend  +  By Source     col-span 3 + 2
     Row 4 (200px) Top Repos + Q.Actions   col-span 3 + 2
     Row 5 (260px) Verifier + AI Triage    col-span 3 + 2
     Row 6 (240px) Recent Activity feed    col-span 5

   Row 3 and Row 4 share the same 3+2 split so the vertical column
   divider lines up across both, giving the body one continuous grid.
   Replaces the pre-2026-05-16 "Latest Secrets Found" + Quick Actions
   row (which restated data already visible in the bell + KPI strip).
   ═══════════════════════════════════════════════════════════ */

// Time-range options — mirrors what Wiz / Snyk / Datadog ship.
const RANGE_OPTIONS: Array<{ label: string; days: number; key: string }> = [
  { label: "Last 24 hours", days: 1, key: "24h" },
  { label: "Last 7 days", days: 7, key: "7d" },
  { label: "Last 30 days", days: 30, key: "30d" },
  { label: "Last 90 days", days: 90, key: "90d" },
  { label: "All time", days: 0, key: "all" },
];
const DEFAULT_RANGE_KEY = "30d";

// Provider → emoji glyph for the Top Leaking Repos list.  Kept small so
// the row stays compact; falls back to a neutral folder glyph for any
// provider we don't recognise yet.
const PROVIDER_GLYPH: Record<string, string> = {
  github: "🐙",
  gitlab: "🦊",
  bitbucket: "🪣",
  azure_devops: "🔷",
};

// Source category → emoji glyph for the Findings by Source bars.
const CATEGORY_GLYPH: Record<string, string> = {
  "Code Repos": "🧑‍💻",
  "Collaboration": "💬",
  "Docs & Wikis": "📄",
  "Issue Tracking": "🗂️",
  "Cloud Storage": "☁️",
  "DevOps": "⚙️",
  "APIs": "🔌",
  "CRM & Support": "🤝",
  "Other": "🔍",
};

// Backend category key → user-visible display name.  Lets us keep the
// API contract terse ("Code Repos") while showing the fully-spelled
// label on the dashboard.  Falls through to the raw key when no mapping
// exists, so unrecognised categories still render legibly.
const CATEGORY_DISPLAY: Record<string, string> = {
  "Code Repos": "Code Repositories",
};

/* ── Severity-weighted bar fill ── */
// Computes a single CSS color from a {critical,high,medium,low} count map.
// Used by both the source-category bars and the top-repos bars so the bar
// fill carries severity signal — a row that's "100 lows" doesn't read the
// same red as a row that's "100 criticals."
function severityBlendedColor(sev: { critical: number; high: number; medium: number; low: number }): string {
  const total = sev.critical + sev.high + sev.medium + sev.low;
  if (total === 0) return "rgba(148, 163, 184, 0.4)"; // slate
  // Weighted severity score 0-1, then mapped to the red→orange→yellow→slate ramp.
  const score = (sev.critical * 4 + sev.high * 3 + sev.medium * 2 + sev.low) / (total * 4);
  if (score >= 0.7) return "rgba(239, 68, 68, 0.55)";   // red
  if (score >= 0.45) return "rgba(251, 146, 60, 0.55)"; // orange
  if (score >= 0.25) return "rgba(234, 179, 8, 0.5)";   // yellow
  return "rgba(96, 165, 250, 0.4)";                     // blue
}

/* ── Delta badge ── one tiny "↑ 12%" pill under each KPI tile's value ──
   Compares the metric in the current time window to the same-length
   window immediately before it.  The "vs Previous X Days" suffix is
   passed in by the caller so it stays in sync with the range picker;
   that way the badge reads as a complete English phrase ("↑ 12% vs
   Previous 30 Days") rather than a vague "vs Previous" that forces
   the user to glance back up at the picker for context.

   `goodDirection` flips the colour semantics: for most metrics
   (Criticals, Active Leaks) rising is bad → red.  For Auto-Fix
   coverage, rising is good → green. */
function DeltaBadge({ curr, prev, prevLabel, goodDirection = "down" }: {
  curr: number;
  prev: number | undefined;
  prevLabel: string;        // e.g. "Previous 30 Days" — passed in so the
                            // badge tracks the range picker.  Empty
                            // string when range is All Time (the "vs"
                            // suffix then degrades to "Previous Period").
  goodDirection?: "up" | "down";
}) {
  // The "vs <prevLabel>" suffix is the constant anchor — present in
  // every state so the badge always reads as a complete English phrase.
  // Falls back to "Previous Period" when no window is specified
  // (All-Time range, where the backend didn't fetch a prev period).
  const suffix = prevLabel || "Previous Period";

  // No prev-period query was made (All Time) or prev window was empty.
  // Show an em-dash for the missing percentage; the "vs Previous"
  // suffix unambiguously frames it as "no value to compare against."
  if (prev === undefined || prev === 0) {
    return (
      <span className="text-[10px] text-slate-600">
        — <span className="font-normal">vs {suffix}</span>
      </span>
    );
  }
  const pct = Math.round(((curr - prev) / prev) * 100);
  if (pct === 0) {
    return (
      <span className="text-[10px] text-slate-500">
        No Change <span className="text-slate-600 font-normal">vs {suffix}</span>
      </span>
    );
  }
  const rising = pct > 0;
  const isGood = (rising && goodDirection === "up") || (!rising && goodDirection === "down");
  const color = isGood ? "text-emerald-400" : "text-red-400";
  const arrow = rising ? "↑" : "↓";
  // Cap displayed percentage at 999%+ so a near-zero prev period
  // (e.g. a tenant that just started scanning) doesn't surface a
  // shouting "5200%" reading.
  const display = Math.abs(pct) >= 1000 ? "999%+" : `${Math.abs(pct)}%`;
  return (
    <span className={`text-[10px] font-medium ${color}`}>
      {arrow} {display} <span className="text-slate-600 font-normal">vs {suffix}</span>
    </span>
  );
}

/* ── Donut chart for the Verifier Breakdown widget ── */
// Renders a four-segment donut from validation_status counts.  Each
// segment is a colored arc; the centre carries the total verified
// count.  Tooltip shows status name on hover (via the SVG <title>).
function VerifierDonut({ segments, totalLabel }: {
  segments: Array<{ key: string; label: string; count: number; color: string }>;
  totalLabel: string;
}) {
  const total = segments.reduce((acc, s) => acc + s.count, 0);
  const size = 140;
  const stroke = 16;
  const r = (size - stroke) / 2;
  const cx = size / 2;
  const cy = size / 2;
  const c = 2 * Math.PI * r;
  // Empty state — render an inert outline ring so the card still has
  // its visual anchor.
  if (total === 0) {
    return (
      <div className="relative shrink-0" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth={stroke} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-slate-500">0</span>
          <span className="text-[10px] text-slate-600 mt-0.5">{totalLabel}</span>
        </div>
      </div>
    );
  }
  let offset = 0;
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth={stroke} />
        {segments.map((s) => {
          if (s.count === 0) return null;
          const len = (s.count / total) * c;
          const dasharray = `${len} ${c - len}`;
          const arc = (
            <circle
              key={s.key}
              cx={cx}
              cy={cy}
              r={r}
              fill="none"
              stroke={s.color}
              strokeWidth={stroke}
              strokeDasharray={dasharray}
              strokeDashoffset={-offset}
              strokeLinecap="butt"
            >
              <title>{s.label}: {s.count}</title>
            </circle>
          );
          offset += len;
          return arc;
        })}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-bold text-white">{total.toLocaleString()}</span>
        <span className="text-[10px] text-slate-500 mt-0.5">{totalLabel}</span>
      </div>
    </div>
  );
}

/* ── Findings Trend chart (responsive SVG, no chart-lib dependency) ── */
// Renders a 1×W×H area chart from daily-counts data.  Uses viewBox +
// preserveAspectRatio="none" so the chart stretches to fill its parent
// width responsively without needing a resize listener.  No external
// chart library — the dashboard bundle already includes plenty of code,
// and the visual is simple enough that hand-rolled SVG is the right
// trade-off (≈ 20 lines vs ≈ 100 KB recharts/visx).
function FindingsTrendChart({ data }: { data: Array<{ date: string; count: number }> }) {
  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center" style={{ height: 180 }}>
        <p className="text-[11px] text-slate-600">No findings in this window</p>
      </div>
    );
  }

  // Fixed virtual coordinate space — viewBox handles responsive scaling.
  const W = 800;
  const H = 180;
  const PAD = 4;
  const innerH = H - PAD * 2;

  const max = Math.max(...data.map(d => d.count), 1);
  const stepX = W / Math.max(data.length - 1, 1);
  const points = data.map((d, i) => ({
    x: i * stepX,
    y: PAD + innerH - (d.count / max) * innerH,
    count: d.count,
    date: d.date,
  }));
  const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x} ${p.y}`).join(" ");
  const areaPath = `${linePath} L ${W} ${H} L 0 ${H} Z`;
  const last = points[points.length - 1];

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="none"
      style={{ width: "100%", height: "100%" }}
      className="overflow-visible"
    >
      <defs>
        <linearGradient id="trendGradient" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="rgba(239,68,68,0.35)" />
          <stop offset="100%" stopColor="rgba(239,68,68,0.02)" />
        </linearGradient>
      </defs>
      <path d={areaPath} fill="url(#trendGradient)" />
      <path d={linePath} fill="none" stroke="#ef4444" strokeWidth={1.5} strokeLinecap="round" vectorEffect="non-scaling-stroke" />
      <circle cx={last.x} cy={last.y} r={3} fill="#ef4444" />
    </svg>
  );
}


export default function DashboardPage() {
  const { user } = useAuthStore(); // kept for future use (welcome greeting, etc.)
  void user;

  const [loading, setLoading] = useState(true);

  // Time-range state — initialised from ?range= URL param so the view is
  // shareable / bookmarkable.  `days === 0` means "all time".
  const initialRangeKey = typeof window !== "undefined"
    ? new URLSearchParams(window.location.search).get("range") || DEFAULT_RANGE_KEY
    : DEFAULT_RANGE_KEY;
  const [rangeKey, setRangeKey] = useState<string>(initialRangeKey);
  const rangeMeta = RANGE_OPTIONS.find((r) => r.key === rangeKey) || RANGE_OPTIONS[2];
  const rangeDays = rangeMeta.days;

  // Human-readable suffix for the DeltaBadge — matches the active range
  // so the badge reads as a complete phrase ("↑ 12% vs Previous 30 Days")
  // rather than the ambiguous "vs Previous" that forced the user to glance
  // back at the picker.  Empty string for All-Time (DeltaBadge falls back
  // to "No Baseline" because prev-period data isn't fetched there).
  const prevLabel =
    rangeKey === "24h" ? "Previous 24 Hours" :
    rangeKey === "7d"  ? "Previous 7 Days"   :
    rangeKey === "30d" ? "Previous 30 Days"  :
    rangeKey === "90d" ? "Previous 90 Days"  : "";

  const [metrics, setMetrics] = useState<any>(null);
  const [findingsM, setFindingsM] = useState<any>(null);
  const [remediationM, setRemediationM] = useState<any>(null);
  const [repoCount, setRepoCount] = useState(0);
  const [mttrData, setMttrData] = useState<any>(null);
  const [trendData, setTrendData] = useState<any>(null);
  const [categoryData, setCategoryData] = useState<any>(null);
  const [topRepos, setTopRepos] = useState<any>(null);
  // Row 5 + Row 6 (below-the-fold Vooda differentiator widgets).
  const [verifierData, setVerifierData] = useState<any>(null);
  const [aiAccuracy, setAiAccuracy] = useState<any>(null);
  const [activityFeed, setActivityFeed] = useState<any[]>([]);

  useEffect(() => {
    setLoading(true);
    // Persist picker state to URL.
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      if (rangeKey === DEFAULT_RANGE_KEY) params.delete("range");
      else params.set("range", rangeKey);
      const qs = params.toString();
      window.history.replaceState(null, "", window.location.pathname + (qs ? `?${qs}` : "") + window.location.hash);
    }
    const daysParam = rangeDays > 0 ? rangeDays : undefined;
    // Trend chart works at the lower of (rangeDays, 90) — over 90 days the
    // daily line gets too noisy to be useful at the FE width budget.
    const trendDays = Math.min(rangeDays > 0 ? rangeDays : 30, 90);

    Promise.allSettled([
      // `with_delta=true` so each KPI tile can render its period-over-period
      // delta badge without a second round-trip.  Backend handles the
      // prev-window query in the same response.
      getMetricsOverview(daysParam, daysParam !== undefined).then(r => setMetrics(r.data)),
      getFindingsMetrics().then(r => setFindingsM(r.data)),
      getRemediationMetrics().then(r => setRemediationM(r.data)),
      getRepositories({ page_size: 1 }).then(r => {
        const d = r.data;
        setRepoCount(d?.total ?? (Array.isArray(d) ? d.length : (d?.items?.length || 0)));
      }),
      getMTTRMetrics().then(r => setMttrData(r.data)),
      getTrendData(trendDays).then(r => setTrendData(r.data)),
      getFindingsByCategory(daysParam).then(r => setCategoryData(r.data)).catch(() => setCategoryData(null)),
      getTopLeakingRepos(daysParam, 7).then(r => setTopRepos(r.data)).catch(() => setTopRepos(null)),
      // Row 5 — Verifier Breakdown source data (by_validation field).
      getFindingsBreakdown().then(r => setVerifierData(r.data)).catch(() => setVerifierData(null)),
      // Row 5 — AI Triage Confidence (precision/recall + confidence distribution).
      getAIAccuracy().then(r => setAiAccuracy(r.data)).catch(() => setAiAccuracy(null)),
      // Row 6 — Recent Activity feed.  Server-side `exclude_noise=true` drops
      // auth churn (logins) and system-internal events (watchdog reaps,
      // dead-lettered notifications) so the dashboard surfaces security-relevant
      // activity only; the full audit trail remains at /settings/admin?tab=audit.
      // page_size 20 → ~8 displayed leaves headroom for the client-side backstop.
      getAuditEvents({ exclude_noise: "true", page_size: "20" })
        .then(r => setActivityFeed(Array.isArray(r.data) ? r.data : []))
        .catch(() => setActivityFeed([])),
    ]).finally(() => setLoading(false));
  }, [rangeKey, rangeDays]);

  // ── Derived KPI values ────────────────────────────────────────────
  // `total` is OPEN findings — the number every risk tile reconciles
  // against. `detected` is every detection including the ones triage
  // settled; it is context for the noise rate, never a risk figure.
  const total = metrics?.total_findings ?? 0;
  const detected = metrics?.detected_total ?? total;
  const filteredNoise = metrics?.filtered_as_noise ?? 0;
  const noisePct = detected > 0 ? Math.round((filteredNoise / detected) * 100) : 0;
  const sev = (key: string) => (metrics?.by_severity?.[`Severity.${key}`] ?? 0) + (metrics?.by_severity?.[key.toLowerCase()] ?? 0);
  const criticals = sev("CRITICAL"), highs = sev("HIGH"), mediums = sev("MEDIUM"), lows = sev("LOW"), infos = sev("INFO");
  const critHighTotal = criticals + highs;
  // Sanity check — criticals + highs + mediums + lows + infos should sum to
  // `total`.  If they don't, the helper-line totals will look off by one.
  // Surfacing Info in the helper is why the row reconciles now.
  void (criticals + highs + mediums + lows + infos);

  // Open-scoped count from the overview (matches the queue the chip
  // links to); the classification breakdown is unfiltered and would
  // also count suppressed rows.
  const needsReview = metrics?.needs_review_open
    ?? ((metrics?.by_classification?.["Classification.NEEDS_REVIEW"] ?? 0) + (metrics?.by_classification?.["needs_review"] ?? 0));

  // MTTR — server-side endpoint.  Used by the MTTR tile + the posture banner.
  const avgMttrHours = mttrData?.avg_hours ?? null;
  const mttrResolved = mttrData?.resolved_count ?? 0;

  // Active/Inactive secrets — verifier-confirmed live credentials.  Tile +
  // posture banner read this; the Active Credentials quick action also.
  const activeSecrets = metrics?.active_secrets || 0;
  const inactiveSecrets = metrics?.inactive_secrets || 0;

  // Previous-period values for delta badges.  Server returns these inside
  // `previous_period` when `with_delta=true` is passed to /metrics/overview.
  const prev = metrics?.previous_period;
  const prevTotal: number | undefined = prev?.total_findings;
  const prevCritHigh: number | undefined = prev
    ? (
        (prev.by_severity?.["Severity.CRITICAL"] ?? 0) + (prev.by_severity?.["critical"] ?? 0) +
        (prev.by_severity?.["Severity.HIGH"] ?? 0)     + (prev.by_severity?.["high"] ?? 0)
      )
    : undefined;
  const prevActive: number | undefined = prev?.active_secrets;

  // Auto-Remediation — split into Covered (engine drafted any patch) and
  // Applied (human approved/applied so the fix actually landed).  Single
  // "Remediation Rate" number that lived here previously was misleading.
  // Numerators come from the overview response, computed under the SAME
  // open + time-window scope as `total` — a percentage only means
  // something when both sides of the division share a scope. The
  // standalone /remediation endpoint counts all-time across every
  // classification; dividing that by a windowed open denominator
  // inflates the figure and can exceed 100%. It remains the fallback
  // for an older API.
  const remStats = remediationM?.by_remediation_status ?? {};
  const _remCount = (k: string) =>
    (remStats[k] ?? 0) + (remStats[`RemediationStatus.${k.toUpperCase()}`] ?? 0);
  const remediationCovered = metrics?.remediation_covered
    ?? (_remCount("patch_generated") + _remCount("approved") + _remCount("applied"));
  const remediationApplied = metrics?.remediation_applied
    ?? (_remCount("approved") + _remCount("applied"));
  const pendingPatches = remediationCovered - remediationApplied;
  const appliedPatches = metrics?.remediation_applied ?? _remCount("applied");
  const coveragePct = total > 0 ? Math.min(100, Math.round((remediationCovered / total) * 100)) : 0;
  const appliedPct = total > 0 ? Math.min(100, Math.round((remediationApplied / total) * 100)) : 0;

  // ── Posture status — three tiers driven by KPI signal strength ────
  //   At Risk:        any verifier-confirmed live credentials
  //   Action Needed:  criticals or highs present, but no active leaks
  //   Healthy:        no critical / high findings
  let postureLabel = "Healthy";
  let postureColor: "red" | "orange" | "emerald" = "emerald";
  if (activeSecrets > 0) { postureLabel = "At Risk"; postureColor = "red"; }
  else if (criticals > 0 || highs > 0) { postureLabel = "Action Needed"; postureColor = "orange"; }
  const postureDotColor =
    postureColor === "red" ? "#f87171" :
    postureColor === "orange" ? "#fb923c" : "#34d399";
  const postureDotShadow =
    postureColor === "red" ? "0 0 10px rgba(248,113,113,0.7)" :
    postureColor === "orange" ? "0 0 8px rgba(251,146,60,0.6)" :
    "0 0 8px rgba(52,211,153,0.55)";
  const postureTextColor =
    postureColor === "red" ? "#fca5a5" :
    postureColor === "orange" ? "#fdba74" : "#6ee7b7";
  const postureBorder =
    postureColor === "red" ? "rgba(248,113,113,0.22)" :
    postureColor === "orange" ? "rgba(251,146,60,0.22)" : "rgba(52,211,153,0.22)";
  const postureBg =
    postureColor === "red" ? "rgba(248,113,113,0.06)" :
    postureColor === "orange" ? "rgba(251,146,60,0.05)" : "rgba(52,211,153,0.05)";

  // ── Findings by Source — pack top 5 + fold tail into "+N other" ────
  const allCategories: Array<{ category: string; count: number; severity: any }> =
    categoryData?.categories || [];
  const categoryTotal = categoryData?.total || allCategories.reduce((acc, c) => acc + c.count, 0);
  const topCategories = allCategories.slice(0, 5);
  const tailCount = allCategories.slice(5).reduce((acc, c) => acc + c.count, 0);
  const tailSize = allCategories.length - 5;

  // ── Top Leaking Repos — rows already sorted desc by backend ────────
  const repos: Array<{ repository_id: string; name: string; provider: string; count: number; severity: any }> =
    topRepos?.repos || [];
  const repoMaxCount = topRepos?.max_count || 1;
  // Scan-scope coverage (configured / scanned / leaking) — shown in the card
  // header so the dashboard reports scope even when there are zero findings.
  const cov = topRepos?.coverage as
    | { total_configured: number; total_scanned: number; total_leaking: number }
    | undefined;
  // The banner says "Scanned" — count repositories that actually have a
  // scan, not everything configured. Falls back to the configured count
  // only when the coverage payload is unavailable.
  const scannedRepoCount = cov?.total_scanned ?? repoCount;

  // ── Trend chart data ─────────────────────────────────────────────
  const dailyTrend: Array<{ date: string; count: number }> = trendData?.daily_counts || [];
  const trendChangePct: number | null = trendData?.period_summary?.change_pct ?? null;

  // ── Format helpers ───────────────────────────────────────────────
  const fmtMttr = (hours: number | null): { value: string; unit: string } => {
    if (hours === null) return { value: "—", unit: "" };
    const s = hours * 3600;
    if (s < 3600) {
      const m = Math.round(s / 60);
      return { value: String(m), unit: m === 1 ? "Minute" : "Minutes" };
    }
    if (s < 86400) {
      const h = Math.round(s / 3600);
      return { value: String(h), unit: h === 1 ? "Hour" : "Hours" };
    }
    const d = Math.round(s / 86400);
    return { value: String(d), unit: d === 1 ? "Day" : "Days" };
  };
  const mttrParts = fmtMttr(avgMttrHours);

  // ── Row 5: Verifier Breakdown ────────────────────────────────────
  // Map raw validation_status counts → ordered display segments.  We
  // fix the order (Live → Inactive → Awaiting → Not Validated) so the
  // donut reads as a "stages of verification" arc rather than random.
  const byValidation = (verifierData?.by_validation as Record<string, number>) || {};
  const verifierSegments = [
    { key: "active",        label: "Live (Verified)",        count: byValidation["active"] || 0,        color: "#ef4444" },
    { key: "inactive",      label: "Verified Inactive",      count: byValidation["inactive"] || 0,      color: "#22c55e" },
    { key: "pending",       label: "Awaiting Verification",  count: byValidation["pending"] || 0,       color: "#fbbf24" },
    { key: "not_validated", label: "Not Validated",          count: byValidation["not_validated"] || 0, color: "#64748b" },
  ];
  const verifierTotal = verifierSegments.reduce((acc, s) => acc + s.count, 0);
  // Per-provider top-3 list for the right-side sub-list — uses the
  // by_provider object on the same endpoint.  Numerically these are
  // verifier-attempted findings per provider, which is a good proxy
  // for "what's being verified."
  const byProvider = (verifierData?.by_provider as Record<string, number>) || {};
  const topProviders = Object.entries(byProvider)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4)
    .map(([provider, count]) => ({ provider, count: count as number }));

  // ── Row 5: AI Triage Confidence ──────────────────────────────────
  const aiTriaged = aiAccuracy?.ai_triaged_findings || 0;
  const aiConfirmed = aiAccuracy?.user_confirmed_decisions || 0;
  // Accuracy is agreement with HUMAN verdicts. With zero human
  // confirmations it is undefined, not 0.0% — showing a number would
  // claim the AI has been measured when it hasn't.
  const aiAccuracyPct = aiConfirmed > 0 ? (aiAccuracy?.accuracy_pct || "—") : "—";
  const aiConfDist = (aiAccuracy?.confidence_distribution as Record<string, number>) || { low: 0, medium: 0, high: 0, very_high: 0 };
  const aiConfTotal = Object.values(aiConfDist).reduce((acc, v) => acc + (v as number), 0);

  // ── Row 6: Recent Activity feed ──────────────────────────────────
  // Audit endpoint returns events newest-first.  Filter out repetitive
  // login events so the feed surfaces operationally meaningful events
  // (scans, classifications, integrations, remediation).  If after
  // filtering we have fewer than 3 entries, fall back to including
  // logins — better to show something than an empty feed.
  type AuditEvent = { id: string; action: string; resource_type: string | null; detail: string | null; user_name: string | null; created_at: string };
  const allEvents = activityFeed as AuditEvent[];
  const meaningfulEvents = allEvents.filter(e =>
    e.resource_type !== "auth" && !(e.action || "").startsWith("login")
  );
  const displayEvents = (meaningfulEvents.length >= 3 ? meaningfulEvents : allEvents).slice(0, 8);
  // Time-ago formatter — short form, e.g. "2m ago", "3h ago", "5d ago".
  const fmtTimeAgo = (iso: string): string => {
    try {
      const then = new Date(iso).getTime();
      const diffS = Math.max(0, Math.floor((Date.now() - then) / 1000));
      if (diffS < 60) return `${diffS}s Ago`;
      const m = Math.floor(diffS / 60);
      if (m < 60) return `${m}m Ago`;
      const h = Math.floor(m / 60);
      if (h < 24) return `${h}h Ago`;
      const d = Math.floor(h / 24);
      return `${d}d Ago`;
    } catch { return ""; }
  };
  // Glyph map keyed by resource_type — wraps each event in a tiny icon
  // pill so the eye can scan the column even when detail text is short.
  const ACTIVITY_GLYPH: Record<string, string> = {
    scan: "📡", finding: "🔍", integration: "🔌",
    remediation: "🔧", rotation_event: "🔄", user: "👤",
    auth: "🔐", repository: "📦", scan_source: "🌐",
    ai_model: "🤖", api_key: "🔑", suppression: "🤫",
  };

  /* ─────────────────────────────────────────────────────────────────
     LOADING SKELETON — shape-matches the eventual layout so the
     paint feels like content sliding in, not a fresh render.
     ───────────────────────────────────────────────────────────────── */
  if (loading) {
    return (
      <AppShell pageTitle="Overview">
        <div className="space-y-4 max-w-[1400px]">
          <Skeleton w="100%" h={48} radius={8} />
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
            {Array.from({ length: 5 }).map((_, i) => <SkeletonKpiTile key={i} />)}
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
            <div className="lg:col-span-3"><SkeletonCard rows={5} /></div>
            <div className="lg:col-span-2"><SkeletonCard rows={5} /></div>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
            <div className="lg:col-span-3"><SkeletonCard rows={5} /></div>
            <div className="lg:col-span-2"><SkeletonCard rows={4} /></div>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
            <div className="lg:col-span-3"><SkeletonCard rows={5} /></div>
            <div className="lg:col-span-2"><SkeletonCard rows={4} /></div>
          </div>
          <SkeletonCard rows={6} />
        </div>
      </AppShell>
    );
  }

  /* ─────────────────────────────────────────────────────────────────
     PAGE RENDER
     ───────────────────────────────────────────────────────────────── */
  return (
    <AppShell pageTitle="Overview">
      <div className="space-y-4 max-w-[1400px]">

        {/* ══════ ROW 1 — POSTURE BANNER ══════════════════════════════
            Status pill + (optional) source-count + time-range picker.
            Numeric KPIs moved to Row 2 — keeps the banner from
            duplicating the tiles. */}
        <div
          className="rounded-lg flex items-center justify-between gap-4 px-4 py-2.5"
          style={{ background: postureBg, border: `1px solid ${postureBorder}` }}
        >
          <div className="flex items-center gap-3 min-w-0">
            <div className="flex items-center gap-2">
              <span
                className="w-2 h-2 rounded-full shrink-0"
                style={{ background: postureDotColor, boxShadow: postureDotShadow }}
              />
              <span className="text-sm font-semibold" style={{ color: postureTextColor }}>
                {postureLabel}
              </span>
            </div>
            <span className="text-slate-700">·</span>
            <span className="text-xs text-slate-400">
              <b className="text-white font-semibold">{scannedRepoCount}</b> {scannedRepoCount === 1 ? "Repository" : "Repositories"} Scanned
            </span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <svg className="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" style={{ color: "#64748b" }}>
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
            <select
              value={rangeKey}
              onChange={(e) => setRangeKey(e.target.value)}
              className="select-dark text-xs min-w-[130px]"
              style={{ paddingTop: "0.35rem", paddingBottom: "0.35rem" }}
              title="Time range — scopes all metrics in this view"
              aria-label="Dashboard time range"
            >
              {RANGE_OPTIONS.map((r) => <option key={r.key} value={r.key}>{r.label}</option>)}
            </select>
          </div>
        </div>

        {/* ══════ ROW 2 — KPI STRIP (5 EQUAL TILES) ════════════════════
            Total · Severity Mix · Active · MTTR · Auto-Fix.  Each
            tile shows a current value, a delta badge vs the previous
            window of the same size, and a one-line helper.  Delta
            colour follows whether the metric is "good rising" (only
            Auto-Fix) or "bad rising" (the rest). */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          {/* Tile 1: Total Secrets — helper drops the repo count (banner
              already carries "N Repository Scanned") and instead surfaces
              the per-repo density, which is the more decision-grade
              follow-on number: 50 secrets in 1 repo is alarming, 50
              spread across 50 repos is routine. */}
          <div className="card p-4">
            <p className="text-[10px] text-red-400 uppercase tracking-wider font-medium">Open Secrets</p>
            <div className="flex items-baseline gap-2 mt-1.5">
              <span className="text-3xl font-bold text-white">{total.toLocaleString()}</span>
            </div>
            <div className="mt-1"><DeltaBadge curr={total} prev={prevTotal} prevLabel={prevLabel} goodDirection="down" /></div>
            <p className="text-[11px] text-slate-500 mt-1">
              {detected > 0
                ? <>{detected.toLocaleString()} Detected{filteredNoise > 0 && <> · {filteredNoise.toLocaleString()} Filtered As Noise ({noisePct}%)</>}</>
                : "Awaiting First Scan"}
            </p>
          </div>

          {/* Tile 2: Severity Mix — full severity names spelled out; the
              4-bucket sum reconciles with Total Secrets (was off-by-one
              because Info wasn't surfaced before). */}
          <div className="card p-4">
            <p className="text-[10px] text-red-400 uppercase tracking-wider font-medium">Severity Mix</p>
            <div className="flex items-baseline gap-1.5 mt-1.5">
              <span className="text-3xl font-bold text-red-400">{criticals}</span>
              <span className="text-[11px] text-red-400/60">Critical</span>
              <span className="text-base font-semibold text-orange-400 ml-1">{highs}</span>
              <span className="text-[11px] text-orange-400/60">High</span>
            </div>
            <div className="mt-1"><DeltaBadge curr={critHighTotal} prev={prevCritHigh} prevLabel={prevLabel} goodDirection="down" /></div>
            <p className="text-[11px] text-slate-500 mt-1">
              <span className="text-yellow-400/70">{mediums}</span> Medium · <span className="text-blue-400/70">{lows}</span> Low{infos > 0 && <> · <span className="text-slate-400/70">{infos}</span> Info</>}
            </p>
          </div>

          {/* Tile 3: Active Credentials (Vooda differentiator) */}
          <div className="card p-4">
            <p className={`text-[10px] uppercase tracking-wider font-medium ${activeSecrets > 0 ? "text-red-400" : "text-green-400"}`}>Active Credentials</p>
            <p className={`text-3xl font-bold mt-1.5 ${activeSecrets > 0 ? "text-red-400" : "text-green-400"}`}>{activeSecrets}</p>
            <div className="mt-1"><DeltaBadge curr={activeSecrets} prev={prevActive} prevLabel={prevLabel} goodDirection="down" /></div>
            <p className="text-[11px] text-slate-500 mt-1">
              {inactiveSecrets > 0 ? `${inactiveSecrets} Verified Inactive` : "Verifier-Confirmed Live"}
            </p>
          </div>

          {/* Tile 4: MTTR */}
          <div className="card p-4">
            <p className="text-[10px] text-purple-400 uppercase tracking-wider font-medium">Mean Time To Remediate</p>
            <div className="flex items-baseline gap-1.5 mt-1.5">
              <span className={`text-3xl font-bold ${avgMttrHours === null ? "text-slate-500" : avgMttrHours < 48 ? "text-green-400" : "text-orange-400"}`}>{mttrParts.value}</span>
              {mttrParts.unit && <span className={`text-[11px] ${avgMttrHours === null ? "text-slate-500" : avgMttrHours < 48 ? "text-green-400" : "text-orange-400"}`}>{mttrParts.unit}</span>}
            </div>
            <div className="mt-1">
              {/* MTTR's prev-period delta isn't currently tracked server-side
                  — show a neutral resolved-count line so the tile keeps the
                  same vertical rhythm as its peers. */}
              <span className="text-[10px] text-slate-600">{mttrResolved > 0 ? `${mttrResolved} Resolved` : "No Resolved Findings Yet"}</span>
            </div>
            <p className="text-[11px] text-slate-500 mt-1">Average Time-To-Fix</p>
          </div>

          {/* Tile 5: Auto-Fix coverage / applied (Vooda differentiator) */}
          <div className="card p-4">
            <p className="text-[10px] text-cyan-400 uppercase tracking-wider font-medium">Auto-Fix</p>
            <div className="flex items-baseline gap-1.5 mt-1.5" title="Covered = engine drafted a patch · Applied = human approved or applied">
              <span className={`text-3xl font-bold ${remediationCovered > 0 ? "text-cyan-400" : "text-slate-500"}`}>{coveragePct}%</span>
              <span className="text-[11px] text-slate-500">Covered</span>
              <span className="text-slate-700 mx-0.5">·</span>
              <span className={`text-base font-semibold ${remediationApplied > 0 ? "text-emerald-400" : "text-slate-600"}`}>{appliedPct}%</span>
              <span className="text-[10px] text-slate-500">Applied</span>
            </div>
            <div className="mt-1">
              <span className="text-[10px] text-slate-600">
                {pendingPatches > 0 ? `${pendingPatches} Draft · ${appliedPatches} Applied` : "No Patches Yet"}
              </span>
            </div>
            <p className="text-[11px] text-slate-500 mt-1">{remediationCovered} Of {total}</p>
          </div>
        </div>

        {/* ══════ ROW 3 — TREND  +  FINDINGS BY SOURCE ════════════════
            3-col + 2-col split.  The chart on the left answers "are
            we getting better?"; the bars on the right answer "where
            is leak concentration?".  Both clickable through to the
            findings page with the appropriate filter. */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
          {/* Findings Trend — wider */}
          <div className="lg:col-span-3 card p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Findings Trend · {rangeMeta.label.replace("Last ", "")}</h3>
              {trendChangePct !== null && (
                <span className={`text-[11px] font-medium ${trendChangePct < 0 ? "text-emerald-400" : trendChangePct > 0 ? "text-red-400" : "text-slate-500"}`}>
                  {trendChangePct < 0 ? "▼" : trendChangePct > 0 ? "▲" : "·"} {Math.abs(trendChangePct) >= 1000 ? "999%+" : `${Math.abs(trendChangePct)}%`} vs {prevLabel || "Previous Period"}
                </span>
              )}
            </div>
            <div className="w-full" style={{ height: 180 }}>
              <FindingsTrendChart data={dailyTrend} />
            </div>
            {dailyTrend.length > 0 && (
              <div className="flex items-center justify-between mt-1 text-[10px] text-slate-600">
                <span>{dailyTrend[0]?.date}</span>
                <span>{dailyTrend[dailyTrend.length - 1]?.date}</span>
              </div>
            )}
          </div>

          {/* Findings by Source — narrower */}
          <div className="lg:col-span-2 card p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Findings by Source</h3>
              <Link href="/findings" className="text-[10px] flex items-center gap-1" style={{ color: "#ef4444" }}>
                View All <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
              </Link>
            </div>
            {topCategories.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8">
                <p className="text-[11px] text-slate-600">No Findings In This Window</p>
              </div>
            ) : (
              <div className="space-y-2">
                {topCategories.map((c) => {
                  const pct = categoryTotal > 0 ? Math.round((c.count / categoryTotal) * 100) : 0;
                  const fill = severityBlendedColor(c.severity);
                  return (
                    <Link
                      key={c.category}
                      href={`/findings?category=${encodeURIComponent(c.category)}`}
                      className="block group"
                    >
                      <div className="flex items-center gap-2 text-[12px]">
                        <span className="w-5 text-center shrink-0">{CATEGORY_GLYPH[c.category] || "🔍"}</span>
                        <span className="text-slate-300 group-hover:text-white transition-colors truncate flex-1">{CATEGORY_DISPLAY[c.category] || c.category}</span>
                        <span className="text-slate-500 tabular-nums shrink-0">{c.count}</span>
                        <span className="text-slate-600 tabular-nums shrink-0 w-9 text-right">{pct}%</span>
                      </div>
                      <div className="h-1.5 mt-1 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.04)" }}>
                        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: fill }} />
                      </div>
                    </Link>
                  );
                })}
                {tailSize > 0 && (
                  <Link href="/findings" className="block pt-1 text-[11px] text-slate-500 hover:text-slate-300 transition-colors">
                    … +{tailSize} Other {tailSize === 1 ? "Source" : "Sources"} ({tailCount})
                  </Link>
                )}
              </div>
            )}
          </div>
        </div>

        {/* ══════ ROW 4 — TOP LEAKING REPOS  +  QUICK ACTIONS ═════════
            Same 3+2 split as Row 3.  Repos list is the "fix this on
            Monday" tactical widget.  Quick Actions trimmed from 5 to
            4 (dropped "Add Repository" — onboarding-only). */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
          {/* Top Leaking Repos — wider */}
          <div className="lg:col-span-3 card p-4">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Top Leaking Repositories</h3>
              <Link href="/repositories" className="text-[10px] flex items-center gap-1" style={{ color: "#ef4444" }}>
                View All <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
              </Link>
            </div>
            {cov && (
              <div className="flex items-center gap-2 mb-3 text-[10px] tabular-nums text-slate-500">
                <span><span className="text-slate-200 font-semibold">{cov.total_configured}</span> Configured</span>
                <span className="text-slate-700">·</span>
                <span><span className={`font-semibold ${cov.total_scanned < cov.total_configured ? "text-amber-400" : "text-slate-200"}`}>{cov.total_scanned}</span> Scanned</span>
                <span className="text-slate-700">·</span>
                <span><span className={`font-semibold ${cov.total_leaking > 0 ? "text-red-400" : "text-green-400"}`}>{cov.total_leaking}</span> Leaking</span>
              </div>
            )}
            {repos.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8">
                <p className="text-[11px] text-slate-600">No Findings In This Window</p>
                <Link href="/repositories" className="mt-2 text-xs font-medium" style={{ color: "#ef4444" }}>Connect A Repository →</Link>
              </div>
            ) : (
              <div className="space-y-1.5">
                {repos.map((r) => {
                  const pct = Math.round((r.count / repoMaxCount) * 100);
                  const fill = severityBlendedColor(r.severity);
                  return (
                    <Link
                      key={r.repository_id}
                      href={`/findings?repository_id=${r.repository_id}`}
                      className="block px-2 py-1 rounded-md transition-colors hover:bg-white/[0.02]"
                    >
                      <div className="flex items-center gap-2.5 text-[12px]">
                        <span className="w-5 text-center shrink-0">{PROVIDER_GLYPH[r.provider] || "📦"}</span>
                        <span className="text-slate-300 truncate flex-1 font-medium">{r.name}</span>
                        {r.severity.critical > 0 && (
                          <span className="text-[10px] tabular-nums px-1.5 py-0.5 rounded shrink-0" style={{ background: "rgba(239,68,68,0.15)", color: "#fca5a5" }}>
                            {r.severity.critical} Critical
                          </span>
                        )}
                        {r.severity.high > 0 && (
                          <span className="text-[10px] tabular-nums px-1.5 py-0.5 rounded shrink-0" style={{ background: "rgba(251,146,60,0.15)", color: "#fdba74" }}>
                            {r.severity.high} High
                          </span>
                        )}
                        <span className="text-white font-semibold tabular-nums shrink-0 w-10 text-right">{r.count}</span>
                      </div>
                      <div className="h-1 mt-1 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.04)" }}>
                        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: fill }} />
                      </div>
                    </Link>
                  );
                })}
              </div>
            )}
          </div>

          {/* Quick Actions — narrower */}
          <div className="lg:col-span-2 card p-4">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Quick Actions</h3>
            <div className="space-y-1.5">
              {[
                {
                  href: "/findings?validation_status=active",
                  label: "Active Credentials",
                  desc: activeSecrets > 0 ? `${activeSecrets} Verified Live — Rotate Now` : "No Active Leaks Confirmed",
                  color: "bg-red-500/15", tc: "text-red-400",
                  icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" />,
                },
                {
                  href: `/findings${needsReview > 0 ? "?classification=NEEDS_REVIEW" : ""}`,
                  label: "Triage Queue",
                  desc: needsReview > 0 ? `${needsReview} Findings Need Review` : "Queue Clear",
                  color: "bg-yellow-500/15", tc: "text-yellow-400",
                  icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />,
                },
                {
                  href: "/findings?remediation_status=PATCH_GENERATED",
                  label: "Pending Patches",
                  desc: pendingPatches > 0 ? `${pendingPatches} Fixes Await Approval` : "No Patches Pending",
                  color: "bg-purple-500/15", tc: "text-purple-400",
                  icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 13l4 4L19 7" />,
                },
                {
                  href: "/secrets/rotation",
                  label: "Rotation Queue",
                  desc: activeSecrets > 0 ? `${activeSecrets} Awaiting Rotation` : "All Current Leaks Rotated",
                  color: "bg-orange-500/15", tc: "text-orange-400",
                  icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />,
                },
              ].map((a) => (
                <Link
                  key={a.href}
                  href={a.href}
                  className="flex items-center gap-2.5 px-2 py-1.5 rounded-lg transition-all duration-200"
                  style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)" }}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.04)"; (e.currentTarget as HTMLElement).style.borderColor = "rgba(255,255,255,0.08)"; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.02)"; (e.currentTarget as HTMLElement).style.borderColor = "rgba(255,255,255,0.05)"; }}
                >
                  <div className={`w-7 h-7 rounded-lg ${a.color} flex items-center justify-center shrink-0`}>
                    <svg className={`w-3.5 h-3.5 ${a.tc}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">{a.icon}</svg>
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-[13px] text-slate-200 font-medium">{a.label}</p>
                    <p className="text-[10px] text-slate-500 truncate">{a.desc}</p>
                  </div>
                  <svg className="w-3.5 h-3.5 text-slate-600 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5l7 7-7 7" /></svg>
                </Link>
              ))}
            </div>
          </div>
        </div>

        {/* ══════ ROW 5 — VERIFIER BREAKDOWN  +  AI TRIAGE CONFIDENCE ══
            Vooda's competitive moat surfaced below the fold.  Same 3+2
            split as Rows 3 and 4 so the vertical column divider stays
            aligned through the whole page. */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
          {/* Verifier Breakdown — wider (donut + per-provider list) */}
          <div className="lg:col-span-3 card p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Verifier Breakdown</h3>
              <span className="text-[10px] text-slate-600">Active Provider-Side Check</span>
            </div>
            {verifierTotal === 0 && Object.keys(byProvider).length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8">
                <p className="text-[11px] text-slate-600">No Findings Sent To Verifier Yet</p>
              </div>
            ) : (
              <div className="flex items-center gap-6">
                <VerifierDonut segments={verifierSegments} totalLabel="Findings" />
                {/* Right side: stage labels + counts (donut legend), then a
                    thin separator + the top-4 providers being verified.
                    Two columns of information at one glance. */}
                <div className="flex-1 min-w-0 grid grid-cols-2 gap-x-4 gap-y-1.5">
                  {verifierSegments.map((s) => (
                    <div key={s.key} className="flex items-center gap-2 text-[12px]">
                      <span className="w-2 h-2 rounded-full shrink-0" style={{ background: s.color }} />
                      <span className="text-slate-400 truncate flex-1">{s.label}</span>
                      <span className="text-slate-300 tabular-nums">{s.count}</span>
                    </div>
                  ))}
                  {topProviders.length > 0 && (
                    <div className="col-span-2 pt-2 mt-1 border-t border-white/[0.04]">
                      <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1.5">Top Providers</p>
                      <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                        {topProviders.map(p => (
                          <div key={p.provider} className="flex items-center gap-2 text-[11px]">
                            <span className="text-slate-400 truncate flex-1">
                              {p.provider.charAt(0).toUpperCase() + p.provider.slice(1)}
                            </span>
                            <span className="text-slate-500 tabular-nums">{p.count}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* AI Triage Confidence — narrower */}
          <div className="lg:col-span-2 card p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">AI Triage Confidence</h3>
              <span className="text-[10px] text-slate-600">Per-Tenant Calibration</span>
            </div>
            {aiTriaged === 0 ? (
              <div className="flex flex-col items-center justify-center py-8">
                <p className="text-[11px] text-slate-600">No AI Triage Yet</p>
              </div>
            ) : (
              <>
                {/* Big accuracy number + raw triage volume. */}
                <div className="flex items-baseline gap-3 mb-3">
                  <span className={`text-3xl font-bold ${aiConfirmed === 0 ? "text-slate-500" : "text-emerald-400"}`}>{aiAccuracyPct}</span>
                  <span className="text-[11px] text-slate-500">Accuracy</span>
                </div>
                <p className="text-[11px] text-slate-500 mb-3">
                  {aiTriaged} Triaged · {aiConfirmed} Confirmed By Humans
                </p>
                {/* Confidence distribution — one stacked bar.  The
                    proportions show how confident the AI was on the
                    triaged set; right-skewed (very_high) means the
                    model is decisive, left-skewed means it's hedging. */}
                {aiConfTotal > 0 && (
                  <>
                    <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1.5">Confidence Distribution</p>
                    <div className="flex h-2 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.04)" }}>
                      {[
                        { key: "low",       label: "Low (<25%)",       count: aiConfDist.low,       color: "rgba(239,68,68,0.7)" },
                        { key: "medium",    label: "Medium (25-50%)",  count: aiConfDist.medium,    color: "rgba(251,146,60,0.7)" },
                        { key: "high",      label: "High (50-75%)",    count: aiConfDist.high,      color: "rgba(234,179,8,0.7)" },
                        { key: "very_high", label: "Very High (≥75%)", count: aiConfDist.very_high, color: "rgba(34,197,94,0.7)" },
                      ].map(b => {
                        const pct = aiConfTotal > 0 ? (b.count / aiConfTotal) * 100 : 0;
                        if (pct === 0) return null;
                        return (
                          <div
                            key={b.key}
                            style={{ width: `${pct}%`, background: b.color }}
                            title={`${b.label}: ${b.count}`}
                          />
                        );
                      })}
                    </div>
                    <div className="flex justify-between text-[10px] text-slate-600 mt-1.5">
                      <span>Low {aiConfDist.low}</span>
                      <span>Med {aiConfDist.medium}</span>
                      <span>High {aiConfDist.high}</span>
                      <span>Very High {aiConfDist.very_high}</span>
                    </div>
                  </>
                )}
              </>
            )}
          </div>
        </div>

        {/* ══════ ROW 6 — RECENT ACTIVITY FEED  ·  full-width ══════════
            Unified chronological event log: scans, finding decisions,
            integrations, remediation events, rotations.  Replaces the
            old "Latest Secrets Found" recency view but covers all
            operational activity, not just newly-created findings. */}
        <div className="card p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Recent Activity</h3>
            <Link href="/settings/admin?tab=audit" className="text-[10px] flex items-center gap-1" style={{ color: "#ef4444" }}>
              View All <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
            </Link>
          </div>
          {displayEvents.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8">
              <p className="text-[11px] text-slate-600">No Recent Activity</p>
            </div>
          ) : (
            <div className="space-y-1">
              {displayEvents.map(e => {
                const glyph = ACTIVITY_GLYPH[e.resource_type || ""] || "•";
                return (
                  <div key={e.id} className="flex items-center gap-3 py-1 text-[12px]">
                    <span className="w-5 text-center shrink-0">{glyph}</span>
                    <span className="text-slate-500 tabular-nums w-16 shrink-0">{fmtTimeAgo(e.created_at)}</span>
                    <span className="text-slate-300 truncate flex-1">{e.detail || e.action}</span>
                    {e.user_name && (
                      <span className="text-[10px] text-slate-600 shrink-0 hidden md:inline">
                        By {e.user_name}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

      </div>
    </AppShell>
  );
}

/* ── findingName import removed: "Latest Secrets Found" card was the
     only consumer and that card has been replaced by the
     Findings-by-Source + Top-Leaking-Repos pair.  Severity-badge CSS
     also no longer needed here. ── */
