"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * ScanMetrics — commercial-grade security verdict + scan metrics for the
 * live ScanDetailDrawer and the /scan-jobs/{id} page.
 *
 * The pipeline stepper/funnel (ScanTimeline) answers "where is the scan?".
 * This answers "what did it find, and how bad?" — the part the drawer was
 * missing. It surfaces the rich data scan_jobs.stats already collects:
 *   • severity breakdown (Snyk model: counts by Critical/High/Medium/Low)
 *   • headline counts (files scanned, findings, AI-triaged, FP removed)
 *   • verified-live credentials (GitGuardian/TruffleHog model) — shown
 *     ONLY when the verify-credentials phase actually populated it; never
 *     faked when absent
 *   • composition (new vs previously-seen)
 *   • efficiency (files from cache, duplicates deduped, AI calls saved)
 *
 * Every section degrades gracefully — it renders only when its datum is
 * present — so a partial mid-scan stats blob and a complete end-of-scan
 * blob both render correctly without throwing.
 */

type Props = {
  stats?: Record<string, any> | null;
  status?: string | null;
};

function num(v: any): number | null {
  return typeof v === "number" && !Number.isNaN(v) ? v : null;
}
function fmt(v: number): string {
  return v.toLocaleString();
}

const SEVERITIES: { key: string; label: string; text: string; dot: string }[] = [
  { key: "critical", label: "Critical", text: "text-red-400", dot: "bg-red-500" },
  { key: "high", label: "High", text: "text-orange-400", dot: "bg-orange-500" },
  { key: "medium", label: "Medium", text: "text-yellow-400", dot: "bg-yellow-500" },
  { key: "low", label: "Low", text: "text-slate-400", dot: "bg-slate-500" },
];

export function ScanMetrics({ stats }: Props) {
  const s = stats || {};

  const filesScanned = num(s.files_analyzed) ?? num(s.items_scanned);
  const findingsTotal = num(s.findings_total);
  const confirmed = num(s.true_positives);
  const aiTriaged = num(s.ai_triaged);
  const fpRemoved = num(s.false_positives);
  const activeCreds = num(s.active_credentials);
  const fNew = num(s.findings_new);
  const fExisting = num(s.findings_existing);

  const sevObj =
    s.findings_by_severity && typeof s.findings_by_severity === "object"
      ? (s.findings_by_severity as Record<string, any>)
      : null;
  const sevCounts = SEVERITIES.map((sv) => ({ ...sv, count: sevObj ? num(sevObj[sv.key]) : null }));
  const anySev = sevCounts.some((sv) => sv.count != null && sv.count > 0);

  // Efficiency — only surface the ones that actually saved work.
  const cacheHits = num(s.file_cache_hits);
  const dedup = num(s.dedup_saved);
  const aiSaved = num(s.ai_calls_saved);
  const effParts: string[] = [];
  if (cacheHits != null && cacheHits > 0) effParts.push(`${fmt(cacheHits)} files from cache`);
  if (dedup != null && dedup > 0) effParts.push(`${fmt(dedup)} duplicates deduped`);
  if (aiSaved != null && aiSaved > 0) effParts.push(`saved ${fmt(aiSaved)} AI calls`);

  // Headline metric cells (render only those present).
  const cells: { label: string; value: number; accent?: boolean }[] = [];
  if (filesScanned != null) cells.push({ label: "Files scanned", value: filesScanned });
  if (findingsTotal != null) cells.push({ label: "Findings", value: findingsTotal });
  if (aiTriaged != null) cells.push({ label: "AI triaged", value: aiTriaged });
  if (fpRemoved != null) cells.push({ label: "FP removed", value: fpRemoved });

  const hasComposition = fNew != null || fExisting != null;
  const nothing =
    !anySev && cells.length === 0 && activeCreds == null && !hasComposition && effParts.length === 0;
  if (nothing) return null;

  return (
    <section>
      <h3 className="text-[11px] uppercase tracking-wider text-slate-500 mb-3">Security findings</h3>

      {/* Verified-live callout — the GitGuardian/TruffleHog headline.
          Only rendered when the verify-credentials phase populated it. */}
      {activeCreds != null && (
        <div
          className={`mb-3 flex items-center gap-2 rounded-lg border px-3 py-2 ${
            activeCreds > 0
              ? "border-red-500/30 bg-red-500/[0.06]"
              : "border-green-500/20 bg-green-500/[0.04]"
          }`}
        >
          <span className={`text-lg font-semibold tabular-nums ${activeCreds > 0 ? "text-red-400" : "text-green-400"}`}>
            {fmt(activeCreds)}
          </span>
          <span className={`text-xs ${activeCreds > 0 ? "text-red-300" : "text-green-300"}`}>
            {activeCreds > 0 ? "verified live · confirmed exploitable" : "verified live — none active"}
          </span>
        </div>
      )}

      {/* Severity breakdown (Snyk model). */}
      {anySev && (
        <div className="mb-3 grid grid-cols-4 gap-1.5">
          {sevCounts.map((sv) => (
            <div
              key={sv.key}
              className={`rounded-lg border border-white/[0.05] bg-white/[0.02] px-2 py-1.5 text-center ${
                sv.count && sv.count > 0 ? "" : "opacity-40"
              }`}
            >
              <div className="flex items-center justify-center gap-1">
                <span className={`w-1.5 h-1.5 rounded-full ${sv.dot}`} />
                <span className={`text-base font-semibold tabular-nums ${sv.text}`}>
                  {sv.count != null ? fmt(sv.count) : "—"}
                </span>
              </div>
              <p className="text-[9px] uppercase tracking-wide text-slate-500 mt-0.5">{sv.label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Headline count cells. */}
      {cells.length > 0 && (
        <dl className="grid grid-cols-2 gap-1.5 mb-2">
          {cells.map((c) => (
            <div key={c.label} className="rounded-lg border border-white/[0.04] bg-white/[0.02] px-3 py-2">
              <dd className="text-base font-semibold tabular-nums text-slate-200">{fmt(c.value)}</dd>
              <dt className="text-[10px] text-slate-500">{c.label}</dt>
            </div>
          ))}
        </dl>
      )}

      {/* Composition + efficiency — secondary, single lines. */}
      {hasComposition && (
        <p className="text-[10px] text-slate-500 tabular-nums">
          {fNew != null && <span className="text-slate-300">{fmt(fNew)} new</span>}
          {fNew != null && fExisting != null && " · "}
          {fExisting != null && <span>{fmt(fExisting)} previously seen</span>}
        </p>
      )}
      {effParts.length > 0 && (
        <p className="text-[10px] text-slate-600 mt-1">⚡ {effParts.join(" · ")}</p>
      )}
    </section>
  );
}
