"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * /scan-jobs/{id} — deep-linkable, bookmarkable view of a single scan
 * (Sprint S / WS-4).  Unlike the slide-out drawer (which only opens
 * from a Running card on the repo page), this survives a page load and
 * works for a completed/failed scan too, because the timeline is seeded
 * from the persisted scan_phase_events via the shared <ScanTimeline>.
 *
 * Polls getScanJob while the scan is still active so progress + the
 * timeline stay fresh; stops polling once terminal.
 */

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import AppShell from "@/components/layout/AppShell";
import { ScanTimeline } from "@/components/scans/ScanTimeline";
import { ScanMetrics } from "@/components/scans/ScanMetrics";
import { ScanLiveness } from "@/components/scans/ScanLiveness";
import { ScanTypeBadge, ScanProvenance } from "@/components/scans/ScanProvenance";
import { getScanJob } from "@/lib/api";
import type { ScanJob } from "@/types";

const STATUS_PILL: Record<string, { bg: string; text: string; label: string }> = {
  pending: { bg: "bg-slate-500/15", text: "text-slate-400", label: "Pending" },
  running: { bg: "bg-red-500/15", text: "text-red-400", label: "Running" },
  analyzing: { bg: "bg-purple-500/15", text: "text-purple-400", label: "AI Analyzing" },
  completed: { bg: "bg-green-500/15", text: "text-green-400", label: "Completed" },
  failed: { bg: "bg-red-500/15", text: "text-red-400", label: "Failed" },
  cancelled: { bg: "bg-orange-500/15", text: "text-orange-400", label: "Cancelled" },
};

const ACTIVE = new Set(["pending", "running", "analyzing"]);

export default function ScanJobDetailPage() {
  const params = useParams();
  const id = params?.id as string;

  const [job, setJob] = useState<ScanJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const res = await getScanJob(id);
      setJob(res.data);
      setError(null);
    } catch (e: any) {
      setError(e?.response?.status === 404 ? "not_found" : "error");
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    if (!id) return;
    load();
  }, [id, load]);

  // Poll every 5s while the scan is active; stop once terminal.
  useEffect(() => {
    if (!job || !ACTIVE.has(job.status)) return;
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [job, load]);

  const pill = (job && STATUS_PILL[job.status]) || STATUS_PILL.pending;
  const isActive = job ? ACTIVE.has(job.status) : false;
  const progress = job?.progress_pct ?? 0;
  const stats = (job?.stats || {}) as Record<string, any>;

  return (
    <AppShell>
      <div className="space-y-5">
        <div>
          <h2 className="text-2xl font-bold text-white">Scan Job</h2>
          <p className="text-sm text-slate-400 mt-1">Job details and progress</p>
        </div>

        {loading ? (
          <div className="card">
            <p className="text-sm text-slate-500">Loading scan…</p>
          </div>
        ) : error === "not_found" ? (
          <div className="card">
            <p className="text-sm text-slate-300">Scan job not found.</p>
            <p className="text-xs text-slate-500 mt-1">
              It may belong to another tenant, or it was removed with its repository.
            </p>
          </div>
        ) : error ? (
          <div className="card">
            <p className="text-sm text-red-400">Couldn’t load this scan. Try again shortly.</p>
          </div>
        ) : job ? (
          <>
            {/* Header card — status + progress */}
            <div className="card">
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div className="flex items-center gap-2 min-w-0">
                  <span
                    className={`text-xs px-2.5 py-1 rounded-full font-medium ${pill.bg} ${pill.text} border border-white/[0.04] inline-flex items-center`}
                  >
                    {isActive && (
                      <span className="inline-block w-1.5 h-1.5 rounded-full bg-current mr-1.5 animate-pulse" />
                    )}
                    {pill.label}
                  </span>
                  <ScanTypeBadge scanType={job.scan_type} />
                  <code className="text-[11px] text-slate-600 font-mono">· {job.id.slice(0, 8)}</code>
                  <Link
                    href={`/repositories/${job.repository_id}`}
                    className="text-[11px] text-red-400 hover:underline"
                  >
                    View repository →
                  </Link>
                </div>
                <span className="text-2xl font-semibold text-red-400 tabular-nums">{progress}%</span>
              </div>

              <p className="text-sm text-slate-200 leading-relaxed mt-3 min-h-[1.5rem]">
                {job.status_message || (isActive ? "Processing…" : pill.label)}
              </p>

              {/* CLI/CI two-way-sync provenance (commit/branch/actor/pipeline) */}
              <ScanProvenance job={job} />

              <div className="mt-3 w-full bg-white/[0.04] rounded-full h-2 overflow-hidden">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-red-500 to-orange-500 transition-all duration-500"
                  style={{ width: `${Math.max(0, Math.min(100, progress))}%` }}
                />
              </div>

              {/* Scan-progress liveness / stall (active scans only). */}
              <div className="mt-3">
                <ScanLiveness
                  status={job.status}
                  heartbeatAt={job.heartbeat_at}
                  updatedAt={job.updated_at}
                  createdAt={job.created_at}
                />
              </div>

              {/* WS-3′ — show WHY a scan failed/cancelled, not a bare badge. */}
              {(job.status === "failed" || job.status === "cancelled") && job.error_detail && (
                <div className="mt-4 rounded-lg border border-red-400/20 bg-red-500/[0.06] px-3 py-2">
                  <p className="text-[10px] uppercase tracking-wider text-red-400/80 mb-1">
                    {job.status === "cancelled" ? "Reason" : "Failure reason"}
                  </p>
                  <p className="text-xs text-slate-300 leading-snug break-words">{job.error_detail}</p>
                </div>
              )}
            </div>

            {/* Security findings — severity, headline counts, verified-
                live (when present), composition + efficiency. Replaces
                the old 3-stat Result card with the shared <ScanMetrics>
                (superset). Self-gates per datum; shows live during an
                active scan and the full picture when terminal. */}
            {(stats.findings_total != null ||
              stats.findings_by_severity != null ||
              stats.files_analyzed != null ||
              stats.active_credentials != null) && (
              <div className="card">
                <ScanMetrics stats={stats} status={job.status} />
              </div>
            )}

            {/* Funnel + 8-step pipeline — seeded from persisted events. */}
            <div className="card">
              <h3 className="text-[11px] uppercase tracking-wider text-slate-500 mb-3">Pipeline</h3>
              <ScanTimeline
                scanId={job.id}
                liveMessage={job.status_message}
                liveProgress={job.progress_pct}
                liveStatus={job.status}
                liveStats={stats}
                emptyText="No phase events recorded for this scan."
              />
            </div>
          </>
        ) : null}
      </div>
    </AppShell>
  );
}
