"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * ScanDetailDrawer — slide-out panel showing live progress of an
 * in-flight scan.  Opens when the user clicks a Running / Analyzing /
 * Pending ScanJobCard on the repository detail page.
 *
 * Data flow
 * ─────────
 * • `scan` is the latest record from the 5-second poll on the parent
 *   page (always present, may be slightly stale).
 * • `liveUpdate` is the newest WebSocket payload (from
 *   useScanProgressWS) when WS is connected.  When both are present
 *   we prefer `liveUpdate` for status / progress_pct / message and
 *   fall back to `scan` for everything else.
 * • `wsConnected` + `wsReconnecting` + `wsGaveUp` drive the
 *   connection chip in the footer so users can tell whether they're
 *   watching live or watching the 5s poll.
 *
 * Phase indicator parses the worker's status_message convention
 * (`[N/M] description`) — see apps/worker/tasks.py:_run_scan_job for
 * the canonical step list.  If the message doesn't match the pattern
 * (e.g. a custom error string) we just show the message text and skip
 * the step counter.
 *
 * Recent-activity timeline is delegated to the shared <ScanTimeline>
 * (Sprint S / WS-2), which seeds itself from the persisted
 * scan_phase_events via GET /scan-jobs/{id}/events and then merges the
 * live WS/poll update on top — so it survives refresh / reopen and
 * shows a completed scan's full history (the old client-side-only list
 * only kept messages seen after the drawer opened).
 *
 * Track-A Recommendation #1 (2026-05-22); timeline reworked Sprint S.
 */

import { useEffect, useState } from "react";
import type { ScanJob } from "@/types";
import type { ScanWSUpdate } from "@/lib/useScanProgressWS";
import { ScanTimeline } from "./ScanTimeline";
import { ScanMetrics } from "./ScanMetrics";
import { ScanLiveness } from "./ScanLiveness";
import { ScanTypeBadge, ScanProvenance } from "./ScanProvenance";

type Props = {
  scan: ScanJob;
  liveUpdate: ScanWSUpdate | null;
  wsConnected: boolean;
  wsReconnecting: boolean;
  wsGaveUp: boolean;
  onClose: () => void;
  onCancel?: (scanId: string) => void;
};

const STATUS_PILL: Record<string, { bg: string; text: string; label: string }> = {
  pending:   { bg: "bg-slate-500/15",  text: "text-slate-400",  label: "Pending" },
  running:   { bg: "bg-red-500/15",    text: "text-red-400",    label: "Running" },
  analyzing: { bg: "bg-purple-500/15", text: "text-purple-400", label: "AI Analyzing" },
  completed: { bg: "bg-green-500/15",  text: "text-green-400",  label: "Completed" },
  failed:    { bg: "bg-red-500/15",    text: "text-red-400",    label: "Failed" },
  cancelled: { bg: "bg-orange-500/15", text: "text-orange-400", label: "Cancelled" },
};

const PHASE_RX = /^\[(\d+)(?:[a-z]?)\/(\d+)\]\s*(.*)$/;

function parsePhase(msg: string | null | undefined): { step: number; total: number; label: string } | null {
  if (!msg) return null;
  const m = msg.match(PHASE_RX);
  if (!m) return null;
  return {
    step: parseInt(m[1], 10),
    total: parseInt(m[2], 10),
    label: m[3] || msg,
  };
}

export function ScanDetailDrawer({
  scan,
  liveUpdate,
  wsConnected,
  wsReconnecting,
  wsGaveUp,
  onClose,
  onCancel,
}: Props) {
  // Merge: prefer live WS payload, fall back to polled scan row.
  const status = (liveUpdate?.status as string | undefined) ?? scan.status;
  const progress = liveUpdate?.progress_pct ?? scan.progress_pct ?? 0;
  const message = liveUpdate?.message || scan.status_message || "Processing...";
  const stats = (liveUpdate?.stats && Object.keys(liveUpdate.stats).length > 0)
    ? (liveUpdate.stats as Record<string, any>)
    : (scan.stats || {});

  const phase = parsePhase(message);
  const pill = STATUS_PILL[status] || STATUS_PILL.pending;
  const isActive = ["running", "analyzing", "pending"].includes(status);
  const [cancelling, setCancelling] = useState(false);

  // Esc closes the drawer.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Close on terminal status — but give the user 2s to read the
  // "completed" message before auto-dismissing.  Cancelled and Failed
  // never auto-dismiss; the user should see the error.
  useEffect(() => {
    if (status !== "completed") return;
    const t = setTimeout(onClose, 2000);
    return () => clearTimeout(t);
  }, [status, onClose]);

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden
      />
      {/* Drawer */}
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="Scan progress detail"
        className="fixed right-0 top-0 z-50 h-full w-full max-w-[440px] bg-[#0a0a0a] border-l border-white/[0.08] shadow-2xl flex flex-col"
      >
        {/* Header */}
        <header className="flex items-center justify-between px-5 py-4 border-b border-white/[0.06]">
          <div className="flex items-center gap-2 min-w-0">
            <span className={`text-xs px-2.5 py-1 rounded-full font-medium ${pill.bg} ${pill.text} border border-white/[0.04] inline-flex items-center`}>
              {isActive && <span className="inline-block w-1.5 h-1.5 rounded-full bg-current mr-1.5 animate-pulse" />}
              {pill.label}
            </span>
            <ScanTypeBadge scanType={scan.scan_type} />
            <span className="text-[11px] text-slate-600 truncate">· {scan.id.slice(0, 8)}</span>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/[0.06] transition-all"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </header>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-5 py-5 space-y-6">
          {/* CLI/CI two-way-sync provenance (commit/branch/actor/pipeline) */}
          <ScanProvenance job={scan} />

          {/* Phase indicator + progress */}
          <section>
            <div className="flex items-baseline justify-between mb-2">
              <div className="flex items-baseline gap-2">
                {phase ? (
                  <>
                    <span className="text-2xl font-semibold text-white tabular-nums">
                      {phase.step}
                      <span className="text-slate-500 text-base font-normal">/{phase.total}</span>
                    </span>
                    <span className="text-xs text-slate-500 uppercase tracking-wider">step</span>
                  </>
                ) : (
                  <span className="text-xs text-slate-500 uppercase tracking-wider">Status</span>
                )}
              </div>
              <span className="text-2xl font-semibold text-red-400 tabular-nums">{progress}%</span>
            </div>
            <p className="text-sm text-slate-200 leading-relaxed min-h-[2.5rem]">
              {phase ? phase.label : message}
            </p>
            <div className="mt-3 w-full bg-white/[0.04] rounded-full h-2 overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-red-500 to-orange-500 transition-all duration-500"
                style={{ width: `${Math.max(0, Math.min(100, progress))}%` }}
              />
            </div>

            {/* Scan-PROGRESS liveness / stall — heartbeat-backed, distinct
                from the footer WS "Live" chip (which only means the socket
                is up). This is what tells the user the frozen-looking bar
                is still working vs genuinely stuck. */}
            <div className="mt-3">
              <ScanLiveness
                status={status}
                heartbeatAt={scan.heartbeat_at}
                updatedAt={scan.updated_at}
                createdAt={scan.created_at}
              />
            </div>
          </section>

          {/* Security findings — severity breakdown, headline counts,
              verified-live (when present), composition + efficiency.
              Surfaces the rich scan_jobs.stats the drawer previously
              ignored; degrades gracefully on partial mid-scan stats. */}
          <ScanMetrics stats={stats} status={status} />

          {/* Detection funnel + 8-step pipeline. Seeded from the
              persisted scan_phase_events (survives refresh / reopen /
              completion) and merged with the live WS/poll update. The
              funnel reframes the raw match count into confirmed secrets;
              the stepper shows the whole pipeline, not just the last few
              messages seen since the drawer opened. */}
          <section>
            <h3 className="text-[11px] uppercase tracking-wider text-slate-500 mb-3">
              Pipeline
            </h3>
            <ScanTimeline
              scanId={scan.id}
              liveMessage={message}
              liveProgress={progress}
              liveStatus={status}
              liveStats={stats}
            />
          </section>
        </div>

        {/* Footer */}
        <footer className="border-t border-white/[0.06] px-5 py-3 flex items-center justify-between gap-3">
          <div className="flex items-center gap-1.5 text-[11px]">
            {wsConnected ? (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
                <span className="text-green-400">Live</span>
              </>
            ) : wsReconnecting ? (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 animate-pulse" />
                <span className="text-yellow-400">Reconnecting…</span>
              </>
            ) : wsGaveUp ? (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
                <span className="text-slate-400">Polling fallback</span>
              </>
            ) : (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
                <span className="text-slate-500">Connecting…</span>
              </>
            )}
          </div>
          {isActive && onCancel ? (
            <div className="flex items-center gap-2">
              {/* Close just dismisses the drawer — the scan keeps running
                  in the background (distinct from Cancel scan). */}
              <button
                onClick={onClose}
                className="text-xs px-3 py-1.5 rounded-lg text-slate-300 border border-white/[0.08] hover:bg-white/[0.04] transition-all"
              >
                Close
              </button>
              <button
                onClick={() => {
                  setCancelling(true);
                  onCancel(scan.id);
                }}
                disabled={cancelling}
                className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg text-red-400 border border-red-400/20 hover:bg-red-400/10 transition-all disabled:opacity-50"
              >
                {cancelling ? (
                  <div className="w-3 h-3 border border-red-400/50 border-t-red-400 rounded-full animate-spin" />
                ) : (
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                )}
                Cancel scan
              </button>
            </div>
          ) : (
            <button
              onClick={onClose}
              className="text-xs px-3 py-1.5 rounded-lg text-slate-300 border border-white/[0.08] hover:bg-white/[0.04] transition-all"
            >
              Close
            </button>
          )}
        </footer>
      </aside>
    </>
  );
}
