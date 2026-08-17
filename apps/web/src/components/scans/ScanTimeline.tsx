"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * ScanTimeline — the canonical live/persisted view of a scan's pipeline
 * (Sprint S WS-2/WS-4 + console P0).
 *
 * Renders two things from one data source:
 *   1. The detection FUNNEL — Candidates (raw regex matches) → Filtered
 *      (AI false positives) → Confirmed secrets (true positives). A
 *      secret scanner must NOT headline the raw match count (it reads as
 *      noise); the funnel reframes it honestly and makes the AI-triage
 *      value visible. Numbers are aggregated across every phase event's
 *      stats_snapshot, so the funnel is correct mid-scan AND on a
 *      completed scan loaded fresh.
 *   2. The 8-step STEPPER — the whole pipeline with done / active /
 *      pending / skipped / failed states, per-step counts and durations,
 *      instead of the old "last N messages since the drawer opened" log.
 *
 * Data: seeds the full history from GET /scan-jobs/{id}/events (the
 * append-only, already-redacted scan_phase_events) and merges the live
 * WS/poll update on top. Entries carry real timestamps and re-sort by
 * time, so seed + live interleave correctly regardless of arrival order.
 *
 * Used by ScanDetailDrawer (live) and the /scan-jobs/{id} page (history).
 */

import { useEffect, useRef, useState } from "react";
import type { ScanPhaseEvent } from "@/types";
import { getScanJobEvents } from "@/lib/api";

type Props = {
  scanId: string;
  /** Live overlay from useScanProgressWS / the poll merge (optional). */
  liveMessage?: string | null;
  liveProgress?: number | null;
  liveStatus?: string | null;
  liveStats?: Record<string, any> | null;
  emptyText?: string;
};

type Entry = {
  at: number; // ms epoch — seeded created_at OR Date.now()
  message: string;
  progress_pct: number;
  step?: number;
  total?: number;
  status?: string;
  stats?: Record<string, any> | null;
};

// Canonical pipeline. total_steps is also written on every event (8),
// but the labels live here so skipped phases still render a row.
const PHASES: { step: number; label: string }[] = [
  { step: 1, label: "Preparing repository" },
  { step: 2, label: "Fetching source" },
  { step: 3, label: "Analyzing repository" },
  { step: 4, label: "Scanning for secrets" },
  { step: 5, label: "Verifying credentials" },
  { step: 6, label: "Storing findings" },
  { step: 7, label: "AI false-positive analysis" },
  { step: 8, label: "Complete" },
];

const PHASE_RX = /^\[(\d+)(?:[a-z]?)\/(\d+)\]\s*(.*)$/;
const TERMINAL = new Set(["completed", "failed", "cancelled"]);
const ACTIVE = new Set(["running", "analyzing", "pending"]);

function stripPrefix(msg: string | null | undefined): string {
  if (!msg) return "";
  const m = msg.match(PHASE_RX);
  return m ? (m[3] || msg) : msg;
}

function fmtAgo(ts: number): string {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  return `${Math.floor(s / 60)}m ${s % 60}s ago`;
}

function fmtDur(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

function n(v: any): string {
  return typeof v === "number" ? v.toLocaleString() : String(v);
}

export function ScanTimeline({
  scanId,
  liveMessage,
  liveProgress,
  liveStatus,
  liveStats,
  emptyText = "Waiting for the first update…",
}: Props) {
  const [entries, setEntries] = useState<Entry[]>([]);
  const seenRef = useRef<Set<string>>(new Set());
  const [, setTick] = useState(0);

  const addEntries = (incoming: Entry[]) => {
    const fresh = incoming.filter((e) => e.message && !seenRef.current.has(e.message));
    if (fresh.length === 0) return;
    fresh.forEach((e) => seenRef.current.add(e.message));
    setEntries((prev) => [...prev, ...fresh].sort((a, b) => a.at - b.at));
  };

  // Seed the full persisted history when the scan changes.
  useEffect(() => {
    let cancelled = false;
    seenRef.current = new Set();
    setEntries([]);
    (async () => {
      try {
        const res = await getScanJobEvents(scanId);
        if (cancelled) return;
        const rows: ScanPhaseEvent[] = res.data || [];
        addEntries(
          rows.map((r) => ({
            at: Date.parse(r.created_at),
            message: r.phase_label,
            progress_pct: r.progress_pct,
            step: r.step,
            total: r.total_steps,
            status: r.status,
            stats: r.stats_snapshot,
          })),
        );
      } catch {
        // Telemetry panel must never throw — fall back to live overlay.
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  // Merge each distinct live update on top.
  useEffect(() => {
    if (!liveMessage) return;
    const m = liveMessage.match(PHASE_RX);
    addEntries([
      {
        at: Date.now(),
        message: liveMessage,
        progress_pct: liveProgress ?? 0,
        step: m ? parseInt(m[1], 10) : undefined,
        total: m ? parseInt(m[2], 10) : undefined,
        status: liveStatus ?? undefined,
        stats: liveStats ?? undefined,
      },
    ]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveMessage, liveProgress, liveStatus, liveStats]);

  // Keep relative labels fresh.
  useEffect(() => {
    const t = setInterval(() => setTick((x) => x + 1), 5000);
    return () => clearInterval(t);
  }, []);

  if (entries.length === 0) {
    return <p className="text-xs text-slate-600 italic">{emptyText}</p>;
  }

  // ── Trim the STEPPER to the latest pass ─────────────────────────────
  // A re-run (retroactive AI triage via the "Run AI Triage" button) appends a
  // fresh step sequence AFTER the prior pass's terminal event. Find the last
  // point where the step number went BACKWARDS — that's the newest pass start —
  // and drive the stepper + terminal state from there. Without this, a stale
  // "Complete" from the old pass masks the live re-run (the drawer shows the old
  // status while the AI is analyzing). The funnel below still aggregates ALL
  // passes, so the Candidates count (written at the original scan's store step)
  // survives the trim.
  let _passStart = 0, _runMax = 0;
  for (let i = 0; i < entries.length; i++) {
    const s = entries[i].step ?? 0;
    if (s > 0 && s < _runMax) { _passStart = i; _runMax = s; }
    else if (s > _runMax) _runMax = s;
  }
  const pass = entries.slice(_passStart);

  // ── Aggregate stats across phases (time order; later keys win) ──────
  const agg: Record<string, any> = {};
  for (const e of entries) if (e.stats) Object.assign(agg, e.stats);

  // ── Per-step model for the stepper (latest pass only) ───────────────
  // first event per step (start time) + latest event per step (label/pct).
  const firstAt = new Map<number, number>();
  const latest = new Map<number, Entry>();
  for (const e of pass) {
    if (e.step == null) continue;
    if (!firstAt.has(e.step) || e.at < (firstAt.get(e.step) as number)) firstAt.set(e.step, e.at);
    const cur = latest.get(e.step);
    if (!cur || e.at >= cur.at) latest.set(e.step, e);
  }
  const firedSteps = [...firstAt.keys()].sort((a, b) => a - b);
  const maxFired = firedSteps.length ? firedSteps[firedSteps.length - 1] : 0;

  const liveTerminal = liveStatus && TERMINAL.has(liveStatus) ? liveStatus : null;
  const lastStatus = latest.get(maxFired)?.status;
  const terminal = liveTerminal || (lastStatus && TERMINAL.has(lastStatus) ? lastStatus : null);
  const isCompleted = terminal === "completed";
  const isFailed = terminal === "failed" || terminal === "cancelled";

  // start time of the next fired step after `step` (for durations).
  const nextFiredStart = (step: number): number | undefined => {
    const nxt = firedSteps.find((s) => s > step);
    return nxt != null ? firstAt.get(nxt) : undefined;
  };

  type State = "done" | "active" | "pending" | "skipped" | "failed";
  const stateFor = (step: number): State => {
    const fired = firstAt.has(step);
    if (isCompleted) return fired ? "done" : step < maxFired ? "skipped" : "done";
    if (isFailed) {
      if (step === maxFired) return "failed";
      if (step < maxFired) return fired ? "done" : "skipped";
      return "pending";
    }
    // running
    if (step === maxFired) return "active";
    if (step < maxFired) return fired ? "done" : "skipped";
    return "pending";
  };

  // ── Funnel numbers ─────────────────────────────────────────────────
  const candidates = agg.raw_findings_count;
  const filtered = agg.false_positives;
  const confirmed = agg.true_positives ?? (isCompleted ? agg.findings_total : undefined);
  const aiRan = filtered != null || agg.true_positives != null;
  const showFunnel = candidates != null || confirmed != null;

  const dot = (state: State) =>
    state === "active"
      ? "bg-red-400 animate-pulse"
      : state === "done"
      ? "bg-green-400"
      : state === "failed"
      ? "bg-red-500"
      : state === "skipped"
      ? "bg-slate-700"
      : "bg-slate-700/50";

  return (
    <div className="space-y-5">
      {/* ── Detection funnel ──────────────────────────────────────── */}
      {showFunnel && (
        <div className="grid grid-cols-3 gap-2">
          <FunnelCell
            label="Candidates"
            sub="raw matches"
            value={candidates != null ? n(candidates) : "—"}
            tone="muted"
          />
          <FunnelCell
            label="Filtered"
            sub="AI false pos."
            value={filtered != null ? n(filtered) : aiRan ? "0" : "—"}
            tone="muted"
            arrow
          />
          <FunnelCell
            label="Confirmed"
            sub={aiRan || confirmed != null ? "true secrets" : "AI triage pending"}
            value={confirmed != null ? n(confirmed) : "—"}
            tone="hero"
            arrow
          />
        </div>
      )}

      {/* ── 8-step pipeline stepper ───────────────────────────────── */}
      <ol className="space-y-2.5">
        {PHASES.map((p) => {
          const st = stateFor(p.step);
          const ev = latest.get(p.step);
          const isActive = st === "active";
          const label =
            isActive && ev ? stripPrefix(ev.message) : ev ? stripPrefix(ev.message) : p.label;
          const start = firstAt.get(p.step);
          let meta = "";
          if (st === "done" && start != null) {
            const end = nextFiredStart(p.step);
            if (end != null) meta = fmtDur(end - start);
          } else if (isActive && start != null) {
            meta = fmtAgo(start);
          }
          const textCls =
            st === "active"
              ? "text-slate-100"
              : st === "done"
              ? "text-slate-300"
              : st === "failed"
              ? "text-red-300"
              : "text-slate-600";
          return (
            <li key={p.step} className="flex items-start gap-2.5 text-xs">
              <div className={`mt-1 w-1.5 h-1.5 rounded-full flex-shrink-0 ${dot(st)}`} />
              <div className="flex-1 min-w-0">
                <div className="flex items-baseline justify-between gap-2">
                  <p className={`leading-snug truncate ${textCls}`}>{label}</p>
                  {st === "skipped" && (
                    <span className="text-[10px] text-slate-600 flex-shrink-0">skipped</span>
                  )}
                  {st === "failed" && (
                    <span className="text-[10px] text-red-400 flex-shrink-0">failed</span>
                  )}
                  {meta && <span className="text-[10px] text-slate-600 tabular-nums flex-shrink-0">{meta}</span>}
                </div>
                <p className="text-[10px] text-slate-600 mt-0.5">
                  <span className="text-slate-500 tabular-nums">[{p.step}/8]</span>
                  {ev && <span className="tabular-nums"> · {ev.progress_pct}%</span>}
                  {stepStat(p.step, ev?.stats)}
                </p>
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

// Per-step inline stat (the funnel narrative, inline on the stepper).
function stepStat(step: number, stats?: Record<string, any> | null): string {
  if (!stats) return "";
  if (step === 4 && stats.files_to_scan != null) return ` · ${n(stats.files_to_scan)} files`;
  if (step === 6 && stats.raw_findings_count != null) return ` · ${n(stats.raw_findings_count)} candidates`;
  if (step === 7 && stats.true_positives != null)
    return ` · ${n(stats.true_positives)} confirmed / ${n(stats.false_positives ?? 0)} FP`;
  return "";
}

function FunnelCell({
  label,
  sub,
  value,
  tone,
  arrow,
}: {
  label: string;
  sub: string;
  value: string;
  tone: "muted" | "hero";
  arrow?: boolean;
}) {
  return (
    <div className="relative bg-white/[0.02] border border-white/[0.04] rounded-lg px-3 py-2">
      {arrow && (
        <span className="absolute -left-[11px] top-1/2 -translate-y-1/2 text-slate-600 text-xs">→</span>
      )}
      <dt className="text-[10px] uppercase tracking-wider text-slate-500">{label}</dt>
      <dd
        className={`font-semibold tabular-nums ${
          tone === "hero" ? "text-red-400 text-xl" : "text-slate-300 text-base"
        }`}
      >
        {value}
      </dd>
      <p className="text-[9px] text-slate-600 leading-tight">{sub}</p>
    </div>
  );
}
