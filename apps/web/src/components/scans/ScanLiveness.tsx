"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useEffect, useState } from "react";

/**
 * ScanLiveness — scan-PROGRESS liveness + stall indicator (P0).
 *
 * The footer "Live" chip means the WebSocket is connected — it stays
 * green even on a wedged scan. This is different: it reflects whether the
 * scan is actually MAKING PROGRESS, computed from G-2's `heartbeat_at`
 * (stamped at every real progress point: phase transition, storing
 * chunk-commit, each completed AI-triage batch). It answers the question
 * the frozen-at-70% progress bar can't: "is this stuck, or just slow?"
 *
 * Ticks every second so "last progress Ns ago" counts up smoothly between
 * the 5s polls and resets when a poll brings a fresher heartbeat_at.
 *
 * Thresholds are deliberately generous: on a healthy large scan the
 * heartbeat legitimately pauses for a couple of minutes between storing
 * chunks / triage batches (measured up to ~3m in gap windows), so we only
 * escalate to "possibly stuck" well before the watchdog's reap threshold.
 */

type Tone = "green" | "amber" | "red" | "slate";

type Props = {
  status?: string | null;
  heartbeatAt?: string | null;
  updatedAt?: string | null;
  createdAt?: string | null;
};

const TONE_CLS: Record<Tone, string> = {
  green: "border-green-500/25 bg-green-500/[0.06] text-green-300",
  amber: "border-amber-500/25 bg-amber-500/[0.06] text-amber-300",
  red: "border-red-500/30 bg-red-500/[0.08] text-red-300",
  slate: "border-white/[0.08] bg-white/[0.03] text-slate-300",
};
const DOT_CLS: Record<Tone, string> = {
  green: "bg-green-400",
  amber: "bg-amber-400",
  red: "bg-red-400",
  slate: "bg-slate-400",
};

function ago(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

function ts(v?: string | null): number {
  return v ? Date.parse(v) : NaN;
}

export function ScanLiveness({ status, heartbeatAt, updatedAt, createdAt }: Props) {
  const [now, setNow] = useState<number>(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const st = (status || "").toLowerCase();
  const isRunning = st === "running" || st === "analyzing";
  if (!isRunning && st !== "pending") return null;

  let tone: Tone;
  let warn = false;
  let text: string;

  if (st === "pending") {
    // Hasn't started — measure how long it's been queued. A long queue
    // means no worker picked it up (the wedge we hit this session).
    const created = ts(createdAt);
    const age = Number.isNaN(created) ? 0 : now - created;
    if (age >= 180_000) {
      tone = "red";
      warn = true;
      text = `Queued ${ago(age)} — no worker has picked this up yet`;
    } else if (age >= 60_000) {
      tone = "amber";
      text = `Queued ${ago(age)} — waiting for a worker…`;
    } else {
      tone = "slate";
      text = "Queued — waiting for a worker…";
    }
  } else {
    // Running / analyzing — measure since the last REAL progress.
    const candidates = [ts(heartbeatAt), ts(updatedAt), ts(createdAt)].filter(
      (x) => !Number.isNaN(x),
    );
    const last = candidates.length ? Math.max(...candidates) : NaN;
    const age = Number.isNaN(last) ? 0 : Math.max(0, now - last);
    if (age < 150_000) {
      tone = "green";
      text = `Progressing — last activity ${ago(age)} ago`;
    } else if (age < 480_000) {
      tone = "amber";
      text = `Working — no new progress for ${ago(age)} (large phases can pause here)`;
    } else {
      tone = "red";
      warn = true;
      text = `Possibly stuck — no progress for ${ago(age)}. The watchdog auto-recovers a truly wedged scan; you can cancel and retry.`;
    }
  }

  return (
    <div
      className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-xs leading-snug ${TONE_CLS[tone]}`}
      role="status"
      aria-live="polite"
    >
      {warn ? (
        <span className="flex-shrink-0 leading-none">⚠</span>
      ) : (
        <span className={`mt-1 w-1.5 h-1.5 rounded-full flex-shrink-0 ${DOT_CLS[tone]} ${tone === "green" || tone === "slate" ? "animate-pulse" : ""}`} />
      )}
      <span>{text}</span>
    </div>
  );
}
