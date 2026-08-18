"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * useScanProgressWS — subscribes to the live scan-progress WebSocket
 * (`/api/v1/ws/scan/{scan_job_id}?token=<jwt>`) for a given scan job
 * and returns the latest progress payload alongside connection state.
 *
 * Design choices
 * ──────────────
 * • WS-first, poll-fallback.  The hook tries the WS three times with
 *   exponential backoff (1s, 3s, 9s); if all three fail it sets
 *   `gaveUp: true` and the caller is expected to keep its existing
 *   5s polling cadence running.  This matters in enterprise networks
 *   where corporate proxies / WAFs / strict CSP eat WS upgrades.
 *
 * • Auth via query param.  The backend (apps/api/app/routers/ws.py)
 *   decodes the JWT from `?token=…` — there's no header opportunity
 *   in browser WebSocket().  The token is read from the same
 *   `vooda_token` localStorage key used by `lib/api.ts` for HTTP.
 *
 * • Suppresses reconnect on intentional unmount.  Without this, the
 *   onclose handler would queue a reconnect attempt right as the
 *   component unmounts (React StrictMode double-invokes effects in
 *   dev, which would also trigger spurious reconnects).
 *
 * • Single update slot.  Each message replaces the previous one; the
 *   consumer renders the latest snapshot.  No event log is kept here
 *   — the drawer owns its own history if it needs one.
 *
 * Track-A Recommendation #1 (2026-05-22) — leverages the WS infra in
 * apps/api/app/routers/ws.py + services/pubsub/redis_pubsub.py +
 * apps/worker/tasks.py:_publish() that already existed.
 */

import { useEffect, useRef, useState } from "react";

export type ScanWSStatus =
  | "pending"
  | "running"
  | "analyzing"
  | "completed"
  | "failed"
  | "cancelled";

export type ScanWSUpdate = {
  scan_job_id: string;
  status: ScanWSStatus;
  progress_pct: number;
  message: string;
  stats?: Record<string, unknown>;
};

export type ScanWSState = {
  /** Latest payload received from the server (initial snapshot or live). */
  update: ScanWSUpdate | null;
  /** True only while a socket is OPEN. */
  connected: boolean;
  /** True between attempts ≥ 2 — UI can show a quiet "reconnecting…" chip. */
  reconnecting: boolean;
  /** True after 3 failed attempts — caller should fall back to polling. */
  gaveUp: boolean;
};

const MAX_RECONNECT_ATTEMPTS = 3;
const BACKOFF_BASE_MS = 1000;
const BACKOFF_MULTIPLIER = 3; // 1s → 3s → 9s

/**
 * Build the WS URL for a scan job.  Exported for tests.
 */
export function buildScanProgressWSUrl(scanJobId: string, token: string): string {
  // Use NEXT_PUBLIC_API_URL when set (cross-origin API),
  // otherwise use same-origin (dev / single-domain deploys).
  const apiBase =
    process.env.NEXT_PUBLIC_API_URL ||
    (typeof window !== "undefined" ? window.location.origin : "");
  const wsBase = apiBase.replace(/^http/i, (m) =>
    m.toLowerCase() === "https" ? "wss" : "ws",
  );
  return `${wsBase}/api/v1/ws/scan/${encodeURIComponent(scanJobId)}?token=${encodeURIComponent(token)}`;
}

export function useScanProgressWS(scanJobId: string | null): ScanWSState {
  const [update, setUpdate] = useState<ScanWSUpdate | null>(null);
  const [connected, setConnected] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);
  const [gaveUp, setGaveUp] = useState(false);

  // Refs avoid closing over stale state inside the WS event handlers
  // and let cleanup suppress the reconnect chain on unmount.
  const wsRef = useRef<WebSocket | null>(null);
  const attemptRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const cancelledRef = useRef(false);

  useEffect(() => {
    // Reset for a new scanJobId (or first mount).
    cancelledRef.current = false;
    attemptRef.current = 0;
    setUpdate(null);
    setConnected(false);
    setReconnecting(false);
    setGaveUp(false);

    if (!scanJobId) return;
    if (typeof window === "undefined") return; // SSR guard

    const token = localStorage.getItem("vooda_token");
    if (!token) {
      // No auth → don't even try, signal fallback to caller.
      setGaveUp(true);
      return;
    }

    const connect = () => {
      if (cancelledRef.current) return;

      const url = buildScanProgressWSUrl(scanJobId, token);
      let ws: WebSocket;
      try {
        ws = new WebSocket(url);
      } catch {
        scheduleReconnect();
        return;
      }
      wsRef.current = ws;
      setReconnecting(attemptRef.current > 0);

      ws.onopen = () => {
        if (cancelledRef.current) {
          ws.close();
          return;
        }
        attemptRef.current = 0;
        setConnected(true);
        setReconnecting(false);
      };

      ws.onmessage = (event) => {
        if (cancelledRef.current) return;
        try {
          const data = JSON.parse(event.data);
          if (data && typeof data === "object" && "error" in data) {
            // Auth or server-side rejection — don't keep retrying.
            setGaveUp(true);
            try { ws.close(); } catch { /* noop */ }
            return;
          }
          setUpdate(data as ScanWSUpdate);
        } catch {
          // Malformed frame — silently ignore; live updates will resume.
        }
      };

      ws.onerror = () => {
        // The 'close' handler will fire right after with the actual outcome.
        // Don't double-schedule a reconnect here.
      };

      ws.onclose = (ev) => {
        setConnected(false);
        if (cancelledRef.current || gaveUpInternal()) return;

        // Code 1000 = normal closure (e.g. server saw terminal status
        // and shut the stream).  Don't reconnect a finished scan.
        if (ev.code === 1000) {
          return;
        }
        scheduleReconnect();
      };
    };

    const gaveUpInternal = () => attemptRef.current >= MAX_RECONNECT_ATTEMPTS;

    const scheduleReconnect = () => {
      attemptRef.current += 1;
      if (attemptRef.current > MAX_RECONNECT_ATTEMPTS) {
        setReconnecting(false);
        setGaveUp(true);
        return;
      }
      setReconnecting(true);
      const delay =
        BACKOFF_BASE_MS * Math.pow(BACKOFF_MULTIPLIER, attemptRef.current - 1);
      reconnectTimerRef.current = setTimeout(() => {
        if (!cancelledRef.current) connect();
      }, delay);
    };

    connect();

    return () => {
      cancelledRef.current = true;
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      if (wsRef.current) {
        // Detach handlers BEFORE close so a pending close event from
        // the network layer can't re-enter the reconnect chain.
        wsRef.current.onopen = null;
        wsRef.current.onmessage = null;
        wsRef.current.onerror = null;
        wsRef.current.onclose = null;
        try { wsRef.current.close(); } catch { /* noop */ }
        wsRef.current = null;
      }
    };
  }, [scanJobId]);

  return { update, connected, reconnecting, gaveUp };
}
