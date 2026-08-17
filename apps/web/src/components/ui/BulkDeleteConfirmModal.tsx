"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/*
 * Bulk-selection destructive-action confirmation modal.
 *
 * Sibling of DeleteConfirmModal — same visual treatment, same friction
 * gate, but the preview payload is the *aggregated* roll-up from
 * /repositories/bulk-delete-preview.  Incidents that span multiple
 * selected repos are counted once (the backend does the dedup; the FE
 * cannot just sum per-repo previews without double-counting).
 *
 * Friction tier: typed token "DELETE" (the count + scope is in the
 * heading and the project list).  We deliberately use a fixed token
 * rather than e.g. the count, because the count changes as the user
 * adjusts selection and the muscle-memory protection should not.
 * Same pattern as Stripe / GitHub bulk deletes.
 */

import { useState, useEffect } from "react";

export type BulkDeletePreview = {
  scope: "repository" | "scan_source";
  count: number;
  names: string[];
  findings_count: number;
  incidents_affected: number;
  incidents_will_close: number;
  incidents_will_survive: number;
  active_credentials: number;
  scan_history_count: number;
};

interface Props {
  preview: BulkDeletePreview | null;
  error?: string | null;
  onConfirm: () => Promise<void> | void;
  onCancel: () => void;
  /** Optional: a less-destructive bulk archive flow.  When provided,
      an "Archive all instead" link appears. */
  onArchiveAll?: () => void;
}

const TYPED_TOKEN = "DELETE";

export default function BulkDeleteConfirmModal({
  preview,
  error,
  onConfirm,
  onCancel,
  onArchiveAll,
}: Props) {
  const [typed, setTyped] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    setTyped("");
  }, [preview?.count]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !submitting) onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel, submitting]);

  const tokenMatches = typed.trim().toUpperCase() === TYPED_TOKEN;
  const scopeLabel = preview?.scope === "scan_source" ? "source" : "project";
  const scopeLabelPlural = scopeLabel + "s";
  const headingSuffix = preview
    ? preview.count === 1
      ? `1 ${scopeLabel}`
      : `${preview.count} ${scopeLabelPlural}`
    : "";

  const handleConfirm = async () => {
    if (!tokenMatches || submitting) return;
    setSubmitting(true);
    try {
      await onConfirm();
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-[200] flex items-start justify-center pt-[8vh] px-4 vooda-fade-in"
      onClick={!submitting ? onCancel : undefined}
      role="dialog"
      aria-modal="true"
      aria-label="Confirm bulk permanent deletion"
      style={{
        background: "rgba(2, 4, 12, 0.65)",
        backdropFilter: "blur(8px)",
        WebkitBackdropFilter: "blur(8px)",
      }}
    >
      <div
        className="w-full max-w-lg rounded-xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
        style={{
          background: "rgba(12, 15, 32, 0.98)",
          border: "1px solid rgba(248, 113, 113, 0.18)",
          boxShadow: "0 24px 80px rgba(0,0,0,0.6), 0 0 0 1px rgba(248,113,113,0.06)",
        }}
      >
        {/* Header */}
        <div
          className="px-5 py-4 flex items-center gap-3"
          style={{ borderBottom: "1px solid rgba(248,113,113,0.12)", background: "rgba(248,113,113,0.04)" }}
        >
          <svg className="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" style={{ color: "#f87171" }}>
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                  d="M12 9v2m0 4h.01M5.062 19h13.876c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <div className="min-w-0 flex-1">
            <h2 className="text-base font-semibold text-white truncate">
              Delete {headingSuffix}?
            </h2>
            <p className="text-[11px] text-slate-500 mt-0.5">
              Permanent action — cannot be undone.
            </p>
          </div>
        </div>

        {/* Body */}
        <div className="px-5 py-4 space-y-4">
          {error && (
            <div className="text-xs text-red-300 px-3 py-2 rounded" style={{ background: "rgba(248,113,113,0.08)", border: "1px solid rgba(248,113,113,0.18)" }}>
              {error}
            </div>
          )}

          {!preview && !error && (
            <div className="space-y-2">
              <div className="h-3 bg-white/[0.04] rounded animate-pulse w-3/4" />
              <div className="h-3 bg-white/[0.04] rounded animate-pulse w-1/2" />
              <div className="h-3 bg-white/[0.04] rounded animate-pulse w-2/3" />
            </div>
          )}

          {preview && (
            <>
              {/* Selected items list — truncated to keep modal compact. */}
              <div>
                <div className="text-[10px] uppercase tracking-wider text-slate-500 font-medium mb-1.5">
                  Selected
                </div>
                <ul className="space-y-0.5 text-xs text-slate-400 max-h-32 overflow-y-auto pr-1">
                  {preview.names.slice(0, 8).map((n, i) => (
                    <li key={i} className="flex items-center gap-2">
                      <span className="w-1 h-1 rounded-full bg-slate-500" />
                      <span className="text-slate-300 truncate">{n}</span>
                    </li>
                  ))}
                  {preview.names.length > 8 && (
                    <li className="text-slate-600 text-[11px] pl-3">
                      …and {preview.names.length - 8} more
                    </li>
                  )}
                </ul>
              </div>

              <div className="text-xs text-slate-300 pt-1">
                This permanently removes:
              </div>
              <ul className="space-y-1.5 text-xs text-slate-400">
                <li className="flex items-center gap-2">
                  <span className="w-1 h-1 rounded-full bg-slate-500" />
                  <span><b className="text-white">{preview.findings_count.toLocaleString()}</b> {preview.findings_count === 1 ? "finding" : "findings"}</span>
                </li>
                <li className="flex items-center gap-2">
                  <span className="w-1 h-1 rounded-full bg-slate-500" />
                  <span>
                    <b className="text-white">{preview.incidents_affected}</b> {preview.incidents_affected === 1 ? "incident" : "incidents"} affected
                    {preview.incidents_affected > 0 && (
                      <span className="text-slate-500">
                        {" "}— <b className="text-amber-300">{preview.incidents_will_close}</b> will auto-close
                        {preview.incidents_will_survive > 0 && (
                          <>, <b className="text-emerald-300">{preview.incidents_will_survive}</b> stay open via other locations</>
                        )}
                      </span>
                    )}
                  </span>
                </li>
                <li className="flex items-center gap-2">
                  <span className="w-1 h-1 rounded-full bg-slate-500" />
                  <span><b className="text-white">{preview.scan_history_count}</b> scan history {preview.scan_history_count === 1 ? "record" : "records"}</span>
                </li>
              </ul>

              {/* Active-credentials warning — same callout as single delete. */}
              {preview.active_credentials > 0 && (
                <div
                  className="px-3 py-2.5 rounded text-xs"
                  style={{
                    background: "rgba(248, 113, 113, 0.08)",
                    border: "1px solid rgba(248, 113, 113, 0.22)",
                    color: "#fca5a5",
                  }}
                >
                  <div className="flex items-start gap-2">
                    <svg className="w-3.5 h-3.5 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8}
                            d="M12 9v2m0 4h.01M5.062 19h13.876c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    <div>
                      <b className="text-white">{preview.active_credentials} active {preview.active_credentials === 1 ? "credential" : "credentials"}</b> verified live at the provider.
                      <div className="mt-1 text-[11px] text-red-300/80">
                        Deletion does <b>not</b> rotate these credentials. Rotate them at the provider first if not already done.
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {onArchiveAll && (
                <div className="text-[11px] text-slate-500 leading-relaxed">
                  💡 If you only want to stop scanning, use{" "}
                  <button
                    onClick={onArchiveAll}
                    disabled={submitting}
                    className="text-slate-300 hover:text-white underline-offset-2 hover:underline transition-colors disabled:opacity-40"
                  >
                    Archive all
                  </button>
                  {" "}instead — preserves findings, scan history, and incident triage.
                </div>
              )}

              {/* Typed token gate. */}
              <div className="space-y-1.5 pt-1">
                <label className="text-[10px] uppercase tracking-wider text-slate-500 font-medium">
                  Type <span className="text-slate-300 font-mono">{TYPED_TOKEN}</span> to confirm
                </label>
                <input
                  value={typed}
                  onChange={(e) => setTyped(e.target.value)}
                  placeholder={TYPED_TOKEN}
                  spellCheck={false}
                  autoComplete="off"
                  disabled={submitting}
                  className="input-dark text-sm font-mono"
                  autoFocus
                />
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div
          className="px-5 py-3 flex items-center justify-end gap-2"
          style={{ borderTop: "1px solid rgba(255,255,255,0.06)", background: "rgba(255,255,255,0.015)" }}
        >
          <button
            onClick={onCancel}
            disabled={submitting}
            className="btn-secondary-sm"
          >
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            disabled={!tokenMatches || submitting}
            className="inline-flex items-center justify-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-all duration-200 select-none"
            style={{
              color: tokenMatches ? "#ffffff" : "#475569",
              background: tokenMatches ? "#dc2626" : "rgba(255,255,255,0.04)",
              border: tokenMatches ? "1px solid #b91c1c" : "1px solid rgba(255,255,255,0.07)",
              cursor: tokenMatches ? "pointer" : "not-allowed",
            }}
          >
            {submitting && (
              <div className="w-3 h-3 rounded-full border-2 animate-spin"
                   style={{ borderColor: "rgba(255,255,255,0.25)", borderTopColor: "#ffffff" }} />
            )}
            {submitting ? "Deleting…" : `Delete permanently`}
          </button>
        </div>
      </div>
    </div>
  );
}
