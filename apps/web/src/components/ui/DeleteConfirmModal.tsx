"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/*
 * Shared destructive-action confirmation modal.
 *
 * Renders the impact preview returned by GET /<scope>/{id}/delete-preview
 * and gates the destructive action behind a typed-confirmation field
 * (user must re-type the entity name).  Pattern adopted by every
 * commercial peer (GitHub, GitGuardian, Snyk, Wiz, Stripe) — the
 * friction is the point.  A single accidental click should not be able
 * to nuke a repository or scan source.
 *
 * Used by both the repositories list and the sources list.  Scope
 * differences (repo vs source) live in the preview payload, not in
 * the component logic, so the modal renders identically for either.
 */

import { useState, useEffect } from "react";

type DeletePreview = {
  scope: "repository" | "scan_source";
  id: string;
  name: string;
  findings_count: number;
  incidents_affected: number;
  incidents_will_close: number;
  incidents_will_survive: number;
  active_credentials: number;
  scan_history_count: number;
  source_type?: string; // only present for scan_source
};

interface Props {
  /** Preview payload — pass null to show a loading skeleton. */
  preview: DeletePreview | null;
  /** Optional error message from the preview fetch. */
  error?: string | null;
  /** Called when user confirms the destructive action.  Should call
      the actual DELETE endpoint and close the modal on success. */
  onConfirm: () => Promise<void> | void;
  /** Called when user dismisses without deleting. */
  onCancel: () => void;
  /** Optional: navigate the user to the archive flow as a less-
      destructive alternative.  When provided, an "Archive instead"
      link appears in the modal. */
  onArchive?: () => void;
}

export default function DeleteConfirmModal({
  preview,
  error,
  onConfirm,
  onCancel,
  onArchive,
}: Props) {
  const [typed, setTyped] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Reset the typed value whenever the preview changes (e.g. the user
  // dismissed the modal for repo-A then opened it for repo-B; the old
  // name shouldn't carry over and accidentally satisfy the gate).
  useEffect(() => {
    setTyped("");
  }, [preview?.id]);

  // Esc to cancel — universal modal expectation.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !submitting) onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel, submitting]);

  const nameMatches = preview ? typed.trim() === preview.name.trim() : false;
  const scopeLabel = preview?.scope === "repository" ? "repository" : "source";

  const handleConfirm = async () => {
    if (!nameMatches || submitting) return;
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
      aria-label="Confirm permanent deletion"
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
        {/* Header — danger-tinted strip + title */}
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
              Delete {scopeLabel}{preview ? ` "${preview.name}"` : ""}?
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

          {/* Impact preview — counts that mirror what will be destroyed. */}
          {!preview && !error && (
            <div className="space-y-2">
              <div className="h-3 bg-white/[0.04] rounded animate-pulse w-3/4" />
              <div className="h-3 bg-white/[0.04] rounded animate-pulse w-1/2" />
              <div className="h-3 bg-white/[0.04] rounded animate-pulse w-2/3" />
            </div>
          )}

          {preview && (
            <>
              <div className="text-xs text-slate-300">
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

              {/* Active-credentials warning — the single most important
                  callout.  Deleting the repo/source does NOT rotate
                  these; the user must act at the provider first. */}
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

              {/* Archive-instead suggestion — soft-delete alternative. */}
              {onArchive && (
                <div className="text-[11px] text-slate-500 leading-relaxed">
                  💡 If you only want to stop scanning, use{" "}
                  <button
                    onClick={onArchive}
                    disabled={submitting}
                    className="text-slate-300 hover:text-white underline-offset-2 hover:underline transition-colors disabled:opacity-40"
                  >
                    Archive
                  </button>
                  {" "}instead — preserves findings, scan history, and incident triage.
                </div>
              )}

              {/* Typed confirmation — the friction gate. */}
              <div className="space-y-1.5 pt-1">
                <label className="text-[10px] uppercase tracking-wider text-slate-500 font-medium">
                  Type <span className="text-slate-300 font-mono">{preview.name}</span> to confirm
                </label>
                <input
                  value={typed}
                  onChange={(e) => setTyped(e.target.value)}
                  placeholder={preview.name}
                  spellCheck={false}
                  autoComplete="off"
                  disabled={submitting}
                  className="input-dark text-sm font-mono"
                  // Auto-focus when the preview lands so keyboard users
                  // can start typing immediately.
                  autoFocus
                />
              </div>
            </>
          )}
        </div>

        {/* Footer — actions */}
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
            disabled={!nameMatches || submitting}
            className="inline-flex items-center justify-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-all duration-200 select-none"
            style={{
              color: nameMatches ? "#ffffff" : "#475569",
              background: nameMatches ? "#dc2626" : "rgba(255,255,255,0.04)",
              border: nameMatches ? "1px solid #b91c1c" : "1px solid rgba(255,255,255,0.07)",
              cursor: nameMatches ? "pointer" : "not-allowed",
            }}
          >
            {submitting && (
              <div className="w-3 h-3 rounded-full border-2 animate-spin"
                   style={{ borderColor: "rgba(255,255,255,0.25)", borderTopColor: "#ffffff" }} />
            )}
            {submitting ? "Deleting…" : "Delete permanently"}
          </button>
        </div>
      </div>
    </div>
  );
}

// Export the type so consumers can fetch preview payloads without
// duplicating the shape.
export type { DeletePreview };
