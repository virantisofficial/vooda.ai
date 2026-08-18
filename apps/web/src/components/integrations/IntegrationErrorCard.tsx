"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * IntegrationErrorCard — single source of truth for rendering a
 * structured integration error returned by any backend adapter.
 *
 * Backend contract: an error response looks like
 *
 *   {
 *     status: "error",
 *     message: "<plain-English summary>",     // legacy; same as `summary`
 *     title:   "<≤ 8 words>",
 *     summary: "<≤ 2 sentences>",
 *     fix_steps: [ "<imperative step>", ... ],
 *     doc_anchor: "/docs?section=...",
 *     details: {
 *       code:        "atlassian.auth.token_invalid",
 *       trace_id:    "atl-traceid: ...",
 *       occurred_at: "2026-05-09T07:42:18Z",
 *     },
 *   }
 *
 * Layer 1 fields (title / summary / fix_steps / doc_anchor) are
 * always shown.
 *
 * Layer 2 fields (details.*) are tucked behind a "Show details"
 * disclosure — copyable for support tickets, never relied on for
 * user comprehension.
 *
 * Layer 3 (raw HTTP body, headers, request URL, full stack) is
 * never exposed by the API and therefore never rendered here.
 *
 * If the backend returns the legacy bare-string shape (older
 * adapters that haven't been migrated to the new model), the card
 * gracefully degrades to showing just `message` — no broken layout,
 * no crashing on missing fields.
 */

import { useState } from "react";

export interface IntegrationError {
  // Layer 1
  title?: string;
  summary?: string;
  message?: string;            // legacy
  fix_steps?: string[];
  doc_anchor?: string;

  // Layer 2
  details?: {
    code?: string;
    trace_id?: string | null;
    occurred_at?: string;
  };

  // Tolerated extras the backend may send for forward compat
  [k: string]: unknown;
}

interface Props {
  /** The structured error from the backend, or null/undefined when no error. */
  error: IntegrationError | null | undefined;
  /** Compact rendering for inline locations (next to a button); default false. */
  compact?: boolean;
}

export function IntegrationErrorCard({ error, compact = false }: Props) {
  const [showDetails, setShowDetails] = useState(false);

  if (!error) return null;

  // Backward compat — if the adapter returned only the legacy
  // {message: ...} shape, surface that as the summary so the user
  // still sees something useful instead of an empty card.
  const title = error.title || "Connection failed";
  const summary = error.summary || error.message || "An unknown error occurred.";
  const fixSteps = Array.isArray(error.fix_steps) ? error.fix_steps : [];
  const docAnchor = error.doc_anchor;
  const details = error.details ?? {};
  const code = details.code;
  const traceId = details.trace_id;
  const occurredAt = details.occurred_at;

  // Compact mode: one-line title + summary, expand-to-see-details.
  // Used inline next to a Test Connection button where vertical space
  // is tight.
  if (compact) {
    return (
      <div className="flex flex-col gap-1 text-[12px]">
        <div className="flex items-start gap-2">
          <span className="text-red-400 mt-0.5">⚠</span>
          <div className="flex-1 min-w-0">
            <p className="font-semibold text-red-300">{title}</p>
            <p className="text-slate-400">{summary}</p>
          </div>
        </div>
        {(fixSteps.length > 0 || code || traceId) && (
          <button
            onClick={() => setShowDetails((v) => !v)}
            className="self-start text-[11px] text-slate-500 hover:text-slate-300 underline decoration-dotted"
          >
            {showDetails ? "Hide details ▴" : "Show details ▾"}
          </button>
        )}
        {showDetails && (
          <DetailBlock fixSteps={fixSteps} docAnchor={docAnchor} code={code} traceId={traceId} occurredAt={occurredAt} />
        )}
      </div>
    );
  }

  // Full card mode — used in the wizard's Test Connection panel and
  // anywhere the user is actively trying to fix the error.
  return (
    <div className="rounded-xl border border-red-500/20 bg-red-500/[0.04] p-4 my-3">
      <div className="flex items-start gap-3">
        <div className="w-8 h-8 rounded-lg bg-red-500/15 flex items-center justify-center shrink-0 text-red-400">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
          </svg>
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-[14px] font-semibold text-red-300">{title}</p>
          <p className="text-[13px] text-slate-300 mt-1 leading-relaxed">{summary}</p>

          {fixSteps.length > 0 && (
            <div className="mt-3">
              <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">What to try</p>
              <ol className="mt-1.5 space-y-1.5 list-decimal list-inside text-[13px] text-slate-300">
                {fixSteps.map((step, i) => (
                  <li key={i} className="leading-relaxed">{step}</li>
                ))}
              </ol>
            </div>
          )}

          <div className="mt-3 flex items-center gap-3">
            {docAnchor && (
              <a href={docAnchor} className="text-[12px] text-red-400 hover:text-red-300 underline decoration-red-400/30 inline-flex items-center gap-1">
                📖 Read more
              </a>
            )}
            <button
              onClick={() => setShowDetails((v) => !v)}
              className="text-[12px] text-slate-500 hover:text-slate-300 underline decoration-dotted"
            >
              {showDetails ? "Hide details ▴" : "Show details ▾"}
            </button>
          </div>

          {showDetails && (
            <DetailBlock fixSteps={[]} docAnchor={undefined} code={code} traceId={traceId} occurredAt={occurredAt} omitFixSteps />
          )}
        </div>
      </div>
    </div>
  );
}

/** Layer 2 disclosure block — the technical reference info.
 *  Each line has a clipboard-copy button (single click) so a user
 *  can paste the trace ID directly into a support ticket. */
function DetailBlock({
  fixSteps,
  docAnchor,
  code,
  traceId,
  occurredAt,
  omitFixSteps = false,
}: {
  fixSteps: string[];
  docAnchor?: string;
  code?: string;
  traceId?: string | null;
  occurredAt?: string;
  omitFixSteps?: boolean;
}) {
  const copy = (s: string | undefined) => {
    if (!s) return;
    try { navigator.clipboard.writeText(s); } catch {}
  };
  return (
    <div className="mt-3 pt-3 border-t border-white/[0.06] space-y-1.5 text-[11px] text-slate-500 font-mono">
      {!omitFixSteps && fixSteps.length > 0 && (
        <p className="text-slate-400">{fixSteps.length} suggested fix{fixSteps.length === 1 ? "" : "es"} above</p>
      )}
      {code && (
        <DetailLine label="Error code" value={code} onCopy={copy} />
      )}
      {traceId && (
        <DetailLine label="Reference ID" value={traceId} onCopy={copy} />
      )}
      {occurredAt && (
        <DetailLine label="Time" value={occurredAt} onCopy={copy} />
      )}
      {!code && !traceId && !occurredAt && (
        <p className="italic text-slate-600">No additional reference info available.</p>
      )}
    </div>
  );
}

function DetailLine({ label, value, onCopy }: { label: string; value: string; onCopy: (s: string) => void }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-slate-600 w-24 shrink-0">{label}:</span>
      <code className="text-slate-400 truncate flex-1">{value}</code>
      <button
        onClick={() => onCopy(value)}
        className="text-slate-600 hover:text-slate-300 px-1.5 py-0.5 rounded hover:bg-white/[0.06]"
        title="Copy to clipboard"
      >
        📋
      </button>
    </div>
  );
}
