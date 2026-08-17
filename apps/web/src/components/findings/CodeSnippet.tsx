// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import React from "react";

/**
 * Code snippet with a real-file line-number gutter and the offending line
 * highlighted — the GitHub / GitGuardian / Snyk convention.
 *
 * The scanner builds each snippet as `lines[max(0, line_num - 6) : line_num + 5]`
 * (services/secret_scan/engine.py), so the FIRST snippet line is the real file
 * line `max(1, lineStart - 5)`, and it clips correctly near the top of a file.
 * Keep this "- 5" in sync with the engine's snippet window if it ever changes.
 */
export function CodeSnippet({
  snippet,
  lineStart,
  className = "",
}: {
  snippet: string;
  lineStart?: number | null;
  className?: string;
}) {
  const lines = snippet.replace(/\n+$/, "").split("\n");
  const startLine = lineStart != null ? Math.max(1, lineStart - 5) : 1;
  const gutterCh = String(startLine + lines.length).length + 1;
  return (
    <div
      className={`bg-[#0a0e1a] rounded-xl text-[12px] leading-relaxed font-mono border border-white/[0.04] overflow-x-auto py-2 ${className}`}
    >
      {lines.map((ln, i) => {
        const lineNo = startLine + i;
        const isHit = lineStart != null && lineNo === lineStart;
        return (
          <div key={i} className={`flex min-w-max ${isHit ? "bg-red-500/[0.12]" : ""}`}>
            <span
              className={`select-none text-right pr-3 pl-4 shrink-0 tabular-nums ${isHit ? "text-red-400 font-semibold" : "text-slate-600"}`}
              style={{ minWidth: `${gutterCh + 2}ch` }}
              aria-hidden="true"
            >
              {lineNo}
            </span>
            <span className={`pl-3 pr-6 whitespace-pre ${isHit ? "text-red-200" : "text-slate-300"}`}>
              {ln.length ? ln : " "}
            </span>
          </div>
        );
      })}
    </div>
  );
}
