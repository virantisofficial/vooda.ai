// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * Scan-type badge + provenance header for CLI/CI (two-way-sync) scans.
 *
 * Shared by the scan-job detail page and the live drawer so a `vooda scan`
 * (CLI) / `vooda monitor` (CI) import renders first-class instead of as a raw
 * "ci" string.
 *
 * SECURITY: the provenance fields (actor, branch, commit, pipeline URL) are
 * self-reported by the CI runner and are UNTRUSTED. Text is rendered via JSX
 * (React escapes it — no XSS), and the pipeline URL is scheme-validated to
 * http(s) before being used as an href so a `javascript:`/`data:` URI from a
 * malicious import payload can never become a clickable link.
 */
import type { ReactNode } from "react";
import type { ScanJob } from "@/types";

const SCAN_TYPE_META: Record<string, { label: string; cls: string }> = {
  standalone: { label: "Current Code", cls: "bg-slate-500/15 text-slate-300" },
  history: { label: "Git History", cls: "bg-slate-500/15 text-slate-300" },
  source_scan: { label: "Source", cls: "bg-slate-500/15 text-slate-300" },
  hybrid: { label: "Hybrid", cls: "bg-slate-500/15 text-slate-300" },
  import: { label: "Imported", cls: "bg-amber-500/15 text-amber-300" },
  cli: { label: "CLI", cls: "bg-sky-500/15 text-sky-300" },
  ci: { label: "CI", cls: "bg-emerald-500/15 text-emerald-300" },
};

const CI_PROVIDER_LABEL: Record<string, string> = {
  github_actions: "GitHub Actions",
  gitlab_ci: "GitLab CI",
  jenkins: "Jenkins",
  circleci: "CircleCI",
  bitbucket_pipelines: "Bitbucket Pipelines",
  azure_pipelines: "Azure Pipelines",
};

export function ScanTypeBadge({ scanType }: { scanType?: string | null }) {
  const key = (scanType || "").toLowerCase();
  const meta =
    SCAN_TYPE_META[key] || { label: scanType || "scan", cls: "bg-slate-500/15 text-slate-300" };
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium ${meta.cls}`}
    >
      {meta.label}
    </span>
  );
}

/** Only render an href if the URL is an http(s) URL — blocks javascript:/data:. */
function safeHttpUrl(url?: string | null): string | null {
  if (!url) return null;
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:" ? u.href : null;
  } catch {
    return null;
  }
}

export function ScanProvenance({ job }: { job: ScanJob }) {
  const t = (job.scan_type || "").toLowerCase();
  if (t !== "cli" && t !== "ci") return null;

  const items: Array<{ label: string; value: ReactNode }> = [];
  if (job.commit_sha)
    items.push({
      label: "Commit",
      value: <span className="font-mono text-slate-300">{job.commit_sha.slice(0, 10)}</span>,
    });
  if (job.branch) items.push({ label: "Branch", value: job.branch });
  if (job.actor) items.push({ label: "Run by", value: job.actor });
  if (job.ci_provider)
    items.push({
      label: "CI",
      value: CI_PROVIDER_LABEL[job.ci_provider.toLowerCase()] || job.ci_provider,
    });

  const pipelineUrl = safeHttpUrl(job.ci_pipeline_url);
  if (items.length === 0 && !pipelineUrl) return null;

  return (
    <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 rounded-md border border-slate-700/60 bg-slate-800/40 px-3 py-2 text-[11px]">
      {items.map((it) => (
        <span key={it.label} className="inline-flex items-center gap-1">
          <span className="text-slate-500">{it.label}</span>
          <span className="text-slate-300">{it.value}</span>
        </span>
      ))}
      {pipelineUrl && (
        <a
          href={pipelineUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="text-sky-400 hover:text-sky-300 hover:underline"
        >
          View pipeline run ↗
        </a>
      )}
    </div>
  );
}
