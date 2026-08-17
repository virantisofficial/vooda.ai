// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

export interface User {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
  roles: string[];
}

export interface Repository {
  id: string;
  name: string;
  url: string | null;
  source_type: string;
  default_branch: string;
  is_active: boolean;
  languages: string[];
  frameworks: string[];
  metadata_?: Record<string, any>;
  // Per-repo scan toggles + webhook health (migration u8v9w0x1y2z3).
  // Drives the list-view webhook health badge and the detail-view
  // "Webhook & PR Scans" Settings section.
  push_scan_enabled?: boolean;
  pr_scan_enabled?: boolean;
  last_webhook_event_at?: string | null;
  last_webhook_event_type?: string | null;   // push / pull_request / merge_request
  last_webhook_event_status?: string | null; // success / failed
  // fnmatch globs that gate which branches trigger a scan on webhook
  // delivery.  null = scan every branch (preserves the pre-w0x1y2z3a4b5
  // default).  Examples: ["main"], ["main", "release/*"], ["*"].
  branch_patterns?: string[] | null;
  created_at: string;
}

export interface ScanJob {
  id: string;
  repository_id: string;
  scan_type: string;
  status: string;
  progress_pct: number;
  status_message: string | null;
  // WS-3′ failure reason — populated for FAILED scans (never empty),
  // already redacted server-side. Shown on the scan-job page / drawer.
  error_detail?: string | null;
  stats: Record<string, any>;
  // Scan-trigger config — the worker reads keys like `skip_ai`,
  // `force_full`, `branch` etc.  Added 2026-05-24 (Vooda Scan
  // Intelligence audit) so the scan-card UI can distinguish a
  // user-requested AI skip from a missing-provider state — both
  // would otherwise show as ``ai_triaged=0`` with no other signal.
  config?: Record<string, any>;
  created_at: string;
  updated_at: string;
  // G-2 — "last made real progress" timestamp (phase transition,
  // storing chunk, AI-triage batch). Drives the scan-progress liveness
  // / stall indicator. Null until the first heartbeat / pre-G-2 rows.
  heartbeat_at?: string | null;
  // P0 two-way sync — provenance for CLI/CI scans (a `vooda scan` /
  // `vooda monitor` synced from a dev machine or pipeline). Null for
  // server-side scans. `actor` is self-reported by the runner (UNTRUSTED,
  // display only).
  commit_sha?: string | null;
  branch?: string | null;
  actor?: string | null;
  ci_provider?: string | null;
  ci_pipeline_url?: string | null;
}

// One row of the append-only per-phase scan timeline (Sprint S / WS-1).
// Returned oldest-first by GET /repositories/{id}/scans/{id}/events and
// rendered by <ScanTimeline>.  `phase_label` is already redacted (WS-6).
export interface ScanPhaseEvent {
  id: string;
  scan_job_id: string;
  step: number;
  total_steps: number;
  phase_label: string;
  status: string;
  progress_pct: number;
  stats_snapshot: Record<string, any> | null;
  created_at: string;
}

export interface FindingListItem {
  id: string;
  title: string;
  vulnerability_category: string;
  cwe: string | null;
  severity: "critical" | "high" | "medium" | "low" | "info";
  classification: string;
  review_status: string;
  remediation_status: string;
  scanner_name: string;
  file_path: string;
  line_start: number | null;
  confidence: number;
  ai_confidence: number | null;
  code_snippet: string | null;
  assigned_to: string | null;
  tags: string[];
  // Set by the API when the finding's parent (repo or scan_source) is
  // archived.  Drives the inline "Archived source" badge on rows.
  is_archived_parent?: boolean;
  created_at: string;
}

export interface FindingDetail extends FindingListItem {
  scan_job_id: string;
  repository_id: string;
  scanner_rule_id: string | null;
  external_finding_id: string | null;
  description: string | null;
  cwe: string | null;
  cve: string | null;
  exploitability_score: number | null;
  business_risk_score: number | null;
  branch: string | null;
  commit_sha: string | null;
  line_end: number | null;
  function_name: string | null;
  class_name: string | null;
  code_snippet: string | null;
  ai_explanation: string | null;
  true_positive_reasons: string[];
  false_positive_reasons: string[];
  compensating_controls: string[];
  is_suppressed: boolean;
  evidence: Evidence[];
  decisions: Decision[];
  remediation_plans: RemediationPlanSummary[];
  updated_at: string;
}

export interface Evidence {
  type: string;
  file: string | null;
  summary: string | null;
  content: string | null;
}

export interface Decision {
  action: string;
  comment: string | null;
  created_at: string;
  user_name: string;
  user_id: string;
  previous_classification: string | null;
  new_classification: string | null;
}

export interface RemediationPlanSummary {
  id: string;
  summary: string;
  confidence: number | null;
}
