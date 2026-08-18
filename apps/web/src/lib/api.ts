// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import axios from "axios";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";

const api = axios.create({
  baseURL: `${API_BASE}/api/v1`,
  headers: { "Content-Type": "application/json" },
});

api.interceptors.request.use((config) => {
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("vooda_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401 && typeof window !== "undefined") {
      localStorage.removeItem("vooda_token");
      window.location.href = "/login";
    }
    return Promise.reject(err);
  }
);

// Auth
export const login = (email: string, password: string) =>
  api.post("/auth/login", { email, password });

export const getMe = () => api.get("/auth/me");

// Repositories
export const getRepositories = (params?: Record<string, string | number>) =>
  api.get("/repositories", { params });
export const getRepositoryFacets = () => api.get("/repositories/facets");
export const getRepository = (id: string) => api.get(`/repositories/${id}`);
export const createRepository = (data: {
  name: string; url?: string; source_type: string; default_branch?: string;
  auth?: Record<string, string>; provider?: string;
  scan_mode?: string; scanner_integration_id?: string; scanner_project_key?: string;
  [key: string]: any;
}) => api.post("/repositories", data);
export const updateRepository = (id: string, data: object) =>
  api.put(`/repositories/${id}`, data);
// Per-repo push/PR scan toggles + branch-pattern monitoring.  All
// fields optional so the FE can update them independently.  The
// backend normalises ``branch_patterns: []`` and whitespace-only
// entries to ``null`` ("monitor all branches").  Audit-logged.
export const updateRepoScanConfig = (id: string, data: {
  push_scan_enabled?: boolean;
  pr_scan_enabled?: boolean;
  branch_patterns?: string[] | null;
}) =>
  api.patch(`/repositories/${id}/scan-config`, data);
// Severity-weighted daily series for the list-view sparkline.  Returns
// a fixed-length array (zero-padded), oldest first.  `weighted` = the
// dashboard's severity blend (4×crit + 3×high + 2×med + 1×low).
export const getRepoSeverityTrend = (id: string, days = 30) =>
  api.get(`/repositories/${id}/severity-trend`, { params: { days } });
export const deleteRepository = (id: string) =>
  api.delete(`/repositories/${id}`);
export const archiveRepository = (id: string) =>
  api.post(`/repositories/${id}/archive`);
export const unarchiveRepository = (id: string) =>
  api.post(`/repositories/${id}/unarchive`);
// Impact preview for permanent repository delete — drives the
// destructive-action confirmation modal.  Pairs with
// /scan-sources/{id}/delete-preview (same response shape, different
// scope) so the FE DeleteConfirmModal can render both identically.
export const getRepositoryDeletePreview = (id: string) =>
  api.get(`/repositories/${id}/delete-preview`);
// Aggregated impact preview for a bulk-selection delete.  Returns
// roll-up counts where incidents spanning multiple selected repos are
// counted once (NOT a sum of per-repo previews).
export const getRepositoryBulkDeletePreview = (ids: string[]) =>
  api.post(`/repositories/bulk-delete-preview`, { ids });
export const getRepoStats = (id: string) =>
  api.get(`/repositories/${id}/stats`);
export const getRepoBranches = (id: string) =>
  api.get(`/repositories/${id}/branches`);
export const triggerScan = (repoId: string, data?: object) =>
  api.post(`/repositories/${repoId}/scan`, data || {});
export const uploadToRepository = (repoId: string, file: File) => {
  const formData = new FormData();
  formData.append("file", file);
  return api.post(`/repositories/${repoId}/upload`, formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
};
export const probeRepository = (data: {
  url: string;
  token?: string;
  username?: string;
  password?: string;
}) => api.post("/repositories/probe", data);
export const getRepoScans = (repoId: string) =>
  api.get(`/repositories/${repoId}/scans`);
export const getScanStatus = (repoId: string, scanId: string) =>
  api.get(`/repositories/${repoId}/scans/${scanId}`);
// Flat scan-job accessors by id (Sprint S / WS-4) — for the standalone
// /scan-jobs/{id} page + external pollers that only hold a scan id.
// Tenant-scoped server-side.
export const getScanJob = (scanId: string) =>
  api.get(`/scan-jobs/${scanId}`);
// Append-only per-phase scan timeline (Sprint S / WS-1).  Oldest-first;
// seeds <ScanTimeline> so the drawer + /scan-jobs page survive refresh
// and show a completed scan's full history (the client-side-only
// timeline could not).  phase_label is already redacted server-side.
export const getScanJobEvents = (scanId: string) =>
  api.get(`/scan-jobs/${scanId}/events`);
export const cancelScan = (repoId: string, scanId: string) =>
  api.post(`/repositories/${repoId}/scans/${scanId}/cancel`);
export const deleteScan = (repoId: string, scanId: string) =>
  api.delete(`/repositories/${repoId}/scans/${scanId}`);
// Re-run AI triage on an already-completed scan whose triage was skipped
// (no AI model at scan time). Triages the existing findings in place — no
// re-scan. 400 if no AI model is configured.
export const runAiTriage = (repoId: string, scanId: string) =>
  api.post(`/repositories/${repoId}/scans/${scanId}/ai-triage`);

// Findings
export const getFindings = (params?: Record<string, string>) =>
  api.get("/findings", { params });
export const getFindingTags = () => api.get("/findings/tags");
export const getFinding = (id: string) => api.get(`/findings/${id}`);
export const triageFinding = (
  id: string,
  data: {
    action: string;
    comment?: string;
    /** Provenance marker — set by SuggestionChips clicks to
     *  "suggestion_placeholder" / "suggestion_test_file" /
     *  "suggestion_git_history".  Threaded into the audit `via` field. */
    source?: string;
    /** Optimistic-lock token from the row the user loaded.  When set,
     *  the server rejects the write with HTTP 409 if another reviewer
     *  saved a change in the same window — UI then prompts the user
     *  to reload.  Backend treats this as optional for backwards-compat
     *  with non-UI callers (CI scripts / integrations). */
    expected_version?: number;
  },
) => api.post(`/findings/${id}/triage`, data);
export const addFindingComment = (id: string, comment: string) =>
  api.post(`/findings/${id}/comment`, { action: "comment", comment });
export const assignFinding = (id: string, userId: string | null, userName?: string) =>
  api.post(`/findings/${id}/assign`, { user_id: userId, user_name: userName });
export const updateFindingTags = (id: string, tags: string[]) =>
  api.post(`/findings/${id}/tags`, { tags });

// Saved Views
export const getSavedViews = (viewType?: string) =>
  api.get("/saved-views", { params: { view_type: viewType || "findings" } });
export const createSavedView = (data: { name: string; filters: Record<string, string>; view_type?: string }) =>
  api.post("/saved-views", data);
export const deleteSavedView = (id: string) =>
  api.delete(`/saved-views/${id}`);

export const requestRemediation = (id: string) =>
  api.post(`/findings/${id}/remediate`, {});
export const approvePatch = (id: string, data: { action: string; comment?: string }) =>
  api.post(`/findings/${id}/approve`, data);

// Metrics
export const getMetricsOverview = (days?: number, withDelta = false) =>
  api.get("/metrics/overview", {
    params: {
      ...(days ? { days } : {}),
      ...(withDelta ? { with_delta: true } : {}),
    },
  });
// Dashboard-only: findings grouped by source category (Code Repos, Collaboration,
// Docs & Wikis, etc.) for the "Findings by Source" bar chart.  Severity-blended
// counts per category so the FE can render colour-coded bar fills.
export const getFindingsByCategory = (days?: number) =>
  api.get("/metrics/findings-by-category", { params: days ? { days } : {} });
// Dashboard-only: top N repos ranked by finding count, with per-severity
// breakdown for the "Top Leaking Repos" row.
export const getTopLeakingRepos = (days?: number, limit = 7) =>
  api.get("/metrics/top-leaking-repos", {
    params: { ...(days ? { days } : {}), limit },
  });

// Bell notifications (persistent, emitted by backend — worker triage health, etc.)
export const getNotifications = (params?: { limit?: number; unread_only?: boolean }) =>
  api.get("/notifications", { params });
export const markNotificationRead = (id: string) =>
  api.post(`/notifications/${id}/read`);
export const markAllNotificationsRead = () =>
  api.post("/notifications/read-all");
export const getFindingsMetrics = () => api.get("/metrics/findings");
export const getRemediationMetrics = (repoId?: string) =>
  api.get("/metrics/remediation", { params: repoId ? { repository_id: repoId } : {} });
export const getMTTRMetrics = () => api.get("/metrics/mttr");
export const getFindingsBreakdown = () => api.get("/metrics/findings-breakdown");

// Rotation events (B3 — credential-rotation telemetry)
export const getRotationEvents = (params?: { provider?: string; days?: number; limit?: number; offset?: number }) =>
  api.get("/rotation-events", { params: params || {} });
export const getRotationSummary = (days: number = 30) =>
  api.get("/rotation-events/summary", { params: { days } });

// Incidents — Case-B aggregation (one row per unique credential).
// The /findings page renders these in "Incidents view" mode as an
// alternative to the per-occurrence findings list.
export const getIncidents = (params?: Record<string, string | number | boolean>) =>
  api.get("/incidents", { params: params || {} });
export const getIncident = (id: string) => api.get(`/incidents/${id}`);
export const patchIncident = (id: string, data: {
  classification?: string;
  review_status?: string;
  rotation_status?: string;
  validation_status?: string;
  assigned_to?: string | null;
  /** Full tag-list replacement.  IncidentDetailDrawer's tag editor
   *  passes the new array on add/remove (same pattern as
   *  updateFindingTags) — backend lowercases + dedupes server-side. */
  tags?: string[];
  /** Optional free-text "why" that rides along to the audit log
   *  (never persisted on the incident row itself).  Mirrors the
   *  Findings drawer's save-with-comment pattern. */
  comment?: string;
  /** Provenance marker — set by SuggestionChips clicks to
   *  "suggestion_placeholder" / "suggestion_test_file" /
   *  "suggestion_git_history" so the History tab can show
   *  signal-confirmed actions distinctly. */
  source?: string;
  /** Optimistic-lock token from the incident the user loaded.  When set,
   *  the server rejects the write with HTTP 409 if another reviewer
   *  saved a change in the same window — UI then prompts to reload. */
  expected_version?: number;
}) => api.patch(`/incidents/${id}`, data);
// Bulk "Mark rotated" — accepts up to 200 incident_ids per call.
// Idempotent: incidents already in rotated state are counted
// separately in the response.
export const bulkMarkIncidentsRotated = (incident_ids: string[], note?: string) =>
  api.post("/incidents/bulk-mark-rotated", { incident_ids, note });

// Bulk triage — apply the same status change to N incidents in one
// server-side transaction.  Replaces the fan-out (N parallel PATCHes)
// the UI used to do; at 500 selected incidents the difference is
// ~25s vs ~1s wall-clock plus full transactional safety.
//
// Action vocabulary matches the IncidentDetailDrawer's status
// dropdown exactly:
//   mark_tp | mark_fp | mark_rotated | mark_test | accept_risk | reopen
// Response shape:
//   { updated, unchanged, not_found, cascaded_findings }
export const bulkTriageIncidents = (
  incident_ids: string[],
  action: string,
  comment?: string,
) => api.post("/incidents/bulk-triage", { incident_ids, action, comment });

// Bulk triage for Findings — same shape as the incident version,
// commits each finding's triage state + cascades to its parent
// incident (+ sibling occurrences) in a single transaction.
//
// Response shape:
//   { updated, unchanged, not_found, incidents_cascaded, siblings_cascaded }
export const bulkTriageFindings = (
  finding_ids: string[],
  action: string,
  comment?: string,
) => api.post("/findings/bulk-triage", { finding_ids, action, comment });

// Per-incident audit timeline — used by the IncidentDetailDrawer's
// History tab.  Newest-first, capped at 200 entries by the API.
// Backend normalises each entry into a pretty shape (kind + label +
// previous/new fields) so the UI doesn't have to interpret raw
// metadata JSON.
export const getIncidentHistory = (id: string) =>
  api.get(`/incidents/${id}/history`);


// Audit
export const getAuditEvents = (params?: Record<string, string>) =>
  api.get("/audit", { params });
export const exportAuditCSV = (params?: Record<string, string>) =>
  api.get("/audit/export", { params, responseType: "blob" });
export const enforceRetention = (retentionDays: number) =>
  api.post(`/audit/enforce-retention?retention_days=${retentionDays}`);
export const getAuditStats = () => api.get("/audit/stats");

// Integrations
export const getIntegrationProviders = () => api.get("/integrations/providers");
export const getProviderSchema = (provider: string) =>
  api.get(`/integrations/providers/${provider}`);
export const testIntegrationConnection = (data: { provider: string; config: Record<string, string> }) =>
  api.post("/integrations/test", data);
export const createIntegration = (data: {
  provider: string;
  name?: string;
  config: Record<string, string>;
  scope_level?: string;
  business_unit_id?: string;
  repository_id?: string;
}) => api.post("/integrations", data);
export const getIntegrations = () => api.get("/integrations");
export const getIntegration = (id: string) => api.get(`/integrations/${id}`);
export const updateIntegration = (id: string, data: {
  name?: string; config?: Record<string, string>; scope_level?: string;
  business_unit_id?: string; repository_id?: string; is_active?: boolean;
}) => api.put(`/integrations/${id}`, data);
export const deleteIntegration = (id: string) => api.delete(`/integrations/${id}`);

// Notification Rules
export const getNotificationRules = () => api.get("/notifications/rules");
export const updateNotificationRules = (rules: Array<{event_type: string; severity_threshold: string; is_enabled: boolean}>) =>
  api.put("/notifications/rules", rules);

// Suppressions
export const getSuppressionRules = (params?: Record<string, string>) =>
  api.get("/suppressions", { params });
export const createSuppressionRule = (data: object) => api.post("/suppressions", data);
export const updateSuppressionRule = (id: string, data: object) => api.put(`/suppressions/${id}`, data);
export const deleteSuppressionRule = (id: string) => api.delete(`/suppressions/${id}`);
export const getSuppressionStats = () => api.get("/suppressions/stats");
export const triggerLearning = () => api.post("/suppressions/learn");
// getCalibrationStats removed — it called GET /ai-models/calibration,
// which no endpoint has ever served. Nothing imported it, so it was a
// 404 waiting for whoever wired it up first.

// Rule Overrides — proactive scanner-rule muting (per-repo / org-wide).
// Distinct from Suppressions which is the reactive post-finding triage
// surface.  See apps/api/app/models/rule_override.py for the rationale.
export const getRuleOverrides = (params?: Record<string, string | number | boolean>) =>
  api.get("/rule-overrides", { params });
export const getRuleOverrideStats = () => api.get("/rule-overrides/stats");
export const getAvailableRules = (params?: { q?: string }) =>
  api.get("/rule-overrides/available-rules", { params });
export const createRuleOverride = (data: {
  scanner_rule_id: string;
  repository_id?: string | null;
  scan_source_id?: string | null;
  mode?: string;
  reason: string;
}) => api.post("/rule-overrides", data);
export const updateRuleOverride = (id: string, data: {
  mode?: string;
  reason?: string;
  is_active?: boolean;
}) => api.patch(`/rule-overrides/${id}`, data);
export const deleteRuleOverride = (id: string) => api.delete(`/rule-overrides/${id}`);

// Custom Detectors
export const getCustomDetectors = (params?: Record<string, string>) =>
  api.get("/custom-detectors", { params });
export const getCustomDetector = (id: string) =>
  api.get(`/custom-detectors/${id}`);
export const createCustomDetector = (data: object) =>
  api.post("/custom-detectors", data);
export const updateCustomDetector = (id: string, data: object) =>
  api.put(`/custom-detectors/${id}`, data);
export const deleteCustomDetector = (id: string) =>
  api.delete(`/custom-detectors/${id}`);
export const toggleCustomDetector = (id: string) =>
  api.post(`/custom-detectors/${id}/toggle`);
export const testCustomDetectorRegex = (data: { pattern: string; test_strings: string[]; multiline?: boolean }) =>
  api.post("/custom-detectors/test-regex", data);
export const getCustomDetectorStats = () =>
  api.get("/custom-detectors/stats/summary");

// Users
export const getUsers = () => api.get("/users");
export const createUser = (data: { full_name: string; email: string; password: string; role: string }) =>
  api.post("/users", data);
export const updateUser = (id: string, data: object) => api.put(`/users/${id}`, data);
export const deleteUser = (id: string) => api.delete(`/users/${id}`);
export const activateUser = (id: string) => api.post(`/users/${id}/activate`);
// Self-service password change — requires the current password.
export const changeMyPassword = (data: { current_password: string; new_password: string }) =>
  api.post(`/auth/change-password`, data);

// Roles
export const getRoles = () => api.get("/roles");
export const getPermissions = () => api.get("/roles/permissions");
export const createRole = (data: object) => api.post("/roles", data);
export const updateRole = (id: string, data: object) => api.put(`/roles/${id}`, data);
export const deleteRole = (id: string) => api.delete(`/roles/${id}`);
export const resetRole = (id: string) => api.post(`/roles/${id}/reset`);

// Reports
export const getExecutiveSummary = (days?: number, repoId?: string) =>
  api.get("/reports/executive", { params: { days: days || 30, ...(repoId ? { repository_id: repoId } : {}) } });
export const getAgingReport = (repoId?: string) =>
  api.get("/reports/aging", { params: repoId ? { repository_id: repoId } : {} });
export const getRepoRiskReport = () => api.get("/reports/repo-risk");
export const getDeveloperActivity = (days?: number, repoId?: string) =>
  api.get("/reports/developer-activity", { params: { days: days || 30, ...(repoId ? { repository_id: repoId } : {}) } });
export const getSLACompliance = (repoId?: string) =>
  api.get("/reports/sla", { params: repoId ? { repository_id: repoId } : {} });
export const getComplianceReport = (repoId?: string) =>
  api.get("/reports/compliance", { params: repoId ? { repository_id: repoId } : {} });
export const getOWASPReport = (repoId?: string) =>
  api.get("/reports/owasp", { params: repoId ? { repository_id: repoId } : {} });
export const getTrendData = (days?: number) =>
  api.get("/metrics/trends", { params: { days: days || 30 } });
export const getAIAccuracy = (repoId?: string) =>
  api.get("/metrics/ai-accuracy", { params: repoId ? { repository_id: repoId } : {} });
export const getScannerComparison = () => api.get("/metrics/scanner-comparison");
export const exportSARIF = (repoId?: string) =>
  api.get("/reports/export/sarif", { params: repoId ? { repository_id: repoId } : {}, responseType: "blob" });
export const exportCSV = (repoId?: string) =>
  api.get("/reports/export/csv", { params: repoId ? { repository_id: repoId } : {}, responseType: "blob" });

// Enterprise Reports
export const getReleaseReadiness = (repoId?: string) =>
  api.get("/reports/release-readiness", { params: repoId ? { repository_id: repoId } : {} });
export const getSecurityDebt = (repoId?: string) =>
  api.get("/reports/security-debt", { params: repoId ? { repository_id: repoId } : {} });
export const getFixPriority = (repoId?: string, topN?: number) =>
  api.get("/reports/fix-priority", { params: { ...(repoId ? { repository_id: repoId } : {}), ...(topN ? { top_n: topN } : {}) } });
export const getDeveloperReport = (repoId?: string, findingId?: string) =>
  api.get("/reports/developer-report", { params: { ...(repoId ? { repository_id: repoId } : {}), ...(findingId ? { finding_id: findingId } : {}) } });

// API Keys
export const getAPIKeyScopes = () => api.get("/api-keys/scopes");
export const getAPIKeys = () => api.get("/api-keys");
export const createAPIKey = (data: { name: string; scopes: string[]; expires_in_days?: number | null; allowed_ip_cidrs?: string[] | null }) =>
  api.post("/api-keys", data);
export const revokeAPIKey = (id: string) => api.delete(`/api-keys/${id}`);
// Rotate (Sprint 2 GAP-7) — server clamps grace_period_days to [0, 30].
// Returns the new key (shown once) + status linkage on the old key.
export const rotateAPIKey = (id: string, grace_period_days = 7) =>
  api.post(`/api-keys/${id}/rotate`, { grace_period_days });
// Usage analytics (Sprint 2 GAP-13).
export const getAPIKeyUsage = (id: string, days = 7) =>
  api.get(`/api-keys/${id}/usage`, { params: { days } });
// PATCH in-place edit (Sprint 3 GAP-10) — name + allowlist only.
// Pass allowed_ip_cidrs: [] to CLEAR, omit to leave untouched.
export const updateAPIKey = (id: string, data: { name?: string; allowed_ip_cidrs?: string[] | null }) =>
  api.patch(`/api-keys/${id}`, data);

// Access Control — Business Units & Grants
export const getBusinessUnits = () => api.get("/access/business-units");
export const createBusinessUnit = (data: { name: string; description?: string; parent_id?: string }) =>
  api.post("/access/business-units", data);
export const updateBusinessUnit = (id: string, data: { name: string; description?: string }) =>
  api.put(`/access/business-units/${id}`, data);
export const deleteBusinessUnit = (id: string) => api.delete(`/access/business-units/${id}`);
export const getAccessGrants = (userId?: string) =>
  api.get("/access/grants", { params: userId ? { user_id: userId } : {} });
export const createAccessGrant = (data: {
  user_id: string; access_level: string; role: string;
  business_unit_id?: string; repository_id?: string;
}) => api.post("/access/grants", data);
export const deleteAccessGrant = (id: string) => api.delete(`/access/grants/${id}`);
export const getMyAccess = () => api.get("/access/my-access");

// AI Models
export const getAIModels = () => api.get("/ai-models");
export const getAIStatus = () => api.get("/ai-models/status");
export const createAIModel = (data: object) => api.post("/ai-models", data);
export const updateAIModel = (id: string, data: object) => api.put(`/ai-models/${id}`, data);
export const deleteAIModel = (id: string) => api.delete(`/ai-models/${id}`);
export const testAIModel = (data: object) => api.post("/ai-models/test", data);
export const getAITaskRouting = () => api.get("/ai-models/routing/tasks");
export const getAIEngineSettings = () => api.get("/ai-models/engine-settings");
export const updateAIEngineSettings = (data: Record<string, any>) => api.put("/ai-models/engine-settings", data);
export const discoverModels = (data: { provider: string; api_key?: string; endpoint_url?: string }) =>
  api.post("/ai-models/discover-models", data);
export const getAutoConfig = (data: { provider: string; model_id: string; prompt_strategy?: string; parameter_size?: string }) =>
  api.post("/ai-models/auto-config", data);

// Governance API clients (policies, NHI, agents, supply-chain, quantum,
// federation, migrations, universal governance, gates) removed 2026-05-16 —
// product surfaces deleted alongside the scanner-core refocus.
// See Sidebar.tsx and docs/page.tsx for rationale.

// Blast Radius
export const getBlastRadius = (findingId: string) =>
  api.get(`/findings/${findingId}/blast-radius`);

// Manual credential re-verification.  Calls the per-provider verifier
// against the live API and updates validation_status in place.  Used
// by the "re-verify" button on the Validation Status cards in both
// drawers.  Returns:
//   { status: "active" | "inactive" | "revoked" | "unsupported" | "error",
//     details, permissions, provider, blast_radius? }
// "active" means the credential still works → rotate immediately.
//
// NOTE 2026-05-17: FindingPanel previously used `fetch("/api/findings/...")`
// which 404'd because the API is mounted at `/api/v1/findings/...`.
// Centralising both calls through the axios client (which bakes in
// the /api/v1 prefix) prevents that class of bug entirely.
export const verifyFinding = (findingId: string) =>
  api.post(`/findings/${findingId}/verify`);
export const verifyIncident = (incidentId: string) =>
  api.post(`/incidents/${incidentId}/verify`);

// Phase 5: Non-Git Source Scanning
export const getScanSourceTypes = () => api.get("/scan-sources/types");
export const getScanSources = (params?: Record<string, string | number>) =>
  api.get("/scan-sources", { params });
export const getScanSource = (id: string) => api.get(`/scan-sources/${id}`);
export const createScanSource = (data: {
  name: string; source_type: string; integration_config_id: string;
  scan_schedule?: string; config?: Record<string, any>;
  target_repository_id?: string | null;
  target_business_unit_id?: string | null;
}) => api.post("/scan-sources", data);
export const updateScanSource = (id: string, data: {
  name?: string; is_active?: boolean; scan_schedule?: string; config?: Record<string, any>;
  target_repository_id?: string | null;
  target_business_unit_id?: string | null;
}) => api.put(`/scan-sources/${id}`, data);
export const deleteScanSource = (id: string) => api.delete(`/scan-sources/${id}`);
// Impact preview for permanent scan-source delete — see
// getRepositoryDeletePreview for the design rationale.
export const getScanSourceDeletePreview = (id: string) =>
  api.get(`/scan-sources/${id}/delete-preview`);
export const triggerSourceScan = (id: string) => api.post(`/scan-sources/${id}/scan`);
export const testSourceConnection = (id: string) => api.post(`/scan-sources/${id}/test`);
// Pre-create test — used by the Connect Source modal so users can
// validate credentials BEFORE saving. The legacy
// `testIntegrationConnection` validates against PROVIDER_SCHEMAS
// (the OUTBOUND notification config), which is wrong for source-scan
// adapters: Slack expects bot_token here, not webhook_url. This
// endpoint hits the source-scan adapter's `test_connection()`
// directly. See `/api/v1/scan-sources/test-connection`.
export const testUnsavedSourceConnection = (data: {
  source_type: string;
  credentials: Record<string, string>;
  config?: Record<string, any>;
}) => api.post(`/scan-sources/test-connection`, data);
export const getSourceScans = (id: string) => api.get(`/scan-sources/${id}/scans`);

// ── OAuth 2.0 (Atlassian) ────────────────────────────────────────
// Two-step flow: caller posts /start with the IntegrationConfig ID,
// gets back an authorize_url, navigates the user to it (popup or
// top-level redirect), and Atlassian redirects to the API callback
// which finishes the exchange + stores tokens on the same row.
// /disconnect clears tokens but preserves the OAuth app credentials
// so reconnect doesn't require re-entering client_id/secret.
export const startAtlassianOAuth = (integration_id: string) =>
  api.post(`/integrations/oauth/atlassian/start?integration_id=${integration_id}`);
export const disconnectAtlassianOAuth = (integration_id: string) =>
  api.post(`/integrations/oauth/atlassian/disconnect?integration_id=${integration_id}`);

export default api;
