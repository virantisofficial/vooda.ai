-- Performance indexes for Vooda AI
-- Run manually if not using Alembic for these

-- Composite index for finding list queries (most common query)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_severity_class
ON normalized_findings (tenant_id, severity, classification)
WHERE is_suppressed = false;

-- Composite for repo-scoped finding queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_repo_created
ON normalized_findings (repository_id, created_at DESC)
WHERE is_suppressed = false;

-- Composite for scan job finding queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_scan_job
ON normalized_findings (scan_job_id, severity);

-- Index for correlation group lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_correlation
ON normalized_findings (correlation_group_id)
WHERE correlation_group_id IS NOT NULL;

-- Index for finding decisions (calibration queries)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_decisions_finding_action
ON finding_decisions (finding_id, action);

-- Index for audit events
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_tenant_created
ON audit_events (tenant_id, created_at DESC);

-- Index for scan jobs by repo
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scans_repo_created
ON scan_jobs (repository_id, created_at DESC);

-- Index for suppression rules
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_suppressions_rule_pattern
ON suppression_rules (scanner_rule_id, pattern_hash)
WHERE is_active = true;
