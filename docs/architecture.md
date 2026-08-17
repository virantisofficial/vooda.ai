# Vooda AI -- Architecture Overview

## System Architecture

```
                              +---------------------------+
                              |       Load Balancer       |
                              +---------------------------+
                                     |            |
                        +------------+            +-------------+
                        |                                       |
               +--------v--------+                   +----------v---------+
               |    Next.js 15   |                   |     FastAPI API     |
               |   Frontend      |                   |     (Python 3.12)  |
               |   Port 3000     |                   |     Port 8000      |
               +-----------------+                   +--------------------+
                        |                              |     |       |
                        |  HTTP/WS                     |     |       |
                        +---->  /api/v1/*  ----------->+     |       |
                                                             |       |
                                         +-------------------+       |
                                         |                           |
                               +---------v--------+       +---------v--------+
                               |     Redis 7      |       |  PostgreSQL 16   |
                               |  (Queue + Cache  |       |  (37 tables)     |
                               |   + Pub/Sub)     |       |  Port 5433       |
                               +------------------+       +------------------+
                                         |
                               +---------v--------+
                               |  Celery Workers   |
                               |  (concurrency=4)  |
                               |  Scan, Triage,    |
                               |  Verify, Report   |
                               +-------------------+
                                         |
                        +----------------+------------------+
                        |                |                  |
               +--------v----+  +--------v------+  +-------v--------+
               | Secret Scan |  | AI Triage     |  | Verification   |
               | Engine      |  | (Claude/GPT/  |  | (live provider |
               | (rule pack) |  |  local/BYO)   |  |  auth check)   |
               +-------------+  +---------------+  +----------------+
```

### Data Flow

```
Repository --> Clone --> File Analysis --> Pattern Scan (rules + entropy)
  --> Org-Wide Learned Suppressions
  --> Multi-Scanner Correlation
  --> AI Triage (parallel batch, framework-aware, evidence-enriched)
  --> Metrics Snapshot --> Notifications
  --> [User approves remediation]
  --> AI Patch Generation (with templates) --> Fix Validation
  --> PR Creation (GitHub / GitLab / Bitbucket)
```

## Component Overview

### API Server (`apps/api/`)

The FastAPI application serves as the central coordination layer. It handles HTTP requests, WebSocket connections for real-time scan progress, and orchestrates work across services.

- **Entry point**: `apps/api/app/main.py`
- **28 routers** under `/api/v1/`, exposing 199 endpoints
- **Swagger UI** at `/api/docs`
- **Authentication**: JWT tokens with RBAC (admin, security_engineer, developer, viewer)
- **Multi-tenancy**: All models include `tenant_id` for data isolation

### Worker (`apps/worker/`)

Celery workers process asynchronous tasks including repository scanning, non-git source scanning, AI triage, and report generation. Workers connect to the same database and Redis instance as the API.

- **Broker**: Redis
- **Concurrency**: 4 (configurable)
- **Task types**: scan, source scan, triage, remediation, reporting

### Web Frontend (`apps/web/`)

Next.js 15 application using the App Router pattern with React 19 and Tailwind CSS.

- **Port**: 3000 (published by `docker-compose.yml`)
- **API proxy**: Routes `/api/*` requests to the backend
- **Real-time**: WebSocket connection for live scan progress
- **Auth guard**: Client-side route protection via `AuthGuard` component

### Database (PostgreSQL 16)

Async SQLAlchemy ORM with Alembic migrations. All tables use UUID primary keys and include `created_at`/`updated_at` timestamps.

### Redis 7

Serves three roles:
1. **Celery broker** -- task queue for async workers
2. **Cache** -- API response caching and session data
3. **Pub/Sub** -- real-time WebSocket message distribution

## Service Layer

All domain logic lives in the `services/` directory. Each service module is independent and communicates through the database or Redis pub/sub.

| Module | Path | Purpose |
|--------|------|---------|
| **Secret Scanner** | `services/secret_scan/` | Signature, regex, and Shannon-entropy detection across many provider modules |
| **Secret Verification** | `services/secret_verification/` | Provider authentication confirming a candidate credential is still live; stamps `validation_status` and computes blast radius |
| **Secret Validation** | `services/secret_validation/` | Live credential validation against provider APIs (AWS, GitHub, GitLab, Slack, Stripe, Twilio, SendGrid, GCP, Azure, npm) |
| **Source Scanners** | `services/source_scanners/` | Non-git source adapters — collaboration, docs and wikis, issue tracking, cloud storage, DevOps |
| **Repo Scan** | `services/repo_scan/` | Repository checkout and scan concurrency control |
| **Integration Errors** | `services/integration_errors/` | Provider-specific classification of integration failures (GitHub, Atlassian, Azure, MS Graph) |
| **Code Context** | `services/code_context/` | AST-aware context extraction for AI triage enrichment |
| **AI Triage** | `services/ai_triage/` | Multi-provider AI classification with batch processing, deduplication, and Bayesian calibration |
| **AI Remediation** | `services/ai_remediation/` | AI-generated code patches for secret removal |
| **Evidence Collector** | `services/evidence/` | Security pattern discovery and context enrichment |
| **Correlation** | `services/correlation/` | Cross-scanner finding deduplication |
| **Normalization** | `services/normalization/` | Finding normalization with stability IDs and decision caching |
| **Learning** | `services/learning/` | Org-wide false positive pattern learning and suppression |
| **Git Integration** | `services/git_integration/` | GitHub, GitLab, Bitbucket API abstraction with factory pattern |
| **Git History** | `services/git_history/` | Historical commit scanning |
| **PR Pipeline** | `services/pr_pipeline/` | End-to-end pull request creation for remediation |
| **Fix Validation** | `services/fix_validation/` | Re-scan of generated patches before PR submission |
| **Batch Remediation** | `services/batch_remediation/` | Bulk remediation across multiple findings |
| **Incidents** | `services/incidents/` | Incident tracking and response workflows |
| **Scheduler** | `services/scheduler/` | Celery Beat scan scheduling (on-demand, daily, weekly) |
| **Notifications** | `services/notifications/` | Slack, Teams, email, and webhook notification channels |
| **Reporting** | `services/reporting/` | Compliance reports (SOC 2, PCI-DSS, ISO 27001, NIST), risk scoring, and developer guidance |
| **Webhooks** | `services/webhooks/` | Inbound webhook receiver for external integrations |
| **Ingestion** | `services/ingestion/` | SARIF, Checkmarx, Fortify, generic JSON/XML finding import |
| **Repo Analysis** | `services/repo_analysis/` | Repository structure and language analysis |
| **Auth** | `services/auth/` | SSO provider integration (SAML 2.0, OIDC, LDAP) |
| **Pub/Sub** | `services/pubsub/` | Redis pub/sub abstraction for real-time events |

### Secret Scanner Detectors

The `services/secret_scan/detectors/` directory contains 31+ detector modules:

| Detector | Coverage |
|----------|----------|
| `aws.py` | AWS Access Keys, Secret Keys, Session Tokens, MWS Keys |
| `gcp.py` | GCP API Keys, Service Account Keys, OAuth Secrets |
| `azure.py` | Azure Storage Keys, AD Client Secrets, Connection Strings |
| `github.py` | GitHub PATs, OAuth Tokens, App Keys |
| `gitlab.py` | GitLab PATs, Pipeline Tokens, Runner Tokens |
| `bitbucket.py` | Bitbucket App Passwords, OAuth Secrets |
| `stripe.py` | Stripe Secret Keys, Publishable Keys, Webhook Secrets |
| `slack.py` | Slack Bot Tokens, Webhook URLs, App Tokens |
| `twilio.py` | Twilio Auth Tokens, API Keys |
| `sendgrid.py` | SendGrid API Keys |
| `database.py` | Database connection strings (PostgreSQL, MySQL, MongoDB, Redis) |
| `crypto.py` | Private keys (RSA, EC, DSA, PGP), certificates |
| `payment.py` | PayPal, Square, Braintree, Adyen credentials |
| `saas.py` | Salesforce, HubSpot, Zendesk, Intercom tokens |
| `cloud_misc.py` | DigitalOcean, Heroku, Cloudflare, Vercel tokens |
| `cloud_infra.py` | Terraform tokens, Kubernetes secrets, Docker registry |
| `cicd.py` | Jenkins, CircleCI, Travis CI, GitHub Actions secrets |
| `auth.py` | OAuth tokens, JWT secrets, API keys, basic auth |
| `communication.py` | Discord, Telegram, WhatsApp, PagerDuty tokens |
| `generic.py` | Generic API key patterns, bearer tokens, passwords |
| `ai_ml.py` | OpenAI, Anthropic, HuggingFace, Cohere API keys |
| `productivity.py` | Notion, Airtable, Asana, Trello tokens |
| `analytics.py` | Mixpanel, Segment, Amplitude, Google Analytics |
| `messaging.py` | RabbitMQ, Kafka, NATS credentials |
| `cms.py` | WordPress, Contentful, Sanity tokens |
| `social.py` | Twitter/X, Facebook, Instagram, LinkedIn |
| `enterprise.py` | SAP, Oracle, ServiceNow credentials |
| `devtools.py` | npm, PyPI, RubyGems, NuGet tokens |
| `quantum_vulnerable.py` | RSA < 3072-bit, ECDSA, DSA quantum-risk detection |
| `gitleaks_batch1-5.py` | Ported Gitleaks community rules |
| `trufflehog_final.py` | Ported TruffleHog detection patterns |

### AI Architecture

- **Provider abstraction**: Unified interface for Claude, GPT-4, Gemini, Azure OpenAI, and custom endpoints
- **Multi-model routing**: Different models can be assigned per task (triage, remediation, analysis)
- **Framework-aware prompts**: 12 frameworks with security-specific context
- **Confidence calibration**: Bayesian adjustment from user feedback loops
- **Groundedness validation**: Strips ungrounded evidence from AI output
- **Batch processing**: Groups similar findings for efficient token usage
- **Decision caching**: Caches AI decisions by stability ID to avoid re-processing unchanged code

## Database Models

The platform uses 37 PostgreSQL application tables organized by domain
(plus Alembic's `alembic_version`). All models use UUID primary keys with timestamp and tenant isolation mixins.

### Core / Auth (7 tables)

| Table | Model | Purpose |
|-------|-------|---------|
| `tenants` | Tenant | Multi-tenant organization isolation |
| `users` | User | User accounts with hashed passwords |
| `user_roles` | UserRole | Role assignments (admin, security_engineer, developer, viewer) |
| `role_definitions` | RoleDefinition | Custom role definitions with permission sets |
| `business_units` | BusinessUnit | Hierarchical organizational units |
| `user_access_grants` | UserAccessGrant | Scoped access (org, business unit, project) |
| `api_keys` | APIKey | CI/CD API key management |

### Repositories & Scanning (9 tables)

| Table | Model | Purpose |
|-------|-------|---------|
| `repositories` | Repository | Connected repositories (GitHub, GitLab, Bitbucket) |
| `repository_snapshots` | RepositorySnapshot | Point-in-time repo state captures |
| `scan_jobs` | ScanJob | Scan execution tracking with status and progress |
| `scan_artifacts` | ScanArtifact | Scan output artifacts and logs |
| `scan_sources` | ScanSource | Non-git scan targets (collaboration, docs, storage, DevOps) |
| `scan_phase_events` | ScanPhaseEvent | Per-phase progress events for live scan tracking |
| `file_scan_cache` | FileScanCache | Per-file content and rule-version cache for fast re-scans |
| `repo_branch_checkpoints` | RepoBranchCheckpoint | Per-branch watermarks for incremental scanning |
| `custom_detectors` | CustomDetector | User-authored regex detectors |

### Findings & Triage (10 tables)

| Table | Model | Purpose |
|-------|-------|---------|
| `imported_findings` | ImportedFinding | Raw findings from scanners (SARIF, Checkmarx, etc.) |
| `normalized_findings` | NormalizedFinding | Canonical finding model with AI classification, severity, CWE |
| `finding_evidence` | FindingEvidence | Code context and security pattern evidence |
| `finding_decisions` | FindingDecision | User triage decisions with audit trail |
| `finding_decision_cache` | FindingDecisionCache | AI/user decisions keyed by stability ID for cross-scan persistence |
| `suppression_rules` | SuppressionRule | Learned and manual suppression patterns |
| `saved_views` | SavedView | Custom filtered views of findings |
| `scanners` | Scanner | Scanner configuration and type registry |
| `secret_incidents` | SecretIncident | One row per unique credential per tenant — the primary triage entity, aggregating its occurrences |
| `rule_overrides` | RuleOverride | Per-repo or global muting of individual scanner rules |

### Remediation (4 tables)

| Table | Model | Purpose |
|-------|-------|---------|
| `remediation_plans` | RemediationPlan | AI-generated remediation strategies |
| `remediation_patches` | RemediationPatch | Generated code patches for secret removal |
| `review_feedback` | ReviewFeedback | User feedback on AI-generated patches |
| `credential_rotation_events` | CredentialRotationEvent | Rotation lifecycle events per credential |

### Audit (1 table)

| Table | Model | Purpose |
|-------|-------|---------|
| `audit_events` | AuditEvent | Full audit trail of all platform actions |

### Platform (6 tables)

| Table | Model | Purpose |
|-------|-------|---------|
| `integration_configs` | IntegrationConfig | Scanner, notification, and external tool configs |
| `ai_model_configs` | AIModelConfig | AI provider settings per model |
| `ai_engine_settings` | AIEngineSettings | Global AI behavior (context mode, batch size, thresholds) |
| `notifications` | Notification | Notification delivery records |
| `notification_rules` | NotificationRule | Conditional notification routing rules |
| `metric_snapshots` | MetricSnapshot | Time-series KPI snapshots for dashboard trending |

## API Router Structure

The API server mounts 28 routers, all versioned under `/api/v1/`,
exposing 199 endpoints:

```
/api/v1/
  auth/                  -- Login and current-user session
  repositories/          -- CRUD, scan triggers, scan history, stats
  scan-jobs/             -- Job status and phase events
  scan-sources/          -- Non-git scan targets and their scans
  findings/              -- Query, triage, assign, remediate, verify
  incidents/             -- Credential-level aggregation and bulk triage
  imports/               -- CLI/CI client-side findings ingest
  suppressions/          -- Suppression rules and learning
  rule-overrides/        -- Per-repo and global scanner-rule muting
  custom-detectors/      -- User-authored regex detectors
  saved-views/           -- Custom filtered views
  rotation-events/       -- Rotation queue and summary
  metrics/               -- Dashboard KPIs and trends
  reports/               -- Compliance reports and exports
  ai-models/             -- AI provider and model management
  integrations/          -- Notification, ticketing and scanner configs
  integrations/oauth/    -- Atlassian OAuth handshake
  notifications/         -- Notification delivery and rules
  webhooks/              -- Inbound push/PR webhook receivers
  push-protection/       -- Inline pre-commit secret blocking
  api-keys/              -- CI/CD API key management
  users/                 -- User CRUD and activation
  roles/                 -- Custom role definitions and permissions
  access/                -- Business units and access grants
  audit/                 -- Audit queries, stats, export, retention
  sso/                   -- SAML and OIDC configuration
  public/                -- Public scanner-rule catalogue
  ws/                    -- WebSocket (scan progress)
```

Additional endpoints:
- `GET /api/health` -- Health check
- `GET /api/about` -- Platform version and attribution
- `GET /api/docs` -- Swagger UI
- `GET /api/openapi.json` -- OpenAPI schema

## Frontend Architecture

### Technology

- **Framework**: Next.js 15 with App Router
- **UI**: React 19 with Tailwind CSS
- **State**: React hooks and context
- **HTTP client**: Fetch API with auth token injection
- **Real-time**: WebSocket for scan progress

### App Router Pages

```
apps/web/src/app/
  layout.tsx              -- Root layout with AppShell (sidebar + header)
  page.tsx                -- Root redirect
  login/                  -- Authentication page
  dashboard/              -- KPI dashboard
  repositories/           -- Repo list and detail ([id])
  sources/                -- Non-git scan sources, by category ([category])
  findings/               -- Finding list and detail ([id])
  incidents/              -- Incident detail ([id])
  secrets/                -- Secret detail ([id]) and analysis views
    heatmap/              -- Secret density visualization
    rotation/             -- Rotation queue and SLA tracking
    trends/               -- Temporal trend analysis
  scan-jobs/              -- Scan job detail ([id])
  integrations/           -- Integration hub
  settings/
    admin/                -- Admin panel (users, roles, org config)
  reports/                -- Report generation and export
  schedules/              -- Scan schedule management
  suppressions/           -- Suppression rule management
  allowlists/             -- Allowlist management
  webhooks/               -- Webhook configuration
  profile/                -- User profile
  about/                  -- Platform info
  docs/                   -- Embedded documentation
```

### Component Architecture

```
apps/web/src/components/
  layout/
    AppShell.tsx           -- Main layout with sidebar + header + content area
    Sidebar.tsx            -- 6-item navigation sidebar
    Header.tsx             -- Top bar with user menu and breadcrumbs
    SubNav.tsx             -- Section-level tab navigation
    AuthGuard.tsx          -- Client-side route protection
  ui/
    SearchableSelect.tsx   -- Filterable dropdown component
    Toast.tsx              -- Notification toasts
  repositories/
    AddRepositoryModal.tsx -- Repo connection wizard
    DefectTable.tsx        -- Finding table within repo context
  integrations/
    ScannerConnectModal.tsx    -- Scanner integration setup
    NotificationConnectModal.tsx -- Notification channel setup
    ScannerIcons.tsx           -- Scanner brand icons
  findings/
    FindingPanel.tsx       -- Finding detail slide-over panel
  governance/
  policies/
  secrets/
    SchedulesContent.tsx   -- Scan schedule management
    SuppressionsContent.tsx -- Suppression rule management
```

## Security

### Authentication

- **JWT tokens**: Short-lived access tokens with refresh token rotation
- **RBAC roles**: admin, security_engineer, developer, viewer
- **SSO**: SAML 2.0, OIDC with Okta, Azure AD, Google Workspace
- **API keys**: Prefixed (`vooda_...`) keys for CI/CD integration
- **Session management**: Redis-backed with configurable expiry

### Tenant Isolation

Every database model includes a `tenant_id` column enforced at the query layer. All API requests are scoped to the authenticated user's tenant, preventing cross-tenant data access.

### Encrypted Configuration

Vault connection strings and integration configs (ticketing, notification, and webhook credentials) are stored in encrypted JSONB columns. The encryption key is derived from the `SECRET_KEY` environment variable.

### Access Control

Three-tier access model:
1. **Organization** -- Full access to all business units and projects
2. **Business Unit** -- Access to all projects within a BU
3. **Project** -- Access to a single repository/project

Admin role users automatically receive organization-level access.
