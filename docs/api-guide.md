# Vooda AI -- API Reference

Complete REST API reference for the Vooda AI Security Engine.

---

## Overview

| Detail              | Value                                    |
|---------------------|------------------------------------------|
| Base URL            | `http://localhost:8000/api/v1`           |
| Interactive Docs    | `http://localhost:8000/api/docs`         |
| OpenAPI Spec        | `http://localhost:8000/api/openapi.json` |
| Auth                | Bearer token (JWT)                       |
| Content-Type        | `application/json`                       |

---

## Authentication

All endpoints (except `/api/v1/auth/login`, SSO callbacks, and push protection) require a JWT bearer token.

```
Authorization: Bearer <jwt_token>
```

Obtain a token via `POST /api/v1/auth/login`.

---

## Pagination

Paginated endpoints accept these query parameters:

| Parameter   | Type | Default | Description                |
|-------------|------|---------|----------------------------|
| `page`      | int  | 1       | Page number (1-indexed)    |
| `page_size` | int  | 50      | Items per page (max 200)   |

Response envelope:

```json
{
  "items": [],
  "total": 142,
  "page": 1,
  "page_size": 50,
  "total_pages": 3
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "detail": "Human-readable error message"
}
```

| Status | Meaning                              |
|--------|--------------------------------------|
| 400    | Bad request / validation error       |
| 401    | Invalid or missing credentials       |
| 403    | Insufficient permissions             |
| 404    | Resource not found                   |
| 422    | Unprocessable entity                 |
| 500    | Internal server error                |

---

## Rate Limiting

Default limits per tenant:

| Tier     | Limit          |
|----------|----------------|
| Standard | 60 req/min     |
| Burst    | 120 req/min    |
| Scan     | 10 concurrent  |

Rate limit headers are returned on every response:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 58
X-RateLimit-Reset: 1700000000
```

---

## Health & Info

| Method | Path           | Description                      | Auth |
|--------|----------------|----------------------------------|------|
| GET    | `/api/health`  | Health check                     | No   |
| GET    | `/api/about`   | Engine version and attribution   | No   |

## Endpoint Reference

> This reference is generated from the running service's OpenAPI schema
> (`GET /api/openapi.json`). The interactive Swagger UI at
> **`/api/docs`** is always the authoritative, up-to-date source — including
> request/response schemas for every endpoint below.

### Authentication

Prefix: `/api/v1/auth`

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/auth/change-password` | Change Password |
| POST | `/api/v1/auth/login` | Login |
| GET | `/api/v1/auth/me` | Get Me |

### Repositories

Prefix: `/api/v1/repositories`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/repositories` | List Repositories |
| POST | `/api/v1/repositories` | Create Repository |
| POST | `/api/v1/repositories/bulk-delete-preview` | Bulk Delete Preview |
| GET | `/api/v1/repositories/facets` | Get Repository Facets |
| POST | `/api/v1/repositories/probe` | Probe Repository |
| GET | `/api/v1/repositories/{repo_id}` | Get Repository |
| PUT | `/api/v1/repositories/{repo_id}` | Update Repository |
| DELETE | `/api/v1/repositories/{repo_id}` | Delete Repository |
| POST | `/api/v1/repositories/{repo_id}/archive` | Archive Repository |
| GET | `/api/v1/repositories/{repo_id}/branches` | Get Repository Branches |
| GET | `/api/v1/repositories/{repo_id}/delete-preview` | Get Delete Preview |
| POST | `/api/v1/repositories/{repo_id}/import/findings` | Import client-side (CLI/CI) Vooda findings for a repository |
| POST | `/api/v1/repositories/{repo_id}/scan` | Trigger Scan |
| PATCH | `/api/v1/repositories/{repo_id}/scan-config` | Update Scan Config |
| GET | `/api/v1/repositories/{repo_id}/scans` | List Scans |
| GET | `/api/v1/repositories/{repo_id}/scans/{scan_id}` | Get Scan Status |
| DELETE | `/api/v1/repositories/{repo_id}/scans/{scan_id}` | Delete Scan |
| POST | `/api/v1/repositories/{repo_id}/scans/{scan_id}/ai-triage` | Trigger Ai Triage Retro |
| POST | `/api/v1/repositories/{repo_id}/scans/{scan_id}/cancel` | Cancel Scan |
| GET | `/api/v1/repositories/{repo_id}/scans/{scan_id}/events` | Get Scan Events |
| GET | `/api/v1/repositories/{repo_id}/severity-trend` | Get Severity Trend |
| GET | `/api/v1/repositories/{repo_id}/stats` | Get Repository Stats |
| POST | `/api/v1/repositories/{repo_id}/unarchive` | Unarchive Repository |
| POST | `/api/v1/repositories/{repo_id}/upload` | Upload Repository |

### Scan Jobs

Prefix: `/api/v1/scan-jobs`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/scan-jobs/{scan_id}` | Get Scan Job |
| GET | `/api/v1/scan-jobs/{scan_id}/events` | Get Scan Job Events |
| GET | `/api/v1/scan-jobs/{scan_id}/events/export` | Export Scan Events |

### Inline / Push-Protection Scan

Prefix: `/api/v1/scan`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/scan/health` | Scan Health |
| POST | `/api/v1/scan/inline` | Inline Scan |

### Findings (Secrets)

Prefix: `/api/v1/findings`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/findings` | List Findings |
| POST | `/api/v1/findings/batch-remediate` | Batch Remediate Findings |
| POST | `/api/v1/findings/bulk-triage` | Bulk Triage Findings |
| GET | `/api/v1/findings/tags` | List Tags |
| GET | `/api/v1/findings/{finding_id}` | Get Finding |
| POST | `/api/v1/findings/{finding_id}/approve` | Approve Patch |
| POST | `/api/v1/findings/{finding_id}/assign` | Assign Finding |
| GET | `/api/v1/findings/{finding_id}/blast-radius` | Get Blast Radius |
| POST | `/api/v1/findings/{finding_id}/comment` | Add Comment |
| POST | `/api/v1/findings/{finding_id}/mark-false-positive` | Mark False Positive |
| POST | `/api/v1/findings/{finding_id}/remediate` | Request Remediation |
| POST | `/api/v1/findings/{finding_id}/tags` | Update Tags |
| POST | `/api/v1/findings/{finding_id}/triage` | Triage Finding |
| POST | `/api/v1/findings/{finding_id}/verify` | Verify Finding Credential |

### Incidents (Deduplicated Secrets)

Prefix: `/api/v1/incidents`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/incidents` | List Incidents |
| POST | `/api/v1/incidents/bulk-mark-rotated` | Bulk Mark Rotated |
| POST | `/api/v1/incidents/bulk-triage` | Bulk Triage Incidents |
| GET | `/api/v1/incidents/export/csv` | Export Incidents Csv |
| GET | `/api/v1/incidents/{incident_id}` | Get Incident |
| PATCH | `/api/v1/incidents/{incident_id}` | Patch Incident |
| GET | `/api/v1/incidents/{incident_id}/history` | Get Incident History |
| POST | `/api/v1/incidents/{incident_id}/verify` | Verify Incident Credential |

### Scan Sources

Prefix: `/api/v1/scan-sources`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/scan-sources` | List Scan Sources |
| POST | `/api/v1/scan-sources` | Create Scan Source |
| POST | `/api/v1/scan-sources/test-connection` | Test Unsaved Source Connection |
| GET | `/api/v1/scan-sources/types` | List Source Types |
| GET | `/api/v1/scan-sources/{source_id}` | Get Scan Source |
| PUT | `/api/v1/scan-sources/{source_id}` | Update Scan Source |
| DELETE | `/api/v1/scan-sources/{source_id}` | Delete Scan Source |
| GET | `/api/v1/scan-sources/{source_id}/delete-preview` | Get Source Delete Preview |
| POST | `/api/v1/scan-sources/{source_id}/scan` | Trigger Source Scan |
| GET | `/api/v1/scan-sources/{source_id}/scans` | List Source Scans |
| POST | `/api/v1/scan-sources/{source_id}/test` | Test Source Connection |

### Metrics

Prefix: `/api/v1/metrics`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/metrics/ai-accuracy` | Ai Accuracy Metrics |
| GET | `/api/v1/metrics/findings` | Findings Metrics |
| GET | `/api/v1/metrics/findings-breakdown` | Findings Breakdown |
| GET | `/api/v1/metrics/findings-by-category` | Findings By Category |
| GET | `/api/v1/metrics/mttr` | Mttr Metrics |
| GET | `/api/v1/metrics/overview` | Metrics Overview |
| GET | `/api/v1/metrics/remediation` | Remediation Metrics |
| GET | `/api/v1/metrics/scanner-comparison` | Scanner Comparison |
| GET | `/api/v1/metrics/top-leaking-repos` | Top Leaking Repos |
| GET | `/api/v1/metrics/trends` | Finding Trends |

### Reports & Exports

Prefix: `/api/v1/reports`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/reports/aging` | Vulnerability Aging |
| GET | `/api/v1/reports/compliance` | Compliance Report |
| GET | `/api/v1/reports/developer-activity` | Developer Activity |
| GET | `/api/v1/reports/developer-report` | Developer Remediation Report |
| GET | `/api/v1/reports/executive` | Executive Summary |
| GET | `/api/v1/reports/export/csv` | Export Csv |
| GET | `/api/v1/reports/export/json` | Export Json |
| GET | `/api/v1/reports/export/pdf` | Export Pdf |
| GET | `/api/v1/reports/export/sarif` | Export Sarif |
| GET | `/api/v1/reports/export/spdx` | Export Spdx |
| GET | `/api/v1/reports/fix-priority` | Fix Priority Report |
| GET | `/api/v1/reports/owasp` | Owasp Report |
| GET | `/api/v1/reports/release-readiness` | Release Readiness |
| GET | `/api/v1/reports/repo-risk` | Repository Risk Report |
| GET | `/api/v1/reports/security-debt` | Security Debt Report |
| GET | `/api/v1/reports/sla` | Sla Compliance |

### Rotation Events

Prefix: `/api/v1/rotation-events`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/rotation-events` | List Rotation Events |
| GET | `/api/v1/rotation-events/summary` | Rotation Summary |

### Integrations

Prefix: `/api/v1/integrations`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/integrations` | List Integrations |
| POST | `/api/v1/integrations` | Create Integration |
| POST | `/api/v1/integrations/jira/preview-issue-types` | Preview Jira Issue Types |
| POST | `/api/v1/integrations/jira/preview-projects` | Preview Jira Projects |
| GET | `/api/v1/integrations/oauth/atlassian/callback` | Atlassian Oauth Callback |
| POST | `/api/v1/integrations/oauth/atlassian/disconnect` | Disconnect Atlassian Oauth |
| POST | `/api/v1/integrations/oauth/atlassian/start` | Start Atlassian Oauth |
| GET | `/api/v1/integrations/providers` | List Providers |
| GET | `/api/v1/integrations/providers/{provider}` | Get Provider Schema |
| POST | `/api/v1/integrations/servicenow/preview-assignment-groups` | Preview Servicenow Assignment Groups |
| POST | `/api/v1/integrations/test` | Test Connection |
| POST | `/api/v1/integrations/test-ticketing` | Test Ticketing Connection |
| GET | `/api/v1/integrations/{integration_id}` | Get Integration |
| PUT | `/api/v1/integrations/{integration_id}` | Update Integration |
| DELETE | `/api/v1/integrations/{integration_id}` | Delete Integration |
| GET | `/api/v1/integrations/{integration_id}/jira-issue-types` | List Jira Issue Types |
| GET | `/api/v1/integrations/{integration_id}/jira-projects` | List Jira Projects |
| GET | `/api/v1/integrations/{integration_id}/servicenow-assignment-groups` | List Servicenow Assignment Groups |
| POST | `/api/v1/integrations/{integration_id}/test` | Test Saved Integration |

### AI Models

Prefix: `/api/v1/ai-models`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/ai-models` | List Models |
| POST | `/api/v1/ai-models` | Create Model |
| POST | `/api/v1/ai-models/auto-config` | Get Auto Configuration |
| POST | `/api/v1/ai-models/discover-models` | Discover Available Models |
| GET | `/api/v1/ai-models/engine-settings` | Get Engine Settings |
| PUT | `/api/v1/ai-models/engine-settings` | Update Engine Settings |
| GET | `/api/v1/ai-models/routing/tasks` | Get Task Routing |
| GET | `/api/v1/ai-models/status` | Ai Status |
| POST | `/api/v1/ai-models/test` | Test Model Connection |
| GET | `/api/v1/ai-models/{model_id}` | Get Model |
| PUT | `/api/v1/ai-models/{model_id}` | Update Model |
| DELETE | `/api/v1/ai-models/{model_id}` | Delete Model |

### Notifications

Prefix: `/api/v1/notifications`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/notifications` | List Notifications |
| POST | `/api/v1/notifications/read-all` | Mark All Read |
| GET | `/api/v1/notifications/rules` | List Notification Rules |
| PUT | `/api/v1/notifications/rules` | Update Notification Rules |
| GET | `/api/v1/notifications/unread-count` | Unread Count |
| POST | `/api/v1/notifications/{notification_id}/read` | Mark Read |

### Webhooks (Inbound)

Prefix: `/api/v1/webhooks`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/webhooks/config` | Get Webhook Config |
| POST | `/api/v1/webhooks/{provider}` | Receive Webhook |
| PUT | `/api/v1/webhooks/{provider}/config` | Update Webhook Config |
| POST | `/api/v1/webhooks/{provider}/test` | Test Webhook |

### Imports

Prefix: `/api/v1/imports`

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/imports/scan` | Import client-side (CLI/CI) Vooda findings (repo identified in body) |
| GET | `/api/v1/imports/scan/{scan_job_id}` | Status of an import job (readable by the same write-only key) |

### Custom Detectors

Prefix: `/api/v1/custom-detectors`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/custom-detectors` | List Custom Detectors |
| POST | `/api/v1/custom-detectors` | Create Custom Detector |
| GET | `/api/v1/custom-detectors/stats/summary` | Custom Detector Stats |
| POST | `/api/v1/custom-detectors/test-regex` | Test Regex |
| GET | `/api/v1/custom-detectors/{detector_id}` | Get Custom Detector |
| PUT | `/api/v1/custom-detectors/{detector_id}` | Update Custom Detector |
| DELETE | `/api/v1/custom-detectors/{detector_id}` | Delete Custom Detector |
| POST | `/api/v1/custom-detectors/{detector_id}/toggle` | Toggle Custom Detector |

### Rule Overrides

Prefix: `/api/v1/rule-overrides`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/rule-overrides` | List Rule Overrides |
| POST | `/api/v1/rule-overrides` | Create Rule Override |
| GET | `/api/v1/rule-overrides/available-rules` | List Available Rules |
| GET | `/api/v1/rule-overrides/stats` | Rule Override Stats |
| PATCH | `/api/v1/rule-overrides/{rule_id}` | Update Rule Override |
| DELETE | `/api/v1/rule-overrides/{rule_id}` | Delete Rule Override |

### Suppressions

Prefix: `/api/v1/suppressions`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/suppressions` | List Suppression Rules |
| POST | `/api/v1/suppressions` | Create Suppression Rule |
| POST | `/api/v1/suppressions/learn` | Trigger Learning |
| GET | `/api/v1/suppressions/stats` | Suppression Stats |
| PUT | `/api/v1/suppressions/{rule_id}` | Update Suppression Rule |
| DELETE | `/api/v1/suppressions/{rule_id}` | Delete Suppression Rule |

### Saved Views

Prefix: `/api/v1/saved-views`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/saved-views` | List Saved Views |
| POST | `/api/v1/saved-views` | Create Saved View |
| DELETE | `/api/v1/saved-views/{view_id}` | Delete Saved View |

### Users

Prefix: `/api/v1/users`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/users` | List Users |
| POST | `/api/v1/users` | Create User |
| GET | `/api/v1/users/{user_id}` | Get User |
| PUT | `/api/v1/users/{user_id}` | Update User |
| DELETE | `/api/v1/users/{user_id}` | Delete User |
| POST | `/api/v1/users/{user_id}/activate` | Activate User |

### Roles

Prefix: `/api/v1/roles`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/roles` | List Roles |
| POST | `/api/v1/roles` | Create Role |
| GET | `/api/v1/roles/permissions` | List Permissions |
| PUT | `/api/v1/roles/{role_id}` | Update Role |
| DELETE | `/api/v1/roles/{role_id}` | Delete Role |
| POST | `/api/v1/roles/{role_id}/reset` | Reset Builtin Role |

### Access Control

Prefix: `/api/v1/access`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/access/business-units` | List Business Units |
| POST | `/api/v1/access/business-units` | Create Business Unit |
| PUT | `/api/v1/access/business-units/{bu_id}` | Update Business Unit |
| DELETE | `/api/v1/access/business-units/{bu_id}` | Delete Business Unit |
| GET | `/api/v1/access/grants` | List Access Grants |
| POST | `/api/v1/access/grants` | Create Access Grant |
| DELETE | `/api/v1/access/grants/{grant_id}` | Delete Access Grant |
| GET | `/api/v1/access/my-access` | Get My Access |

### API Keys

Prefix: `/api/v1/api-keys`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/api-keys` | List Api Keys |
| POST | `/api/v1/api-keys` | Create Api Key |
| GET | `/api/v1/api-keys/scopes` | List Scopes |
| PATCH | `/api/v1/api-keys/{key_id}` | Update Api Key |
| DELETE | `/api/v1/api-keys/{key_id}` | Revoke Api Key |
| POST | `/api/v1/api-keys/{key_id}/rotate` | Rotate Api Key |
| GET | `/api/v1/api-keys/{key_id}/usage` | Api Key Usage |

### SSO & Identity

Prefix: `/api/v1/sso`

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/sso/configure` | Configure Sso |
| GET | `/api/v1/sso/oidc/authorize` | Oidc Authorize |
| GET | `/api/v1/sso/oidc/callback` | Oidc Callback |
| GET | `/api/v1/sso/providers` | List Sso Providers |
| POST | `/api/v1/sso/saml/acs` | Saml Acs |
| GET | `/api/v1/sso/saml/metadata` | Saml Metadata |

### Audit

Prefix: `/api/v1/audit`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/audit` | List Audit Events |
| POST | `/api/v1/audit/enforce-retention` | Enforce Retention |
| GET | `/api/v1/audit/export` | Export Audit Csv |
| GET | `/api/v1/audit/stats` | Audit Stats |

### Public Scanner Rules

Prefix: `/api/v1/public`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/public/scanner-rules` | List Public Scanner Rules |

## Endpoint Count

166 paths · 200 operations across 27 endpoint groups (live build).

---

## Common Examples

### Log in and get a token

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@vooda.ai","password":"<your-password>"}'
```

```json
{ "access_token": "eyJhbGc...", "token_type": "bearer" }
```

Send the token as `Authorization: Bearer <access_token>` on every subsequent call.

### Trigger a scan on a repository

```bash
curl -X POST http://localhost:8000/api/v1/repositories/<repo_id>/scan \
  -H "Authorization: Bearer $TOKEN"
```

Poll `GET /api/v1/repositories/<repo_id>/scans/<scan_id>` for status, or stream
progress over the WebSocket channel (`/api/v1/ws`).

### List critical findings

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/findings?severity=critical&page=1&page_size=50"
```

### Import findings from the CLI / CI

Client-side scans (the `vooda` CLI in a pipeline) push their results back to a
repository so they show up in the dashboard and triage queue:

```bash
curl -X POST http://localhost:8000/api/v1/repositories/<repo_id>/import/findings \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  --data @vooda-findings.json
```

---

## Notes

- Every endpoint except `POST /api/v1/auth/login`, the SSO callbacks, and the
  inbound webhook / push-protection routes requires a bearer token.
- List endpoints share the pagination envelope described above.
- The counts here reflect the current release; the live `/api/docs` always
  matches the running build exactly.
