# Atlassian OAuth 2.0 (3LO) Setup

Vooda supports two ways to authenticate against Jira and Confluence:

1. **Basic Auth** — email + API token. Simple, but most enterprise security
   teams disallow long-lived static tokens.
2. **OAuth 2.0 (3LO)** — recommended. The customer registers an OAuth app
   in their own Atlassian Developer Console, then connects it to Vooda.
   Tokens are short-lived and refreshed automatically.

This doc walks through the OAuth path.

## 1. Register an OAuth 2.0 (3LO) app at Atlassian

1. Sign in at <https://developer.atlassian.com/console/myapps/>.
2. **Create app** → **OAuth 2.0 integration**.
3. Name it (e.g. "Vooda Secret Scanner").
4. Under **Permissions**, enable the APIs you need:
   - **Jira API** — required for Jira source scanning.
   - **Confluence API** — required for Confluence source scanning.
5. Under each enabled API, click **Add** and select the read scopes Vooda
   uses by default:

   | Use case | Scopes |
   |---|---|
   | Jira source scanning | `read:jira-work`, `read:jira-user`, `offline_access` |
   | Confluence source scanning | `read:confluence-content.all`, `read:confluence-user`, `offline_access` |

   `offline_access` is required for Vooda to refresh tokens without
   prompting the user every hour.

6. Under **Authorization**, set **Callback URL** to:

   ```
   https://<your-vooda-host>/api/v1/integrations/oauth/atlassian/callback
   ```

   For local development, this is `http://localhost:8001/api/v1/integrations/oauth/atlassian/callback`.

7. Copy the **Client ID** and **Client Secret** from the **Settings** tab.

## 2. Configure the IntegrationConfig in Vooda

The Jira / Confluence IntegrationConfig row's `config` JSONB now accepts
two new fields:

- `auth_type` — set to `"oauth2"`.
- `oauth_client_id` — from step 1.7.
- `oauth_client_secret` — from step 1.7. Encrypted at rest.
- `oauth_scope` (optional) — override the default scope list.

If you're using the API directly:

```bash
curl -X POST https://<host>/api/v1/integrations \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "jira",
    "name": "Acme Atlassian (OAuth)",
    "config": {
      "auth_type": "oauth2",
      "oauth_client_id": "abc123…",
      "oauth_client_secret": "xyz789…"
    }
  }'
```

The response includes the new `id`. Hold onto it.

## 3. Authorize

Vooda exposes two endpoints. Both require an authenticated Vooda user
(except the callback, which is hit by Atlassian's redirect):

| Method + path | Purpose |
|---|---|
| `POST /api/v1/integrations/oauth/atlassian/start?integration_id=<id>` | Returns the URL to redirect the user to. |
| `GET  /api/v1/integrations/oauth/atlassian/callback?code=…&state=…` | Atlassian's callback. Exchanges the code, persists tokens. |
| `POST /api/v1/integrations/oauth/atlassian/disconnect?integration_id=<id>` | Revokes stored tokens. Keeps the OAuth app credentials so reconnect doesn't re-enter them. |

Walk-through:

```bash
# 1. Start the flow
curl -X POST "https://<host>/api/v1/integrations/oauth/atlassian/start?integration_id=<id>" \
  -H "Authorization: Bearer <token>"
# {"authorize_url": "https://auth.atlassian.com/authorize?...", "redirect_uri": "..."}

# 2. Open authorize_url in a browser. The user clicks Approve.
# Atlassian redirects to /callback. Vooda finishes the exchange
# server-side, then redirects back to the FE Integrations page
# with ?status=success or ?status=error.

# 3. Verify tokens were stored:
curl "https://<host>/api/v1/integrations/<id>" \
  -H "Authorization: Bearer <token>" | jq '.config | {auth_type, cloud_id, site_url, has_access_token: (.oauth_access_token != null)}'
```

## 4. Use it for source scanning

Create a `ScanSource` of `source_type=jira` pointing at the OAuth
IntegrationConfig — no other change needed. The factory dispatches
automatically based on `auth_type`.

```bash
curl -X POST https://<host>/api/v1/scan-sources \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Jira (via OAuth)",
    "source_type": "jira",
    "integration_config_id": "<oauth integration id>",
    "scan_schedule": "daily",
    "config": {"include_attachments": true, "exclude_self_created": true},
    "target_repository_id": "<repo id>"
  }'
```

When the worker runs the scan, it calls
`refresh_atlassian_token_if_needed` before each scan. If the access
token is fresh, that's a single in-process check. If it's expired, one
upstream call to `auth.atlassian.com/oauth/token` mints a new pair.
The customer never sees re-prompts as long as `offline_access` was
granted.

## 5. Token rotation + revocation

- **Atlassian access tokens** expire after 1 hour. Vooda refreshes
  automatically on the next scan.
- **Atlassian refresh tokens** are long-lived but rotate when used.
  Vooda persists the rotated refresh token on each refresh.
- **To revoke**: hit `POST /oauth/atlassian/disconnect`. The OAuth app
  credentials remain so reconnecting is one click. To fully sever the
  connection, also revoke the app at
  <https://id.atlassian.com/manage-profile/security/connected-apps>.

## Security notes

- Client secrets and tokens are stored Fernet-encrypted at rest with
  the `enc:` prefix Vooda uses everywhere else.
- The `state` parameter in the OAuth flow is HMAC-SHA256-signed with
  the Vooda `SECRET_KEY` and includes a TTL (10 min) + tenant pin, so
  a code redeemed by one tenant cannot land on another tenant's row.
- Atlassian's OAuth app exists in the customer's own developer console
  — Vooda never has the client secret of a shared app. Each customer
  is fully isolated at the Atlassian layer.
