# Slack Integration — Setup & Behavior

This document explains what's required to connect Vooda to a Slack
workspace, what every field in the **Connect Slack** form means, what
the bot will and won't be able to read, and how to troubleshoot the
common failure modes.

> **Audience:** Slack workspace admins setting up Vooda for the first
> time. The setup is entirely Slack-side until step 5; Vooda needs no
> additional fields beyond the standard form.

---

## 1. What Vooda does with Slack

Vooda's Slack source adapter scans **message text, file
attachments, and code snippets** posted to channels for hardcoded
secrets — API keys, passwords, tokens, signed URLs, and the 880+
provider-specific patterns the secret-scan engine ships with.

Findings carry the message location (`slack://{channel_id}/{ts}`),
the channel name, the message author, and a deep link back to the
original Slack message so triagers can context-switch in one click.

### What Vooda reads
- **Public channel messages** — always, when the bot is a member
- **Private channel messages** — only when both:
  - The "Include private channels" toggle is on, AND
  - The bot has been invited to that specific private channel
- **File attachments** — only when "Scan file attachments" is on; we
  download text-like files (`.env`, `.json`, `.yaml`, `.log`, `.csv`,
  `.conf`, `.properties`, plain text) and scan their contents

### What Vooda **does not** read
- **DMs** between users (we don't request `im:read`)
- **Multi-party DMs** (we don't request `mpim:read`)
- **Voice / video / huddles**
- **Reactions, pins, or workflow steps** as standalone surfaces
  (reactions on scanned messages are visible by default with
  `channels:history` but Vooda doesn't index them separately)

---

## 2. The single decision: which Slack app issues the bot token?

Slack's API stamps every request Vooda makes with the bot identity
of the app that issued the token. Whatever the bot's display name is
in Slack will appear in the channel members list when the bot is
invited and in any future audit logs Slack admins inspect.

You have two choices:

| Option | Bot displays as | Pros | Cons |
|---|---|---|---|
| **A. Dedicated Vooda Secret Scanner app** ✅ recommended | `Vooda Secret Scanner` | Clear attribution; isolated scopes; easy to revoke | 5–10 min one-time setup |
| **B. Reuse an existing in-house app** | `<your bot's name>` | Zero new app to manage | Requires adding scopes to a production-critical app |

The rest of this document walks through **Option A** end to end.

---

## 3. Create the Slack app

### Step 3.1 — Open the Slack app dashboard

Navigate to **<https://api.slack.com/apps>** (must be signed in as a
workspace admin or someone the workspace allows to install apps).

### Step 3.2 — Create the app

1. Click **Create New App** → **From scratch**
2. **App Name:** `Vooda Secret Scanner`
3. **Pick a workspace:** select the workspace you want scanned
4. Click **Create App**

You're now on the app's **Basic Information** page.

---

## 4. Configure OAuth scopes

In the left sidebar, click **OAuth & Permissions**. Scroll to the
**Scopes** section, then under **Bot Token Scopes**, click **Add an
OAuth Scope** and add the scopes from the table below.

### Required scopes (always)

| Scope | What Vooda uses it for |
|---|---|
| `channels:read` | List public channels in the workspace |
| `channels:history` | Read messages in public channels the bot is a member of |
| `users:read` | Resolve message author user IDs to display names so findings show "posted by Jane" not "U0AR5MLCA81" |

### Optional scopes (only if you'll enable the matching toggle)

| Scope | Required when... |
|---|---|
| `groups:read` | "Include private channels" is on — needed to enumerate the bot's private channels |
| `groups:history` | "Include private channels" is on — needed to read messages in those channels |
| `files:read` | "Scan file attachments" is on — needed to download attachment content |

**Don't add scopes you don't plan to enable.** The principle of
least privilege applies: if you only scan public channels, Slack's
audit log will reflect that.

---

## 5. Install the app to your workspace

Same page (**OAuth & Permissions**), scroll to the top:

1. Click **Install to &lt;workspace name&gt;**
2. Slack shows the consent screen listing every scope you added —
   review and click **Allow**
3. After install, the page reloads with **OAuth Tokens for Your
   Workspace** at the top
4. Copy the **Bot User OAuth Token** — it starts with **`xoxb-`**

> ⚠️ **Token handling:** treat this token like a password. Vooda
> encrypts it at rest with Fernet (the same encryption every other
> credential here uses), but anyone with the raw value can call your
> Slack API as the bot.

If you ever need to rotate the token, the same page has a
**"Reinstall to Workspace"** button which generates a fresh `xoxb-`
value and invalidates the old one.

---

## 6. Invite the bot to channels

This step is critical and easy to forget. Slack's API only returns
message history for channels the bot is **a member of**. Without
invites, `conversations.list` returns the channel names but
`conversations.history` returns `not_in_channel` and the scan walks
zero messages.

For each channel you want scanned, run:

```
/invite @Vooda Secret Scanner
```

inside that channel.

### Bulk invite tip
For workspaces with hundreds of channels, an admin can use Slack's
[Slack CLI](https://api.slack.com/automation/cli) or write a small
script using the bot's User OAuth token:

```bash
TOK="xoxb-..."
curl -s "https://slack.com/api/conversations.invite" \
  -H "Authorization: Bearer $TOK" \
  -d "channel=C01234567" \
  -d "users=$BOT_USER_ID"
```

You can find `$BOT_USER_ID` by hitting `https://slack.com/api/auth.test`
with the bot token — the response includes `"user_id"`.

---

## 7. Connect the source in Vooda

In Vooda:

1. Navigate to **Sources** (left nav) → **Collaboration** → **Slack**
2. Fill in the form:

| Field | What to enter |
|---|---|
| **Name** | A friendly label — e.g. `Trivex Slack` (used on the source card and in scan logs) |
| **Schedule** | `On Demand`, `Hourly`, `Daily`, or `Weekly` (see §8) |
| **Bot User OAuth Token** | The `xoxb-...` value from step 5 |
| **Scope** | `Organization-wide`, `Business Unit`, or `Repository` (see §9) |
| **Channels to scan** | Comma-separated channel names (e.g. `#engineering, #devops`). Leave blank or enter `*` to scan every channel the bot has been added to |
| **Include private channels** | On = also scan private channels the bot is in. Off (default) = public only |
| **Scan file attachments** | On = download + scan text-like uploads (`.env`, `.json`, etc.). Off (default) = scan message text only |

3. Click **Test Connection** — should display `Connected to <workspace> as <bot name>` in green
4. Click **Connect**

---

## 8. Schedule

The schedule controls how often Vooda scans the source automatically:

| Option | Behavior |
|---|---|
| `On Demand` | No automatic scans. You trigger via **Scan now** button (or the API) |
| `Hourly` | Scans every hour |
| `Daily` | Scans once per 24h |
| `Weekly` | Scans once per 7 days |

Independently of this, Vooda runs a **weekly full sweep** on every
active source (regardless of schedule) to catch deletions and
watermark drift. See [Weekly Full Sweep](#weekly-full-sweep) below.

---

## 9. Scope binding

The **Scope** field decides where Slack findings appear in Vooda's
RBAC tree:

| Mode | Findings appear under | Use when |
|---|---|---|
| **Organization-wide** | The whole tenant (default) | Slack is a cross-cutting concern; everyone with the right role can triage |
| **Business Unit** | The selected BU (and inherits BU access controls) | One BU owns Slack triage |
| **Repository** | The selected repo (inherits the repo's ticketing destination) | You want Slack findings to file Jira tickets to the same board the repo's code findings file to |

Most teams start with **Organization-wide** and refine later.

---

## 10. First scan & what to expect

After clicking **Connect**, click **Scan now**. The card flashes
"Scanning…" while the worker:

1. Calls `auth.test` to confirm credentials (preflight, ~1s)
2. Calls `conversations.list` to enumerate visible channels
3. For each channel where `is_member=true`, calls
   `conversations.history` and walks every message
4. For each message, runs the scanner against the body
5. If "Scan file attachments" is on, downloads each text-like
   attachment under the size cap and scans it too

A typical first scan on a 50-channel workspace with the bot in 10
channels takes 30–90 seconds. Subsequent scans are **incremental**:
they only fetch messages newer than the previous scan's watermark,
so they finish in seconds.

### Expected finding distribution

In our experience, Slack typically yields:
- **0–2 findings per 1000 messages** in well-disciplined engineering
  channels
- **5–20 findings per 1000 messages** in incident-response channels
  where engineers paste credentials during firefights
- **High noise rate** in channels with bot-generated content
  (deploy logs, monitoring alerts) — these are usually `xoxb-`-style
  test tokens and will be auto-classified as test credentials by AI
  triage

---

## 11. Weekly full sweep <a name="weekly-full-sweep"></a>

In addition to whatever schedule you set above, Vooda runs a weekly
**full-sync sweep** for every active source. Why:

1. **Watermark drift recovery** — if Slack changes their API or our
   stored cursor becomes invalid, regular polling silently returns 0
   messages. The sweep ignores the watermark and re-walks everything
2. **Deletion detection** — when a Slack message containing a
   detected secret is deleted, the polling path can't detect it
   (Slack doesn't surface deletion events to polling consumers).
   The sweep marks the finding as `RESOLVED_ITEM_DELETED` so
   dashboards stop counting it
3. **First-scan recovery** — if the very first scan of a workspace
   was rate-limited halfway through, the sweep re-baselines the
   missing tail

The sweep is fully automatic. To force a sweep right now, the API
endpoint is `POST /api/v1/scan-sources/{id}/scan` with body
`{"config": {"force_full": true}}`.

---

## 12. Troubleshooting

### "Test Connection" returns `invalid_auth`

The token is wrong or the app was uninstalled. Re-check:

- Token starts with `xoxb-` (not `xoxa-` / `xoxe.xoxp-` / `xapp-`)
- App is still installed at <https://api.slack.com/apps>
- Workspace admin hasn't revoked the install

If unsure, click **"Reinstall to Workspace"** on the OAuth &
Permissions page to get a fresh token, then update the source via
the **Edit** button.

### "Test Connection" returns `missing_scope`

Slack rejects the API call because the bot doesn't have the scopes
Vooda is requesting for that specific endpoint:

- `channels:read` missing → Vooda can't list channels at all
- `channels:history` missing → Vooda lists channels but reads zero
  messages
- `users:read` missing → findings appear with raw user IDs
  (`U0AR5MLCA81`) instead of names

Add the missing scopes (§4), then **reinstall the app to the
workspace** — adding scopes alone doesn't grant them; the reinstall
forces Slack to re-issue the consent prompt.

### Scan completes with `items=0` and `findings=0`

Most common cause: **the bot is not in any channels**. Check:

- In Slack, go to any channel and run `/invite @Vooda Secret Scanner`
- Confirm with `/who` that the bot appears in the member list

After inviting to channels, click **Scan now** again in Vooda — the
worker will now find messages.

Less common causes:
- Channels you expect are private but **"Include private
  channels"** is off
- All workspace messages are recent (under 1 minute old) and the
  watermark hasn't advanced yet — try again in a minute

### The same finding appears multiple times

Each `(message_text, rule_id)` pair produces one finding. If the
same secret was pasted in 5 different messages, you'll see 5
findings — that's correct, since each lives at a different
`source_locator`. Vooda's findings list groups them under "X
locations" automatically; click to expand the group.

### Findings keep coming back after I delete the messages

Wait for the next weekly sweep (or trigger one manually with
`force_full: true`). The sweep marks findings whose source messages
no longer exist as `RESOLVED_ITEM_DELETED` and they drop off the
default findings view.

If a finding stays open after a sweep:
- The bot may not have been re-invited to a channel where the
  message lived (Slack returns `not_in_channel`, the sweep can't
  prove the message is gone)
- Verify by checking the message URL in the finding's `Open in
  Slack` deep link

### Rate limit errors in worker logs

Slack's Tier 3 rate limit (`conversations.history`) is ~50
req/minute. For workspaces with many channels Vooda may hit it on
the first scan. The adapter automatically backs off on `429`s and
the scan will complete; subsequent runs are faster because they
only fetch the diff.

If rate limits become persistent (visible in worker logs as
repeated `rate_limited` warnings), narrow the **Channels to scan**
filter to just the channels you actually need.

---

## 13. Security & data handling

| Concern | How Vooda handles it |
|---|---|
| Bot token storage | Encrypted at rest with Fernet (symmetric AES-128); never logged; redacted from API responses |
| Message body storage | The full message text is sent to the rule engine in memory only. The persisted finding stores the masked secret value (`xoxb****uVwX`) and a code snippet of the surrounding message context. The full original is fetched on-demand from Slack via the deep link |
| Bot identity | Always `Vooda Secret Scanner` (the app name you chose). Slack's audit log shows the bot's API calls under this identity |
| Tenant isolation | Each tenant's Slack source is bound to that tenant's `IntegrationConfig` row. Vooda never reads across tenant boundaries — the source-scan worker filters every query by `tenant_id` |
| Compliance | Vooda's workspace access is read-only. The bot has **no** scopes for `chat:write`, `files:write`, or any mutation. Slack workspace admins can confirm by inspecting the bot's installed scopes at any time |

---

## 14. Removing the integration

To remove Slack from Vooda:

1. Navigate to **Sources** → **Collaboration** → click the Slack
   source card
2. Click the **trash icon** (right-hand side of the action bar)
3. Confirm the styled deletion prompt — this cascades to:
   - All scan jobs that ran against this source
   - All findings detected from this source
   - The stored bot token (the linked `IntegrationConfig`)

To revoke the bot's access on the Slack side (recommended after
removal):

1. Go to <https://api.slack.com/apps> → your app
2. **Settings** → **Install App** → **Uninstall App**
3. Confirm — Slack invalidates the token immediately

---

## 15. Field reference (canonical names + their backend keys)

| UI label | Backend key | Type | Notes |
|---|---|---|---|
| Name | `name` | string | User-facing label only; not validated |
| Schedule | `scan_schedule` | enum | `on_demand` / `hourly` / `daily` / `weekly` |
| Bot User OAuth Token | `credentials.bot_token` | password | Must start with `xoxb-` |
| Channels to scan | `config.channels` | comma-separated | Channel names with or without `#` prefix; `*` or empty = all bot-member channels |
| Include private channels | `config.include_private` | boolean | Default: `false` |
| Scan file attachments | `config.include_files` | boolean | Default: `false` |
| Scope | `target_repository_id` / `target_business_unit_id` | UUID | One or the other; both null = organization-wide |

---

## 16. API examples (for CI / scripted setup)

### Test connection before saving

```bash
curl -X POST "$VOODA/api/v1/scan-sources/test-connection" \
  -H "Authorization: Bearer $VOODA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "source_type": "slack",
    "credentials": { "bot_token": "xoxb-…" },
    "config": { "channels": "#engineering, #devops" }
  }'
```

Response on success:
```json
{
  "status": "success",
  "message": "Connected to Trivex workspace as vooda_secret_scanner",
  "details": { "team": "Trivex", "user": "vooda_secret_scanner" }
}
```

### Create the source

```bash
# Step 1 — save credentials
INT=$(curl -s -X POST "$VOODA/api/v1/integrations" \
  -H "Authorization: Bearer $VOODA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"provider":"slack","name":"Trivex Slack credentials","config":{"bot_token":"xoxb-…"}}' \
  | jq -r '.id')

# Step 2 — create the scan source
curl -X POST "$VOODA/api/v1/scan-sources" \
  -H "Authorization: Bearer $VOODA_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"Trivex Slack\",
    \"source_type\": \"slack\",
    \"integration_config_id\": \"$INT\",
    \"scan_schedule\": \"daily\",
    \"config\": {
      \"channels\": \"#engineering, #incidents\",
      \"include_private\": false,
      \"include_files\": true
    }
  }"
```

### Trigger a scan

```bash
curl -X POST "$VOODA/api/v1/scan-sources/$SOURCE_ID/scan" \
  -H "Authorization: Bearer $VOODA_API_KEY"
```

### Force a full sweep (bypass watermark)

```bash
curl -X POST "$VOODA/api/v1/scan-sources/$SOURCE_ID/scan" \
  -H "Authorization: Bearer $VOODA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"config":{"force_full":true}}'
```

---

## 17. Related documentation

- **[Jira Integration](./jira-integration.md)** — for filing tickets
  from Slack findings
- **[OAuth Atlassian](./oauth-atlassian.md)** — if you also want to
  scan Atlassian sources
- **[API Guide](./api-guide.md)** — programmatic source / scan
  management
- **[Verifier Guarantees](./verifier-guarantees.md)** — what the
  inline credential validator does on Slack-derived findings

---

*Last updated: 2026-05-07. Reflects the post-2026-05-07 form
labels (`Bot User OAuth Token`, `Channels to scan`, etc.), the new
`/api/v1/scan-sources/test-connection` endpoint, the styled delete
confirmation, and the weekly full-sync sweep.*
