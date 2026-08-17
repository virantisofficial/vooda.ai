# Jira Integration — Setup & Behavior

This document explains what's required to connect Vooda to Atlassian
Jira Cloud, what every field in the integration config means, how
tickets are created, and how to ensure tickets are attributed to a
**Vooda AI** identity rather than to a personal account — entirely
through Atlassian, with no additional steps in Vooda.

---

## 1. The single decision: which Atlassian account owns the API token?

Atlassian's REST API automatically stamps every issue Vooda creates
with two attribution fields:

- **Creator** — the account whose API token authenticated the
  request. Atlassian-enforced, cannot be overridden.
- **Reporter** — defaults to the same account as Creator.

Both fields display the **account's display name** on the Jira
board. Whatever name appears on those fields is set entirely by
Atlassian based on whose token Vooda is using. Vooda has zero
references to personal account names anywhere in its code (verified
across `.py`, `.ts`, `.tsx`, `.json`, `.md` — no matches).

**This means the Reporter on every Vooda-created ticket is decided
by which Atlassian account generates the API token. Nothing else.**

You have three choices, in order of operational hygiene:

| Option | Reporter shows | Pros | Cons |
|---|---|---|---|
| **A. Personal account** | `<your name>` | Zero setup, works in 2 minutes | Tickets look personally attributed; rotating off your personal token disrupts the integration |
| **B. Dedicated Vooda AI service account** ✅ recommended | `Vooda AI` | Clean attribution; clean rotation; clean audit trail | Costs one paid Atlassian Cloud seat (~$8/month at Standard) |
| **C. Atlassian Connect app account** | `<App name>` | Free; sandboxed permissions | Requires running an Atlassian Connect app — significant engineering |

The rest of this document walks through **Option B** end to end. It
is entirely Atlassian-side configuration; Vooda needs no additional
fields, no additional code, and no additional clicks beyond the
standard integration setup.

---

## 2. Setting up a Vooda AI service account in Atlassian (recommended)

### Step 2.1 — Create the user

> Requires an Atlassian Cloud workspace admin to perform.

1. Go to <https://admin.atlassian.com/> → **Directory** → **Managed
   accounts**
2. Click **Invite users**
3. Email: `vooda-ai@yourcompany.com` (a real mailbox, even if it
   forwards to a security team alias — Atlassian sends the
   confirmation there)
4. Display name: `Vooda AI`
5. Assign the user to the products that include Jira Cloud
6. Send the invite, complete sign-up via the confirmation email

The new user `Vooda AI` is now a regular member of your workspace.
This counts as one paid seat on Atlassian Cloud.

### Step 2.2 — Grant minimum project permissions

In every Jira project where you want Vooda to file findings:

1. Open **Project Settings → People**
2. Add **Vooda AI** with role **Member** (or a custom role with the
   permissions listed below)

Required Jira permissions in each target project:

- **Browse Projects**
- **Create Issues**
- **View Issues**
- **Add Comments** (used by future features; safe to grant now)

Do **not** grant workspace-admin or project-admin roles. Principle
of least privilege — if the API token ever leaks, blast radius is
limited to filing/reading issues in the projects you explicitly
allowed.

### Step 2.3 — Generate the API token

1. Sign into Atlassian as `Vooda AI` (the email you used in 2.1,
   then click through any first-time login flow)
2. Go to <https://id.atlassian.com/manage-profile/security/api-tokens>
3. **Create API token**
4. Label: `vooda-ai-prod` (or `vooda-ai-staging`, etc. — makes
   future rotation auditable)
5. Copy the token value. You can't see it again.

### Step 2.4 — Configure the integration in Vooda

Open Vooda → **Integrations → Ticketing → Jira** and fill in:

| Field | Value |
|---|---|
| **Site URL** | `https://yourcompany.atlassian.net` |
| **Account Email** | `vooda-ai@yourcompany.com` (the Vooda AI account's email) |
| **API Token** | The token from step 2.3 |
| **Project** | Auto-loaded after **Test Connection** — pick any project where Vooda AI has permissions |
| **Issue Type** | Auto-loaded from the chosen project's schema |

Click **Test Connection** — the green chip will display
`Authenticated as Vooda AI`, confirming the token belongs to the
service account, not to a person. Click **Connect** (or **Update**
if updating an existing config) to save.

That's it. Every Vooda-created ticket from now on will read:

```
Creator:  Vooda AI
Reporter: Vooda AI
```

No Reporter dropdowns, no override fields, no additional config in
Vooda. Atlassian fills the fields in automatically because it sees
the token belonging to the Vooda AI account.

---

## 3. What you need before you start

Before walking through section 2, confirm:

- [ ] You have an Atlassian Cloud workspace admin available (only
      needed for steps 2.1 + 2.2)
- [ ] A real mailbox you can use for `vooda-ai@yourcompany.com`
      (gets the Atlassian confirmation email)
- [ ] One paid Atlassian Cloud seat available (Standard plan = $8.15
      per user/month at the time of writing — check
      <https://www.atlassian.com/software/jira/pricing>)
- [ ] You know which Jira project(s) Vooda should file findings into

If any of these are blockers, fall back to **Option A** (personal
account) for now — the integration works identically; only the
display name on tickets differs.

---

## 4. Risk notes

The Atlassian-side approach has a few things to be aware of:

| Risk | Mitigation |
|---|---|
| **Atlassian seat cost** | Use the Standard plan's per-user pricing. One seat for all of Vooda's traffic across every project. |
| **Token has the same permissions as the user** | Don't grant Vooda AI workspace-admin. Grant only project-Member in the projects Vooda files into. Token leak = scoped blast radius. |
| **Account might be "cleaned up" by an HR script that thinks it's an inactive employee** | Mark the account clearly: display name `Vooda AI`, profile photo of the Vooda logo, profile bio explaining the role. Atlassian also lets admins flag accounts as "service" type in newer admin consoles. |
| **API token expires or gets revoked** | Atlassian Cloud tokens don't expire automatically, but admins can revoke them. Document who has access to the Vooda AI account so token rotation isn't blocked when someone leaves the org. |
| **Multi-workspace orgs** | If you run multiple Atlassian workspaces (e.g. one per product), each needs its own Vooda AI account + token, and a separate Vooda integration row pointed at it. |
| **Atlassian SSO / SCIM-managed identity** | Some orgs lock down user creation behind SSO. The Vooda AI account must be exempted from SSO requirements (admins can do this in the user's directory entry) so the account can sign in with email + password to manage tokens. |
| **Audit ambiguity — who created the token?** | Atlassian's token-creation audit log shows "Vooda AI created an API token at \<timestamp\>". Whoever signed into the Vooda AI account to create it is recorded only via the underlying Atlassian admin session (separate audit trail). Document the human operator in your runbook. |

None of these risks are unique to Vooda — they're the standard
shape of running a service account in any SaaS that uses per-user
API tokens. The same considerations apply to GitHub bot accounts,
ServiceNow integration users, etc.

---

## 5. What ends up on the Jira board

For every finding that survives the push rules (see section 6),
Vooda creates a ticket with:

**Summary** — `[Vooda AI] [SEVERITY] <secret_type> in <filename>:<line>`
e.g. `[Vooda AI] [CRITICAL] aws_access_key in config/secrets.yaml:42`

**Description** — full defect details:

- Severity, type, validation status, AI classification
- Detection rule, scanner name, CWE / CVE
- Repository name, file path, line range, branch, commit
- Detected value (masked, e.g. `AKIA••••••XYZA`)
- AI confidence percentage + AI explanation
- Code snippet (up to 1500 chars)
- Concrete remediation steps
- Back-link: `View in Vooda: <deep link>`

**Issue Type** — whatever you picked in **Issue Type**

**Priority** — derived from severity per **Priority Mapping**

**Labels** — `vooda-ai`, `secret-detection`, `<severity>`

**Reporter / Creator** — both set to the authenticating Atlassian
account. With Option B (recommended) this is `Vooda AI` on every
ticket.

---

## 6. Push rules

The **Push Rules** section of the integration controls _which_
findings file as tickets:

| Setting | Effect |
|---|---|
| **Trigger** | When a ticket is created. Choices: **On True Positive confirmation** (default — only AI-confirmed real findings), **On detection** (everything, before triage), **Manual only** (user clicks "Push" on a finding) |
| **Push Frequency** | Currently `Immediate` is the only honored mode; hourly/daily/weekly batching is roadmap |
| **Minimum Severity** | Findings below this floor never create tickets |
| **Priority Mapping** | How Vooda severity maps to the Jira `priority` field (default: `Critical → Highest`, `High → High`, `Medium → Medium`, `Low → Low`) |
| **Exclude from Ticketing** | Four checkboxes — findings matching any checked state are skipped. Defaults are all on. |

The **Exclude** rules silently skip findings; they don't error or
log per-finding noise. The dispatcher emits a per-channel summary
(`attempted=N succeeded=M`) at the end of each scan.

### Dedup

Vooda tags every successfully-ticketed finding with a marker like
`jira:VOOD-42` on the finding's `tags` field. On subsequent scans,
findings carrying this tag for the active provider are skipped, so
re-running a scan against unchanged code does not re-fire duplicate
tickets.

---

## 7. Troubleshooting

### "✗ Atlassian rejected the credentials"

The API token is wrong, expired, or doesn't belong to the email in
the **Account Email** field. Re-generate the token at
<https://id.atlassian.com/manage-profile/security/api-tokens> and
re-paste it. Make sure you signed into Atlassian as the Vooda AI
account before generating, not your personal account.

### "✗ Atlassian returned a non-JSON 200 response (SSO redirect…)"

Your Atlassian site is gated behind SSO and the basic-auth path is
disabled for the account. The Vooda AI account needs to be SSO-
exempted (admin can set this in the user's directory entry) so
its API token can authenticate over basic auth.

### "✗ Jira returned HTTP 404 for project VOOD"

The Vooda AI account can't see that project (permission gap) or the
project key is wrong. Confirm the project key in **Project Settings
→ Details** in Jira, and confirm the Vooda AI account has
**Browse Projects** + **Create Issues** in that project's people
list.

### "Test Connection succeeds but tickets aren't appearing"

Most common cause: the **Trigger** is set to `On True Positive
confirmation` (default), and the findings haven't been classified
as Likely / Confirmed True Positives yet. Either wait for AI
triage, change the trigger to `On detection`, or push manually
from the finding actions menu.

### "Re-running a scan creates new duplicate tickets"

Shouldn't happen — Vooda dedups on the `jira:<KEY>` tag. If you
deleted the underlying findings (e.g. via repo re-add), the dedup
state is gone and new tickets will be created. Don't delete
findings in bulk if you want dedup to hold.

### "Tickets still show my personal name"

You're using Option A (your personal account's API token). Walk
through section 2 to switch to a Vooda AI service account.

---

## 8. Security notes

- The API token is encrypted at rest using Fernet
  (`packages/common/encryption.py`) with the app's `SECRET_KEY`
- The token is **never** returned to the browser in plaintext —
  the integrations API masks all sensitive fields with `•`
  characters before returning the config to the UI
- Tokens are decrypted only at the moment Vooda needs to make an
  outbound call to Atlassian (see `_decrypted_config` in
  `apps/api/app/routers/integrations.py`)
- All Vooda → Atlassian calls go over HTTPS using `httpx.AsyncClient`
- No customer-identifying data is logged — Vooda code has zero
  references to specific customer / user names

---

## 9. Multiple Jira boards (multi-product teams)

A team running multiple products typically wants findings from
each product to land on that product's own Jira board, not all
piled into one place. Vooda supports this natively — configure
one Jira integration per board, and Vooda will route each
finding to whichever board(s) match its scope.

### How routing works

Each Jira integration carries a **Scope** that determines which
findings flow to it:

| Scope | Meaning |
|---|---|
| **Organization-wide** (default) | Catches every finding in the tenant. Use as a default "everything else" board. |
| **Business Unit** | Findings only flow here when their repository belongs to the chosen BU. |
| **Specific Repository** | Findings only flow here when they originate from the exact repository you select. |

Multiple boards can match a single finding. For example, with one
Org-wide board + one Repository-scoped board pointing at `api-server`,
findings from `api-server` will be ticketed on **both** boards
(once each). Use the scope intentionally — Org-wide + Repo-scoped
gives you a "global view + team-specific view" pattern; pure
Repo-scoped per repo gives you strict isolation with no global
catch-all.

### Setup walk-through (two boards, two products)

Suppose you have two products:

- **Product A** — repos `frontend`, `mobile`. Engineering team
  files on Jira project `ENG`.
- **Product B** — repos `api`, `worker`. Platform team files on
  Jira project `PLAT`.

You'll create **two Vooda Jira integrations**, both pointing at the
same Atlassian site but at different projects. Each uses its own
API token (so revoking one doesn't break the other) and is scoped
to the matching repositories.

#### Step 1 — Create two service accounts on Atlassian

Following section 2 above, create two Atlassian users:

- `vooda-ai-eng@yourcompany.com` (display name: `Vooda AI — Engineering`)
- `vooda-ai-plat@yourcompany.com` (display name: `Vooda AI — Platform`)

Grant each account **Member** on the corresponding Jira project
(`ENG` for the eng account, `PLAT` for the platform account).
Generate an API token under each account.

> Alternatively, use a single `Vooda AI` account with permissions
> on both projects + a single token. Both designs work; per-board
> tokens give cleaner audit + rotation semantics.

#### Step 2 — Configure the first board

In Vooda → **Integrations → Ticketing → Jira**, the panel now shows
a **Boards** section at the top. Click **+ Add Board** if no boards
exist yet, or click an existing chip to edit.

Fill in:

| Field | Engineering board |
|---|---|
| Board Name | `Engineering Board` |
| Scope | `Specific Repository` → pick `frontend` |
| Site URL | `https://yourcompany.atlassian.net` |
| Account Email | `vooda-ai-eng@yourcompany.com` |
| API Token | (token for the eng account) |
| Project | `ENG` (auto-loaded after Test Connection) |
| Issue Type | `Task` (auto-loaded from project schema) |

Click **Test Connection** → should show `Authenticated as Vooda AI
— Engineering`. Click **Add Board** to save.

Repeat for `mobile` (another board with the same Atlassian creds
but Scope = `mobile`). You'll end up with two Engineering-scoped
boards. If the team prefers one board per *team* rather than per
*repo*, set Scope to **Business Unit** instead and create a
business unit that contains both repos.

#### Step 3 — Configure the second board

Click **+ Add Board** again and set up the platform board:

| Field | Platform board |
|---|---|
| Board Name | `Platform Board` |
| Scope | `Business Unit` → pick `Platform Team` |
| Site URL | `https://yourcompany.atlassian.net` |
| Account Email | `vooda-ai-plat@yourcompany.com` |
| API Token | (token for the platform account) |
| Project | `PLAT` |
| Issue Type | (whatever the PLAT project uses) |

Save.

#### Step 4 — Verify routing

Run a scan against the `frontend` repo. You should see:

- ✓ One ticket on the `ENG` board (because `frontend` is the
  Engineering Board's scoped repo)
- ✗ Zero tickets on the `PLAT` board (correct — `frontend` doesn't
  belong to the Platform Team BU)

Run a scan against `api` (a Platform Team repo). You should see:

- ✗ Zero tickets on the `ENG` board
- ✓ One ticket on the `PLAT` board

Each board's chip in the Vooda UI shows its scope inline (e.g.
`ENG · Repo: frontend`, `PLAT · BU: Platform Team`) so you can
audit the routing at a glance.

### Adding an Org-wide catch-all (optional)

To guarantee no finding is silently lost (e.g. when a repo isn't
yet assigned to a BU), add a third board with **Organization-wide**
scope pointing at a generic project like `SECURITY`. Every finding
will land on this board too — providing a single source of truth
for the security team while the dev teams work off their scoped
boards.

### Push rules per board

Each board has its own push rules. Put a stricter `Minimum
Severity` on the Org-wide catch-all (e.g. Critical only) to avoid
flooding the security board with low-severity findings while the
team boards see everything. Or use the trigger and exclusions
independently — every board can opt into any combination.

### Limitations

- Today, **all push frequencies** must be `Immediate` (batching is
  roadmap)
- Boards can target the **same Atlassian project** with different
  scope — the dispatcher will create one ticket per matching
  board, so you'll see duplicates if two boards match the same
  finding and the same project. Audit your scopes.
- **No conflict resolution UI** — if two boards match the same
  finding, both fire. There's no "first-match-wins" or "this
  scope overrides that scope" resolution today.

---

## 10. Roadmap (not in this version)

These are explicit non-features today:

- **Bidirectional sync** — close findings in Vooda when the Jira
  ticket is moved to Done.
- **Comment passthrough** — when AI triage updates a finding, add
  a comment to the existing ticket instead of creating a new one.
- **Hourly / daily / weekly batching** — currently `Immediate` is
  the only honored push frequency.
- **First-match-wins routing** — today every matching board fires;
  some teams want a strict "narrowest scope wins, others skip".
