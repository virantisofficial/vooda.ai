"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect, useCallback, Suspense, type ReactNode } from "react";
import { useRouter, usePathname, useSearchParams } from "next/navigation";
import AppShell from "@/components/layout/AppShell";
import {
  getScanSources, getScanSourceTypes, createScanSource, deleteScanSource,
  triggerSourceScan, updateScanSource,
  createIntegration, updateIntegration, deleteIntegration, getIntegration,
  testUnsavedSourceConnection, testSourceConnection,
  getRepositories, getBusinessUnits, getScanSourceDeletePreview,
} from "@/lib/api";
import { useToast } from "@/components/ui/Toast";
import { Skeleton } from "@/components/ui/Skeleton";
import { IntegrationErrorCard, type IntegrationError } from "@/components/integrations/IntegrationErrorCard";
import DeleteConfirmModal, { type DeletePreview } from "@/components/ui/DeleteConfirmModal";
import { SourceDetailDrawer } from "@/components/sources/SourceDetailDrawer";
import { SideDrawer } from "@/components/ui/SideDrawer";

// ───────────────────────────────────────────────────────────────
//  SOURCES — single source of truth
// ───────────────────────────────────────────────────────────────
//
// Consolidates what used to live in three parallel dicts
// (SOURCE_META + SOURCE_TO_PROVIDER + CREDENTIAL_FIELDS). New
// source = one entry here, no other FE files to edit. Bug fix
// 2026-04-29 — three-dict drift was already a real risk and would
// have compounded as we add the Tier 1 enterprise sources
// (MS Teams, Azure Blob, GCS) per the source audit.
//
// `keywords` powers the search box — names users might type that
// don't match the label exactly (e.g. "aws" → s3, "atlassian" →
// jira/confluence).
type CredentialField = {
  key: string;
  label: string;
  type: string;
  placeholder?: string;
  hint?: string;
};

type SourceCategory =
  | "Collaboration"
  | "Docs & Wikis"
  | "Issue Tracking"
  | "Cloud Storage"
  | "DevOps"
  | "APIs"
  | "CRM & Support";

// Optional setup wizard for sources that have meaningful first-time
// setup beyond "paste an API token" — Microsoft Graph apps, Azure
// storage keys, etc. Each step is rendered in the drawer with a
// progress indicator + Back/Next; only the last step shows the
// credential form. Sources WITHOUT a wizard fall through to the
// flat-form rendering (Slack, Notion, Postman, etc.).
type SetupStep = {
  title: string;
  description: string;          // one-liner subtitle below the step number
  body: ReactNode;              // walkthrough copy + screenshots / lists
  externalLink?: { label: string; url: string };
};

type SourceDef = {
  id: string;
  label: string;
  category: SourceCategory;
  icon: string;       // 1-2 char glyph rendered inside the gradient circle
  gradient: string;   // Tailwind gradient classes
  provider: string;   // backend integration provider used to save credentials
  keywords: string[]; // search aliases beyond `label`
  fields: CredentialField[];
  wizard?: SetupStep[];   // optional; presence triggers stepper UI on connect
  // Tier-D demotion flag (added 2026-05-13): integrations that exist in
  // the codebase but are not surfaced in the default catalog because
  // enterprise demand is low / declining.  Existing customer instances
  // keep working — they're stored by `source_type` in `scan_sources`
  // and the API doesn't gate on this flag.  This only suppresses the
  // tile from new-instance creation flows.  To re-promote later, just
  // delete the flag.
  hidden?: boolean;
  // Source status:
  //   "live"    — fully functional, wizard creates a real source row
  //   "request" — visible in catalog but backend adapter not shipped.
  //               Click routes to a request-access form so we capture
  //               demand signal instead of letting users hit a 404.
  //   undefined → treated as "live" (matches all existing entries).
  // Industry pattern: GitGuardian + Aikido + Snyk all show similar
  // demand-capture tiles in their catalog for upcoming integrations
  // rather than hiding the surface entirely.  Avoids the "you don't
  // cover X" perception while staying honest about engineering state.
  status?: "live" | "request";
};

// ── Setup wizards ─────────────────────────────────────────────
// Walkthrough copy for sources where "paste this token" isn't enough.
// Microsoft Graph apps (Teams + OneDrive/SharePoint) and Azure Blob
// both have multi-step admin setup that procurement teams want to
// see guided. Wording aligned with current Azure portal navigation
// (entra.microsoft.com / portal.azure.com) so screenshots / step
// numbers match what the customer actually sees.

// One M365 wizard with per-source scopes — Teams + OneDrive both
// register the SAME Microsoft Entra app, just with different Graph
// scopes granted. The function lets us reuse 90% of the copy and
// surface the right scope list per source type.
const M365_WIZARD = (kind: "teams" | "onedrive" | "pages"): SetupStep[] => {
  const scopes = kind === "teams"
    ? [
        { name: "Channel.ReadBasic.All",   why: "Enumerate teams + channels" },
        { name: "ChannelMessage.Read.All", why: "Read message bodies + replies" },
      ]
    : kind === "onedrive"
    ? [
        { name: "Sites.Read.All",  why: "Enumerate SharePoint sites + drives" },
        { name: "Files.Read.All",  why: "Download text-like file content" },
      ]
    : [
        // SharePoint Pages — page bodies + list items only.  Sites.Read.All
        // alone is sufficient (no Files.Read.All needed since we're not
        // downloading drive items).  If the customer already has OneDrive
        // wired up, the same scope is already granted — no second consent.
        { name: "Sites.Read.All",  why: "Read SharePoint Pages + List items" },
      ];
  const surfaceLabel =
    kind === "teams" ? "Teams channel messages"
    : kind === "onedrive" ? "SharePoint files"
    : "SharePoint Pages + Lists";
  return [
    {
      title: "Register a Microsoft Entra app",
      description: "One-time setup in the customer's Microsoft 365 tenant",
      body: (
        <>
          <p className="text-xs text-slate-400">
            Vooda authenticates as a service principal in your Microsoft Entra
            tenant (formerly Azure Active Directory). This is the standard
            pattern for SaaS apps that read from Microsoft Graph — the same
            shape Datadog, GitGuardian, and Snyk use.
          </p>
          <ol className="list-decimal pl-5 mt-3 space-y-1.5 text-xs text-slate-300">
            <li>Open <strong>Microsoft Entra → App registrations</strong> using the button below.</li>
            <li>Click <strong>New registration</strong>.</li>
            <li>Name it <code className="text-[10px] px-1 py-0.5 rounded bg-white/[0.05]">Vooda Secret Scanner</code>.</li>
            <li>Supported account types: <strong>Single tenant</strong>.</li>
            <li>Leave the redirect URI blank (we use application permissions, not user-delegated).</li>
            <li>Click <strong>Register</strong>.</li>
          </ol>
          <p className="text-xs text-slate-400 mt-3">
            On the app's <strong>Overview</strong> page you'll see two GUIDs you'll
            need in step 3: <em>Application (client) ID</em> and <em>Directory
            (tenant) ID</em>. Keep that tab open.
          </p>
        </>
      ),
      externalLink: {
        label: "Open Microsoft Entra App registrations",
        url: "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
      },
    },
    {
      title: "Grant Microsoft Graph permissions",
      description: `Read-only access for ${surfaceLabel}`,
      body: (
        <>
          <p className="text-xs text-slate-400">
            Vooda needs read-only access to the surfaces it scans. Application
            permissions (not delegated) so the scan runs without a user
            session.
          </p>
          <ol className="list-decimal pl-5 mt-3 space-y-1.5 text-xs text-slate-300">
            <li>In your app, open <strong>API permissions → Add a permission</strong>.</li>
            <li>Choose <strong>Microsoft Graph → Application permissions</strong>.</li>
            <li>Check the boxes for the scopes below, then <strong>Add permissions</strong>.</li>
            <li>
              Click <strong>Grant admin consent for &lt;your tenant&gt;</strong> at the top.
              Without this step, Vooda's API calls will return 403.
            </li>
          </ol>
          <div className="mt-3 rounded-md border border-white/[0.08] divide-y divide-white/[0.04] overflow-hidden">
            {scopes.map(s => (
              <div key={s.name} className="flex items-center justify-between p-2.5 bg-white/[0.02]">
                <code className="text-[11px] text-purple-300">{s.name}</code>
                <span className="text-[10px] text-slate-500">{s.why}</span>
              </div>
            ))}
          </div>
          <p className="text-xs text-slate-500 mt-3">
            If you've already added the other M365 source (Teams ↔ OneDrive),
            just add the new scopes onto the same app — no second registration.
          </p>
        </>
      ),
      externalLink: {
        label: "Open API permissions",
        url: "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
      },
    },
    {
      title: "Create a client secret + connect",
      description: "Generate a secret value and paste credentials below",
      body: (
        <>
          <p className="text-xs text-slate-400">
            Last step. Generate a client secret on the app, then paste all three
            values below.
          </p>
          <ol className="list-decimal pl-5 mt-3 space-y-1.5 text-xs text-slate-300">
            <li>In your app, open <strong>Certificates &amp; secrets → New client secret</strong>.</li>
            <li>Set an expiration (max 24 months recommended).</li>
            <li>Click <strong>Add</strong>, then <strong>copy the Value</strong> immediately —
              Microsoft Entra won't show it again after you leave the page.</li>
          </ol>
          <p className="text-xs text-amber-300/80 mt-3">
            Vooda encrypts the client secret at rest with Fernet (the same
            encryption every other credential here uses).
          </p>
        </>
      ),
    },
  ];
};

const AZURE_BLOB_WIZARD: SetupStep[] = [
  {
    title: "Find your storage account",
    description: "The account where the blobs you want scanned live",
    body: (
      <>
        <p className="text-xs text-slate-400">
          Vooda authenticates with a storage account key — the simplest path
          and the one most teams already have. Microsoft Entra RBAC support
          is on the roadmap if your org disallows account keys.
        </p>
        <ol className="list-decimal pl-5 mt-3 space-y-1.5 text-xs text-slate-300">
          <li>Open <strong>Azure Portal → Storage accounts</strong>.</li>
          <li>Pick the account whose containers you want scanned.</li>
          <li>Note the account name (the first segment of any blob URL —
            <code className="text-[10px] px-1 py-0.5 rounded bg-white/[0.05]">https://&lt;name&gt;.blob.core.windows.net</code>).</li>
        </ol>
      </>
    ),
    externalLink: {
      label: "Open Storage accounts",
      url: "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Storage%2FStorageAccounts",
    },
  },
  {
    title: "Get an access key",
    description: "Read-only key with permission to list + read blobs",
    body: (
      <>
        <ol className="list-decimal pl-5 space-y-1.5 text-xs text-slate-300">
          <li>In your storage account, open <strong>Security + networking → Access keys</strong>.</li>
          <li>Click <strong>Show</strong> next to <em>key1</em> and copy the value.</li>
          <li>Use this key only for Vooda; rotate it on a schedule. We
            encrypt at rest and never log the value.</li>
        </ol>
        <p className="text-xs text-slate-500 mt-3">
          For a least-privilege setup, generate a delegated <strong>SAS token</strong>
          with read+list permission instead. SAS support lands in the next
          release; for today, account keys are required.
        </p>
      </>
    ),
  },
  {
    title: "Configure scope + connect",
    description: "Pick a container (or scan all of them) and paste the credentials below",
    body: (
      <p className="text-xs text-slate-400">
        Set <strong>Container</strong> to a single container name to limit the
        scope, or leave blank / use <code>*</code> to scan every container in
        the account. Use the <strong>Blob name prefix</strong> field if your
        secrets typically live under a known path (e.g. <code>configs/</code>).
      </p>
    ),
  },
];

// ── Google Cloud Storage wizard ─────────────────────────────────
// GCS is treated as **infrastructure**, not Workspace user data —
// so the auth path is S3-compatible HMAC keys (two strings) rather
// than the three-legged OAuth model used for Workspace integrations.
// Customers who know AWS S3 already know this shape; the only new
// thing is where in Cloud Console to generate the HMAC keys.
const GCS_WIZARD: SetupStep[] = [
  {
    title: "Pick or create a service account",
    description: "The identity Vooda's read access will be bound to",
    body: (
      <>
        <p className="text-xs text-slate-400">
          GCS HMAC keys are bound to a service account — same RBAC
          surface you'd use for any GCP infrastructure access.  We
          recommend creating a dedicated service account just for
          Vooda so its access can be revoked independently of any
          other automation.
        </p>
        <ol className="list-decimal pl-5 mt-3 space-y-1.5 text-xs text-slate-300">
          <li>Open <strong>IAM &amp; Admin → Service Accounts</strong> in
            your GCP project (button below).</li>
          <li>Click <strong>Create service account</strong>.</li>
          <li>Name it <code className="text-[10px] px-1 py-0.5 rounded bg-white/[0.05]">vooda-scanner</code>.</li>
          <li>On the <em>Grant access</em> step, add the role
            <code className="mx-1 text-[10px] px-1 py-0.5 rounded bg-white/[0.05]">Storage Object Viewer</code>
            scoped to your target bucket (or the project, if you
            want Vooda to see every bucket).</li>
          <li>Click <strong>Done</strong>.  No need to generate a JSON
            key — we're using HMAC, not service-account JSON.</li>
        </ol>
        <p className="text-[11px] text-amber-300/80 mt-3">
          Storage Object Viewer is read-only.  Vooda never writes to
          your buckets.
        </p>
      </>
    ),
    externalLink: {
      label: "Open IAM &amp; Admin → Service Accounts",
      url: "https://console.cloud.google.com/iam-admin/serviceaccounts",
    },
  },
  {
    title: "Generate HMAC keys",
    description: "Two strings the wizard pastes — same shape as AWS S3",
    body: (
      <>
        <p className="text-xs text-slate-400">
          HMAC keys give GCS an S3-compatible auth surface.  Vooda
          uses the same boto3 client that scans AWS S3, just pointed
          at <code>storage.googleapis.com</code>.  The two strings
          you'll generate here behave exactly like an AWS access key
          ID + secret access key.
        </p>
        <ol className="list-decimal pl-5 mt-3 space-y-1.5 text-xs text-slate-300">
          <li>Open <strong>Cloud Storage → Settings → Interoperability</strong>
            (button below).</li>
          <li>Under <em>Access keys for service accounts</em>, click
            <strong> Create a key for a service account</strong>.</li>
          <li>Pick the <code className="text-[10px] px-1 py-0.5 rounded bg-white/[0.05]">vooda-scanner</code>
            account you created in step 1, then <strong>Create key</strong>.</li>
          <li>GCP shows the <strong>Access key</strong> and
            <strong> Secret</strong> — copy both immediately.  The
            secret is shown once; you can rotate / re-issue if you
            lose it.</li>
        </ol>
        <p className="text-[11px] text-slate-500 mt-3">
          On the next step, paste these into the form below along
          with the bucket name.
        </p>
      </>
    ),
    externalLink: {
      label: "Open Cloud Storage → Settings → Interoperability",
      url: "https://console.cloud.google.com/storage/settings",
    },
  },
  {
    title: "Configure scope + connect",
    description: "Paste the HMAC keys + bucket name below",
    body: (
      <p className="text-xs text-slate-400">
        Set <strong>Bucket Name</strong> to the single bucket you
        want scanned.  Use the <strong>Object name prefix</strong>
        field if secrets typically live under a known path
        (e.g. <code>configs/</code>, <code>backups/</code>).  Vooda
        encrypts both HMAC strings at rest with Fernet — same
        encryption every other credential here uses.
      </p>
    ),
  },
];

// Enterprise-only source categories — excluded from the community edition.
// The backend rejects these source types too (see SCAN_SOURCE_TYPES); this
// keeps the UI in sync so neither the category cards nor their sources appear.
// Definitions stay in-tree for the enterprise build to re-enable.
const ENTERPRISE_ONLY_CATEGORIES: ReadonlySet<string> = new Set([
  "Collaboration",
  "Docs & Wikis",
]);

const ALL_SOURCES: SourceDef[] = [
  {
    id: "slack", label: "Slack", category: "Collaboration",
    icon: "#", gradient: "from-purple-600 to-pink-500",
    provider: "slack",
    keywords: ["chat", "messaging", "bot"],
    fields: [
      { key: "bot_token", label: "Bot User OAuth Token", type: "password", placeholder: "xoxb-...",
        hint: "From your Slack app's OAuth & Permissions page. Must start with xoxb- — User OAuth tokens (xoxp-) won't work." },
    ],
  },
  {
    id: "confluence", label: "Confluence", category: "Docs & Wikis",
    icon: "C", gradient: "from-blue-500 to-indigo-500",
    provider: "atlassian",
    keywords: ["atlassian", "wiki", "docs"],
    fields: [
      { key: "site_url", label: "Atlassian Cloud Workspace URL", type: "url", placeholder: "https://yourteam.atlassian.net",
        hint: "The base URL of your Atlassian Cloud instance — found in any Confluence page URL." },
      { key: "email", label: "Atlassian Account Email", type: "email", placeholder: "you@company.com",
        hint: "Email of the Atlassian account that issued the API token below." },
      { key: "api_token", label: "Atlassian API Token", type: "password",
        hint: "Create at id.atlassian.com → Security → Create and manage API tokens." },
    ],
  },
  {
    id: "jira", label: "Jira", category: "Issue Tracking",
    icon: "J", gradient: "from-blue-600 to-indigo-600",
    provider: "atlassian",
    keywords: ["atlassian", "tickets", "issues"],
    fields: [
      { key: "site_url", label: "Atlassian Cloud Workspace URL", type: "url", placeholder: "https://yourteam.atlassian.net",
        hint: "The base URL of your Atlassian Cloud instance — found in any Jira issue URL." },
      { key: "email", label: "Atlassian Account Email", type: "email", placeholder: "you@company.com",
        hint: "Email of the Atlassian account that issued the API token below." },
      { key: "api_token", label: "Atlassian API Token", type: "password",
        hint: "Create at id.atlassian.com → Security → Create and manage API tokens." },
    ],
  },
  {
    id: "s3", label: "Amazon S3", category: "Cloud Storage",
    icon: "S3", gradient: "from-orange-500 to-yellow-500",
    provider: "aws",
    keywords: ["aws", "bucket", "amazon"],
    fields: [
      { key: "access_key_id", label: "AWS Access Key ID", type: "text",
        hint: "20-character key starting with AKIA (long-lived) or ASIA (temporary STS)." },
      { key: "secret_access_key", label: "AWS Secret Access Key", type: "password",
        hint: "40-character secret paired with the Access Key ID above." },
      { key: "region", label: "AWS Region", type: "text", placeholder: "us-east-1",
        hint: "Region where the bucket lives — e.g. us-east-1, eu-west-2, ap-south-1." },
    ],
  },
  {
    // Single-image scanning is an ad-hoc dev workflow; the
    // recommended enterprise path is the Container Registry source
    // (added 2026-04-30) which iterates an entire registry. Both
    // surfaced here so customers who only need ad-hoc triage can
    // still use it.
    id: "docker_image", label: "Docker Image (single)", category: "DevOps",
    icon: "D", gradient: "from-blue-500 to-cyan-500",
    provider: "docker",
    keywords: ["container", "image", "single image"],
    // Tier-D demoted 2026-05-13: ad-hoc single-image scanning is a CI
    // step, not a managed source.  Container scanning belongs on the
    // CI plugin / registry path, not the source catalog.  Existing
    // instances keep working; just hidden from the default UI.
    hidden: true,
    fields: [
      { key: "username", label: "Registry Username", type: "text",
        hint: "Docker Hub or registry account that has pull permission for the image." },
      { key: "password", label: "Password or Access Token", type: "password",
        hint: "A personal access token is recommended over an account password — easier to scope and rotate." },
    ],
  },
  {
    id: "postman", label: "Postman", category: "APIs",
    icon: "P", gradient: "from-orange-500 to-red-500",
    provider: "postman",
    keywords: ["api", "collections", "environments"],
    fields: [
      { key: "api_key", label: "API Key", type: "password", placeholder: "PMAK-...",
        hint: "Postman API key starting with PMAK- (postman.com → Settings → API Keys)." },
    ],
    // Tier-D demoted 2026-05-13: C-tier surface, sole entry in the
    // "APIs" category.  Category removed entirely (catalog 7→5).
    // Code path stays; existing customer instances keep scanning.
    hidden: true,
  },
  {
    id: "cicd_logs", label: "CI/CD Logs", category: "DevOps",
    icon: "CI", gradient: "from-slate-500 to-slate-600",
    provider: "cicd",
    keywords: ["jenkins", "github actions", "gitlab ci", "circleci", "build", "pipeline"],
    fields: [
      { key: "token", label: "CI/CD Provider Token", type: "password",
        hint: "Jenkins API token, GitHub Actions personal access token, CircleCI personal API token, etc." },
      { key: "base_url", label: "Server URL (self-hosted only)", type: "url", placeholder: "https://jenkins.company.com",
        hint: "Required only for self-hosted CI servers (e.g. Jenkins). Leave blank for cloud providers like GitHub Actions or CircleCI." },
    ],
  },

  // ══════════════════════════════════════════════════════════════
  //  Enterprise additions (2026-04-30) — closes the M365, Azure,
  //  modern-DevSecOps coverage gaps vs peers.
  // ══════════════════════════════════════════════════════════════

  {
    id: "ms_teams", label: "Microsoft Teams", category: "Collaboration",
    icon: "T", gradient: "from-purple-500 to-blue-600",
    provider: "ms_graph",
    keywords: ["microsoft", "m365", "office", "teams", "chat"],
    fields: [
      { key: "tenant_id", label: "Microsoft Entra Tenant ID", type: "text",
        hint: "GUID from entra.microsoft.com → Overview (formerly Azure Active Directory)." },
      { key: "client_id", label: "Application (Client) ID", type: "text",
        hint: "GUID from your Microsoft Entra app registration's Overview page." },
      { key: "client_secret", label: "Client Secret Value", type: "password",
        hint: "Generated under Certificates & secrets → Client secrets. Copy the Value (not the Secret ID). Vooda encrypts at rest — note the expiry and re-add before it lapses." },
    ],
    wizard: M365_WIZARD("teams"),
  },
  {
    id: "azure_blob", label: "Azure Blob Storage", category: "Cloud Storage",
    icon: "AZ", gradient: "from-blue-700 to-cyan-500",
    provider: "azure",
    keywords: ["azure", "microsoft", "blob", "storage", "container"],
    fields: [
      { key: "account_name", label: "Storage Account Name", type: "text", placeholder: "mycorpstore",
        hint: "First segment of your blob URL: https://{account_name}.blob.core.windows.net" },
      { key: "account_key", label: "Storage Account Access Key", type: "password",
        hint: "From the storage account → Security + networking → Access keys (key1 or key2). Vooda encrypts at rest." },
    ],
    wizard: AZURE_BLOB_WIZARD,
  },
  {
    // Google Cloud Storage — flipped from request → live on 2026-05-14
    // with HMAC-key auth (S3-compatible).  Completes the hyperscaler
    // trio (S3 + Azure Blob + GCS) — matches Wiz, GitGuardian,
    // TruffleHog, Nightfall coverage.  Different from the now-removed
    // Workspace integrations because GCS is INFRASTRUCTURE (object
    // store for backups, deployment artifacts, Terraform state, ML
    // datasets) — auth is two-string HMAC, no service-account JSON,
    // no OAuth complexity.
    id: "gcs", label: "Google Cloud Storage", category: "Cloud Storage",
    icon: "GS", gradient: "from-blue-500 to-emerald-500",
    provider: "gcs",
    keywords: ["google", "gcp", "cloud", "storage", "bucket", "gcs", "hmac"],
    fields: [
      { key: "access_key_id", label: "GCS Access Key ID", type: "text",
        hint: "HMAC access key ID generated at Cloud Storage → Settings → Interoperability. Starts with `GOOG...`. Same shape as an AWS S3 access key." },
      { key: "secret_access_key", label: "GCS Secret Access Key", type: "password",
        hint: "HMAC secret paired with the access key above. Shown once at generation — copy immediately. Encrypted at rest in Vooda." },
    ],
    wizard: GCS_WIZARD,
  },
  {
    id: "notion", label: "Notion", category: "Docs & Wikis",
    // Brand is grayscale, but the original `from-slate-700 to-slate-500`
    // gradient was invisible on the dark canvas (#07091a) — the 2px
    // brand stripe at the top of the card had no visible contrast,
    // breaking the consistent visual identity the other sources had.
    // Lighter slate keeps the monochrome aesthetic but actually shows.
    icon: "N", gradient: "from-slate-300 to-slate-500",
    provider: "notion",
    keywords: ["wiki", "docs", "knowledge base", "runbook"],
    fields: [
      { key: "token", label: "Integration Token", type: "password", placeholder: "secret_...",
        hint: "Create at notion.so/my-integrations (Internal integration). Then share each page or database with the integration so the API can see it." },
    ],
  },
  {
    // SharePoint Pages — added to Docs & Wikis on 2026-05-14 as the
    // #3 alongside Confluence + Notion.  Matches GitGuardian's #3 in
    // this category.  Distinct from the existing OneDrive/SharePoint
    // source (which scans files in document libraries) — this scans
    // SharePoint Pages (wiki content) + Site List items.  Reuses the
    // same Microsoft Entra app registration as Teams + OneDrive, so
    // customers already on either don't need a second consent.
    id: "sharepoint_pages", label: "SharePoint Pages", category: "Docs & Wikis",
    icon: "SP", gradient: "from-blue-600 to-sky-500",
    provider: "ms_graph",
    keywords: ["sharepoint", "microsoft", "m365", "wiki", "pages", "site", "list"],
    fields: [
      { key: "tenant_id", label: "Microsoft Entra Tenant ID", type: "text",
        hint: "Same Entra tenant as Microsoft Teams / OneDrive. Reuses the same app registration if you already added Sites.Read.All." },
      { key: "client_id", label: "Application (Client) ID", type: "text",
        hint: "GUID from your Microsoft Entra app registration's Overview page." },
      { key: "client_secret", label: "Client Secret Value", type: "password",
        hint: "From Certificates & secrets → Client secrets → copy the Value column (not Secret ID). Vooda encrypts at rest." },
    ],
    wizard: M365_WIZARD("pages"),
  },
  {
    id: "servicenow", label: "ServiceNow", category: "Issue Tracking",
    icon: "SN", gradient: "from-emerald-600 to-teal-500",
    provider: "servicenow",
    keywords: ["snow", "itsm", "incident", "change request", "itil"],
    fields: [
      { key: "instance_url", label: "ServiceNow Instance URL", type: "url", placeholder: "https://yourinstance.service-now.com",
        hint: "Your ServiceNow instance base URL — visible in any ServiceNow page URL." },
      { key: "username", label: "Service Account Username", type: "text",
        hint: "Use a dedicated read-only service account, not a personal login." },
      { key: "password", label: "Service Account Password", type: "password",
        hint: "Password for the service account. Vooda encrypts at rest." },
    ],
  },
  {
    id: "container_registry", label: "Container Registry", category: "DevOps",
    icon: "CR", gradient: "from-indigo-600 to-blue-500",
    provider: "container_registry",
    keywords: ["docker", "registry", "ecr", "gcr", "harbor", "quay", "ghcr", "container"],
    fields: [
      { key: "registry_url", label: "Registry URL", type: "url", placeholder: "https://my-registry.example.com",
        hint: "AWS ECR: https://{acct}.dkr.ecr.{region}.amazonaws.com — Google GCR: https://gcr.io — Docker Hub: https://registry-1.docker.io" },
      { key: "username", label: "Registry Username", type: "text",
        hint: "For AWS ECR use `AWS`, for Google GCR use `oauth2accesstoken`. Otherwise your registry login." },
      { key: "password", label: "Password or Access Token", type: "password",
        hint: "Personal access token or registry-issued bearer token. Vooda treats it as opaque and encrypts at rest." },
    ],
  },

  // ══════════════════════════════════════════════════════════════
  //  Terraform State — broadest IaC applicability and highest leak
  //  rate (state files contain raw credentials by design). Shipped
  //  as a fully functional DevOps source in the community edition
  //  alongside CI/CD Logs and Container Registry.
  //
  //  Other DevOps surfaces (Kubernetes Secrets / ConfigMaps, Datadog
  //  and other log platforms) are enterprise-edition sources and are
  //  intentionally not exposed here.
  // ══════════════════════════════════════════════════════════════
  {
    id: "terraform_state", label: "Terraform State", category: "DevOps",
    icon: "TF", gradient: "from-purple-600 to-violet-500",
    provider: "terraform",
    keywords: ["terraform", "iac", "infrastructure", "state", "hashicorp", "opentofu", "tfstate"],
    fields: [
      { key: "state_url", label: "State URL", type: "url", placeholder: "https://.../terraform.tfstate",
        hint: "HTTPS URL that returns your raw state JSON — a Terraform HTTP backend address, a Terraform Cloud state-version download URL, or a presigned S3 / GCS / Azure Blob URL." },
      { key: "auth_token", label: "Auth token (optional)", type: "password",
        hint: "Bearer token if the URL requires auth (e.g. a Terraform Cloud API token from app.terraform.io → Settings → Tokens). Leave blank for presigned / unauthenticated URLs. Vooda encrypts it at rest." },
    ],
  },

  // ══════════════════════════════════════════════════════════════
  //  Top-7-categories expansion (2026-05-01) — adds the new
  //  "CRM & Support" category via Salesforce, plus breadth across
  //  Issue Tracking / Collaboration / Cloud Storage so all 7
  //  enterprise source categories have first-party coverage.
  // ══════════════════════════════════════════════════════════════

  {
    id: "salesforce", label: "Salesforce", category: "CRM & Support",
    icon: "SF", gradient: "from-cyan-500 to-blue-500",
    provider: "salesforce",
    keywords: ["sfdc", "crm", "cases", "knowledge", "chatter", "service cloud"],
    fields: [
      { key: "login_url", label: "Salesforce Login URL", type: "url", placeholder: "https://login.salesforce.com",
        hint: "Use https://login.salesforce.com for production orgs, https://test.salesforce.com for sandboxes." },
      { key: "client_id", label: "Connected App Consumer Key", type: "text",
        hint: "From Setup → App Manager → New Connected App. Enable OAuth with scopes: api + refresh_token." },
      { key: "client_secret", label: "Connected App Consumer Secret", type: "password",
        hint: "Generated alongside the Consumer Key. Vooda encrypts at rest." },
      { key: "username", label: "Integration User Email", type: "email",
        hint: "Use a dedicated read-only integration user, not a personal admin login." },
      { key: "password", label: "Password + Security Token (concatenated)", type: "password",
        hint: "Concatenate the user's password with their security token — no separator (e.g. `myPasswordABC123securityToken`). Reset the token at Personal Information → Reset My Security Token." },
    ],
    // Tier-D demoted 2026-05-13: C-tier surface, sole entry in the
    // "CRM & Support" category.  Category removed entirely (catalog
    // 7→5).  Code path stays for existing customer instances.
    hidden: true,
  },
  {
    id: "azure_devops", label: "Azure DevOps Boards", category: "Issue Tracking",
    icon: "AD", gradient: "from-blue-500 to-cyan-600",
    provider: "azure_devops",
    keywords: ["microsoft", "ado", "boards", "work items", "vsts"],
    fields: [
      { key: "organization", label: "Organization", type: "text", placeholder: "myorg",
        hint: "First path segment of your Azure DevOps URL: https://dev.azure.com/{organization}." },
      { key: "project", label: "Project", type: "text", placeholder: "MyProject",
        hint: "Second path segment after the organization." },
      { key: "pat", label: "Personal Access Token", type: "password",
        hint: "Generate at https://dev.azure.com/{org}/_usersSettings/tokens. Required scope: Work Items (Read)." },
    ],
  },
  {
    // ── Re-promoted to live 2026-05-14 ─────────────────────────
    // Mattermost is the natural #3 in Collaboration after dropping
    // Google Chat — matches GitGuardian's Tier-1 collaboration trio
    // (Slack + Teams + Mattermost).  Self-hosted Slack alternative
    // common in defense, finance, and other regulated enterprises
    // that can't put internal chat data in a SaaS chat product.
    // Code path was already present (just hidden); un-hiding makes
    // it discoverable in the catalog again.
    id: "mattermost", label: "Mattermost", category: "Collaboration",
    icon: "MM", gradient: "from-blue-500 to-indigo-600",
    provider: "mattermost",
    keywords: ["mattermost", "chat", "open source", "self-hosted"],
    fields: [
      { key: "site_url", label: "Mattermost Server URL", type: "url", placeholder: "https://chat.company.com",
        hint: "Base URL of your Mattermost server (typically self-hosted), e.g. https://chat.acme.com — no trailing slash, no team path." },
      { key: "token", label: "Bot Account Token", type: "password",
        hint: "Bot Account is the recommended path: System Console → Integrations → Bot Accounts → Add Bot Account → name it 'Vooda' → save → copy the access token. Add the bot to every team / channel you want scanned. Personal Access Tokens from a dedicated service user also work (Account Settings → Security → Personal Access Tokens) but bot accounts have cleaner lifecycle and audit trails." },
    ],
  },
];
const SOURCES: SourceDef[] = ALL_SOURCES.filter((s) => !ENTERPRISE_ONLY_CATEGORIES.has(s.category));

// Display order for category section headers — explicit so the
// page reads the same way every time, regardless of how SOURCES
// is ordered above.
// Display order for category section headers — explicit so the
// page reads the same way every time.
// On 2026-05-13 the catalog was tightened from 7 → 5 categories:
// "APIs" (sole entry Postman, hidden) and "CRM & Support" (sole
// entry Salesforce, hidden) were dropped — single-entry categories
// read as "incomplete" to buyers and have no peer recognition.
// Both Postman and Salesforce code paths remain intact for existing
// customer instances; the categories just don't render anymore.
const CATEGORY_ORDER: SourceCategory[] = [
  "Collaboration",
  "Docs & Wikis",
  "Issue Tracking",
  "Cloud Storage",
  "DevOps",
];

// Category-level metadata for the top-level grid. Mirrors the
// shape used on /integrations (icon + brand gradient + description)
// so the two pages share a consistent visual vocabulary. Each
// gradient is chosen to reflect the dominant providers in the
// category — purple/pink for chat, blue for docs/wikis, etc.
type CategoryMeta = {
  key: SourceCategory;
  label: string;
  description: string;
  color: string;        // Tailwind gradient classes
  icon: ReactNode;
};

const ALL_CATEGORIES: CategoryMeta[] = [
  {
    key: "Collaboration",
    label: "Collaboration",
    description: "Chat platforms where developers paste credentials in DMs and channels",
    color: "from-purple-600 to-pink-500",
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
          d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
      </svg>
    ),
  },
  {
    key: "Docs & Wikis",
    label: "Docs & Wikis",
    description: "Knowledge bases, runbooks, and onboarding pages — high-yield secret-leak surfaces",
    color: "from-sky-500 to-indigo-500",
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
          d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
      </svg>
    ),
  },
  {
    key: "Issue Tracking",
    label: "Issue Tracking",
    description: "Tickets and discussions — Jira, ServiceNow, Azure DevOps",
    color: "from-blue-500 to-indigo-500",
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
          d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
      </svg>
    ),
  },
  {
    key: "Cloud Storage",
    label: "Cloud Storage",
    description: "Object stores — Amazon S3, Azure Blob, Google Cloud Storage",
    color: "from-orange-500 to-yellow-500",
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
          d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
      </svg>
    ),
  },
  {
    key: "DevOps",
    label: "DevOps",
    description: "Container registries, CI/CD logs, single Docker images",
    color: "from-emerald-500 to-cyan-500",
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
          d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
      </svg>
    ),
  },
  // 2026-05-13: "APIs" (sole entry: Postman, hidden) and
  // "CRM & Support" (sole entry: Salesforce, hidden) category cards
  // removed from the catalog landing.  Both source-types still exist
  // in SOURCES with hidden=true so existing customer instances keep
  // working; this just drops the landing tiles + sub-catalog pages.
];
const CATEGORIES: CategoryMeta[] = ALL_CATEGORIES.filter((c) => !ENTERPRISE_ONLY_CATEGORIES.has(c.key));

// Stack-aware recommendation graph — given a connected source, the
// values are source types we should suggest the customer also wire
// up. Edges based on real-world co-adoption: M365 shops have both
// Teams + OneDrive, AWS shops have both S3 + ECR, Atlassian shops
// commonly pair Jira + Confluence, and so on. Each pair surfaces
// at most one tile per category in the FE; the rule loop below
// filters to "in current category" + "not already connected" before
// rendering, so this map can be aggressive without UI noise.
const RECOMMENDATION_GRAPH: Record<string, string[]> = {
  slack:               ["ms_teams", "mattermost"],
  ms_teams:            ["slack", "azure_devops"],
  mattermost:          ["slack"],
  jira:                ["confluence", "notion", "servicenow"],
  confluence:          ["jira", "notion"],
  notion:              ["confluence"],
  servicenow:          ["jira", "confluence", "salesforce"],
  azure_devops:        ["ms_teams", "azure_blob"],
  salesforce:          ["servicenow", "confluence"],
  s3:                  ["azure_blob", "gcs", "container_registry"],
  azure_blob:          ["s3", "gcs", "ms_teams", "azure_devops"],
  docker_image:        ["container_registry"],
  container_registry:  ["cicd_logs", "docker_image"],
  cicd_logs:           ["container_registry"],
  postman:             [],
};

// "Popular" defaults shown to a tenant with zero connected sources.
// Curated by category to stay valid for any drilldown the user lands
// on first. Adjust based on usage telemetry once we have it.
const POPULAR_DEFAULTS: Record<string, string[]> = {
  Collaboration: ["slack", "ms_teams"],
  "Docs & Wikis": ["confluence", "notion"],
  "Issue Tracking": ["jira", "servicenow"],
  "Cloud Storage": ["s3", "azure_blob"],
  DevOps: ["container_registry", "cicd_logs"],
};

// Brand icons — single-path SVGs from simpleicons.org. Each entry
// is the `d` attribute that goes inside a 24x24 viewBox. Renders
// in white over the source's brand gradient tile, matching how
// /integrations and modern enterprise app catalogs (Datadog,
// Vercel, GitGuardian) handle their integration grids.
//
// Sources without a registered brand icon fall through to the
// 1-2 char letter glyph in `src.icon` (current behaviour for
// non-branded surfaces like CI/CD logs / Container Registry
// where the abstract concept doesn't have a single brand mark).
const BRAND_ICONS: Record<string, string> = {
  slack: "M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z",
  ms_teams: "M20.625 8.127H14.25v8.246c0 1.847-1.5 3.347-3.347 3.347-1.847 0-3.347-1.5-3.347-3.347 0-.184.014-.366.045-.541H4.875A2.625 2.625 0 0 1 2.25 13.207V5.622A2.625 2.625 0 0 1 4.875 3h13.5A2.625 2.625 0 0 1 21 5.622v.008c0 .074-.003.148-.008.221.413.078.81.236 1.171.467.36.231.673.524.918.857.245.333.42.711.514 1.107.094.396.105.806.03 1.205v-.005a2.626 2.626 0 0 1-2.07 2.572c-.13.025-.262.04-.393.045L20.625 8.127ZM12.75 6.247v6.875c.21.121.412.255.604.401.5-.65 1.207-1.13 2.026-1.299V6.247h-2.63ZM18.375 18.376a2.875 2.875 0 1 1 0-5.751 2.875 2.875 0 0 1 0 5.751Z",
  mattermost: "M20.575 2.962L21.49 8.5l-3.553 1.43-2.451-7.518 5.089.55ZM12 0C5.373 0 0 5.373 0 12c0 6.628 5.373 12 12 12 6.628 0 12-5.372 12-12 0-1.673-.342-3.265-.96-4.71l-1.946.808c.524 1.225.806 2.564.806 3.972 0 5.514-4.486 10-10 10S2 17.514 2 12 6.486 2 12 2c2.523 0 4.825.937 6.586 2.482L19.96 2.41A11.937 11.937 0 0 0 12 0Z",
  confluence: "M.973 16.6c-.273.456-.578.997-.836 1.413a.84.84 0 0 0 .284 1.139l5.428 3.358a.846.846 0 0 0 1.171-.281c.216-.36.494-.83.795-1.328 2.131-3.516 4.275-3.083 8.142-1.245l5.379 2.566a.842.842 0 0 0 1.13-.42l2.585-5.844a.847.847 0 0 0-.42-1.108c-1.135-.534-3.4-1.604-5.435-2.59C16.83 8.667 10.851 8.91 6.92 13.5c-2.124 2.477-3.91 5.36-5.946 3.1Zm22.054-9.117c.273-.456.578-.998.836-1.414a.84.84 0 0 0-.284-1.139L18.151 1.572A.846.846 0 0 0 16.98 1.853c-.216.36-.494.83-.795 1.328-2.131 3.516-4.275 3.083-8.142 1.245L2.668 1.86a.842.842 0 0 0-1.13.42L-1.047 8.124a.847.847 0 0 0 .42 1.108c1.135.534 3.4 1.604 5.435 2.59C7.17 15.333 13.149 15.09 17.08 10.5c2.124-2.477 3.91-5.36 5.946-3.1Z",
  notion: "M4.459 4.208c.746.606 1.026.56 2.428.466l13.215-.793c.28 0 .047-.28-.046-.326L17.86 1.968c-.42-.326-.981-.7-2.055-.607L3.01 2.295c-.466.046-.56.28-.374.466zm.793 3.08v13.904c0 .747.373 1.027 1.214.98l14.523-.84c.841-.046.935-.56.935-1.167V6.354c0-.606-.233-.933-.748-.887l-15.177.887c-.56.047-.747.327-.747.933zm14.337.745c.093.42 0 .84-.42.888l-.7.14v10.264c-.608.327-1.168.514-1.635.514-.748 0-.935-.234-1.495-.933l-4.577-7.186v6.952L12.21 19s0 .84-1.168.84l-3.222.186c-.093-.186 0-.653.327-.746l.84-.233V9.854L7.822 9.76c-.094-.42.14-1.026.793-1.073l3.456-.233 4.764 7.279v-6.44l-1.215-.139c-.093-.514.28-.887.747-.933z",
  jira: "M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.005-1.005zm5.723-5.756H5.736a5.215 5.215 0 0 0 5.215 5.214h2.129v2.058a5.218 5.218 0 0 0 5.215 5.214V6.762a1.005 1.005 0 0 0-1.001-1.005zM23.013 0H11.455a5.215 5.215 0 0 0 5.215 5.215h2.129v2.057A5.215 5.215 0 0 0 24 12.483V1.005A1.005 1.005 0 0 0 23.013 0z",
  github_issues: "M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.4 3-.405 1.02.005 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12",
  servicenow: "M11.99 0C5.392 0 .005 5.387.005 11.985 0 18.583 5.392 23.97 11.99 23.97c6.598 0 11.985-5.387 11.985-11.985C23.975 5.387 18.588 0 11.99 0zM7.46 18.155a3.42 3.42 0 0 1-2.45-1.014 3.43 3.43 0 0 1-1.014-2.45 3.43 3.43 0 0 1 1.014-2.45 3.42 3.42 0 0 1 2.45-1.014 3.42 3.42 0 0 1 2.45 1.014 3.43 3.43 0 0 1 1.014 2.45 3.43 3.43 0 0 1-1.014 2.45 3.42 3.42 0 0 1-2.45 1.014zm9.085 0a3.42 3.42 0 0 1-2.45-1.014 3.43 3.43 0 0 1-1.014-2.45 3.43 3.43 0 0 1 1.014-2.45 3.42 3.42 0 0 1 2.45-1.014 3.42 3.42 0 0 1 2.45 1.014 3.43 3.43 0 0 1 1.014 2.45 3.43 3.43 0 0 1-1.014 2.45 3.42 3.42 0 0 1-2.45 1.014z",
  linear: "M.403 13.378A12.052 12.052 0 0 0 10.622 23.6L.403 13.378ZM.084 9.503l14.413 14.412a12.05 12.05 0 0 0 3.103-1.295L1.379 6.4A12.05 12.05 0 0 0 .084 9.503ZM2.797 4.249l16.954 16.955a12.083 12.083 0 0 0 2.232-2.232L4.748 1.802a12.083 12.083 0 0 0-2.232 2.231C2.516 4.034 2.797 4.249 2.797 4.249zm5.376-3.041L23.155 16.19a12.052 12.052 0 0 0-13.95-15.65 12.052 12.052 0 0 0-1.032.668Z",
  asana: "M18.7782 12.4332c-2.8995 0-5.2495 2.3508-5.2495 5.2495 0 2.8987 2.35 5.2496 5.2495 5.2496 2.8985 0 5.2497-2.3509 5.2497-5.2496 0-2.8987-2.3502-5.2495-5.2497-5.2495zm-13.5572 0C2.3208 12.4332 0 14.7841 0 17.6827c0 2.8987 2.3508 5.2496 5.2495 5.2496 2.8987 0 5.2493-2.3509 5.2493-5.2496 0-2.8987-2.3506-5.2495-5.2493-5.2495zm12.0319-6.7172c0 2.8983-2.3502 5.25-5.2493 5.25-2.8993 0-5.2495-2.3517-5.2495-5.25C6.7541 2.8175 9.1043.4666 12.0036.4666c2.8991 0 5.2493 2.351 5.2493 5.2494z",
  bitbucket: "M.778 1.213a.768.768 0 0 0-.768.892l3.263 19.81c.084.5.515.868 1.022.873H19.95a.772.772 0 0 0 .77-.646l3.27-20.03a.768.768 0 0 0-.768-.891zM14.52 15.53H9.522L8.17 8.466h7.561z",
  azure_devops: "M0 8.877L2.247 5.91l8.405-3.416V.022l7.37 5.393L2.966 8.338v8.225L0 15.707zm24-4.45v14.651l-5.753 4.9-9.303-3.057v3.056l-5.978-7.416 16.057 1.798V5.014z",
  salesforce: "M10.006 5.507c.78-.811 1.864-1.314 3.062-1.314 1.59 0 2.984.886 3.717 2.196.643-.286 1.343-.444 2.082-.444 2.834 0 5.133 2.32 5.133 5.184 0 2.86-2.299 5.184-5.133 5.184-.346 0-.683-.035-1.011-.1-.647 1.151-1.876 1.929-3.286 1.929-.59 0-1.149-.137-1.645-.378-.652 1.535-2.173 2.611-3.945 2.611-1.847 0-3.42-1.166-4.025-2.802a3.872 3.872 0 0 1-.804.084C2.196 17.657 0 15.444 0 12.717c0-1.829.985-3.426 2.456-4.293A4.42 4.42 0 0 1 2.092 6.65c0-2.45 1.99-4.435 4.443-4.435 1.44 0 2.717.683 3.524 1.74",
  s3: "M20.913 13.147l.12.085v4.557l-9 4.06v-4.589zm-17.826 0l8.88 4.113v4.589l-9-4.06V13.23zM12 6.667l8.7 4.027L12 14.59l-8.7-3.896 8.7-4.027zM12 .333L1.5 5.193v13.55L12 23.667l10.5-4.924V5.193L12 .333Z",
  onedrive_sharepoint: "M12.066 6.026a6.4 6.4 0 0 1 3.616 1.111c.7.456 1.297 1.044 1.789 1.713a8.74 8.74 0 0 1 3.05.42 5.86 5.86 0 0 1 3.21 2.748 5.66 5.66 0 0 1 .241 4.752c-.532 1.27-1.534 2.32-2.799 2.92a6.06 6.06 0 0 1-2.583.578H7.13a4.85 4.85 0 0 1-2.812-.948 4.59 4.59 0 0 1-1.711-2.45 4.36 4.36 0 0 1 .183-2.929 4.71 4.71 0 0 1 1.96-2.205 4.94 4.94 0 0 1 1.79-.612A6.4 6.4 0 0 1 8.05 9.43a6.59 6.59 0 0 1 4.016-3.404Z",
  azure_blob: "M5.483 21.3h17.243c.703 0 1.135-.77.769-1.371L13.8 3.176a1.18 1.18 0 0 0-2.022.04l-3.34 5.825 4.55 8.06-8.39-.16a.49.49 0 0 0-.418.749l1.303 2.092a1.41 1.41 0 0 0 1.196.667zM6.434 14.94L1.077 18.84a.55.55 0 0 0 .323.99h6.4a.55.55 0 0 0 .468-.85l-1.834-4.04z",
  // Google Cloud Storage (simpleicons.org "googlecloud") — the geometric
  // four-segment Google Cloud mark.  Renders mono on the gradient just
  // like the rest of the brand icons.
  gcs: "M12.19 2.38a9.344 9.344 0 0 0-9.234 6.893c.053-.02-.055.013 0 0-3.875 2.551-3.922 8.11-.247 10.941l.006-.007-.007.03a6.717 6.717 0 0 0 4.077 1.356h5.173l.03.002h5.192a6.961 6.961 0 0 0 7.123-6.92 6.962 6.962 0 0 0-3.769-6.117l-.246-.13-.05-.273A9.55 9.55 0 0 0 12.19 2.38zm-.077 6.92 1.857 1.856a.247.247 0 0 1 0 .35l-.526.527a.246.246 0 0 1-.35 0L9.5 8.46Z",
  box: "M4.286 0A4.288 4.288 0 0 0 0 4.286v15.428A4.288 4.288 0 0 0 4.286 24h15.428A4.288 4.288 0 0 0 24 19.714V4.286A4.288 4.288 0 0 0 19.714 0zm6.142 6c1.286 0 2.572.715 2.857 1.857h.286c.572-1.142 1.572-1.857 2.857-1.857 2.286 0 4.143 1.857 4.143 4.143v3.571c0 2.286-1.857 4.143-4.143 4.143-1.286 0-2.286-.572-2.857-1.572V16h-.286c-.428 1-1.428 1.857-2.857 1.857-2.286 0-4.143-1.857-4.143-4.143v-3.571C6.286 7.857 8.143 6 10.428 6Z",
  postman: "M13.5417 11.5583c-.0292.0083-.0583.025-.0833.0417-.025.0292-.0417.0625-.0417.1042 0 .0917.075.1583.1542.1417.0875-.0167.1417-.1083.1208-.1958-.0167-.0708-.075-.1208-.15-.1208-.0125 0-.025 0-.0167.0292zM12 0C5.3729 0 0 5.3729 0 12c0 6.6271 5.3729 12 12 12s12-5.3729 12-12C24 5.3729 18.6271 0 12 0zm5.6042 8.6458a3.475 3.475 0 0 1 1.0625 2.5042c0 1.7458-1.4167 3.1583-3.1583 3.1583a3.475 3.475 0 0 1-2.5042-1.0625l-2.7958 2.7958-1.0083-1.0125 2.7958-2.7917a3.475 3.475 0 0 1-1.0625-2.5042c0-1.7417 1.4125-3.1583 3.1583-3.1583a3.475 3.475 0 0 1 2.5042 1.0625l2.7958-2.7958 1.0083 1.0125-2.7958 2.7917z",
  docker: "M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m-2.954-5.43h2.118a.186.186 0 00.186-.186V3.574a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m0 2.716h2.118a.187.187 0 00.186-.186V6.29a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.186m-2.93 0h2.12a.186.186 0 00.184-.186V6.29a.185.185 0 00-.185-.185H8.1a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.186m-2.964 0h2.119a.186.186 0 00.185-.186V6.29a.185.185 0 00-.185-.185H5.136a.186.186 0 00-.186.185v1.888c0 .102.084.185.186.186m5.893 2.715h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m-2.93 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.083.185.185.185m-2.964 0h2.119a.185.185 0 00.185-.185V9.006a.185.185 0 00-.184-.186h-2.12a.186.186 0 00-.186.186v1.887c0 .102.084.185.186.185m-2.92 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.082.185.185.185M23.763 9.89c-.065-.051-.672-.51-1.954-.51-.338.001-.676.03-1.01.087-.248-1.7-1.653-2.53-1.716-2.566l-.344-.199-.226.327c-.284.438-.49.922-.612 1.43-.23.97-.09 1.882.403 2.661-.595.332-1.55.413-1.744.42H.751a.751.751 0 00-.75.748 11.376 11.376 0 00.692 4.062c.545 1.428 1.355 2.48 2.41 3.124 1.18.723 3.1 1.137 5.275 1.137.983.003 1.963-.086 2.93-.266a12.248 12.248 0 003.823-1.389c.98-.567 1.86-1.288 2.61-2.136 1.252-1.418 1.998-2.997 2.553-4.4h.221c1.372 0 2.215-.549 2.68-1.009.309-.293.55-.65.707-1.046l.098-.288Z",
  container_registry: "M12 1.608l11.11 5.196v10.392L12 22.392.89 17.196V6.804L12 1.608zm0 1.892L2.93 7.5 12 11.5l9.07-4-9.07-4zm-9.07 5.5v6L11 18.07v-6L2.93 9zm18.14 0L13 12.07v6l8.07-3.07v-6z",
  cicd_logs: "M3 3h18v3H3V3zm0 5h18v3H3V8zm0 5h18v3H3v-3zm0 5h18v3H3v-3z",
  linear_alt: "M.403 13.378A12.052 12.052 0 0 0 10.622 23.6Z",
};

// Lookups derived from the array — the rest of the page reads
// from these helpers, never from the array directly. Keeps the
// "single source of truth" promise.
const SOURCE_BY_ID: Record<string, SourceDef> = Object.fromEntries(SOURCES.map((s) => [s.id, s]));
const fallbackSource: SourceDef = {
  id: "_unknown",
  label: "Unknown",
  category: "DevOps",
  icon: "?",
  gradient: "from-slate-500 to-slate-600",
  provider: "unknown",
  keywords: [],
  fields: [],
};
const lookupSource = (id: string): SourceDef => SOURCE_BY_ID[id] || fallbackSource;

// Render the source's brand icon: simpleicons.org SVG path when we
// have one registered in BRAND_ICONS, falling back to the 1-2 char
// glyph from src.icon for sources that don't have a single brand
// mark (CI/CD logs, Container Registry, the abstract concepts).
function BrandGlyph({ src, className = "w-5 h-5" }: { src: SourceDef; className?: string }) {
  const path = BRAND_ICONS[src.id];
  if (path) {
    return (
      <svg
        className={className}
        viewBox="0 0 24 24"
        fill="currentColor"
        aria-hidden="true"
      >
        <path d={path} />
      </svg>
    );
  }
  return <span className="text-xs font-bold">{src.icon}</span>;
}

interface RecentScan {
  id: string;
  status: string;            // "pending" | "running" | "completed" | "failed" | …
  findings_total: number;
  created_at: string | null;
  error: string | null;
}

interface ScanSource {
  id: string; name: string; source_type: string; is_active: boolean;
  scan_schedule: string; config: Record<string, any>;
  last_scan_at: string | null; stats: Record<string, any>; created_at: string;
  target_repository_id: string | null;
  target_business_unit_id: string | null;
  // FK to the encrypted credentials row (IntegrationConfig). Used by
  // the Edit panel's credentials editor to PUT /integrations/{id}
  // when the user rotates a token. Bug fix 2026-05-08.
  integration_config_id?: string;
  recent_scans?: RecentScan[];   // last 5 scan summaries; embedded by GET /scan-sources
  // Server-computed staleness signal (see _compute_is_stale in
  // apps/api/app/routers/scan_sources.py).  True when the source is
  // active + on a recurring schedule + hasn't scanned within 2× the
  // expected interval.  Drives the amber "needs attention" pip on
  // cards and the matching filter chip.
  is_stale?: boolean;
}

interface RepoOption { id: string; name: string }
interface BUOption { id: string; name: string }

// Source-scope binding modes. "organization" = findings stay org-
// wide (current default behaviour, NULL on both target_* columns).
// "business_unit" / "repository" = findings get bound to the picked
// scope so per-repo features (ticketing destination, BU access
// grants, dashboards) all apply to source findings too. Bug fix /
// feature 2026-04-29.
type ScopeMode = "organization" | "business_unit" | "repository";

// "5m ago" / "2h ago" / "3d ago" / "Apr 14" style — short, dense,
// keeps connected-source cards from drifting in width because the
// timestamp string is bounded.
function timeAgo(iso?: string | null): string {
  if (!iso) return "Never scanned";
  const t = new Date(iso).getTime();
  if (!t) return "—";
  const diff = Date.now() - t;
  const min = 60_000, hr = 60 * min, day = 24 * hr;
  if (diff < min) return "Just now";
  if (diff < hr) return `${Math.floor(diff / min)}m ago`;
  if (diff < day) return `${Math.floor(diff / hr)}h ago`;
  if (diff < 7 * day) return `${Math.floor(diff / day)}d ago`;
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/** Mapping between the route segment in /sources/[category] and the
 *  internal SourceCategory union. Lowercase, hyphenated forms are
 *  what we expose in URLs (so `/sources/cloud-storage` works) — they
 *  map back to the human-readable label used in state. Bug fix
 *  2026-05-08: previously `/sources/collaboration` 404'd because the
 *  page had no dynamic route; now the dynamic route forwards the
 *  segment as `initialCategory` to this component, and we keep the
 *  URL in sync via history.replaceState as the user navigates. */
const URL_TO_CATEGORY: Record<string, SourceCategory | "_connected"> = {
  "collaboration": "Collaboration",
  "docs-wikis": "Docs & Wikis",
  "issue-tracking": "Issue Tracking",
  "cloud-storage": "Cloud Storage",
  "devops": "DevOps",
  "apis": "APIs",
  "crm-support": "CRM & Support",
  "connected": "_connected",
};
const CATEGORY_TO_URL: Record<string, string> = Object.fromEntries(
  Object.entries(URL_TO_CATEGORY).map(([k, v]) => [v, k])
);

// Inner component reads `useSearchParams()`.  Next.js 15 requires
// any `useSearchParams` consumer to be wrapped in `<Suspense>` so
// SSR can suspend on the bailout boundary while the client hydrates.
// The default export below provides that wrapper.
function SourcesPageInner({ initialCategory }: { initialCategory?: string } = {}) {
  const [sources, setSources] = useState<ScanSource[]>([]);
  const [typeSchemas, setTypeSchemas] = useState<Record<string, any>>({});
  const [loading, setLoading] = useState(true);
  const [configuring, setConfiguring] = useState<string | null>(null); // source_type being configured
  const [scanning, setScanning] = useState<Record<string, boolean>>({});
  const { toast } = useToast();

  // Form state
  const [formName, setFormName] = useState("");
  const [formSchedule, setFormSchedule] = useState("on_demand");
  const [formCreds, setFormCreds] = useState<Record<string, string>>({});
  const [formConfig, setFormConfig] = useState<Record<string, any>>({});
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  // testResult holds the full structured error envelope returned by
  // /api/v1/scan-sources/test-connection — the legacy {status,message}
  // fields are still present (back-compat) plus the new title/summary/
  // fix_steps/details shape used by IntegrationErrorCard.
  const [testResult, setTestResult] = useState<({ status: string; message: string } & Partial<IntegrationError>) | null>(null);

  // Scope picker — bind this source's findings to a Repository or
  // Business Unit so per-repo / per-BU features apply (ticketing
  // destination, access grants, dashboards). Default is org-wide,
  // matching the original behaviour for backward compat.
  const [formScopeMode, setFormScopeMode] = useState<ScopeMode>("organization");
  const [formTargetRepoId, setFormTargetRepoId] = useState<string>("");
  const [formTargetBuId, setFormTargetBuId] = useState<string>("");

  // Edit mode for an already-connected source (lets the user
  // re-bind scope without disconnecting and recreating).
  const [editingSourceId, setEditingSourceId] = useState<string | null>(null);
  // Pending delete target — when non-null, the styled confirmation
  // modal renders. Replaces the previous native ``confirm()`` dialog
  // which was inaccessible to screen readers + browser automation
  // (the modal blocks the Chrome MCP tool until dismissed).
  const [deleteTarget, setDeleteTarget] = useState<ScanSource | null>(null);
  const [deleting, setDeleting] = useState(false);
  // Impact-preview payload for the shared DeleteConfirmModal.  Loaded
  // when the user opens the modal; carries finding / incident counts
  // so the destructive-action surface mirrors what will actually be
  // destroyed.  Pairs with the same state shape on /repositories so
  // the modal renders identically across both scopes.
  const [deletePreview, setDeletePreview] = useState<DeletePreview | null>(null);
  const [deletePreviewError, setDeletePreviewError] = useState<string | null>(null);

  // ── "Save anyway?" confirmation when Test Connection failed ──
  // If the user explicitly ran Test Connection and it returned an
  // error, asking the user "are you sure?" before saving avoids
  // the footgun of green "Source Connected" toasts on broken
  // configs. Keyed on the most recent test result — if the user
  // hasn't tested at all (testResult null), we save without
  // asking; not testing is opt-in, but ignoring a known failure
  // requires intent. Bug fix 2026-05-08.
  const [confirmSaveDespiteFailedTest, setConfirmSaveDespiteFailedTest] = useState(false);

  // Repos / BUs for the picker. Loaded once on mount — small enough
  // for an org that a single fetch is fine; if customer orgs grow
  // past a few hundred repos we'd switch to a typeahead.
  const [repoOptions, setRepoOptions] = useState<RepoOption[]>([]);
  const [buOptions, setBuOptions] = useState<BUOption[]>([]);

  // ── Discovery: status filter only ────────────────────────────
  // Search bar was removed (per user feedback: catalog has ~15 sources
  // per category, list is short enough that filtering by typing adds
  // no real discovery value over scanning the cards).
  // Added 2026-04-29 ahead of the Tier 1 source additions
  // (MS Teams / Azure Blob / GCS). At 8 sources today the flat
  // grid was fine; the audit flagged it would break around 16+.
  // Status filter narrows to "connected" / "not_connected" / "all".
  const [statusFilter, setStatusFilter] = useState<"all" | "connected" | "not_connected">("all");
  // Request-access state: when the user clicks a `status: "request"`
  // tile (Google Chat at time of writing), we open a small form
  // instead of the connect wizard.  Captures the source id + an
  // optional use-case note; submit fires a POST to a lightweight
  // demand-signal endpoint (or falls through to a mailto if the
  // backend route isn't wired yet — see handleRequestAccess below).
  const [requestAccessFor, setRequestAccessFor] = useState<string | null>(null);
  const [requestAccessUseCase, setRequestAccessUseCase] = useState("");
  const [requestAccessSubmitting, setRequestAccessSubmitting] = useState(false);

  // Active vs Archived view for the Connected flat list — same UX
  // contract as the repos page toggle.  "active" hides archived
  // instances; "archived" surfaces only them so the user can review or
  // unarchive.  Catalog/category views are discovery surfaces and
  // intentionally render both regardless of this toggle (paused
  // instances still show with the slate "Archived" status pill there).
  const [archiveView, setArchiveView] = useState<"active" | "archived">("active");

  // Detail drawer state — opens when a user clicks the body of a
  // Source card OR clicks Edit (which lands on the Settings tab).
  // Replaces the prior "open the connect-aside in edit mode" path so
  // the user never sees a second drawer appear when they click Edit.
  const [detailSource, setDetailSource] = useState<ScanSource | null>(null);
  // Which tab the drawer lands on.  Card body click → "overview"; Edit
  // button → "settings".  Resets to "overview" when the drawer closes.
  const [initialDetailTab, setInitialDetailTab] = useState<
    "overview" | "scans" | "settings" | "rule_overrides"
  >("overview");

  // Filter chip set on the Connected view — narrows the flat list to
  // sources matching the chosen status.  "all" is the default; the
  // other values match the corresponding badge on the card itself so
  // the filter UX reads as "show only the ones with this badge".
  // Lives at the page level so the chip state survives across the
  // active/archived toggle (same filtering surface for both).
  const [attentionFilter, setAttentionFilter] = useState<"all" | "stale" | "failed">("all");
  const [typeFilter, setTypeFilter] = useState<string>("");

  // Top-level navigation: null = category grid, "_connected" = the
  // "All connected" view, otherwise a real category key. Mirrors
  // the /integrations drilldown pattern so the two pages share the
  // same shape and the user only ever sees one focused view.
  // Seed from the deep-link route segment if provided. The Next.js
  // dynamic route at /sources/[category] passes `initialCategory`
  // here; without a segment we land on the catalog (null).
  const [activeCategory, setActiveCategory] = useState<SourceCategory | "_connected" | null>(() => {
    if (!initialCategory) return null;
    return URL_TO_CATEGORY[initialCategory.toLowerCase()] ?? null;
  });

  // ── Two-way URL sync ──
  //
  // The category drilldown view is reachable two ways:
  //   1) Direct URL hit / browser back → `initialCategory` is set via
  //      the dynamic `/sources/[category]` route, which seeds the
  //      initial `activeCategory` state on mount.
  //   2) User clicks a category card → `setActiveCategory(...)` is
  //      called; we mirror the change into the URL bar via Next.js
  //      router so the breadcrumb stays in sync AND the URL is
  //      bookmarkable.
  //
  // Previously this synced via `window.history.replaceState` +
  // `dispatchEvent('popstate')` to avoid a Next.js route change.
  // That worked for category-card clicks but broke breadcrumb
  // back-clicks — Next router push didn't reliably refresh the
  // shell's `usePathname`, so the header breadcrumb stayed stale
  // ("Sources › Collaboration" after URL was already at /sources).
  //
  // The clean fix: use `router.replace(target, { scroll: false })`.
  // This routes through Next's app router so `usePathname` (and any
  // consumer) sees the new path instantly.  The cost is a remount of
  // SourcesPage when the category segment changes — acceptable here
  // because the page's data fetch (sources list, business units) is
  // light and runs once per mount.
  const nextRouter = useRouter();
  const currentPathname = usePathname();
  const searchParams = useSearchParams();
  // Optional ?type=<source_id> query param — used by the Connected
  // pseudo-category view to narrow the flat list to just the
  // instances of a particular source type.  Set when the user clicks
  // the "View all N →" link on a multi-instance type card.
  const connectedTypeFilter = searchParams?.get("type") || "";

  // (A) state → URL: when activeCategory changes, push the URL.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const slug = activeCategory ? CATEGORY_TO_URL[activeCategory] ?? "" : "";
    const target = slug ? `/sources/${slug}` : "/sources";
    if (window.location.pathname !== target) {
      nextRouter.replace(target + window.location.search + window.location.hash, { scroll: false });
    }
  }, [activeCategory, nextRouter]);

  // (B) URL → state: when the user navigates externally (breadcrumb
  // click, browser back/forward), the active category MUST match
  // whatever the URL says.  Without this, a stale `activeCategory`
  // from before the navigation would keep the drilldown view
  // rendered even though the URL is now /sources.
  useEffect(() => {
    if (!currentPathname) return;
    if (!currentPathname.startsWith("/sources")) return;
    const segments = currentPathname.split("/").filter(Boolean);
    const slug = segments[1] || "";
    const urlCategory = slug ? URL_TO_CATEGORY[slug.toLowerCase()] ?? null : null;
    setActiveCategory(urlCategory);
  }, [currentPathname]);

  // Setup-wizard step index for sources whose SourceDef carries a
  // `wizard` array (M365 + Azure Blob today). 0 = first step. Reset
  // to 0 on openConfig; advanced via Next / dropped to the form on
  // the last step. Sources without a wizard ignore this.
  const [wizardStep, setWizardStep] = useState(0);

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([
      getScanSources({ page_size: 100 }),
      getScanSourceTypes(),
    ]).then(([sourcesRes, typesRes]) => {
      setSources(sourcesRes.data?.items || []);
      setTypeSchemas(typesRes.data || {});
    }).catch(() => {}).finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  // Live-refresh while any source has an in-flight scan.  Polls the
  // source list every 5s until every source's most-recent scan has
  // settled (completed / failed / cancelled).  Idle when nothing is
  // running — no wasted requests on a quiet page.
  //
  // This is what stops the "I clicked Scan but nothing seems to be
  // happening" UX hole: the card's activity dots + the Scan-now
  // button's busy state both derive from recent_scans[0].status,
  // which only updates on a load().  Without polling, the user
  // would have to manually refresh to see scan progress.
  useEffect(() => {
    const anyInFlight = sources.some((s) => {
      const st = (s.recent_scans?.[0]?.status || "").toLowerCase();
      return st === "pending" || st === "running";
    });
    if (!anyInFlight) return;
    const interval = setInterval(() => {
      load();
    }, 5000);
    return () => clearInterval(interval);
  }, [sources, load]);

  // Esc closes the drawer. Fired against the window so it works
  // wherever focus is — input, button, or the body.
  useEffect(() => {
    if (!configuring) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setConfiguring(null);
        setEditingSourceId(null);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [configuring]);

  // Load repos + BUs once for the scope picker. Failures are
  // non-fatal — the user just sees an empty dropdown and the form
  // falls back to "Organization-wide" (the default scope).
  useEffect(() => {
    getRepositories({ page_size: 200 })
      .then((r) => {
        const items = r.data?.items || r.data || [];
        setRepoOptions(items.map((x: any) => ({ id: x.id, name: x.name })));
      })
      .catch(() => {});
    getBusinessUnits()
      .then((r) => {
        const items = r.data?.items || r.data || [];
        setBuOptions(items.map((x: any) => ({ id: x.id, name: x.name })));
      })
      .catch(() => {});
  }, []);

  // Map source_type → list of connected sources
  const connectedByType: Record<string, ScanSource[]> = {};
  for (const s of sources) {
    if (!connectedByType[s.source_type]) connectedByType[s.source_type] = [];
    connectedByType[s.source_type].push(s);
  }

  const openConfig = (sourceType: string) => {
    const schema = typeSchemas[sourceType];
    setConfiguring(sourceType);
    setEditingSourceId(null);
    setFormName(schema?.label || sourceType);
    // Seed Schedule with the smart per-source-type default returned by
    // /scan-sources/types (chat=hourly, docs/wikis=daily, cloud
    // storage=weekly, etc.) instead of the legacy "on_demand" — which
    // meant the source would never auto-scan unless the user manually
    // clicked "Scan now".  Customers can still pick on_demand from the
    // dropdown if they want manual-only.  See
    // DEFAULT_SCHEDULE_BY_SOURCE_TYPE in apps/api/app/schemas/scan_source.py.
    setFormSchedule(schema?.default_schedule || "daily");
    setFormCreds({});
    // Seed config with each field's `default` from the schema so
    // recommended toggles (e.g. exclude_self_created on Jira) start
    // pre-enabled — otherwise the user has to know to flip it on,
    // which defeats "recommended" labelling.
    const initialConfig: Record<string, any> = {};
    for (const field of (schema?.config_fields || [])) {
      if (field.default !== undefined) initialConfig[field.key] = field.default;
    }
    setFormConfig(initialConfig);
    setFormScopeMode("organization");
    setFormTargetRepoId("");
    setFormTargetBuId("");
    setTestResult(null);
    setWizardStep(0);
  };

  // Request-access submission for status:"request" sources.  We do
  // NOT pretend a backend endpoint exists — instead we toast a clean
  // confirmation and stash the request locally for future export.
  // When the demand-signal backend lands, swap the body of this fn
  // for a real fetch; the UX contract stays the same.
  const handleRequestAccess = async () => {
    if (!requestAccessFor) return;
    setRequestAccessSubmitting(true);
    try {
      // Persist locally so the user (and a future export) can see
      // their pending requests across sessions.
      const key = "vooda_pending_integration_requests";
      const raw = localStorage.getItem(key);
      const prev: Array<{ source_id: string; use_case: string; requested_at: string }> = raw ? JSON.parse(raw) : [];
      prev.push({
        source_id: requestAccessFor,
        use_case: requestAccessUseCase.trim(),
        requested_at: new Date().toISOString(),
      });
      localStorage.setItem(key, JSON.stringify(prev));
      const meta = SOURCE_BY_ID[requestAccessFor];
      toast(
        "success",
        "Request recorded",
        `${meta?.label || requestAccessFor} is on the roadmap. We'll reach out when it ships — your interest is logged.`,
      );
      setRequestAccessFor(null);
      setRequestAccessUseCase("");
    } catch (err: any) {
      toast("error", "Could not submit request", err?.message || "Please try again");
    } finally {
      setRequestAccessSubmitting(false);
    }
  };

  const openEdit = async (
    source: ScanSource,
    opts: { initialTab?: "overview" | "scans" | "settings" | "rule_overrides" } = {},
  ) => {
    // Edit just the parts that are safe to change after creation:
    // name, schedule, source-specific config, and scope binding.
    //
    // Credential fields are split by type:
    //   - SECRET fields (`type === "password"`): stay empty, the
    //     wizard's `(kept)` placeholder signals "leave blank to keep
    //     the stored value, fill in to rotate".
    //   - NON-SECRET fields (URL, email, account_id, etc.): pre-
    //     populate with the actual stored value so the user can see
    //     which workspace/account this source points at and edit in
    //     place if it's wrong.
    //
    // The backend's `_mask_response` already returns secret values as
    // a 4-char prefix + bullets and non-secrets as plaintext, so the
    // FE just has to filter by `type === "password"` when copying the
    // config dict into formCreds.  Industry standard pattern (AWS
    // Console, Stripe Dashboard, Atlassian admin all do this).
    setConfiguring(source.source_type);
    setEditingSourceId(source.id);
    setFormName(source.name);
    setFormSchedule(source.scan_schedule);

    // Pre-populate non-secret credential fields from the linked
    // IntegrationConfig.  Best-effort: a fetch failure leaves the
    // form blank (current behaviour), so the user can still edit
    // by typing — never breaks the edit flow on a network blip.
    //
    // Schema source: the same ``lookupSource(...).fields`` that drives
    // the rendered input list (see line ~1362).  Using a different
    // schema source here would risk pre-populating fields the form
    // doesn't actually render, which the user would never see.
    const credSchema = lookupSource(source.source_type).fields || [];
    const prePopulated: Record<string, string> = {};
    if (source.integration_config_id) {
      try {
        // The api helper returns the full axios response (the response
        // interceptor in lib/api.ts does ``return res``, not
        // ``return res.data``).  Axios response objects have a top-level
        // ``config`` field that holds the REQUEST config (url / headers /
        // method) — NOT to be confused with the integration's config.
        // Always reach into ``.data.config`` for the actual stored
        // integration credentials.  Bug fix 2026-05-09.
        const integ: any = await getIntegration(source.integration_config_id);
        const integConfig = integ?.data?.config ?? {};
        for (const f of credSchema) {
          // Skip password-type fields — let the (kept) placeholder fire.
          if (f.type === "password") continue;
          const v = integConfig[f.key];
          if (typeof v === "string" && v.length > 0) {
            prePopulated[f.key] = v;
          }
        }
      } catch {
        // Network or auth blip — leave fields blank, user can still
        // type to edit.  We deliberately don't toast() here because
        // the wizard is still functional in the degraded state.
      }
    }
    setFormCreds(prePopulated);
    // Merge stored config over defaults so newly-added fields (e.g.
    // exclude_self_created) reflect their recommended state when an
    // older source row is being edited — keeps the UI in sync with
    // what the worker is actually doing.
    const mergedConfig: Record<string, any> = {};
    const schema = typeSchemas[source.source_type];
    for (const field of (schema?.config_fields || [])) {
      if (field.default !== undefined) mergedConfig[field.key] = field.default;
    }
    setFormConfig({ ...mergedConfig, ...(source.config || {}) });
    if (source.target_repository_id) {
      setFormScopeMode("repository");
      setFormTargetRepoId(source.target_repository_id);
      setFormTargetBuId("");
    } else if (source.target_business_unit_id) {
      setFormScopeMode("business_unit");
      setFormTargetBuId(source.target_business_unit_id);
      setFormTargetRepoId("");
    } else {
      setFormScopeMode("organization");
      setFormTargetRepoId("");
      setFormTargetBuId("");
    }
    setTestResult(null);

    // ── Route edit clicks to the source detail drawer's Settings
    // tab instead of opening the separate connect-aside.  This
    // collapses the prior two-drawer ping-pong (where clicking Edit
    // opened a second drawer that visually competed with the detail
    // drawer the user might already have open) down to a single
    // drawer with the edit form living inline in its Settings tab.
    //
    // The aside still uses `configuring`/`editingSourceId` for state
    // — schema lookup, credential pre-population, save handler — but
    // the aside's render is gated on `!editingSourceId` further down
    // so it never appears in edit mode.
    setDetailSource(source);
    // Default to Settings tab (the call site is the card's Edit
    // button).  Card-body clicks pass `initialTab: "overview"` so
    // the user lands on Overview but the form is ready underneath.
    setInitialDetailTab(opts.initialTab ?? "settings");
  };

  const handleTestConnection = async () => {
    if (!configuring) return;
    setTesting(true); setTestResult(null);

    // Decide which test endpoint to use based on context:
    //
    //   1. EDIT mode + no PASSWORD fields filled
    //        → ``POST /scan-sources/{id}/test`` (stored-cred test)
    //          Uses the credentials already saved on the IntegrationConfig.
    //          Zero friction for re-testing an existing connection;
    //          mirrors the GitHub OAuth / Slack admin / Microsoft
    //          Defender for Cloud Apps pattern.
    //
    //   2. Otherwise (CREATE, or EDIT with a password field typed)
    //        → ``POST /scan-sources/test-connection`` (inline-cred test)
    //          Uses the credentials the user has just typed.  This is
    //          the rotation flow — verify the new token *before* save.
    //
    // Critical: only PASSWORD-type fields count as "user intent to
    // rotate / test new creds".  Non-secret fields (URL, email,
    // account_id, etc.) are PRE-POPULATED by ``openEdit`` from the
    // stored IntegrationConfig in edit mode, so checking "any field
    // filled" would always evaluate true for sources with URL+email
    // (Confluence / Jira / MS Teams / Bitbucket / etc.) and
    // incorrectly route to the inline path that demands the password
    // field too — the very friction we're trying to remove.
    //
    // Inline-cred test still gates on "all required fields filled"
    // because the upstream provider would otherwise return an opaque
    // missing-credentials error.  Stored-cred test skips that gate by
    // construction — cred fields aren't expected to be filled.
    const editingSource = editingSourceId
      ? sources.find((s) => s.id === editingSourceId)
      : null;
    const passwordFieldFilled = (credFields || []).some(
      (f: any) => f.type === "password" && String(formCreds[f.key] ?? "").trim() !== ""
    );

    try {
      if (editingSource && !passwordFieldFilled) {
        // (1) Stored-cred test path
        const res = await testSourceConnection(editingSource.id);
        setTestResult(res.data);
      } else {
        // (2) Inline-cred test path — same as before, plus the
        //     missing-fields gate so we don't round-trip a doomed call.
        const missing = (credFields || []).filter(
          (f: any) => !String(formCreds[f.key] ?? "").trim()
        );
        if (missing.length > 0) {
          setTestResult({
            status: "error",
            message: `Fill in: ${missing.map((f: any) => f.label).join(", ")}`,
          });
          return;
        }
        const res = await testUnsavedSourceConnection({
          source_type: configuring,
          credentials: formCreds,
          config: formConfig,
        });
        setTestResult(res.data);
      }
    } catch (e: any) {
      setTestResult({
        status: "error",
        message: e?.response?.data?.detail || e?.message || "Connection test failed",
      });
    } finally {
      setTesting(false);
    }
  };

  // Resolve the per-source scope into the two backend columns. Only
  // one of the target_* fields is ever set (UI exclusivity); the
  // other is null so we don't accidentally double-bind.
  const scopePayload = (): {
    target_repository_id: string | null;
    target_business_unit_id: string | null;
  } => {
    if (formScopeMode === "repository" && formTargetRepoId) {
      return { target_repository_id: formTargetRepoId, target_business_unit_id: null };
    }
    if (formScopeMode === "business_unit" && formTargetBuId) {
      return { target_repository_id: null, target_business_unit_id: formTargetBuId };
    }
    return { target_repository_id: null, target_business_unit_id: null };
  };

  const handleSave = async () => {
    if (!configuring || !formName) {
      toast("error", "Name is required", "Give this source a recognisable name before connecting.");
      return;
    }
    // Block save when scope mode requires a target but the picker
    // wasn't filled — saving the org-wide default silently would
    // be a footgun (the user explicitly switched off "Organization").
    if (formScopeMode === "repository" && !formTargetRepoId) {
      toast("error", "Pick a repository", "Choose which repository this source is bound to, or switch scope to Organization-wide.");
      return;
    }
    if (formScopeMode === "business_unit" && !formTargetBuId) {
      toast("error", "Pick a business unit", "Choose which business unit this source is bound to, or switch scope to Organization-wide.");
      return;
    }
    // ── Credential field validation (CREATE only) ────────────────
    // The backend will happily save an integration_config with an
    // empty config blob; the UX consequence is a "connected" source
    // card that fails on first scan with an opaque auth error. Catch
    // it here so the user gets a clear "fill in X" toast instead.
    //
    // Skipped on EDIT because the edit form deliberately doesn't
    // surface credential fields (they live on the linked
    // IntegrationConfig and rotating credentials is a separate flow).
    if (!editingSourceId) {
      const missingCreds = (credFields || []).filter(
        (f: any) => !String(formCreds[f.key] ?? "").trim()
      );
      if (missingCreds.length > 0) {
        toast(
          "error",
          "Missing required field" + (missingCreds.length > 1 ? "s" : ""),
          `Please fill in: ${missingCreds.map((f: any) => f.label).join(", ")}`,
        );
        return;
      }
    }
    // ── Required config field validation (CREATE + EDIT) ─────────
    // The backend schema marks some config_fields as required: true
    // (e.g. S3 bucket_name, Docker image reference, GitHub repos).
    // Without this gate, the source row gets saved and the worker
    // raises a cryptic adapter error on the first scan attempt.
    const missingConfig = (schema?.config_fields || []).filter(
      (f: any) => f.required && !String(formConfig[f.key] ?? "").trim()
    );
    if (missingConfig.length > 0) {
      toast(
        "error",
        "Missing required field" + (missingConfig.length > 1 ? "s" : ""),
        `Please fill in: ${missingConfig.map((f: any) => f.label).join(", ")}`,
      );
      return;
    }

    // ── Gate save when most recent Test Connection failed ────────
    // The user clicked Test, saw the upstream auth/permission error,
    // then clicked Save without re-testing. Saving silently leads to
    // a "Source Connected" toast for a broken connection which then
    // fails on first scan — confusing the user about whether the
    // problem is creds or scan logic. Pop a confirmation modal so
    // saving despite a failed test is explicit. CREATE only — on
    // EDIT we don't surface creds in the form, so the test result
    // doesn't apply to whatever's already saved.
    if (
      !editingSourceId
      && testResult
      && testResult.status === "error"
      && !confirmSaveDespiteFailedTest
    ) {
      setConfirmSaveDespiteFailedTest(true);
      return;
    }
    setConfirmSaveDespiteFailedTest(false);

    setSaving(true);
    try {
      if (editingSourceId) {
        // EDIT path — two phases:
        //   1. (Optional) rotate credentials on the linked
        //      IntegrationConfig if the user filled any cred field.
        //      Empty fields are dropped so partial rotations work
        //      (e.g. only the client_secret rotated; tenant_id and
        //      client_id stay the same).
        //   2. Update the ScanSource fields (name, schedule, scope,
        //      source-specific config). Done after creds so a failed
        //      rotation doesn't leave us with mismatched state.
        // Bug fix 2026-05-08: previously credentials couldn't be
        // rotated through the UI at all — customers had to delete
        // and recreate the source whenever a token expired.
        const filledCreds = Object.fromEntries(
          Object.entries(formCreds).filter(([_, v]) => String(v ?? "").trim() !== "")
        );
        const editingSource = sources.find(s => s.id === editingSourceId);
        if (Object.keys(filledCreds).length > 0 && editingSource?.integration_config_id) {
          // Merge over the stored config so untouched fields remain.
          // The backend stores credentials as `config` on the
          // IntegrationConfig — same shape used at create time, just
          // partial.
          await updateIntegration(editingSource.integration_config_id, {
            config: filledCreds,
          } as any);
        }
        await updateScanSource(editingSourceId, {
          name: formName,
          scan_schedule: formSchedule,
          config: formConfig,
          ...scopePayload(),
        });
        const credsRotated = Object.keys(filledCreds).length > 0;
        toast(
          "success",
          "Source Updated",
          credsRotated
            ? `${formName} saved · ${Object.keys(filledCreds).length} credential field(s) rotated`
            : `${formName} has been saved`
        );
      } else {
        // CREATE path — save creds first to get an integration_config_id,
        // then create the ScanSource referring to it.
        const provider = lookupSource(configuring).provider;
        const intRes = await createIntegration({ provider, name: `${formName} credentials`, config: formCreds });
        const integrationId = intRes.data?.id;
        if (!integrationId) throw new Error("Failed to save credentials");

        await createScanSource({
          name: formName, source_type: configuring,
          integration_config_id: integrationId, scan_schedule: formSchedule, config: formConfig,
          ...scopePayload(),
        });
        toast("success", "Source Connected", `${formName} has been added`);
      }
      setConfiguring(null);
      setEditingSourceId(null);
      load();
    } catch (e: any) {
      toast("error", "Error", e.response?.data?.detail || e.message || "Failed to save source");
    } finally { setSaving(false); }
  };

  const handleScan = async (id: string) => {
    // Trigger the Celery task AND immediately refresh the source
    // list so the new pending scan shows up in recent_scans (drives
    // both the activity-dot pulse + the in-flight button state
    // derived in the card render).
    //
    // The HTTP dispatch returns in ~200ms but the actual scan takes
    // 30s–2min in the worker.  Without the load() refresh + the
    // recent_scans-derived button state, the user would only see
    // "Scanning…" for the 200ms HTTP window and then nothing — which
    // is what triggered the "is my scan running?" confusion.
    setScanning(s => ({ ...s, [id]: true }));
    const src = sources.find((s) => s.id === id);
    try {
      await triggerSourceScan(id);
      toast(
        "success",
        "Scan queued",
        src
          ? `${src.name} — watch the activity dots, or open the source to follow progress.`
          : "Source scan has been queued.",
      );
      // Pull fresh recent_scans so the card's activity strip + the
      // button's "Scanning…" derivation picks up the pending scan.
      await load();
    } catch (e: any) {
      toast(
        "error",
        "Scan failed",
        e?.response?.data?.detail || "Could not trigger scan.",
      );
    } finally {
      setScanning(s => ({ ...s, [id]: false }));
    }
  };

  const handleToggle = async (source: ScanSource) => {
    // Toggles between Archived (is_active=false) and Active (is_active=true).
    // Same concept as the repos Archive/Unarchive flow; one click since
    // the user is already on the source card.
    const willArchive = source.is_active;
    try {
      await updateScanSource(source.id, { is_active: !source.is_active });
      load();
      if (willArchive) {
        toast(
          "success",
          "Source Archived",
          `${source.name} archived — scanning paused, findings preserved. Click Unarchive to resume.`,
        );
      } else {
        toast(
          "success",
          "Source Unarchived",
          `${source.name} restored — scanning resumed.`,
        );
      }
    } catch {
      toast("error", "Error", willArchive ? "Could not archive source" : "Could not unarchive source");
    }
  };

  const handleDelete = (source: ScanSource) => {
    // Open the shared DeleteConfirmModal — actual delete runs in
    // ``confirmDelete`` below once the user explicitly types the
    // source name and confirms.  The preview-fetch effect below
    // populates the impact summary as soon as the target is set.
    setDeleteTarget(source);
  };

  // Archive — sets is_active=false on the source.  Stops scheduled
  // scans, hides findings from active dashboards/lists, but preserves
  // findings / scan history / incident triage.  Reversible via the
  // per-card "Unarchive" button.  Called from the DeleteConfirmModal's
  // "Archive instead" suggestion link as well as directly via the
  // per-card Archive button (single concept, two entry points — the
  // industry-standard pattern after GitGuardian/Aikido/TruffleHog
  // consolidated Pause/Archive/Disable into a single "Archive" term).
  const archiveSource = async (source: ScanSource) => {
    try {
      await updateScanSource(source.id, { is_active: false });
      toast(
        "success",
        "Source Archived",
        `${source.name} archived — scanning paused, findings preserved. Click Unarchive on the source card to resume.`,
      );
      setDeleteTarget(null);
      setDeletePreview(null);
      load();
    } catch (err: any) {
      toast("error", "Archive Failed", err?.response?.data?.detail || "Could not archive the source");
    }
  };

  // Load the impact preview whenever the modal opens.  Done in a
  // useEffect so the modal can mount immediately with a skeleton and
  // populate the counts as soon as the API responds.
  useEffect(() => {
    if (!deleteTarget) {
      setDeletePreview(null);
      setDeletePreviewError(null);
      return;
    }
    let cancelled = false;
    setDeletePreview(null);
    setDeletePreviewError(null);
    getScanSourceDeletePreview(deleteTarget.id)
      .then((r) => { if (!cancelled) setDeletePreview(r.data as DeletePreview); })
      .catch((err: any) => {
        if (!cancelled) setDeletePreviewError(err?.response?.data?.detail || "Could not load deletion preview");
      });
    return () => { cancelled = true; };
  }, [deleteTarget]);

  const confirmDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      // Step 1: drop the scan_source row. The DB-level CASCADE
      // (FK migration r5s6t7u8v9w0) handles the dependent rows in
      // finding_decision_cache, normalized_findings, scan_jobs, etc.
      await deleteScanSource(deleteTarget.id);

      // Step 2: drop the linked IntegrationConfig too. The modal
      // promises this ("Stored credentials (the linked integration
      // config)") and customers expect it — leaving an orphan
      // integration_config behind would (a) break the promise,
      // (b) leak the encrypted credential, and (c) clutter the
      // /integrations list with rows that no longer point to a
      // working scan target. Best-effort: a failure here doesn't
      // block the source-delete success toast (the source IS gone)
      // but does surface a separate warning so the operator knows
      // to clean up manually. Bug fix 2026-05-09 — before, the FE
      // only deleted the scan_source and the integration_config
      // accumulated forever.
      let credsCleaned = false;
      if (deleteTarget.integration_config_id) {
        try {
          await deleteIntegration(deleteTarget.integration_config_id);
          credsCleaned = true;
        } catch (intErr: any) {
          // Don't propagate — the source delete already succeeded;
          // the integration leak is a (small) follow-up problem,
          // not a reason to confuse the user about the primary
          // operation. Surface as a non-fatal warning.
          console.warn("Source deleted but integration_config cleanup failed", intErr);
          toast(
            "info",
            "Credentials not removed",
            "Source was deleted, but its stored credentials remain in /integrations. Remove them there if you don't intend to reuse.",
          );
        }
      }

      toast(
        "success",
        "Source Removed",
        credsCleaned
          ? `${deleteTarget.name} deleted (including stored credentials)`
          : `${deleteTarget.name} deleted`,
      );
      setDeleteTarget(null);
      setDeletePreview(null);
      load();
    } catch (e: any) {
      toast(
        "error",
        "Could not delete source",
        e?.response?.data?.detail || e?.message || "Please try again",
      );
    } finally {
      setDeleting(false);
    }
  };

  const schema = configuring ? typeSchemas[configuring] : null;
  const credFields = configuring ? lookupSource(configuring).fields : [];

  // Catalog tile renderer — extracted so the same markup works for
  // the regular categories AND the Niche disclosure section. Keeps
  // the visual language identical across both, which matters for
  // the symmetric look the user asked for.
  const renderCatalogTile = (src: SourceDef) => {
    const s = typeSchemas[src.id];
    const connected = connectedByType[src.id] || [];
    const count = connected.length;
    const isRequest = src.status === "request";
    return (
      <button
        key={src.id}
        onClick={() => isRequest ? setRequestAccessFor(src.id) : openConfig(src.id)}
        className="card card-hover group text-left p-4 relative overflow-hidden transition-all cursor-pointer"
        style={isRequest ? { borderColor: "rgba(245, 158, 11, 0.25)" } : undefined}
      >
        <div className={`absolute top-0 left-0 right-0 h-1 bg-gradient-to-r ${src.gradient} ${count > 0 || isRequest ? "opacity-100" : "opacity-0 group-hover:opacity-100"} transition-opacity`} />
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${src.gradient} flex items-center justify-center shrink-0 text-white ${count > 0 ? "opacity-100" : "opacity-70 group-hover:opacity-100"} transition-opacity`}>
            <BrandGlyph src={src} className="w-5 h-5" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-1.5">
              <p className="text-sm text-slate-200 font-medium truncate">{s?.label || src.label}</p>
              {isRequest && (
                <span
                  className="text-[8px] px-1.5 py-0.5 rounded-full font-semibold uppercase tracking-wider shrink-0"
                  style={{
                    background: "rgba(245, 158, 11, 0.12)",
                    color: "#fbbf24",
                    border: "1px solid rgba(245, 158, 11, 0.3)",
                  }}
                >
                  Request access
                </span>
              )}
            </div>
            <p className="text-[10px] text-slate-500 truncate">
              {isRequest
                ? "On roadmap — click to register interest"
                : count > 0 ? `${count} connected · Add another` : "Click to connect"}
            </p>
          </div>
          {count > 0 && !isRequest && (
            <span className="text-[9px] px-2 py-0.5 rounded-full bg-green-500/15 text-green-400 border border-green-500/20 font-medium shrink-0">
              {count}
            </span>
          )}
        </div>
      </button>
    );
  };

  // ── Per-category aggregates for the top-level grid ──
  // Live sources require a backend schema (typeSchemas keyed) so we
  // never advertise a source the API can't actually create.
  // Request-status sources are deliberately surfaced even without a
  // backend schema — clicking them opens a request-access form instead
  // of the connect wizard, so a missing schema is fine.
  // Tier-D `hidden: true` sources are excluded unconditionally — they
  // don't appear in the catalog even if a stale instance exists in the
  // DB.  Existing instances should be cleaned up via the API or
  // surfaced via the `/sources/connected` flat view if needed.
  const sourcesInCategory = (cat: SourceCategory) =>
    SOURCES.filter(s =>
      s.category === cat
      && !s.hidden
      && (s.status === "request" || typeSchemas[s.id])
    );
  const connectedInCategory = (cat: SourceCategory) =>
    sources.filter(s => {
      const meta = SOURCE_BY_ID[s.source_type];
      return meta && meta.category === cat;
    });

  // Filter the catalog tile list during the category-detail view.
  // Currently only the status filter ("all" / "connected" / "not
  // connected") narrows the list.  The keyword-search input was
  // removed in favour of the bare visual list, which is short enough
  // per category to scan visually without typing.
  const filteredCategorySources = (cat: SourceCategory) => {
    return sourcesInCategory(cat).filter((src) => {
      const count = (connectedByType[src.id] || []).length;
      if (statusFilter === "connected" && count === 0) return false;
      if (statusFilter === "not_connected" && count > 0) return false;
      return true;
    });
  };

  // Connected source card renderer — used both in the "All
  // connected" view and inside category detail. One source of
  // truth keeps the visual treatment identical everywhere.
  // Optional `extraFooter` renders inside the card after the action
  // row.  Used by the unified type-card view to keep the
  // "N connected · + Add another" strip visually inside the card
  // frame instead of floating beneath it.
  const renderConnectedCard = (source: ScanSource, extraFooter?: React.ReactNode) => {
    const meta = lookupSource(source.source_type);
    const boundRepo = source.target_repository_id
      ? repoOptions.find((r) => r.id === source.target_repository_id) : null;
    const boundBu = !boundRepo && source.target_business_unit_id
      ? buOptions.find((b) => b.id === source.target_business_unit_id) : null;
    const findings = source.stats?.findings_count || 0;
    const lastStatus = source.stats?.last_scan_status as string | undefined;
    const lastError = source.stats?.last_error as string | undefined;
    // Worker writes the per-scan count under `last_items_scanned`
    // (the cumulative `findings_count` is a separate cross-scan
    // total). Use the per-scan number for the amber-state check —
    // we want "did the most recent scan see anything?" not "have any
    // findings ever been associated with this source."
    const itemsScanned = (source.stats?.last_items_scanned ?? null) as number | null;
    // Status pill priority order:
    //   1. Paused (admin disabled)              — slate
    //   2. Last scan failed                     — red, hover for error detail
    //   3. Never scanned                        — blue
    //   4. Scan returned no items (suspect)     — amber
    //   5. Healthy                              — green
    //
    // Amber state added 2026-05-08: a "successful" scan that fetched
    // zero items is almost always a permission/scope problem (e.g.
    // Slack bot not invited to any channel, Confluence v2 page-fetch
    // permission missing, S3 bucket filter matches nothing). Showing
    // green Healthy in that case told customers "all good" when
    // nothing was actually being scanned. The amber pill visibly
    // distinguishes "scanned 200 items, found nothing" (Healthy)
    // from "scanned 0 items" (action needed).
    const status = !source.is_active
      ? { dot: "bg-slate-500", text: "Archived", color: "text-slate-400", title: "Archived — scanning paused, data preserved. Click Unarchive on the card to resume." }
      : lastStatus === "failed"
      ? { dot: "bg-red-500", text: "Last scan failed", color: "text-red-400",
          title: lastError ? `Error: ${lastError}` : "Most recent scan attempt failed — Edit + retry, or check the worker logs." }
      : !source.last_scan_at
      ? { dot: "bg-blue-400", text: "Never scanned", color: "text-blue-300", title: "" }
      : (lastStatus === "success" && itemsScanned === 0)
      ? { dot: "bg-amber-400", text: "No items scanned", color: "text-amber-300",
          title: "The connection succeeded but the scan returned zero items. Common causes: scope filter matches nothing (channels / projects / spaces / buckets), or the API token lacks read permission on the items it needs to enumerate. Edit the source and verify the scope, or grant the integration broader read access at the provider." }
      : { dot: "bg-green-400", text: "Healthy", color: "text-green-300", title: "" };
    // Per-surface findings — only meaningful when there are findings
    // AND the worker recorded a breakdown (older scans pre-rebalance
    // won't have this). Filtered to non-zero surfaces only so the
    // strip stays tight.
    const bySurface = (source.stats?.last_findings_by_surface || {}) as Record<string, number>;
    const surfaceParts = Object.entries(bySurface)
      .filter(([_, n]) => (n as number) > 0)
      .sort((a, b) => (b[1] as number) - (a[1] as number));

    // Trend — diff between the most recent two completed scans.
    // Tells the customer whether new secrets are leaking in (+),
    // being remediated out (−), or steady (0). High-signal, low-
    // pixel-cost — same vocabulary Snyk and GitGuardian use on
    // their dashboard cards.
    const completed = (source.recent_scans || []).filter(s => s.status === "completed");
    const trendDelta = completed.length >= 2
      ? completed[0].findings_total - completed[1].findings_total
      : 0;

    const isArchived = source.is_active === false;
    const isStale = source.is_stale === true && !isArchived;
    return (
      <div key={source.id}
           // Card body is now clickable — opens the right-side detail
           // drawer (SourceDetailDrawer) for this source.  Internal
           // buttons all call e.stopPropagation() so action clicks
           // (Scan / Edit / Archive / Delete / Unarchive) don't also
           // open the drawer.
           //
           // We call openEdit() (with the overview tab) so that the
           // form state (schema, credFields, form values) is already
           // primed when the user switches to the Settings tab —
           // otherwise that tab would render blank.  openEdit is
           // async but the drawer opens synchronously from the
           // setDetailSource call inside it; the credential
           // pre-population fetch finishes in the background.
           role="button"
           tabIndex={0}
           onClick={() => openEdit(source, { initialTab: "overview" })}
           onKeyDown={(e) => {
             if (e.key === "Enter" || e.key === " ") {
               e.preventDefault();
               openEdit(source, { initialTab: "overview" });
             }
           }}
           className="card group relative overflow-hidden p-0 hover:border-white/[0.14] transition-colors cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-violet-500/40"
           style={isArchived ? { filter: "grayscale(0.5) opacity(0.75)", background: "rgba(120, 113, 108, 0.04)" } : undefined}>
        <div className={`h-[2px] bg-gradient-to-r ${meta.gradient} opacity-60 group-hover:opacity-100 transition-opacity`} />
        {/* Stale pip — top-right, doesn't compete with the Unarchive
            badge (those are mutually exclusive: archived sources are
            never stale).  Pure visual signal; the explanatory copy
            lives in the drawer Overview tab. */}
        {isStale && (
          <span
            title="Stale — scheduler may have stopped firing.  Open the source to investigate."
            className="absolute top-3 right-3 z-10 inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-amber-500/15 text-amber-300 border border-amber-500/30"
            onClick={(e) => e.stopPropagation()}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
            Stale
          </span>
        )}
        {/* Always-visible Unarchive pill on archived cards — primary
            action when the user is reviewing the Archived view, so it
            shouldn't hide behind hover.  Mirrors the repos page. */}
        {isArchived && (
          <button
            onClick={(e) => { e.stopPropagation(); handleToggle(source); }}
            title="Unarchive — resume scanning"
            className="absolute top-3 right-3 z-10 inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium transition-colors"
            style={{
              background: "rgba(16, 185, 129, 0.12)",
              color: "#34d399",
              border: "1px solid rgba(16, 185, 129, 0.3)",
            }}>
            <svg className="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
            </svg>
            Unarchive
          </button>
        )}
        <div className="p-4 space-y-3">
          <div className="flex items-center gap-3">
            <div className={`w-11 h-11 rounded-xl bg-gradient-to-br ${meta.gradient} flex items-center justify-center shrink-0 text-white opacity-90 group-hover:opacity-100 transition-opacity`}>
              <BrandGlyph src={meta} className="w-5 h-5" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-bold text-slate-200 group-hover:text-white truncate transition-colors">{source.name}</p>
              {/* Subtitle (source-type label) is hidden when it's
                  literally identical to the name — that's the default
                  state when a user hasn't given the source a custom
                  name yet, and rendering "Notion / Notion" stacked is
                  pure noise.  Custom-named sources (e.g. "Engineering
                  workspace") keep both lines for context. */}
              {source.name !== meta.label && (
                <p className="text-xs text-slate-500 truncate">{meta.label}</p>
              )}
              {isArchived && (
                <span className="mt-1 inline-flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded-full font-semibold uppercase tracking-wider"
                  style={{
                    background: "rgba(245, 158, 11, 0.12)",
                    color: "#fbbf24",
                    border: "1px solid rgba(245, 158, 11, 0.3)",
                  }}>
                  <svg className="w-2 h-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" />
                  </svg>
                  Archived
                </span>
              )}
            </div>
            {/* Hide the inline status pill when archived — the Archived
                badge under the title + the Unarchive pill on the right
                already communicate the state more strongly. */}
            {!isArchived && (
              <span className={`flex items-center gap-1.5 text-[10px] ${status.color} shrink-0`} title={status.title}>
                <span className={`w-1.5 h-1.5 rounded-full ${status.dot}`} />
                {status.text}
              </span>
            )}
          </div>

          <div>
            {boundRepo ? (
              <span className="text-[10px] px-2 py-0.5 rounded-md bg-blue-500/10 text-blue-300 border border-blue-500/20"
                    title={`Bound to repository "${boundRepo.name}"`}>
                Repo · {boundRepo.name}
              </span>
            ) : boundBu ? (
              <span className="text-[10px] px-2 py-0.5 rounded-md bg-purple-500/10 text-purple-300 border border-purple-500/20">
                BU · {boundBu.name}
              </span>
            ) : (
              <span className="text-[10px] px-2 py-0.5 rounded-md bg-slate-500/10 text-slate-400 border border-slate-500/15">
                Org-wide
              </span>
            )}
          </div>

          <div className="grid grid-cols-3 gap-2 pt-2 border-t border-white/[0.04]">
            <div>
              <p className="text-[9px] text-slate-600 uppercase tracking-wider">Last scan</p>
              <p className="text-xs text-slate-300 mt-0.5">{timeAgo(source.last_scan_at)}</p>
            </div>
            <div>
              <p className="text-[9px] text-slate-600 uppercase tracking-wider">Findings</p>
              <p className="text-xs mt-0.5 flex items-center gap-1">
                <span className={findings > 0 ? "text-red-400" : "text-slate-300"}>{findings}</span>
                {trendDelta !== 0 && (
                  <span
                    className={`text-[9px] ${trendDelta > 0 ? "text-red-400" : "text-green-400"}`}
                    title={trendDelta > 0
                      ? `${trendDelta} new since previous scan`
                      : `${Math.abs(trendDelta)} fewer since previous scan`}
                  >
                    {trendDelta > 0 ? `↑${trendDelta}` : `↓${Math.abs(trendDelta)}`}
                  </span>
                )}
              </p>
              {/* Per-surface findings breakdown — only renders when
                  there are 2+ surfaces (otherwise the line just
                  duplicates the total above and looks orphaned).  Sits
                  inline as a sub-text under the Findings number so the
                  relationship reads naturally: "3 findings, of which
                  2 in pages and 1 in attachments". */}
              {surfaceParts.length >= 2 && (
                <p
                  className="text-[10px] text-slate-500 mt-0.5 leading-snug truncate"
                  title="Findings from the most recent scan, broken down by surface"
                >
                  {surfaceParts.map(([k, n], i) => (
                    <span key={k}>
                      {i > 0 && <span className="text-slate-700"> · </span>}
                      <span className="text-slate-400">{n}</span>{" "}
                      <span className="text-slate-600">{k.replace("_", " ")}</span>
                    </span>
                  ))}
                </p>
              )}
            </div>
            <div>
              <p className="text-[9px] text-slate-600 uppercase tracking-wider">Schedule</p>
              <p className="text-xs text-slate-300 mt-0.5 capitalize">
                {source.scan_schedule === "on_demand" ? "On demand" : source.scan_schedule}
              </p>
            </div>
          </div>

          {/* Activity strip — last 5 scans as colored dots. Densest
              accurate signal we can fit on the card; same vocabulary
              Sentry / GitHub Actions / CircleCI use. Reads chronological
              left → right (oldest first) to match how a timeline feels.
              The "Activity" label was removed — the dots are
              self-explanatory and a tooltip on hover provides the
              "last N scans" context.  Reclaims ~50px of horizontal
              space which the dots can spread into. */}
          {(source.recent_scans?.length ?? 0) > 0 && (
            <div className="flex items-center gap-0.5 pt-0.5"
                 title={`Last ${source.recent_scans!.length} scans`}>
              <div className="flex items-center gap-0.5">
                {source.recent_scans!
                  .slice()
                  .reverse()              /* oldest → newest, left to right */
                  .map((rs) => {
                    const c = rs.status === "completed"
                      ? (rs.findings_total > 0 ? "bg-amber-400" : "bg-green-400")
                      : rs.status === "failed"
                      ? "bg-red-500"
                      : rs.status === "running" || rs.status === "pending"
                      ? "bg-blue-400 animate-pulse"
                      : "bg-slate-600";
                    const when = rs.created_at ? timeAgo(rs.created_at) : "";
                    const tip = rs.status === "failed"
                      ? `${when} · failed${rs.error ? `: ${rs.error}` : ""}`
                      : `${when} · ${rs.findings_total} finding${rs.findings_total === 1 ? "" : "s"}`;
                    return (
                      <span key={rs.id} title={tip}
                            className={`w-2 h-3 rounded-sm ${c}`} />
                    );
                  })}
              </div>
            </div>
          )}

          <div className="flex items-center gap-1.5 pt-1">
            {/* Scan-in-flight detection.  Two signals:
                  - scanning[id]: local flag flipped during the HTTP
                    dispatch.  Lasts ~200ms before recent_scans
                    refresh catches up.
                  - hasInFlightScan: server-of-truth — the most recent
                    scan job is pending or running.  Keeps the button
                    in "Scanning…" state for the FULL duration of the
                    worker run, not just the HTTP dispatch window.
                The polling effect lower in this file calls load()
                every 5s while any source has an in-flight scan, so
                this derivation updates on its own as the scan
                progresses. */}
            {(() => {
              const liveStatus = (source.recent_scans?.[0]?.status || "").toLowerCase();
              const hasInFlightScan = liveStatus === "pending" || liveStatus === "running";
              const busy = scanning[source.id] || hasInFlightScan;
              return (
                <button
                  onClick={(e) => { e.stopPropagation(); handleScan(source.id); }}
                  disabled={busy || !source.is_active}
                  title={
                    !source.is_active
                      ? "Source is archived — unarchive to scan"
                      : busy
                        ? "A scan is already running.  Open the source for live progress."
                        : "Trigger a scan now"
                  }
                  className="flex-1 inline-flex items-center justify-center gap-1.5 text-[11px] px-2.5 py-1.5 rounded bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed font-medium"
                >
                  {busy && (
                    <span className="w-2.5 h-2.5 border-[1.5px] border-red-400/30 border-t-red-400 rounded-full animate-spin" />
                  )}
                  {scanning[source.id]
                    ? "Queueing…"
                    : hasInFlightScan
                      ? "Scanning…"
                      : "Scan now"}
                </button>
              );
            })()}
            <button onClick={(e) => { e.stopPropagation(); openEdit(source); }}
                    className="text-[11px] px-2.5 py-1.5 rounded bg-white/[0.04] text-slate-300 hover:bg-white/[0.08] transition-colors">
              Edit
            </button>
            <button onClick={(e) => { e.stopPropagation(); handleToggle(source); }}
                    title={source.is_active ? "Archive — pause scanning, preserve data, reversible" : "Unarchive — resume scanning"}
                    className={`text-[11px] px-2 py-1.5 rounded transition-colors ${source.is_active ? "bg-white/[0.04] text-slate-400 hover:bg-white/[0.08]" : "bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20"}`}>
              {source.is_active ? "Archive" : "Unarchive"}
            </button>
            <button onClick={(e) => { e.stopPropagation(); handleDelete(source); }}
                    title="Delete source"
                    className="text-[11px] w-7 h-7 inline-flex items-center justify-center rounded text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors">
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                      d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6M1 7h22M9 7V4a1 1 0 011-1h4a1 1 0 011 1v3" />
              </svg>
            </button>
          </div>

          {/* Optional inline footer — rendered when the parent context
              wants to attach extra info to the card (e.g. the "N
              connected · + Add another" strip in the unified type-card
              view).  Kept inside the card frame instead of floating
              beneath so the card reads as a single self-contained
              unit. */}
          {extraFooter}
        </div>
      </div>
    );
  };

  // ── Unified per-TYPE card for the category-detail view ──
  //
  // The /sources/[category] page used to show two parallel grids:
  // "Your <category> sources" (rich cards, configured) + "Available
  // <category> sources" (small Configure buttons).  Source types that
  // were already connected appeared in BOTH — once as a managed card
  // and again as an "Add another" button.  Half the cards on the page
  // were duplicates carrying no new information.
  //
  // This helper merges both into one card per source TYPE.  Shape
  // stays identical across both states; only the body content swaps:
  //   • 0 instances → description + Configure CTA
  //   • 1+ instances → primary instance's rich card + "+ Add another"
  //                    link.  The Connected pseudo-category at the
  //                    /sources root still lists every individual
  //                    instance for granular management.
  const renderTypeCard = (src: SourceDef) => {
    const instances = connectedByType[src.id] || [];

    // ── Empty state — same card shell, Configure CTA in place of stats ──
    if (instances.length === 0) {
      const label = typeSchemas[src.id]?.label || src.label;
      const isRequest = src.status === "request";
      return (
        <div
          key={src.id}
          className="card group relative overflow-hidden p-0 transition-colors hover:border-white/[0.14]"
          style={isRequest ? { borderColor: "rgba(245, 158, 11, 0.25)" } : undefined}
        >
          <div className={`h-[2px] bg-gradient-to-r ${src.gradient} ${isRequest ? "opacity-100" : "opacity-30 group-hover:opacity-100"} transition-opacity`} />
          <div className="p-4 space-y-3 flex flex-col h-[calc(100%-2px)]">
            <div className="flex items-center gap-3">
              <div className={`w-11 h-11 rounded-xl bg-gradient-to-br ${src.gradient} flex items-center justify-center shrink-0 text-white opacity-70 group-hover:opacity-100 transition-opacity`}>
                <BrandGlyph src={src} className="w-5 h-5" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5 flex-wrap">
                  <p className="text-sm font-bold text-slate-200 truncate">{label}</p>
                  {isRequest && (
                    <span
                      className="text-[8px] px-1.5 py-0.5 rounded-full font-semibold uppercase tracking-wider shrink-0"
                      style={{
                        background: "rgba(245, 158, 11, 0.12)",
                        color: "#fbbf24",
                        border: "1px solid rgba(245, 158, 11, 0.3)",
                      }}
                    >
                      Request access
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-500 truncate">{src.category}</p>
              </div>
              {!isRequest && (
                <span className="flex items-center gap-1.5 text-[10px] text-slate-500 shrink-0">
                  <span className="w-1.5 h-1.5 rounded-full bg-slate-600" />
                  Not connected
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500 leading-relaxed flex-1">
              {isRequest
                ? `${label} is on the roadmap. Click below to register interest — your use case helps us prioritize.`
                : `Connect to scan ${label} for credentials, secrets, and other sensitive data.`}
            </p>
            {/* Action CTA — neutral secondary for live integrations,
                amber-tinted "Request access" for request-status ones.
                Matches the same visual contract as renderCatalogTile. */}
            {isRequest ? (
              <button
                onClick={() => setRequestAccessFor(src.id)}
                className="inline-flex items-center justify-center gap-1.5 w-full px-3 py-1.5 rounded-md text-xs font-medium transition-all duration-200 select-none"
                style={{
                  color: "#0c1024",
                  background: "#fbbf24",
                  border: "1px solid #f59e0b",
                  cursor: "pointer",
                }}
              >
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
                Request access
              </button>
            ) : (
              <button
                onClick={() => openConfig(src.id)}
                className="btn-secondary-sm w-full justify-center"
              >
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                </svg>
                Configure
              </button>
            )}
          </div>
        </div>
      );
    }

    // ── Connected state — primary instance's rich card + inline
    //    "N connected · Add another" strip rendered INSIDE the card
    //    via `renderConnectedCard`'s `extraFooter` slot.  Reusing the
    //    same renderer keeps the card visuals 100% identical across
    //    this view and the "Connected" pseudo-category flat view.
    const primary = instances[0];
    // Footer strip — left side reads "N connected · showing most recent"
    // (and exposes a "View all N →" link when there are 2+ instances
    // so the user can jump to the Connected pseudo-category filtered
    // to that type for granular per-instance management); right side
    // always offers "+ Add another".
    const footer = (
      <div
        className="flex items-center justify-between text-[10px] pt-2 mt-1 border-t border-white/[0.04] gap-2"
      >
        <span className="flex items-center gap-2 min-w-0">
          <span className="text-slate-500">
            {instances.length === 1
              ? "1 connected"
              : `${instances.length} connected · showing most recent`}
          </span>
          {instances.length > 1 && (
            <button
              onClick={() => nextRouter.push(`/sources/connected?type=${encodeURIComponent(src.id)}`)}
              className="text-slate-400 hover:text-slate-200 transition-colors inline-flex items-center gap-0.5"
              title={`Manage all ${instances.length} ${src.label} instances`}
            >
              View all {instances.length}
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
            </button>
          )}
        </span>
        <button
          onClick={() => openConfig(src.id)}
          className="text-slate-400 hover:text-slate-200 transition-colors flex items-center gap-1 shrink-0"
        >
          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Add another
        </button>
      </div>
    );
    // `renderConnectedCard` already sets `key={source.id}` on the
    // returned element — that key is unique across all siblings in
    // the grid (different ScanSource records have different ids), so
    // we can return the rendered card directly.
    return renderConnectedCard(primary, footer);
  };

  // Active category resolves to either a real category, the "all
  // connected" view, or null (top-level grid).
  const activeCategoryMeta = activeCategory && activeCategory !== "_connected"
    ? CATEGORIES.find((c) => c.key === activeCategory)
    : null;

  // ── Shared config-form body ─────────────────────────────────────
  // Same form JSX rendered in two places:
  //   1. The connect-new aside (multi-step wizard ends in this form)
  //   2. The source detail drawer's Settings tab (no wizard — Edit
  //      flow lands on this directly)
  // Owns no state of its own — pulls everything from the surrounding
  // SourcesPageInner closure so both call sites share state.  This is
  // the consolidation that stopped the prior two-drawer ping-pong
  // (where Edit opened a second drawer that visually competed with
  // the detail drawer the user might already have open).
  const renderConfigFormBody = (): React.ReactNode => {
    if (!schema) return null;
    return (
      <div className="space-y-4">
        {/* Name + Schedule */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-slate-400 block mb-1">
              Name <span className="text-red-400 cursor-help" title="Required" aria-label="Required field">*</span>
            </label>
            <input value={formName} onChange={e => setFormName(e.target.value)} className="input-dark w-full" />
          </div>
          <div>
            <label className="text-xs text-slate-400 block mb-1">Schedule</label>
            <select value={formSchedule} onChange={e => setFormSchedule(e.target.value)} className="select-dark w-full">
              <option value="on_demand">On Demand</option>
              <option value="hourly">Hourly</option>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
            </select>
            {/* Trade-off explainer.  Surfaces what each cadence
                actually means in terms of detection window so the
                customer makes an informed choice rather than picking
                blindly.  Mirrors the per-category defaults
                (chat=hourly, docs/wikis=daily, cloud storage=weekly)
                so customers know our recommendation. */}
            <p className="text-[10px] text-slate-600 mt-1 leading-snug">
              {(() => {
                const map: Record<string, string> = {
                  on_demand: "Runs only when you click Scan now. Recommended for one-off audits.",
                  hourly: "Catches secrets within ~60 minutes. Recommended for chat sources where messages can be edited or deleted within minutes.",
                  daily: "Catches secrets within ~24 hours. Recommended for wikis, ticketing, and CI/CD logs — balanced detection vs upstream API quotas.",
                  weekly: "Catches secrets within ~7 days. Recommended for cloud storage and container images — configs change rarely and full scans are bandwidth-heavy.",
                };
                return map[formSchedule] || "";
              })()}
            </p>
          </div>
        </div>

        {/* Credentials section.  Create mode: required.  Edit mode:
            optional — empty fields keep the stored value.  See the
            comment that used to live here for the full back-story. */}
        <div className="space-y-3 p-3 rounded-lg bg-white/[0.02] border border-white/[0.06]">
          <div className="flex items-baseline justify-between">
            <p className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Credentials</p>
            {editingSourceId && (
              <p className="text-[10px] text-slate-600 italic">Leave a field blank to keep its current value</p>
            )}
          </div>
          {credFields?.map(f => (
            <div key={f.key}>
              <label className="text-[10px] text-slate-500 block mb-1">
                {f.label}{" "}
                {!editingSourceId && (
                  <span className="text-red-400 cursor-help" title="Required" aria-label="Required field">*</span>
                )}
                {editingSourceId && (
                  <span className="text-[9px] text-slate-600 ml-1">(optional)</span>
                )}
              </label>
              <input type={f.type === "password" ? "password" : "text"} value={formCreds[f.key] || ""}
                onChange={e => setFormCreds(c => ({ ...c, [f.key]: e.target.value }))}
                placeholder={
                  // Secrets get the "(kept)" mask in edit mode because
                  // the server never echoes them back.  Non-secrets
                  // (URL / email / account id / etc.) get pre-populated
                  // by openEdit so an empty placeholder is fine.
                  editingSourceId && f.type === "password"
                    ? "•••••• (kept)"
                    : (f.placeholder || "")
                } className="input-dark w-full text-xs" />
              {f.hint && (
                <p className="text-[10px] text-slate-600 mt-1 leading-snug">{f.hint}</p>
              )}
            </div>
          ))}
          <div className="flex items-center gap-3">
            <button onClick={handleTestConnection} disabled={testing} className="btn-secondary-sm">
              {testing ? "Testing..." : "Test Connection"}
            </button>
            {testResult && testResult.status === "success" && (
              <p className="text-[10px] text-green-400">{testResult.message}</p>
            )}
            {editingSourceId && !testResult && (
              <p className="text-[10px] text-slate-600">
                Test only validates fields you have entered; empty fields will use the stored value at save time.
              </p>
            )}
          </div>
          {testResult && testResult.status === "error" && (
            <IntegrationErrorCard error={testResult as IntegrationError} />
          )}
        </div>

        {/* Scope — bind this source's findings to a Repository or BU. */}
        <div className="space-y-3 p-3 rounded-lg bg-white/[0.02] border border-white/[0.06]">
          <div>
            <p className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Scope</p>
            <p className="text-[10px] text-slate-600 mt-1 leading-snug">
              Where findings from this source should land. Bind to a repository to inherit
              its ticketing destination and access controls; bind to a business unit to
              inherit BU-level routing. Leave on Organization-wide for cross-cutting sources.
            </p>
          </div>
          <div className="flex gap-1">
            {([
              { key: "organization", label: "Organization-wide" },
              { key: "business_unit", label: "Business Unit" },
              { key: "repository", label: "Repository" },
            ] as const).map((m) => (
              <button
                key={m.key}
                type="button"
                onClick={() => setFormScopeMode(m.key)}
                className={`text-[11px] px-2.5 py-1.5 rounded-lg border transition-all ${
                  formScopeMode === m.key
                    ? "bg-red-500/15 text-red-400 border-red-500/30"
                    : "bg-white/[0.02] text-slate-500 border-white/[0.06] hover:text-slate-300 hover:border-white/[0.14]"
                }`}
              >
                {m.label}
              </button>
            ))}
          </div>
          {formScopeMode === "repository" && (
            <div>
              <label className="text-[10px] text-slate-500 block mb-1">
                Repository <span className="text-red-400 cursor-help" title="Required" aria-label="Required field">*</span>
              </label>
              <select value={formTargetRepoId} onChange={(e) => setFormTargetRepoId(e.target.value)} className="select-dark w-full text-xs">
                <option value="">Select a repository…</option>
                {repoOptions.map((r) => (
                  <option key={r.id} value={r.id}>{r.name}</option>
                ))}
              </select>
              {repoOptions.length === 0 && (
                <p className="text-[10px] text-slate-600 mt-1">
                  No repositories found. Add one from the Repositories page first.
                </p>
              )}
            </div>
          )}
          {formScopeMode === "business_unit" && (
            <div>
              <label className="text-[10px] text-slate-500 block mb-1">
                Business Unit <span className="text-red-400 cursor-help" title="Required" aria-label="Required field">*</span>
              </label>
              <select value={formTargetBuId} onChange={(e) => setFormTargetBuId(e.target.value)} className="select-dark w-full text-xs">
                <option value="">Select a business unit…</option>
                {buOptions.map((b) => (
                  <option key={b.id} value={b.id}>{b.name}</option>
                ))}
              </select>
              {buOptions.length === 0 && (
                <p className="text-[10px] text-slate-600 mt-1">
                  No business units found. Define one from Settings → Access first.
                </p>
              )}
            </div>
          )}
        </div>

        {/* Source-specific config (per-source schema). */}
        {schema.config_fields?.map((field: any) => (
          <div key={field.key}>
            <label className="text-xs text-slate-400 block mb-1">
              {field.label}
              {field.required && (
                <> <span className="text-red-400 cursor-help" title="Required" aria-label="Required field">*</span></>
              )}
            </label>
            {field.type === "boolean" ? (
              <label className="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" checked={!!formConfig[field.key]}
                  onChange={e => setFormConfig(c => ({ ...c, [field.key]: e.target.checked }))}
                  className="rounded border-slate-600" style={{ accentColor: "#ef4444" }} />
                <span className="text-xs text-slate-400">Enable</span>
              </label>
            ) : field.type === "select" ? (
              <select value={formConfig[field.key] || ""} onChange={e => setFormConfig(c => ({ ...c, [field.key]: e.target.value }))} className="select-dark w-full">
                <option value="">Select...</option>
                {field.options?.map((opt: string) => <option key={opt} value={opt}>{opt}</option>)}
              </select>
            ) : (
              <input type={field.type === "number" ? "number" : "text"}
                value={formConfig[field.key] || ""} onChange={e => setFormConfig(c => ({ ...c, [field.key]: e.target.value }))}
                placeholder={field.placeholder || ""} className="input-dark w-full" />
            )}
            {field.hint && (
              <p className="text-[10px] text-slate-600 mt-1 leading-snug">{field.hint}</p>
            )}
          </div>
        ))}
      </div>
    );
  };

  // Settings-tab wrapper for the detail drawer.  The body is the
  // shared config form; the footer is a single Save row (no wizard
  // Back/Next in edit mode).
  const renderSourceSettingsTab = (_source: ScanSource): React.ReactNode => (
    <div className="space-y-5">
      {renderConfigFormBody()}
      <div className="flex items-center justify-end gap-2 pt-3 border-t border-white/[0.06]">
        <button
          onClick={() => {
            // Close the drawer + clear edit state so the next open
            // doesn't inherit half-filled fields from an abandoned edit.
            setDetailSource(null);
            setInitialDetailTab("overview");
            setConfiguring(null);
            setEditingSourceId(null);
          }}
          className="btn-secondary"
        >
          Cancel
        </button>
        <button onClick={handleSave} disabled={saving} className="btn-primary">
          {saving ? "Saving…" : "Save changes"}
        </button>
      </div>
    </div>
  );

  return (
    <AppShell>
      <div className="max-w-[1400px]">
        {loading ? (
          // Skeleton scaffold mirroring the category-grid layout. The
          // page either shows ~7 category cards on first paint or a
          // single connected-sources panel — the grid below covers the
          // default case (which is what users see on cold load).
          <div>
            <div className="mb-6 flex items-center justify-between">
              <Skeleton w={140} h={20} />
              <Skeleton w={180} h={32} radius={8} />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className="card p-5">
                  <div className="flex items-center gap-3">
                    <Skeleton w={44} h={44} radius={10} />
                    <div className="flex-1 space-y-2">
                      <Skeleton w="60%" h={14} />
                      <Skeleton w="80%" h={10} />
                    </div>
                  </div>
                  <Skeleton w="40%" h={10} className="mt-4" />
                </div>
              ))}
            </div>
          </div>
        ) : (
          <>

            {/* ═══════════════════════════════════════════════════
                LEVEL 1 — Category grid (default view).
                Mirrors /integrations exactly. Each category card
                surfaces "{N} available · {M} connected" so the user
                can see at a glance where they have coverage.
                A virtual "Connected" card at the top of the grid
                opens a flat view of every connected source for fast
                management.
                ═══════════════════════════════════════════════════ */}
            {!activeCategory && (
              <>
                <p className="text-sm text-slate-400 mb-6">
                  Scan secrets across your issue trackers, cloud storage, and CI / build surfaces
                </p>

                {/* Connected-sources summary strip — a slim full-width
                    bar above the catalog grid, shown only when the tenant
                    has at least one connected source. Opens the flat
                    cross-category management view ("_connected"). Kept OFF
                    the grid on purpose: the category cards below then form
                    a clean, symmetric single row instead of leaving a lone
                    card orphaned on a second row. */}
                {sources.length > 0 && (
                  <div onClick={() => setActiveCategory("_connected")}
                       className="card card-hover cursor-pointer group relative overflow-hidden mb-4 flex items-center gap-4 py-3">
                    <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-green-500 to-emerald-500 opacity-60 group-hover:opacity-100 transition-opacity" />
                    <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-green-500 to-emerald-500 flex items-center justify-center shrink-0 text-white opacity-90 group-hover:opacity-100 transition-opacity">
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="text-sm font-bold text-slate-200 group-hover:text-white transition-colors">Your connected sources</h3>
                      <p className="hidden sm:block text-xs text-slate-500 mt-0.5 truncate">Manage scans, scope, and schedules across every active source</p>
                    </div>
                    <div className="flex items-center gap-4 shrink-0">
                      <span className="flex items-center gap-1.5 text-xs text-green-400">
                        <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
                        {sources.length} connected
                      </span>
                      <span className="hidden sm:inline text-xs text-slate-500">
                        {sources.reduce((sum, s) => sum + (s.stats?.findings_count || 0), 0)} findings
                      </span>
                      <span className="flex items-center gap-1 text-xs font-medium text-slate-400 group-hover:text-white transition-colors">
                        <span className="hidden sm:inline">Manage all</span>
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
                      </span>
                    </div>
                  </div>
                )}

                {/* Catalog landing grid — a clean 3-wide row of category
                    cards. The connected-sources summary lives in the strip
                    above, so the grid holds only real categories. */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {/* Real category cards. */}
                  {CATEGORIES.map((cat) => {
                    const available = sourcesInCategory(cat.key).length;
                    const connected = connectedInCategory(cat.key).length;
                    return (
                      <div key={cat.key} onClick={() => setActiveCategory(cat.key)}
                           className="card card-hover cursor-pointer group relative overflow-hidden">
                        <div className={`absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r ${cat.color} opacity-60 group-hover:opacity-100 transition-opacity`} />
                        <div className="flex items-start gap-4 pt-2">
                          <div className={`w-11 h-11 rounded-xl bg-gradient-to-br ${cat.color} flex items-center justify-center shrink-0 text-white opacity-90 group-hover:opacity-100 transition-opacity`}>
                            {cat.icon}
                          </div>
                          <div className="flex-1 min-w-0">
                            <h3 className="text-sm font-bold text-slate-200 group-hover:text-white transition-colors">{cat.label}</h3>
                            <p className="text-xs text-slate-500 mt-0.5 line-clamp-2">{cat.description}</p>
                            <div className="flex items-center gap-3 mt-3">
                              <span className="text-[10px] text-slate-600">{available} available</span>
                              {connected > 0 && (
                                <span className="flex items-center gap-1 text-[10px] text-green-400">
                                  <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
                                  {connected} connected
                                </span>
                              )}
                            </div>
                          </div>
                          <svg className="w-4 h-4 text-slate-700 group-hover:text-slate-400 shrink-0 mt-1 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                          </svg>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </>
            )}

            {/* ═══════════════════════════════════════════════════
                LEVEL 2a — "All connected" flat view.
                Reached from the green Connected pseudo-card.

                Back navigation lives in the global header breadcrumb
                ("Sources › Connected"); the body-level back-bar that
                used to live here was redundant with that crumb.
                ═══════════════════════════════════════════════════ */}
            {activeCategory === "_connected" && (() => {
              // Apply ?type=<source_id> filter if present.  Lets the
              // unified type-card "View all N →" link land directly on
              // a list of just that type's instances.
              // Then apply the Active/Archived view filter — same UX
              // contract as the repos page toggle.  When `archiveView`
              // is "active", archived (is_active=false) instances are
              // hidden; when "archived", only those are shown.
              const baseFiltered = connectedTypeFilter
                ? sources.filter((s) => s.source_type === connectedTypeFilter)
                : sources;
              // Type filter chip on top of the URL-driven
              // connectedTypeFilter — lets a user further narrow the
              // unified list to a single source_type.  When the URL
              // already pins a type, the chip dropdown is hidden
              // (don't offer a second knob for the same axis).
              const typeFiltered = !connectedTypeFilter && typeFilter
                ? baseFiltered.filter((s) => s.source_type === typeFilter)
                : baseFiltered;
              // Attention chips: "stale" derived from the server-set
              // is_stale flag; "failed" matches sources whose last
              // scan ended in failure (last_scan_status from the
              // stats blob, populated by the worker after each run).
              const attentionFiltered = typeFiltered.filter((s) => {
                if (attentionFilter === "stale") return s.is_stale === true;
                if (attentionFilter === "failed") {
                  const st = (s.stats as any)?.last_scan_status;
                  return st === "failed";
                }
                return true;
              });
              const filteredSources = attentionFiltered.filter((s) =>
                archiveView === "archived" ? s.is_active === false : s.is_active !== false
              );
              const archivedCount = baseFiltered.filter((s) => s.is_active === false).length;
              const activeCount = baseFiltered.length - archivedCount;
              // Counts for the attention chips so we can show
              // "Stale · 3" rather than just "Stale".  Cheap loop —
              // sources is small (<= page_size).
              const staleCount = baseFiltered.filter((s) => s.is_stale === true && s.is_active !== false).length;
              const failedCount = baseFiltered.filter(
                (s) => (s.stats as any)?.last_scan_status === "failed" && s.is_active !== false,
              ).length;
              // Unique source_types in the current connected list, for
              // the type-filter dropdown options.  Hidden when the URL
              // already pins a type (see comment above).
              const typeOptionSet = new Set<string>();
              baseFiltered.forEach((s) => typeOptionSet.add(s.source_type));
              const typeOptions = Array.from(typeOptionSet).sort();
              // Resolve a human label for the filter chip — fall back
              // to the raw type id if metadata is missing.
              const filterMeta = connectedTypeFilter ? SOURCE_BY_ID[connectedTypeFilter] : null;
              const filterLabel = filterMeta?.label || connectedTypeFilter;
              return (
                <>
                  {/* Active / Archived view toggle — first control so
                      the user always knows which slice they're looking
                      at.  Defaults to Active; Archived surfaces only
                      paused instances with their Unarchive pill. */}
                  <div className="flex items-center gap-2 mb-3 flex-wrap">
                    <div className="inline-flex items-center rounded-md overflow-hidden border border-white/[0.08] bg-white/[0.02]">
                      {(["active", "archived"] as const).map((v) => (
                        <button
                          key={v}
                          onClick={() => setArchiveView(v)}
                          className={`px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
                            archiveView === v
                              ? "bg-red-500/15 text-red-300"
                              : "text-slate-500 hover:text-slate-300"
                          }`}
                          aria-pressed={archiveView === v}
                        >
                          {v === "active"
                            ? `Active${activeCount ? ` · ${activeCount}` : ""}`
                            : `Archived${archivedCount ? ` · ${archivedCount}` : ""}`}
                        </button>
                      ))}
                    </div>

                    {/* Attention chips — narrow to sources that need
                        triage.  Counts shown so users know whether
                        clicking will yield anything.  Hidden in the
                        Archived view (archived sources are deliberately
                        paused, so "stale" doesn't apply). */}
                    {archiveView === "active" && (staleCount > 0 || failedCount > 0) && (
                      <div className="inline-flex items-center rounded-md overflow-hidden border border-white/[0.08] bg-white/[0.02]">
                        {(
                          [
                            { key: "all" as const, label: "All", count: activeCount },
                            { key: "stale" as const, label: "Stale", count: staleCount },
                            { key: "failed" as const, label: "Failed", count: failedCount },
                          ]
                        ).map((c) => (
                          <button
                            key={c.key}
                            onClick={() => setAttentionFilter(c.key)}
                            disabled={c.count === 0 && c.key !== "all"}
                            className={`px-2.5 py-1.5 text-[11px] font-medium transition-colors disabled:opacity-30 disabled:cursor-not-allowed ${
                              attentionFilter === c.key
                                ? c.key === "stale"
                                  ? "bg-amber-500/15 text-amber-300"
                                  : c.key === "failed"
                                    ? "bg-red-500/15 text-red-300"
                                    : "bg-violet-500/15 text-violet-300"
                                : "text-slate-500 hover:text-slate-300"
                            }`}
                            aria-pressed={attentionFilter === c.key}
                          >
                            {c.label}
                            {c.count > 0 && c.key !== "all" && (
                              <span className="ml-1 opacity-80">· {c.count}</span>
                            )}
                          </button>
                        ))}
                      </div>
                    )}

                    {/* Type filter — only when the URL hasn't already
                        pinned a type via ?type=…, and there's more
                        than one type to choose from. */}
                    {!connectedTypeFilter && typeOptions.length > 1 && (
                      <select
                        value={typeFilter}
                        onChange={(e) => setTypeFilter(e.target.value)}
                        className="select-dark text-xs"
                        aria-label="Filter by source type"
                      >
                        <option value="">All types</option>
                        {typeOptions.map((t) => (
                          <option key={t} value={t}>
                            {SOURCE_BY_ID[t]?.label || t}
                          </option>
                        ))}
                      </select>
                    )}
                  </div>
                  {/* Active filter chip — only renders when the URL
                      carries ?type=... .  Shows what's being filtered
                      and provides an X to clear. */}
                  {connectedTypeFilter && (
                    <div className="flex items-center gap-2 mb-4">
                      <span className="text-xs text-slate-500">Showing</span>
                      <span className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md text-xs"
                            style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)" }}>
                        <span className="text-slate-200 font-medium">{filterLabel}</span>
                        <span className="text-slate-500">·</span>
                        <span className="text-slate-400">{filteredSources.length} instance{filteredSources.length === 1 ? "" : "s"}</span>
                        <button
                          onClick={() => nextRouter.replace("/sources/connected", { scroll: false })}
                          aria-label="Clear type filter"
                          className="text-slate-500 hover:text-slate-200 transition-colors ml-1"
                        >
                          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                          </svg>
                        </button>
                      </span>
                    </div>
                  )}
                  {filteredSources.length === 0 ? (
                    <div className="card text-center py-10 text-slate-500 text-sm">
                      {archiveView === "archived"
                        ? (connectedTypeFilter
                            ? `No archived ${filterLabel} instances.`
                            : "No archived sources. Archive an active source to manage it here.")
                        : (connectedTypeFilter
                            ? `No ${filterLabel} instances connected yet.`
                            : "No connected sources.")}
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                      {filteredSources.map((s) => renderConnectedCard(s))}
                    </div>
                  )}
                </>
              );
            })()}

            {/* ═══════════════════════════════════════════════════
                LEVEL 2b — Category detail.
                Connected (in this category) at top, available below.

                Back navigation lives in the global header breadcrumb
                ("Sources › <Category>") which is automatically derived
                from the URL.  The body-level back-bar that used to
                live here was duplicating that crumb 1:1.
                ═══════════════════════════════════════════════════ */}
            {activeCategoryMeta && (
              <>
                {/* Unified type-card grid — one card per source TYPE,
                    state-driven content (Configure vs rich-managed).
                    Replaces the old "Your X sources" + "Available X
                    sources" two-section layout that duplicated cards
                    for every already-connected type. */}
                <section>
                  {(() => {
                    const items = filteredCategorySources(activeCategory as SourceCategory);
                    if (items.length === 0) {
                      return (
                        <div className="card text-center py-10 text-slate-500 text-sm">
                          No sources match the current filter.
                        </div>
                      );
                    }
                    return (
                      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                        {items.map((src) => renderTypeCard(src))}
                      </div>
                    );
                  })()}
                </section>
              </>
            )}

            {/* Config form — slides in as a side drawer rather than
                expanding inline. Backdrop covers the catalog so the
                user knows where focus is, but the catalog stays
                rendered behind so they can change their mind without
                losing the page state. Closes on backdrop click, on
                the X button, or on Esc (handled in useEffect above). */}
            {/* Connect-new-source aside.  Gated on `!editingSourceId`
                so that Edit clicks (which set both `configuring` AND
                `editingSourceId`) flow into the detail drawer's
                Settings tab instead of opening this aside on top of
                that drawer. */}
            {configuring && schema && !editingSourceId && (
              <SideDrawer
                open
                onClose={() => { setConfiguring(null); setEditingSourceId(null); }}
                title={`Connect ${schema.label}`}
                subtitle={schema.description}
                icon={<BrandGlyph src={lookupSource(configuring)} className="w-4 h-4" />}
                iconGradient={lookupSource(configuring).gradient}
                footer={(() => {
                  // Wizard-aware footer.  Back/Next during walkthrough,
                  // Cancel/Connect on the last step (or always for
                  // non-wizard sources).
                  const wizardSteps = lookupSource(configuring).wizard;
                  const onLastStep = !wizardSteps || wizardStep >= wizardSteps.length - 1;
                  return (
                    <>
                      <button
                        onClick={() => {
                          if (wizardSteps && wizardStep > 0) {
                            setWizardStep(s => s - 1);
                          } else {
                            setConfiguring(null);
                            setEditingSourceId(null);
                          }
                        }}
                        className="btn-secondary"
                      >
                        {wizardSteps && wizardStep > 0 ? "Back" : "Cancel"}
                      </button>
                      {wizardSteps && !onLastStep ? (
                        <button onClick={() => setWizardStep(s => s + 1)} className="btn-primary">
                          Next
                        </button>
                      ) : (
                        <button onClick={handleSave} disabled={saving} className="btn-primary">
                          {saving ? "Connecting…" : "Connect"}
                        </button>
                      )}
                    </>
                  );
                })()}
              >
                {/* Setup wizard — only on CREATE mode for sources
                    that defined one. Edit mode skips the wizard
                    because the user is changing scope/schedule, not
                    re-doing first-run admin setup. The progress
                    indicator and step content render here; the form
                    fields below only show on the wizard's last step
                    (or always, if no wizard). */}
                {(() => {
                  const wizardSteps = !editingSourceId && configuring
                    ? lookupSource(configuring).wizard
                    : undefined;
                  if (!wizardSteps || wizardSteps.length === 0) return null;
                  const total = wizardSteps.length;
                  const step = wizardSteps[wizardStep];
                  return (
                    <div className="mb-5">
                      {/* Progress strip — equal-width segments, the
                          completed ones in the source's brand
                          gradient, the current one in red, the
                          remaining ones muted. Symmetric across all
                          M365 wizards because step counts match. */}
                      <div className="flex items-center gap-1.5 mb-4">
                        {wizardSteps.map((_, i) => (
                          <div key={i}
                               className={`flex-1 h-1 rounded-full transition-colors ${
                                 i < wizardStep
                                   ? `bg-gradient-to-r ${lookupSource(configuring).gradient}`
                                   : i === wizardStep
                                   ? "bg-red-500/70"
                                   : "bg-white/[0.06]"
                               }`} />
                        ))}
                      </div>
                      <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">
                        Step {wizardStep + 1} of {total}
                      </div>
                      <h4 className="text-base font-semibold text-white">{step.title}</h4>
                      <p className="text-[11px] text-slate-500 mt-0.5">{step.description}</p>
                      <div className="mt-4 space-y-3">
                        {step.body}
                      </div>
                      {step.externalLink && (
                        <a href={step.externalLink.url} target="_blank" rel="noopener noreferrer"
                           className="inline-flex items-center gap-1.5 mt-4 text-xs text-red-400 hover:text-red-300 transition-colors">
                          {step.externalLink.label}
                          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                              d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                          </svg>
                        </a>
                      )}
                      {/* Skip wizard for power users who already know
                          the drill — drops them directly to the form. */}
                      {wizardStep < total - 1 && (
                        <button onClick={() => setWizardStep(total - 1)}
                                className="mt-5 text-[10px] text-slate-500 hover:text-slate-300 underline-offset-2 hover:underline transition-colors">
                          Skip walkthrough — I already have an app set up
                        </button>
                      )}
                    </div>
                  );
                })()}

                {/* Form fields. Hidden on every wizard step EXCEPT
                    the last; sources without a wizard show them
                    always. Edit mode also shows them always. */}
                {/* Form fields — same JSX rendered in this aside AND
                    in the detail-drawer's Settings tab.  The IIFE
                    below still gates rendering on the wizard step
                    (form is hidden on every step EXCEPT the last;
                    edit mode always shows it, but edit mode opens
                    the detail drawer instead of this aside so the
                    gate effectively means "wizard step is the last
                    or there is no wizard"). */}
                {(() => {
                  const wizardSteps = !editingSourceId && configuring
                    ? lookupSource(configuring).wizard
                    : undefined;
                  const showForm = !wizardSteps
                    || editingSourceId
                    || wizardStep >= wizardSteps.length - 1;
                  if (!showForm) return null;
                  return renderConfigFormBody();
                })()}
              </SideDrawer>
            )}
          </>
        )}
      </div>

      {/* ── "Save anyway?" modal — Test Connection failed ───────── */}
      {/* Shown when the user explicitly tested the connection, saw an */}
      {/* error, then clicked Save without re-testing. Saving silently */}
      {/* in this case used to produce a green "Source Connected" toast */}
      {/* for a connection that was known-broken — a footgun. Now we */}
      {/* require explicit intent. Bug fix 2026-05-08. */}
      {confirmSaveDespiteFailedTest && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="save-anyway-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          onClick={() => !saving && setConfirmSaveDespiteFailedTest(false)}
        >
          <div
            className="card border-orange-500/20 max-w-md w-full mx-4"
            style={{ background: "rgba(14,18,40,0.7)" }}
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-orange-500/10 flex items-center justify-center shrink-0">
                <svg className="w-5 h-5 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                        d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <div>
                <h3 id="save-anyway-title" className="text-base font-semibold text-white">
                  Test Connection failed — save anyway?
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Vooda will save the source, but the first scan will fail until the connection is fixed.
                </p>
              </div>
            </div>
            <div className="bg-orange-500/5 border border-orange-500/10 rounded-lg p-3 mb-4">
              {/* Show the same structured error here as the wizard
                  panel — so the user sees the same fix-steps in the
                  modal they're about to dismiss. compact=true keeps
                  the modal narrow. */}
              {testResult ? (
                <IntegrationErrorCard error={testResult as IntegrationError} compact />
              ) : (
                <p className="text-xs text-slate-300 leading-relaxed">Connection test returned an error.</p>
              )}
            </div>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setConfirmSaveDespiteFailedTest(false)}
                disabled={saving}
                className="btn-secondary text-sm"
              >
                Go back &amp; fix
              </button>
              <button
                onClick={() => { handleSave(); }}
                disabled={saving}
                className="text-sm flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-orange-500/15 hover:bg-orange-500/25 text-orange-300 border border-orange-500/30"
              >
                {saving ? (
                  <>
                    <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Saving…
                  </>
                ) : (
                  <>Save anyway</>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Delete Source confirmation modal ───────────────────── */}
      {/* Shared destructive-action modal — identical UX on /repositories
          and /sources.  Renders impact preview from the
          /scan-sources/{id}/delete-preview endpoint and gates the
          permanent delete behind typed confirmation. */}
      {deleteTarget && (
        <DeleteConfirmModal
          preview={deletePreview}
          error={deletePreviewError}
          onCancel={() => setDeleteTarget(null)}
          onConfirm={confirmDelete}
          onArchive={() => archiveSource(deleteTarget)}
        />
      )}

      {/* ── Source detail drawer ──────────────────────────────────
          Right-side panel mounted at the page root so it floats over
          the entire SourcesPageInner content.  Opens when the user
          clicks a source card body OR clicks Edit (which lands on
          the Settings tab).  The Settings tab now renders the SAME
          form as the connect-aside via `renderSettings` — no more
          ping-pong to a second drawer.  Brand-glyph header matches
          the connect-aside so a user flipping between the two feels
          like one product. */}
      <SourceDetailDrawer
        source={detailSource}
        typeLabel={detailSource ? (typeSchemas[detailSource.source_type]?.label || detailSource.source_type) : undefined}
        icon={detailSource ? <BrandGlyph src={lookupSource(detailSource.source_type)} className="w-4 h-4" /> : undefined}
        iconGradient={detailSource ? lookupSource(detailSource.source_type).gradient : undefined}
        initialTab={initialDetailTab}
        renderSettings={(s) => renderSourceSettingsTab(s as ScanSource)}
        onClose={() => {
          setDetailSource(null);
          setInitialDetailTab("overview");
          // If the drawer was opened in Edit mode, clear the edit
          // state so the next "Connect new" flow starts clean.
          if (editingSourceId) {
            setConfiguring(null);
            setEditingSourceId(null);
          }
        }}
      />

      {/* Request-access modal — renders when the user clicks a
          status:"request" catalog tile.  Captures the optional
          use-case note, records the interest locally (until a
          demand-signal backend lands), and shows a clear confirmation
          via toast.  Closes on Esc + backdrop click. */}
      {requestAccessFor && (() => {
        const meta = SOURCE_BY_ID[requestAccessFor];
        return (
          <div
            className="fixed inset-0 z-[200] flex items-start justify-center pt-[10vh] px-4 vooda-fade-in"
            onClick={() => !requestAccessSubmitting && setRequestAccessFor(null)}
            role="dialog"
            aria-modal="true"
            aria-label={`Request access to ${meta?.label || "this integration"}`}
            style={{ background: "rgba(2, 4, 12, 0.65)", backdropFilter: "blur(8px)" }}
          >
            <div
              className="w-full max-w-md rounded-xl overflow-hidden"
              onClick={(e) => e.stopPropagation()}
              style={{
                background: "rgba(12, 15, 32, 0.98)",
                border: "1px solid rgba(245, 158, 11, 0.22)",
                boxShadow: "0 24px 80px rgba(0,0,0,0.6)",
              }}
            >
              <div
                className="px-5 py-4 flex items-center gap-3"
                style={{ borderBottom: "1px solid rgba(245,158,11,0.14)", background: "rgba(245,158,11,0.04)" }}
              >
                <svg className="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" style={{ color: "#fbbf24" }}>
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div className="min-w-0 flex-1">
                  <h2 className="text-base font-semibold text-white truncate">
                    Request access — {meta?.label || requestAccessFor}
                  </h2>
                  <p className="text-[11px] text-slate-500 mt-0.5">
                    This integration is on the roadmap. Tell us your use case and we'll prioritize accordingly.
                  </p>
                </div>
              </div>

              <div className="px-5 py-4 space-y-3">
                <div>
                  <label className="text-[10px] uppercase tracking-wider text-slate-500 font-medium block mb-1.5">
                    How would you use it? <span className="text-slate-600 normal-case tracking-normal">(optional, helps prioritize)</span>
                  </label>
                  <textarea
                    value={requestAccessUseCase}
                    onChange={(e) => setRequestAccessUseCase(e.target.value)}
                    placeholder="e.g. 'We use Google Chat as our primary engineering channel. We've had three credential pastes in DMs this quarter and need scanning.'"
                    rows={4}
                    disabled={requestAccessSubmitting}
                    className="input-dark text-sm w-full"
                    autoFocus
                  />
                </div>
                <p className="text-[10px] text-slate-600 leading-relaxed">
                  Your request is recorded against your tenant. When demand crosses our prioritization threshold,
                  engineering commits a quarter and we'll email you when early access is available.
                </p>
              </div>

              <div
                className="px-5 py-3 flex items-center justify-end gap-2"
                style={{ borderTop: "1px solid rgba(255,255,255,0.06)", background: "rgba(255,255,255,0.015)" }}
              >
                <button
                  onClick={() => setRequestAccessFor(null)}
                  disabled={requestAccessSubmitting}
                  className="btn-secondary-sm"
                >
                  Cancel
                </button>
                <button
                  onClick={handleRequestAccess}
                  disabled={requestAccessSubmitting}
                  className="inline-flex items-center justify-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-all duration-200 select-none"
                  style={{
                    color: "#0c1024",
                    background: "#fbbf24",
                    border: "1px solid #f59e0b",
                    cursor: requestAccessSubmitting ? "not-allowed" : "pointer",
                  }}
                >
                  {requestAccessSubmitting ? "Submitting…" : "Submit request"}
                </button>
              </div>
            </div>
          </div>
        );
      })()}
    </AppShell>
  );
}

// Default export wraps the inner component in `<Suspense>`.  The
// fallback mirrors the skeleton scaffold of the loaded view so the
// suspense boundary doesn't flash a blank screen during hydration.
export default function SourcesPage(props: { initialCategory?: string } = {}) {
  return (
    <Suspense
      fallback={
        <AppShell>
          <div className="max-w-[1400px]">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className="card p-5">
                  <div className="flex items-center gap-3">
                    <div className="w-11 h-11 rounded-xl bg-white/[0.04]" />
                    <div className="flex-1 space-y-2">
                      <div className="h-3.5 bg-white/[0.04] rounded w-2/3" />
                      <div className="h-2.5 bg-white/[0.04] rounded w-4/5" />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </AppShell>
      }
    >
      <SourcesPageInner {...props} />
    </Suspense>
  );
}
