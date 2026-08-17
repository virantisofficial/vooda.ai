"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useEffect, useRef, useState, Suspense, createContext, useContext, type ReactNode } from "react";
import { useSearchParams } from "next/navigation";

import AppShell from "@/components/layout/AppShell";
import ScannerConnectModal from "@/components/integrations/ScannerConnectModal";
import ScannerIcon from "@/components/integrations/ScannerIcons";
import api, {
  getIntegrations, deleteIntegration, updateIntegration,
  getAIModels, createAIModel, updateAIModel, deleteAIModel, testAIModel, getAITaskRouting,
  getAIEngineSettings, updateAIEngineSettings, discoverModels, getAutoConfig,
  getNotificationRules, updateNotificationRules,
  getProviderSchema, testIntegrationConnection, createIntegration, getBusinessUnits, getRepositories,
} from "@/lib/api";
import SearchableSelect from "@/components/ui/SearchableSelect";
import { useToast } from "@/components/ui/Toast";

// ═══════════════════════════════════════════════════════════════
//  Section-action context
//  ─────────────────────────────────────────────────────────────
//  Lifts each section's primary "Add X" button (or any other right-
//  aligned header control) into the page-level breadcrumb row, so
//  the back-bar and the action button share one row instead of
//  stacking into two.  Saves ~80px of vertical chrome per page
//  view; matches the single-line header pattern shipped on
//  /sources (where Back + category indicator + sub-controls all
//  live on one row).
//
//  Sections register their current action via useEffect:
//
//    const { setAction } = useContext(SectionActionContext);
//    useEffect(() => {
//      setAction(<button onClick={...}>+ Add Channel</button>);
//      return () => setAction(null);
//    }, [showForm, ...]);
//
//  The provider lives on the IntegrationsPage component and clears
//  the slot when activeCategory changes (so a stale action from
//  a previously-rendered section can't leak into the next one).
//  Added 2026-05-14.
// ═══════════════════════════════════════════════════════════════
const SectionActionContext = createContext<{
  setAction: (node: ReactNode | null) => void;
}>({ setAction: () => {} });

// ═══════════════════════════════════════════════════════════════
//  TYPES & DATA
// ═══════════════════════════════════════════════════════════════

// "cloud_connectors" category removed 2026-05-16 — its only purpose was NHI
// discovery and NHI was removed alongside the governance refocus.
// "siem" tile removed 2026-05-19 — functionality relocated to
// Settings → Audit & Compliance → Audit Log Streaming (org-level
// setting rather than a per-scanner integration tile).  Removing
// it also lands the Integrations hub at a clean 3×2 = 6 grid.
type HubCategory = "scanners" | "ai_models" | "notifications" | "webhooks" | "ticketing" | "identity";

interface CategoryDef {
  key: HubCategory;
  label: string;
  description: string;
  icon: React.ReactNode;
  color: string;
  count?: number;
}

interface ScannerDef {
  name: string;
  provider: string;
  type: string;
  formats: string[];
  color: string;
}

interface SavedIntegration {
  id: string;
  name: string;
  provider: string;
  integration_type: string;
  is_active: boolean;
  config: Record<string, string>;
  created_at: string;
  scope_level?: string;
  business_unit_id?: string;
  repository_id?: string;
}

const SCANNERS: ScannerDef[] = [];  // Vooda AI is the scanner — no external imports needed

const NOTIFICATION_CHANNELS = [
  { name: "Slack", provider: "slack", description: "Channel notifications and alerts", color: "from-purple-600 to-pink-500",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M5.5 9.5A1.5 1.5 0 117 8h3.5v3.5A1.5 1.5 0 019 13H8a1.5 1.5 0 01-1.5-1.5V9.5zM18.5 9.5A1.5 1.5 0 1017 8h-3.5v3.5A1.5 1.5 0 0015 13h1a1.5 1.5 0 001.5-1.5V9.5zM5.5 14.5A1.5 1.5 0 107 16h3.5v-3.5A1.5 1.5 0 019 11H8a1.5 1.5 0 00-1.5 1.5v2zM18.5 14.5A1.5 1.5 0 1117 16h-3.5v-3.5A1.5 1.5 0 0115 11h1a1.5 1.5 0 011.5 1.5v2z" /></svg>) },
  { name: "Microsoft Teams", provider: "teams", description: "Incoming webhook connector", color: "from-indigo-500 to-blue-600",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="14" cy="7" r="2.5" /><rect x="3" y="10" width="12" height="9" rx="1" /><path d="M17 11v6a2 2 0 002 2h0a2 2 0 002-2v-3a2 2 0 00-2-2h-2" /></svg>) },
  { name: "Email (SMTP)", provider: "email", description: "Scan reports and alerts", color: "from-cyan-500 to-teal-500",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="3" y="5" width="18" height="14" rx="2" /><path d="M3 7l9 6 9-6" /></svg>) },
  { name: "Custom Webhook (Outbound)", provider: "webhook", description: "Send alerts to your custom endpoint via HTTP POST", color: "from-slate-500 to-slate-600",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="6" cy="12" r="2" /><circle cx="18" cy="6" r="2" /><circle cx="18" cy="18" r="2" /><path d="M8 12h4l4-6M12 12l4 6" /></svg>) },
  { name: "PagerDuty", provider: "pagerduty", description: "Critical finding escalation", color: "from-green-500 to-emerald-500",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" /></svg>) },
];

// Connection-form fields per provider. The section header already
// names the provider (Jira, ServiceNow, Linear) so labels here drop
// the redundant prefix — "Site URL" reads cleaner than "Jira Site
// URL" when the panel is already titled Jira. Hint text is shown
// directly under the input for fields whose meaning isn't obvious
// from the label alone.
const TICKETING_TOOLS = [
  { name: "Jira", provider: "jira", description: "Create issues from findings", color: "from-blue-500 to-indigo-500",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 2L2 12l10 10 10-10L12 2z" /><path d="M12 8v8M8 12h8" strokeLinecap="round" /></svg>),
    fields: [
      { key: "site_url", label: "Site URL", type: "url", required: true, placeholder: "https://yourteam.atlassian.net",
        hint: "Your Atlassian Cloud workspace URL" },
      { key: "email", label: "Account Email", type: "email", required: true,
        hint: "The Atlassian account that owns the API token below" },
      // Generate API tokens at id.atlassian.com — the user creates the
      // token themselves and pastes it here. (We removed the inline
      // "Get token →" link 2026-04-27 because it was just a deep-link
      // to Atlassian's token page; the user already knows where to go
      // and the link added more visual noise than value.)
      { key: "api_token", label: "API Token", type: "password", required: true,
        hint: "Generate at id.atlassian.com → Security → API tokens" },
      // project_key + issue_type are rendered as <select> dropdowns
      // populated from the live Jira API (see loadJiraProjects /
      // loadJiraIssueTypes in TicketingSection). Until a successful
      // Test Connection runs they degrade gracefully to a free-text
      // input so first-time setup still works.
      //
      // Label clarification 2026-04-27: this destination field used
      // to be labeled "Project". On the same form the Scope section
      // talks about a Vooda "Repository", and several places in the
      // app already use "Project" (Jira / GCP / Azure DevOps) — two
      // different "project" meanings on one screen was user-reported
      // confusing. This field is now explicitly "Jira Project" (the
      // destination where tickets land); "Repository" stays the
      // unambiguous name for the Vooda source-of-findings unit.
      { key: "project_key", label: "Jira Project", type: "text", required: true,
        placeholder: "Test connection to load your Jira projects",
        hint: "The Jira project where Vooda will file tickets (e.g. VOOD, ENG, SECURITY)." },
      // Issue Type — selected once per board, applied to every
      // ticket Vooda creates from a secret finding. The dropdown
      // exists because different Jira projects expose different
      // types (VOOD has only Task/Epic; TRUF has the full software
      // set). It auto-pre-picks Bug → Task → Story → first
      // available once issue types load, so the user only has to
      // override if their team uses a custom type for security
      // work. (User feedback 2026-04-27: the raw 5-option dropdown
      // implied an important per-finding decision when really it's
      // a one-time setup choice.)
      { key: "issue_type", label: "Issue Type", type: "text", required: true,
        placeholder: "Auto-selected after Jira project loads",
        hint: "All tickets Vooda creates on this board are filed as this type. Pre-picks Bug (or Task if Bug isn't available); override only if your team uses a different type." },
    ] },
  { name: "ServiceNow", provider: "servicenow", description: "Create security incidents automatically", color: "from-green-500 to-teal-500",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="9" /><path d="M12 8v4l2 2" strokeLinecap="round" /></svg>),
    fields: [
      { key: "instance_url", label: "Instance URL", type: "url", required: true, placeholder: "https://yourinstance.service-now.com",
        hint: "Your ServiceNow instance — paste just the hostname (paths get stripped automatically)." },
      { key: "username", label: "Username", type: "text", required: true,
        hint: "Service-account username (e.g. vooda-ai). Use a service account so token rotation is independent of any human user." },
      { key: "password", label: "Password or API Token", type: "password", required: true,
        hint: "Service-account credential — basic auth password or OAuth token. Generate at System OAuth → Application Registry." },
      // assignment_group renders as a dropdown once the auto-loader
      // populates it (after Test Connection or as soon as creds are
      // typed). Falls back to a free-text input until the lookup
      // succeeds — first-time setup doesn't get blocked.
      { key: "assignment_group", label: "Assignment Group", type: "text", required: false,
        placeholder: "Auto-loaded after credentials are entered",
        hint: "Group that owns the incident. Auto-defaults to Security Operations if your instance has it." },
    ] },
  { name: "Custom Webhook", provider: "custom_ticketing", description: "Send findings to any ticketing system via webhook", color: "from-slate-500 to-slate-600",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="4" y="4" width="16" height="16" rx="2" /><path d="M9 9l3 3-3 3M13 15h3" strokeLinecap="round" strokeLinejoin="round" /></svg>),
    fields: [
      { key: "webhook_url", label: "Webhook URL", type: "url", required: true,
        hint: "Receives a POST with the finding payload (JSON)" },
      { key: "auth_header", label: "Authorization Header", type: "password", required: false, placeholder: "Bearer your-token",
        hint: "Optional — sent as the Authorization HTTP header on every request" },
    ] },
];

const SSO_PROVIDERS = [
  { name: "SAML 2.0", provider: "saml", description: "Enterprise SSO via SAML assertions", color: "from-blue-500 to-indigo-500",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" /><rect x="3" y="5" width="18" height="14" rx="2" /><path d="M3 9h18" /></svg>),
    fields: [
      { key: "idp_metadata_url", label: "IdP Metadata URL", type: "url", required: true, placeholder: "https://idp.example.com/metadata.xml" },
      { key: "entity_id", label: "SP Entity ID", type: "text", required: true, placeholder: "https://vooda.example.com/saml" },
      { key: "acs_url", label: "ACS URL (auto-generated)", type: "text", required: false, placeholder: "https://vooda.example.com/api/v1/sso/saml/callback" },
      { key: "certificate", label: "IdP Certificate (PEM)", type: "password", required: false },
    ] },
  { name: "OpenID Connect", provider: "oidc", description: "OAuth 2.0 / OIDC for modern apps", color: "from-purple-500 to-pink-500",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="9" /><path d="M12 3v18" /><ellipse cx="12" cy="12" rx="4" ry="9" /></svg>),
    fields: [
      { key: "client_id", label: "Client ID", type: "text", required: true },
      { key: "client_secret", label: "Client Secret", type: "password", required: true },
      { key: "issuer_url", label: "Issuer URL", type: "url", required: true, placeholder: "https://accounts.google.com" },
      { key: "redirect_uri", label: "Redirect URI (auto-generated)", type: "text", required: false, placeholder: "https://vooda.example.com/api/v1/sso/oidc/callback" },
    ] },
  { name: "Okta", provider: "okta", description: "Okta workforce identity", color: "from-blue-500 to-blue-600",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="3" fill="currentColor" stroke="none" opacity="0.4" /></svg>),
    fields: [
      { key: "okta_domain", label: "Okta Domain", type: "url", required: true, placeholder: "https://yourorg.okta.com" },
      { key: "client_id", label: "Client ID", type: "text", required: true },
      { key: "client_secret", label: "Client Secret", type: "password", required: true },
    ] },
  { name: "Azure AD / Entra ID", provider: "azure_ad", description: "Microsoft Entra ID", color: "from-cyan-500 to-blue-500",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M3 17l6-12h6l6 12" strokeLinecap="round" strokeLinejoin="round" /><path d="M7.5 17h9" strokeLinecap="round" /></svg>),
    fields: [
      { key: "tenant_id", label: "Tenant ID", type: "text", required: true },
      { key: "client_id", label: "Application (Client) ID", type: "text", required: true },
      { key: "client_secret", label: "Client Secret", type: "password", required: true },
    ] },
  { name: "Google Workspace", provider: "google_sso", description: "Google Cloud Identity SSO", color: "from-red-500 to-yellow-500",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="9" /><path d="M12 7v5l4 2" strokeLinecap="round" /></svg>),
    fields: [
      { key: "client_id", label: "OAuth Client ID", type: "text", required: true },
      { key: "client_secret", label: "OAuth Client Secret", type: "password", required: true },
      { key: "hosted_domain", label: "Hosted Domain (restrict to org)", type: "text", required: false, placeholder: "yourcompany.com" },
    ] },
  { name: "LDAP / Active Directory", provider: "ldap_sso", description: "On-premise directory authentication", color: "from-slate-500 to-slate-600",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="6" y="3" width="12" height="5" rx="1" /><rect x="6" y="10" width="12" height="5" rx="1" /><rect x="6" y="17" width="12" height="4" rx="1" /><circle cx="15" cy="5.5" r="1" fill="currentColor" stroke="none" /></svg>),
    fields: [
      { key: "server_url", label: "LDAP Server URL", type: "url", required: true, placeholder: "ldaps://ad.company.com:636" },
      { key: "bind_dn", label: "Bind DN", type: "text", required: true, placeholder: "CN=admin,DC=company,DC=com" },
      { key: "bind_password", label: "Bind Password", type: "password", required: true },
      { key: "base_dn", label: "User Search Base DN", type: "text", required: true, placeholder: "OU=Users,DC=company,DC=com" },
    ] },
];

// SIEM_TOOLS removed 2026-05-19 — relocated to
// `apps/web/src/components/secrets/AuditLogStreaming.tsx` and
// rendered under Settings → Audit & Compliance.  Backend storage
// (`integrations.integration_type = "siem"`) is unchanged so old
// configs migrate automatically.

// ═══════════════════════════════════════════════════════════════
//  STATUS BADGE
// ═══════════════════════════════════════════════════════════════

function StatusBadge({ status }: { status?: string }) {
  if (status === "coming_soon") return (
    <span className="text-[9px] px-2 py-0.5 rounded-full bg-slate-500/15 text-slate-500 border border-slate-500/20">Coming Soon</span>
  );
  if (status === "template") return (
    <span className="text-[9px] px-2 py-0.5 rounded-full bg-red-500/15 text-red-400 border border-red-500/20">Template</span>
  );
  if (status === "webhook") return (
    <span className="text-[9px] px-2 py-0.5 rounded-full bg-green-500/15 text-green-400 border border-green-500/20">Webhook</span>
  );
  return null;
}

// ═══════════════════════════════════════════════════════════════
//  INTEGRATION CARD (generic — used across all categories)
// ═══════════════════════════════════════════════════════════════

function IntegrationCard({ name, icon, color, description, status, isConnected, formats, onClick }: {
  name: string; icon?: React.ReactNode; color: string; description: string;
  status?: string; isConnected?: boolean; formats?: string[]; onClick?: () => void;
}) {
  const disabled = status === "coming_soon";
  return (
    <div
      onClick={disabled ? undefined : onClick}
      className={`group relative rounded-xl border p-4 transition-all duration-200 ${
        disabled ? "border-white/[0.03] bg-white/[0.01] opacity-60 cursor-default"
        : isConnected ? "border-green-500/20 bg-white/[0.02] cursor-pointer hover:border-green-500/30 hover:bg-white/[0.04]"
        : "border-white/[0.06] bg-white/[0.02] cursor-pointer hover:border-white/[0.12] hover:bg-white/[0.04]"
      }`}
      style={{ boxShadow: disabled ? "none" : undefined }}
    >
      {isConnected && (
        <div className="absolute top-3 right-3 pointer-events-none">
          <span className="flex items-center gap-1 text-[9px] px-2 py-0.5 rounded-full bg-green-500/15 text-green-400 border border-green-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
            Connected
          </span>
        </div>
      )}
      <div className="flex items-start gap-3">
        <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${color} flex items-center justify-center shrink-0 text-white`}>
          {icon || <ScannerIcon provider={name.toLowerCase()} className="w-5 h-5" />}
        </div>
        <div className="flex-1 min-w-0 pt-0.5">
          <div className="flex items-center gap-2">
            <h4 className={`text-sm font-semibold ${disabled ? "text-slate-500" : "text-slate-200 group-hover:text-white"} transition-colors`}>{name}</h4>
            <StatusBadge status={status} />
          </div>
          <p className="text-xs text-slate-500 mt-0.5 line-clamp-1">{description}</p>
          {formats && formats.length > 0 && (
            <div className="flex gap-1 mt-2">
              {formats.map((f) => (
                <span key={f} className="text-[9px] px-1.5 py-0.5 rounded bg-white/[0.04] text-slate-500 border border-white/[0.04]">{f}</span>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  CATEGORY SECTION (renders a grid of IntegrationCards)
// ═══════════════════════════════════════════════════════════════

function CategorySection({ title, description, children }: { title: string; description: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-4">
        <h3 className="text-base font-bold text-white">{title}</h3>
        <p className="text-sm text-slate-500 mt-0.5">{description}</p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
        {children}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  CONNECTED INTEGRATIONS BANNER
// ═══════════════════════════════════════════════════════════════

function ConnectedBanner({ integrations, onDisconnect, onReconfigure }: {
  integrations: SavedIntegration[];
  onDisconnect: (id: string) => void;
  onReconfigure: (provider: string) => void;
}) {
  if (integrations.length === 0) return null;
  return (
    <div className="card bg-gradient-to-r from-green-500/[0.03] to-orange-500/[0.03] border-green-500/10">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
          <h3 className="text-sm font-semibold text-green-400">{integrations.length} Active Connection{integrations.length > 1 ? "s" : ""}</h3>
        </div>
      </div>
      <div className="flex gap-3 flex-wrap">
        {integrations.map((i) => {
          const scanner = SCANNERS.find((s) => s.provider === i.provider);
          return (
            <div key={i.id} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/[0.03] border border-white/[0.06] group/item">
              <div className={`w-6 h-6 rounded bg-gradient-to-br ${scanner?.color || "from-slate-500 to-slate-600"} flex items-center justify-center text-white`}>
                <ScannerIcon provider={i.provider} className="w-3.5 h-3.5" />
              </div>
              <span className="text-xs text-slate-300 font-medium">{i.name}</span>
              <div className="flex gap-1 opacity-0 group-hover/item:opacity-100 transition-opacity">
                <button onClick={() => onReconfigure(i.provider)} className="text-[10px] text-slate-500 hover:text-red-400" title="Reconfigure">⚙</button>
                <button onClick={() => onDisconnect(i.id)} className="text-[10px] text-slate-500 hover:text-red-400" title="Disconnect">×</button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  AI MODELS FULL SECTION (with task routing + registered models)
// ═══════════════════════════════════════════════════════════════

const AI_PROVIDERS = [
  { value: "anthropic", label: "Anthropic (Claude)", requiresKey: true, requiresEndpoint: false, color: "from-orange-500 to-red-400",
    keyPlaceholder: "sk-ant-...",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3L4 9v6l8 6 8-6V9l-8-6z" strokeLinejoin="round" /><path d="M12 9v6M9 12h6" strokeLinecap="round" /></svg>) },
  { value: "openai", label: "OpenAI", requiresKey: true, requiresEndpoint: false, color: "from-green-500 to-emerald-500",
    keyPlaceholder: "sk-...",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="3" /><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" strokeLinecap="round" /></svg>) },
  { value: "google", label: "Google (Gemini)", requiresKey: true, requiresEndpoint: false, color: "from-red-500 to-yellow-500",
    keyPlaceholder: "AIza...",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="9" /><path d="M12 7v5l4 2" strokeLinecap="round" /></svg>) },
  { value: "azure_openai", label: "Azure OpenAI", requiresKey: true, requiresEndpoint: true, color: "from-blue-500 to-cyan-500",
    keyPlaceholder: "Azure API key",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M3 17l6-12h6l6 12" strokeLinecap="round" strokeLinejoin="round" /><path d="M7.5 17h9" strokeLinecap="round" /></svg>) },
  { value: "aws_bedrock", label: "AWS Bedrock", requiresKey: true, requiresEndpoint: true, color: "from-yellow-500 to-orange-500",
    keyPlaceholder: "AWS access key",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 3v18M3 12h18" strokeLinecap="round" /><path d="M12 3l-5 5M12 3l5 5" strokeLinecap="round" strokeLinejoin="round" opacity="0.5" /></svg>) },
  { value: "ollama", label: "Ollama (Local)", requiresKey: false, requiresEndpoint: true, color: "from-slate-400 to-slate-600",
    keyPlaceholder: "",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="4" /><path d="M12 2v4M12 18v4M2 12h4M18 12h4" strokeLinecap="round" /></svg>) },
  { value: "custom", label: "Custom / Self-Hosted", requiresKey: false, requiresEndpoint: true, color: "from-purple-500 to-indigo-500",
    keyPlaceholder: "Optional — leave blank if no auth required",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="4" y="4" width="16" height="16" rx="2" /><path d="M9 9l3 3-3 3M13 15h3" strokeLinecap="round" strokeLinejoin="round" /></svg>) },
];

// Single task — AI is only used for triage (false positive reduction + classification)
const AI_TASKS = [
  { key: "triage", label: "AI Triage", description: "False positive reduction and finding classification" },
];

function AIModelsFullSection() {
  // Register header action with the page-level breadcrumb — see
  // SectionActionContext at the top of the file for the contract.
  const { setAction } = useContext(SectionActionContext);
  const openAddRef = useRef<() => void>(() => {});
  const [models, setModels] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  // `tasks` is set implicitly to ["triage", "remediation"] — the only two
  // task strings the worker actually dispatches on. No UI surface; Vooda's
  // product model is one primary does everything, with task-level routing
  // reserved as a backend capability for future hybrid setups.
  const [form, setForm] = useState({ name: "", provider: "anthropic", model_id: "", api_key: "", endpoint_url: "", tasks: ["triage", "remediation"], is_primary: false, max_tokens: 4096, temperature: 0, context_window: 4096, stop_sequences: [] as string[], supports_json_mode: false, use_compact_prompt: false, system_prompt_override: "", prompt_strategy: "recommended", model_size_class: null as string | null, provider_config_json: "{}" });
  // Transient per-model test-connection status — replaces the jarring alert()
  // popups. Auto-dismisses ~5s after each test completes.
  const [testStatus, setTestStatus] = useState<Record<string, { status: string; message: string; at: number }>>({});
  const [providerConfigError, setProviderConfigError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [selectedModelParam, setSelectedModelParam] = useState<string | null>(null);
  const [menuOpen, setMenuOpen] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  // Model discovery state
  const [discoveredModels, setDiscoveredModels] = useState<any[]>([]);
  const [discovering, setDiscovering] = useState(false);
  const [discoverStatus, setDiscoverStatus] = useState<{ status: string; message: string } | null>(null);
  const [keyValidated, setKeyValidated] = useState(false);
  // Track the original model_id when entering edit mode. If the user swaps to
  // a different model, we auto-recompute backend defaults so stale per-model
  // values (max_tokens, context_window, etc.) don't leak across models.
  const [originalModelId, setOriginalModelId] = useState<string>("");
  const [defaultsRecomputedFor, setDefaultsRecomputedFor] = useState<string | null>(null);

  const loadModels = () => { getAIModels().then((r) => setModels(r.data || [])).catch(() => {}).finally(() => setLoading(false)); };
  useEffect(() => { loadModels(); }, []);

  // Close menu on click outside (replaces the previous full-viewport overlay
  // whose z-index could swallow clicks on the menu items themselves).
  useEffect(() => {
    if (!menuOpen) return;
    const onDown = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(null);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [menuOpen]);

  // When the user swaps model_id in Edit mode, auto-recompute backend defaults
  // (max_tokens, context_window, model_size_class, etc.) so stale values from
  // the previously-selected model don't persist. Debounced so that clicking
  // through the discovered-model list doesn't hammer the API.
  //
  // Also auto-retitle the display `name` when it still equals the previous
  // model_id — meaning the user never customized it. If they DID customize
  // (e.g. "Prod Primary"), we leave the name alone.
  useEffect(() => {
    if (!editingId || !form.model_id) return;
    if (form.model_id === originalModelId) return;  // unchanged — keep user's stored values
    const t = setTimeout(() => {
      applyAutoConfig(form.provider, form.model_id, form.prompt_strategy);
      setDefaultsRecomputedFor(form.model_id);
      setForm((f) => {
        // Only rewrite name if it still matches the original model_id —
        // preserves user-chosen labels like "Prod Primary" or "Team Sonnet".
        const nameLooksDefault = !f.name || f.name === originalModelId;
        return nameLooksDefault ? { ...f, name: form.model_id } : f;
      });
    }, 400);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [form.model_id, editingId, originalModelId]);

  const providerFor = (p: string) => AI_PROVIDERS.find((pr) => pr.value === p);

  const handleDiscoverModels = async (opts?: { modelConfigId?: string; preserveSelection?: boolean }) => {
    const prov = providerFor(form.provider);
    const needsKey = prov?.requiresKey ?? true;
    const usingStoredKey = !!opts?.modelConfigId;
    if (!usingStoredKey) {
      if (needsKey && !form.api_key) return;
      if (!needsKey && !form.endpoint_url) return;
    }
    setDiscovering(true);
    setDiscoverStatus(null);
    setDiscoveredModels([]);
    setKeyValidated(false);
    try {
      const payload: any = { provider: form.provider };
      if (form.api_key) payload.api_key = form.api_key;
      if (form.endpoint_url) payload.endpoint_url = form.endpoint_url;
      if (opts?.modelConfigId) payload.model_config_id = opts.modelConfigId;
      const r = await discoverModels(payload);
      const data = r.data;
      setDiscoverStatus({ status: data.status, message: data.message });
      if (data.status === "success" && data.models?.length > 0) {
        setDiscoveredModels(data.models);
        setKeyValidated(true);
        if (!opts?.preserveSelection) {
          const firstModel = data.models[0];
          setForm((f) => ({ ...f, model_id: firstModel.model_id, name: f.name || firstModel.model_id }));
          setSelectedModelParam(firstModel.parameter_size || null);
          applyAutoConfig(form.provider, firstModel.model_id, form.prompt_strategy, firstModel.parameter_size);
        }
      }
    } catch (e: any) {
      setDiscoverStatus({ status: "error", message: e.response?.data?.message || "Failed to validate key" });
    } finally {
      setDiscovering(false);
    }
  };

  const resetForm = () => {
    // Tasks always = triage + remediation (the only two keywords the worker
    // dispatches on). Routing is uniform across providers — the primary
    // fallback in get_provider_for_task handles everything.
    setForm({ name: "", provider: "anthropic", model_id: "", api_key: "", endpoint_url: "", tasks: ["triage", "remediation"], is_primary: false, max_tokens: 4096, temperature: 0, context_window: 4096, stop_sequences: [], supports_json_mode: false, use_compact_prompt: false, system_prompt_override: "", prompt_strategy: "recommended", model_size_class: null, provider_config_json: "{}" });
    setDiscoveredModels([]);
    setDiscoverStatus(null);
    setKeyValidated(false);
    setEditingId(null);
    setShowAdvanced(false);
    setSelectedModelParam(null);
    setOriginalModelId("");
    setDefaultsRecomputedFor(null);
    setProviderConfigError(null);
  };

  const handleEditModel = (model: any) => {
    setEditingId(model.id);
    setOriginalModelId(model.model_id || "");
    setDefaultsRecomputedFor(null);
    setForm({
      name: model.name || "",
      provider: model.provider || "anthropic",
      model_id: model.model_id || "",
      api_key: "",
      endpoint_url: model.endpoint_url || "",
      tasks: model.tasks || ["triage", "remediation"],
      is_primary: model.is_primary || false,
      max_tokens: model.max_tokens || 4096,
      temperature: model.temperature ?? 0,
      context_window: model.context_window || 4096,
      stop_sequences: model.stop_sequences || [],
      supports_json_mode: model.supports_json_mode || false,
      use_compact_prompt: model.use_compact_prompt || false,
      system_prompt_override: model.system_prompt_override || "",
      prompt_strategy: model.prompt_strategy || "recommended",
      model_size_class: model.model_size_class || null,
      provider_config_json: model.provider_config && Object.keys(model.provider_config).length > 0
        ? JSON.stringify(model.provider_config, null, 2)
        : "{}",
    });
    setProviderConfigError(null);
    setKeyValidated(true);  // Already validated since it's an existing model
    setDiscoveredModels([]);
    setDiscoverStatus(null);
    setShowForm(true);
    // Auto-load available models using stored credentials so the user can switch
    // without re-entering their API key.
    if (model.api_key_set || !providerFor(model.provider)?.requiresKey) {
      handleDiscoverModels({ modelConfigId: model.id, preserveSelection: true });
    }
    // Scroll to form
    setTimeout(() => document.getElementById("ai-model-form")?.scrollIntoView({ behavior: "smooth" }), 100);
  };

  const applyAutoConfig = async (provider: string, modelId: string, strategy: string, sizeOverride?: string) => {
    if (!modelId) return;
    try {
      const paramSize = selectedModelParam || sizeOverride || undefined;
      const r = await getAutoConfig({ provider, model_id: modelId, prompt_strategy: strategy, parameter_size: paramSize });
      const cfg = r.data?.config;
      if (cfg) {
        setForm((f) => ({
          ...f,
          max_tokens: cfg.max_tokens ?? f.max_tokens,
          temperature: cfg.temperature ?? f.temperature,
          context_window: cfg.context_window ?? f.context_window,
          stop_sequences: cfg.stop_sequences ?? f.stop_sequences,
          supports_json_mode: cfg.supports_json_mode ?? f.supports_json_mode,
          use_compact_prompt: cfg.use_compact_prompt ?? f.use_compact_prompt,
          model_size_class: cfg.model_size_class ?? f.model_size_class,
          system_prompt_override: strategy === "custom" ? f.system_prompt_override : (cfg.system_prompt_override || ""),
        }));
      }
    } catch { /* silently fail — user can still set manually */ }
  };

  const handleSave = async () => {
    // Validate provider_config JSON before submit — reject save rather than
    // silently ship invalid config that would break the OpenAI payload.
    let parsedProviderConfig: any = {};
    try {
      parsedProviderConfig = form.provider_config_json.trim()
        ? JSON.parse(form.provider_config_json)
        : {};
      setProviderConfigError(null);
    } catch (e: any) {
      setProviderConfigError(`Invalid JSON: ${e.message}`);
      setShowAdvanced(true); // open the accordion so the user sees the error
      return;
    }

    setSaving(true);
    try {
      if (editingId) {
        // Update existing model
        const updateData: any = {
          name: form.name, model_id: form.model_id, tasks: form.tasks, is_primary: form.is_primary,
          max_tokens: form.max_tokens, temperature: form.temperature, context_window: form.context_window,
          stop_sequences: form.stop_sequences, supports_json_mode: form.supports_json_mode,
          use_compact_prompt: form.use_compact_prompt, system_prompt_override: form.system_prompt_override || null,
          prompt_strategy: form.prompt_strategy, model_size_class: form.model_size_class,
          provider_config: parsedProviderConfig,
        };
        if (form.api_key) updateData.api_key = form.api_key;
        if (form.endpoint_url) updateData.endpoint_url = form.endpoint_url;
        await updateAIModel(editingId, updateData);
      } else {
        // Create new model
        const createPayload: any = { ...form, provider_config: parsedProviderConfig };
        delete createPayload.provider_config_json;
        await createAIModel(createPayload);
      }
      setShowForm(false);
      resetForm();
      loadModels();
    } finally { setSaving(false); }
  };

  const apiErr = (e: any, fallback: string) =>
    e?.response?.data?.detail || e?.response?.data?.message || e?.message || fallback;

  const handleDelete = async (id: string) => {
    try {
      await deleteAIModel(id);
    } catch (e: any) {
      alert(`Failed to remove provider: ${apiErr(e, "Unknown error")}`);
      return;
    }
    setMenuOpen(null); setConfirmDelete(null);
    if (editingId === id) { setShowForm(false); resetForm(); }
    loadModels();
  };

  const handleSetPrimary = async (id: string) => {
    setMenuOpen(null);
    try {
      await updateAIModel(id, { is_primary: true });
    } catch (e: any) {
      alert(`Failed to set as primary: ${apiErr(e, "Unknown error")}`);
      return;
    }
    loadModels();
  };

  const handleToggleActive = async (id: string) => {
    setMenuOpen(null);
    const m = models.find((x: any) => x.id === id);
    if (!m) return;
    try {
      await updateAIModel(id, { is_active: !m.is_active });
    } catch (e: any) {
      alert(`Failed to update provider: ${apiErr(e, "Unknown error")}`);
      return;
    }
    loadModels();
  };

  const handleTest = async (id: string) => {
    setMenuOpen(null);
    // Show a "testing..." badge immediately so the user gets feedback
    setTestStatus((prev) => ({
      ...prev,
      [id]: { status: "testing", message: "Testing connection…", at: Date.now() },
    }));
    const writeResult = (status: string, message: string) => {
      setTestStatus((prev) => ({ ...prev, [id]: { status, message, at: Date.now() } }));
      // Auto-dismiss after 8 seconds
      setTimeout(() => {
        setTestStatus((prev) => {
          const cur = prev[id];
          if (!cur || Date.now() - cur.at < 7500) return prev;
          const next = { ...prev };
          delete next[id];
          return next;
        });
      }, 8000);
    };
    try {
      const r = await testAIModel({ model_config_id: id });
      const d = r.data;
      if (d?.status === "success") {
        writeResult("success", `Connected · ${d.latency_ms ?? "?"} ms`);
      } else {
        writeResult("error", d?.message || d?.error || "Test failed");
      }
    } catch (e: any) {
      writeResult("error", apiErr(e, "Connection test failed"));
    }
  };

  // The Add Provider affordance now lives INLINE in the Configured
  // Providers card header (see below) rather than in the page-level
  // breadcrumb row.  Rationale (2026-05-19): user-driven design
  // consolidation — every integration sub-section now owns its Add
  // button next to its own header, matching the Webhooks / Ticketing
  // / Identity / SIEM / Vault tile-based pattern.  The previous
  // SectionActionContext header button felt like a page-level
  // primary action even though the work happens inside the card.
  openAddRef.current = () => setShowForm(true);

  return (
    <div>
      {/* ── Configured Providers ──
          Header is a flex row so the Add Provider button can sit
          inline with the title — same pattern as Notifications and
          (visually) the Vault "+ Add Vault" affordance.  Button
          hides while the form is open so the user has a single Add
          surface to focus on. */}
      <div className="card mb-5">
        <div className="flex items-center justify-between mb-4 gap-3">
          <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Configured Providers</h4>
          {!showForm && (
            <button onClick={() => openAddRef.current()} className="btn-primary text-xs px-3 py-1.5 flex items-center gap-1.5 shrink-0">
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 4v16m8-8H4" />
              </svg>
              Add Provider
            </button>
          )}
        </div>
        {loading ? (
          <div className="text-center py-8"><div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin mx-auto" /></div>
        ) : models.length === 0 ? (
          <div className="text-center py-10">
            <p className="text-sm text-slate-500">No AI provider configured</p>
            <p className="text-xs text-slate-600 mt-1">Add a provider to enable AI-powered false positive reduction on scan results</p>
          </div>
        ) : (
          <div className="space-y-3">
            {models.map((model: any) => {
              const pDef = providerFor(model.provider);
              return (
                <div key={model.id} className={`relative bg-white/[0.02] border rounded-xl p-4 flex items-center gap-4 ${model.is_active ? "border-white/[0.06]" : "border-white/[0.02]"} ${menuOpen === model.id ? "z-40" : ""}`}>
                  <div className={`w-11 h-11 rounded-xl bg-gradient-to-br ${pDef?.color || "from-slate-500 to-slate-600"} flex items-center justify-center shrink-0 text-white ${!model.is_active ? "opacity-50" : ""}`}>
                    {pDef?.icon || <span className="text-sm font-bold">?</span>}
                  </div>
                  <div className={`flex-1 min-w-0 ${!model.is_active ? "opacity-50" : ""}`}>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium text-slate-200">{model.name}</span>
                      {model.is_primary && <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/20">Primary</span>}
                      {!model.is_active && <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-500/15 text-slate-500">Disabled</span>}
                      {model.last_error && String(model.last_error).startsWith("triage_parse_failure:") && (
                        <span
                          title={String(model.last_error).replace(/^triage_parse_failure:\s*/, "")}
                          className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/25 flex items-center gap-1 cursor-help"
                        >
                          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
                          Triage parse errors
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5 font-mono">{model.model_id}</p>
                    <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
                      {model.model_size_class && (
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                          model.model_size_class === "small" ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/20" :
                          model.model_size_class === "medium" ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/20" :
                          "bg-green-500/10 text-green-400 border-green-500/20"
                        }`}>{model.model_size_class === "small" ? "Small <7B" : model.model_size_class === "medium" ? "Medium 7-30B" : "Large 30B+"}</span>
                      )}
                      {model.prompt_strategy && model.prompt_strategy !== "recommended" && (
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                          model.prompt_strategy === "strict" ? "bg-orange-500/10 text-orange-400 border-orange-500/20" :
                          model.prompt_strategy === "sensitive" ? "bg-purple-500/10 text-purple-400 border-purple-500/20" :
                          "bg-slate-500/10 text-slate-400 border-slate-500/20"
                        }`}>{model.prompt_strategy === "strict" ? "🛡️ Strict" : model.prompt_strategy === "sensitive" ? "🔍 Sensitive" : "✏️ Custom"}</span>
                      )}
                      {(model.tasks || []).map((t: string) => (
                        <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-white/[0.03] text-slate-500 border border-white/[0.04] capitalize">{t}</span>
                      ))}
                    </div>
                    {model.total_requests > 0 && (
                      <div className="flex gap-4 mt-2 text-[10px] text-slate-600">
                        <span>{model.total_requests?.toLocaleString()} requests</span>
                        <span>{(((model.total_input_tokens || 0) + (model.total_output_tokens || 0)) / 1000).toFixed(0)}K tokens</span>
                        {model.total_cost_usd > 0 && <span>${model.total_cost_usd?.toFixed(2)}</span>}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    {testStatus[model.id] ? (
                      <span className={`text-xs flex items-center gap-1 ${
                        testStatus[model.id].status === "success" ? "text-green-400"
                        : testStatus[model.id].status === "error" ? "text-red-400"
                        : "text-slate-400"
                      }`}>
                        {testStatus[model.id].status === "testing" && (
                          <div className="w-3 h-3 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" />
                        )}
                        {testStatus[model.id].status === "success" && (
                          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                        )}
                        {testStatus[model.id].status === "error" && (
                          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                        )}
                        <span title={testStatus[model.id].message} className="max-w-[200px] truncate">{testStatus[model.id].message}</span>
                      </span>
                    ) : model.api_key_set ? (
                      <span className="text-xs text-green-400 flex items-center gap-1">
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                        Key set
                      </span>
                    ) : ["ollama", "custom", "lm_studio", "vllm", "localai"].includes(model.provider) ? (
                      <span className="text-xs text-cyan-400 flex items-center gap-1">
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 12h14M12 5v14" /></svg>
                        Local
                      </span>
                    ) : (
                      <span className="text-xs text-yellow-400">Key needed</span>
                    )}
                    {/* Actions menu */}
                    <div className="relative">
                      <button onClick={() => setMenuOpen(menuOpen === model.id ? null : model.id)} className="p-1.5 rounded-lg hover:bg-white/[0.06]">
                        <svg className="w-4 h-4 text-slate-500" fill="currentColor" viewBox="0 0 20 20"><path d="M10 6a2 2 0 110-4 2 2 0 010 4zM10 12a2 2 0 110-4 2 2 0 010 4zM10 18a2 2 0 110-4 2 2 0 010 4z" /></svg>
                      </button>
                      {menuOpen === model.id && (
                        <div ref={menuRef} className="absolute right-0 top-8 z-50 w-44 py-1 rounded-lg border border-white/[0.08] shadow-xl" style={{ background: "rgba(8,11,28,0.95)" }}>
                            <button onClick={() => { setMenuOpen(null); handleEditModel(model); }} className="block w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-white/[0.04]">
                              <span className="flex items-center gap-2">
                                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" /></svg>
                                Edit Model
                              </span>
                            </button>
                            <button onClick={() => handleTest(model.id)} className="block w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-white/[0.04]">
                              <span className="flex items-center gap-2">
                                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
                                Test Connection
                              </span>
                            </button>
                            {!model.is_primary && models.length > 1 && <button onClick={() => handleSetPrimary(model.id)} className="block w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-white/[0.04]">
                              <span className="flex items-center gap-2">
                                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" /></svg>
                                Set as Primary
                              </span>
                            </button>}
                            <button onClick={() => handleToggleActive(model.id)} className="block w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-white/[0.04]">
                              <span className="flex items-center gap-2">
                                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
                                {model.is_active ? "Disable" : "Enable"}
                              </span>
                            </button>
                            <div className="border-t border-white/[0.06] my-1" />
                            <button onClick={() => { setMenuOpen(null); setConfirmDelete(model.id); }} className="block w-full text-left px-4 py-2 text-sm text-red-400 hover:bg-red-500/5">
                              <span className="flex items-center gap-2">
                                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                                Remove
                              </span>
                            </button>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ── Add Model Form (Step-based: Provider → API Key → Discover → Configure) ── */}
      {showForm && (
        <div id="ai-model-form" className="card border-red-500/20">
          <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-5">
            {editingId ? "Edit AI Provider" : "Add AI Provider"}
          </h4>

          {/* Step 1: Provider + Credentials */}
          {(() => {
            const prov = providerFor(form.provider);
            const needsKey = prov?.requiresKey ?? true;
            const needsEndpoint = prov?.requiresEndpoint ?? false;
            const canDiscover = needsKey ? !!form.api_key : !!form.endpoint_url;

            return (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-5">
                <div>
                  <label className="text-xs text-slate-500 mb-1.5 block">Provider</label>
                  <select value={form.provider} onChange={(e) => {
                    const next = e.target.value;
                    // Only wipe the form if the user has entered meaningful data
                    // (picked a model, typed a key, named it, etc.). Otherwise the
                    // change is harmless and should preserve the in-progress state.
                    const isDirty = !!(form.model_id || form.api_key || form.name || form.endpoint_url);
                    if (isDirty && !confirm("Changing the provider will clear the current form. Continue?")) {
                      return;
                    }
                    resetForm();
                    setForm((f) => ({ ...f, provider: next }));
                    setShowForm(true);
                  }} className="select-dark w-full">
                    <optgroup label="Cloud Providers">
                      {AI_PROVIDERS.filter((p) => p.requiresKey && !p.requiresEndpoint).map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
                    </optgroup>
                    <optgroup label="Enterprise Cloud">
                      {AI_PROVIDERS.filter((p) => p.requiresKey && p.requiresEndpoint).map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
                    </optgroup>
                    <optgroup label="Self-Hosted / Local">
                      {AI_PROVIDERS.filter((p) => !p.requiresKey).map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
                    </optgroup>
                  </select>
                </div>

                {needsEndpoint && (
                  <div>
                    <label className="text-xs text-slate-500 mb-1.5 block">
                      Endpoint URL {!needsKey && <span className="text-red-400">*</span>}
                    </label>
                    <input value={form.endpoint_url}
                      onChange={(e) => { setForm((f) => ({ ...f, endpoint_url: e.target.value })); setKeyValidated(false); setDiscoveredModels([]); setDiscoverStatus(null); }}
                      placeholder={form.provider === "ollama" ? "http://localhost:11434" : form.provider === "custom" ? "http://localhost:8080" : "https://your-endpoint.openai.azure.com/"}
                      className="input-dark" />
                  </div>
                )}

                <div className={needsEndpoint ? "md:col-span-2" : ""}>
                  <label className="text-xs text-slate-500 mb-1.5 block">
                    API Key {needsKey ? <span className="text-red-400">*</span> : <span className="text-slate-600">(optional)</span>}
                  </label>
                  <div className="flex gap-2">
                    <input type="password" value={form.api_key}
                      onChange={(e) => { setForm((f) => ({ ...f, api_key: e.target.value })); setKeyValidated(false); setDiscoveredModels([]); setDiscoverStatus(null); }}
                      placeholder={editingId ? "Leave blank to keep existing key" : (prov?.keyPlaceholder || "API key")}
                      className="input-dark flex-1" />
                    <button onClick={() => handleDiscoverModels()} disabled={!canDiscover || discovering}
                      className="btn-secondary shrink-0 flex items-center gap-2 whitespace-nowrap">
                      {discovering ? (
                        <><div className="w-3.5 h-3.5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" />Connecting...</>
                      ) : keyValidated ? (
                        <><svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>Connected</>
                      ) : (
                        <><svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101" /></svg>{needsKey ? "Validate & Load Models" : "Connect & Load Models"}</>
                      )}
                    </button>
                  </div>
                  {!needsKey && !form.api_key && (
                    <p className="text-[10px] text-slate-600 mt-1.5">Leave blank if your endpoint doesn&apos;t require authentication</p>
                  )}
                </div>
              </div>
            );
          })()}

          {/* Validation status */}
          {discoverStatus && (
            <div className={`flex items-center gap-2 p-3 rounded-lg mb-5 text-sm ${
              discoverStatus.status === "success" ? "bg-green-500/5 border border-green-500/15 text-green-400" : "bg-red-500/5 border border-red-500/15 text-red-400"
            }`}>
              {discoverStatus.status === "success" ? (
                <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
              ) : (
                <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
              )}
              {discoverStatus.message}
            </div>
          )}

          {/* Auto-recompute notice — shown when user swaps model_id in edit mode */}
          {defaultsRecomputedFor && editingId && (
            <div className="flex items-center gap-2 p-3 rounded-lg mb-5 text-xs bg-cyan-500/5 border border-cyan-500/15 text-cyan-400">
              <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
              <span>Defaults recomputed for <span className="font-mono">{defaultsRecomputedFor}</span> — fine-tune parameters refreshed.</span>
            </div>
          )}

          {/* Step 2: Model Selection (appears after validation) */}
          {(keyValidated || editingId) && discoveredModels.length === 0 && !discovering && (
            <div className="mb-5 p-4 rounded-lg bg-yellow-500/5 border border-yellow-500/15">
              <p className="text-sm text-yellow-400 mb-2">
                {editingId ? "Couldn't list models automatically — enter or update the model ID manually, or retry discovery below." : "Server connected but model listing is not supported"}
              </p>
              <label className="text-xs text-slate-500 mb-1.5 block">Model ID</label>
              <input value={form.model_id}
                onChange={(e) => setForm((f) => ({ ...f, model_id: e.target.value, name: f.name || e.target.value }))}
                placeholder="e.g. llama3, mistral, codellama, gpt-4o"
                className="input-dark" />
              {editingId && (
                <div className="mt-3 flex gap-2 items-center">
                  <button onClick={() => handleDiscoverModels({ modelConfigId: editingId, preserveSelection: true })}
                    className="btn-secondary text-xs flex items-center gap-1.5">
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
                    Retry with stored key
                  </button>
                  <span className="text-[10px] text-slate-600">or enter a new API key above</span>
                </div>
              )}
            </div>
          )}
          {editingId && discovering && discoveredModels.length === 0 && (
            <div className="mb-5 p-4 rounded-lg bg-white/[0.02] border border-white/[0.06] flex items-center gap-3">
              <div className="w-4 h-4 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" />
              <span className="text-sm text-slate-400">Loading available models with stored credentials…</span>
            </div>
          )}
          {(keyValidated || editingId) && discoveredModels.length > 0 && (
            <div className="space-y-4 mb-5">
              <div>
                <label className="text-xs text-slate-500 mb-1.5 block">Select Model ({discoveredModels.length} available)</label>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                  {discoveredModels.map((m) => (
                    <button key={m.model_id} onClick={() => { setForm((f) => ({ ...f, model_id: m.model_id, name: (!f.name || f.name === f.model_id) ? m.model_id : f.name })); setSelectedModelParam(m.parameter_size || null); applyAutoConfig(form.provider, m.model_id, form.prompt_strategy, m.parameter_size); }}
                      className={`text-left p-3 rounded-lg border transition-all ${
                        form.model_id === m.model_id
                          ? "border-red-500/30 bg-red-500/5"
                          : "border-white/[0.06] hover:border-white/[0.12] bg-white/[0.02]"
                      }`}>
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full shrink-0 ${form.model_id === m.model_id ? "bg-red-400" : "bg-slate-600"}`} />
                        <span className="text-sm font-medium text-slate-200 truncate">{m.name || m.model_id}</span>
                      </div>
                      <p className="text-[10px] text-slate-600 font-mono mt-1 truncate">{m.model_id}</p>
                      {m.description && <p className="text-[10px] text-slate-500 mt-1 line-clamp-1">{m.description}</p>}
                      {(m.context_window || m.max_output) && (
                        <div className="flex gap-2 mt-1.5 text-[9px] text-slate-600">
                          {m.context_window && <span>{(m.context_window / 1000).toFixed(0)}K context</span>}
                          {m.max_output && <span>{(m.max_output / 1000).toFixed(0)}K output</span>}
                        </div>
                      )}
                    </button>
                  ))}
                </div>
              </div>

              {/* ── Essentials: Name + Primary toggle ── */}
              {form.model_id && (
                <div className="pt-4 border-t border-white/[0.06]">
                  <label className="text-xs text-slate-500 mb-1.5 block">Display Name</label>
                  <input value={form.name}
                    onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                    placeholder={form.model_id || "e.g. Production Primary"} className="input-dark" />
                  <label className="flex items-center gap-2 cursor-pointer mt-3">
                    <input type="checkbox" checked={form.is_primary}
                      onChange={(e) => setForm((f) => ({ ...f, is_primary: e.target.checked }))}
                      className="w-4 h-4 rounded border-slate-600 bg-dark-950 text-red-500" />
                    <span className="text-sm text-slate-300">Set as primary provider</span>
                  </label>
                </div>
              )}
            </div>
          )}

          {/* ── Analysis Strategy (always visible when configuring) ── */}
          {(keyValidated || editingId) && form.model_id && (
            <div className="space-y-4 mb-5">
              <div>
                <label className="text-xs text-slate-500 mb-1.5 block">Analysis Strategy</label>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5">
                  {([
                    { key: "recommended", label: "Recommended", desc: "Balanced accuracy", icon: "⚖️" },
                    { key: "strict",      label: "Strict",      desc: "Low false positives", icon: "🛡️" },
                    { key: "sensitive",   label: "Sensitive",   desc: "Aggressive FP detection", icon: "🔍" },
                    { key: "custom",      label: "Custom",      desc: "Your own prompt", icon: "✏️" },
                  ]).map((s) => (
                    <button key={s.key}
                      onClick={() => { setForm((f) => ({ ...f, prompt_strategy: s.key })); applyAutoConfig(form.provider, form.model_id, s.key); }}
                      className={`text-xs px-2 py-2.5 rounded-lg border transition-all text-left ${
                        form.prompt_strategy === s.key
                          ? "bg-red-500/10 text-red-400 border-red-500/25"
                          : "bg-white/[0.02] text-slate-500 border-white/[0.04] hover:border-white/[0.08]"
                      }`}>
                      <div className="font-medium">{s.icon} {s.label}</div>
                      <div className="text-[9px] mt-0.5 opacity-70">{s.desc}</div>
                    </button>
                  ))}
                </div>
              </div>

              {form.prompt_strategy === "custom" && (
                <div>
                  <label className="text-xs text-slate-500 mb-1.5 block">Custom System Prompt</label>
                  <textarea value={form.system_prompt_override}
                    onChange={(e) => setForm((f) => ({ ...f, system_prompt_override: e.target.value }))}
                    placeholder="You are a security scanner false positive analyzer. Rules:&#10;1. Output ONLY valid JSON.&#10;2. Classify as likely_true_positive, likely_false_positive, or needs_review.&#10;3. Be concise."
                    className="input-dark h-28 resize-y font-mono text-xs w-full" />
                </div>
              )}

              {/* ── Advanced settings (collapsed by default) ── */}
              <div>
                <button onClick={() => setShowAdvanced(!showAdvanced)}
                  className="flex items-center gap-2 text-xs text-slate-500 hover:text-slate-400 transition-colors">
                  <svg className={`w-3 h-3 transition-transform ${showAdvanced ? "rotate-90" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                  Advanced settings
                </button>

                {showAdvanced && (
                  <div className="mt-4 space-y-5 p-4 rounded-lg bg-white/[0.015] border border-white/[0.04]">

                    {/* Model size — auto-detected; override via dropdown */}
                    <div>
                      <label className="text-xs text-slate-400 mb-1.5 block"
                        title="Drives default max_tokens, context_window, and prompt style. Auto-detected from the model name; override only if the detection is wrong.">
                        Model Size Class <span className="text-slate-600 font-normal">(auto-detected)</span>
                      </label>
                      <select value={form.model_size_class || ""}
                        onChange={(e) => setForm((f) => ({ ...f, model_size_class: e.target.value || null }))}
                        className="select-dark w-full text-xs">
                        <option value="">Auto</option>
                        <option value="small">Small (&lt;7B)</option>
                        <option value="medium">Medium (7–30B)</option>
                        <option value="large">Large (30B+)</option>
                      </select>
                    </div>

                    {/* Numeric parameters — 2×2 symmetric grid */}
                    <div>
                      <label className="text-xs text-slate-400 mb-2 block">Model Parameters</label>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div>
                          <label className="text-[10px] text-slate-600 mb-1 block" title="Max tokens the model can emit in one response. Too low → truncated JSON.">Max Output Tokens</label>
                          <input type="number" min="0" value={form.max_tokens}
                            onChange={(e) => { const v = parseInt(e.target.value, 10); setForm((f) => ({ ...f, max_tokens: Number.isNaN(v) ? 4096 : v })); }}
                            className="input-dark text-xs" />
                        </div>
                        <div>
                          <label className="text-[10px] text-slate-600 mb-1 block" title="0 = deterministic (recommended for classification). Higher values introduce randomness.">Temperature</label>
                          <input type="number" step="0.05" min="0" max="2" value={form.temperature}
                            onChange={(e) => { const v = parseFloat(e.target.value); setForm((f) => ({ ...f, temperature: Number.isNaN(v) ? 0 : v })); }}
                            className="input-dark text-xs" />
                        </div>
                        <div>
                          <label className="text-[10px] text-slate-600 mb-1 block" title="Maximum input context. Use the model's real window (e.g. 32K for Mistral Small, 128K for Llama 3.x).">Context Window</label>
                          <input type="number" min="0" value={form.context_window}
                            onChange={(e) => { const v = parseInt(e.target.value, 10); setForm((f) => ({ ...f, context_window: Number.isNaN(v) ? 4096 : v })); }}
                            className="input-dark text-xs" />
                        </div>
                        <div>
                          <label className="text-[10px] text-slate-600 mb-1 block" title="Comma-separated terminators. Leave blank unless you know the model emits a specific stop string.">Stop Sequences</label>
                          <input value={(form.stop_sequences || []).join(", ")}
                            onChange={(e) => setForm((f) => ({ ...f, stop_sequences: e.target.value ? e.target.value.split(",").map((s: string) => s.trim()) : [] }))}
                            placeholder="Leave blank (recommended)" className="input-dark text-xs" />
                        </div>
                      </div>
                    </div>

                    {/* Output toggles */}
                    <div>
                      <label className="text-xs text-slate-400 mb-2 block">Output Controls</label>
                      <div className="space-y-2">
                        <label className="flex items-start gap-2 cursor-pointer p-2 rounded hover:bg-white/[0.02]">
                          <input type="checkbox" checked={form.supports_json_mode}
                            onChange={(e) => setForm((f) => ({ ...f, supports_json_mode: e.target.checked }))}
                            className="w-4 h-4 mt-0.5 rounded border-slate-600 bg-dark-950 text-red-500 shrink-0" />
                          <div>
                            <div className="text-xs text-slate-300 font-medium">JSON Mode</div>
                            <div className="text-[10px] text-slate-600">Ask the provider to enforce valid JSON output. Disable if the model truncates or errors — some routes don't support this flag cleanly.</div>
                          </div>
                        </label>
                        <label className="flex items-start gap-2 cursor-pointer p-2 rounded hover:bg-white/[0.02]">
                          <input type="checkbox" checked={form.use_compact_prompt}
                            onChange={(e) => setForm((f) => ({ ...f, use_compact_prompt: e.target.checked }))}
                            className="w-4 h-4 mt-0.5 rounded border-slate-600 bg-dark-950 text-red-500 shrink-0" />
                          <div>
                            <div className="text-xs text-slate-300 font-medium">Compact Prompt</div>
                            <div className="text-[10px] text-slate-600">Use a minimal prompt format. Only needed for models under 7B that can't handle the full schema.</div>
                          </div>
                        </label>
                      </div>
                    </div>

                    {/* Provider-specific config (JSON) */}
                    <div>
                      <label className="text-xs text-slate-400 mb-1.5 block"
                        title='Extra fields merged into the request body. For OpenRouter use {"provider": {"ignore": ["Cloudflare"]}} to skip a flaky upstream.'>
                        Provider-Specific Config <span className="text-slate-600 font-normal">(JSON)</span>
                      </label>
                      <textarea value={form.provider_config_json}
                        onChange={(e) => { setForm((f) => ({ ...f, provider_config_json: e.target.value })); setProviderConfigError(null); }}
                        placeholder='{}  — for OpenRouter routing, e.g. {"provider": {"ignore": ["Cloudflare"]}}'
                        className="input-dark h-20 resize-y font-mono text-xs w-full" />
                      {providerConfigError && (
                        <p className="text-[10px] text-red-400 mt-1">{providerConfigError}</p>
                      )}
                    </div>

                  </div>
                )}
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-3 items-center">
            {((editingId && form.model_id) || (keyValidated && form.model_id && form.name)) && (
              <button onClick={handleSave} disabled={saving || !form.model_id || !form.name} className="btn-primary">
                {saving ? "Saving..." : editingId ? "Update Provider" : "Save Provider"}
              </button>
            )}
            <button onClick={() => { setShowForm(false); resetForm(); }} className="btn-secondary">Cancel</button>
            {editingId && (
              <button onClick={() => setConfirmDelete(editingId)} className="btn-danger ml-auto flex items-center gap-2">
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                Remove Provider
              </button>
            )}
          </div>
        </div>
      )}

      {/* ── AI Engine Settings ── */}
      <AIEngineSettingsSection />

      {/* Delete confirmation */}
      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="card border-red-500/20 max-w-md w-full mx-4">
            <h4 className="text-base font-semibold text-white mb-2">Remove AI Provider</h4>
            <p className="text-sm text-slate-400 mb-4">
              Are you sure you want to remove this provider? AI triage will be disabled until another provider is configured.
            </p>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setConfirmDelete(null)} className="btn-secondary text-sm">Cancel</button>
              <button onClick={() => handleDelete(confirmDelete)} className="btn-danger text-sm">Remove Provider</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  NOTIFICATIONS FULL SECTION (inline, no modal)
// ═══════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════
//  SCANNERS FULL SECTION (inline config, same pattern as Notifications)
// ═══════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════
//  IDENTITY & SSO — tiles + expand with config form
// ═══════════════════════════════════════════════════════════════

function SSOSection() {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [configs, setConfigs] = useState<Record<string, any>>({});
  const [form, setForm] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);

  useEffect(() => {
    // Load existing SSO config from integrations table (type=sso)
    api.get("/integrations").then((r) => {
      const items = Array.isArray(r.data) ? r.data : r.data?.items || [];
      const byProvider: Record<string, any> = {};
      for (const item of items) {
        if (item.integration_type === "sso") byProvider[item.provider || item.config?.provider] = item;
      }
      setConfigs(byProvider);
    }).catch(() => {});
  }, []);

  const handleSave = async (provider: string) => {
    setSaving(true);
    try {
      const provDef = SSO_PROVIDERS.find((p) => p.provider === provider);
      const config: Record<string, string> = {};
      (provDef?.fields || []).forEach((f) => { if (form[f.key]) config[f.key] = form[f.key]; });
      // Include SSO settings
      if (form._sso_enforcement) config._sso_enforcement = form._sso_enforcement;
      if (form._auto_provision) config._auto_provision = form._auto_provision;
      if (form._default_role) config._default_role = form._default_role;
      if (form._allowed_domains) config._allowed_domains = form._allowed_domains;

      // Use the SSO configure endpoint
      const protocol = provider === "saml" ? "saml" : "oidc";
      await api.post("/sso/configure", { provider, protocol, config });

      // Reload
      const r = await api.get("/integrations");
      const items = Array.isArray(r.data) ? r.data : r.data?.items || [];
      const byProvider: Record<string, any> = {};
      for (const item of items) {
        if (item.integration_type === "sso") byProvider[item.provider || item.config?.provider] = item;
      }
      setConfigs(byProvider);
      setForm({});
    } catch { /* ignore */ }
    finally { setSaving(false); }
  };

  const handleDelete = async (provider: string) => {
    const existing = configs[provider];
    if (!existing || !confirm("Remove this SSO provider? Users will need to log in with email/password.")) return;
    try {
      await api.delete(`/integrations/${existing.id}`);
      setConfigs((c) => { const n = { ...c }; delete n[provider]; return n; });
    } catch { /* ignore */ }
  };

  const handleTest = async (provider: string) => {
    setTesting(provider);
    try {
      // Test by checking the OIDC authorize URL or SAML metadata
      const protocol = provider === "saml" ? "saml" : "oidc";
      await api.get(`/sso/${protocol === "saml" ? "saml/metadata" : "oidc/authorize"}?test=true`);
    } catch { /* ignore */ }
    finally { setTesting(null); }
  };

  return (
    <div>
      {/* ── Available Identity Providers ──
          Card + uppercase section header — design consolidation
          2026-05-19. */}
      <div className="card mb-5">
        <div className="flex items-center justify-between mb-4 gap-3">
          <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Available Identity Providers</h4>
        </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {SSO_PROVIDERS.map((p) => {
          const isExpanded = expandedId === p.provider;
          const isConfigured = !!configs[p.provider];

          return (
            <button key={p.provider} onClick={() => {
              setExpandedId(isExpanded ? null : p.provider);
              if (!isExpanded && isConfigured) setForm(configs[p.provider]?.config || {});
              else if (!isExpanded) setForm({});
            }}
              className={`relative text-left rounded-xl border p-4 transition-all duration-200 ${
                isExpanded ? "border-red-500/30 bg-red-500/5 ring-1 ring-red-500/20"
                : isConfigured ? "border-green-500/20 bg-white/[0.02] hover:border-green-500/30 hover:bg-white/[0.04]"
                : "border-white/[0.06] bg-white/[0.02] hover:border-white/[0.12] hover:bg-white/[0.04]"
              }`}>
              <div className="absolute top-3 right-3 pointer-events-none">
                {isConfigured ? (
                  <span className="text-[8px] px-1.5 py-0.5 rounded-full bg-green-500/15 text-green-400 border border-green-500/20 flex items-center gap-1">
                    <span className="w-1 h-1 rounded-full bg-green-400" />Active
                  </span>
                ) : (
                  <span className="text-[8px] px-1.5 py-0.5 rounded-full bg-slate-500/10 text-slate-500 border border-slate-500/20">Not connected</span>
                )}
              </div>
              <div className="flex items-center gap-3 pr-16">
                <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${p.color} flex items-center justify-center text-white shrink-0`}>
                  {p.icon}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-white">{p.name}</p>
                  <p className="text-[10px] text-slate-600 mt-0.5">{isConfigured ? p.description : "Click to configure"}</p>
                </div>
              </div>
            </button>
          );
        })}
      </div>
      </div>

      {expandedId && (() => {
        const p = SSO_PROVIDERS.find((pr) => pr.provider === expandedId);
        if (!p) return null;
        const isConfigured = !!configs[p.provider];

        return (
          <div className="bg-white/[0.02] border border-red-500/20 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`w-8 h-8 rounded-lg bg-gradient-to-br ${p.color} flex items-center justify-center text-white`}>{p.icon}</div>
                <div>
                  <h4 className="text-sm font-semibold text-white">{p.name}</h4>
                  <p className="text-[10px] text-slate-500">{p.description}</p>
                </div>
              </div>
              {isConfigured && (
                <div className="flex items-center gap-2">
                  <button onClick={() => handleTest(p.provider)} disabled={testing === p.provider}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-red-400 border border-red-500/20 hover:bg-red-500/10 transition-all disabled:opacity-50">
                    {testing === p.provider ? "Testing..." : "Test SSO"}
                  </button>
                  <button onClick={() => handleDelete(p.provider)}
                    className="px-3 py-1.5 rounded-lg text-xs font-medium text-red-400 border border-red-500/20 hover:bg-red-500/10 transition-all">
                    Remove
                  </button>
                </div>
              )}
            </div>

            <div className="border border-white/[0.06] bg-white/[0.01] rounded-lg p-4 space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {p.fields.map((field) => (
                  <div key={field.key} className={field.key.includes("certificate") || field.key.includes("metadata") ? "md:col-span-2" : ""}>
                    <label className="text-[10px] text-slate-500 block mb-1">{field.label} {field.required && <span className="text-red-400">*</span>}</label>
                    {field.key.includes("certificate") ? (
                      <textarea value={form[field.key] || ""} onChange={(e) => setForm((f) => ({ ...f, [field.key]: e.target.value }))}
                        placeholder={field.placeholder || ""} rows={3} className="input-dark text-xs w-full resize-none font-mono" />
                    ) : (
                      <input type={field.type === "password" ? "password" : "text"} value={form[field.key] || ""}
                        onChange={(e) => setForm((f) => ({ ...f, [field.key]: e.target.value }))}
                        placeholder={field.placeholder || ""} className="input-dark text-xs w-full" />
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* SSO settings */}
            <div className="border border-white/[0.06] bg-white/[0.01] rounded-lg p-4 space-y-3">
              <p className="text-[10px] text-slate-500 uppercase tracking-wider font-medium">SSO Settings</p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1">Enforcement</label>
                  <select value={form._sso_enforcement || "optional"} onChange={(e) => setForm((f) => ({ ...f, _sso_enforcement: e.target.value }))} className="select-dark text-xs w-full">
                    <option value="optional">Optional — users can also use email/password</option>
                    <option value="required">Required — all users must use SSO</option>
                    <option value="required_except_admins">Required except admins</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1">Auto-provisioning</label>
                  <select value={form._auto_provision || "disabled"} onChange={(e) => setForm((f) => ({ ...f, _auto_provision: e.target.value }))} className="select-dark text-xs w-full">
                    <option value="disabled">Disabled — admin must create users</option>
                    <option value="jit">Just-in-Time — create user on first login</option>
                    <option value="scim">SCIM — sync users from IdP directory</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1">Default Role for New Users</label>
                  <select value={form._default_role || "viewer"} onChange={(e) => setForm((f) => ({ ...f, _default_role: e.target.value }))} className="select-dark text-xs w-full">
                    <option value="viewer">Viewer (read-only)</option>
                    <option value="developer">Developer</option>
                    <option value="security_analyst">Security Analyst</option>
                    <option value="admin">Admin</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1">Allowed Email Domains</label>
                  <input value={form._allowed_domains || ""} onChange={(e) => setForm((f) => ({ ...f, _allowed_domains: e.target.value }))}
                    placeholder="company.com, subsidiary.com" className="input-dark text-xs w-full" />
                </div>
              </div>
            </div>

            <div className="flex gap-2">
              <button onClick={() => handleSave(p.provider)} disabled={saving}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/15 text-red-400 hover:bg-red-500/25 transition-all disabled:opacity-50">
                {saving ? "Saving..." : isConfigured ? "Update" : "Connect"}
              </button>
              <button onClick={() => setExpandedId(null)} className="btn-secondary-sm">Cancel</button>
            </div>
          </div>
        );
      })()}
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════
//  SIEM section removed 2026-05-19 — moved to
//  apps/web/src/components/secrets/AuditLogStreaming.tsx and
//  rendered under Settings → Audit & Compliance.  See the type
//  comment near `HubCategory` for the move rationale.
// ═══════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════
//  TICKETING — tiles + expand with config form
// ═══════════════════════════════════════════════════════════════

function TicketingSection() {
  const { toast } = useToast();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [configs, setConfigs] = useState<Record<string, any>>({});
  const [form, setForm] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  // Test-before-save result. Cleared when the user edits any form field
  // so a stale red/green chip never sticks around after a fix.
  const [testResult, setTestResult] = useState<{ status: string; message: string; details?: Record<string, unknown> } | null>(null);
  // Dynamic Jira project list — fetched after a successful Test Connection
  // so the Project Key field becomes a real dropdown of the user's projects
  // instead of a free-text "guess the key" box. Empty until token is verified.
  const [jiraProjects, setJiraProjects] = useState<{ key: string; name: string }[]>([]);
  // Dynamic Jira issue-type list — depends on the selected project_key.
  // Different projects expose different types (VOOD has Task/Epic/Subtask,
  // not Bug — hardcoding "Bug" returns HTTP 400 from such projects).
  const [jiraIssueTypes, setJiraIssueTypes] = useState<{ id: string; name: string }[]>([]);
  // ServiceNow assignment group list — same auto-load pattern as
  // Jira projects. Populated when ServiceNow credentials become
  // valid; rendered as a dropdown when non-empty.
  const [snowGroups, setSnowGroups] = useState<{ sys_id: string; name: string; description?: string }[]>([]);
  // Preview failure surfaced inline so the user sees WHY a dropdown
  // didn't populate (was previously swallowed silently). Cleared
  // when the user edits any credential field — the next debounced
  // preview run gets a fresh chance.
  const [previewError, setPreviewError] = useState<string | null>(null);

  // ── Multi-board support for Jira ─────────────────────────────
  // A team with multiple products can configure several Jira boards
  // (e.g. one for Engineering, one for Security, one per repo) and
  // route findings per repository / business unit. The dispatcher
  // already honors `scope_level` + `business_unit_id` +
  // `repository_id` on each integration row to decide which channel
  // a given finding flows to. Here we just expose the management
  // surface — list, add, edit, delete Jira boards.
  //
  // editingBoardId values:
  //   - <UUID>  : edit an existing board, form pre-filled from it
  //   - "new"   : create a new board, blank form
  //   - null    : no board selected (show the picker only)
  const [jiraBoards, setJiraBoards] = useState<any[]>([]);
  const [editingBoardId, setEditingBoardId] = useState<string | "new" | null>(null);
  // Lists for the Scope picker (Organization-wide / BU-scoped /
  // Project-scoped). Loaded lazily when the Jira tile is opened.
  const [businessUnits, setBusinessUnits] = useState<{ id: string; name: string }[]>([]);
  const [repositories, setRepositories] = useState<{ id: string; name: string }[]>([]);

  // Load existing ticketing integrations + the lists used by the
  // multi-board Scope picker. The configs map keeps "the currently
  // active board for this provider" — for jira specifically that's
  // whichever board is being edited (see editingBoardId). For
  // single-board providers (servicenow / linear / custom) the map
  // is the source of truth as before.
  useEffect(() => {
    api.get("/integrations").then((r) => {
      const items = (r.data?.items || r.data || []) as any[];
      const byProvider: Record<string, any> = {};
      const jiraList: any[] = [];
      for (const item of (Array.isArray(items) ? items : [])) {
        if (item.integration_type === "ticketing" || TICKETING_TOOLS.some((t) => t.provider === item.provider)) {
          if (item.provider === "jira") {
            jiraList.push(item);
          } else if (!byProvider[item.provider]) {
            byProvider[item.provider] = item;
          }
        }
      }
      // Default the configs.jira pointer to the first board so
      // legacy code paths (Test button, refresh-after-save, etc.)
      // keep working while editingBoardId drives the form.
      if (jiraList[0]) byProvider.jira = jiraList[0];
      setConfigs(byProvider);
      setJiraBoards(jiraList);
    }).catch(() => {});

    // Lazy-load lists used by the Scope picker. Errors are swallowed
    // — Org-wide scope works fine even if these lists never arrive.
    api.get("/access/business-units").then((r) => {
      const items = (r.data?.items || r.data || []) as any[];
      setBusinessUnits((Array.isArray(items) ? items : []).map((b) => ({ id: b.id, name: b.name })));
    }).catch(() => {});
    api.get("/repositories", { params: { page_size: 200 } }).then((r) => {
      const items = (r.data?.items || []) as any[];
      setRepositories(items.map((repo) => ({ id: repo.id, name: repo.name })));
    }).catch(() => {});
  }, []);

  const handleSave = async (provider: string, fields: any[]) => {
    setSaving(true);
    try {
      const config: Record<string, string> = {};
      // The form is pre-filled with the MASKED config from the API
      // (api_token displays as `ATATT3xF••••••••…`). If we naively
      // forward whatever's in the form on Update we'd overwrite the
      // real DB token with the masked string and silently break every
      // future ticket dispatch. Drop any field whose value is masked
      // so the backend keeps the existing decrypted value.
      fields.forEach((f) => {
        const val = form[f.key];
        if (!val) return;
        if (typeof val === "string" && /[•·●]/.test(val)) return;  // masked → skip
        config[f.key] = val;
      });
      // Push-rule + scope keys live in form state with `_` prefix —
      // some are stored in the integration's config dict (so the
      // dispatcher can read them per-channel), others are top-level
      // columns on the integration row (so the dispatcher can scope
      // routing without parsing config). Split them appropriately.
      ["_push_trigger", "_push_frequency", "_min_severity", "_priority_mapping",
       "_exclude_false_positive", "_exclude_test_credential", "_exclude_accepted_risk",
       "_exclude_rotated", "_labels"].forEach((k) => {
         if (form[k] !== undefined) config[k] = form[k];
       });

      const isJira = provider === "jira";
      // Multi-board values (Jira only). For non-jira providers the
      // single-config flow is preserved exactly as before.
      const boardName = (form._name || (isJira ? "Jira Board" : `${provider} Integration`)).trim();
      const scopeLevel = form._scope_level || "organization";
      const buId = scopeLevel === "business_unit" ? (form._business_unit_id || null) : null;
      const repoId = scopeLevel === "project" ? (form._repository_id || null) : null;

      let savedId: string | null = null;
      if (isJira) {
        // Multi-board path: editingBoardId tells us whether this is a
        // new board (POST) or an existing one (PUT). For POST we send
        // scope columns; for PUT we send config + scope changes.
        if (editingBoardId && editingBoardId !== "new") {
          await api.put(`/integrations/${editingBoardId}`, {
            name: boardName,
            config,
            is_active: true,
            scope_level: scopeLevel,
            business_unit_id: buId,
            repository_id: repoId,
          });
          savedId = editingBoardId;
        } else {
          const r = await api.post("/integrations", {
            name: boardName,
            provider,
            integration_type: "ticketing",
            config,
            is_active: true,
            scope_level: scopeLevel,
            business_unit_id: buId,
            repository_id: repoId,
          });
          savedId = r.data?.id || null;
        }
      } else {
        // Legacy single-config flow for ServiceNow / Linear / Custom.
        const existing = configs[provider];
        if (existing) {
          await api.put(`/integrations/${existing.id}`, { config, is_active: true });
          savedId = existing.id;
        } else {
          const r = await api.post("/integrations", {
            name: `${provider} Integration`, provider, integration_type: "ticketing",
            config, is_active: true,
          });
          savedId = r.data?.id || null;
        }
      }

      // Reload the canonical integration list and rebuild local state.
      const r = await api.get("/integrations");
      const items = (r.data?.items || r.data || []) as any[];
      const byProvider: Record<string, any> = {};
      const jiraList: any[] = [];
      for (const item of (Array.isArray(items) ? items : [])) {
        if (item.integration_type === "ticketing" || TICKETING_TOOLS.some((t) => t.provider === item.provider)) {
          if (item.provider === "jira") {
            jiraList.push(item);
          } else if (!byProvider[item.provider]) {
            byProvider[item.provider] = item;
          }
        }
      }
      // For jira: re-pin configs.jira to the just-saved row (or the
      // first one if the save returned no id) so dropdowns + tests
      // continue working against it.
      const savedRow = isJira
        ? (jiraList.find((b) => b.id === savedId) || jiraList[0])
        : byProvider[provider];
      if (isJira && savedRow) byProvider.jira = savedRow;
      setConfigs(byProvider);
      setJiraBoards(jiraList);
      if (isJira && savedRow?.id) setEditingBoardId(savedRow.id);

      // Re-pin the form to the freshly-saved config (with the now-
      // masked api_token) instead of wiping it. Bug fix 2026-04-27 —
      // the previous `setForm({})` made Update look like a Reset
      // button: the user clicked Save, all the input fields cleared,
      // and they had to re-open the tile to see their saved values.
      if (savedRow?.config) {
        setForm({
          ...savedRow.config,
          _name: savedRow.name,
          _scope_level: savedRow.scope_level || "organization",
          _business_unit_id: savedRow.business_unit_id || "",
          _repository_id: savedRow.repository_id || "",
        });
      } else {
        setForm({});
      }
      // Also refresh the Jira dropdowns so the dynamic options stay
      // aligned with the now-saved project_key (otherwise the issue-
      // type dropdown would show the previous project's types until
      // the user closes + reopens the tile).
      if (provider === "jira" && savedRow?.id) {
        await loadJiraProjects(savedRow.id);
        const pk = (savedRow.config || {}).project_key;
        if (pk) await loadJiraIssueTypes(savedRow.id, pk);
      }
      // Surface success — was silently completing before, leaving
      // the user wondering whether the click did anything. Toast
      // wording adapts to whether it was a new board or an update.
      const wasNew = isJira ? (editingBoardId === "new") : !configs[provider];
      toast(
        "success",
        wasNew ? "Board added" : "Board updated",
        savedRow?.name
          ? `${savedRow.name} is now active.`
          : "Configuration saved. Findings will route to this board on the next scan.",
      );
    } catch (e: unknown) {
      // Surface failures so the user gets actionable feedback
      // instead of an unchanged-looking form. Pull the FastAPI
      // detail when present (e.g. 400 "repository_id required for
      // project-scoped integration"); fall back to the bare HTTP
      // status when not.
      const err = e as { response?: { status?: number; data?: { detail?: string } }; message?: string };
      const detail = err.response?.data?.detail || err.message || "Save failed";
      toast("error", "Could not save board", String(detail).slice(0, 200));
    }
    finally { setSaving(false); }
  };

  const handleDelete = async (provider: string) => {
    // For Jira (multi-board), delete the currently-edited board.
    // For other providers, delete the single configured row.
    const targetId = provider === "jira"
      ? (editingBoardId && editingBoardId !== "new" ? editingBoardId : configs[provider]?.id)
      : configs[provider]?.id;
    if (!targetId || !confirm("Remove this board / integration?")) return;
    try {
      await api.delete(`/integrations/${targetId}`);
      // Refresh list — for jira this might leave us with 0 or N-1
      // boards. Reset the editing pointer so the UI reflects reality.
      const r = await api.get("/integrations");
      const items = (r.data?.items || r.data || []) as any[];
      const byProvider: Record<string, any> = {};
      const jiraList: any[] = [];
      for (const item of (Array.isArray(items) ? items : [])) {
        if (item.integration_type === "ticketing" || TICKETING_TOOLS.some((t) => t.provider === item.provider)) {
          if (item.provider === "jira") jiraList.push(item);
          else if (!byProvider[item.provider]) byProvider[item.provider] = item;
        }
      }
      if (jiraList[0]) byProvider.jira = jiraList[0];
      setConfigs(byProvider);
      setJiraBoards(jiraList);
      if (provider === "jira") {
        setEditingBoardId(jiraList[0]?.id || null);
        setForm(jiraList[0]?.config ? {
          ...jiraList[0].config,
          _name: jiraList[0].name,
          _scope_level: jiraList[0].scope_level || "organization",
          _business_unit_id: jiraList[0].business_unit_id || "",
          _repository_id: jiraList[0].repository_id || "",
        } : {});
      }
      toast("success", "Board removed", "The board's saved configuration has been deleted.");
    } catch (e: unknown) {
      const err = e as { response?: { data?: { detail?: string } }; message?: string };
      toast("error", "Could not remove board", err.response?.data?.detail || err.message || "Delete failed");
    }
  };

  const handleTest = async (provider: string) => {
    // Jira multi-board: test the currently-edited board's saved
    // credentials; if we're in "new" mode, there's nothing saved yet
    // to test (the user should click Test Connection on the form
    // values instead).
    const targetId = provider === "jira"
      ? (editingBoardId && editingBoardId !== "new" ? editingBoardId : configs[provider]?.id)
      : configs[provider]?.id;
    if (!targetId) return;
    setTesting(provider);
    try {
      const r = await api.post(`/integrations/${targetId}/test`);
      const status = r.data?.status;
      const message = r.data?.message || "Connection test completed.";
      if (status === "success") {
        toast("success", "Connection OK", message);
      } else if (status === "auth_failed") {
        toast("warning", "Authentication failed", message);
      } else {
        toast("error", "Test failed", message);
      }
    } catch (e: unknown) {
      const err = e as { response?: { data?: { detail?: string } }; message?: string };
      toast("error", "Test failed", err.response?.data?.detail || err.message || "Could not reach Vooda API");
    }
    finally { setTesting(null); }
  };

  // Test the values currently in the form WITHOUT saving them. Lets users
  // verify their token works before committing the credential to the
  // encrypted store. Hits the /integrations/test-ticketing endpoint added
  // 2026-04-26 specifically for this UX.
  const handleTestForm = async (provider: string, fields: { key: string; required?: boolean }[]) => {
    setTesting(provider);
    setTestResult(null);
    try {
      const config: Record<string, string> = {};
      fields.forEach((f) => { if (form[f.key]) config[f.key] = form[f.key]; });

      // The form is pre-filled with the integration's MASKED config
      // (the API returns api_token as `ATATT3xF••••••••…` to avoid
      // ever leaking the real value back to the browser). If the
      // user clicks Test without re-typing the token, that masked
      // string would be sent verbatim to Atlassian — which correctly
      // returns 401 "Client must be authenticated". Detect that
      // case and route to the post-save Test endpoint instead, which
      // uses the REAL credential decrypted server-side. Bug fix
      // 2026-04-27 — was the cause of the user-reported "401 even
      // though the saved integration works for ticketing".
      const existing = configs[provider];
      const SENSITIVE = ["api_token", "api_key", "password", "secret", "auth_token", "smtp_password", "token"];
      const looksMasked = (val: string | undefined) => !!val && /[•·●]/.test(val);
      const hasMaskedSensitive = SENSITIVE.some((k) => looksMasked(config[k]));

      let r: { data?: { status?: string; message?: string; details?: Record<string, unknown> } };
      if (hasMaskedSensitive && existing?.id) {
        // Saved integration + user hasn't re-typed the secret →
        // test against the stored credential.
        r = await api.post(`/integrations/${existing.id}/test`);
      } else {
        // Fresh form values (or no saved integration yet) →
        // test what's in the form.
        r = await api.post("/integrations/test-ticketing", { provider, config });
      }
      setTestResult({
        status: r.data?.status || "error",
        message: r.data?.message || "No response",
        details: r.data?.details || undefined,
      });
      // On a successful Jira test, fetch the project list so the Project
      // Key dropdown can be populated from real data. We need a saved row
      // for this — if one already exists for this provider we use it,
      // otherwise we save first via a temporary persist (only for the
      // test path). Simplest approach: only enable the dynamic dropdown
      // for already-saved integrations; if this is the first Test ever,
      // the user types the key once and the next Test will dropdown-ify it.
      if (r.data?.status === "success" && provider === "jira") {
        if (existing?.id) {
          await loadJiraProjects(existing.id);
          // If a project_key is already selected (form pre-fill from
          // a saved config, OR user picked one before Test), pull
          // its issue types too — otherwise the Issue Type dropdown
          // is stranded empty even though the project is valid.
          const pk = form.project_key || (existing.config || {}).project_key;
          if (pk) {
            await loadJiraIssueTypes(existing.id, pk);
          }
        }
      }
    } catch (e: unknown) {
      // Disambiguate three failure modes the user might hit so the
      // chip shows something useful instead of a raw axios string:
      //   1. 5xx from our own API → "API is unreachable, retry in a sec"
      //      (this used to surface as "Request failed with status code
      //      500" — opaque, looked like a credential problem when it
      //      was actually our own backend bouncing)
      //   2. 4xx from our own API → use the FastAPI `detail` if present
      //   3. Network error (no response) → say so explicitly
      const err = e as {
        response?: { status?: number; data?: { detail?: string } };
        message?: string;
        code?: string;
      };
      const status = err.response?.status;
      const detail = err.response?.data?.detail;
      let message: string;
      if (status && status >= 500) {
        message = `Vooda API returned ${status} — the backend is restarting or unreachable. Wait a moment and retry. (No credentials were sent to the provider.)`;
      } else if (status && status >= 400) {
        message = detail || `Vooda API returned ${status}`;
      } else if (err.code === "ERR_NETWORK" || !err.response) {
        message = `Could not reach the Vooda API: ${err.message || "network error"}`;
      } else {
        message = detail || err.message || "Request failed";
      }
      setTestResult({ status: "error", message });
    } finally { setTesting(null); }
  };

  // Pull the Jira project list using the saved integration's stored
  // credentials (token decrypted server-side, never returned to the UI).
  // Single retry on 502/503 — Atlassian's project endpoints are
  // occasionally rate-limited or briefly 5xx-flap right after a save
  // (observed 2026-04-27); a 600ms retry hides those transient hiccups
  // so the dropdown isn't stranded empty.
  const loadJiraProjects = async (integrationId: string) => {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const r = await api.get(`/integrations/${integrationId}/jira-projects`);
        setJiraProjects(r.data?.projects || []);
        return;
      } catch (e: unknown) {
        const status = (e as { response?: { status?: number } })?.response?.status;
        if (attempt === 0 && (status === 502 || status === 503)) {
          await new Promise((res) => setTimeout(res, 600));
          continue;
        }
        setJiraProjects([]);
        return;
      }
    }
  };

  // Pre-pick a sensible default issue type when the dropdown loads,
  // so the user doesn't have to make an "important-looking" choice
  // every time they configure a board. Industry convention for
  // security findings is Bug; Task is the universal fallback for
  // projects (like VOOD) that don't expose Bug. Story / first-
  // non-subtask round it out for unusual project schemas.
  // Only fires when the user hasn't explicitly picked something —
  // never overwrites an existing form.issue_type.
  const autoPickIssueType = (types: { id: string; name: string }[]) => {
    if (form.issue_type || !types.length) return;
    const preference = ["Bug", "Task", "Story"];
    const matched = preference.map((name) => types.find((t) => t.name === name)).find(Boolean);
    const pick = matched?.name || types[0]?.name;
    if (pick) setForm((f) => ({ ...f, issue_type: pick }));
  };

  // Pull the issue types for whichever project_key the user picked. Called
  // when the project_key changes (after typing or selecting from dropdown)
  // so the Issue Type dropdown reflects what's ACTUALLY available — not a
  // hardcoded guess. Same single-retry behavior as loadJiraProjects.
  const loadJiraIssueTypes = async (integrationId: string, projectKey: string) => {
    if (!projectKey) { setJiraIssueTypes([]); return; }
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const r = await api.get(`/integrations/${integrationId}/jira-issue-types`, { params: { project_key: projectKey } });
        const types = r.data?.issue_types || [];
        setJiraIssueTypes(types);
        autoPickIssueType(types);
        return;
      } catch (e: unknown) {
        const status = (e as { response?: { status?: number } })?.response?.status;
        if (attempt === 0 && (status === 502 || status === 503)) {
          await new Promise((res) => setTimeout(res, 600));
          continue;
        }
        setJiraIssueTypes([]);
        return;
      }
    }
  };

  // ── ServiceNow assignment-group loaders ─────────────────────
  // Mirror of the Jira preview path. Auto-pre-pick "Security
  // Operations" if it exists (industry-standard for security
  // incidents), otherwise leave the field blank for the user.
  const autoPickServiceNowGroup = (groups: { name: string }[]) => {
    if (form.assignment_group || !groups.length) return;
    const pick = groups.find((g) => g.name === "Security Operations") || groups[0];
    if (pick) setForm((f) => ({ ...f, assignment_group: pick.name }));
  };

  const previewServiceNowGroupsFromForm = async (instanceUrl: string, username: string, password: string) => {
    if (!instanceUrl?.trim() || !username?.trim() || !password?.trim()) return;
    if (/[•·●]/.test(password)) return;
    try {
      const r = await api.post("/integrations/servicenow/preview-assignment-groups", {
        instance_url: instanceUrl, username, password,
      });
      const groups = r.data?.assignment_groups || [];
      setSnowGroups(groups);
      autoPickServiceNowGroup(groups);
    } catch { /* swallow; field falls back to text input */ }
  };

  const loadServiceNowGroups = async (integrationId: string) => {
    try {
      const r = await api.get(`/integrations/${integrationId}/servicenow-assignment-groups`);
      const groups = r.data?.assignment_groups || [];
      setSnowGroups(groups);
      autoPickServiceNowGroup(groups);
    } catch { setSnowGroups([]); }
  };

  // Stateless project preview — used by the Add Board form so the
  // Project dropdown auto-populates AS the user fills in
  // credentials, no save-then-reload round trip required. Vooda
  // backend proxies the supplied creds to Atlassian and returns
  // the project list. Skips silently if creds aren't yet complete
  // or the api_token is still in masked form (form pre-fill from
  // an existing saved row that we can't preview against). Bug fix
  // 2026-04-27 (user UX request: "JIRA Project and Issue Type
  // should load automatically when after passing the credentials").
  const previewJiraProjectsFromForm = async (siteUrl: string, email: string, apiToken: string) => {
    if (!siteUrl?.trim() || !email?.trim() || !apiToken?.trim()) return;
    if (/[•·●]/.test(apiToken)) return;
    try {
      const r = await api.post("/integrations/jira/preview-projects", {
        site_url: siteUrl, email, api_token: apiToken,
      });
      setJiraProjects(r.data?.projects || []);
      setPreviewError(null);
    } catch (e: unknown) {
      // Surface the failure inline instead of leaving the dropdown
      // mysteriously empty. Translate the most common HTTP errors
      // into plain copy; fall back to the FastAPI detail otherwise.
      const err = e as { response?: { status?: number; data?: { detail?: string } } };
      const status = err.response?.status;
      const detail = err.response?.data?.detail || "";
      let msg = detail || "Could not load Jira projects.";
      if (status === 401) msg = "Atlassian rejected the credentials. Check the API token + email — they must belong to the same account.";
      else if (status === 502 && /HTTP 401/.test(detail)) msg = "Atlassian rejected the credentials (401). The token + email don't match an active Atlassian account.";
      else if (status === 502 && /HTTP 403/.test(detail)) msg = "The account lacks permission to list projects. Grant Browse Projects in the target Jira project.";
      setPreviewError(msg);
      setJiraProjects([]);
    }
  };

  // Stateless issue-type preview — same idea, fired when the user
  // picks a project in the new-board flow. Resolves the issue
  // types from Atlassian without saving the integration first.
  const previewJiraIssueTypesFromForm = async (siteUrl: string, email: string, apiToken: string, projectKey: string) => {
    if (!siteUrl?.trim() || !email?.trim() || !apiToken?.trim() || !projectKey?.trim()) return;
    if (/[•·●]/.test(apiToken)) return;
    try {
      const r = await api.post("/integrations/jira/preview-issue-types", {
        site_url: siteUrl, email, api_token: apiToken, project_key: projectKey,
      });
      const types = r.data?.issue_types || [];
      setJiraIssueTypes(types);
      autoPickIssueType(types);
      setPreviewError(null);
    } catch (e: unknown) {
      const err = e as { response?: { status?: number; data?: { detail?: string } } };
      const status = err.response?.status;
      const detail = err.response?.data?.detail || "";
      let msg = detail || "Could not load issue types for this project.";
      if (status === 401) msg = "Atlassian rejected the credentials when listing issue types.";
      else if (status === 502 && /HTTP 404/.test(detail)) msg = `Project "${projectKey}" wasn't found. Re-pick the project from the dropdown.`;
      else if (status === 502 && /HTTP 403/.test(detail)) msg = `The account can't access project "${projectKey}". Grant Browse Projects on this project.`;
      setPreviewError(msg);
      setJiraIssueTypes([]);
    }
  };

  // Debounced auto-preview — when the user is in the Add Board
  // flow (or has actively edited the credentials of an existing
  // board), watch for site_url/email/api_token completeness and
  // pull the project list as soon as all three are non-empty +
  // non-masked. 800ms debounce so we don't hit Atlassian on every
  // keystroke.
  useEffect(() => {
    const isJiraForm = expandedId === "jira";
    if (!isJiraForm) return;
    const site = (form.site_url || "").trim();
    const email = (form.email || "").trim();
    const token = (form.api_token || "").trim();
    // Clear stale errors as soon as the user edits a credential
    // field — gives them visual confirmation that "this run might
    // succeed" while they're still typing.
    setPreviewError(null);
    if (!site || !email || !token) return;
    if (/[•·●]/.test(token)) return;  // masked → can't preview
    const timer = setTimeout(() => {
      previewJiraProjectsFromForm(site, email, token);
    }, 800);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [expandedId, form.site_url, form.email, form.api_token]);

  // When the user picks a project in the form (or the form's
  // project_key is pre-filled from a saved row), auto-load the
  // issue types using the same preview path. Runs only when the
  // creds are already valid (the projects-effect above gates that).
  useEffect(() => {
    const isJiraForm = expandedId === "jira";
    if (!isJiraForm) return;
    const site = (form.site_url || "").trim();
    const email = (form.email || "").trim();
    const token = (form.api_token || "").trim();
    const pk = (form.project_key || "").trim();
    if (!site || !email || !token || !pk) return;
    if (/[•·●]/.test(token)) return;
    previewJiraIssueTypesFromForm(site, email, token, pk);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [expandedId, form.project_key]);

  // ServiceNow auto-preview — same debounced pattern. Watch the
  // three credential fields, fire after 800ms of no input.
  useEffect(() => {
    if (expandedId !== "servicenow") return;
    const instance = (form.instance_url || "").trim();
    const username = (form.username || "").trim();
    const password = (form.password || "").trim();
    if (!instance || !username || !password) return;
    if (/[•·●]/.test(password)) return;
    const timer = setTimeout(() => {
      previewServiceNowGroupsFromForm(instance, username, password);
    }, 800);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [expandedId, form.instance_url, form.username, form.password]);

  return (
    <div>
      {/* ── Available Ticketing Tools ──
          Card + uppercase section header — design consolidation
          2026-05-19, matches Notifications / AI Provider / other
          sub-sections. */}
      <div className="card mb-5">
        <div className="flex items-center justify-between mb-4 gap-3">
          <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Available Ticketing Tools</h4>
        </div>

      {/* Provider tiles — the 3 community providers (Jira, ServiceNow,
          Custom Webhook) sit in a single row. The expanded config panel
          renders full-width below this grid, so a 3-up row here doesn't
          constrain it. */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {TICKETING_TOOLS.map((t) => {
          const isExpanded = expandedId === t.provider;
          const isConfigured = !!configs[t.provider];

          return (
            <button key={t.provider} onClick={() => {
              setExpandedId(isExpanded ? null : t.provider);
              if (!isExpanded && isConfigured) {
                // Pre-fill form with existing config. For jira this
                // means defaulting to the first board; the user can
                // switch via the board picker once the panel is open.
                const existing = configs[t.provider];
                if (t.provider === "jira") {
                  const first = jiraBoards[0] || existing;
                  if (first) {
                    setEditingBoardId(first.id);
                    setForm({
                      ...(first.config || {}),
                      _name: first.name,
                      _scope_level: first.scope_level || "organization",
                      _business_unit_id: first.business_unit_id || "",
                      _repository_id: first.repository_id || "",
                    });
                    loadJiraProjects(first.id).then(() => {
                      const pk = (first.config || {}).project_key;
                      if (pk) loadJiraIssueTypes(first.id, pk);
                    });
                  } else {
                    setEditingBoardId("new");
                    setForm({ _scope_level: "organization" });
                  }
                } else {
                  setForm(existing?.config || {});
                }
              } else if (!isExpanded && t.provider === "jira") {
                // First-time setup: open the form in "new" mode.
                setEditingBoardId("new");
                setForm({ _scope_level: "organization" });
              } else if (!isExpanded) {
                setForm({});
                setJiraProjects([]);
                setJiraIssueTypes([]);
              }
            }}
              className={`relative text-left rounded-xl border p-4 transition-all duration-200 ${
                isExpanded ? "border-red-500/30 bg-red-500/5 ring-1 ring-red-500/20"
                : isConfigured ? "border-green-500/20 bg-white/[0.02] hover:border-green-500/30 hover:bg-white/[0.04]"
                : "border-white/[0.06] bg-white/[0.02] hover:border-white/[0.12] hover:bg-white/[0.04]"
              }`}>
              <div className="absolute top-3 right-3 pointer-events-none">
                {isConfigured ? (
                  <span className="text-[8px] px-1.5 py-0.5 rounded-full bg-green-500/15 text-green-400 border border-green-500/20 flex items-center gap-1">
                    <span className="w-1 h-1 rounded-full bg-green-400" />
                    {t.provider === "jira" && jiraBoards.length > 1
                      ? `${jiraBoards.length} boards`
                      : "Active"}
                  </span>
                ) : (
                  <span className="text-[8px] px-1.5 py-0.5 rounded-full bg-slate-500/10 text-slate-500 border border-slate-500/20">Not connected</span>
                )}
              </div>
              <div className="flex items-center gap-3 pr-16">
                <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${t.color} flex items-center justify-center text-white shrink-0`}>
                  {t.icon}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-white">{t.name}</p>
                  <p className="text-[10px] text-slate-600 mt-0.5">
                    {t.provider === "jira" && jiraBoards.length > 0
                      ? `${jiraBoards.length} board${jiraBoards.length === 1 ? "" : "s"} configured`
                      : isConfigured ? t.description : "Click to configure"}
                  </p>
                </div>
              </div>
            </button>
          );
        })}
      </div>
      </div>

      {/* Expanded config panel */}
      {expandedId && (() => {
        const t = TICKETING_TOOLS.find((tool) => tool.provider === expandedId);
        if (!t) return null;
        const isConfigured = !!configs[t.provider];

        // Cross-provider warning: list other ticketing providers
        // that already have at least one active integration. Surfaces
        // a banner reminding the user that mixing systems is allowed
        // but each finding will route based on scope rules / per-repo
        // destinations — easy to mis-configure and silently fan out
        // to multiple systems. NOT a hard block (multi-system is
        // legitimate when different teams use different tools); it's
        // a heads-up. User-requested 2026-04-27.
        const otherTicketingProviders: { provider: string; name: string }[] = [];
        // jira's multiple boards live in jiraBoards (not configs.jira directly)
        if (t.provider !== "jira" && jiraBoards.length > 0) {
          otherTicketingProviders.push({ provider: "jira", name: "Jira" });
        }
        for (const other of TICKETING_TOOLS) {
          if (other.provider === t.provider) continue;
          if (other.provider === "jira") continue; // already handled above
          if (configs[other.provider]) {
            otherTicketingProviders.push({ provider: other.provider, name: other.name });
          }
        }

        return (
          <div className="bg-white/[0.02] border border-red-500/20 rounded-xl p-5 space-y-4">
            {otherTicketingProviders.length > 0 && (
              <div className="flex items-start gap-2.5 px-3 py-2.5 rounded-lg bg-amber-500/[0.06] border border-amber-500/20">
                <svg className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.6} d="M12 9v2m0 4h.01M5.07 19h13.86c1.54 0 2.5-1.67 1.73-3L13.73 4c-.77-1.33-2.69-1.33-3.46 0L3.34 16c-.77 1.33.19 3 1.73 3z" />
                </svg>
                <div className="flex-1 text-[11px] leading-relaxed">
                  <p className="text-amber-300 font-medium">
                    You already have {otherTicketingProviders.map((p) => p.name).join(" + ")} configured.
                  </p>
                  <p className="text-amber-200/80 mt-0.5">
                    Adding {t.name} doesn't replace it — both systems can stay active. Each finding routes per its repository's <span className="font-medium">Ticketing Destination</span> (set on the Repository edit modal), or per the board's <span className="font-medium">Scope</span> if no destination is set. Make sure the routing rules across systems are intentional, otherwise findings can fan out to both.
                  </p>
                </div>
              </div>
            )}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`w-8 h-8 rounded-lg bg-gradient-to-br ${t.color} flex items-center justify-center text-white`}>{t.icon}</div>
                <div>
                  <h4 className="text-sm font-semibold text-white">{t.name}</h4>
                  <p className="text-[10px] text-slate-500">{t.description}</p>
                </div>
              </div>
              {/* Top-level Test + Remove buttons only show on
                  single-config providers (ServiceNow / Linear /
                  Custom Webhook). For Jira, multi-board management
                  lives in the Boards chip strip below — each chip
                  has its own × delete affordance, and "Test
                  Connection" is the form-bottom button. Showing
                  Test + Remove at the panel level on Jira was
                  user-reported as ambiguous: it looked like they
                  applied to the entire Jira integration, when in
                  fact they only applied to whichever board was
                  currently being edited. Removed for Jira to make
                  the multi-board mental model unambiguous. */}
              {isConfigured && t.provider !== "jira" && (
                <div className="flex items-center gap-2">
                  <button onClick={() => handleTest(t.provider)} disabled={testing === t.provider}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-red-400 border border-red-500/20 hover:bg-red-500/10 transition-all disabled:opacity-50">
                    {testing === t.provider ? "Testing..." : "Test"}
                  </button>
                  <button onClick={() => handleDelete(t.provider)}
                    className="px-3 py-1.5 rounded-lg text-xs font-medium text-red-400 border border-red-500/20 hover:bg-red-500/10 transition-all">
                    Remove
                  </button>
                </div>
              )}
            </div>

            {/* Board picker (Jira-only multi-board UI).
                A team running multiple products on multiple Jira
                boards configures one Vooda integration row per
                board. Each row carries its own scope (Org / BU /
                Project) — see the Scope panel below — and the
                dispatcher routes findings accordingly. The chip
                strip lets the user switch between boards or add a
                new one without leaving the panel. */}
            {t.provider === "jira" && (
              <div className="border border-white/[0.06] bg-white/[0.01] rounded-lg p-4">
                <div className="flex items-center justify-between mb-2.5">
                  <p className="text-[10px] text-slate-500 uppercase tracking-wider font-medium">Boards</p>
                  <p className="text-[10px] text-slate-600">
                    {jiraBoards.length === 0 ? "No boards yet — fill the form below to add the first." :
                     jiraBoards.length === 1 ? "One board configured. Add more for multi-product teams." :
                     `${jiraBoards.length} boards. Findings route per scope.`}
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  {jiraBoards.map((b) => {
                    const isActive = b.id === editingBoardId;
                    const scope = b.scope_level || "organization";
                    const scopeLabel =
                      scope === "business_unit" ? `BU: ${(businessUnits.find(x => x.id === b.business_unit_id) || {}).name || "—"}` :
                      scope === "project" ? `Repo: ${(repositories.find(x => x.id === b.repository_id) || {}).name || "—"}` :
                      "Org-wide";
                    return (
                      // Each chip is a single tile with two click
                      // targets: the main body (selects this board
                      // for editing) and a × button in the corner
                      // (deletes this specific board after confirm).
                      // The × stops propagation so clicking it
                      // doesn't also re-select the chip.
                      <div key={b.id}
                        className={`group relative rounded-lg border transition-all ${
                          isActive
                            ? "border-red-500/40 bg-red-500/10"
                            : "border-white/[0.06] bg-white/[0.02] hover:border-white/[0.14] hover:bg-white/[0.04]"
                        }`}
                      >
                        <button type="button"
                          onClick={() => {
                            setEditingBoardId(b.id);
                            setForm({
                              ...(b.config || {}),
                              _name: b.name,
                              _scope_level: scope,
                              _business_unit_id: b.business_unit_id || "",
                              _repository_id: b.repository_id || "",
                            });
                            setTestResult(null);
                            loadJiraProjects(b.id).then(() => {
                              const pk = (b.config || {}).project_key;
                              if (pk) loadJiraIssueTypes(b.id, pk);
                            });
                          }}
                          className="flex flex-col items-start gap-0.5 px-3 py-2 text-left pr-7"
                        >
                          <span className={`text-xs font-medium ${isActive ? "text-white" : "text-slate-300"}`}>
                            {b.name || "Jira Board"}
                          </span>
                          <span className="text-[9px] text-slate-500">
                            {(b.config || {}).project_key || "—"} · {scopeLabel}
                          </span>
                        </button>
                        <button type="button"
                          aria-label={`Remove board ${b.name}`}
                          title="Remove this board"
                          onClick={(e) => {
                            e.stopPropagation();
                            // Route through handleDelete after pinning
                            // editingBoardId so handleDelete deletes
                            // THIS chip, not whichever was active.
                            setEditingBoardId(b.id);
                            // Use a microtask so editingBoardId is
                            // committed before handleDelete reads it.
                            setTimeout(() => handleDelete("jira"), 0);
                          }}
                          className="absolute top-1 right-1 w-4 h-4 flex items-center justify-center rounded text-slate-500 opacity-0 group-hover:opacity-100 hover:bg-red-500/20 hover:text-red-400 transition-all text-[11px] leading-none"
                        >
                          ×
                        </button>
                      </div>
                    );
                  })}
                  <button type="button"
                    onClick={() => {
                      setEditingBoardId("new");
                      setForm({ _scope_level: "organization", _name: "" });
                      setJiraProjects([]);
                      setJiraIssueTypes([]);
                      setTestResult(null);
                    }}
                    className={`flex items-center gap-1.5 px-3 py-2 rounded-lg border text-xs transition-all ${
                      editingBoardId === "new"
                        ? "border-red-500/40 bg-red-500/10 text-white"
                        : "border-dashed border-white/[0.12] bg-white/[0.01] text-slate-400 hover:border-red-500/30 hover:bg-red-500/5 hover:text-red-300"
                    }`}
                  >
                    {jiraBoards.length === 0 ? "+ Configure first board" : "+ Add another board"}
                  </button>
                </div>
              </div>
            )}

            {/* Board metadata (Jira multi-board only). The Name + Scope
                are stored as top-level columns on IntegrationConfig
                (not in the encrypted config dict) so the dispatcher
                can route on them without parsing the config payload. */}
            {t.provider === "jira" && (
              <div className="border border-white/[0.06] bg-white/[0.01] rounded-lg p-4 space-y-3">
                <p className="text-[10px] text-slate-500 uppercase tracking-wider font-medium">Board Identity & Scope</p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <label className="text-[10px] text-slate-500 block mb-1">
                      Board Name <span className="text-red-400">*</span>
                    </label>
                    <input value={form._name || ""}
                      onChange={(e) => { setForm((s) => ({ ...s, _name: e.target.value })); setTestResult(null); }}
                      placeholder="e.g. Engineering Board, Security Team"
                      className="input-dark text-xs w-full" />
                    <p className="text-[10px] text-slate-600 mt-1 leading-snug">A label for this board — shown on the chip above and in audit history.</p>
                  </div>
                  <div>
                    <label className="text-[10px] text-slate-500 block mb-1">
                      Scope <span className="text-red-400">*</span>
                    </label>
                    <select value={form._scope_level || "organization"}
                      onChange={(e) => {
                        const v = e.target.value;
                        setForm((s) => ({
                          ...s,
                          _scope_level: v,
                          _business_unit_id: v === "business_unit" ? (s._business_unit_id || "") : "",
                          _repository_id: v === "project" ? (s._repository_id || "") : "",
                        }));
                        setTestResult(null);
                      }}
                      className="select-dark text-xs w-full">
                      <option value="organization">Organization-wide (all findings)</option>
                      <option value="business_unit">Business Unit (all repos in a BU)</option>
                      <option value="project">Single Repository</option>
                    </select>
                    <p className="text-[10px] text-slate-600 mt-1 leading-snug">
                      {(form._scope_level || "organization") === "organization"
                        ? "Catches every finding in the tenant. Good as the default catch-all board."
                        : (form._scope_level === "business_unit")
                        ? "Tickets only fire when the finding's repository belongs to the chosen Business Unit."
                        : "Tickets only fire when the finding originates from this one repository."}
                    </p>
                  </div>
                  {(form._scope_level === "business_unit") && (
                    <div className="md:col-span-2">
                      <label className="text-[10px] text-slate-500 block mb-1">
                        Business Unit <span className="text-red-400">*</span>
                      </label>
                      <select value={form._business_unit_id || ""}
                        onChange={(e) => setForm((s) => ({ ...s, _business_unit_id: e.target.value }))}
                        className="select-dark text-xs w-full">
                        <option value="">— pick a business unit —</option>
                        {businessUnits.map((bu) => (
                          <option key={bu.id} value={bu.id}>{bu.name}</option>
                        ))}
                      </select>
                      {businessUnits.length === 0 && (
                        <p className="text-[10px] text-orange-400 mt-1">No business units yet — create one in Settings → Access Control first.</p>
                      )}
                    </div>
                  )}
                  {(form._scope_level === "project") && (
                    <div className="md:col-span-2">
                      <label className="text-[10px] text-slate-500 block mb-1">
                        Repository <span className="text-red-400">*</span>
                      </label>
                      <select value={form._repository_id || ""}
                        onChange={(e) => setForm((s) => ({ ...s, _repository_id: e.target.value }))}
                        className="select-dark text-xs w-full">
                        <option value="">— pick a repository —</option>
                        {repositories.map((repo) => (
                          <option key={repo.id} value={repo.id}>{repo.name}</option>
                        ))}
                      </select>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Connection credentials */}
            <div className="border border-white/[0.06] bg-white/[0.01] rounded-lg p-4 space-y-3">
              <p className="text-[10px] text-slate-500 uppercase tracking-wider font-medium">Connection</p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {t.fields.map((field) => {
                  const f = field as { key: string; label: string; type: string; required?: boolean; placeholder?: string; helpUrl?: string; helpLabel?: string; hint?: string };
                  // Jira-only: project_key and issue_type render as a real
                  // <select> populated from the live Jira API once the
                  // user has tested + saved their credentials. The
                  // dropdowns are loaded:
                  //   1. After a successful Test Connection (jiraProjects
                  //      arrives, then issue types arrive once a project
                  //      is picked), and
                  //   2. When an existing Jira config is opened (the
                  //      useEffect below pre-fetches both lists so the
                  //      dropdowns are ready before the user clicks).
                  // If the lists are empty (first-time setup, no token
                  // verified yet) we fall back to a free-text input so
                  // the form still works.
                  const isJiraProject = t.provider === "jira" && f.key === "project_key";
                  const isJiraIssueType = t.provider === "jira" && f.key === "issue_type";
                  const isSnowGroup = t.provider === "servicenow" && f.key === "assignment_group";
                  const showProjectSelect = isJiraProject && jiraProjects.length > 0;
                  const showIssueTypeSelect = isJiraIssueType && jiraIssueTypes.length > 0;
                  const showSnowGroupSelect = isSnowGroup && snowGroups.length > 0;
                  return (
                    <div key={f.key}>
                      <div className="flex items-center justify-between mb-1">
                        <label className="text-[10px] text-slate-500">{f.label} {f.required && <span className="text-red-400">*</span>}</label>
                        {f.helpUrl && (
                          // External link to wherever the credential is generated
                          // (Atlassian token page, Linear API key page, etc.).
                          // Discoverability fix added 2026-04-26 — without this
                          // hint, first-time setup is a guessing game.
                          <a href={f.helpUrl} target="_blank" rel="noopener noreferrer"
                            className="text-[10px] text-red-400 hover:text-red-300 inline-flex items-center gap-0.5">
                            {f.helpLabel || "Help"} &rarr;
                          </a>
                        )}
                        {/* (Removed the "N loaded" inline counter on
                            project / issue-type labels per user
                            feedback 2026-04-27 — the dropdown's own
                            options make it obvious whether the list
                            is real or empty, and the count was just
                            visual noise next to the asterisk.) */}
                      </div>
                      {showProjectSelect ? (
                        <select
                          value={form[f.key] || ""}
                          onChange={(e) => {
                            const val = e.target.value;
                            setForm((s) => ({ ...s, [f.key]: val, issue_type: "" }));
                            setTestResult(null);
                            // Project changed → fetch issue types for the
                            // new project. If no saved row yet, the call
                            // is a no-op (dropdown stays as text input).
                            const existing = configs[t.provider];
                            if (existing?.id && val) loadJiraIssueTypes(existing.id, val);
                            else setJiraIssueTypes([]);
                          }}
                          className="select-dark text-xs w-full"
                        >
                          <option value="">— pick a project —</option>
                          {jiraProjects.map((p) => (
                            <option key={p.key} value={p.key}>{p.key} · {p.name}</option>
                          ))}
                        </select>
                      ) : showIssueTypeSelect ? (
                        <select
                          value={form[f.key] || ""}
                          onChange={(e) => { setForm((s) => ({ ...s, [f.key]: e.target.value })); setTestResult(null); }}
                          className="select-dark text-xs w-full"
                        >
                          <option value="">— pick an issue type —</option>
                          {jiraIssueTypes.map((it) => (
                            <option key={it.id} value={it.name}>{it.name}</option>
                          ))}
                        </select>
                      ) : showSnowGroupSelect ? (
                        <select
                          value={form[f.key] || ""}
                          onChange={(e) => { setForm((s) => ({ ...s, [f.key]: e.target.value })); setTestResult(null); }}
                          className="select-dark text-xs w-full"
                        >
                          <option value="">— pick an assignment group —</option>
                          {snowGroups.map((g) => (
                            <option key={g.sys_id} value={g.name}>
                              {g.name}{g.description ? ` — ${g.description.slice(0, 60)}` : ""}
                            </option>
                          ))}
                        </select>
                      ) : (
                        <input
                          type={f.type === "password" ? "password" : "text"}
                          value={form[f.key] || ""}
                          onChange={(e) => { setForm((s) => ({ ...s, [f.key]: e.target.value })); setTestResult(null); }}
                          placeholder={f.placeholder || ""}
                          className="input-dark text-xs w-full"
                        />
                      )}
                      {/* Hint text under each input — shown only when
                          defined on the field, so older fields without
                          hints render unchanged. Keeps each field
                          self-explanatory without forcing the user to
                          hover or read external docs. */}
                      {f.hint && (
                        <p className="text-[10px] text-slate-600 mt-1 leading-snug">{f.hint}</p>
                      )}
                      {/* Inline preview-error chip under the Project
                          field — surfaces why the dropdown didn't
                          populate (was previously swallowed silently
                          when Atlassian rejected the credentials). */}
                      {isJiraProject && previewError && (
                        <p className="text-[10px] text-red-400 mt-1 leading-snug">⚠ {previewError}</p>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Push rules — what gets pushed and when */}
            <div className="border border-white/[0.06] bg-white/[0.01] rounded-lg p-4 space-y-3">
              <p className="text-[10px] text-slate-500 uppercase tracking-wider font-medium">Push Rules</p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1">Trigger</label>
                  <select value={form._push_trigger || "on_true_positive"} onChange={(e) => setForm((f) => ({ ...f, _push_trigger: e.target.value }))} className="select-dark text-xs w-full">
                    <option value="on_true_positive">On True Positive confirmation</option>
                    <option value="manual">Manual only (from finding actions)</option>
                    <option value="on_detection">On detection (before triage)</option>
                  </select>
                  <p className="text-[10px] text-slate-600 mt-1 leading-snug">When a ticket is created. Defaults to True Positive only — safest to avoid noise.</p>
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1">Push Frequency</label>
                  <select value={form._push_frequency || "immediate"} onChange={(e) => setForm((f) => ({ ...f, _push_frequency: e.target.value }))} className="select-dark text-xs w-full">
                    <option value="immediate">Immediate (real-time)</option>
                    <option value="hourly">Hourly batch</option>
                    <option value="daily">Daily digest</option>
                    <option value="weekly">Weekly summary</option>
                  </select>
                  <p className="text-[10px] text-slate-600 mt-1 leading-snug">How often qualifying findings are flushed to the board.</p>
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1">Minimum Severity</label>
                  <select value={form._min_severity || "medium"} onChange={(e) => setForm((f) => ({ ...f, _min_severity: e.target.value }))} className="select-dark text-xs w-full">
                    <option value="critical">Critical only</option>
                    <option value="high">High and above</option>
                    <option value="medium">Medium and above</option>
                    <option value="low">All severities</option>
                  </select>
                  <p className="text-[10px] text-slate-600 mt-1 leading-snug">Findings below this severity never create tickets.</p>
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1">Priority Mapping</label>
                  <select value={form._priority_mapping || "severity"} onChange={(e) => setForm((f) => ({ ...f, _priority_mapping: e.target.value }))} className="select-dark text-xs w-full">
                    <option value="severity">Map from severity (Critical → P1, High → P2, Med → P3)</option>
                    <option value="all_high">All as high priority</option>
                    <option value="all_medium">All as medium priority</option>
                  </select>
                  <p className="text-[10px] text-slate-600 mt-1 leading-snug">How Vooda severity translates to the destination board's priority field.</p>
                </div>
              </div>

              {/* What states to exclude — always shown */}
              <div>
                <label className="text-[10px] text-slate-500 block mb-1.5">Exclude from Ticketing</label>
                <div className="flex gap-2 flex-wrap">
                  {[
                    { key: "false_positive", label: "False Positive", default: true,
                      tooltip: "Findings the AI or a reviewer marked as not a real exposure" },
                    { key: "test_credential", label: "Test Credential", default: true,
                      tooltip: "Findings in test/fixture/spec paths or tagged as test" },
                    { key: "accepted_risk", label: "Accepted Risk", default: true,
                      tooltip: "Findings explicitly accepted by the security team" },
                    { key: "rotated", label: "Already Rotated", default: true,
                      tooltip: "Findings whose remediation has already been applied" },
                  ].map((ex) => {
                    const isExcluded = form[`_exclude_${ex.key}`] !== "false";
                    return (
                      <label key={ex.key} title={ex.tooltip} className="flex items-center gap-1.5 text-[10px] px-2.5 py-1.5 rounded-lg bg-white/[0.02] border border-white/[0.04] cursor-pointer hover:bg-white/[0.04]">
                        <input type="checkbox" checked={isExcluded}
                          onChange={(e) => setForm((f) => ({ ...f, [`_exclude_${ex.key}`]: e.target.checked ? "true" : "false" }))}
                          className="w-3 h-3 rounded border-slate-600 bg-dark-950 text-red-500" />
                        <span className="text-slate-400">{ex.label}</span>
                      </label>
                    );
                  })}
                </div>
                {/* Footnote adapts to the selected trigger so the
                    promise it makes ("only confirmed True Positives")
                    matches the rule the user just configured. The old
                    text was misleading whenever Trigger ≠ on_true_positive. */}
                <p className="text-[10px] text-slate-600 mt-1.5 leading-snug">
                  Checked items never create tickets.{" "}
                  {(form._push_trigger || "on_true_positive") === "on_true_positive"
                    ? "Only Likely / Confirmed True Positives at or above the minimum severity will be pushed."
                    : (form._push_trigger === "on_detection")
                    ? "All detected findings at or above the minimum severity will be pushed (regardless of triage state)."
                    : "Tickets are created only when you click \"Push to ticketing\" on a finding manually."}
                </p>
              </div>
            </div>

            {/* Ticket format.
                Issue Type is configured in the Connection panel above
                — it's a real Jira project field that has to match what
                the project actually exposes. Auto Labels is one
                concept, so we let it span full width instead of
                stranding it in a 2-col grid with empty space on the
                right (was a visible asymmetry in the layout audit). */}
            <div className="border border-white/[0.06] bg-white/[0.01] rounded-lg p-4 space-y-3">
              <p className="text-[10px] text-slate-500 uppercase tracking-wider font-medium">Ticket Format</p>
              <div>
                <label className="text-[10px] text-slate-500 block mb-1">Auto Labels</label>
                <input value={form._labels || "vooda-ai, secret-leak"} onChange={(e) => setForm((f) => ({ ...f, _labels: e.target.value }))}
                  placeholder="vooda-ai, secret-leak" className="input-dark text-xs w-full" />
                <p className="text-[10px] text-slate-600 mt-1 leading-snug">Comma-separated labels applied to every ticket Vooda creates.</p>
              </div>
            </div>

            {/* Test → Save → Cancel.
                "Test" hits /integrations/test-ticketing with the form
                values, never persisting them. Lets users verify the
                token works BEFORE committing it to the encrypted store.
                Result chip below shows green/red with a precise message
                from the provider (e.g. "Authenticated as Jane Doe" or
                "Atlassian rejected credentials — generate an API token"). */}
            <div className="flex items-center gap-2 flex-wrap">
              <button onClick={() => handleTestForm(t.provider, t.fields)} disabled={testing === t.provider || saving}
                className="px-3 py-1.5 rounded-lg text-xs font-medium border border-red-500/30 text-red-400 hover:bg-red-500/10 transition-all disabled:opacity-50">
                {testing === t.provider ? "Testing..." : "Test Connection"}
              </button>
              <button onClick={() => handleSave(t.provider, t.fields)} disabled={saving || testing === t.provider}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/15 text-red-400 hover:bg-red-500/25 transition-all disabled:opacity-50">
                {saving ? "Saving..."
                  : t.provider === "jira"
                    ? (editingBoardId === "new" ? "Add Board" : "Update Board")
                    : (isConfigured ? "Update" : "Connect")}
              </button>
              <button onClick={() => { setExpandedId(null); setTestResult(null); }} className="btn-secondary-sm">Cancel</button>
              {testResult && (
                <div className={`text-[11px] px-2.5 py-1 rounded-md border max-w-full ${
                  testResult.status === "success"
                    ? "bg-green-500/10 text-green-400 border-green-500/20"
                    : testResult.status === "auth_failed"
                    ? "bg-orange-500/10 text-orange-400 border-orange-500/20"
                    : "bg-red-500/10 text-red-400 border-red-500/20"
                }`}>
                  <div>{testResult.status === "success" ? "✓" : testResult.status === "auth_failed" ? "⚠" : "✗"} {testResult.message}</div>
                  {/* Show server-supplied details — HTTP status, body preview, etc. — so
                      the user can see WHY it failed without me asking them to check
                      the network tab. Empty when the test succeeded. */}
                  {testResult.details && Object.keys(testResult.details).length > 0 && (
                    <div className="mt-1 pt-1 border-t border-white/[0.06] font-mono text-[10px] opacity-70 break-all">
                      {Object.entries(testResult.details).map(([k, v]) => (
                        <div key={k}>{k}: {String(v).slice(0, 160)}</div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        );
      })()}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  WEBHOOKS (INBOUND) — 3 tiles, click to expand
// ═══════════════════════════════════════════════════════════════

const WEBHOOK_PROVIDERS = [
  { name: "GitHub", provider: "github", events: ["push", "pull_request"], color: "from-slate-600 to-slate-700",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="9" /><path d="M4.93 4.93l4.24 4.24M14.83 14.83l4.24 4.24M4.93 19.07l4.24-4.24M14.83 9.17l4.24-4.24" /></svg>),
    endpoint: "/api/v1/webhooks/github", signature: "X-Hub-Signature-256", sigType: "HMAC-SHA256",
    setupUrl: "https://docs.github.com/en/webhooks/using-webhooks/creating-webhooks", setupLabel: "GitHub Docs" },
  { name: "GitLab", provider: "gitlab", events: ["Push Hook", "Merge Request Hook"], color: "from-orange-500 to-red-500",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 2l3 9h6l-5 4 2 9-6-5-6 5 2-9-5-4h6l3-9z" /></svg>),
    endpoint: "/api/v1/webhooks/gitlab", signature: "X-Gitlab-Token", sigType: "Secret token",
    setupUrl: "https://docs.gitlab.com/ee/user/project/integrations/webhooks.html", setupLabel: "GitLab Docs" },
  { name: "Bitbucket", provider: "bitbucket", events: ["repo:push", "pullrequest:created"], color: "from-blue-500 to-cyan-500",
    icon: (<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M3 5h18l-2 14H5L3 5z" /><ellipse cx="12" cy="12" rx="3" ry="2" /></svg>),
    endpoint: "/api/v1/webhooks/bitbucket", signature: "X-Hub-Signature", sigType: "HMAC-SHA256",
    setupUrl: "https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/", setupLabel: "Bitbucket Docs" },
];

function WebhooksSection() {
  const [expandedProvider, setExpandedProvider] = useState<string | null>(null);
  const [webhookSecrets, setWebhookSecrets] = useState<Record<string, string>>({});
  const [webhookStatus, setWebhookStatus] = useState<Record<string, { enabled: boolean; lastEvent?: string; totalEvents?: number }>>({});
  const [copied, setCopied] = useState<string | null>(null);
  const [testing, setTesting] = useState<string | null>(null);

  // Load webhook config on mount
  useEffect(() => {
    api.get("/webhooks/config").then((r) => {
      const data = r.data || {};
      const secrets: Record<string, string> = {};
      const status: Record<string, { enabled: boolean; lastEvent?: string; totalEvents?: number }> = {};
      for (const wh of (data.webhooks || [])) {
        if (wh.secret) secrets[wh.provider] = wh.secret;
        status[wh.provider] = { enabled: wh.enabled ?? true, lastEvent: wh.last_event_at, totalEvents: wh.total_events };
      }
      setWebhookSecrets(secrets);
      setWebhookStatus(status);
    }).catch(() => {
      // No config yet — all unconfigured
    });
  }, []);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleTest = async (provider: string) => {
    setTesting(provider);
    try {
      await api.post(`/webhooks/${provider}/test`);
      setWebhookStatus((s) => ({ ...s, [provider]: { ...s[provider], enabled: true } }));
    } catch { /* ignore */ }
    finally { setTesting(null); }
  };

  const handleToggle = async (provider: string, enabled: boolean) => {
    setWebhookStatus((s) => ({ ...s, [provider]: { ...s[provider], enabled } }));
    try {
      await api.put(`/webhooks/${provider}/config`, { enabled });
    } catch { /* revert on failure */ }
  };

  const baseUrl = typeof window !== "undefined" ? window.location.origin : "";

  return (
    <div>
      {/* ── Available Webhook Sources ──
          Card + uppercase section header to match the design
          language of Notifications + AI Provider sub-sections
          (2026-05-19 design consolidation).  Tiles continue to be
          the Add affordance — clicking expands the configure panel
          inline below. */}
      <div className="card mb-5">
        <div className="flex items-center justify-between mb-4 gap-3">
          <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Available Webhook Sources</h4>
        </div>

      {/* 3 tiles side by side */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {WEBHOOK_PROVIDERS.map((wh) => {
          const isExpanded = expandedProvider === wh.provider;
          const status = webhookStatus[wh.provider];
          const hasSecret = !!webhookSecrets[wh.provider];
          const isConfigured = hasSecret || status?.enabled;

          return (
            <button
              key={wh.provider}
              onClick={() => setExpandedProvider(isExpanded ? null : wh.provider)}
              className={`relative text-left rounded-xl border p-4 transition-all duration-200 ${
                isExpanded
                  ? "border-red-500/30 bg-red-500/5 ring-1 ring-red-500/20"
                  : isConfigured
                    ? "border-green-500/20 bg-white/[0.02] hover:border-green-500/30 hover:bg-white/[0.04]"
                    : "border-white/[0.06] bg-white/[0.02] hover:border-white/[0.12] hover:bg-white/[0.04]"
              }`}
            >
              {/* Status badge — top right */}
              <div className="absolute top-3 right-3 pointer-events-none">
                {isConfigured ? (
                  <span className="text-[8px] px-1.5 py-0.5 rounded-full bg-green-500/15 text-green-400 border border-green-500/20 flex items-center gap-1">
                    <span className="w-1 h-1 rounded-full bg-green-400" />Active
                  </span>
                ) : (
                  <span className="text-[8px] px-1.5 py-0.5 rounded-full bg-slate-500/10 text-slate-500 border border-slate-500/20">Not connected</span>
                )}
              </div>
              <div className="flex items-center gap-3 pr-16">
                <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${wh.color} flex items-center justify-center text-white shrink-0`}>
                  {wh.icon}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-white">{wh.name}</p>
                  {status?.totalEvents ? (
                    <p className="text-[10px] text-slate-500 mt-0.5">{status.totalEvents} events received</p>
                  ) : (
                    <p className="text-[10px] text-slate-600 mt-0.5">Click to configure</p>
                  )}
                </div>
              </div>
            </button>
          );
        })}
      </div>
      </div>

      {/* Expanded detail panel — appears below tiles */}
      {expandedProvider && (() => {
        const wh = WEBHOOK_PROVIDERS.find((w) => w.provider === expandedProvider);
        if (!wh) return null;
        const status = webhookStatus[wh.provider];
        const secret = webhookSecrets[wh.provider];
        const fullUrl = `${baseUrl}${wh.endpoint}`;

        return (
          <div className="bg-white/[0.02] border border-red-500/20 rounded-xl p-5 space-y-4 animate-in fade-in duration-200">
            {/* Header */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`w-8 h-8 rounded-lg bg-gradient-to-br ${wh.color} flex items-center justify-center text-white`}>{wh.icon}</div>
                <h4 className="text-sm font-semibold text-white">{wh.name} Webhook Configuration</h4>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleToggle(wh.provider, !(status?.enabled ?? false))}
                  className={`relative w-9 h-5 rounded-full transition-colors ${status?.enabled ? "bg-green-500" : "bg-slate-700"}`}
                >
                  <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${status?.enabled ? "left-[18px]" : "left-0.5"}`} />
                </button>
                <span className="text-[10px] text-slate-500">{status?.enabled ? "Enabled" : "Disabled"}</span>
              </div>
            </div>

            {/* Config fields */}
            <div className="space-y-3">
              {/* Payload URL */}
              <div>
                <label className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">Payload URL</label>
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-xs text-red-400 font-mono bg-black/20 rounded-lg px-3 py-2 truncate">{fullUrl}</code>
                  <button onClick={() => handleCopy(fullUrl, `url-${wh.provider}`)}
                    className={`shrink-0 px-3 py-2 rounded-lg text-[10px] font-medium transition-all ${copied === `url-${wh.provider}` ? "bg-green-500/15 text-green-400" : "bg-white/[0.04] text-slate-400 hover:text-red-400 hover:bg-white/[0.08]"}`}>
                    {copied === `url-${wh.provider}` ? "Copied!" : "Copy"}
                  </button>
                </div>
              </div>

              {/* Secret */}
              <div>
                <label className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">Webhook Secret</label>
                <div className="flex items-center gap-2">
                  <input
                    type="password"
                    value={secret || ""}
                    readOnly
                    placeholder="Not set — click Generate to create one"
                    className="input-dark flex-1 text-xs font-mono"
                  />
                  {secret ? (
                    <div className="flex gap-1.5">
                      <button onClick={() => handleCopy(secret, `secret-${wh.provider}`)}
                        className={`shrink-0 px-3 py-2 rounded-lg text-[10px] font-medium transition-all ${copied === `secret-${wh.provider}` ? "bg-green-500/15 text-green-400" : "bg-white/[0.04] text-slate-400 hover:text-red-400"}`}>
                        {copied === `secret-${wh.provider}` ? "Copied!" : "Copy"}
                      </button>
                      <button onClick={() => {
                        const newSecret = "whsec_" + Array.from(crypto.getRandomValues(new Uint8Array(24))).map(b => b.toString(16).padStart(2, "0")).join("");
                        setWebhookSecrets((s) => ({ ...s, [wh.provider]: newSecret }));
                        api.put(`/webhooks/${wh.provider}/config`, { secret: newSecret }).catch(() => {});
                      }} className="shrink-0 px-3 py-2 rounded-lg text-[10px] font-medium bg-white/[0.04] text-orange-400 hover:bg-orange-500/10 transition-all">
                        Regenerate
                      </button>
                    </div>
                  ) : (
                    <button onClick={() => {
                      const newSecret = "whsec_" + Array.from(crypto.getRandomValues(new Uint8Array(24))).map(b => b.toString(16).padStart(2, "0")).join("");
                      setWebhookSecrets((s) => ({ ...s, [wh.provider]: newSecret }));
                      api.put(`/webhooks/${wh.provider}/config`, { secret: newSecret, enabled: true }).catch(() => {});
                      setWebhookStatus((s) => ({ ...s, [wh.provider]: { ...s[wh.provider], enabled: true } }));
                    }} className="shrink-0 px-3 py-2 rounded-lg text-[10px] font-medium bg-red-500/15 text-red-400 hover:bg-red-500/25 transition-all">
                      Generate
                    </button>
                  )}
                </div>
              </div>

              {/* Info row */}
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-black/20 rounded-lg px-3 py-2">
                  <span className="text-[10px] text-slate-500 block">Events</span>
                  <div className="flex gap-1 mt-1 flex-wrap">
                    {wh.events.map((e) => (
                      <span key={e} className="text-[9px] px-1.5 py-0.5 rounded bg-white/[0.06] text-slate-400">{e}</span>
                    ))}
                  </div>
                </div>
                <div className="bg-black/20 rounded-lg px-3 py-2">
                  <span className="text-[10px] text-slate-500 block">Signature</span>
                  <code className="text-[10px] text-red-400/70 mt-1 block">{wh.signature}</code>
                  <span className="text-[9px] text-slate-600">{wh.sigType}</span>
                </div>
                <div className="bg-black/20 rounded-lg px-3 py-2">
                  <span className="text-[10px] text-slate-500 block">Last Event</span>
                  <span className="text-xs text-slate-300 mt-1 block">
                    {status?.lastEvent ? new Date(status.lastEvent).toLocaleString() : "No events yet"}
                  </span>
                  {status?.totalEvents ? <span className="text-[9px] text-slate-600">{status.totalEvents} total</span> : null}
                </div>
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center justify-between pt-2 border-t border-white/[0.04]">
              <button onClick={() => handleTest(wh.provider)} disabled={testing === wh.provider}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-red-400 border border-red-500/20 hover:bg-red-500/10 transition-all disabled:opacity-50">
                {testing === wh.provider ? (
                  <><div className="w-3 h-3 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" />Testing...</>
                ) : (
                  <><svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>Test Connection</>
                )}
              </button>
              <a href={wh.setupUrl} target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-red-400 transition-colors">
                {wh.setupLabel}
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
              </a>
            </div>
          </div>
        );
      })()}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════

function ScannersFullSection() {
  // Register header action with page-level breadcrumb.
  const { setAction } = useContext(SectionActionContext);
  const openAddRef = useRef<() => void>(() => {});
  const [savedIntegrations, setSavedIntegrations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [selectedProvider, setSelectedProvider] = useState<string>("");
  const [schema, setSchema] = useState<any>(null);
  const [formData, setFormData] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [testStatus, setTestStatus] = useState<{ status: string; message: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [menuOpen, setMenuOpen] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  const loadIntegrations = () => {
    getIntegrations()
      .then((r) => setSavedIntegrations((r.data || []).filter((i: any) => SCANNERS.some((s) => s.provider === i.provider))))
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { loadIntegrations(); }, []);

  const resetForm = () => {
    setEditingId(null);
    setSelectedProvider("");
    setSchema(null);
    setFormData({});
    setTestStatus(null);
  };

  const handleSelectProvider = (provider: string) => {
    setSelectedProvider(provider);
    setTestStatus(null);
    setFormData({});
    getProviderSchema(provider).then((r) => {
      setSchema(r.data);
      const init: Record<string, string> = {};
      for (const f of r.data.fields) init[f.key] = "";
      setFormData(init);
    });
    setShowForm(true);
    setTimeout(() => document.getElementById("scanner-form")?.scrollIntoView({ behavior: "smooth" }), 100);
  };

  const handleEditScanner = (integration: any) => {
    setEditingId(integration.id);
    setSelectedProvider(integration.provider);
    setTestStatus(null);
    getProviderSchema(integration.provider).then((r) => {
      setSchema(r.data);
      const init: Record<string, string> = {};
      for (const f of r.data.fields) init[f.key] = integration.config?.[f.key] || "";
      setFormData(init);
    });
    setShowForm(true);
    setTimeout(() => document.getElementById("scanner-form")?.scrollIntoView({ behavior: "smooth" }), 100);
  };

  const handleTest = async () => {
    setTesting(true);
    setTestStatus(null);
    try {
      const testConfig: Record<string, string> = {};
      for (const [k, v] of Object.entries(formData)) {
        if (v && !v.includes("•")) testConfig[k] = v;
      }
      const res = await testIntegrationConnection({ provider: selectedProvider, config: Object.keys(testConfig).length > 0 ? testConfig : formData });
      setTestStatus({ status: res.data.status, message: res.data.message });
    } catch {
      setTestStatus({ status: "error", message: "Failed to test connection" });
    }
    setTesting(false);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      if (editingId) {
        await updateIntegration(editingId, { name: schema?.label, config: formData });
      } else {
        await createIntegration({ provider: selectedProvider, name: schema?.label, config: formData });
      }
      setShowForm(false);
      resetForm();
      loadIntegrations();
    } catch (err: any) {
      setTestStatus({ status: "error", message: err?.response?.data?.detail || "Failed to save" });
    }
    setSaving(false);
  };

  const handleDisconnect = async (id: string) => {
    await deleteIntegration(id).catch(() => {});
    setConfirmDelete(null);
    setMenuOpen(null);
    loadIntegrations();
  };

  const sDef = (provider: string) => SCANNERS.find((s) => s.provider === provider);

  // Scanners section is currently a stub (the SCANNERS array is
  // intentionally empty — Vooda is its own scanner, no external
  // ones to register).  Add Scanner button removed from the page
  // header to match the design consolidation across the other
  // integration sub-sections (Notifications, AI Provider).  If
  // external scanners are re-introduced later, add an inline
  // button to the Connected Scanners card header, same pattern as
  // the other sections.
  openAddRef.current = () => { resetForm(); setShowForm(true); };

  return (
    <div>
      {/* Header H2 + description + Add button removed 2026-05-14 —
          see SectionActionContext at top of file. */}

      {/* Connected Scanners */}
      <div className="card mb-5 overflow-visible relative z-10">
        <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">Connected Scanners</h4>
        {loading ? (
          <div className="text-center py-8"><div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin mx-auto" /></div>
        ) : savedIntegrations.length === 0 ? (
          <div className="text-center py-10">
            <p className="text-sm text-slate-500">No scanners connected</p>
            <p className="text-xs text-slate-600 mt-1">Add a security scanner to start importing findings</p>
          </div>
        ) : (
          <div className="space-y-3">
            {savedIntegrations.map((integration: any) => {
              const sc = sDef(integration.provider);
              return (
                <div key={integration.id} className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-4 flex items-center gap-4">
                  <div className={`w-11 h-11 rounded-xl bg-gradient-to-br ${sc?.color || "from-slate-500 to-slate-600"} flex items-center justify-center shrink-0 text-white`}>
                    <ScannerIcon provider={integration.provider} className="w-5 h-5" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium text-slate-200">{integration.name || sc?.name || integration.provider}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded ${integration.is_active ? "bg-green-500/15 text-green-400 border border-green-500/20" : "bg-slate-500/15 text-slate-500 border border-slate-500/20"}`}>
                        {integration.is_active ? "Active" : "Disabled"}
                      </span>
                      {sc && <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/20">{sc.type}</span>}
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5">{sc?.name || integration.provider}</p>
                    <p className="text-[10px] text-slate-600 mt-1">Connected {new Date(integration.created_at).toLocaleDateString()}</p>
                  </div>
                  {/* Actions menu */}
                  <div className="relative shrink-0">
                    <button onClick={() => setMenuOpen(menuOpen === integration.id ? null : integration.id)} className="p-1.5 rounded-lg hover:bg-white/[0.06]">
                      <svg className="w-4 h-4 text-slate-500" fill="currentColor" viewBox="0 0 20 20"><path d="M10 6a2 2 0 110-4 2 2 0 010 4zM10 12a2 2 0 110-4 2 2 0 010 4zM10 18a2 2 0 110-4 2 2 0 010 4z" /></svg>
                    </button>
                    {menuOpen === integration.id && (
                      <>
                        <div className="fixed inset-0 z-10" onClick={() => setMenuOpen(null)} />
                        <div className="absolute right-0 top-8 z-30 w-44 py-1 rounded-lg border border-white/[0.08] shadow-xl" style={{ background: "rgba(8,11,28,0.95)",  }}>
                          <button onClick={() => { setMenuOpen(null); handleEditScanner(integration); }}
                            className="block w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-white/[0.04]">
                            <span className="flex items-center gap-2">
                              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" /></svg>
                              Edit Scanner
                            </span>
                          </button>
                          <button onClick={() => {
                            setMenuOpen(null);
                            setSelectedProvider(integration.provider);
                            // Load schema then test with current config
                            getProviderSchema(integration.provider).then((r) => {
                              setSchema(r.data);
                              const cfg: Record<string, string> = {};
                              for (const f of r.data.fields) cfg[f.key] = integration.config?.[f.key] || "";
                              setFormData(cfg);
                              testIntegrationConnection({ provider: integration.provider, config: integration.config })
                                .then((res) => setTestStatus({ status: res.data.status, message: res.data.message }))
                                .catch(() => setTestStatus({ status: "error", message: "Test failed" }));
                            });
                          }}
                            className="block w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-white/[0.04]">
                            <span className="flex items-center gap-2">
                              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
                              Test Connection
                            </span>
                          </button>
                          <button onClick={() => {
                            setMenuOpen(null);
                            updateIntegration(integration.id, { is_active: !integration.is_active }).then(() => loadIntegrations());
                          }} className="block w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-white/[0.04]">
                            <span className="flex items-center gap-2">
                              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
                              {integration.is_active ? "Disable" : "Enable"}
                            </span>
                          </button>
                          <div className="border-t border-white/[0.06] my-1" />
                          <button onClick={() => { setMenuOpen(null); setConfirmDelete(integration.id); }}
                            className="block w-full text-left px-4 py-2 text-sm text-red-400 hover:bg-red-500/5">
                            <span className="flex items-center gap-2">
                              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                              Disconnect
                            </span>
                          </button>
                        </div>
                      </>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Test Connection result banner (when tested from menu) */}
      {testStatus && !showForm && (
        <div className={`flex items-center gap-2 p-3 rounded-lg mb-5 text-sm ${
          testStatus.status === "success" ? "bg-green-500/5 border border-green-500/15 text-green-400" : "bg-red-500/5 border border-red-500/15 text-red-400"
        }`}>
          {testStatus.status === "success" ? (
            <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
          ) : (
            <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          )}
          {testStatus.message}
          <button onClick={() => setTestStatus(null)} className="ml-auto text-xs opacity-60 hover:opacity-100">Dismiss</button>
        </div>
      )}

      {/* Add/Edit Scanner Form (inline) */}
      {showForm && (
        <div id="scanner-form" className="card border-red-500/20 mb-5">
          <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-5">
            {editingId ? "Edit Scanner Configuration" : "Connect a Security Scanner"}
          </h4>

          {/* Step 1: Provider selection (new only) */}
          {!selectedProvider ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
              {SCANNERS.map((s) => (
                <button key={s.provider} onClick={() => handleSelectProvider(s.provider)}
                  className="text-left p-4 rounded-xl border border-white/[0.06] hover:border-red-500/30 hover:bg-red-500/5 transition-all">
                  <div className="flex items-center gap-3 mb-2">
                    <div className={`w-9 h-9 rounded-lg bg-gradient-to-br ${s.color} flex items-center justify-center text-white`}>
                      <ScannerIcon provider={s.provider} className="w-4.5 h-4.5" />
                    </div>
                    <div>
                      <span className="text-sm font-medium text-slate-200">{s.name}</span>
                      <span className="block text-[10px] text-slate-500">{s.type}</span>
                    </div>
                  </div>
                  <div className="flex gap-1">
                    {s.formats.map((f) => (
                      <span key={f} className="text-[9px] px-1.5 py-0.5 rounded bg-white/[0.04] text-slate-500 border border-white/[0.04]">{f}</span>
                    ))}
                  </div>
                </button>
              ))}
            </div>
          ) : schema ? (
            <>
              {/* Provider header */}
              <div className="flex items-center gap-3 mb-5 pb-4 border-b border-white/[0.06]">
                <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${sDef(selectedProvider)?.color || "from-slate-500 to-slate-600"} flex items-center justify-center text-white`}>
                  <ScannerIcon provider={selectedProvider} className="w-5 h-5" />
                </div>
                <div className="flex-1">
                  <h5 className="text-sm font-semibold text-white">{schema.label}</h5>
                  <p className="text-xs text-slate-500">{schema.description}</p>
                </div>
                {!editingId && (
                  <button onClick={() => { setSelectedProvider(""); setSchema(null); setFormData({}); setTestStatus(null); }}
                    className="text-xs text-slate-500 hover:text-red-400 transition-colors">Change</button>
                )}
              </div>

              {/* Config fields */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-5">
                {schema.fields.map((field: any) => (
                  <div key={field.key} className={schema.fields.length === 1 ? "md:col-span-2" : ""}>
                    <label className="text-xs text-slate-500 mb-1.5 block">
                      {field.label}{field.required && !editingId && <span className="text-red-400 ml-1">*</span>}
                    </label>
                    {field.type === "select" ? (
                      <select value={formData[field.key] || ""} onChange={(e) => setFormData((d) => ({ ...d, [field.key]: e.target.value }))} className="select-dark w-full">
                        <option value="">Select...</option>
                        {(field.options || []).map((opt: string) => (
                          <option key={opt} value={opt}>{opt.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase())}</option>
                        ))}
                      </select>
                    ) : (
                      <input type={field.type === "password" ? "password" : field.type === "url" ? "url" : "text"}
                        value={formData[field.key] || ""} onChange={(e) => setFormData((d) => ({ ...d, [field.key]: e.target.value }))}
                        placeholder={editingId && field.type === "password" ? "Leave blank to keep current" : (field.placeholder || "")} className="input-dark" />
                    )}
                  </div>
                ))}
              </div>

              {/* Test status */}
              {testStatus && (
                <div className={`flex items-center gap-2 p-3 rounded-lg mb-5 text-sm ${
                  testStatus.status === "success" ? "bg-green-500/5 border border-green-500/15 text-green-400" : "bg-red-500/5 border border-red-500/15 text-red-400"
                }`}>
                  {testStatus.status === "success" ? (
                    <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                  ) : (
                    <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                  )}
                  {testStatus.message}
                </div>
              )}

              {/* Actions */}
              <div className="flex gap-3">
                <button onClick={handleTest} disabled={testing} className="btn-secondary flex items-center gap-2">
                  {testing ? (
                    <><div className="w-3.5 h-3.5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" />Testing...</>
                  ) : (
                    <><svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>Test Connection</>
                  )}
                </button>
                {editingId ? (
                  <button onClick={handleSave} disabled={saving} className="btn-primary flex items-center gap-2">
                    {saving ? "Saving..." : "Update Scanner"}
                  </button>
                ) : testStatus?.status === "success" ? (
                  <button onClick={handleSave} disabled={saving} className="btn-primary flex items-center gap-2">
                    {saving ? "Saving..." : "Save & Connect"}
                  </button>
                ) : null}
                <button onClick={() => { setShowForm(false); resetForm(); }} className="btn-secondary">Cancel</button>
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center py-8"><div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" /></div>
          )}
        </div>
      )}

      {/* Delete confirmation */}
      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="card border-red-500/20 max-w-md w-full mx-4">
            <h4 className="text-base font-semibold text-white mb-2">Disconnect Scanner</h4>
            <p className="text-sm text-slate-400 mb-4">Are you sure? This will remove the scanner integration and its configuration.</p>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setConfirmDelete(null)} className="btn-secondary text-sm">Cancel</button>
              <button onClick={() => handleDisconnect(confirmDelete)} className="btn-danger text-sm">Disconnect</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function NotificationsFullSection() {
  // Register the "+ Add Channel" header action with the page-level
  // breadcrumb row so the section header doesn't duplicate the
  // breadcrumb's identity.  Cleared on unmount / when showForm flips
  // (no Add button visible while the create form is open).
  const { setAction } = useContext(SectionActionContext);
  const [savedIntegrations, setSavedIntegrations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [selectedProvider, setSelectedProvider] = useState<string>("");
  const [schema, setSchema] = useState<any>(null);
  const [formData, setFormData] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [testStatus, setTestStatus] = useState<{ status: string; message: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [menuOpen, setMenuOpen] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  // Tracks which sensitive keys ARE configured on the current edit
  // target — backend ships this in `secrets_present` because the
  // actual ciphertext is intentionally NOT exposed in the masked
  // response.  Drives the "✓ currently set" indicator next to empty
  // sensitive inputs so the user knows the field is configured.
  const [secretsPresent, setSecretsPresent] = useState<string[]>([]);

  // Scoping
  const [scopeLevel, setScopeLevel] = useState("organization");
  const [businessUnitId, setBusinessUnitId] = useState("");
  const [repositoryId, setRepositoryId] = useState("");
  const [businessUnits, setBusinessUnits] = useState<{ id: string; name: string }[]>([]);
  const [repositories, setRepositories] = useState<{ id: string; name: string; business_unit_id?: string | null }[]>([]);

  // Rules
  interface NotifRule { id: string; event_type: string; label: string; severity_threshold: string; is_enabled: boolean; }
  const [notifRules, setNotifRules] = useState<NotifRule[]>([]);
  const [rulesLoading, setRulesLoading] = useState(false);
  const [rulesSaving, setRulesSaving] = useState(false);
  const [rulesDirty, setRulesDirty] = useState(false);

  const loadIntegrations = () => {
    getIntegrations()
      .then((r) => setSavedIntegrations((r.data || []).filter((i: any) => i.integration_type === "notification")))
      .catch(() => {})
      .finally(() => setLoading(false));
  };
  const loadRules = () => {
    setRulesLoading(true);
    getNotificationRules().then((r) => setNotifRules(r.data?.rules || [])).catch(() => {}).finally(() => setRulesLoading(false));
  };
  const saveRules = async () => {
    setRulesSaving(true);
    try {
      const res = await updateNotificationRules(notifRules.map((r) => ({ event_type: r.event_type, severity_threshold: r.severity_threshold, is_enabled: r.is_enabled })));
      setNotifRules(res.data?.rules || notifRules);
      setRulesDirty(false);
    } catch {}
    setRulesSaving(false);
  };

  useEffect(() => {
    loadIntegrations();
    loadRules();
    getBusinessUnits().then((r) => setBusinessUnits(r.data?.business_units || r.data || [])).catch(() => {});
    getRepositories({ page_size: 200 }).then((r) => {
      const d = r.data;
      setRepositories(d?.items ?? (Array.isArray(d) ? d : d?.repositories || []));
    }).catch(() => {});
  }, []);

  // Ref pattern lets the action button click handler reach the
  // latest resetForm / setShowForm without forcing them to be
  // defined before the useEffect that registers the action.  Without
  // the ref we'd either (a) have to hoist resetForm above this hook
  // — possible but invasive — or (b) recreate the button on every
  // render that touches the form state.  The ref makes the closure
  // always read the current value.
  const openAddRef = useRef<() => void>(() => {});
  const defaultBU = businessUnits.find((bu) => bu.name === "Default");
  const filteredRepos = businessUnitId
    ? repositories.filter((r: any) => {
        if (r.business_unit_id) return r.business_unit_id === businessUnitId;
        return defaultBU && businessUnitId === defaultBU.id;
      })
    : repositories;

  const resetForm = () => {
    setEditingId(null);
    setSelectedProvider("");
    setSchema(null);
    setFormData({});
    setTestStatus(null);
    setScopeLevel("organization");
    setBusinessUnitId("");
    setRepositoryId("");
    setSecretsPresent([]);
  };

  // Add Channel affordance now lives INLINE in the Connected
  // Channels card header (see render below) rather than the page-
  // level breadcrumb row.  Same rationale as the AI Provider
  // section: each integration category owns its Add button next to
  // its own card header, matching the existing Webhooks / Ticketing
  // / Identity / SIEM / Vault tile patterns.  Avoids the previous
  // header-button look that suggested a page-level primary action.
  openAddRef.current = () => { resetForm(); setShowForm(true); };

  const handleSelectProvider = (provider: string) => {
    setSelectedProvider(provider);
    setTestStatus(null);
    setFormData({});
    setScopeLevel("organization");
    setBusinessUnitId("");
    setRepositoryId("");
    getProviderSchema(provider).then((r) => {
      setSchema(r.data);
      const init: Record<string, string> = {};
      for (const f of r.data.fields) init[f.key] = "";
      setFormData(init);
    });
    setShowForm(true);
    setTimeout(() => document.getElementById("notif-form")?.scrollIntoView({ behavior: "smooth" }), 100);
  };

  const handleEditChannel = (integration: any) => {
    setEditingId(integration.id);
    setSelectedProvider(integration.provider);
    setTestStatus(null);
    setScopeLevel(integration.scope_level || "organization");
    setBusinessUnitId(integration.business_unit_id || "");
    setRepositoryId(integration.repository_id || "");
    // Capture which sensitive keys ARE configured server-side so the
    // form can render a "✓ currently set" indicator next to the
    // (intentionally empty) input.  The backend masks secrets to ""
    // so the user is forced into the "leave blank to keep, or type
    // new" pattern rather than seeing garbled ciphertext.
    setSecretsPresent(integration.secrets_present || []);
    // Load the provider schema and pre-fill with existing config.
    // Sensitive fields will be empty strings (backend masks them);
    // the placeholder "Leave blank to keep current" surfaces in that
    // case (see input rendering below).
    getProviderSchema(integration.provider).then((r) => {
      setSchema(r.data);
      const init: Record<string, string> = {};
      for (const f of r.data.fields) init[f.key] = integration.config?.[f.key] || "";
      setFormData(init);
    });
    setShowForm(true);
    setTimeout(() => document.getElementById("notif-form")?.scrollIntoView({ behavior: "smooth" }), 100);
  };

  const handleTest = async () => {
    setTesting(true);
    setTestStatus(null);
    try {
      // For edit mode, only send non-masked values for testing
      const testConfig: Record<string, string> = {};
      for (const [k, v] of Object.entries(formData)) {
        if (v && !v.includes("•")) testConfig[k] = v;
      }
      const res = await testIntegrationConnection({ provider: selectedProvider, config: Object.keys(testConfig).length > 0 ? testConfig : formData });
      setTestStatus({ status: res.data.status, message: res.data.message });
    } catch {
      setTestStatus({ status: "error", message: "Failed to test connection" });
    }
    setTesting(false);
  };

  const handleSave = async () => {
    if (scopeLevel === "business_unit" && !businessUnitId) { setTestStatus({ status: "error", message: "Select a Business Unit" }); return; }
    if (scopeLevel === "project" && !repositoryId) { setTestStatus({ status: "error", message: "Select a Repository" }); return; }
    setSaving(true);
    try {
      if (editingId) {
        // Update existing integration
        await updateIntegration(editingId, {
          name: schema?.label,
          config: formData,
          scope_level: scopeLevel,
          business_unit_id: scopeLevel === "business_unit" ? businessUnitId : undefined,
          repository_id: scopeLevel === "project" ? repositoryId : undefined,
        });
      } else {
        // Create new integration
        await createIntegration({
          provider: selectedProvider,
          name: schema?.label,
          config: formData,
          scope_level: scopeLevel,
          business_unit_id: scopeLevel === "business_unit" ? businessUnitId : undefined,
          repository_id: scopeLevel === "project" ? repositoryId : undefined,
        });
      }
      setShowForm(false);
      resetForm();
      loadIntegrations();
    } catch (err: any) {
      setTestStatus({ status: "error", message: err?.response?.data?.detail || "Failed to save" });
    }
    setSaving(false);
  };

  const handleDisconnect = async (id: string) => {
    await deleteIntegration(id).catch(() => {});
    setConfirmDelete(null);
    setMenuOpen(null);
    loadIntegrations();
  };

  const chDef = (provider: string) => NOTIFICATION_CHANNELS.find((c) => c.provider === provider);

  return (
    <div>
      {/* Header H2 + description + Add button removed 2026-05-14.
          The page-level breadcrumb ("Integrations › Notifications")
          already names the section; the Add button is registered
          via SectionActionContext above and renders in the
          breadcrumb row.  Saves ~80px of vertical chrome. */}

      {/* ── Connected Channels (card list like AI Models) ──
          Inline "+ Add Channel" button on the card header.  Hidden
          when the form is open so the user has one Add surface. */}
      <div className="card mb-5 overflow-visible relative z-10">
        <div className="flex items-center justify-between mb-4 gap-3">
          <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Connected Channels</h4>
          {!showForm && (
            <button onClick={() => openAddRef.current()} className="btn-primary text-xs px-3 py-1.5 flex items-center gap-1.5 shrink-0">
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 4v16m8-8H4" />
              </svg>
              Add Channel
            </button>
          )}
        </div>
        {loading ? (
          <div className="text-center py-8"><div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin mx-auto" /></div>
        ) : savedIntegrations.length === 0 ? (
          <div className="text-center py-10">
            <p className="text-sm text-slate-500">No channels connected</p>
            <p className="text-xs text-slate-600 mt-1">Add a notification channel to receive security alerts</p>
          </div>
        ) : (
          <div className="space-y-3">
            {savedIntegrations.map((integration: any) => {
              const ch = chDef(integration.provider);
              return (
                <div key={integration.id} className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-4 flex items-center gap-4">
                  <div className={`w-11 h-11 rounded-xl bg-gradient-to-br ${ch?.color || "from-slate-500 to-slate-600"} flex items-center justify-center shrink-0 text-white`}>
                    {ch?.icon || <span className="text-sm font-bold">N</span>}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium text-slate-200">{integration.name}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded ${integration.is_active ? "bg-green-500/15 text-green-400 border border-green-500/20" : "bg-slate-500/15 text-slate-500 border border-slate-500/20"}`}>
                        {integration.is_active ? "Active" : "Disabled"}
                      </span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                        integration.scope_level === "project" ? "bg-purple-500/10 text-purple-400 border border-purple-500/20" :
                        integration.scope_level === "business_unit" ? "bg-amber-500/10 text-amber-400 border border-amber-500/20" :
                        "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                      }`}>{
                        integration.scope_level === "project" ? "Project" :
                        integration.scope_level === "business_unit" ? "Business Unit" : "Org-wide"
                      }</span>
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5">{ch?.description || integration.provider}</p>
                    <p className="text-[10px] text-slate-600 mt-1">Connected {new Date(integration.created_at).toLocaleDateString()}</p>
                  </div>
                  {/* Actions menu */}
                  <div className="relative shrink-0">
                    <button onClick={() => setMenuOpen(menuOpen === integration.id ? null : integration.id)} className="p-1.5 rounded-lg hover:bg-white/[0.06]">
                      <svg className="w-4 h-4 text-slate-500" fill="currentColor" viewBox="0 0 20 20"><path d="M10 6a2 2 0 110-4 2 2 0 010 4zM10 12a2 2 0 110-4 2 2 0 010 4zM10 18a2 2 0 110-4 2 2 0 010 4z" /></svg>
                    </button>
                    {menuOpen === integration.id && (
                      <>
                        <div className="fixed inset-0 z-10" onClick={() => setMenuOpen(null)} />
                        <div className="absolute right-0 top-8 z-30 w-44 py-1 rounded-lg border border-white/[0.08] shadow-xl" style={{ background: "rgba(8,11,28,0.95)",  }}>
                          <button onClick={() => { setMenuOpen(null); handleEditChannel(integration); }}
                            className="block w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-white/[0.04]">
                            <span className="flex items-center gap-2">
                              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" /></svg>
                              Edit Channel
                            </span>
                          </button>
                          <button onClick={() => { setMenuOpen(null); handleTest(); }}
                            className="block w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-white/[0.04]">
                            <span className="flex items-center gap-2">
                              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
                              Test Connection
                            </span>
                          </button>
                          <button onClick={() => {
                            setMenuOpen(null);
                            updateIntegration(integration.id, { is_active: !integration.is_active }).then(() => loadIntegrations());
                          }} className="block w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-white/[0.04]">
                            <span className="flex items-center gap-2">
                              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
                              {integration.is_active ? "Disable" : "Enable"}
                            </span>
                          </button>
                          <div className="border-t border-white/[0.06] my-1" />
                          <button onClick={() => { setMenuOpen(null); setConfirmDelete(integration.id); }}
                            className="block w-full text-left px-4 py-2 text-sm text-red-400 hover:bg-red-500/5">
                            <span className="flex items-center gap-2">
                              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                              Disconnect
                            </span>
                          </button>
                        </div>
                      </>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ── Add/Edit Channel Form (inline, like AI Models) ── */}
      {showForm && (
        <div id="notif-form" className="card border-red-500/20 mb-5">
          <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-5">
            {editingId ? "Edit Notification Channel" : "Add Notification Channel"}
          </h4>

          {/* Step 1: Provider selection (only for new channels) */}
          {!selectedProvider ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {NOTIFICATION_CHANNELS.map((ch) => (
                <button key={ch.provider} onClick={() => handleSelectProvider(ch.provider)}
                  className="text-left p-4 rounded-xl border border-white/[0.06] hover:border-red-500/30 hover:bg-red-500/5 transition-all">
                  <div className="flex items-center gap-3 mb-2">
                    <div className={`w-9 h-9 rounded-lg bg-gradient-to-br ${ch.color} flex items-center justify-center text-white`}>
                      {ch.icon}
                    </div>
                    <span className="text-sm font-medium text-slate-200">{ch.name}</span>
                  </div>
                  <p className="text-xs text-slate-500">{ch.description}</p>
                </button>
              ))}
            </div>
          ) : schema ? (
            <>
              {/* Selected provider header */}
              <div className="flex items-center gap-3 mb-5 pb-4 border-b border-white/[0.06]">
                <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${chDef(selectedProvider)?.color || "from-slate-500 to-slate-600"} flex items-center justify-center text-white`}>
                  {chDef(selectedProvider)?.icon}
                </div>
                <div className="flex-1">
                  <h5 className="text-sm font-semibold text-white">{schema.label}</h5>
                  <p className="text-xs text-slate-500">{schema.description}</p>
                </div>
                {!editingId && (
                  <button onClick={() => { setSelectedProvider(""); setSchema(null); setFormData({}); setTestStatus(null); }}
                    className="text-xs text-slate-500 hover:text-red-400 transition-colors">Change</button>
                )}
              </div>

              {/* Step 2: Provider fields */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-5">
                {schema.fields.map((field: any) => {
                  // When editing an existing integration and this
                  // field is a known sensitive key currently stored
                  // server-side, show a small green "currently set"
                  // hint.  The input itself is empty (backend masks
                  // sensitive values to "") so the user understands
                  // they can either leave it blank to keep, or type
                  // a new value to replace.
                  const fieldHasSecret = editingId && secretsPresent.includes(field.key);
                  return (
                  <div key={field.key} className={schema.fields.length === 1 ? "md:col-span-2" : ""}>
                    <label className="text-xs text-slate-500 mb-1.5 block flex items-center gap-2">
                      <span>{field.label}{field.required && !editingId && <span className="text-red-400 ml-1">*</span>}</span>
                      {fieldHasSecret && (
                        <span className="text-[10px] text-emerald-400/80 inline-flex items-center gap-0.5">
                          <svg className="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                          </svg>
                          currently set
                        </span>
                      )}
                    </label>
                    {field.type === "select" ? (
                      <select value={formData[field.key] || ""} onChange={(e) => setFormData((d) => ({ ...d, [field.key]: e.target.value }))} className="select-dark w-full">
                        <option value="">Select...</option>
                        {(field.options || []).map((opt: string) => (
                          <option key={opt} value={opt}>{opt.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase())}</option>
                        ))}
                      </select>
                    ) : (
                      <input type={field.type === "password" ? "password" : field.type === "url" ? "url" : "text"}
                        value={formData[field.key] || ""} onChange={(e) => setFormData((d) => ({ ...d, [field.key]: e.target.value }))}
                        placeholder={fieldHasSecret ? "Leave blank to keep current value" : (editingId && field.type === "password" ? "Leave blank to keep current" : (field.placeholder || ""))} className="input-dark" />
                    )}
                  </div>
                  );
                })}
              </div>

              {/* Step 3: Notification Scope */}
              <div className="mb-5 pt-4 border-t border-white/[0.06]">
                <div className="flex items-center gap-2 mb-3">
                  <svg className="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                  <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Notification Scope</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="text-xs text-slate-500 mb-1.5 block">Scope Level <span className="text-red-400">*</span></label>
                    <select value={scopeLevel} onChange={(e) => { setScopeLevel(e.target.value); setBusinessUnitId(""); setRepositoryId(""); }} className="select-dark w-full">
                      <option value="organization">Organization (all repos)</option>
                      <option value="business_unit">Business Unit</option>
                      <option value="project">Project (specific repo)</option>
                    </select>
                  </div>
                  {scopeLevel === "business_unit" && (
                    <div>
                      <SearchableSelect label="Business Unit" placeholder="Search business units..." required
                        items={businessUnits.map((bu) => ({ id: bu.id, name: bu.name }))}
                        value={businessUnitId} onChange={(id) => { setBusinessUnitId(id); setRepositoryId(""); }}
                        emptyText="No business units found" />
                    </div>
                  )}
                  {scopeLevel === "project" && (
                    <>
                      {businessUnits.length > 0 && (
                        <div>
                          <SearchableSelect label="Business Unit" placeholder="Filter by BU..."
                            items={businessUnits.map((bu) => ({ id: bu.id, name: bu.name }))}
                            value={businessUnitId} onChange={(id) => { setBusinessUnitId(id); setRepositoryId(""); }}
                            emptyText="No business units" />
                          <p className="text-[10px] text-slate-600 mt-1">Optional filter</p>
                        </div>
                      )}
                      <div>
                        <SearchableSelect label="Repository" placeholder="Search repositories..." required
                          items={filteredRepos.map((r) => ({ id: r.id, name: r.name }))}
                          value={repositoryId} onChange={setRepositoryId}
                          emptyText={businessUnitId ? "No repos in this BU" : "No repositories"} />
                      </div>
                    </>
                  )}
                </div>
              </div>

              {/* Test status */}
              {testStatus && (
                <div className={`flex items-center gap-2 p-3 rounded-lg mb-5 text-sm ${
                  testStatus.status === "success" ? "bg-green-500/5 border border-green-500/15 text-green-400" : "bg-red-500/5 border border-red-500/15 text-red-400"
                }`}>
                  {testStatus.status === "success" ? (
                    <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                  ) : (
                    <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                  )}
                  {testStatus.message}
                </div>
              )}

              {/* Actions */}
              <div className="flex gap-3">
                <button onClick={handleTest} disabled={testing} className="btn-secondary flex items-center gap-2">
                  {testing ? (
                    <><div className="w-3.5 h-3.5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" />Testing...</>
                  ) : (
                    <><svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>Test Connection</>
                  )}
                </button>
                {editingId ? (
                  <button onClick={handleSave} disabled={saving} className="btn-primary flex items-center gap-2">
                    {saving ? "Saving..." : "Update Channel"}
                  </button>
                ) : testStatus?.status === "success" ? (
                  <button onClick={handleSave} disabled={saving} className="btn-primary flex items-center gap-2">
                    {saving ? "Saving..." : "Save & Connect"}
                  </button>
                ) : null}
                <button onClick={() => { setShowForm(false); resetForm(); }} className="btn-secondary">Cancel</button>
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center py-8"><div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" /></div>
          )}
        </div>
      )}

      {/* ── Notification Rules ── */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <svg className="w-4 h-4 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
              Event Rules
            </h4>
            <p className="text-xs text-slate-500 mt-1">Control which events trigger notifications across all connected channels</p>
          </div>
          {rulesDirty && (
            <button onClick={saveRules} disabled={rulesSaving} className="btn-primary text-sm px-4 py-1.5 flex items-center gap-2">
              {rulesSaving ? <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> :
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>}
              Save Changes
            </button>
          )}
        </div>

        {rulesLoading ? (
          <div className="text-center py-8"><div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin mx-auto" /></div>
        ) : notifRules.length === 0 ? (
          <p className="text-sm text-slate-500 text-center py-6">Rules will be created automatically when you first visit this page.</p>
        ) : (
          <div className="border border-white/[0.06] rounded-lg overflow-hidden">
            <div className="grid grid-cols-[1fr_200px] gap-4 px-4 py-2.5 bg-white/[0.02] border-b border-white/[0.06]">
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Event</span>
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Severity Threshold</span>
            </div>
            {notifRules.map((rule, idx) => {
              const eventIcons: Record<string, string> = {
                scan_complete: "\u{1F50D}", critical_finding: "\u{1F6A8}", policy_violation: "\u{1F6AB}",
                remediation_ready: "\u{1F527}", finding_assigned: "\u{1F464}", patch_approved: "\u2705",
                sla_breach: "\u23F0", import_completed: "\u{1F4E5}",
              };
              // Map: "disabled" means not configured; is_enabled=false
              const currentValue = !rule.is_enabled ? "disabled" : rule.severity_threshold;
              return (
                <div key={rule.event_type} className={`grid grid-cols-[1fr_200px] gap-4 px-4 py-3 items-center transition-colors ${idx % 2 === 0 ? "" : "bg-white/[0.01]"} ${!rule.is_enabled ? "opacity-50" : ""}`}>
                  <div className="flex items-center gap-2.5">
                    <span className="text-base">{eventIcons[rule.event_type] || "\u{1F514}"}</span>
                    <span className="text-sm text-slate-200 font-medium">{rule.label}</span>
                  </div>
                  <select value={currentValue}
                    onChange={(e) => {
                      const u = [...notifRules];
                      if (e.target.value === "disabled") {
                        u[idx] = { ...u[idx], is_enabled: false };
                      } else {
                        u[idx] = { ...u[idx], is_enabled: true, severity_threshold: e.target.value };
                      }
                      setNotifRules(u);
                      setRulesDirty(true);
                    }}
                    className="select-dark text-xs">
                    <option value="disabled">Not Configured</option>
                    <option value="all">All Severities</option>
                    <option value="high_and_above">High & Above</option>
                    <option value="critical">Critical Only</option>
                  </select>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Delete confirmation */}
      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="card border-red-500/20 max-w-md w-full mx-4">
            <h4 className="text-base font-semibold text-white mb-2">Disconnect Channel</h4>
            <p className="text-sm text-slate-400 mb-4">Are you sure? This channel will stop receiving security alerts.</p>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setConfirmDelete(null)} className="btn-secondary text-sm">Cancel</button>
              <button onClick={() => handleDisconnect(confirmDelete)} className="btn-danger text-sm">Disconnect</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── AI Engine Settings Sub-Component ──────────────────
// ── AWS-style Rich Dropdown ──────────────────────────
function RichSelect({ label, description, value, options, onChange }: {
  label: string; description: string; value: string;
  options: { value: string; label: string; desc: string; recommended?: boolean }[];
  onChange: (v: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const dropRef = useRef<HTMLDivElement>(null);
  const selected = options.find((o) => o.value === value) || options[0];

  // Scroll dropdown into view when opened
  useEffect(() => {
    if (open && dropRef.current) {
      setTimeout(() => dropRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" }), 50);
    }
  }, [open]);

  return (
    <div className="relative">
      <label className="block text-xs font-medium text-slate-400 mb-1">{label}</label>
      <p className="text-[10px] text-slate-600 mb-2 leading-relaxed">{description}</p>
      <button type="button" onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between gap-3 px-3.5 py-2.5 rounded-lg bg-white/[0.03] border border-white/[0.08] hover:border-white/[0.15] transition-all text-left">
        <div className="min-w-0">
          <span className="text-sm text-slate-200 block">{selected.label}</span>
          <span className="text-[10px] text-slate-600 block mt-0.5 truncate">{selected.desc}</span>
        </div>
        <svg className={`w-4 h-4 text-slate-500 shrink-0 transition-transform ${open ? "rotate-180" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div ref={dropRef} className="absolute left-0 right-0 top-full mt-1 z-20 rounded-lg border border-white/[0.08] shadow-xl overflow-hidden" style={{ background: "rgba(8,11,28,0.95)" }}>
            {options.map((opt) => (
              <button key={opt.value} type="button"
                onClick={() => { onChange(opt.value); setOpen(false); }}
                className={`w-full text-left px-3.5 py-2.5 hover:bg-white/[0.04] transition-colors border-b border-white/[0.04] last:border-0 ${opt.value === value ? "bg-red-500/5" : ""}`}>
                <div className="flex items-center justify-between">
                  <span className={`text-sm font-medium ${opt.value === value ? "text-red-400" : "text-slate-200"}`}>{opt.label}</span>
                  <div className="flex items-center gap-2">
                    {opt.recommended && <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/15 text-red-400">Recommended</span>}
                    {opt.value === value && (
                      <svg className="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                    )}
                  </div>
                </div>
                <p className="text-[10px] text-slate-500 mt-0.5">{opt.desc}</p>
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

// Backend response shape for /ai-engine/settings. Optional fields
// are ones added later than the original feature; default-on
// behaviour is preserved by checking `!== false` rather than a
// strict equality. Centralised here so additions don't trigger
// the TS errors we hit in 2026-04 (undeclared keys on inferred
// type).
type AIEngineSettings = {
  context_mode: string;
  analysis_mode: string;
  skip_ai_for_info: boolean;
  ai_confidence_threshold: number;
  max_tokens_per_finding: number;
  batch_size: number;
  max_concurrent: number;
  rate_limit_rpm: number;
  auto_verify_credentials?: boolean;
  deprioritize_test_files?: boolean | string;  // legacy bool, modern "exclude" | "deprioritize" | falsy
  scan_scope?: string;                         // "standard" | "extended" | …
};

function AIEngineSettingsSection() {
  const [settings, setSettings] = useState<AIEngineSettings>({
    context_mode: "smart", analysis_mode: "batch_similar", skip_ai_for_info: true,
    ai_confidence_threshold: 0.6, max_tokens_per_finding: 4096,
    batch_size: 5, max_concurrent: 10, rate_limit_rpm: 60,
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);

  useEffect(() => { getAIEngineSettings().then((r) => { setSettings(r.data); setLoading(false); }).catch(() => setLoading(false)); }, []);
  const update = (field: string, value: any) => { setSettings((s) => ({ ...s, [field]: value })); setDirty(true); };
  const handleSave = async () => { setSaving(true); try { await updateAIEngineSettings(settings); setDirty(false); } catch {} finally { setSaving(false); } };

  if (loading) return null;

  return (
    <div className="card mb-5">
      <div className="flex items-center justify-between mb-5">
        <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">AI Engine Settings</h4>
        {dirty && (
          <button onClick={handleSave} disabled={saving} className="btn-primary text-xs px-3 py-1.5">
            {saving ? "Saving..." : "Save Changes"}
          </button>
        )}
      </div>

      {/* Row 1: Context + Finding Analysis */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mb-5">
        <RichSelect label="Context Extraction"
          description="Controls how much surrounding code is sent to the AI model when analyzing each finding. More context helps the AI understand whether a secret is in production code, test fixtures, or documentation — but increases token usage and cost per finding."
          value={settings.context_mode} onChange={(v) => update("context_mode", v)}
          options={[
            { value: "smart", label: "Smart", desc: "Extracts the enclosing function body, imports, and decorators. Gives AI enough context to judge intent while using 30-40% fewer tokens than Full mode.", recommended: true },
            { value: "full", label: "Full", desc: "Sends up to 500 lines of the file plus related file context. Maximum accuracy for complex codebases, but uses significantly more tokens per finding." },
            { value: "minimal", label: "Minimal", desc: "Only the code snippet around the finding (10-20 lines). Fastest and cheapest, but the AI may miss surrounding context like sanitization or safe API usage." },
          ]}
        />
        <RichSelect label="Finding Analysis"
          description="Determines how multiple secrets of the same type in the same file are processed by the AI. Batching groups similar findings into a single AI call, reducing API usage without sacrificing accuracy — since the AI sees all related findings together."
          value={settings.analysis_mode} onChange={(v) => update("analysis_mode", v)}
          options={[
            { value: "batch_similar", label: "Batch Similar", desc: "Groups findings with the same CWE and file into one AI prompt. Saves 30-50% API calls while maintaining the same classification accuracy.", recommended: true },
            { value: "individual", label: "Individual", desc: "Every finding gets its own dedicated AI call with full context. Most thorough analysis but uses the most tokens and takes longer to complete." },
          ]}
        />
      </div>

      {/* Row 2: Confidence + Severity Filter */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mb-5">
        <RichSelect label="AI Confidence Level"
          description="Sets the minimum confidence threshold for AI decisions. When the AI&apos;s confidence falls below this level, the finding is automatically marked as &apos;Needs Review&apos; and routed to a human analyst for manual verification. Higher thresholds mean more human review but fewer incorrect classifications."
          value={[0.8, 0.6, 0.4].includes(settings.ai_confidence_threshold) ? String(settings.ai_confidence_threshold) : "custom"}
          onChange={(v) => { if (v !== "custom") update("ai_confidence_threshold", parseFloat(v)); }}
          options={[
            { value: "0.8", label: "Conservative (0.8)", desc: "Only accepts AI decisions when it is very confident (80%+). Maximizes human oversight — expect more findings routed to manual review." },
            { value: "0.6", label: "Balanced (0.6)", desc: "Accepts reasonably confident AI decisions (60%+). Good balance between automation and human review for most teams.", recommended: true },
            { value: "0.4", label: "Aggressive (0.4)", desc: "Accepts most AI decisions (40%+). Minimizes human review workload but increases the risk of incorrect true/false positive classifications." },
          ]}
        />
        <RichSelect label="Severity Filter"
          description="Controls which severity levels are sent to the AI for false positive analysis. Skipping low-severity and informational findings saves tokens and processing time on items that rarely require AI judgment — they can still be reviewed manually."
          value={settings.skip_ai_for_info ? "skip_low" : "all"}
          onChange={(v) => update("skip_ai_for_info", v === "skip_low")}
          options={[
            { value: "skip_low", label: "Skip Low & Info", desc: "Only analyze Critical, High, and Medium severity findings. Low and Info severity findings remain as &apos;Needs Review&apos; for manual triage.", recommended: true },
            { value: "all", label: "Analyze All", desc: "AI reviews every finding regardless of severity. Uses more tokens but provides complete automated classification across all severity levels." },
          ]}
        />
      </div>

      {/* Row 3: Max Tokens + Credential Verification */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mb-5">
        <RichSelect label="Max Tokens per Finding"
          description="Sets the maximum number of AI tokens allocated for analyzing each individual finding. Higher values allow the AI to produce more detailed reasoning and evidence, but increase cost and processing time per finding. Most findings are adequately analyzed within 4096 tokens."
          value={[2048, 4096, 8192].includes(settings.max_tokens_per_finding) ? String(settings.max_tokens_per_finding) : "custom"}
          onChange={(v) => { if (v !== "custom") update("max_tokens_per_finding", parseInt(v)); }}
          options={[
            { value: "2048", label: "Light (2048)", desc: "Concise analysis — sufficient for straightforward findings like known placeholder patterns. Fastest processing with lowest token cost." },
            { value: "4096", label: "Standard (4096)", desc: "Balanced depth — enough for detailed reasoning, evidence references, and remediation suggestions. Suitable for most codebases.", recommended: true },
            { value: "8192", label: "Deep (8192)", desc: "Thorough analysis with extensive evidence gathering and multi-factor reasoning. Best for complex codebases with nuanced security patterns." },
          ]}
        />
        <RichSelect label="Credential Verification"
          description="When enabled, Vooda automatically tests detected secrets against their provider APIs during the scan (e.g., calling GitHub&apos;s /user endpoint with a found token). This determines whether credentials are still active or have been revoked — critical for prioritizing remediation of live exposures."
          value={settings.auto_verify_credentials !== false ? "enabled" : "disabled"}
          onChange={(v) => update("auto_verify_credentials", v === "enabled")}
          options={[
            { value: "enabled", label: "Enabled", desc: "Verify each detected credential inline during scan. Findings show &apos;Active&apos; or &apos;Inactive&apos; status with blast radius analysis for active secrets.", recommended: true },
            { value: "disabled", label: "Disabled", desc: "Skip credential verification. Scans complete faster but you won&apos;t know which secrets are still live until manually verified." },
          ]}
        />
      </div>

      {/* Row 4: Test File Handling + Scan Scope */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <RichSelect label="Test File Handling"
          description="Controls how secrets found in test and spec files (e.g., *Test.java, *.spec.ts, *_test.go) are treated. Test files often contain intentional hardcoded credentials for automated testing — these are real secrets in the codebase but lower priority than production configuration leaks."
          value={settings.deprioritize_test_files === "exclude" ? "exclude" : settings.deprioritize_test_files ? "deprioritize" : "normal"}
          onChange={(v) => update("deprioritize_test_files", v)}
          options={[
            { value: "normal", label: "Normal Priority", desc: "Treat test file secrets with the same severity as production code. All findings appear in dashboards and alerts regardless of file location.", recommended: true },
            { value: "deprioritize", label: "Deprioritize", desc: "Automatically lower severity to &apos;Low&apos; for findings in test files. They remain visible in the findings list but won&apos;t trigger high-priority alerts." },
            { value: "exclude", label: "Exclude from AI", desc: "Skip AI false positive analysis for test file findings entirely. Saves AI tokens — findings are still detected and stored but not AI-classified." },
          ]}
        />
        <RichSelect label="Scan Scope"
          description="Defines which file types the secret scanner includes during repository analysis. Standard covers all common code and configuration files. Extended adds documentation and extensionless files which occasionally contain leaked credentials in examples or READMEs."
          value={settings.scan_scope || "standard"}
          onChange={(v) => update("scan_scope", v)}
          options={[
            { value: "standard", label: "Standard", desc: "Scans source code, configuration files, CI/CD pipelines, shell scripts, Dockerfiles, and key/certificate files. Covers the vast majority of real-world secret leaks.", recommended: true },
            { value: "extended", label: "Extended", desc: "Includes everything in Standard plus documentation (markdown, text), log files, extensionless files, and backup files. Catches secrets in READMEs and docs." },
            { value: "minimal", label: "Minimal", desc: "Only scans source code (.py, .js, .java, etc.) and configuration files (.env, .yml, .json). Fastest scan speed but may miss secrets in scripts, docs, or CI files." },
          ]}
        />
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  MAIN PAGE
// ═══════════════════════════════════════════════════════════════

// Inner component reads useSearchParams; default export wraps it in
// <Suspense> so Next.js 15 can suspend on the bailout boundary.
function IntegrationsPageInner() {
  const searchParams = useSearchParams();
  const categoryFromUrl = searchParams?.get("category") as HubCategory | null;

  const [activeCategory, setActiveCategory] = useState<HubCategory | null>(categoryFromUrl);
  const [connectingScanner, setConnectingScanner] = useState<ScannerDef | null>(null);
  const [savedIntegrations, setSavedIntegrations] = useState<SavedIntegration[]>([]);
  // Action node rendered inline with the breadcrumb on category-detail
  // views.  Each section uses the SectionActionContext to set / clear
  // this; we clear it ourselves whenever the active category changes,
  // so a stale action button can't leak across navigation.  See the
  // SectionActionContext block at the top of the file for the contract.
  //
  // The clear is gated on prevCategoryRef so it only fires on a REAL
  // navigation between categories — NOT on initial mount.  Without the
  // ref, React's effect ordering (children run before parents) meant
  // the section's child useEffect would set the "+ Add Channel" button
  // and then THIS parent effect would immediately clear it on first
  // render.  Net result: the Add button was never visible, so users
  // saw a Slack-configured Notifications page with no way to add
  // Teams.  Found in user E2E 2026-05-18.
  const [sectionAction, setSectionAction] = useState<ReactNode | null>(null);
  const prevCategoryRef = useRef(activeCategory);
  useEffect(() => {
    if (prevCategoryRef.current !== activeCategory) {
      setSectionAction(null);
      prevCategoryRef.current = activeCategory;
    }
  }, [activeCategory]);

  const loadIntegrations = () => {
    getIntegrations().then((r) => setSavedIntegrations(r.data || [])).catch(() => {});
  };
  useEffect(() => { loadIntegrations(); }, []);

  // Sync activeCategory with URL — reacts to sidebar clicks and browser back/forward
  useEffect(() => {
    setActiveCategory(categoryFromUrl);
  }, [categoryFromUrl]);

  const openCategory = (key: HubCategory) => {
    setActiveCategory(key);
    window.history.pushState(null, "", `/integrations?category=${key}`);
  };
  const goBack = () => {
    setActiveCategory(null);
    window.history.pushState(null, "", "/integrations");
  };

  // Listen for popstate (browser back/forward)
  useEffect(() => {
    const handler = () => {
      const params = new URLSearchParams(window.location.search);
      const cat = params.get("category") as HubCategory | null;
      setActiveCategory(cat);
    };
    window.addEventListener("popstate", handler);
    return () => window.removeEventListener("popstate", handler);
  }, []);

  const connectedProviders = new Set(savedIntegrations.map((i) => i.provider));

  const handleDisconnect = async (id: string) => {
    await deleteIntegration(id).catch(() => {});
    loadIntegrations();
  };

  const CATEGORIES: CategoryDef[] = [
    { key: "ai_models", label: "AI Provider", description: "LLM provider for false positive triage", color: "from-purple-500 to-indigo-500", count: AI_PROVIDERS.length,
      icon: <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg> },
    { key: "notifications", label: "Notifications", description: "Alerts via Slack, Teams, Email", color: "from-yellow-500 to-orange-500", count: NOTIFICATION_CHANNELS.length,
      icon: <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" /></svg> },
    { key: "webhooks", label: "Webhooks (Inbound)", description: "Receive push & PR events to trigger scans", color: "from-red-500 to-blue-500", count: 3,
      icon: <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg> },
    { key: "ticketing", label: "Ticketing", description: "Jira, ServiceNow, Custom Webhook", color: "from-blue-500 to-indigo-500", count: TICKETING_TOOLS.length,
      icon: <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" /></svg> },
    // "Identity & SSO" category removed from the hub because SSO is
    // disabled (settings.SSO_ENABLED = False): the SAML handler does not
    // verify assertion signatures, so the login flow is a fail-closed
    // 503 and there is nothing to configure. Restore this tile only when
    // SSO is rebuilt on a vetted SAML library. SSO_PROVIDERS and
    // SSOSection are left defined for that rebuild.
    // "siem" tile removed 2026-05-19 — relocated to Settings →
    // Audit & Compliance → Audit Log Streaming.
    // "cloud_connectors" tile removed 2026-05-16 — see HubCategory comment.
  ];

  // Count connected per category
  // Scanner imports removed — Vooda AI is the scanner

  // ── Render category detail or overview ─────────────────
  const renderCategoryContent = () => {
    switch (activeCategory) {
      case "ai_models":
        return <AIModelsFullSection />;
      case "notifications":
        return <NotificationsFullSection />;
      case "webhooks":
        return <WebhooksSection />;
      case "ticketing":
        return <TicketingSection />;
      case "identity":
        return <SSOSection />;
      case "scanners":
        return (
          <ScannersFullSection />
        );
      default:
        return null;
    }
  };

  // When a category is active, pass the breadcrumb + section action
  // up to the AppShell header so it renders the trail in the same
  // band as the bell/avatar — same single-row pattern the Sources
  // catalog uses, eliminates the body-level back-bar entirely.
  // `categoryInfo` doubles as the "is in detail view" signal.
  const categoryInfo = activeCategory ? CATEGORIES.find((c) => c.key === activeCategory) : null;
  const shellBreadcrumb = categoryInfo
    ? [
        { label: "Integrations", href: "/integrations" },
        { label: categoryInfo.label },
      ]
    : undefined;

  return (
    <AppShell pageBreadcrumb={shellBreadcrumb} pageActions={sectionAction}>
      <div className="max-w-[1400px]">

        {/* ═══ TILE GRID — shown when no category is selected ═══ */}
        {!activeCategory && (
          <>
            <div className="mb-6">
              <h2 className="text-2xl font-bold text-white">Integrations</h2>
              <p className="text-sm text-slate-400 mt-1">Connect your security tools, AI providers, and developer workflows</p>
            </div>

            {/* 4 category tiles (AI Provider, Notifications, Webhooks,
                Ticketing) — the column count is kept in step with the
                tile count so no breakpoint leaves an orphan card:
                1 col (4×1) on mobile, 2 cols (2×2) on tablet, 4 cols
                (1×4) on desktop. A 3-column cap left a lone card on a
                second row (3+1) once Vault was removed. */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {CATEGORIES.map((cat) => {
              const connected = 0;
              return (
                <div
                  key={cat.key}
                  onClick={() => openCategory(cat.key)}
                  className="card card-hover cursor-pointer group relative overflow-hidden"
                >
                  {/* Gradient accent line at top */}
                  <div className={`absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r ${cat.color} opacity-60 group-hover:opacity-100 transition-opacity`} />

                  <div className="flex items-start gap-4 pt-2">
                    <div className={`w-11 h-11 rounded-xl bg-gradient-to-br ${cat.color} flex items-center justify-center shrink-0 text-white opacity-90 group-hover:opacity-100 transition-opacity`}>
                      {cat.icon}
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="text-sm font-bold text-slate-200 group-hover:text-white transition-colors">{cat.label}</h3>
                      <p className="text-xs text-slate-500 mt-0.5 line-clamp-2">{cat.description}</p>
                      <div className="flex items-center gap-3 mt-3">
                        <span className="text-[10px] text-slate-600">{cat.count} available</span>
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

        {/* ═══ SECTION DETAIL — shown when a category is selected ═══
             The previous body-level back-bar (Integrations › Category +
             Add button on right) was removed 2026-05-14.  The same
             information now lives in the AppShell global header band
             via `pageBreadcrumb` + `pageActions` props — see the
             AppShell wrapper above where shellBreadcrumb / sectionAction
             are passed in.  Matches the single-row header pattern the
             Sources catalog uses (Sources › Collaboration in the global
             header, no body-level back bar). */}
        {activeCategory && (
          <SectionActionContext.Provider value={{ setAction: setSectionAction }}>
            <div>
              {renderCategoryContent()}
            </div>
          </SectionActionContext.Provider>
        )}
      </div>

      {/* Scanner connection modal */}
      {connectingScanner && (
        <ScannerConnectModal
          provider={connectingScanner.provider}
          color={connectingScanner.color}
          onClose={() => setConnectingScanner(null)}
          onConnected={() => { setConnectingScanner(null); loadIntegrations(); }}
        />
      )}

    </AppShell>
  );
}

export default function IntegrationsPage() {
  return (
    <Suspense fallback={<AppShell><div className="flex justify-center py-20"><div className="w-6 h-6 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" /></div></AppShell>}>
      <IntegrationsPageInner />
    </Suspense>
  );
}
