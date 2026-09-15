// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

// Provider console pages for revoking / reissuing a credential, keyed by
// provider then secret type (`_default` = any type for that provider).
// Vooda doesn't rotate credentials — this only points to where you do it.

export type ProviderConsole = { url: string; label: string };

const PROVIDER_CONSOLES: Record<string, Record<string, ProviderConsole>> = {
  aws: { _default: { url: "https://console.aws.amazon.com/iam/home#/security_credentials", label: "AWS IAM Console" } },
  gcp: {
    gcp_service_account_key: { url: "https://console.cloud.google.com/iam-admin/serviceaccounts", label: "GCP Service Accounts" },
    gcp_api_key: { url: "https://console.cloud.google.com/apis/credentials", label: "GCP API Credentials" },
    _default: { url: "https://console.cloud.google.com/iam-admin", label: "GCP IAM Console" },
  },
  azure: {
    azure_client_secret: { url: "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade", label: "Azure App Registrations" },
    azure_storage_key: { url: "https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.Storage%2FStorageAccounts", label: "Azure Storage Accounts" },
    _default: { url: "https://portal.azure.com/", label: "Azure Portal" },
  },
  github: {
    github_oauth: { url: "https://github.com/settings/developers", label: "GitHub Developer Settings" },
    _default: { url: "https://github.com/settings/tokens", label: "GitHub Token Settings" },
  },
  gitlab: { _default: { url: "https://gitlab.com/-/user_settings/personal_access_tokens", label: "GitLab Access Tokens" } },
  stripe: { _default: { url: "https://dashboard.stripe.com/apikeys", label: "Stripe API Keys" } },
  slack: { _default: { url: "https://api.slack.com/apps", label: "Slack App Management" } },
  twilio: { _default: { url: "https://console.twilio.com/", label: "Twilio Console" } },
  sendgrid: { _default: { url: "https://app.sendgrid.com/settings/api_keys", label: "SendGrid API Keys" } },
  npm: { _default: { url: "https://www.npmjs.com/settings/tokens", label: "npm Token Settings" } },
  pypi: { _default: { url: "https://pypi.org/manage/account/", label: "PyPI Account Settings" } },
  atlassian: { _default: { url: "https://id.atlassian.com/manage-profile/security/api-tokens", label: "Atlassian API Tokens" } },
  datadog: { _default: { url: "https://app.datadoghq.com/organization-settings/api-keys", label: "Datadog API Keys" } },
};

/** The console page for this provider/secret type, or undefined if unknown. */
export function providerConsole(provider?: string, secretType?: string): ProviderConsole | undefined {
  const byType = PROVIDER_CONSOLES[(provider || "").toLowerCase()];
  if (!byType) return undefined;
  return byType[(secretType || "").toLowerCase()] || byType._default;
}
