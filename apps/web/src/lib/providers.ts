// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

export interface RepoProvider {
  id: string;
  name: string;
  icon: string; // SVG path data
  color: string;
  authFields: AuthField[];
  urlPattern: RegExp;
}

export interface AuthField {
  key: string;
  label: string;
  type: "text" | "password";
  placeholder: string;
  required: boolean;
  hint?: string;
}

const TOKEN_FIELD: AuthField = {
  key: "token",
  label: "Personal Access Token",
  type: "password",
  placeholder: "ghp_xxxx... or glpat-xxxx...",
  required: false,
  hint: "Required for private repositories",
};

export const REPO_PROVIDERS: RepoProvider[] = [
  {
    id: "github",
    name: "GitHub",
    icon: "M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z",
    color: "#ffffff",
    urlPattern: /github\.com/i,
    authFields: [
      TOKEN_FIELD,
    ],
  },
  {
    id: "gitlab",
    name: "GitLab",
    icon: "M23.955 13.587l-1.342-4.135-2.664-8.189a.455.455 0 00-.867 0L16.418 9.45H7.582L4.918 1.263a.455.455 0 00-.867 0L1.387 9.452.045 13.587a.924.924 0 00.331 1.023L12 23.054l11.624-8.443a.92.92 0 00.331-1.024",
    color: "#FC6D26",
    urlPattern: /gitlab\.(com|io|org)|gitlab[.-]/i,
    authFields: [
      {
        key: "token",
        label: "Personal Access Token",
        type: "password",
        placeholder: "glpat-xxxxxxxxxxxx",
        required: false,
        hint: "Required for private repositories. Create at Settings > Access Tokens",
      },
    ],
  },
  {
    id: "bitbucket",
    name: "Bitbucket",
    icon: "M.778 1.213a.768.768 0 00-.768.892l3.263 19.81c.084.5.515.868 1.022.873H19.95a.772.772 0 00.77-.646l3.27-20.03a.768.768 0 00-.768-.891zM14.52 15.53H9.522L8.17 8.466h7.561z",
    color: "#2684FF",
    urlPattern: /bitbucket\.(org|com)/i,
    authFields: [
      {
        key: "username",
        label: "Username",
        type: "text",
        placeholder: "Bitbucket username",
        required: false,
      },
      {
        key: "app_password",
        label: "App Password",
        type: "password",
        placeholder: "App password",
        required: false,
        hint: "Create at Personal Settings > App Passwords",
      },
    ],
  },
  {
    id: "azure",
    name: "Azure DevOps",
    icon: "M0 8.899l2.247-2.966 8.405-3.416V.045l7.37 5.393L2.966 8.36v8.224L0 15.73zm24-4.08v14.396l-6.072 4.74-9.467-3.442v3.028L3.87 17.46l12.18-.96V2.222z",
    color: "#0078D4",
    urlPattern: /dev\.azure\.com|visualstudio\.com|azure\.com.*repos/i,
    authFields: [
      {
        key: "token",
        label: "Personal Access Token",
        type: "password",
        placeholder: "Azure DevOps PAT",
        required: false,
        hint: "Create at User Settings > Personal Access Tokens",
      },
      {
        key: "organization",
        label: "Organization",
        type: "text",
        placeholder: "my-org",
        required: false,
      },
    ],
  },
  {
    id: "codecommit",
    name: "AWS CodeCommit",
    icon: "M12 0L1.608 6v12L12 24l10.392-6V6zm-1.2 17.4h2.4v-2.4h-2.4zm0-4.8h2.4V6.6h-2.4z",
    color: "#FF9900",
    urlPattern: /codecommit|git-codecommit.*amazonaws/i,
    authFields: [
      {
        key: "username",
        label: "HTTPS Git Credentials Username",
        type: "text",
        placeholder: "AWS CodeCommit username",
        required: false,
      },
      {
        key: "password",
        label: "HTTPS Git Credentials Password",
        type: "password",
        placeholder: "AWS CodeCommit password",
        required: false,
      },
    ],
  },
];

const GENERIC_PROVIDER: RepoProvider = {
  id: "generic",
  name: "Git Repository",
  icon: "M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z",
  color: "#94a3b8",
  urlPattern: /./,
  authFields: [
    {
      key: "username",
      label: "Username",
      type: "text",
      placeholder: "Git username (optional)",
      required: false,
    },
    {
      key: "password",
      label: "Password / Token",
      type: "password",
      placeholder: "Password or access token",
      required: false,
      hint: "Required for private repositories",
    },
  ],
};

export function detectProvider(url: string): RepoProvider {
  if (!url || url.trim().length < 5) return GENERIC_PROVIDER;

  for (const provider of REPO_PROVIDERS) {
    if (provider.urlPattern.test(url)) {
      return provider;
    }
  }
  return GENERIC_PROVIDER;
}

export function extractRepoName(url: string): string {
  try {
    // Handle SSH URLs: git@github.com:user/repo.git
    const sshMatch = url.match(/:([^/]+\/[^/]+?)(?:\.git)?$/);
    if (sshMatch) return sshMatch[1].split("/").pop() || "";

    // Handle HTTPS URLs
    const cleaned = url.replace(/\.git$/, "").replace(/\/$/, "");
    const parts = cleaned.split("/");
    return parts[parts.length - 1] || "";
  } catch {
    return "";
  }
}
