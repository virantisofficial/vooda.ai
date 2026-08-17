// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * Product-specific scanner icons.
 * Each icon is a simplified, recognizable representation of the scanner's brand mark.
 * Rendered as SVG within a gradient container — white/light strokes on colored background.
 */

export function CheckmarxIcon({ className = "w-5 h-5" }: { className?: string }) {
  // Checkmarx "CX" lettermark style — angular checkmark
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none">
      <path d="M4 12.5L9 17.5L20 6.5" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M12 17.5L20 9.5" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" opacity="0.5" />
    </svg>
  );
}

export function FortifyIcon({ className = "w-5 h-5" }: { className?: string }) {
  // Fortify — castle/fortress turret
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none">
      <path d="M4 20V12L6 10V7H8V10L10 12V8H14V12L16 10V7H18V10L20 12V20" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      <rect x="10" y="15" width="4" height="5" rx="0.5" stroke="currentColor" strokeWidth="1.5" />
      <path d="M4 20H20" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

export function VeracodeIcon({ className = "w-5 h-5" }: { className?: string }) {
  // Veracode — stylized "V" shield
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none">
      <path d="M12 3L4 7V13C4 17.4 7.4 21.5 12 22C16.6 21.5 20 17.4 20 13V7L12 3Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
      <path d="M8 11L11 16L16 8" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function CodeQLIcon({ className = "w-5 h-5" }: { className?: string }) {
  // CodeQL / GitHub — octocat-inspired code bracket with query
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.5" />
      <path d="M9 9L6 12L9 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M15 9L18 12L15 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M13 7L11 17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

export function SonarQubeIcon({ className = "w-5 h-5" }: { className?: string }) {
  // SonarQube — sonar wave rings
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none">
      <path d="M5 19C5 12.4 10.4 7 17 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" opacity="0.4" />
      <path d="M7 19C7 13.5 11.5 9 17 9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" opacity="0.6" />
      <path d="M9 19C9 14.6 12.6 11 17 11" stroke="currentColor" strokeWidth="2" strokeLinecap="round" opacity="0.8" />
      <path d="M11 19C11 15.7 13.7 13 17 13" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
    </svg>
  );
}

export function SnykIcon({ className = "w-5 h-5" }: { className?: string }) {
  // Snyk — dog/watchdog silhouette simplified as an eye/watch
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none">
      <path d="M12 5C6.5 5 3 12 3 12C3 12 6.5 19 12 19C17.5 19 21 12 21 12C21 12 17.5 5 12 5Z" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" />
      <circle cx="12" cy="12" r="3.5" stroke="currentColor" strokeWidth="1.8" />
      <circle cx="12" cy="12" r="1.5" fill="currentColor" />
    </svg>
  );
}

export function CustomScannerIcon({ className = "w-5 h-5" }: { className?: string }) {
  // Custom — generic plug/connector
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none">
      <path d="M14 4V8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      <path d="M10 4V8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      <rect x="7" y="8" width="10" height="5" rx="1" stroke="currentColor" strokeWidth="1.8" />
      <path d="M9 13V15C9 17.2 10.8 19 13 19H14" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
      <circle cx="17" cy="19" r="2" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

// ── Registry ──────────────────────────────────────────
const ICON_MAP: Record<string, React.ComponentType<{ className?: string }>> = {
  checkmarx: CheckmarxIcon,
  fortify: FortifyIcon,
  veracode: VeracodeIcon,
  codeql: CodeQLIcon,
  sonarqube: SonarQubeIcon,
  snyk: SnykIcon,
  custom: CustomScannerIcon,
};

export function ScannerIcon({ provider, className = "w-5 h-5" }: { provider: string; className?: string }) {
  const Icon = ICON_MAP[provider.toLowerCase()] || CustomScannerIcon;
  return <Icon className={className} />;
}

export default ScannerIcon;
