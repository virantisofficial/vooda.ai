// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * Scanner branding utilities.
 *
 * Maps internal engine names to customer-facing display names.
 * Vooda AI's own engines show as "Vooda AI Engine".
 * External scanners (customer's tools) keep their original names.
 */

const VOODA_ENGINE_NAMES = new Set([
  "vooda_engine",
  "vooda_standalone",
  "vooda_regex",
]);

const EXTERNAL_SCANNER_DISPLAY: Record<string, string> = {
  checkmarx: "Checkmarx",
  fortify: "Fortify",
  veracode: "Veracode",
  sonarqube: "SonarQube",
  codeql: "CodeQL",
  snyk: "Snyk",
  bandit: "Bandit",
  brakeman: "Brakeman",
  gosec: "GoSec",
};

/**
 * Convert internal scanner name to customer-facing display name.
 */
export function brandScannerName(internalName: string): string {
  const lower = internalName.toLowerCase().trim();

  if (VOODA_ENGINE_NAMES.has(lower)) {
    return "Vooda AI Engine";
  }

  if (lower in EXTERNAL_SCANNER_DISPLAY) {
    return EXTERNAL_SCANNER_DISPLAY[lower];
  }

  // Unknown external scanner — title case
  return internalName
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

/**
 * Check if a scanner name refers to Vooda AI's internal engine.
 */
export function isVoodaEngine(scannerName: string): boolean {
  return VOODA_ENGINE_NAMES.has(scannerName.toLowerCase().trim());
}

/**
 * Get a color class for a scanner badge.
 */
export function getScannerColor(scannerName: string): string {
  if (isVoodaEngine(scannerName)) {
    return "bg-cyan-500/15 text-cyan-400 border-cyan-500/20";
  }
  // External scanners get a neutral style
  return "bg-slate-500/15 text-slate-400 border-slate-500/20";
}
