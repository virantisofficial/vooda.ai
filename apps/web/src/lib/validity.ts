// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
//
// Client-side twin of apps/api/app/core/validity.py.
//
// The client used to read `source_metadata.validation_status` — a JSONB
// key that is frequently absent and carries legacy spellings — and
// defaulted to the string "not_validated", which is no longer a value
// the backend can produce. Validity is now a CHECK-constrained column
// exposed at the top level of the finding and incident payloads.

export type Validity =
  | "active" | "inactive" | "unknown" | "unsupported" | "check_failed";

const LEGACY: Record<string, Validity> = {
  active: "active", valid: "active",
  inactive: "inactive", invalid: "inactive",
  revoked: "inactive", expired: "inactive",
  unknown: "unknown", not_validated: "unknown",
  unverified: "unknown", pending: "unknown",
  unsupported: "unsupported", no_checker: "unsupported",
  error: "check_failed", validation_error: "check_failed",
  failed_to_check: "check_failed", rate_limited: "check_failed",
};

/** Any legacy spelling (or null/undefined) -> canonical value. */
export function validity(v?: string | null): Validity {
  if (!v) return "unknown";
  return LEGACY[String(v).trim().toLowerCase()] ?? "unknown";
}

/**
 * Read a finding's or incident's validity. Prefers the column and
 * falls back to the legacy JSONB copy so a stale cached payload still
 * renders something sane.
 */
export function validityOf(obj: any): Validity {
  return validity(obj?.validation_status ?? obj?.source_metadata?.validation_status);
}

/** The provider rejected it. The only state that means "safe". */
export function isDead(v?: string | null): boolean {
  return validity(v) === "inactive";
}

/** The provider accepted it — this credential works right now. */
export function isLive(v?: string | null): boolean {
  return validity(v) === "active";
}

/**
 * We do not know. Never render these as safe: a failed check is an
 * absence of evidence, not evidence the credential is dead.
 */
export function isInconclusive(v?: string | null): boolean {
  const c = validity(v);
  return c === "unknown" || c === "unsupported" || c === "check_failed";
}

export function validityLabel(v?: string | null): string {
  switch (validity(v)) {
    case "active": return "Live";
    case "inactive": return "Revoked / dead";
    case "unsupported": return "No checker";
    case "check_failed": return "Check failed";
    default: return "Not checked";
  }
}
