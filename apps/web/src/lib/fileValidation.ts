// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * File validation rules for all upload points in Vooda AI.
 */

export interface ValidationResult {
  valid: boolean;
  error?: string;
  warning?: string;
}

const MAX_FILE_SIZES: Record<string, number> = {
  code_archive: 500 * 1024 * 1024,   // 500 MB for code archives
  scan_results: 100 * 1024 * 1024,   // 100 MB for scan result files
  default: 50 * 1024 * 1024,         // 50 MB default
};

const ALLOWED_EXTENSIONS: Record<string, { exts: string[]; label: string }> = {
  code_archive: {
    exts: [".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2"],
    label: "ZIP or TAR archives (.zip, .tar.gz, .tgz)",
  },
  scan_results: {
    exts: [".json", ".xml", ".sarif"],
    label: "SARIF, JSON, or XML files (.sarif, .json, .xml)",
  },
};

function getExtension(filename: string): string {
  const lower = filename.toLowerCase();
  // Handle double extensions like .tar.gz
  if (lower.endsWith(".tar.gz")) return ".tar.gz";
  if (lower.endsWith(".tar.bz2")) return ".tar.bz2";
  const lastDot = lower.lastIndexOf(".");
  return lastDot >= 0 ? lower.slice(lastDot) : "";
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Validate a file for a specific upload context.
 */
export function validateFile(file: File, context: "code_archive" | "scan_results"): ValidationResult {
  // Extension check
  const ext = getExtension(file.name);
  const allowed = ALLOWED_EXTENSIONS[context];
  if (allowed && !allowed.exts.includes(ext)) {
    return {
      valid: false,
      error: `Unsupported file type "${ext || "unknown"}". Expected ${allowed.label}`,
    };
  }

  // Size check
  const maxSize = MAX_FILE_SIZES[context] || MAX_FILE_SIZES.default;
  if (file.size > maxSize) {
    return {
      valid: false,
      error: `File too large (${formatSize(file.size)}). Maximum allowed: ${formatSize(maxSize)}`,
    };
  }

  // Empty file check
  if (file.size === 0) {
    return {
      valid: false,
      error: "File is empty",
    };
  }

  // Warning for very small scan result files (likely not real scan data)
  if (context === "scan_results" && file.size < 50) {
    return {
      valid: true,
      warning: "File is very small — it may not contain valid scan results",
    };
  }

  // Warning for large files
  if (file.size > maxSize * 0.8) {
    return {
      valid: true,
      warning: `Large file (${formatSize(file.size)}). Upload may take a moment.`,
    };
  }

  return { valid: true };
}

/**
 * Validate scan results file content (quick header check).
 * Reads first 500 bytes to verify basic structure.
 */
export async function validateFileContent(file: File, context: "scan_results"): Promise<ValidationResult> {
  if (context !== "scan_results") return { valid: true };

  try {
    const slice = file.slice(0, 500);
    const text = await slice.text();
    const trimmed = text.trim();

    if (!trimmed) {
      return { valid: false, error: "File appears to be empty" };
    }

    // JSON/SARIF files should start with { or [
    if (file.name.endsWith(".json") || file.name.endsWith(".sarif")) {
      if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
        return { valid: false, error: "Invalid JSON/SARIF file — must start with { or [" };
      }
    }

    // XML files should start with < or <?xml
    if (file.name.endsWith(".xml")) {
      if (!trimmed.startsWith("<")) {
        return { valid: false, error: "Invalid XML file — must start with < or <?xml" };
      }
    }

    return { valid: true };
  } catch {
    return { valid: true }; // If we can't read it, let the backend handle it
  }
}
