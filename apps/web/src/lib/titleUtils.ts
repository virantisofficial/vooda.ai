// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * Get a one-liner defect name (max ~30 chars) from a finding.
 * Used as the primary heading in panels and cards.
 */
export function findingName(rawTitle: string, category?: string): string {
  const genericCategories = new Set(["VULNERABILITY", "BUG", "CODE_SMELL", "SECURITY_HOTSPOT", "vulnerability", "bug", "code_smell", "Hardcoded Secret", "hardcoded_secret", "Hardcoded Credentials"]);
  // 1. Try to extract a clean name from the category (CWE description)
  if (category) {
    // "CWE-79: Improper Neutralization of Input..." → "Cross-site Scripting"
    const cweMatch = category.match(/\('([^']+)'\)\s*$/);
    if (cweMatch) return cweMatch[1];

    // "CWE-79: Improper Neutralization..." → extract after colon, shorten
    const colonMatch = category.match(/^CWE-\d+:\s*(.+)/);
    if (colonMatch) {
      const desc = colonMatch[1].trim();
      if (desc.length <= 35) return desc;
      // Common CWE shortenings
      const shorts: Record<string, string> = {
        "Improper Neutralization of Input During Web Page Generation": "Cross-site Scripting (XSS)",
        "Improper Neutralization of Special Elements used in an SQL Command": "SQL Injection",
        "Improper Neutralization of Special Elements used in an OS Command": "Command Injection",
        "Improper Neutralization of Directives in Dynamically Evaluated Code": "Code Injection (eval)",
        "Improper Neutralization of Directives in Statically Saved Code": "Template Injection",
        "Improperly Controlled Modification of Dynamically-Determined Object Attributes": "Prototype Pollution",
        "Deserialization of Untrusted Data": "Insecure Deserialization",
        "Use of a Broken or Risky Cryptographic Algorithm": "Weak Cryptography",
        "Incorrect Type Conversion or Cast": "Type Confusion",
        "Improper Limitation of a Pathname to a Restricted Directory": "Path Traversal",
        "Server-Side Request Forgery": "SSRF",
      };
      for (const [long, short] of Object.entries(shorts)) {
        if (desc.startsWith(long.substring(0, 20))) return short;
      }
      return desc;
    }

    // Non-CWE category — use directly if short and meaningful
    if (category.length <= 35 && !genericCategories.has(category)) return category;
  }

  // 2. Extract from title using keyword patterns
  const namePatterns: [RegExp, string][] = [
    [/template\s+variable.*(?:href|src|action)/i, "XSS via Template Variable"],
    [/innerHTML|outerHTML|document\.write/i, "Unsafe innerHTML Usage"],
    [/prototype\s+pollut/i, "Prototype Pollution"],
    [/\beval\(\)/i, "Unsafe eval() Usage"],
    [/insecure\s+deserializ/i, "Insecure Deserialization"],
    [/template.*string\s+format/i, "Template String Injection"],
    [/SQL\s+string\s+concat/i, "SQL String Concatenation"],
    [/formatted\s+SQL/i, "SQL Injection (Formatted)"],
    [/manually\s+construct.*SQL/i, "SQL Injection (Manual)"],
    [/MD5.*(?:password|hash)/i, "Weak Hash: MD5"],
    [/SHA-?1/i, "Weak Hash: SHA1"],
    [/command\s+inject/i, "Command Injection"],
    [/SSRF|server.side\s+request/i, "SSRF"],
    [/path\s+traversal/i, "Path Traversal"],
    [/hardcoded.*(?:secret|key|password|token)/i, "Hardcoded Secret"],
    [/open\s+redirect/i, "Open Redirect"],
    [/XXE|XML\s+external/i, "XXE Injection"],
    [/LDAP\s+inject/i, "LDAP Injection"],
    [/XPath\s+inject/i, "XPath Injection"],
    [/CSRF|cross.site\s+request/i, "CSRF"],
    [/race\s+condition/i, "Race Condition"],
    [/buffer\s+overflow/i, "Buffer Overflow"],
    [/insecure\s+random/i, "Insecure Randomness"],
    [/missing\s+auth/i, "Missing Authentication"],
  ];

  for (const [pattern, name] of namePatterns) {
    if (pattern.test(rawTitle)) return name;
  }

  // 3. Short titles: return as-is (scanner titles like "X.509 Certificate",
  //    "RSA Private Key", "GitHub App Private Key" are already clean)
  if (rawTitle.length <= 80) {
    return rawTitle.trim();
  }

  // 4. Long titles — extract first sentence. Require ≥2 chars before the
  //    punctuation so we don't clip version numbers like "X.509" or "v2.0".
  const firstSentence = rawTitle.match(/^(.{2,}?[^.!?])[.!?]\s/);
  if (firstSentence) {
    const clause = firstSentence[1].trim();
    if (clause.length <= 80) return clause;
  }

  // Last resort — use category if available and meaningful
  if (category) {
    const stripped = category.replace(/^CWE-\d+:\s*/, "").trim();
    if (stripped && !genericCategories.has(stripped)) return stripped;
  }

  return rawTitle.substring(0, 60).trim();
}

/**
 * Extract a clean, short title (max ~50 chars) from verbose finding descriptions.
 * Scanner titles are often 100-500 character paragraphs — this extracts the key defect name.
 */
export function shortenFindingTitle(rawTitle: string, category?: string, maxLen = 50): string {
  if (!rawTitle) return category || "Unknown Finding";
  if (rawTitle.length <= maxLen) return rawTitle;

  const extractions: [RegExp, string][] = [
    [/^Detected\s+(?:a\s+)?template\s+variable\s+used\s+in\s+an?\s+(.{5,30}?)(?:\.|\s+This)/i, "Template variable in $1"],
    [/^Detected\s+user\s+input\s+flowing\s+into\s+(.{5,40}?)(?:\.|\s+You)/i, "User input in $1"],
    [/^Detected\s+the\s+use\s+of\s+(?:an?\s+)?(?:insecure\s+)?(\w[\w.()]+)/i, "Unsafe $1 usage"],
    [/^Detected\s+(?:possible\s+)?(.{5,45}?)(?:\.|$)/i, "$1"],
    [/^Possibility\s+of\s+([\w\s]+?)(?:\s+detected|\.)/i, "$1"],
    [/^Found\s+(?:a\s+)?(.{5,40}?)(?:\.|\s+This)/i, "$1"],
    [/^User\s+controlled\s+data\s+in\s+(?:methods\s+like\s+)?[`']?(\w+)[`']?/i, "User data in $1"],
    [/^Avoiding\s+([\w\s]+?):\s/i, "$1"],
    [/^It\s+looks\s+like\s+(\w+)\s+is\s+used\s+as\s+(?:a\s+)?([\w\s]+?)(?:\.|\s+because)/i, "$1 as $2"],
    [/^Detected\s+(\w+\s+hash\s+algorithm)/i, "Insecure $1"],
    [/^By\s+not\s+specifying\s+(.{5,35})/i, "Missing $1"],
    [/^([^.]{10,50})\./i, "$1"],
  ];

  for (const [pattern, replacement] of extractions) {
    const m = rawTitle.match(pattern);
    if (m) {
      let result = replacement;
      for (let i = 1; i <= m.length; i++) {
        result = result.replace(`$${i}`, m[i] || "");
      }
      result = result.trim().charAt(0).toUpperCase() + result.trim().slice(1);
      if (result.length > maxLen + 5) result = result.slice(0, maxLen + 2).trim() + "...";
      return result;
    }
  }

  // Fallback: first sentence — require sentence-terminating punctuation
  // followed by whitespace, so "X.509" won't split at the period.
  const firstSentence = rawTitle.match(/^([^.!?]{10,50})[.!?]\s/);
  if (firstSentence) return firstSentence[1].trim();

  const t = rawTitle.substring(0, maxLen);
  const s = t.lastIndexOf(" ");
  return (s > 20 ? t.substring(0, s) : t) + "...";
}
