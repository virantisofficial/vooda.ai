# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""
Structured File Parser — extracts key-value pairs from JSON, YAML, TOML, .properties,
and .env files, then checks if keys match sensitive patterns and values look like credentials.

Unlike line-by-line regex, this understands the data structure:
- Finds nested keys: {"database": {"password": "secret"}} → key="database.password"
- Handles multi-line values in YAML
- Detects secrets by KEY NAME, not just value pattern
"""

import os
import re
from dataclasses import dataclass
from typing import Optional

# ── Sensitive key patterns ─────────────────────────────────
# If a config key matches any of these, the VALUE is checked as a potential secret.

SENSITIVE_KEY_PATTERNS = re.compile(
    r'(?:^|[._-])'
    r'(?:'
    r'password|passwd|pwd|pass'
    r'|secret|token|key|credential|auth'
    r'|api[_-]?key|api[_-]?secret|api[_-]?token'
    r'|access[_-]?key|access[_-]?token|access[_-]?secret'
    r'|private[_-]?key|signing[_-]?key|encryption[_-]?key'
    r'|client[_-]?secret|client[_-]?id'
    r'|jwt[_-]?secret|session[_-]?secret|cookie[_-]?secret'
    r'|hmac[_-]?(?:key|secret)'
    r'|db[_-]?(?:password|pass|pwd)'
    r'|database[_-]?(?:password|url|uri|dsn)'
    r'|redis[_-]?(?:password|url|auth)'
    r'|mongo[_-]?(?:password|uri|url)'
    r'|mysql[_-]?(?:password|pwd)'
    r'|postgres[_-]?(?:password|pwd)'
    r'|smtp[_-]?(?:password|pass)'
    r'|aws[_-]?(?:secret|key|token)'
    r'|gcp[_-]?(?:key|token|credentials)'
    r'|azure[_-]?(?:key|secret|token)'
    r'|github[_-]?(?:token|secret|key)'
    r'|gitlab[_-]?(?:token|secret)'
    r'|slack[_-]?(?:token|secret|webhook)'
    r'|stripe[_-]?(?:key|secret)'
    r'|twilio[_-]?(?:token|sid|secret)'
    r'|sendgrid[_-]?(?:key|token)'
    r'|webhook[_-]?(?:secret|url|token)'
    r'|connection[_-]?string'
    r'|dsn|database[_-]?url'
    r')'
    r'(?:$|[._-])',
    re.IGNORECASE,
)

# Values that are clearly NOT secrets
PLACEHOLDER_VALUES = {
    "", "changeme", "change_me", "your_password", "your_secret", "your_api_key",
    "your_token", "password", "secret", "xxxxxxxx", "********",
    "placeholder", "your-secret-here", "replace_me", "todo", "fixme",
    "example", "test", "dummy", "fake", "sample", "default",
    "none", "null", "undefined", "empty", "notset", "not_set",
    "true", "false", "yes", "no", "on", "off",
    "0", "1", "localhost", "127.0.0.1", "0.0.0.0",
}


@dataclass
class StructuredSecret:
    """A secret found via structured key-value parsing."""
    key_path: str       # e.g., "database.password" or "SMTP_PASSWORD"
    value: str          # The secret value
    line_num: int       # Line number in original file
    file_type: str      # json, yaml, toml, properties, env


def _is_variable_reference(value: str) -> bool:
    """Check if value is an env var reference, not an actual secret."""
    v = value.strip()
    if v.startswith(("${", "$", "%", "{{", "<%")):
        return True
    if re.match(r'^[A-Z_]+$', v) and len(v) < 40:
        return True  # Likely an env var name like "MY_SECRET_KEY"
    return False


def _looks_like_credential(value: str) -> bool:
    """Check if value looks like an actual credential (not a placeholder)."""
    v = value.strip().strip("'\"")
    if len(v) < 6:
        return False
    if v.lower() in PLACEHOLDER_VALUES:
        return False
    if _is_variable_reference(v):
        return False
    # Must have some complexity — not just a word
    if v.isalpha() and len(v) < 20:
        return False
    # ── Additional FP filters ──────────────────────────────────
    # Human-readable sentence (translated UI strings, descriptions)
    space_count = v.count(' ')
    if space_count >= 3 and len(v) > 40:
        return False
    # Purely numeric short values (port numbers, IDs, timestamps)
    if v.replace('.', '').replace('-', '').isdigit() and len(v) < 12:
        return False
    # Plain URL without embedded credentials (no user:pass@host)
    if re.match(r'^https?://', v) and '@' not in v:
        return False
    # File path pattern
    if v.startswith(('./', '/', '~/', 'C:\\')) or re.match(r'^[\w./\\-]+\.\w{1,5}$', v):
        return False
    # HTML content (common in translation files)
    if '<' in v and '>' in v:
        return False
    # Ends with common non-secret file extensions
    if re.search(r'\.(html|css|js|png|jpg|svg|gif|pdf|xml|txt)$', v, re.IGNORECASE):
        return False
    return True


# ── Parsers ────────────────────────────────────────────────

def _parse_json(content: str) -> list[StructuredSecret]:
    """Parse JSON and extract sensitive key-value pairs."""
    import json
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return []

    secrets = []
    lines = content.split("\n")

    def _walk(obj, path=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_path = f"{path}.{k}" if path else k
                if isinstance(v, (dict, list)):
                    _walk(v, key_path)
                elif isinstance(v, str) and SENSITIVE_KEY_PATTERNS.search(k):
                    if _looks_like_credential(v):
                        # Find line number by searching for the key in content
                        line_num = _find_line(lines, k, v)
                        secrets.append(StructuredSecret(
                            key_path=key_path, value=v,
                            line_num=line_num, file_type="json",
                        ))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _walk(item, f"{path}[{i}]")

    _walk(data)
    return secrets


def _parse_yaml(content: str) -> list[StructuredSecret]:
    """Parse YAML and extract sensitive key-value pairs."""
    try:
        import yaml
        data = yaml.safe_load(content)
    except Exception:
        return []

    if not isinstance(data, dict):
        return []

    secrets = []
    lines = content.split("\n")

    def _walk(obj, path=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_path = f"{path}.{k}" if path else str(k)
                if isinstance(v, (dict, list)):
                    _walk(v, key_path)
                elif isinstance(v, str) and SENSITIVE_KEY_PATTERNS.search(str(k)):
                    if _looks_like_credential(v):
                        line_num = _find_line(lines, str(k), v)
                        secrets.append(StructuredSecret(
                            key_path=key_path, value=v,
                            line_num=line_num, file_type="yaml",
                        ))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _walk(item, f"{path}[{i}]")

    _walk(data)
    return secrets


def _parse_toml(content: str) -> list[StructuredSecret]:
    """Parse TOML and extract sensitive key-value pairs."""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # Python < 3.11
        except ImportError:
            return []

    try:
        data = tomllib.loads(content)
    except Exception:
        return []

    secrets = []
    lines = content.split("\n")

    def _walk(obj, path=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_path = f"{path}.{k}" if path else k
                if isinstance(v, dict):
                    _walk(v, key_path)
                elif isinstance(v, str) and SENSITIVE_KEY_PATTERNS.search(k):
                    if _looks_like_credential(v):
                        line_num = _find_line(lines, k, v)
                        secrets.append(StructuredSecret(
                            key_path=key_path, value=v,
                            line_num=line_num, file_type="toml",
                        ))

    _walk(data)
    return secrets


def _parse_properties(content: str) -> list[StructuredSecret]:
    """Parse .properties / .env / .ini style key=value files."""
    secrets = []
    lines = content.split("\n")

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", ";")):
            continue

        # Match key=value or key: value
        match = re.match(r'^([A-Za-z_][A-Za-z0-9._-]*)\s*[=:]\s*(.*)', stripped)
        if not match:
            continue

        key = match.group(1)
        value = match.group(2).strip().strip("'\"")

        if SENSITIVE_KEY_PATTERNS.search(key) and _looks_like_credential(value):
            secrets.append(StructuredSecret(
                key_path=key, value=value,
                line_num=i, file_type="properties",
            ))

    return secrets


def _find_line(lines: list[str], key: str, value: str) -> int:
    """Find the line number containing a key-value pair."""
    for i, line in enumerate(lines, 1):
        if key in line and (value[:20] in line if len(value) > 20 else value in line):
            return i
    # Fallback: find just the key
    for i, line in enumerate(lines, 1):
        if key in line:
            return i
    return 1


# ── Main entry point ──────────────────────────────────────

# File extensions mapped to parsers
STRUCTURED_EXTENSIONS = {
    ".json": _parse_json,
    ".yaml": _parse_yaml,
    ".yml": _parse_yaml,
    ".toml": _parse_toml,
    ".properties": _parse_properties,
    ".env": _parse_properties,
    ".ini": _parse_properties,
    ".cfg": _parse_properties,
    ".conf": _parse_properties,
}

# Filenames that are properties-style regardless of extension
STRUCTURED_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.development", ".env.staging",
    ".env.test", ".env.example", ".npmrc", ".pypirc", ".netrc",
}


def parse_structured_file(file_path: str, content: str) -> list[StructuredSecret]:
    """
    Parse a structured file and extract sensitive key-value pairs.
    Returns empty list if file type is not supported or parsing fails.
    """
    basename = os.path.basename(file_path)
    ext = os.path.splitext(file_path)[1].lower()

    # Check by filename first
    if basename.lower() in STRUCTURED_FILENAMES:
        return _parse_properties(content)

    # Check by extension
    parser = STRUCTURED_EXTENSIONS.get(ext)
    if parser:
        return parser(content)

    return []
