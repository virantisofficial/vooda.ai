# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""
Secret Scanning Engine — detects hardcoded secrets, API keys, tokens, and credentials.

Combines regex-based provider-specific detection with Shannon entropy analysis,
Base64 decoding, config key assignment detection, and context-aware FP filtering.
"""

import base64
import hashlib
import json
import os
import re
from typing import Optional, Callable
# Third-party ``regex`` library used for rule-pack patterns specifically
# because it supports a per-match ``timeout=`` kwarg.  Python's stdlib
# ``re`` does not, and the rule pack contains 946 patterns of varying
# quality — without a wall-clock guard a single pathological pattern
# vs. a pathological input (catastrophic backtracking / "ReDoS") can
# peg a worker at 100% CPU indefinitely.  Module-level constants in
# this file (``_BASE64_RE``, ``_CONFIG_KEY_PATTERN``) intentionally
# stay on stdlib ``re`` — they're hand-audited, fast, and don't
# need the timeout overhead.  Track-A 2026-05-24, after a live
# monitor of pulumi/pulumi showed a worker spend 12+ min pegged at
# 100% CPU on commit ~2,000 with zero throughput (signature of
# catastrophic backtracking).  Industry-standard fix (long-term) is
# to migrate to a non-backtracking engine (RE2 / Hyperscan); this
# is the defensive layer that ships immediately.
import regex as regex_lib  # type: ignore
import structlog

# ── Regex engine selection ──────────────────────────────────────────
# VOODA_REGEX_ENGINE controls which engine compiles the rule pack:
#   "hybrid" (default, recommended): try google-re2 first, fall back to
#     the third-party `regex` library for patterns re2 can't compile
#     (lookahead, large-repetition).  92.6% of the rule pack lands on
#     re2 — ReDoS-immune by design, no timeout needed.  The remaining
#     7.4% retains the `regex` + timeout safety net.
#   "regex": force the legacy `regex` library for ALL rules.  Use to
#     rollback if hybrid causes unexpected detection regressions.
#   "re": stdlib `re` for ALL rules (no timeout possible).  TEST-ONLY
#     escape hatch — never use in production.
_REGEX_TIMEOUT_S: float = float(os.getenv("VOODA_REGEX_TIMEOUT_S", "2.0"))
_REGEX_ENGINE: str = os.getenv("VOODA_REGEX_ENGINE", "hybrid").lower()
logger = structlog.get_logger()

# Try to import google-re2.  If the import fails (not yet installed
# in the runtime env, missing native binary, etc.), the module
# degrades gracefully to regex-only mode.  We log this once at module
# load so ops can see it.
try:
    import re2 as _re2
    _RE2_AVAILABLE = True
except ImportError:
    _re2 = None  # type: ignore
    _RE2_AVAILABLE = False
    if _REGEX_ENGINE == "hybrid":
        logger.warning(
            "regex_engine_re2_unavailable",
            detail="google-re2 not importable; falling back to regex-only mode for this process",
        )


def _compile_rule_pattern(pattern: str, *, case_sensitive: bool, multiline: bool) -> tuple[str, object]:
    """Compile a single rule's pattern with the best available engine.

    Returns (engine_name, compiled_obj) where engine_name is one of
    "re2" or "regex".  Dispatch logic:

    - engine == "re2": try re2 first.  re2 is ReDoS-immune by design
      — no timeout required at match time.  ~92.6% of the rule pack
      compiles clean.  Fall through to "regex" if re2 rejects the
      pattern (lookahead, large-repetition, etc.).
    - engine == "regex": skip re2 entirely.  Used by the env override
      VOODA_REGEX_ENGINE=regex (rollback toggle) or when re2 isn't
      importable in this process.
    - engine == "re": stdlib re, no timeout.  Test-only.

    Flag semantics mapped:
        re.MULTILINE  → re2 default (always on); regex flag
        re.IGNORECASE → re2.Options.case_sensitive = False; regex flag
        re.DOTALL     → re2.Options.dot_nl = True;          regex flag
    """
    re_flags = re.MULTILINE
    if not case_sensitive:
        re_flags |= re.IGNORECASE
    if multiline:
        re_flags |= re.DOTALL

    if _REGEX_ENGINE == "re":
        return ("re", re.compile(pattern, re_flags))

    if _REGEX_ENGINE == "hybrid" and _RE2_AVAILABLE:
        try:
            opts = _re2.Options()
            # NOTE re2 default is case_sensitive=True; Vooda default is
            # the opposite (case-insensitive unless rule opts in to
            # strict matching).  Map explicitly.
            opts.case_sensitive = bool(case_sensitive)
            opts.dot_nl = bool(multiline)
            # Silence re2's stderr "invalid perl operator" noise when a
            # pattern needs the regex fallback — we already log the
            # final per-engine breakdown via secret_scanner_compiled.
            opts.log_errors = False
            # re2 has no separate MULTILINE flag — `^` and `$` always
            # match line boundaries by default, which is what Vooda
            # wants (matches re.MULTILINE behaviour).
            compiled = _re2.compile(pattern, options=opts)
            return ("re2", compiled)
        except Exception:
            # Fall through to regex_lib — re2 can't compile this pattern
            # (lookahead, lookbehind, large repetition, etc.).  This is
            # expected for ~7.4% of the rule pack per the survey.
            pass

    # Fallback path (also the path for VOODA_REGEX_ENGINE=regex)
    return ("regex", regex_lib.compile(pattern, re_flags))


def _safe_finditer(compiled: object, engine: str, content: str):
    """Run finditer with engine-appropriate safety.

    re2: no timeout (ReDoS-immune by engine design).
    regex: per-match timeout from _REGEX_TIMEOUT_S.
    re: no timeout (stdlib doesn't support it — test mode only).

    Returns a list (materialized) so the caller's try/except sees any
    TimeoutError synchronously, not at iteration time.
    """
    if engine == "re2" or engine == "re":
        return list(compiled.finditer(content))  # type: ignore[attr-defined]
    return list(compiled.finditer(content, timeout=_REGEX_TIMEOUT_S))  # type: ignore[call-arg]


def _safe_search(compiled: object, engine: str, content: str):
    """Run search with engine-appropriate safety.  See _safe_finditer."""
    if engine == "re2" or engine == "re":
        return compiled.search(content)  # type: ignore[attr-defined]
    return compiled.search(content, timeout=_REGEX_TIMEOUT_S)  # type: ignore[call-arg]


# Bumped when the engine itself changes in a way that affects scan
# output but isn't reflected in any individual ``SecretRule`` field.
# Examples: changes to ``_should_scan_file``, structured-parser
# normalization, entropy thresholds, dedup logic in
# ``scan_directory``, ``_classify_file_context`` rules.
#
# This constant is folded into ``SecretScanner.rule_pack_version`` so a
# bump invalidates every ``file_scan_cache`` row across every tenant on
# the next scan. Set the date you bump it so it's obvious in code
# review that a cache invalidation is intentional, not accidental.
ENGINE_VERSION = "2026-05-05"

from packages.parsers.base import ParsedFinding
from services.secret_scan.config import (
    SCAN_EXTENSIONS, SPECIAL_FILENAMES, SKIP_DIRS,
    MAX_FILE_SIZE_BYTES, MAX_LINE_LENGTH,
    ENTROPY_SKIP_FILES, STRUCTURED_SKIP_DIRS, FULLY_SKIPPED_FILES,
    FULLY_SKIPPED_PATH_PATTERNS,
    KNOWN_PLACEHOLDER_VALUES, KNOWN_PLACEHOLDER_PATTERNS,
    CONTENT_PROMOTE_RE, CONTENT_PROMOTE_RE_STR, PROMOTE_BINARY_SCREEN_BYTES,
)
import fnmatch as _fnmatch
from services.secret_scan.detectors.base import SecretRule
from services.secret_scan.detectors.registry import get_all_rules
from services.secret_scan.entropy import find_high_entropy_strings
from services.secret_scan.context import adjust_confidence
from services.secret_scan.structured_parser import parse_structured_file
from services.secret_scan.comment_extractor import (
    extract_comments,
    build_virtual_comment_content,
)


def _is_known_placeholder(value: str) -> bool:
    """Check if a detected secret is a known placeholder/example from documentation."""
    if not value:
        return False
    v = value.strip().strip("'\"")
    # Exact match against known placeholder values
    if v in KNOWN_PLACEHOLDER_VALUES:
        return True
    # Partial pattern match — contains known placeholder substrings
    v_upper = v.upper()
    for pattern in KNOWN_PLACEHOLDER_PATTERNS:
        if pattern.upper() in v_upper:
            return True
    return False


def _is_exact_known_placeholder(value: str) -> bool:
    """True only for an EXACT-match canonical published example.

    These (the AWS doc key ``AKIAIOSFODNN7EXAMPLE``, GitHub ``ghp_XXX…``,
    Stripe test keys, …) are enumerated in ``KNOWN_PLACEHOLDER_VALUES`` and are
    NEVER real credentials, so a finding on one can be dropped outright rather
    than surfaced as a low-confidence finding. This is stricter than
    ``_is_known_placeholder`` (which also matches broad substrings like
    ``EXAMPLE``/``xxx``) precisely because dropping is irreversible — only the
    exact, documented example values qualify, so recall on real secrets cannot
    be affected.
    """
    if not value:
        return False
    return value.strip().strip("'\"") in KNOWN_PLACEHOLDER_VALUES


def _decodes_to_known_placeholder(value: str) -> bool:
    """True if ``value`` base64-decodes to a documented placeholder.

    Kubernetes / Helm secret values are base64 by convention, so a base64 blob
    whose plaintext is a known placeholder (b64 of ``example-app-secret``,
    ``changeme``, …) is not a real credential. Recall-safe by construction: a
    random real secret decodes to non-printable bytes, so ``_try_base64_decode``
    (strict-printable) returns None and nothing is suppressed; only a
    deliberately base64-encoded *printable* placeholder is caught. The length
    cap stops a broad substring (``EXAMPLE``/``xxx``) inside a longer, legitimately
    base64-encoded payload from triggering a false suppression.
    """
    if not value:
        return False
    decoded = _try_base64_decode(value)
    return bool(decoded and len(decoded) <= 64 and _is_known_placeholder(decoded))


# A credential key-name appearing near a value is the single strongest signal
# that a high-entropy/structured token is actually a secret (vs. a git SHA,
# content hash, checksum, build id, or random identifier). Used to gate the
# generic hex-entropy rule, which otherwise fires on every 40/64-hex digest in
# a checksum manifest. Deliberately broad on the credential side (recall) and
# applied only to the otherwise-context-free hex charset.
_CREDENTIAL_KEYNAME_RE = re.compile(
    r'(api[_-]?key|secret|token|passwd|password|pwd|credential|access[_-]?key|'
    r'client[_-]?secret|private[_-]?key|signing[_-]?key|session[_-]?key|'
    r'encryption[_-]?key|bearer|auth[_-]?token|authorization|x-api|apikey)',
    re.IGNORECASE,
)


def _hex_has_credential_context(lines: list, line_num: int) -> bool:
    """True if a credential key-name sits on/near a bare hex value's line.

    Pure-hex high-entropy strings are indistinguishable from git SHAs,
    checksums, and digests, so the generic hex-entropy rule only reports one
    when a credential key-name is present. The ±1-line window keeps recall on
    multi-line config (``api_key:`` on the line above the hex value) while a
    checksum manifest (``<hex>  filename``) — which carries no key-name — is
    correctly suppressed.
    """
    lo = max(0, line_num - 2)
    hi = min(len(lines), line_num + 1)
    ctx = "\n".join(lines[lo:hi])
    return bool(_CREDENTIAL_KEYNAME_RE.search(ctx))


# ── Structural inverse-filter (the STRUCT-* false-positive killer) ──────────
# A structural finding fires on (sensitive KEY-NAME + any value); the bulk of
# its false positives are CloudFormation / CDK / Helm / K8s entries whose VALUE
# is provably NOT a literal secret. Suppressing those values cannot drop a true
# positive, because a real secret-in-config is ALWAYS a literal credential value
# — never one of these shapes. This is pinned by the hard-gate recall corpus
# tests/secret_scan/test_secrets_in_config_recall.py.
#
# Deliberately EXCLUDES the ambiguous shapes that *could* be a real secret:
#   - UUIDs (some providers issue UUID-format API keys)
#   - bare URLs (a Slack/Discord/Teams webhook URL is a secret and has no '@')
#   - CamelCase+hex logical-ids (a real secret can end in 8 hex chars)
# so the filter is recall-safe by construction, not by heuristic.
_STRUCT_REFERENCE_RE = re.compile(
    r'^\s*(?:'
    r'\$\{\{?.*\}\}?'                 # ${VAR}, ${{ secrets.X }}
    r'|\$\([^)]*\)'                   # $(VAR)
    r'|\{\{.*\}\}'                    # {{ .Values.x }}, Jinja, Go-template
    r'|<[^>]{1,60}>'                  # <placeholder>
    r'|%\([^)]+\)s'                   # python %(name)s
    r'|!(?:Ref|GetAtt|Sub|Join|Select|FindInMap|ImportValue|If|Equals|Base64|Cidr|GetAZs|Split)\b'
    r')\s*$',
    re.IGNORECASE,
)
_STRUCT_STRUCTURAL_RE = re.compile(
    r'^(?:'
    r'arn:[a-z0-9\-]*:\S+'                              # ARN identifier
    r'|aws[:\-]cdk[:\-]\S*'                             # CDK metadata (aws:cdk:path / aws-cdk:...)
    r'|[A-Za-z][A-Za-z0-9]*(?:::[A-Za-z0-9]+)+'         # resource type Foo::Bar(::Baz)
    r'|(?:true|false|yes|no|on|off|null|none|nil|enabled|disabled)'  # bool / enum
    r'|\d+(?:\.\d+)?(?:ms|s|m|h|d|ki|mi|gi|kb|mb|gb|%)'  # duration / size (unit REQUIRED)
    r')$',
    re.IGNORECASE,
)


def _struct_value_is_nonsecret(value: str) -> bool:
    """True when a structural value is *provably* not a literal secret.

    Recall-safe by construction: a real secret-in-config is always a literal
    credential value, never a reference / IaC intrinsic / ARN / resource-type /
    bool / duration. The config-secret recall corpus is the hard gate proving the
    KEEP cases (``password: hunter2``, etc.) never match here.
    """
    if not value:
        return True
    v = value.strip().strip('\'"').strip()
    if not v:
        return True
    return bool(_STRUCT_REFERENCE_RE.match(v) or _STRUCT_STRUCTURAL_RE.match(v))


# Tier B: the generic STRUCT rule emits under ANY key, so it fires on structural
# values whose KEY is not credential-bearing — Keycloak clientIds, MongoDB /
# OpenTelemetry field names, blockchain addresses, *public* keys. Value-level
# ground truth over the 100-repo benchmark (NOT the noisy AI labels) showed this
# accounts for ~3,232 of 3,930 STRUCT-JSON findings and ~0 real secrets. A real
# secret-in-config lives under a credential-named key; a real secret with a
# recognizable provider/PEM format is independently caught by its specific rule
# (and by the CONTENT_PROMOTE escape hatch at the call site). So generic STRUCT
# is gated to credential-ish keys. `\b…\b` boundaries keep loose substrings
# ("auth" inside "authenticationFlowBindingOverrides", "key" inside "monkey")
# from re-opening the false positives.
#   NB: no \b around token/pwd — snake_case ("access_token", "db_pwd") puts a
#   word char ('_') next to them, so \b would MISS real credential keys. The
#   benchmark's structural-noise keys (clientId, cidrBlock, status_code,
#   consentRequired, authenticationFlowBindingOverrides, version, …) contain
#   none of these substrings, so plain substring matching is both safe and
#   correct here. Bare "key" is deliberately NOT matched (it is the #1 FP key);
#   only the *_key compound forms are.
_STRUCT_CRED_KEY_RE = re.compile(
    r"password|passwd|passphrase|pwd|secret|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|signing[_-]?key|client[_-]?secret|credential|token|"
    r"connection[_-]?string|\bdsn\b|sasl|bearer|"
    # Crypto / key-material compounds — RECALL FIX (2026-06-08). The bare
    # predicate missed these, so the STRUCT credential-key gate could silently
    # drop real secrets stored under them (surfaced by the CONFIG-ASSIGN clone
    # ground truth: authelia `encryption_key: <base64>`). Specific compounds
    # only — deliberately NOT a bare `*[_-]?key`, which would re-admit the
    # DB-schema false positives (foreign_key / primary_key / partition_key /
    # sort_key) that are not secrets.
    r"encryption[_-]?key|master[_-]?key|session[_-]?key|hmac[_-]?key|"
    r"enc[_-]?key|cipher[_-]?key|crypto[_-]?key|ssh[_-]?key|tls[_-]?key|"
    r"gpg[_-]?key|pgp[_-]?key|kms[_-]?key"
)


def _struct_key_is_credential(key_path: str) -> bool:
    """True when a structured-config key name denotes a credential field
    (password / secret / token / api_key …). Used to gate the generic STRUCT
    rule so it stops firing on structural identifiers under non-credential keys.
    Recall-safe: format-recognizable secrets under any key are still caught by
    their specific provider/crypto rule + the marker escape hatch."""
    return bool(_STRUCT_CRED_KEY_RE.search((key_path or "").lower()))


# ── Universal non-secret value shapes (apply to EVERY rule) ─────────────────
# Shapes that are NEVER a plaintext credential, regardless of which rule matched:
#   - a crypt password HASH ($6$…/$2b$…/$argon2id$… — one-way, not reversible),
#   - a bare environment reference ($VAR / ${VAR}),
#   - an "intentionally insecure" doc/template marker (a_not_so_secure_…,
#     you_must_change_this) used universally to say "example — replace me".
# No provider/crypto secret has any of these shapes, so suppressing them cannot
# drop a true positive (pinned by the config-secret + harness recall corpora).
_CRYPT_HASH_RE = re.compile(
    r'^\$(?:1|2[abxy]?|5|6|7|y|gy|s|md5|sha1|sha256|sha512|apr1|'
    r'argon2(?:id|i|d)?|pbkdf2[a-z0-9-]*|scrypt|bcrypt[a-z0-9-]*)\$',
    re.IGNORECASE,
)
# Non-anchored variant — detect a crypt hash anywhere on a line. The entropy
# detector extracts the high-entropy *body* of a hash (which has no ``$id$``
# prefix), so the hash must be recognised at the line level to suppress it.
_CRYPT_HASH_INLINE_RE = re.compile(
    r'\$(?:1|2[abxy]?|5|6|7|y|gy|md5|sha1|sha256|sha512|apr1|'
    r'argon2(?:id|i|d)?|pbkdf2[a-z0-9-]*|scrypt|bcrypt[a-z0-9-]*)\$',
    re.IGNORECASE,
)
_BASH_VARREF_RE = re.compile(r'^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$')
_INSECURE_EXAMPLE_MARKERS = (
    "not_so_secure", "notsosecure", "not-so-secure",
    "you_must_change", "youmustchange", "you-must-change", "must_be_changed",
    "change_this", "changethis", "change-this", "replace_this", "replacethis",
    "insecure_example", "for_testing_only", "do_not_use_in_prod", "donotusethis",
)

# Programming language keywords / type names — CONFIG-ASSIGN also scans source
# files (``var blockType string``, ``PrivateKey any``), where the captured value
# is a language token, never a credential. A bare match against this set is
# recall-safe: no real secret equals "string"/"any"/"int".
_CODE_KEYWORD_VALUES = frozenset({
    "string", "int", "int8", "int16", "int32", "int64",
    "uint", "uint8", "uint16", "uint32", "uint64",
    "bool", "boolean", "byte", "rune", "float", "float32", "float64", "double",
    "decimal", "number", "any", "error", "nil", "null", "none", "void", "char",
    "long", "short", "object", "interface", "struct", "func", "var", "const",
    "let", "map", "slice", "array", "list", "dict", "tuple", "set",
    "true", "false", "undefined", "self", "this", "pass", "return",
    "static", "final", "public", "private", "protected", "abstract",
})


# JWT documentation/example detector (Tier B 2026-06-08). The bare-token
# JWT-001 rule fires heavily on the canonical copy-paste JWTs in docs/tests
# (jwt.io's `"name":"John Doe"` / issuer `example.com`). A JWT whose DECODED
# payload carries one of those canonical example claims is provably not a
# production secret — recall-safe to suppress. Markers are restricted to
# UNAMBIGUOUS example indicators (no bare timestamps / common words), so a real
# token's claims never match. Value-level ground truth: 176 of 420 JWT-001 FP
# carried example claims; the 16 "TP" that did are AI mislabels (an example JWT
# is not a leaked secret).
_JWT_SHAPE_RE = re.compile(r"^eyJ[A-Za-z0-9\-_]+\.(eyJ[A-Za-z0-9\-_]+)\.[A-Za-z0-9\-_]+$")
_JWT_EXAMPLE_CLAIM_RE = re.compile(
    r"john ?doe|jane ?doe|jrocket|joe ?blogg|johndoe|example\.com|@example\.", re.I
)


def _is_example_jwt(value: str) -> bool:
    """True iff ``value`` is a JWT whose decoded payload carries a canonical
    documentation/example claim. Recall-safe: such tokens are copy-paste
    examples, never production secrets."""
    m = _JWT_SHAPE_RE.match(value)
    if not m:
        return False
    seg = m.group(1)
    try:
        payload = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)).decode("utf-8", "ignore")
    except Exception:
        return False
    return _JWT_EXAMPLE_CLAIM_RE.search(payload) is not None


# Tier 1b (2026-06-08): pure value-SHAPE non-secrets safe for EVERY rule.
# Unlike the CONFIG-ASSIGN context filters (value==key, fallback-operand, ref),
# these are intrinsic properties of the value that no real credential ever has,
# so applying them in the universal path cannot suppress a specific rule's own
# secret (a JWT is mixed-case, an AWS key has no underscores, a real token is
# not "your_api_key"). Pinned by test_tier1b_universal_value_shapes.py.
_SCREAMING_SNAKE_VALUE_RE = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
_DOC_PLACEHOLDER_VALUE_RE = re.compile(
    r"goes_?here|[_-]here$|your[_-]\w*(?:key|token|secret|pass)|placeholder|<[\w.\-]+>",
    re.IGNORECASE,
)


def _value_is_nonsecret_universal(value: str) -> bool:
    if not value:
        return False
    v = value.strip().strip('\'"').strip()
    if not v:
        return False
    if _CRYPT_HASH_RE.match(v) or _BASH_VARREF_RE.match(v):
        return True
    if _is_example_jwt(v):
        return True
    # SCREAMING_SNAKE_CASE constant/enum (GRANT_TYPE_REFRESH_TOKEN) — code
    # constant, never a literal secret. Requires an underscore, so AWS-style
    # AKIA… all-caps tokens (no underscore) are NOT matched.
    if _SCREAMING_SNAKE_VALUE_RE.match(v):
        return True
    # Documentation placeholder value (MYAWSACCESSKEYGOESHERE, your_api_key,
    # <your-token>).
    if _DOC_PLACEHOLDER_VALUE_RE.search(v):
        return True
    vl = v.lower()
    return any(m in vl for m in _INSECURE_EXAMPLE_MARKERS)


# ── Tier 1c (2026-06-08): uniform CONTEXT/structural gate for GENERIC rules ──
# The CONFIG-ASSIGN context filters (value==key, fallback-operand, attribute
# ref, structural value) close ~hundreds of FP, but until now only CONFIG-ASSIGN
# ran them — GEN-*/ENTROPY-*/K8S-* emitted from the regex loop got only the
# value-SHAPE universal filter. This consolidates them into one shared gate
# applied to every GENERIC catch-all rule.
#
# Why this is recall-safe for generic rules but NOT promoted to the universal
# path: a generic rule matches by position/keyword and has no recall guarantee
# of its own, so suppressing one of these code-construct matches never loses a
# real secret (a literal secret is never its own key, an unquoted bare-id
# fallback, a dotted ref, or a path; and if the value WERE real, an anchored
# specific rule still catches it). A SPECIFIC rule's anchored match, by
# contrast, IS a real secret even in these contexts — so specific rules are
# excluded and keep firing.
_GENERIC_RULE_RE = re.compile(r"(?:GEN-|CONFIG-|STRUCT-|ENTROPY-|K8S-|HELM-|PLAUSIBLE-)|WEAK$")
_GENERIC_ATTR_REF_RE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+[\[\(.]?")
# url-path / number / boolean — deliberately NOT mime (\w+/\w+): base64 secrets
# contain '/', so a leading-slash anchor is required.
_GENERIC_STRUCT_VAL_RE = re.compile(r"/[\w/.\-]*|[\d.]+|(?:true|false|none|null|nil)", re.IGNORECASE)


def _is_generic_rule(rule_id: str) -> bool:
    """True for catch-all rules (GEN-/CONFIG-/STRUCT-/ENTROPY-/K8S-/HELM-/
    PLAUSIBLE-/*-WEAK); False for anchored provider/crypto rules."""
    return bool(_GENERIC_RULE_RE.search(rule_id or ""))


def _value_is_code_symbol(value: str) -> bool:
    """A captured 'value' that is a code construct/symbol, never a literal secret.
    Recall-safe for GENERIC catch-all rules ONLY (CONFIG-ASSIGN / GEN-*): a real
    secret is a high-entropy token that always carries digits and never contains
    brackets/generics, equals a KEY=value env-line fragment, or is a digit-free
    camelCase/snake_case code identifier. The benchmark TP canaries all carry
    digits (anvato 3hwbSuqqT690…, tianapi 772a…1b84, daytona dtn_…65f0) so none
    are matched here. A specific anchored rule still fires on a real secret."""
    if not value:
        return False
    v = value.strip().strip("'\"").strip()
    if not v:
        return False
    # (1) brackets / generics: Optional[SecretStr], List<str>, {var}, props[...]
    if re.search(r"[\[\]<>{}]", v):
        return True
    # (2) UPPER_SNAKE env-line fragment captured whole: POSTHOG_HOST=https://…
    if re.match(r"[A-Z][A-Z0-9_]{2,}\s*=", v):
        return True
    # (3) camelCase / PascalCase code identifier — PURE letters with a case hump.
    #     Real keys carry digits; a digit-free camelCased token is a symbol
    #     (RefreshToken, credsInputSchema, SecretStr). 3hwbSuqqT690… has digits.
    if v.isalpha() and re.search(r"[a-z][A-Z]", v):
        return True
    # (4) snake_case identifier of pure-lowercase words — a variable / key-name
    #     reference (models_lab_api_key), never a random literal.
    if re.fullmatch(r"[a-z]+(?:_[a-z]+)+", v):
        return True
    return False


def _generic_context_is_nonsecret(value: str, line: str, key: str = "") -> bool:
    """Context/structural non-secret checks, recall-safe for GENERIC rules only.
    Caller MUST gate with `_is_generic_rule` first."""
    if not value:
        return True
    # (a) value == its own key — a self-reference fallback.
    if key and value.lower() == key.lower():
        return True
    # (b) bare identifier as the operand of a boolean/fallback expression — a
    #     variable, not a literal (`= access_token or os.environ.get(...)`). The
    #     closing quote of a real literal breaks this match, so quoted secrets
    #     are unaffected.
    if re.fullmatch(r"[A-Za-z_]\w*", value) and \
       re.search(re.escape(value) + r"\s*(?:\bor\b|\|\||\?\?)", line):
        return True
    # (c) attribute/object reference (process.env[, a.b.c, self.cfg()).
    if _GENERIC_ATTR_REF_RE.fullmatch(value):
        return True
    # (d) structural value: url-path, number, boolean.
    if _GENERIC_STRUCT_VAL_RE.fullmatch(value):
        return True
    # (e) P1: code construct / code-symbol value (brackets/generics, KEY=value
    #     env-line fragment, camelCase / snake_case code identifier) — captured
    #     by the catch-all but never a literal secret.
    if _value_is_code_symbol(value):
        return True
    return False


def _classify_file_context(file_path: str) -> str:
    """Classify a file into a context category based on its path and name."""
    fp = file_path.lower().replace("\\", "/")
    name = fp.split("/")[-1]
    # Prepend "/" so directory tokens like "/test/" match at the repo root
    # (relative paths like "test/api/foo.ts" would otherwise fail the match).
    fp_anchored = "/" + fp.lstrip("/")
    # Path segments for reliable detection regardless of nesting depth.
    segs = set(fp.split("/")[:-1])  # directories only, not filename

    # Test files
    _test_segs = {"test", "tests", "spec", "specs", "__tests__", "testing",
                  "e2e", "fixtures", "cypress", "testdata", "test-data",
                  "mocks", "__mocks__"}
    if segs & _test_segs:
        return "test_file"
    if any(d in fp_anchored for d in ("/test/", "/tests/", "/spec/", "/specs/",
            "/__tests__/", "/testing/", "/test_", "/e2e/", "/fixtures/",
            "/cypress/", "/testdata/", "/test-data/", "/mocks/", "/__mocks__/")):
        return "test_file"
    if name.endswith((".test.js", ".test.ts", ".test.tsx", ".spec.js", ".spec.ts",
            ".spec.tsx", "_test.py", "_test.go", "test.java", "tests.java",
            ".test.rb", ".spec.rb", ".test.kt", ".spec.kt", "_spec.rb", "spec.js",
            "spec.ts")):
        return "test_file"

    # Documentation
    if any(d in fp for d in ("/docs/", "/doc/", "/documentation/", "/guide/", "/wiki/")):
        return "documentation"
    if name in ("README.md", "CHANGELOG.md", "CONTRIBUTING.md", "LICENSE", "SECURITY.md"):
        return "documentation"

    # CI/CD
    if any(d in fp for d in ("/.github/", "/.gitlab-ci", "/.circleci/", "/jenkins/", "/.travis")):
        return "ci_cd"
    if name in ("Jenkinsfile", ".travis.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml"):
        return "ci_cd"

    # Infrastructure / IaC
    if any(d in fp for d in ("/terraform/", "/infrastructure/", "/deploy/", "/k8s/", "/kubernetes/", "/helm/", "/ansible/")):
        return "infrastructure"
    if name.endswith((".tf", ".tfvars", ".hcl")):
        return "infrastructure"
    if name in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml", "Vagrantfile"):
        return "infrastructure"

    # Examples / samples
    if any(d in fp for d in ("/examples/", "/example/", "/samples/", "/sample/", "/demo/", "/sandbox/")):
        return "example"

    # Config files
    if name.startswith(".env") or name in (".npmrc", ".pypirc", ".netrc", ".htpasswd", ".pgpass"):
        return "config"
    if name.endswith((".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties")) and "/src/" not in fp:
        return "config"

    # Default — source code
    return "source_code"


# ── P2 (2026-06-09): low-signal file contexts for GENERIC catch-all rules ──
# A generic rule matching inside a test fixture, minified/bundled blob, i18n/
# locale data, docs/example/notebook prose, or a crypto known-answer-test (KAT)
# vector is noise (Opus×Vooda benchmark: 0 TP across these for GEN-/STRUCT-/
# ENTROPY-). Recall-safe to suppress *generic* rules here — same Tier 1c logic:
# a real secret in these files is still caught by an anchored SPECIFIC rule,
# which is never gated.
_MINIFIED_FILE_RE = re.compile(r"\.(?:min|bundle|chunk)\.(?:js|mjs|css)$|[._-]min\.(?:js|css)$")
_I18N_FILE_RE = re.compile(r"/(?:locales?|i18n|lang|translations?)/|(?:messages|translation|locale|strings)[\w.\-]*\.json$")

# ── Pattern-database / detector-corpus files (2026-06-14) ──
# Files like secrets-patterns-db's db/rules-stable.yml, a gitleaks.toml, or any
# "secret-scanning-custom-patterns" YAML are *definitions of detection patterns*
# — every line is a `name:`/`regex:`/`[[rules]]` entry, not a live credential.
# They are dense in provider keywords (convertkit, api_secret, aws, …) AND in
# example/test token strings, so generic proximity rules misfire en masse there
# (opus×vooda benchmark: 0 TP, many FP — incl. CONVERTKIT-001 matching the
# pattern *name* `trex_okta_client_token`). Gating GENERIC rules on these is
# recall-safe: a real secret in such a file is still caught by an anchored
# SPECIFIC rule, which is never gated.
_PATTERN_DB_DEF_RE = re.compile(r"(?im)^\s*(?:-\s*pattern:|regex:|\[\[rules\]\])")


def _pattern_db_file(file_path: str, content: str | None = None) -> bool:
    """True when the file is a secret-pattern *database* (detector corpus),
    not application code that could hold a live secret."""
    fp = (file_path or "").lower().replace("\\", "/")
    name = fp.rsplit("/", 1)[-1]
    # Known pattern-database repos / canonical filenames (fast path).
    if any(t in fp for t in ("secrets-patterns-db", "secret-scanning-custom-patterns")):
        return True
    if name in ("rules-stable.yml", "rules-stable.yaml", "gitleaks.toml", ".gitleaks.toml"):
        return True
    # Ground-truth shape: a file that is overwhelmingly pattern DEFINITIONS
    # (>=25 of them) is a detector corpus regardless of name/location. The high
    # threshold won't trip on an app config with a couple of `regex:` keys.
    if content and len(_PATTERN_DB_DEF_RE.findall(content)) >= 25:
        return True
    return False


def _generic_lowsignal_file(file_path: str, content: str | None = None) -> bool:
    """True when a GENERIC-rule match in this file is non-secret noise."""
    if _classify_file_context(file_path) in ("test_file", "documentation", "example"):
        return True
    if _pattern_db_file(file_path, content):          # detector-corpus / pattern DB
        return True
    fp = (file_path or "").lower().replace("\\", "/")
    name = fp.rsplit("/", 1)[-1]
    if name.endswith(".ipynb"):                       # notebook prose / output cells
        return True
    if _MINIFIED_FILE_RE.search(name) or _I18N_FILE_RE.search(fp):
        return True
    if any(t in fp for t in ("keygen", "test-vector", "test_vector", "/kat/", "-kat.", "_kat.")):
        return True                                   # crypto known-answer-test vectors
    # P1: env TEMPLATE files (.env.example/.default/.sample/.template/.dist) and
    # test/CI compose+yaml carry placeholder values, not real secrets. Recall-safe
    # (generic-only): a real secret here is still caught by a SPECIFIC rule. NOTE
    # deliberately excludes ".env" / ".env.local" — those hold real dev secrets.
    if re.search(r"\.env\.(example|default|sample|template|dist|tmpl)$", name) or \
       re.search(r"\.(test|spec)\.ya?ml$", name) or \
       name.startswith(("docker-compose.test", "docker-compose.ci", "compose.test")):
        return True
    return False


def _secret_is_guessable(value: str) -> bool:
    """True when revealing ANY slice of the secret would narrow it to a guess —
    so it must be FULLY masked rather than partially revealed.

    A partial mask (first-4/last-4) is only safe for long, high-entropy secrets
    (random API keys/tokens): 8 shown characters of a large random keyspace leak
    almost nothing. For weak/default credentials, dictionary words, and short or
    low-entropy values, the same 8 characters + the length pin the value to a
    handful of candidates (``admin123`` is basically the only fit for ``ad…3``,
    len 8). This is the entropy-aware masking that GitGuardian/Wiz/GitHub use:
    reveal a bounded number of *entropy bits*, never a fixed fraction.

    Heuristic (value-only, no rule context needed):
      * shorter than 12 chars            → guessable (a prefix+length narrows it)
      * < 3.0 bits/char OR < 60 bits total → guessable (dictionary / weak / repeat)
      * otherwise                         → high-entropy → safe to partial-reveal
    """
    v = (value or "").strip().strip("'\"`")
    if not v or len(v) < 12:
        return True
    import math
    from collections import Counter
    n = len(v)
    counts = Counter(v)
    bits_per_char = -sum((c / n) * math.log2(c / n) for c in counts.values())
    if bits_per_char < 3.0 or bits_per_char * n < 60.0:
        return True
    return False


def _pem_parts(value: str):
    """If ``value`` is a PEM / private-key block, return
    ``(begin_marker, base64_body, end_marker)`` with the body stripped of
    whitespace; else ``None``. Lets us mask private keys the way GitGuardian /
    GitHub do — keep the ``BEGIN``/``END`` markers (the key *type*, not the
    secret) and reveal a few chars of the body — instead of collapsing the whole
    multi-line block to a single ``----****----`` token."""
    m = re.search(
        r"(-----BEGIN [A-Z0-9 /]+-----)(.*?)(-----END [A-Z0-9 /]+-----)",
        value, re.DOTALL,
    )
    if not m:
        return None
    return m.group(1), re.sub(r"\s+", "", m.group(2)), m.group(3)


def _mask_secret(value: str) -> str:
    """Entropy/type-aware mask — the SINGLE source used by both the Overview
    ``masked_value`` and the Code-tab snippet redaction, so the two can never
    disagree. Guessable secrets reveal nothing (fixed-width ``********`` so even
    the length isn't leaked); only long high-entropy secrets reveal a safe
    first-4/last-4 window (e.g. ``AIza****kkGM``). A PEM / private key reveals
    the first-4/last-4 of its BODY (e.g. ``b3Bl****zz99``), not the ``-----``
    delimiters."""
    if not value:
        return ""
    parts = _pem_parts(value)
    if parts:
        body = parts[1]
        return (body[:4] + "****" + body[-4:]) if len(body) >= 8 else "********"
    if _secret_is_guessable(value):
        return "********"
    return value[:4] + "****" + value[-4:]


# PEM block matcher: a full BEGIN…END block, OR a BEGIN…<truncated> run when a
# narrow snippet window cut off the END line (long keys). Lets us mask key
# material in a snippet without ever leaving raw body bytes behind.
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 /]+-----[\s\S]*?-----END [A-Z0-9 /]+-----"
    r"|-----BEGIN [A-Z0-9 /]+-----[\s\S]*"
)


def _structured_pem_mask(value: str) -> Optional[str]:
    """For a PEM block return ``BEGIN\\n<body first4****last4>\\nEND`` — the
    BEGIN/END marker lines (the key TYPE, not the secret) are kept and only the
    body is masked. ``None`` when ``value`` isn't a PEM block. This is the
    canonical multi-line key form used EVERYWHERE a key appears in a snippet, so
    a private key is never collapsed to a single flat ``b3Bl****BQYH`` token."""
    parts = _pem_parts(value)
    if not parts:
        return None
    begin, body, end = parts
    body_masked = (body[:4] + "****" + body[-4:]) if len(body) >= 8 else "********"
    return f"{begin}\n{body_masked}\n{end}"


def _mask_pem_in_snippet(snippet: str, value: str) -> Optional[str]:
    """Replace the PEM block in ``snippet`` (a full block, or one truncated by a
    narrow window) with the structured masked form. ``None`` when ``value``
    isn't PEM, so callers fall through to normal masking."""
    structured = _structured_pem_mask(value)
    if structured is None:
        return None
    if value in snippet:
        return snippet.replace(value, structured)
    # Window cut off part of the key — mask any PEM-shaped run so no raw body
    # bytes survive, dropping in the (complete) structured form.
    return _PEM_BLOCK_RE.sub(lambda _m: structured, snippet)


def _redact_in_snippet(snippet: str, raw_value: str, masked_value: str | None = None) -> str:
    """Replace every occurrence of `raw_value` in `snippet` with its
    masked equivalent.  This is the at-write-time scrub that makes our
    persisted `code_snippet` (and FindingEvidence rows) safe to surface
    in the UI's Code tab — the raw secret value never ends up at rest.

    Industry-aligned (GitGuardian, Wiz, Orca, TruffleHog Enterprise all
    redact-at-storage by default).  Idempotent: a snippet with no
    occurrences of `raw_value` is returned unchanged, and re-running on
    an already-masked snippet is a no-op (the masked form contains
    `****` which is not a substring of any real secret).

    Skips empty / very short raw values to avoid corrupting common
    short tokens that happen to appear in code (e.g. "key").  An
    8-char floor matches the mask threshold and is the same heuristic
    GitGuardian uses for redaction.

    Also tries the BASE64-ENCODED form of the raw value when the raw
    looks like binary / certificate content — covers the regex_base64
    detection path where the snippet has the encoded form but the raw
    we store has been decoded for live-validation.
    """
    if not snippet or not raw_value or len(raw_value) < 4:
        return snippet or ""
    # PEM private key: keep the BEGIN/END markers and mask only the body — the
    # canonical multi-line key form — never collapse the key to a flat token.
    # Same shared helper the engine snippet uses, so storage and engine agree.
    _pem_masked = _mask_pem_in_snippet(snippet, raw_value)
    if _pem_masked is not None:
        return _pem_masked
    replacement = masked_value or _mask_secret(raw_value)
    result = snippet.replace(raw_value, replacement)
    # Second pass: try the base64-encoded form of the raw value.  Many
    # secret types (certs, PEM blocks, GCP service-account JSON, signed
    # tokens) appear in source as base64 but are decoded by the
    # validator before storage.  Without this pass, the source-form
    # would survive in the snippet.
    try:
        import base64 as _b64
        # standard base64
        encoded = _b64.b64encode(raw_value.encode("utf-8", errors="replace")).decode("ascii")
        if len(encoded) >= 8 and encoded in result:
            result = result.replace(encoded, replacement)
        # url-safe base64 (GitHub app tokens, OAuth state, etc.)
        encoded_url = _b64.urlsafe_b64encode(raw_value.encode("utf-8", errors="replace")).decode("ascii").rstrip("=")
        if encoded_url and encoded_url != encoded and len(encoded_url) >= 8 and encoded_url in result:
            result = result.replace(encoded_url, replacement)
    except Exception:
        pass  # Encoding fallback is best-effort; never block the persist.
    # Collapse guessable residue when the rule matched only a prefix of a longer
    # value (same fix as _mask_snippet): 'admin' inside 'admin123' masks the whole
    # token, not '********123'. (_FULLMASK_RESIDUE_RE is module-level, defined
    # below; resolved at call time.)
    return _FULLMASK_RESIDUE_RE.sub("********", result)


# ── Residual shape-based scrub (G1 — detection-bounded co-located leak) ──
# `redact_with_scanner` only redacts secrets the ruleset RE-DETECTS in the
# snippet. A secret the rules MISS (a false negative — e.g. a Slack token
# under a non-canonical var name) that sits inside another finding's
# snippet window therefore survives to rest UNMASKED. This is the final
# line of defense: a curated set of UNAMBIGUOUS provider token shapes whose
# mere presence is proof of a secret regardless of surrounding context, so
# masking any occurrence is safe with negligible FP on real source.
#
# Deliberately NOT blanket high-entropy masking: pure-hex (git SHAs, content
# hashes), UUIDs, and base64 asset blobs are legitimately shown in snippets,
# and masking them would gut the Code tab. We mask only well-known token
# formats — the same prefixes the vendor rules already encode, applied here
# context-free so a context-GATED rule's miss can't leak the value at rest.
_RESIDUAL_SECRET_SHAPES = [
    r"xox[baprs]-[A-Za-z0-9-]{10,}",                       # Slack bot/user/app/legacy
    r"xapp-[0-9]+-[A-Za-z0-9-]{16,}",                      # Slack app-level token
    r"https://hooks\.slack\.com/services/T[A-Za-z0-9_/]{20,}",  # Slack webhook
    r"AKIA[0-9A-Z]{16}", r"ASIA[0-9A-Z]{16}",              # AWS access key id
    r"gh[pousr]_[A-Za-z0-9]{36,}",                          # GitHub PAT/OAuth/app/refresh
    r"github_pat_[A-Za-z0-9_]{60,}",                        # GitHub fine-grained PAT
    r"glpat-[A-Za-z0-9_-]{20,}",                            # GitLab PAT
    r"sk-[A-Za-z0-9]{20,}",                                 # OpenAI-style
    r"(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,}",        # Stripe
    r"AIza[0-9A-Za-z_-]{35}",                               # Google API key
    r"ya29\.[0-9A-Za-z_-]{20,}",                            # Google OAuth access token
    r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",         # SendGrid
    r"dop_v1_[a-f0-9]{64}",                                 # DigitalOcean
    r"shp(?:at|ss|pa|ca)_[a-fA-F0-9]{32}",                 # Shopify
    r"npm_[A-Za-z0-9]{36}",                                 # npm automation token
    r"glc_[A-Za-z0-9+/=]{20,}",                             # Grafana Cloud
    r"dckr_pat_[A-Za-z0-9_-]{20,}",                         # Docker Hub PAT
]
_RESIDUAL_RE = re.compile("|".join(f"(?:{p})" for p in _RESIDUAL_SECRET_SHAPES))

# Context-anchored residual scrub (2026-06-13). An AWS secret access key has NO
# fixed prefix (bare 40-char base64), so it can't be a standalone shape above
# without over-masking every hash/token. But when a 40-char base64 value is the
# RHS of a credential-labelled key (`'secret' => "..."`, `aws_secret_access_key:
# "..."`, `client_secret = "..."`), masking it is unambiguously safe — the
# developer labelled it a secret. Closes the G1 co-located-undetected-secret
# leak for the AWS SDK credential-array idiom (a real finding: the secret half
# of a credential pair rendered RAW in the Code tab because no rule detected it).
# Masks ONLY the value group; idempotent (a masked `abcd****wxyz` is <40 chars
# and contains `*`, so it never re-matches).
# Quotes are OPTIONAL on BOTH sides so the UNQUOTED form also matches — the AWS
# shared-credentials/INI idiom `aws_secret_access_key = <40 b64>` (no quotes) as
# well as the quoted `'secret' => "<40>"`. Value is {40,} so a longer base64
# token is fully captured (not a 40-char prefix). re.IGNORECASE.
_CTX_SECRET_VALUE_RE = re.compile(
    r"((?:aws_secret_access_key|secret_?access_?key|client_secret|secret)"
    r"['\"]?\s*(?:=>|[:=])\s*['\"]?)"
    r"([A-Za-z0-9/+]{40,})"
    r"(['\"]?)",
    re.IGNORECASE,
)
# PEM private keys — TWO passes. A code-context window is only ~30 lines, so a
# multi-line PEM key is frequently TRUNCATED: the snippet holds the BEGIN line
# plus partial base64 body but the `-----END-----` marker is cut off. A single
# BEGIN…END regex misses those, leaking raw key material at rest (found in
# validation: 414/453 stored PEM leaks were truncated). So:
#   1. _PEM_FULL_RE  — complete BEGIN…END blocks (incl. encrypted keys w/ headers).
#   2. _PEM_TRUNC_RE — any remaining BEGIN with no END → mask through end-of-text.
# Replacement is MARKER-FREE so a re-scan can't re-match it (idempotent): unlike
# the old replacement, "[PRIVATE KEY REDACTED]" contains no `-----BEGIN-----`.
_PEM_FULL_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
)
# A BEGIN with NO matching END before end-of-text (the END line was cut off by a
# narrow window). The negative lookahead ensures a COMPLETE block — including one
# already rewritten to the structured masked form, which still carries its END
# marker — is left to _PEM_FULL_RE and never clobbered here.
_PEM_TRUNC_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
    r"(?:(?!-----END [A-Z0-9 ]*PRIVATE KEY-----)[\s\S])*\Z",
)
_PEM_REDACTED = "[PRIVATE KEY REDACTED]"


def _scrub_residual_secrets(snippet: str) -> str:
    """Mask unambiguous provider-token shapes the rule re-scan may have
    missed (false negatives) so no raw secret survives in a stored snippet.
    Idempotent: an already-masked value (``abcd****wxyz``) contains ``****``
    which no shape matches, and re-deriving the structured form from an
    already-masked key block yields the same form (``b3Bl****BQYH`` ->
    ``b3Bl****BQYH``), so re-running is a no-op."""
    if not snippet:
        return snippet or ""
    # Complete BEGIN…END key blocks: keep the marker lines (the key TYPE is not
    # secret) and mask only the body — the structured form, matching the engine
    # + storage snippet masking. Body is always masked, so no raw bytes survive.
    out = _PEM_FULL_RE.sub(lambda m: _structured_pem_mask(m.group(0)) or _PEM_REDACTED, snippet)
    # Truncated key (BEGIN but the window cut off END): no END marker to anchor a
    # structured form, so fully redact — never leave raw body bytes at rest.
    out = _PEM_TRUNC_RE.sub(_PEM_REDACTED, out)
    out = _RESIDUAL_RE.sub(lambda m: _mask_secret(m.group(0)), out)
    # Context-anchored: mask the VALUE of a credential-labelled assignment even
    # when no rule detected it (the AWS-secret-in-SDK-array leak). group(2) is
    # the 40-char value; keep the key+operator+quotes (group 1, 3) intact.
    out = _CTX_SECRET_VALUE_RE.sub(
        lambda m: m.group(1) + _mask_secret(m.group(2)) + m.group(3), out)
    return out


def redact_with_scanner(snippet: str, scanner) -> str:
    """Belt-and-suspenders: run the provided scanner across `snippet`
    and redact every secret it finds.  Used at write time as a final
    sweep after the call site's targeted `_redact_in_snippet` pass,
    so detections whose original matched substring no longer matches
    the post-processed `_raw_value_for_verification` (e.g. regex_base64
    paths that decode before store) are still scrubbed.

    Same approach `redact_existing_snippets` (backfill) uses — keeping
    them aligned guarantees that the worst-case snippet a fresh scan
    can produce is at parity with the worst-case after-backfill state.

    Returns the snippet unchanged if the scanner finds nothing, so
    callers can pipe it through unconditionally without paying for
    extra DB writes.
    """
    if not snippet or scanner is None:
        return snippet or ""
    try:
        hits = scanner.scan_file("<snippet>", snippet)
    except Exception:
        return snippet
    out = snippet
    for hit in hits or []:
        rd = (hit.raw_data or {}) if hasattr(hit, "raw_data") else {}
        raw = rd.get("_raw_value_for_verification") or ""
        masked = rd.get("masked_value") or ""
        if raw:
            out = _redact_in_snippet(out, raw, masked)
    # Final shape-based scrub (G1): mask unambiguous provider tokens the
    # rule re-scan missed (false negatives) so a co-located undetected
    # secret can't survive in a stored snippet. No-op when none present.
    out = _scrub_residual_secrets(out)
    return out


def scrub_secrets_in_obj(obj):
    """Recursively mask unambiguous secret shapes in any str / list / dict.

    For AI-generated FREE TEXT that may echo a detected secret back into prose
    we persist and serve via API/UI — triage reasoning + TP/FP reasons, and
    remediation summaries / root-cause / patch diffs. The model is given the
    value (it needs it to triage), so it quotes things like "Real AWS key
    (AKIA…) with sufficient entropy" or emits a patch whose `-` line carries
    the raw secret. This applies the same at-rest guarantee as code_snippet
    (G1b). No-op on any string without a provider shape, so non-secret prose
    is untouched; non-str/list/dict values pass through unchanged.
    """
    if isinstance(obj, str):
        return _scrub_residual_secrets(obj)
    if isinstance(obj, list):
        return [scrub_secrets_in_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: scrub_secrets_in_obj(v) for k, v in obj.items()}
    return obj


def redact_snippet_for_storage(
    snippet: str,
    raw: str,
    masked: str,
    paired_raw: str = "",
    paired_masked: str = "",
    *,
    scanner,
) -> str:
    """Single source of truth for masking ONE snippet before it is persisted.

    The store-time redaction sequence used to be hand-copied across the
    git-scan main loop and the source-adapter loop. That duplication is
    exactly what let the G1 leak exist on one path and not the other — a
    fix applied to one copy didn't reach the other. Centralising the
    sequence here makes every store path mask identically by construction.

    Sequence (order is load-bearing):
      1. Targeted — mask the finding's own raw value, then any paired
         credential (e.g. an AWS access-key + secret combo).
      2. Full-scanner pass (ALWAYS, 2026-06-13) — re-scan the snippet and
         mask EVERY secret the scanner finds in it, not just the finding's
         own value. This used to be conditional (cheap residual-only scrub
         when the raw value was already present), which leaked a co-located
         *detected* secret in a non-prefixed form (unquoted
         `aws_secret_access_key = <40>` beside an AKIA finding). Idempotent.

    Idempotent and None-safe; returns the (possibly unchanged) snippet.
    """
    if not snippet:
        return snippet or ""
    if raw:
        snippet = _redact_in_snippet(snippet, raw, masked)
    if paired_raw:
        snippet = _redact_in_snippet(snippet, paired_raw, paired_masked)
    # SECURITY (2026-06-13): ALWAYS run the full-scanner pass — never the cheap
    # residual-only path. The old conditional ran _scrub_residual_secrets when
    # the finding's own raw value was already in the snippet, which left a
    # CO-LOCATED *detected* secret raw when it wasn't prefix-shaped — e.g. the
    # unquoted `aws_secret_access_key = <40>` beside an AKIA finding in an AWS
    # credentials file (ENV-002 detects it, but the cheap path never masked it).
    # redact_with_scanner masks every secret the scanner finds in the window and
    # is idempotent (masked values can't re-match), so this only ever masks MORE.
    snippet = redact_with_scanner(snippet, scanner)
    return snippet


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:32]


_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _finding_priority(f) -> tuple:
    """Priority key for overlap dedup — higher = preferred.

    Tiebreak chain:
      1. severity rank (critical > high > medium > low > info)
      2. confidence score
      3. detection_method preference (regex vendor-specific beats generic
         entropy on a tie — vendor patterns encode prior knowledge that
         the entropy heuristic can't)
      4. private-key specificity — the generic PEM key rule (GEN-007,
         secret_type ``generic_private_key``) loses to a specific key rule
         (CRYPTO-001..005: rsa/ec/pgp/ssh/pkcs8) when both fire on one key
         block, so the FE shows one correctly-typed key finding, not a generic
         duplicate. DELIBERATELY scoped to the private-key catch-all: a blanket
         "generic always loses to specific" would shift dedup outcomes across
         the whole rule set (e.g. GEN-003 vs HELM-001 on YAML) with unmeasured
         precision/label effects. Ranks ABOVE rule_id length — GEN-007's id is
         the SHORTER one, so the length tiebreak alone would keep the generic.
      5. shorter rule_id (stable, deterministic last resort)
    """
    rd = f.raw_data or {}
    method = rd.get("detection_method") or ""
    method_rank = 1 if method == "regex" else 0
    is_specific = 0 if (rd.get("secret_type") or "") == "generic_private_key" else 1
    return (
        _SEVERITY_RANK.get((f.severity or "").lower(), 0),
        f.confidence or 0,
        method_rank,
        is_specific,
        -len(f.rule_id or ""),
    )


def _dedup_overlapping_findings(findings: list) -> list:
    """Drop lower-priority findings that overlap higher-priority ones in
    the same source.  Two complementary overlap definitions are applied:

      1. **Same-line, same file** — two findings share ``(file_path,
         line_start)``.  Catches cases where multiple rules fire on the
         same line capturing different non-overlapping substrings (e.g.
         ``GH-005`` and ``CRYPTO-001`` both matching a
         ``-----BEGIN PRIVATE KEY-----`` line — neither's match string is
         a substring of the other but they're clearly the same secret).

      2. **Value containment, same file** — one finding's matched secret
         value is a substring of (or equal to) another's.  Catches the
         common case where a vendor-specific regex (Atlassian / GitHub /
         AWS / Stripe) captures a shorter slice while a generic entropy
         detector captures a longer slice covering the same secret.

    Without either pass, the FE renders two or three "different" findings
    that all point at the same credential — wasting triage attention and
    inflating dashboard counts.

    Industry pattern: GitGuardian / TruffleHog Enterprise both ship
    "highest-specificity wins" deduplication.  Implemented here at the
    engine level so every caller (``scan_file``'s callers in source
    adapters, diff scan, git history scan, repo directory scan) gets
    consistent behavior — no per-caller reimplementation.

    Tradeoff (inherited from the same-line check): different credentials
    on the exact same line are collapsed.  Rare in practice — if a user
    packs ``user=X;pass=Y;key=Z`` on a single line they'll see one
    finding rather than three.  Same simplification the legacy
    ``scan_directory`` loop accepted.

    Defensive ordering: we sort by priority *desc* and treat the first
    survivor as the truth.  Worst case O(n²) in number of findings per
    file — bounded by rule count, fine in practice.
    """
    if len(findings) <= 1:
        return findings

    # Group by file_path — overlapping is only meaningful within the
    # same source.  Two findings in different files / different Notion
    # pages / different Confluence spaces are independent by definition.
    by_file: dict = {}
    for f in findings:
        by_file.setdefault(f.file_path, []).append(f)

    kept: list = []
    for file_findings in by_file.values():
        # Sort highest-priority first so survivors are decided greedily.
        file_findings.sort(key=_finding_priority, reverse=True)
        survivors: list = []
        for f in file_findings:
            # ── Check 1: same-line dedup ────────────────────────────
            # Drop if any already-kept survivor sits at the exact same
            # (file_path, line_start).  Catches multi-rule firings on
            # one line where the captured substrings don't overlap.
            f_pos = (f.file_path, f.line_start)
            if any((s.file_path, s.line_start) == f_pos for s in survivors):
                continue

            # ── Check 2: value-containment dedup ────────────────────
            # Drop if this finding's matched value is contained in (or
            # contains) an already-kept survivor's value.  Catches
            # vendor-regex + entropy double-detection on the same secret
            # (different line_start due to detector-internal accounting).
            f_value = (f.raw_data or {}).get("_raw_value_for_verification") or ""
            if not f_value or len(f_value) < 4:
                # Without a raw value we can only check 1, which already
                # passed.  Keep the finding rather than silently lose it.
                survivors.append(f)
                continue
            overlapped = False
            for s in survivors:
                sv = (s.raw_data or {}).get("_raw_value_for_verification") or ""
                if not sv or len(sv) < 4:
                    continue
                if f_value in sv or sv in f_value:
                    overlapped = True
                    break
            if not overlapped:
                survivors.append(f)
        kept.extend(survivors)
    return kept


# Absorb alphanumerics directly adjacent to a FULL mask (>=6 stars). When a rule
# matches only PART of a credential value (the weak keyword "admin" inside
# 'admin123'), the plain replace leaves a guessable tail ('********123'); this
# collapses it back to '********'. The high-entropy PARTIAL mask uses exactly
# 4 stars, so AIza****kkGM is never touched.
_FULLMASK_RESIDUE_RE = re.compile(r"[A-Za-z0-9._@\-]*\*{6,}[A-Za-z0-9._@\-]*")


def _mask_snippet(snippet: str, secret_value: str, line_num: int | None = None) -> str:
    """Redact the secret in a code snippet (vendor-aligned: GitGuardian/GitHub).

      * PRIVATE KEYS (multi-line PEM): keep the BEGIN/END marker lines and reveal
        the body's first-4/last-4 — preserve structure, never collapse the whole
        key to a single ``----****----`` token.
      * SINGLE-LINE secrets: mask ONLY on the finding's hit line (``line_num``),
        so a co-located NON-secret value (email/username/role) on another line
        that happens to equal the secret is left untouched. Falls back to a
        global replace when ``line_num`` is unknown (back-compat).
    """
    if not secret_value or len(secret_value) < 4:
        return snippet
    _pem_masked = _mask_pem_in_snippet(snippet, secret_value)
    if _pem_masked is not None:
        return _pem_masked
    masked = _mask_secret(secret_value)
    if line_num is None:
        # No location → legacy global replace, still collapsing any residue.
        return _FULLMASK_RESIDUE_RE.sub("********", snippet.replace(secret_value, masked))
    # Hit-line-scoped: the snippet starts at file line max(1, line_num - 5), so
    # the finding's own line sits at index ``line_num - that`` — mask only there.
    lines = snippet.split("\n")
    hit = line_num - max(1, line_num - 5)
    if 0 <= hit < len(lines):
        lines[hit] = _FULLMASK_RESIDUE_RE.sub("********", lines[hit].replace(secret_value, masked))
    return "\n".join(lines)


# ── Base64 decode helper ──────────────────────────────────────
# Attempts to decode base64 values so regex rules can match the decoded content.
# Only decodes strings that look like valid base64 (length, charset, padding).

_BASE64_RE = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

# ── Tier A: gate the Base64-decode re-match path to self-anchored rules ──
# The Phase-2.5 base64 pass decodes every base64 run and re-runs EVERY rule on
# the decoded bytes (deliberately ignoring keyword pre-filters + post_filter,
# since context can appear only after decoding). That is sound for a rule whose
# pattern carries a fixed vendor signature (``ghp_``, ``AKIA``, ``xox``,
# ``glpat``, a ``hooks.slack.com`` URL …) — the decoded bytes either contain
# that literal or they don't. It is UNsound for a bare-shape rule
# (``[A-Za-z0-9]{32}`` Segment, ``{43}`` Plausible, ``{24}`` Vercel, ``{22}``
# ConvertKit): those match arbitrary high-entropy decoded base64, producing pure
# shape-collision FPs (100-repo benchmark: ~430 FPs across *-B64, ~0 real
# secrets). This predicate emits a -B64 variant only when the base rule is
# self-anchored. Recall-safe: a base64-WRAPPED real secret is only confidently
# identifiable via its own fixed signature, which lives exactly in the anchored
# rules that still pass.
_B64_LITERAL_RUN = re.compile(r'[A-Za-z0-9_]{2,}')
_B64_ANCHOR_CACHE: dict = {}


def _pattern_is_b64_self_anchored(pattern: str) -> bool:
    """True iff ``pattern`` contains a fixed literal run (>=2 verbatim word
    chars) that must appear in every match — a vendor signature (``ghp_``,
    ``AKIA``, ``xox``, SendGrid ``SG``). Bare character-class shapes have none.
    Cached per unique pattern string."""
    cached = _B64_ANCHOR_CACHE.get(pattern)
    if cached is not None:
        return cached
    s = re.sub(r'\[[^\]]*\]', '', pattern)       # drop char-classes (alternatives, not literals)
    s = re.sub(r'\(\?P?<[^>]*>', '', s)          # drop (named) group prefixes — not literals
    s = re.sub(r'\{\d*,?\d*\}', '', s)           # drop quantifiers {n}/{n,}/{n,m} BEFORE the literal
                                                  # scan, so quantifier digits ({32}) can't masquerade
                                                  # as a 2-char anchor.
    s = re.sub(r'\\.', '', s)                     # drop escaped metachars (\b \s \d \w …)
    result = _B64_LITERAL_RUN.search(s) is not None
    _B64_ANCHOR_CACHE[pattern] = result
    return result


def _try_base64_decode(value: str) -> Optional[str]:
    """Decode a base64 string if valid. Returns decoded text or None.

    2026-04-19 generic-accuracy pass: tries both standard and URL-safe
    base64 alphabets. Some providers (GCP service account JSON,
    GitHub App bearer tokens, OAuth state blobs) use URL-safe base64
    (``-`` and ``_`` instead of ``+`` and ``/``) where the original
    decoder silently returned None. Decoding URL-safe too recovers
    the plaintext so the downstream regex rules can re-match on the
    decoded content.
    """
    try:
        stripped = value.strip()
        # Upper bound covers base64-wrapped private keys (an RSA-4096 PEM is
        # ~4.3 KB once double-encoded — a sealed-secrets key is 4332 b64 chars),
        # large certs, and service-account JSON. The old 4096 cap silently
        # dropped every base64 private key > ~3 KB — a real FN. The printability
        # check below still rejects binary/asset blobs at any size, so a higher
        # ceiling only admits large *printable* secrets worth scanning.
        if len(stripped) < 16 or len(stripped) > 32768:
            return None
        # Attempt standard base64 first
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(stripped + "=" * (-len(stripped) % 4))
                text = decoded.decode("utf-8", errors="strict")
                if all(c.isprintable() or c in '\n\r\t' for c in text):
                    return text
            except Exception:
                continue
    except Exception:
        pass
    return None


def _try_hex_decode(value: str) -> Optional[str]:
    """Decode a hex-encoded string if it looks like one and results in
    printable UTF-8 text. Used in the rescan phase alongside base64 so
    provider tokens hex-encoded into env vars still match rule regexes.
    """
    try:
        stripped = value.strip()
        if len(stripped) < 20 or len(stripped) > 4096:
            return None
        if not all(c in "0123456789abcdefABCDEF" for c in stripped):
            return None
        if len(stripped) % 2 != 0:
            return None
        decoded = bytes.fromhex(stripped)
        text = decoded.decode("utf-8", errors="strict")
        if all(c.isprintable() or c in '\n\r\t' for c in text):
            return text
    except Exception:
        pass
    return None


# ── Config key assignment patterns ────────────────────────────
# Detects secrets assigned to known sensitive config keys like
# DB_PASSWORD=value, API_KEY=value, SECRET_KEY=value, etc.

_CONFIG_KEY_PATTERN = re.compile(
    r'''(?:^|[\s;,{])'''                          # start of line or delimiter
    r'''(?:'''
    r'''(?:DB|DATABASE|MYSQL|POSTGRES|REDIS|MONGO|SQL)_?(?:PASSWORD|PASS|PWD)'''
    r'''|(?:API|APP|AUTH|SECRET|PRIVATE|ACCESS|MASTER|ENCRYPTION|CRYPTO)_?(?:KEY|TOKEN|SECRET)'''
    r'''|(?:AWS|GCP|AZURE|GITHUB|GITLAB|SLACK|STRIPE|TWILIO|SENDGRID|FIREBASE|HEROKU)_?(?:SECRET|TOKEN|KEY|PASSWORD)'''
    r'''|(?:JWT|SESSION|COOKIE|SIGNING|HMAC)_?(?:SECRET|KEY)'''
    r'''|(?:SMTP|EMAIL|MAIL|FTP|SSH)_?(?:PASSWORD|PASS)'''
    r'''|(?:WEBHOOK)_?(?:SECRET|TOKEN|URL)'''
    r'''|CLIENT_?SECRET'''                         # OAuth client secret (but NOT CLIENT_ID which is public)
    r'''|OAUTH_?(?:TOKEN|SECRET)'''                # OAuth tokens and secrets
    r'''|BEARER_?TOKEN'''                          # bearer tokens
    r'''|REFRESH_?TOKEN'''                         # OAuth refresh tokens
    r'''|(?:ADMIN|ROOT|SUPERUSER)_?PASS(?:WORD)?'''  # privileged passwords
    r'''|CONNECTION_STRING|DSN|DATABASE_URL|REDIS_URL|AMQP_URL|MONGODB_URI|MONGO_URI'''
    r''')'''
    r'''\s*[=:]\s*'''                              # assignment operator
    r'''["']?'''                                    # optional quote
    r'''([^\s"'#;,}{]{8,200})'''                   # captured value (8+ chars, no whitespace/quotes)
    r'''["']?''',                                   # optional closing quote
    re.IGNORECASE | re.MULTILINE
)

# Values that are clearly placeholders, not real secrets
_PLACEHOLDER_VALUES = {
    "changeme", "change_me", "your_password", "your_secret", "your_api_key",
    "your_token", "password", "secret", "xxxxxxxx", "********",
    "placeholder", "your-secret-here", "replace_me", "todo", "fixme",
    "example", "test", "dummy", "fake", "sample", "default",
    "none", "null", "undefined", "empty", "notset", "not_set",
}


def _should_scan_file(filename: str, rel_path: str, extensions: set | None = None) -> bool:
    basename = os.path.basename(rel_path)
    if basename in SPECIAL_FILENAMES:
        return True
    # Check for .env.* patterns
    if basename.startswith(".env"):
        return True
    ext = os.path.splitext(filename)[1].lower()
    scan_exts = extensions or SCAN_EXTENSIONS
    if ext in scan_exts:
        return True
    # Scan extensionless files — often credentials, configs, or key files
    # (e.g., "keys", "credentials", "token", "secret", "id_rsa")
    if not ext:
        return True
    return False


def _content_promotes_scan(full_path: str) -> bool:
    """B1 recall net: should an extension-rejected file be scanned anyway?

    Returns ``True`` iff ``full_path`` is a non-binary, in-size-bound text file
    whose CONTENT matches one of the high-signal markers in
    ``CONTENT_PROMOTE_RE`` (PEM/SSH/PGP private-key headers + canonical provider
    token prefixes). This is the format-driven complement to the name-based
    ``_should_scan_file`` allowlist: it closes the benchmark's confirmed
    extension-blind false negatives (a real key sitting in a ``.private`` /
    ``.priv`` / ``.txt`` / ``.log`` / ``.cpp`` file) GENERICALLY, with no
    repo-specific logic.

    Promotion is strictly additive — it can only cause MORE files to be
    scanned, never fewer — so it carries zero recall risk by construction. Cost
    is one bounded read + one linear regex over each *already-rejected* file
    (files that pass ``_should_scan_file`` never reach here). Any I/O error
    fails closed to ``False`` so a transient read problem can never abort the
    walk; the file is simply treated as not-promoted.
    """
    try:
        size = os.path.getsize(full_path)
        if size == 0 or size > MAX_FILE_SIZE_BYTES:
            return False
        if os.path.islink(full_path) and not os.path.exists(os.path.realpath(full_path)):
            return False
        with open(full_path, "rb") as bf:
            data = bf.read(MAX_FILE_SIZE_BYTES)
    except (OSError, ValueError):
        return False
    # Null byte in the screen window ⇒ binary (DER key, image, archive); a
    # PEM/text token can't live there, so don't pay for the marker search.
    if b"\x00" in data[:PROMOTE_BINARY_SCREEN_BYTES]:
        return False
    return CONTENT_PROMOTE_RE.search(data) is not None


def scan_diff(
    repo_path: str,
    base_sha: str,
    head_sha: str,
    scanner: "SecretScanner" = None,
    file_cache=None,
) -> list[ParsedFinding]:
    """
    Incremental scan — only scan files changed between base_sha and head_sha.
    Used by webhook-triggered scans for fast push/PR scanning.

    ``file_cache`` (optional, ``FileScanCacheView``): consulted per
    changed file. Most diff files are genuinely new content, so cache
    hits are rare here — but they DO occur when a file is modified
    then reverted within the diff window, or when the same file's
    content_sha is shared across branches. Cheap to check; never
    hurts.
    """
    from services.secret_scan.git_history import get_diff_files

    if scanner is None:
        scanner = SecretScanner()

    all_findings: list[ParsedFinding] = []
    seen_hashes: set[str] = set()

    diff_files = get_diff_files(repo_path, base_sha, head_sha)

    for file_path, content in diff_files:
        if not _should_scan_file(os.path.basename(file_path), file_path):
            # B1 recall net: an extension-rejected diff file is still scanned
            # if its added content carries a high-signal key/token marker.
            if not (content and CONTENT_PROMOTE_RE_STR.search(content)):
                continue

        # Cache lookup — same shape as scan_directory above. Hits
        # avoid re-running 883 regexes; misses populate the buffer
        # for the worker's flush step.
        content_sha = None
        cached_findings = None
        if file_cache is not None:
            from services.secret_scan.file_cache import compute_content_sha
            content_sha = compute_content_sha(content)
            cached_findings = file_cache.lookup(file_path, content_sha)

        if cached_findings is not None:
            findings = cached_findings
        else:
            findings = scanner.scan_file(file_path, content, repo_root=repo_path)
            if file_cache is not None and content_sha is not None:
                file_cache.record_miss(file_path, content_sha, findings)

        file_ctx = _classify_file_context(file_path)

        for f in findings:
            f.raw_data["file_context"] = file_ctx
            sec_hash = f.raw_data.get("secret_hash", "")
            dedup_key = f"{sec_hash}:{file_path}"
            if dedup_key in seen_hashes:
                continue
            seen_hashes.add(dedup_key)

            f.raw_data["incremental_scan"] = True
            f.raw_data["base_sha"] = base_sha
            f.raw_data["head_sha"] = head_sha
            all_findings.append(f)

    return all_findings


def scan_git_history(
    repo_path: str,
    scanner: "SecretScanner" = None,
    max_commits: int = 5000,
    progress_callback: "Optional[Callable[[int, int, int], None]]" = None,
    progress_every_n_commits: int = 250,
    progress_min_interval_s: float = 5.0,
) -> list[ParsedFinding]:
    """
    Scan full git history for secrets introduced in past commits.
    Returns findings tagged with commit SHA, author, and date.
    Deduplicates by secret_hash + file_path across all commits.

    Optional ``progress_callback(commits_done, max_commits, findings_so_far)``
    is invoked every ``progress_every_n_commits`` commits (default 250)
    OR every ``progress_min_interval_s`` seconds (default 5s) of active
    walking, whichever comes first. The time trigger matters on huge
    repos: a count-only cadence of 250 can be >11 min apart (aws-cdk),
    which let the worker's liveness heartbeat (stamped from this very
    callback) go stale long enough for the stale-scan watchdog to
    FALSE-REAP a perfectly healthy scan. The time trigger still only
    fires *between* processed commits, so it stays a true progress
    signal — a genuinely wedged walk stops firing and is still reaped.
    Backward-compatible: None callback means identical behaviour.
    Callback errors are swallowed so a publish hiccup never poisons the
    scan.

    Track-A 2026-05-23 — added after a live monitor of pulumi/pulumi
    captured a 7m+ silent period at [4/8] 40% with the worker pegged
    at 100% CPU and bounded ~2.6 GB memory; the streaming refactor
    (fec5591) kept the scan alive but no progress events fired inside
    this loop.  The callback hook sweeps the UI from 40 → 55 as the
    commit walk advances.
    """
    from services.secret_scan.git_history import stream_git_history, count_commits

    if scanner is None:
        scanner = SecretScanner()

    all_findings: list[ParsedFinding] = []
    seen_hashes: set[str] = set()  # Dedup: same secret in same file across commits
    commit_count = 0
    import time as _t_hist
    _last_cb_ts = _t_hist.monotonic()  # drives the time-based progress trigger

    for commit in stream_git_history(repo_path, max_commits=max_commits):
        commit_count += 1

        for diff in commit.diffs:
            if not diff.added_content or not diff.file_path:
                continue

            # Check if file type is scannable. B1 recall net: a non-scannable
            # extension is still scanned when the added content carries a
            # high-signal private-key / provider-token marker (format-driven).
            if not _should_scan_file(os.path.basename(diff.file_path), diff.file_path):
                if not CONTENT_PROMOTE_RE_STR.search(diff.added_content):
                    continue

            # Scan the added lines
            findings = scanner.scan_file(diff.file_path, diff.added_content, repo_root=repo_path)
            file_ctx = _classify_file_context(diff.file_path)

            for f in findings:
                # Map the finding's line — which scan_file numbered relative to
                # the concatenated added-content blob — back to the REAL file
                # line via the diff's @@ offsets. Without this, history findings
                # are numbered 1..N within the added block, so the UI highlights
                # the wrong line (typically a low number → an import header).
                _idx = (f.line_start or 1) - 1
                if 0 <= _idx < len(diff.added_line_nums):
                    _span = (f.line_end - f.line_start) if (f.line_end and f.line_start and f.line_end >= f.line_start) else 0
                    f.line_start = diff.added_line_nums[_idx]
                    f.line_end = (f.line_start + _span) if _span else f.line_start
                f.raw_data["file_context"] = file_ctx
                # Dedup by secret_hash + file_path
                sec_hash = f.raw_data.get("secret_hash", "")
                dedup_key = f"{sec_hash}:{diff.file_path}"
                if dedup_key in seen_hashes:
                    continue
                seen_hashes.add(dedup_key)

                # Tag with commit metadata
                f.raw_data["commit_sha"] = commit.sha
                f.raw_data["commit_author"] = commit.author
                f.raw_data["commit_email"] = commit.email
                f.raw_data["commit_date"] = commit.date
                f.raw_data["commit_message"] = commit.message[:100]
                f.raw_data["found_in_history"] = True

                all_findings.append(f)

        # ── Mid-phase progress hook ─────────────────────────────────
        # Fires every N commits OR every progress_min_interval_s seconds
        # of active walking, whichever comes first. The time trigger is
        # what keeps the liveness heartbeat (stamped from this callback)
        # fresh on huge repos where 250 commits can be >11 min apart —
        # otherwise the stale-scan watchdog false-reaps a healthy walk.
        # It fires only here, between processed commits, so it stays a
        # real progress signal (a wedged walk stops firing → still
        # reaped). Wrapped in try/except so a publish hiccup never
        # poisons the scan path itself.
        if progress_callback is not None and progress_every_n_commits > 0:
            _now_cb = _t_hist.monotonic()
            if (
                commit_count % progress_every_n_commits == 0
                or (_now_cb - _last_cb_ts) >= progress_min_interval_s
            ):
                _last_cb_ts = _now_cb
                try:
                    progress_callback(commit_count, max_commits, len(all_findings))
                except Exception:
                    # Intentionally silent — engine.py has no logger import
                    # at this scope and we don't want to add coupling just
                    # for an opportunistic progress signal.
                    pass

    # ── Re-locate findings to their CURRENT HEAD line (2026-06-13) ───────
    # `added_line_nums` (above) maps each finding to the line in the COMMIT
    # THAT INTRODUCED it. When the file is edited in later commits the secret
    # moves, so that line goes STALE versus the current HEAD checkout — e.g. an
    # AWS key introduced at L20 that HEAD now holds at L16, leaving the UI
    # highlighting the wrong line (`.travis.yml`/`patterns.yml` reports). This
    # is the layer ABOVE the earlier 1..N→commit-line fix, not a regression of
    # it. For every secret STILL PRESENT in HEAD, adopt the HEAD scan's line +
    # snippet (what the user actually sees); secrets scrubbed from HEAD keep
    # their historical line, tagged `history_only` so the UI can label them.
    # `git show HEAD:<path>` works for bare and full clones alike.
    def _head_blob(fp: str):
        try:
            import subprocess as _sp
            _r = _sp.run(["git", "-C", repo_path, "show", f"HEAD:{fp}"],
                         capture_output=True, timeout=15)
            if _r.returncode == 0:
                return _r.stdout.decode("utf-8", errors="replace")
        except Exception:
            pass
        return None

    # Path-agnostic HEAD locator (2026-06-14). The direct `git show HEAD:<path>`
    # above fails when the file was RENAMED/MOVED between the introducing commit
    # and HEAD — `added_line_nums` then leaves the finding stranded at the stale
    # introducing-commit path+line and it gets wrongly tagged history_only even
    # though the secret is still live (proven: a value moved tests/a.py:3 →
    # src/a.py:8 reported as history_only at the stale line). `git grep` the raw
    # value across the WHOLE HEAD tree to find its CURRENT location. Cached per
    # value so a repeated secret costs one grep. Returns list[(path, line)].
    _value_loc_cache: dict = {}

    def _head_value_hits(raw: str) -> list:
        if raw in _value_loc_cache:
            return _value_loc_cache[raw]
        hits: list = []
        try:
            import subprocess as _sp
            # -F fixed-string, -I skip binaries, -e guards values starting with '-'.
            _r = _sp.run(["git", "-C", repo_path, "grep", "-n", "-F", "-I", "-e", raw, "HEAD"],
                         capture_output=True, timeout=20)
            if _r.returncode == 0:
                for _ln in _r.stdout.decode("utf-8", errors="replace").splitlines():
                    if not _ln.startswith("HEAD:"):
                        continue
                    _parts = _ln[5:].split(":", 2)  # path : line : content
                    if len(_parts) >= 2 and _parts[1].isdigit():
                        hits.append((_parts[0], int(_parts[1])))
        except Exception:
            pass
        _value_loc_cache[raw] = hits
        return hits

    def _head_value_location(raw: str, prefer_basename: str = ""):
        hits = _head_value_hits(raw)
        if not hits:
            return None
        if prefer_basename:  # disambiguate a value present in multiple files
            for _p, _l in hits:
                if _p.rsplit("/", 1)[-1] == prefer_basename:
                    return (_p, _l)
        return hits[0]

    _head_finds: dict = {}
    _head_text: dict = {}
    for f in all_findings:
        fp = f.file_path
        if fp not in _head_finds:
            _content = _head_blob(fp)
            _head_text[fp] = _content
            _m: dict = {}
            if _content is not None and scanner is not None:
                try:
                    for _hf in (scanner.scan_file(fp, _content, repo_root=repo_path) or []):
                        _h = (_hf.raw_data or {}).get("secret_hash")
                        if _h and _h not in _m:
                            _m[_h] = _hf
                except Exception:
                    pass
            _head_finds[fp] = _m
        _sh = (f.raw_data or {}).get("secret_hash")
        _match = _head_finds[fp].get(_sh) if _sh else None
        if _match is not None:
            # Secret still in HEAD → use the current-file line + snippet.
            f.line_start = _match.line_start
            f.line_end = _match.line_end
            if _match.code_snippet:
                f.code_snippet = _match.code_snippet
            f.raw_data["line_relocated_to_head"] = True
            continue
        # Fallback: secret IS in HEAD but scan_file didn't re-detect it (a
        # non-scannable file force-scanned in history). Fix the line via a
        # direct value search; keep the existing snippet.
        _raw = (f.raw_data or {}).get("_raw_value_for_verification") or ""
        _txt = _head_text.get(fp)
        if _raw and len(_raw) >= 4 and _txt and _raw in _txt:
            # Same path, value present — fix the line in place.
            _span = (f.line_end - f.line_start) if (f.line_end and f.line_start and f.line_end >= f.line_start) else 0
            f.line_start = _txt[:_txt.index(_raw)].count("\n") + 1
            f.line_end = f.line_start + _span
            f.raw_data["line_relocated_to_head"] = True
            continue
        # Path-agnostic fallback: the value was NOT found at the recorded path —
        # the file may have been renamed/moved (or recorded under a stale path).
        # Search ALL of HEAD for the value; if it's still live, relocate BOTH the
        # path and the line to its current location before conceding history_only.
        if _raw and len(_raw) >= 8:
            _hit = _head_value_location(_raw, os.path.basename(fp or ""))
            if _hit is not None:
                _new_fp, _new_line = _hit
                _span = (f.line_end - f.line_start) if (f.line_end and f.line_start and f.line_end >= f.line_start) else 0
                f.file_path = _new_fp
                f.line_start = _new_line
                f.line_end = _new_line + _span
                f.raw_data["line_relocated_to_head"] = True
                f.raw_data["head_path_resolved"] = True
                continue
        # Secret was scrubbed from HEAD — a genuine history-only finding.
        f.raw_data["history_only"] = True

    return all_findings


def _compute_rule_pack_version(
    rules: list[SecretRule],
    *,
    enable_entropy: bool,
    scan_scope: str,
) -> str:
    """Deterministic SHA-256 over the active rule pack + engine config.

    Used as the cache key dimension on ``file_scan_cache`` so any
    change to a rule (built-in OR custom), the engine version, or the
    entropy/scope toggles invalidates every previously-cached file
    result. That gives us "Snyk-style" file caching with rigorous
    correctness — a rule pack bump on Day N+1 forces every file in
    every repo to be re-scanned on Day N+2, automatically.

    Stable across runs because:
      - rules are sorted by rule_id before serialization
      - keyword/exclude-pattern lists inside each rule are sorted
      - JSON is dumped with ``sort_keys=True`` and tight separators

    Cheap: ~1 ms even at 1000 rules — done once per SecretScanner
    instance, then cached on ``self.rule_pack_version``.
    """
    sorted_rules = sorted(rules, key=lambda r: r.rule_id)
    # Only fields that AFFECT DETECTION OUTPUT. Presentation fields
    # (title, description, fix_hint) are deliberately EXCLUDED — a
    # typo fix in a rule's description shouldn't invalidate every
    # tenant's cache. The cached ParsedFinding's presentation fields
    # may go stale by ≤ one full re-scan, which is acceptable: the
    # next time the file's content_sha changes (or a real detection
    # field changes), the cache is repopulated with current copy.
    #
    # `secret_type` and `cwe` are kept because they propagate to
    # NormalizedFinding.classification and are sometimes used for
    # severity routing — changing them is functionally equivalent to
    # adding a new rule.
    payload: dict = {
        "engine_version": ENGINE_VERSION,
        "enable_entropy": enable_entropy,
        "scan_scope": scan_scope,
        "rules": [
            {
                "rule_id": r.rule_id,
                "pattern": r.pattern,
                "severity": r.severity,
                "confidence": r.confidence,
                "keywords": sorted(r.keywords or []),
                "multiline": r.multiline,
                "case_sensitive": getattr(r, "case_sensitive", False),
                "confidence_by_context": dict(
                    sorted((r.confidence_by_context or {}).items())
                ),
                "surface_targeting": (
                    sorted(r.surface_targeting) if r.surface_targeting else None
                ),
                "surface_excluded": (
                    sorted(r.surface_excluded) if r.surface_excluded else None
                ),
                "provider_override": getattr(r, "provider_override", None),
                "exclude_path_patterns": sorted(r.exclude_path_patterns or []),
                "secret_type": r.secret_type,
                "cwe": r.cwe,
            }
            for r in sorted_rules
        ],
    }
    payload_json = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(payload_json.encode("utf-8")).hexdigest()


# ── Intra-scan multiprocessing helpers (module-level for picklability) ──────
# True intra-scan parallelism needs PROCESSES, not threads: google-re2's Python
# binding does not release the GIL, so a thread pool gives no speedup (measured
# ~1x, and the regex engine alone is ~7x slower threaded). A process pool —
# each worker with its own GIL and its own compiled rule pack — measured ~2.9x.
#
# These live at module scope because ProcessPoolExecutor pickles the initializer
# and the worker BY REFERENCE. The per-process scanner is built ONCE by the
# initializer (so the 946-rule pack compiles once per process, not per file).
_MP_SCANNER = None


def _mp_pool_init(enable_entropy: bool, scan_scope: str) -> None:
    """ProcessPoolExecutor initializer — one default-rule scanner per process."""
    global _MP_SCANNER
    _MP_SCANNER = SecretScanner(enable_entropy=enable_entropy, scan_scope=scan_scope)


def _mp_scan_one(target):
    """Pool worker: read + filter + scan ONE file. Returns the file's findings
    (file-context tagged), or ``None`` when skipped. Fully defensive — any
    per-file error returns ``None`` so a single odd/unreadable file can never
    abort the whole scan. Mirrors the sequential walk's skip branches exactly
    so file counts (and therefore progress ticks) match."""
    full_path, rel_path, repo_path = target
    try:
        if os.path.islink(full_path):
            try:
                if not os.path.exists(os.path.realpath(full_path)):
                    return None
            except (OSError, ValueError, RuntimeError):
                return None
        size = os.path.getsize(full_path)
        if size > MAX_FILE_SIZE_BYTES or size == 0:
            return None
        with open(full_path, "rb") as bf:
            if b"\x00" in bf.read(8192):
                return None
        with open(full_path, "r", errors="ignore") as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return None
    try:
        findings = _MP_SCANNER.scan_file(rel_path, content, repo_root=repo_path)
        file_ctx = _classify_file_context(rel_path)
        for finding in findings:
            finding.raw_data["file_context"] = file_ctx
        return findings
    except Exception:
        return None


def _in_daemon_process() -> bool:
    """True inside a daemonic process (e.g. a Celery prefork worker), which
    cannot spawn children — so multiprocessing is unavailable and the scan
    falls back to sequential there."""
    try:
        import multiprocessing
        return bool(multiprocessing.current_process().daemon)
    except Exception:
        return False


class SecretScanner:
    def __init__(
        self,
        rules: Optional[list[SecretRule]] = None,
        enable_entropy: bool = True,
        scan_scope: str = "standard",
    ):
        from services.secret_scan.config import get_scan_extensions
        self.rules = rules or get_all_rules()
        self.enable_entropy = enable_entropy
        self.scan_scope = scan_scope
        self._extensions = get_scan_extensions(scan_scope)
        # True when the default rule pack was used (no custom rules passed in).
        # Intra-scan multiprocessing rebuilds the scanner inside each worker
        # process from the DEFAULT pack, so it only engages when this is True —
        # a custom-rule scanner safely falls back to the sequential path rather
        # than scanning with the wrong rules in a child process.
        self._rules_are_default = rules is None
        # Pre-compile rule patterns via the hybrid engine selector.
        # Each rule lands on either "re2" (ReDoS-immune fast path —
        # ~92.6% of the pack per the compatibility survey) or "regex"
        # (legacy fallback with per-match timeout — ~7.4%).  See
        # _compile_rule_pattern for the dispatch logic and the
        # VOODA_REGEX_ENGINE env override.
        self._compiled = {}
        self._engine_by_rule = {}            # rule_id -> "re2" | "regex" | "re"
        _engine_counts = {"re2": 0, "regex": 0, "re": 0}
        for rule in self.rules:
            engine, compiled = _compile_rule_pattern(
                rule.pattern,
                case_sensitive=bool(getattr(rule, "case_sensitive", False)),
                multiline=bool(rule.multiline),
            )
            self._compiled[rule.rule_id] = compiled
            self._engine_by_rule[rule.rule_id] = engine
            _engine_counts[engine] = _engine_counts.get(engine, 0) + 1

        # Log per-engine breakdown once at scanner init so ops can see
        # how the rule pack distributed.  Visible in worker startup
        # logs; useful for confirming hybrid is actually active.
        try:
            logger.info(
                "secret_scanner_compiled",
                total_rules=len(self.rules),
                engine_mode=_REGEX_ENGINE,
                re2_rules=_engine_counts.get("re2", 0),
                regex_rules=_engine_counts.get("regex", 0),
                re_rules=_engine_counts.get("re", 0),
                re2_available=_RE2_AVAILABLE,
                regex_timeout_s=_REGEX_TIMEOUT_S,
            )
        except Exception:
            # Logger init quirks in tests must never block scanner init
            pass

        # Compute a deterministic fingerprint of the rule pack +
        # engine config so the file-level cache can invalidate when
        # ANY of these change:
        #   - a rule is added/removed/edited (built-in or custom)
        #   - the engine version is bumped (see ENGINE_VERSION above)
        #   - entropy detection is toggled
        #   - the scan scope changes (also a separate cache-key
        #     dimension; included here as a belt-and-braces check)
        #
        # SHA-256 over a sorted JSON payload — stable across runs, in
        # under 1 ms even with ~1000 rules.
        self.rule_pack_version: str = _compute_rule_pack_version(
            self.rules, enable_entropy=enable_entropy, scan_scope=scan_scope
        )

    def scan_directory(
        self,
        repo_path: str,
        file_cache=None,
        progress_callback: "Optional[Callable[[int, int], None]]" = None,
        progress_every_n_files: int = 200,
        max_workers: "Optional[int]" = None,
    ) -> list[ParsedFinding]:
        """Walk ``repo_path`` and return all secret findings.

        ``file_cache`` (optional): a ``FileScanCacheView`` from
        :mod:`services.secret_scan.file_cache`. When provided, each
        file's content_sha is checked against the cache. A hit
        short-circuits the rule engine for that file (still
        contributes to the dedup pool so cross-file overlaps are
        handled identically). A miss runs the engine and buffers the
        result for later flush by the worker.

        Calling without ``file_cache`` preserves the original
        behaviour exactly — every file is scanned. This keeps the
        engine usable from contexts that don't have a DB session
        (CLI, unit tests, ad-hoc scans).

        ``progress_callback`` (optional): ``fn(files_done, findings_so_far)``
        invoked every ``progress_every_n_files`` processed files. This
        is the only intra-phase signal for what is otherwise a single
        multi-minute blocking call on a large repo. The worker uses it
        to advance the progress bar AND stamp the liveness heartbeat —
        without it a big full-scan freezes at 40% and lets the stale-
        scan watchdog false-reap a perfectly healthy scan. Exceptions
        raised by the hook are swallowed so a flaky callback can never
        abort the scan itself.

        ``max_workers`` (optional): intra-scan parallelism via a PROCESS pool
        (threads don't help — google-re2 doesn't release the GIL). Each worker
        process gets its own GIL + its own compiled rule pack, giving real
        multi-core speedup (~2.9x measured) on large repos. Engaged ONLY when
        it is both safe and worthwhile, otherwise the scan transparently runs
        the original sequential path:
          * only the cache-LESS path (``file_cache is None`` — the CLI /
            ``vooda monitor`` case) parallelises; the worker's cache path stays
            sequential (and a server already parallelises ACROSS scans);
          * not inside a daemonic process (a Celery prefork worker can't spawn
            children);
          * only the default rule pack (a custom-rule scanner can't be rebuilt
            in a child process);
          * only above ``VOODA_SCAN_PARALLEL_MIN_FILES`` files (process startup
            isn't worth it for small repos);
          * any pool/spawn failure falls back to sequential.
        Output is byte-IDENTICAL to the sequential walk (``executor.map``
        preserves file-walk order; dedup / file-context / progress run on this
        process in that order). Default workers = ``min(8, cpu_count)`` (override
        via ``VOODA_SCAN_WORKERS``); ``max_workers=1`` forces sequential.
        """
        workers = self._resolve_scan_workers(max_workers)
        if (
            file_cache is None
            and workers > 1
            and self._rules_are_default
            and not _in_daemon_process()
        ):
            parallel = self._scan_directory_parallel(
                repo_path, progress_callback, progress_every_n_files, workers
            )
            if parallel is not None:  # None ⇒ small-repo / spawn-failure fallback
                return parallel

        all_findings = []
        seen_hashes: set[str] = set()
        _processed_files = 0  # files that passed filters + were scanned

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                full_path = os.path.join(root, fname)
                rel_path = os.path.relpath(full_path, repo_path)

                if not _should_scan_file(fname, rel_path, self._extensions):
                    # B1 recall net: scan an extension-rejected file anyway if
                    # its CONTENT carries a private-key/token marker. Closes the
                    # benchmark's extension-blind FNs (.private/.priv/.txt/.log/
                    # .cpp) generically; strictly additive, so recall-safe.
                    if not _content_promotes_scan(full_path):
                        continue

                try:
                    # Skip broken/circular symlinks
                    if os.path.islink(full_path):
                        try:
                            resolved = os.path.realpath(full_path)
                            if not os.path.exists(resolved):
                                continue
                        except (OSError, ValueError, RuntimeError):
                            continue
                    size = os.path.getsize(full_path)
                    if size > MAX_FILE_SIZE_BYTES or size == 0:
                        continue
                    # Quick binary check — skip files with null bytes (compiled binaries, images)
                    with open(full_path, "rb") as bf:
                        head = bf.read(8192)
                    if b"\x00" in head:
                        continue
                    with open(full_path, "r", errors="ignore") as f:
                        content = f.read()
                except (OSError, UnicodeDecodeError):
                    continue

                # ── File cache lookup ────────────────────────────────
                # Check the (file_path, content_sha) pair against the
                # pre-warmed cache. Hit → reuse the cached findings
                # and skip the rule engine entirely for this file.
                # Miss → run the engine, then buffer the result for
                # the worker's flush step.
                #
                # The cache is rule-pack-version-aware (the worker
                # warmed it with the active SecretScanner's
                # ``rule_pack_version``), so a rule update on the
                # next scan cycle automatically invalidates this row.
                content_sha: Optional[str] = None
                cached_findings = None
                if file_cache is not None:
                    from services.secret_scan.file_cache import compute_content_sha
                    content_sha = compute_content_sha(content)
                    cached_findings = file_cache.lookup(rel_path, content_sha)

                if cached_findings is not None:
                    findings = cached_findings
                else:
                    findings = self.scan_file(rel_path, content, repo_root=repo_path)
                    if file_cache is not None and content_sha is not None:
                        file_cache.record_miss(rel_path, content_sha, findings)

                # Tag with file context.  Overlap dedup (multi-rule same-line,
                # multi-detector same-secret) is now handled centrally inside
                # ``scan_file`` via ``_dedup_overlapping_findings``, so this
                # path no longer reimplements the priority logic — every
                # caller of ``scan_file`` gets the same dedup uniformly.
                file_ctx = _classify_file_context(rel_path)
                for finding in findings:
                    finding.raw_data["file_context"] = file_ctx

                # Cross-file uniqueness: skip findings already accumulated
                # from a previous file on this walk that share the same
                # (secret_hash, file_path, line_start) triple.  Different
                # files with the same hash are still emitted (correctly).
                # Defensive — same file isn't visited twice in a single
                # os.walk, but the check is cheap insurance.
                for finding in findings:
                    sec_hash = (finding.raw_data or {}).get("secret_hash", "")
                    dedup_key = f"{sec_hash}:{finding.file_path}:{finding.line_start}"
                    if dedup_key not in seen_hashes:
                        seen_hashes.add(dedup_key)
                        all_findings.append(finding)

                # ── Mid-phase progress tick ──────────────────────────
                # Fire the optional hook every N processed files. The
                # worker turns this into a bar sweep (40→55) + a liveness
                # heartbeat stamp so a long full-scan of a large repo
                # neither freezes the UI at 40% nor goes silent long
                # enough for the stale-scan watchdog to false-reap it.
                # Wrapped so a misbehaving hook can never abort the scan.
                _processed_files += 1
                if (
                    progress_callback is not None
                    and _processed_files % progress_every_n_files == 0
                ):
                    try:
                        progress_callback(_processed_files, len(all_findings))
                    except Exception:
                        pass

        return all_findings

    def _resolve_scan_workers(self, max_workers: "Optional[int]") -> int:
        """Resolve the intra-scan process-pool size.

        Precedence: explicit ``max_workers`` arg > ``VOODA_SCAN_WORKERS`` env >
        default ``min(8, cpu_count)``. Always ≥ 1; 1 forces sequential. Capped
        at 16 so a many-core box can't spawn an unbounded number of rule-pack-
        compiling processes.
        """
        if max_workers is not None:
            try:
                return max(1, int(max_workers))
            except (TypeError, ValueError):
                return 1
        env = os.environ.get("VOODA_SCAN_WORKERS")
        if env:
            try:
                return max(1, min(16, int(env)))
            except ValueError:
                pass
        return min(8, (os.cpu_count() or 2))

    def _scan_directory_parallel(
        self,
        repo_path: str,
        progress_callback: "Optional[Callable[[int, int], None]]",
        progress_every_n_files: int,
        workers: int,
    ) -> "Optional[list[ParsedFinding]]":
        """Process-pool variant of ``scan_directory``, output-identical to the
        sequential walk. Returns the findings list, or ``None`` to signal the
        caller to fall back to sequential (too few files, or the pool could not
        be created — e.g. ``fork`` unavailable). Never raises for those cases.
        """
        from concurrent.futures import ProcessPoolExecutor
        import multiprocessing as _mp

        # Phase 1 — walk + filter (cheap, sequential) → ordered targets.
        targets: list[tuple] = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                full_path = os.path.join(root, fname)
                rel_path = os.path.relpath(full_path, repo_path)
                if not _should_scan_file(fname, rel_path, self._extensions):
                    # B1 recall net (parallel walk parity with the sequential
                    # path): promote an extension-rejected file whose content
                    # carries a key/token marker so it is dispatched to a worker.
                    if not _content_promotes_scan(full_path):
                        continue
                targets.append((full_path, rel_path, repo_path))

        # Small-repo fallback — per-process rule-pack compile + IPC isn't worth
        # it below this many files; the sequential walk is faster there.
        try:
            min_files = int(os.environ.get("VOODA_SCAN_PARALLEL_MIN_FILES", "400"))
        except ValueError:
            min_files = 400
        if len(targets) < max(1, min_files):
            return None  # → sequential

        all_findings: list[ParsedFinding] = []
        seen_hashes: set[str] = set()
        _processed_files = 0
        # Chunk so each IPC round-trip carries several files (less overhead),
        # while map() still yields results in submission (file-walk) order.
        chunksize = max(1, min(50, len(targets) // (workers * 4) or 1))

        try:
            # `fork` (Linux default) inherits the parent cheaply and avoids the
            # `spawn` re-import-of-__main__ trap when run as `python cli/main.py`.
            try:
                ctx = _mp.get_context("fork")
            except ValueError:
                ctx = _mp.get_context()  # platform default (non-fork)
            with ProcessPoolExecutor(
                max_workers=workers,
                mp_context=ctx,
                initializer=_mp_pool_init,
                initargs=(self.enable_entropy, self.scan_scope),
            ) as ex:
                for findings in ex.map(_mp_scan_one, targets, chunksize=chunksize):
                    if findings is None:
                        continue  # skipped file — not counted (matches sequential)
                    for finding in findings:
                        sec_hash = (finding.raw_data or {}).get("secret_hash", "")
                        dedup_key = f"{sec_hash}:{finding.file_path}:{finding.line_start}"
                        if dedup_key not in seen_hashes:
                            seen_hashes.add(dedup_key)
                            all_findings.append(finding)
                    _processed_files += 1
                    if (
                        progress_callback is not None
                        and _processed_files % progress_every_n_files == 0
                    ):
                        try:
                            progress_callback(_processed_files, len(all_findings))
                        except Exception:
                            pass
        except Exception as exc:
            # Pool unavailable (daemonic edge, fork failure, OOM, …) → tell the
            # caller to run sequentially. Never fail the scan for a pool problem.
            try:
                logger.warning("scan_parallel_fallback_to_sequential", error=str(exc)[:200])
            except Exception:
                pass
            return None

        return all_findings

    def scan_file(
        self,
        file_path: str,
        content: str,
        language: str = "",
        repo_root: str = "",
        content_type: str | None = None,
    ) -> list[ParsedFinding]:
        """Scan a single chunk of text and return raw ParsedFinding rows.

        `content_type` (optional) is the categorical tag from the
        non-git source scanners ("message", "page", "comment",
        "file", "env_var", "log_line"). When set, each rule resolves
        its effective base confidence via `SecretRule.confidence_for`
        — letting a single rule express different confidence for
        source code (typical scaffolding noise) vs collaboration-tool
        content (typical real disclosure). Backward compatible: code-
        scan callers don't pass content_type and every rule falls
        through to its default `confidence`.
        """
        findings: list[ParsedFinding] = []
        if not content:
            return findings

        # ── Smart-quote / typographic-character normalization ──
        # Jira, Confluence, Slack, Word, and macOS auto-correct
        # convert straight ASCII quotes into curly Unicode ones
        # (U+2018, U+2019, U+201C, U+201D). Every regex in the
        # detector library matches `['\"]` only — they would miss
        # `password = "admin"` (smart-quoted). One normalization
        # pass at the engine fixes the entire detector library at
        # once. Bug fix 2026-04-30 — discovered on real Jira
        # issue TRUF-5 ("password = "admin"" undetected).
        if any(ch in content for ch in ("\u2018", "\u2019", "\u201c", "\u201d", "\u2013", "\u2014")):
            _xlate = str.maketrans({
                "\u2018": "'", "\u2019": "'",
                "\u201c": '"', "\u201d": '"',
                "\u2013": "-", "\u2014": "-",
            })
            content = content.translate(_xlate)

        # ── R1: escaped-CRLF PEM normalization (juice-shop RSA JWT key) ──
        # A private key serialized as a single-line string literal with escaped
        # CRLF — '-----BEGIN RSA PRIVATE KEY-----\r\n…\r\n-----END…' (OWASP
        # juice-shop lib/insecurity.ts ships its RS256 JWT-signing key this way)
        # — defeats the \n-aware crypto categorization, so the key reads as a
        # generic CONFIG-ASSIGN instead of CRYPTO-001 (a recall miss surfaced by
        # the 20-repo Opus×Vooda benchmark). Normalize escaped \r\n -> \n INSIDE
        # private-key blocks only, so the existing escaped-\n path detects it.
        # The \r\n are literal backslash sequences (not byte newlines), so the
        # real-\n count is unchanged and line numbers stay stable; scoping to
        # BEGIN…PRIVATE KEY…END blocks (via _PEM_FULL_RE) means nothing else is
        # touched. Guarded so the regex only runs when both markers are present.
        if "\\r\\n" in content and "-----BEGIN " in content:
            content = _PEM_FULL_RE.sub(
                lambda _m: _m.group(0).replace("\\r\\n", "\\n"), content)

        # ── Fully-skipped files (auto-generated, never real secrets) ──
        # Lock files / freeze files etc. contain integrity hashes that
        # occasionally match generic secret patterns by accident. Skip
        # ALL detection phases (not just entropy). Expanded 2026-04-19
        # after real-world FP analysis on airflow / react / django
        # showed 59 FP hits on pnpm-lock.yaml / yarn.lock / go.sum.
        if os.path.basename(file_path) in FULLY_SKIPPED_FILES:
            return findings

        # Compute the path we'll match rule.exclude_path_patterns against.
        # Prefer repo-relative when we know the root (cleaner globs like
        # "api/docs/*.yaml" don't need to care about the checkout path),
        # fall back to the raw file_path otherwise.
        if repo_root and file_path.startswith(repo_root):
            rel_for_exclusion = os.path.relpath(file_path, repo_root)
        else:
            rel_for_exclusion = file_path

        # Globally-skipped paths (vendored deps, bundled JS, source maps).
        # Same intent as FULLY_SKIPPED_FILES above but matches glob patterns
        # instead of exact basenames — covers cases like
        # `**/site-packages/**` and `**/*bundle*.js` where the basename
        # alone is not enough to identify the path as third-party
        # structural noise. Gold-label-validated 2026-04-24 — eliminates
        # ~22 false positives across QUANTUM-* / ABLY-001 / CONFIG-ASSIGN
        # without removing any real secrets.
        for _glob in FULLY_SKIPPED_PATH_PATTERNS:
            if _fnmatch.fnmatch(rel_for_exclusion, _glob) or _fnmatch.fnmatch(file_path, _glob):
                return findings

        lines = content.split("\n")
        content_lower = content.lower()

        # Phase 1: Keyword pre-filter — find which rules apply to this file.
        # Path-exclusion is applied here so an excluded rule never reaches
        # the regex / entropy phases. Gold-label-validated 2026-04-24 —
        # HELM-001 excluded from `api/docs/*.yaml` eliminates ~105 FP/scan
        # on moby-class OpenAPI-heavy repos.
        applicable_rules = []
        for rule in self.rules:
            if rule.excluded_for_path(rel_for_exclusion):
                continue
            # Surface targeting — added 2026-05-03. Rules that opt
            # in via surface_targeting / surface_excluded are gated
            # here so they don't even reach the regex phase on
            # surfaces they weren't calibrated for. ~860 rules that
            # don't set either field pass through unchanged.
            if not rule.applies_to_surface(content_type):
                continue
            if not rule.keywords:
                applicable_rules.append(rule)
                continue
            for kw in rule.keywords:
                if kw.lower() in content_lower:
                    applicable_rules.append(rule)
                    break

        # ── Phase 3 B2: PEM-body line range (pre-computed) ──
        # Build the set of line numbers that lie inside a PEM / SSH-key
        # block BEFORE the regex phase runs. Used to suppress non-crypto
        # provider rules that occasionally match Adyen-shape / generic
        # high-entropy characters inside a cert body. Real crypto rules
        # (PEM, SSH, X.509, private-key variants) still fire on these
        # lines — they're the whole point of the block.
        _regex_pem_body_lines: set[int] = set()
        for _li, _line in enumerate(lines):
            if re.match(r"\s*-----BEGIN\s+[\w\s]+-----", _line):
                for _ei in range(_li + 1, min(_li + 200, len(lines))):
                    if re.match(r"\s*-----END\s+[\w\s]+-----", lines[_ei]):
                        # Body = interior lines only (exclude header/footer
                        # so a rule matching the BEGIN line itself still fires).
                        for _bi in range(_li + 1, _ei):
                            _regex_pem_body_lines.add(_bi + 1)  # 1-based
                        break

        # Rule ids that are ALLOWED to fire inside PEM body lines —
        # private-key / SSH / X.509 / certificate / PGP detectors. All
        # other rules are suppressed inside a body to avoid provider-
        # token rules misfiring on high-entropy cert content.
        def _is_crypto_rule(r) -> bool:
            st = (r.secret_type or "").lower()
            rid = (r.rule_id or "").lower()
            return (
                "pem" in st or "private_key" in st or "ssh" in st
                or "x509" in st or "certificate" in st or "pgp" in st
                or "gpg" in st or "keystore" in st
                or "crypto" in rid or "pem" in rid or "ssh" in rid
                or "quantum" in rid or "quantum" in st
            )

        # Phase 2: Run regex for applicable rules.
        #
        # Each rule's finditer is wrapped in a per-call timeout
        # (VOODA_REGEX_TIMEOUT_S, default 2.0s) so a single rule with
        # catastrophic backtracking on this file cannot peg the worker
        # at 100% CPU indefinitely.  On TimeoutError we log the
        # rule_id + file_path + content length, skip THAT rule for
        # THIS file, and continue with the remaining rules.  Other
        # files in the same scan are unaffected.  Long-term fix is
        # to migrate the rule pack to a non-backtracking regex
        # engine (RE2 / Hyperscan); this is the defensive layer.
        for rule in applicable_rules:
            compiled = self._compiled[rule.rule_id]
            engine = self._engine_by_rule[rule.rule_id]
            _rule_allows_pem_body = _is_crypto_rule(rule)
            try:
                # _safe_finditer dispatches by engine: re2 path has no
                # timeout (ReDoS-immune by construction); regex path
                # applies _REGEX_TIMEOUT_S as the safety net.
                _matches = _safe_finditer(compiled, engine, content)
            except TimeoutError:
                logger.warning(
                    "rule_redos_timeout",
                    rule_id=rule.rule_id,
                    secret_type=rule.secret_type,
                    file_path=file_path,
                    content_length=len(content),
                    timeout_s=_REGEX_TIMEOUT_S,
                    engine=engine,
                )
                continue
            for match in _matches:
                # Extract the captured group (group 1) or full match
                secret_value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group()

                line_num = content[:match.start()].count("\n") + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""

                # ── Phase 3 B2: skip non-crypto rules inside PEM bodies ──
                # A provider-token rule (e.g. Adyen, Stripe) firing inside a
                # cert base64 body is a misfire on high-entropy content.
                # Crypto rules (PEM / SSH / X.509) are still allowed here.
                if line_num in _regex_pem_body_lines and not _rule_allows_pem_body:
                    continue

                # ── 2-pass post-filter ──────────────────────────────
                # Lookahead-rewrite rules carry a Python-side
                # keyword-proximity check (see SecretRule.passes_post_filter).
                # No-op for rules that don't set post_filter_keywords —
                # most of the catalog.
                if not rule.passes_post_filter(content, match.start(), match.end()):
                    continue

                # Some regex rules use lookaheads / optional groups that can
                # leave the capture group as None. Guard before the string-
                # only filters below — B1 validation 2026-04-19 caught the
                # scanner crashing on detect-secrets' test corpus because
                # one rule's secret_value came back None.
                if not secret_value:
                    continue

                # Skip dot-separated lowercase identifiers — namespace/class paths, not secrets
                # e.g., "string.regexp", "rule.token", "org.apache.commons"
                if re.match(r'^[a-z]+(\.[a-z_]+)+$', secret_value):
                    continue

                # Skip method calls in captured values
                if re.search(r'\.\w+\(', secret_value):
                    continue

                # Context-aware confidence adjustment.
                # Base confidence resolves through `rule.confidence_for`
                # so a rule's per-content-type override (if any) is
                # the starting point that file-context heuristics then
                # adjust. See SecretRule.confidence_by_context for the
                # rationale.
                confidence = adjust_confidence(
                    rule.confidence_for(content_type),
                    secret_value,
                    file_path,
                    line_content,
                    full_file_content=content,
                    repo_root=repo_root,
                )

                # Universal non-secret value shapes (crypt password hashes, bare
                # $VAR / ${VAR} env-references, intentionally-insecure example
                # markers) — drop for EVERY rule. None can be a plaintext secret.
                if _value_is_nonsecret_universal(secret_value):
                    continue

                # Tier 1c: GENERIC catch-all rules additionally run the
                # context/structural gate (value==key, bare-id boolean/env
                # fallback, attribute ref, url-path/number/bool) — the same
                # filters CONFIG-ASSIGN has, now applied uniformly. Scoped to
                # generic rules: an anchored specific rule's match IS a real
                # secret even in these contexts, so it is never gated here.
                if _is_generic_rule(rule.rule_id):
                    _ck = re.search(r'([A-Za-z_][\w.\-]*)\s*[=:]', line_content)
                    _key = _ck.group(1).rsplit('.', 1)[-1] if _ck else ""
                    if _generic_context_is_nonsecret(secret_value, line_content, _key):
                        continue
                    # P2: a generic match in a low-signal file (test fixture,
                    # minified bundle, i18n/locale data, docs/notebook prose,
                    # crypto KAT vector) is noise — drop it. Recall-safe: a real
                    # secret here is still caught by an anchored SPECIFIC rule,
                    # which is never gated.
                    if _generic_lowsignal_file(file_path, content):
                        continue

                # Check for known placeholder/example values
                is_placeholder = _is_known_placeholder(secret_value)
                if is_placeholder:
                    # An EXACT-match canonical published example (the AWS doc key
                    # AKIAIOSFODNN7EXAMPLE, GitHub ghp_XXX…, Stripe test keys) is
                    # never a real credential — drop it outright instead of
                    # emitting a noisy 0.25-confidence finding. Broad-substring
                    # placeholders keep the confidence cap (heuristic; preserve
                    # recall, route to review).
                    if _is_exact_known_placeholder(secret_value):
                        continue
                    confidence = min(confidence, 0.25)  # Cap at 25%
                elif _decodes_to_known_placeholder(secret_value):
                    # K8s/Helm store secrets as base64; a value that decodes to a
                    # documented placeholder (b64 of "example-app-secret") is not
                    # a real secret. Recall-safe: real secrets don't base64-decode
                    # to printable placeholder text.
                    continue

                # Skip very low confidence
                if confidence < 0.10:
                    continue

                # Build code snippet (5 lines context, secret masked)
                snippet_start = max(0, line_num - 6)
                snippet_end = min(len(lines), line_num + 5)
                snippet = "\n".join(lines[snippet_start:snippet_end])
                snippet = _mask_snippet(snippet, secret_value, line_num)

                findings.append(ParsedFinding(
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    category="Hardcoded Secret",
                    cwe=rule.cwe,
                    rule_id=rule.rule_id,
                    file_path=file_path,
                    line_start=line_num,
                    code_snippet=snippet,
                    confidence=confidence,
                    raw_data={
                        "secret_type": rule.secret_type,
                        "masked_value": _mask_secret(secret_value),
                        "secret_hash": _hash_secret(secret_value),
                        "detection_method": "regex",
                        "entropy_score": None,
                        "fix_hint": rule.fix_hint,
                        "provider": rule.provider_override or rule.secret_type.split("_")[0],
                        "_raw_value_for_verification": secret_value,
                        "is_placeholder": is_placeholder,
                    },
                ))

        # Phase 2.5: Base64 decode — decode base64 values and re-run regex on decoded content
        found_lines = {f.line_start for f in findings}
        # Detect test-file context once per file (reused inside loop)
        _is_test_file = _classify_file_context(file_path) == "test_file"
        for i, line in enumerate(lines, 1):
            if i in found_lines:
                continue
            for b64_match in _BASE64_RE.finditer(line):
                decoded = _try_base64_decode(b64_match.group())
                if not decoded or len(decoded) < 8:
                    continue
                # If the decoded blob is itself PEM crypto material it must be
                # judged ONLY by the crypto rules. A cert's / key's high-entropy
                # base64 BODY coincidentally satisfies broad vendor shapes — a
                # decoded CERTIFICATE matched "Adyen API key"; a decoded RSA key
                # matched "GitHub App private key" — both pure FP / mislabel.
                #   • CERTIFICATE -> public, not a secret -> emit nothing.
                #   • PRIVATE KEY -> restrict to VOODA-SEC-CRYPTO-* so the
                #     finding is labelled by real key type (RSA/EC/PKCS8/...).
                _decoded_is_pem = "-----BEGIN " in decoded
                if "-----BEGIN CERTIFICATE-----" in decoded:
                    continue
                # Run ALL regex rules against the decoded value (not just applicable_rules,
                # because keywords like "hooks.slack.com" only appear after decoding).
                # Same ReDoS guard as Phase 2: per-rule timeout, skip-on-timeout,
                # log + continue. Decoded values are typically short (< 1 KB) so
                # timeouts here are unlikely but we keep the safety net for parity.
                for rule in self.rules:
                    # Decoded PEM private key -> only the canonical crypto key
                    # rules, so a generic RSA key isn't mislabelled as a vendor
                    # key (and broad shapes can't FP on the key body).
                    if _decoded_is_pem and not rule.rule_id.startswith("VOODA-SEC-CRYPTO-"):
                        continue
                    # Tier A: only self-anchored rules may re-match decoded
                    # base64. Bare-shape rules (Segment/Plausible/Vercel/
                    # ConvertKit) collide with arbitrary decoded bytes → pure
                    # shape-FP (~430 on the benchmark, ~0 real). Recall-safe:
                    # a base64-wrapped real secret carries its own fixed
                    # signature, which only anchored rules can identify.
                    if not _pattern_is_b64_self_anchored(rule.pattern):
                        continue
                    compiled = self._compiled[rule.rule_id]
                    engine = self._engine_by_rule[rule.rule_id]
                    try:
                        _b64_match = _safe_search(compiled, engine, decoded)
                    except TimeoutError:
                        logger.warning(
                            "rule_redos_timeout_base64",
                            rule_id=rule.rule_id,
                            secret_type=rule.secret_type,
                            file_path=file_path,
                            decoded_length=len(decoded),
                            timeout_s=_REGEX_TIMEOUT_S,
                            engine=engine,
                        )
                        continue
                    if _b64_match:
                        secret_value = decoded.strip()
                        # ── Base64 FP filters (benchmark-derived) ──
                        # 1. Generic low-confidence rules (e.g. VERCEL-002 "any 24-char
                        #    alnum") produce many FPs when applied to decoded base64
                        #    test data. Require the base rule to have confidence ≥0.70
                        #    before emitting a -B64 variant for short decoded content.
                        if rule.confidence < 0.70 and len(decoded) < 32:
                            continue
                        # 2. In test files, require the base rule to have confidence
                        #    ≥0.80 — test fixtures frequently contain base64-encoded
                        #    short words ("admin", "user", "password") that match
                        #    broad patterns. Real provider-specific rules (prefixed,
                        #    ≥0.90 confidence) still emit.
                        if _is_test_file and rule.confidence < 0.80:
                            continue
                        # Use per-context base when available; * 0.9
                        # discount keeps the original "decoded means
                        # one indirection less than the original
                        # match" intent.
                        confidence = adjust_confidence(
                            rule.confidence_for(content_type) * 0.9,
                            secret_value, file_path, line,
                            full_file_content=content, repo_root=repo_root,
                        )
                        if confidence < 0.10:
                            continue
                        snippet_start = max(0, i - 6)
                        snippet_end = min(len(lines), i + 5)
                        snippet = "\n".join(lines[snippet_start:snippet_end])
                        snippet = _mask_snippet(snippet, b64_match.group())
                        findings.append(ParsedFinding(
                            title=f"{rule.title} (Base64 Encoded)",
                            description=f"Base64-encoded secret detected. Decoded value matches {rule.title}.",
                            severity=rule.severity,
                            category="Hardcoded Secret",
                            cwe=rule.cwe,
                            rule_id=f"{rule.rule_id}-B64",
                            file_path=file_path,
                            line_start=i,
                            code_snippet=snippet,
                            confidence=confidence,
                            raw_data={
                                "secret_type": rule.secret_type,
                                # Mask the SOURCE base64 token as it appears on
                                # the line (first4****last4), not the decoded
                                # value — keeps Overview + Code consistent and
                                # matches what the reviewer sees in the code.
                                "masked_value": _mask_secret(b64_match.group()),
                                "secret_hash": _hash_secret(secret_value),
                                "detection_method": "regex_base64",
                                "entropy_score": None,
                                "fix_hint": f"This secret is Base64-encoded but decodes to a {rule.secret_type}. {rule.fix_hint}",
                                "provider": rule.provider_override or rule.secret_type.split("_")[0],
                                "_raw_value_for_verification": secret_value,
                                # Exact source token for the store-time redactor
                                # (transient; excluded from persisted metadata via
                                # the allowlist + source-path pop).
                                "_source_b64_token": b64_match.group(),
                            },
                        ))
                        found_lines.add(i)
                        break  # One finding per line per base64 match
                if i in found_lines:
                    break

        # Phase 2.6: Config key assignment detection — find secrets assigned to known config keys
        for match in _CONFIG_KEY_PATTERN.finditer(content):
            secret_value = match.group(1).strip().strip("'\"")
            line_num = content[:match.start()].count("\n") + 1

            if line_num in found_lines:
                continue

            # Skip placeholders and very common non-secrets
            if secret_value.lower() in _PLACEHOLDER_VALUES:
                continue
            # Skip values that are variable references like ${VAR} or $VAR or %VAR%
            if re.match(r'^[\$%{]', secret_value) or secret_value.startswith("{{"):
                continue
            # Skip method calls — foo.getFirst("token"), response.get("key"), etc.
            # These are API calls reading values, not hardcoded secrets
            if re.search(r'\.\w+\(', secret_value):
                continue
            # Skip Terraform/HCL/Python attribute references like
            # random_string.password.result, var.db_password, aws_instance.web.id
            # — these are variable references, not hardcoded secrets.
            if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)+$', secret_value):
                continue

            # ── Tier 1 (2026-06-08): recall-safe non-secret value/context filters
            # from the 100-repo FP ground-truth dissection. Each is provably not a
            # literal secret; pinned by test_tier1_config_assign_filters.py. ──
            _ln = lines[line_num - 1] if line_num <= len(lines) else ""
            # (a) value == its own key — a self-reference fallback, e.g.
            #     `secret_key = secret_key or os.environ.get(...)`. The {8,200}
            #     capture grabs the bare variable name, never a literal secret.
            _mk = re.search(r'([A-Za-z_]\w*)\s*[=:]', _ln)
            if _mk and secret_value.lower() == _mk.group(1).lower():
                continue
            # (b) bare identifier that is the operand of a boolean/fallback
            #     expression (`= access_token or os.environ.get(...)`,
            #     `= cfgKey || process.env.X`) — a variable reference, not a literal.
            if re.fullmatch(r'[A-Za-z_]\w*', secret_value) and \
               re.search(re.escape(secret_value) + r'\s*(?:\bor\b|\|\||\?\?)', _ln):
                continue
            # (c) attribute/object reference the value-capture left with a trailing
            #     operator (`process.env[`, `config.get.`, `self.cfg(`).
            if re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+[\[\(.]?', secret_value):
                continue
            # (d) SCREAMING_SNAKE_CASE constant / enum value
            #     (GRANT_TYPE_REFRESH_TOKEN, CONTENT_TYPE_JSON) — a code constant.
            if re.fullmatch(r'[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+', secret_value):
                continue
            # (e) documentation-placeholder markers (MYAWSACCESSKEYGOESHERE,
            #     your_api_key, <your-token>, AKIA…EXAMPLE) — examples, not creds.
            if re.search(r'goes_?here|[_-]here$|your[_-]|<[\w.-]+>|placeholder|example',
                         secret_value, re.IGNORECASE):
                continue

            # Code tokens, not secrets: a bare language keyword/type, or a value
            # containing a function-call expression (``build(``). The call check
            # requires an identifier immediately before the ``(`` so it does NOT
            # catch connection-string fragments like ``(localdb)``.
            if secret_value.lower() in _CODE_KEYWORD_VALUES or re.search(r'[A-Za-z_]\w*\(', secret_value) \
                    or _value_is_code_symbol(secret_value):
                continue
            # P1/P2: CONFIG-ASSIGN is its OWN emission path, so the low-signal-file
            # gate (test fixtures, env templates, minified, i18n, crypto vectors)
            # must be applied here too — the regex-loop generic rules already get
            # it. Recall-safe: a real secret in these files is still caught by a
            # SPECIFIC anchored rule, which is never gated.
            if _generic_lowsignal_file(file_path, content):
                continue

            confidence = adjust_confidence(
                0.75,  # Higher base confidence — matched a known sensitive key name
                secret_value, file_path,
                lines[line_num - 1] if line_num <= len(lines) else "",
                full_file_content=content, repo_root=repo_root,
            )

            # Universal non-secret value shapes (crypt hashes, $VAR refs,
            # insecure-example markers) + structural references — never a
            # plaintext secret. CONFIG-ASSIGN is its own emission path, so apply
            # the same filters the regex-rule / STRUCT paths use.
            if _value_is_nonsecret_universal(secret_value) or _struct_value_is_nonsecret(secret_value):
                continue

            # Check for known placeholder values
            is_placeholder = _is_known_placeholder(secret_value)
            if is_placeholder:
                confidence = min(confidence, 0.25)

            if confidence < 0.10:
                continue

            # Determine provider from the config key
            key_text = match.group().lower()
            provider = "generic"
            for p in ["aws", "gcp", "azure", "github", "gitlab", "slack", "stripe", "twilio", "sendgrid", "redis", "mongo", "mysql", "postgres"]:
                if p in key_text:
                    provider = p
                    break

            snippet_start = max(0, line_num - 6)
            snippet_end = min(len(lines), line_num + 5)
            snippet = "\n".join(lines[snippet_start:snippet_end])
            snippet = _mask_snippet(snippet, secret_value, line_num)

            findings.append(ParsedFinding(
                title="Hardcoded Secret in Config Assignment",
                description=f"Secret value assigned to a sensitive configuration key.",
                severity="high",
                category="Hardcoded Secret",
                cwe="CWE-798",
                rule_id="VOODA-SEC-CONFIG-ASSIGN",
                file_path=file_path,
                line_start=line_num,
                code_snippet=snippet,
                confidence=confidence,
                raw_data={
                    "secret_type": "config_secret",
                    "masked_value": _mask_secret(secret_value),
                    "secret_hash": _hash_secret(secret_value),
                    "detection_method": "config_key",
                    "entropy_score": None,
                    "fix_hint": "Move this value to environment variables or a secret manager. Never hardcode secrets in configuration files.",
                    "provider": provider,
                    "_raw_value_for_verification": secret_value,
                    "is_placeholder": is_placeholder,
                },
            ))
            found_lines.add(line_num)

        # Phase 2.7: Structured file parsing — JSON, YAML, TOML, .properties, .env
        # Uses data-structure-aware parsing to find sensitive key-value pairs.
        # e.g. {"database": {"password": "s3cr3t!"}} → key_path="database.password"
        # Skip structured parsing for i18n/translation directories — they contain
        # UI strings like "Reset your password" keyed by "PASSWORD_RESET", not real secrets.
        _path_parts = set(file_path.replace("\\", "/").split("/"))
        # Skip the GENERIC structural-key heuristic on auto-generated test
        # snapshots (Jest .snap, syrupy .ambr, ApprovalTests .approved./.received.,
        # *.snapshot.*). These serialize test/API-response data where a sensitive-
        # looking key (client_secret, token) holds a mock value — pure noise for
        # the generic STRUCT rule. Recall-safe: the specific provider/crypto rules
        # STILL run on these files (a real keyed secret is still caught); only the
        # generic key-name heuristic is suppressed — parity with WS1's "don't run
        # noisy heuristics on generated artifacts".
        _bn = os.path.basename(file_path).lower()
        _is_snapshot = (
            _bn.endswith((".snap", ".ambr"))
            or ".snapshot." in _bn or ".approved." in _bn or ".received." in _bn
        )
        _skip_structured = bool(_path_parts & STRUCTURED_SKIP_DIRS) or _is_snapshot
        structured_secrets = [] if _skip_structured else parse_structured_file(file_path, content)
        for ss in structured_secrets:
            if ss.line_num in found_lines:
                continue

            # Placeholder/example suppression (parity with the regex-rule path):
            # an exact documented example, or a base64 blob that decodes to a
            # placeholder (the K8s/Helm `secret: <base64>` convention), is never
            # a real credential. Without this, STRUCT-YAML/JSON re-catches the
            # same placeholder line the regex path just dropped.
            if _is_exact_known_placeholder(ss.value) or _decodes_to_known_placeholder(ss.value):
                continue

            # Inverse-filter: a structural value that is a reference/template,
            # an IaC intrinsic (!Ref / Fn::), an ARN, a resource-type, a bool/
            # enum, or a duration is provably not a literal secret — the bulk of
            # STRUCT-JSON/YAML false positives (CloudFormation / CDK / Helm). A
            # real secret is always a literal credential value (pinned green by
            # tests/secret_scan/test_secrets_in_config_recall.py), so this cannot
            # drop a true positive.
            if _struct_value_is_nonsecret(ss.value) or _value_is_nonsecret_universal(ss.value):
                continue

            # Tier B credential-key gate: the generic STRUCT rule otherwise emits
            # under ANY key, firing on structural identifiers (Keycloak clientIds,
            # Mongo/OTel field names, blockchain addresses, *public* keys) — value-
            # level ground truth showed ~3,232 of 3,930 STRUCT-JSON findings are
            # exactly this, with ~0 real secrets. Emit only under a credential-ish
            # key, OR when the value itself carries a high-signal provider/PEM
            # marker (escape hatch — a real format-recognizable secret survives
            # even under an odd key; it is also independently caught by its
            # specific rule). Recall pinned by test_secrets_in_config_recall.py +
            # test_tier_b_struct_key_gate.py.
            if not _struct_key_is_credential(ss.key_path) and not CONTENT_PROMOTE_RE_STR.search(ss.value):
                continue

            # Determine severity based on key pattern
            key_lower = ss.key_path.lower()
            if any(kw in key_lower for kw in ("password", "secret", "private_key", "signing_key", "connection_string")):
                severity = "critical"
            elif any(kw in key_lower for kw in ("token", "api_key", "access_key", "credential", "auth")):
                severity = "high"
            else:
                severity = "high"

            # Determine provider from key path
            provider = "generic"
            for p in [
                "aws", "gcp", "azure", "github", "gitlab", "slack",
                "stripe", "twilio", "sendgrid", "redis", "mongo",
                "mysql", "postgres", "smtp", "webhook", "jwt",
                "docker", "ldap", "amqp", "rabbit",
            ]:
                if p in key_lower:
                    provider = p
                    break

            confidence = adjust_confidence(
                0.85,  # High base confidence — key name matched a sensitive pattern
                ss.value, file_path,
                lines[ss.line_num - 1] if ss.line_num <= len(lines) else "",
                full_file_content=content, repo_root=repo_root,
            )
            if confidence < 0.10:
                continue
            # P2: STRUCT hits in low-signal files (crypto KAT vectors like
            # *keygen*.json, test fixtures, i18n/locale) are noise. Recall-safe:
            # an anchored SPECIFIC rule still fires there.
            if _generic_lowsignal_file(file_path, content):
                continue

            snippet_start = max(0, ss.line_num - 6)
            snippet_end = min(len(lines), ss.line_num + 5)
            snippet = "\n".join(lines[snippet_start:snippet_end])
            snippet = _mask_snippet(snippet, ss.value, ss.line_num)

            findings.append(ParsedFinding(
                title=f"Secret in Structured Config ({ss.file_type.upper()})",
                description=(
                    f"Sensitive key \"{ss.key_path}\" contains a credential value "
                    f"in {ss.file_type.upper()} configuration file."
                ),
                severity=severity,
                category="Hardcoded Secret",
                cwe="CWE-798",
                rule_id=f"VOODA-SEC-STRUCT-{ss.file_type.upper()}",
                file_path=file_path,
                line_start=ss.line_num,
                code_snippet=snippet,
                confidence=confidence,
                raw_data={
                    "secret_type": f"structured_{ss.file_type}",
                    "masked_value": _mask_secret(ss.value),
                    "secret_hash": _hash_secret(ss.value),
                    "detection_method": "structured_parse",
                    "key_path": ss.key_path,
                    "file_type": ss.file_type,
                    "entropy_score": None,
                    "fix_hint": (
                        f"Move the value of \"{ss.key_path}\" to environment variables "
                        f"or a secret manager (Vault, AWS Secrets Manager, etc.). "
                        f"Replace with a variable reference like ${{{ss.key_path.upper().replace('.', '_')}}}."
                    ),
                    "provider": provider,
                    "_raw_value_for_verification": ss.value,
                },
            ))
            found_lines.add(ss.line_num)

        # Phase 3: Entropy-based detection (skipped for lock/hash files)
        # P2: also skip entropy entirely in low-signal files (crypto KAT vectors,
        # test fixtures, minified bundles, i18n/locale) — entropy is the largest
        # noise source and these carry ~0 real secrets. Recall-safe: an anchored
        # SPECIFIC rule still fires there.
        skip_entropy = (os.path.basename(file_path) in ENTROPY_SKIP_FILES
                        or _generic_lowsignal_file(file_path, content))
        if self.enable_entropy and not skip_entropy:
            entropy_matches = find_high_entropy_strings(content, file_path=file_path)
            # Filter out already-found secrets by line
            found_lines = {f.line_start for f in findings}

            # Build PEM/SSH key block line ranges to suppress body entropy
            # When regex already detected -----BEGIN...PRIVATE KEY-----, the
            # base64 body lines are part of the same secret — not separate findings.
            pem_suppressed_lines: set[int] = set()
            for line_idx, line in enumerate(lines):
                if re.match(r'\s*-----BEGIN\s+[\w\s]+-----', line):
                    # Scan forward for matching END marker
                    for end_idx in range(line_idx + 1, min(line_idx + 100, len(lines))):
                        if re.match(r'\s*-----END\s+[\w\s]+-----', lines[end_idx]):
                            # Suppress all lines inside the PEM block
                            for suppress_idx in range(line_idx, end_idx + 1):
                                pem_suppressed_lines.add(suppress_idx + 1)  # 1-based
                            break

            for em in entropy_matches:
                if em.line_num in found_lines:
                    continue
                if em.line_num in pem_suppressed_lines:
                    continue

                # WS4 context-gating — the hex AND base64 charsets are the
                # audit's largest noise sources (~3.7k + several-k findings, <1%
                # TP). A bare high-entropy string with no credential key-name in
                # its context is a checksum / digest / gzip blob / encoded test
                # payload, not a secret. Require a credential key-name nearby.
                # Recall-safe — a real secret-in-config carries a key-name
                # (``token: <b64>``), which also keeps the provider/CONFIG/STRUCT
                # rules firing and is pinned green by the config-secret recall
                # corpus (test_secrets_in_config_recall.py); random base64 test
                # payloads under random keys do not.
                if em.charset.lower() in ("hex", "base64") and not _hex_has_credential_context(lines, em.line_num):
                    continue

                line_content = lines[em.line_num - 1] if em.line_num <= len(lines) else ""

                # The high-entropy run is the BODY of a crypt password hash
                # ($6$…/$2b$…/$argon2id$…) on this line — a one-way hash, not a
                # plaintext secret. (The hash's ``$id$`` prefix isn't part of the
                # extracted entropy run, so detect it at the line level.)
                if _CRYPT_HASH_INLINE_RE.search(line_content):
                    continue

                confidence = adjust_confidence(
                    0.60,  # Base confidence for entropy
                    em.value,
                    file_path,
                    line_content,
                    full_file_content=content,
                    repo_root=repo_root,
                )
                if confidence < 0.10:
                    continue

                snippet_start = max(0, em.line_num - 6)
                snippet_end = min(len(lines), em.line_num + 5)
                snippet = "\n".join(lines[snippet_start:snippet_end])
                snippet = _mask_snippet(snippet, em.value, em.line_num)

                findings.append(ParsedFinding(
                    title=f"High-Entropy {em.charset.upper()} String",
                    description=f"High-entropy {em.charset} string detected (entropy: {em.entropy:.2f}). May be a secret or credential.",
                    severity="medium",
                    category="Hardcoded Secret",
                    cwe="CWE-798",
                    rule_id=f"VOODA-SEC-ENTROPY-{em.charset.upper()}",
                    file_path=file_path,
                    line_start=em.line_num,
                    code_snippet=snippet,
                    confidence=confidence,
                    raw_data={
                        "secret_type": f"entropy_{em.charset}",
                        "masked_value": _mask_secret(em.value),
                        "secret_hash": _hash_secret(em.value),
                        "detection_method": "entropy",
                        "entropy_score": round(em.entropy, 3),
                        "fix_hint": "Investigate this high-entropy string. If it is a secret, move to environment variables.",
                        "provider": "unknown",
                        "_raw_value_for_verification": em.value,
                    },
                ))

        # ── Phase 4: Comment-aware scan (CODE path only) ──
        # Code comments are free-form prose: developers leave the same
        # `# the prod password is hunter2` shape they'd put in a Slack
        # message. The strict CODE rules miss this because the content
        # isn't quoted / assigned. Extract comments per language, pad
        # back to original line numbers, and re-scan with
        # content_type="comment" so the COLLAB rules fire.
        #
        # Guarded on `content_type is None` so we don't recurse: a
        # Slack message's content_type="message" already routes to the
        # COLLAB rules in Phase 1 above; recursing on it would do work
        # for nothing. Same for files already routed to "page" via the
        # file_routing helper.
        if content_type is None:
            comments = extract_comments(content, file_path)
            if comments:
                comment_content = build_virtual_comment_content(
                    comments, total_lines_hint=len(lines)
                )
                # Recursive call — the `content_type="comment"` arg
                # gates rule selection in Phase 1's surface filter:
                # CODE rules with surface_excluded=[..., "comment"]
                # won't fire (avoiding double-finds with the strict
                # pass we just ran), and COLLAB rules with
                # surface_targeting=[..., "comment"] DO fire.
                comment_findings = self.scan_file(
                    file_path,
                    comment_content,
                    language=language,
                    repo_root=repo_root,
                    content_type="comment",
                )
                # Dedup against findings already reported on the same
                # line/secret. Two cases to suppress:
                #   1. Provider rules (AWS, GitHub, etc.) are surface-
                #      agnostic and fire on the comment text too —
                #      same secret_hash, same line.
                #   2. The CONFIG_KEY / STRUCT-* helpers also re-fire
                #      because they don't check surface_targeting.
                # Comparison key: (line, secret_hash) covers both.
                existing = {
                    (f.line_start, (f.raw_data or {}).get("secret_hash"))
                    for f in findings
                }
                for cf in comment_findings:
                    key = (cf.line_start, (cf.raw_data or {}).get("secret_hash"))
                    if key in existing:
                        continue
                    cf.raw_data["found_in_comment"] = True
                    findings.append(cf)
                    existing.add(key)

        # Final pass: collapse findings whose matched secret values
        # overlap (a vendor-specific regex match contained inside an
        # entropy match's value, etc.).  Implemented at engine level so
        # every caller gets consistent dedup — see
        # ``_dedup_overlapping_findings`` for the priority rules.
        findings = _dedup_overlapping_findings(findings)

        return findings
