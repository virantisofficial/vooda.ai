# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Context-aware false positive filtering for secret detection."""

import os
import re

# Patterns that identify "test context" file paths.  When any of
# these matches, ``adjust_confidence()`` applies a 0.4× dampener to
# any finding's base confidence — usually pushing test-fixture
# matches below the emission threshold without eliminating them
# entirely.
#
# Path-segment-aware design (2026-05-24): every directory-style
# pattern is anchored with `(?:^|[/\\])` on the left so substring
# matches against unrelated words can't trip the filter.  Without
# this, `test[s_/\\]` matched `tests` inside `protests`, downgrading
# confidence on findings in a file like `src/util/protests/manager.py`
# — a pre-existing bug surfaced by the BUG-P2 audit (scan_id
# 03671f65 on pulumi/pulumi).
#
# Brought in line with ``_classify_file_context()`` in engine.py
# which already recognised the Go-convention `testdata/` /
# `testing/` directories the original regex missed.
_TEST_PATH_PATTERNS = [
    # Test directory conventions (path-anchored so `protests/` etc.
    # don't false-match).  Each handles plural `s` and the
    # `test_`/`spec_` filename-prefix conventions.
    r"(?:^|[/\\])tests?[/\\_]",
    r"(?:^|[/\\])specs?[/\\_]",
    r"(?:^|[/\\])__tests?__[/\\]",
    r"(?:^|[/\\])__mocks?__[/\\]",
    r"(?:^|[/\\])fixtures?[/\\]",
    r"(?:^|[/\\])examples?[/\\]",
    r"(?:^|[/\\])samples?[/\\]",
    r"(?:^|[/\\])mocks?[/\\]",
    r"(?:^|[/\\])fakes?[/\\]",
    # Go-convention directories (BUG-P2 fix, 2026-05-24).
    r"(?:^|[/\\])testdata[/\\]",
    r"(?:^|[/\\])test-data[/\\]",
    r"(?:^|[/\\])testing[/\\]",
    # Snapshot / golden / VCR / E2E conventions.
    r"(?:^|[/\\])golden[/\\]",
    r"(?:^|[/\\])snapshots?[/\\]",
    r"(?:^|[/\\])__snapshots__[/\\]",
    r"(?:^|[/\\])cassettes[/\\]",
    r"(?:^|[/\\])vcr[/\\]",
    r"(?:^|[/\\])e2e[/\\]",
    r"(?:^|[/\\])cypress[/\\]",
    r"(?:^|[/\\])integration[/\\]",
    # File-suffix recognisers (kept anchored to filename boundaries).
    r"\.test\.",
    r"\.spec\.",
    r"_test\.",
    r"_spec\.",
    r"_test\.go$", r"_test\.py$", r"_test\.rb$", r"_spec\.rb$",
    # WS7 2026-06-05: snapshot / approval-test FILE suffixes for snapshots that
    # live next to the source rather than under a __snapshots__/ dir — Jest
    # ``.snap``, syrupy ``.ambr``, ApprovalTests ``.approved.``/``.received.``.
    # Generated test artifacts: dampen (route to review), never suppress — a real
    # key captured in a snapshot is still key material, so recall is preserved.
    r"\.snap$", r"\.ambr$", r"\.approved\.", r"\.received\.", r"\.snapshot\.",
    # Substring-only conventions where a path segment of `dummy`
    # explicitly signals a fixture.  Conservative — `dummy_data/`
    # is the documented usage; we still allow it to match anywhere
    # in the path because the word is very rarely incidental.
    r"(?:^|[/\\])dummy(?:[/\\_]|$)",
]
_TEST_PATH_RE = re.compile("|".join(_TEST_PATH_PATTERNS), re.IGNORECASE)

_PLACEHOLDER_VALUES = {
    "change_me", "changeme", "change-me", "replace_me", "replaceme",
    "your_key_here", "your-key-here", "your_api_key", "your_secret",
    "xxx", "xxxx", "xxxxxxxx", "todo", "fixme",
    "insert_key", "insert-key", "put_your_key", "add_your_key",
    "placeholder", "example", "sample", "test", "demo", "fake",
    "dummy", "mock", "development", "staging",
    "sk_test_", "pk_test_", "test_key", "test_secret", "test_token",
    "password123", "password1234", "admin123", "secret123",
    "none", "null", "undefined", "n/a", "na", "tbd",
    # ── Expanded 2026-04-19: generic dummy strings and RFC-blessed
    # example tokens commonly left behind in code. Each one appearing
    # in source dampens the finding's confidence, never eliminates it.
    "p@ssword", "p@ssw0rd", "passw0rd", "root", "toor", "administrator",
    "defaultpassword", "default-password",
    "myusername", "mypassword", "myapikey",
    "exampleexample", "testtest", "keykeykey",
    "aaaaaaaa", "00000000", "11111111", "12345678",
    "abcdefgh", "abcd1234", "test1234",
    "xxxxxxxxxxxx", "yyyyyyyy", "zzzzzzzz",
    "your-client-id", "your-client-secret", "your-access-token",
    "my-secret-key", "my-api-key", "my-access-token",
    "lorem", "ipsum", "foo", "bar", "baz", "qux",
    # Common Docker/Linux distro placeholders used in examples.
    # ``busybox``, ``alpine``, ``anonymous`` etc. appear as default
    # passwords/users in documentation but are never real creds.
    "busybox", "busybox@", "anonymous", "anonymous@", "alpine",
    "guest", "demo_user", "demo-user", "guest@",
}

_PLACEHOLDER_PREFIXES = [
    "sk_test_", "pk_test_", "rk_test_", "whsec_test_",
    "xoxb-0000", "xoxp-0000",
    # ── Expanded 2026-04-19 ──
    "fake-", "fake_", "test-", "dummy-", "mock-", "example-",
    "replace-", "placeholder-", "insert-", "your-",
    "00000000", "XXXXXXXX", "AAAAAAAA",
]

# Regex-level placeholder patterns — matches when the FULL secret value
# matches, not just prefixes. Each pattern dampens confidence.
_PLACEHOLDER_VALUE_PATTERNS = [
    r"^0+$",                             # all zeros
    r"^[xX]+$",                          # all X's
    r"^[aA]+$",                          # all A's
    r"^(?:abc|ABC|xyz|XYZ){2,}.*",       # repeated dummy sequences
    r"^[a-zA-Z]{1,4}[0-9]{1,6}$",        # short-prefix + digits (test42, user1)
    r"^_+$",                             # all underscores
    r"^-+$",                             # all dashes
    # Short purely-numeric values are usually IDs or timestamps. The
    # 12-char cap keeps this narrow enough that long real hex secrets
    # don't accidentally match — a 40-hex secret like
    # ``abc0abc0abc0abc0abc0abc0abc0abc0abc0abc0`` has letters so it
    # wouldn't match here either way.
    r"^[0-9]{1,12}$",
    r"^\$\{[A-Z_]+\}$",                  # ${ENV_VAR} template
    r"^<[^>]+>$",                        # <placeholder> template
    r"^\{\{[^}]+\}\}$",                  # {{template}} (handlebars / Jinja)
    r"^%[A-Z_]+%$",                      # %WINDOWS_STYLE%
    # The value looks like a bare identifier WITH underscore — e.g.
    # API_KEY=API_KEY, SECRET=MY_SECRET. The underscore requirement
    # is critical: without it, real AKIA-style provider tokens like
    # ``AKIAIOSFODNN7EXAMPLE`` (20 uppercase + digits, no underscore)
    # would incorrectly match. Real tokens almost never contain ``_``.
    r"^[A-Z][A-Z0-9]*_[A-Z0-9_]*$",
]
_PLACEHOLDER_VALUE_RE = re.compile("|".join(_PLACEHOLDER_VALUE_PATTERNS))

# Long-run-of-identical-chars dampener (Phase 2 A1, 2026-04-19).
# Catches values like ``ghu_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`` or
# ``glrt-tx_xxxxxxxxxxxxxxxxxxxxxxxxxxx`` — valid provider prefixes
# followed by a padding run. Gitleaks / TruffleHog explicitly list
# these in their own ``fps`` test arrays; Vooda was scanning them
# blind. Match triggers when any run of ≥15 identical chars appears
# anywhere in the captured value.
_IDENTICAL_RUN_RE = re.compile(r"(.)\1{14,}")

# Explicit placeholder-marker substrings (Phase 2 A1). When a captured
# credential value contains any of these as a distinct token, it's a
# test fixture label, never a live secret. Kept case-sensitive to
# avoid mangling legitimate base64 that happens to contain ``dummy``
# as bytes.
_PLACEHOLDER_MARKERS = [
    "DUMMY", "FAKE", "REPLACE_ME", "REPLACEME", "YOUR_",
    "RANDOMSTRING", "EXAMPLEHERE", "INITIAL_", "HEREHERE",
    "YOURTOKEN", "YOURKEY", "YOURSECRET",
    # Case-insensitive end-of-value placeholder words. ``xoxe.xoxp-1-initial``
    # from gitleaks' own FP list should match here; ``ntn_initial-key`` too.
    "-INITIAL", "_INITIAL",
]
# Case-insensitive — picks up ``initial`` / ``dummy`` / ``fake`` regardless
# of shouted-case / camel-case. Real provider tokens don't contain these
# literal substrings.
_PLACEHOLDER_MARKER_RE = re.compile(
    r"(?:" + "|".join(re.escape(m) for m in _PLACEHOLDER_MARKERS) + r")",
    re.IGNORECASE,
)

# URL-basic-auth with star-masked / repeated-char password. E.g.
# ``ftp://user:********@host`` or ``https://u:xxxxxxx@host`` — usually
# a redacted test fixture, not a live credential.
_URL_STARS_PW_RE = re.compile(
    r"[a-z][a-z0-9+.\-]*://[^:/\s]+:(?:[\*x]{3,}|\.{3,})@",
    re.IGNORECASE,
)

# Format-string / template-placeholder dampener (Phase 2 A2).
# Catches ``fmt.Sprintf("https://%s:%s@bitbucket.org", ...)`` where the
# value captured by a URL-basic-auth rule is a format template, not a
# live credential. Any of these tokens in the captured span is
# disqualifying on its own.
_FORMAT_TEMPLATE_RE = re.compile(
    r"(?:"
    r"%[sdvqx@]"                    # Go / C / Obj-C printf
    r"|%\([A-Za-z_][A-Za-z0-9_]*\)[sd]"  # Python %(name)s / %(name)d
    r"|\{[0-9A-Za-z_]*\}"           # .NET / brace templates
    r"|<%=[^%]*%>"                  # ERB
    r"|<\?=[^?]*\?>"                # PHP short-echo
    r")"
)

# PEM-without-body dampener (Phase 2 A3).
# The ``-----BEGIN X-----`` marker alone — no END, no body lines — is
# almost always a string constant naming the delimiter
# (e.g. ``BEGIN_PRIVATE_KEY_TOKEN = "-----BEGIN PRIVATE KEY-----"``),
# not an actual key. A real key always has at least one base64-like
# body line AND a matching END marker.
_PEM_HEADER_RE = re.compile(r"-----BEGIN\s+[A-Z0-9 ]+-----")
_PEM_END_RE = re.compile(r"-----END\s+[A-Z0-9 ]+-----")

# Advisory-rule bare-algorithm names (Phase 3 B1).
# These are advisory rules that fire on any mention of a quantum-
# vulnerable algorithm name — useful in crypto config files, noisy
# in source-code imports/type references. We detect matches that
# are JUST the algorithm name (no digits/keys around it) so we can
# dampen based on surrounding-line context.
_ADVISORY_BARE_ALGO_RE = re.compile(
    r"^(?:ECDSA|ECDH|DSA|RSA|X25519|Ed25519|ED25519|"
    r"P-256|P-384|secp256r1|secp384r1|prime256v1|SECP256R1|SECP384R1|"
    r"ssh-ed25519|TLS_RSA_WITH|TLS_ECDHE_RSA|TLS_ECDHE_ECDSA)$",
    re.IGNORECASE,
)

# Code-symbol context — import/type/class-reference patterns. If a
# bare algorithm name is matched on a line that looks like source-code
# symbol usage rather than a crypto-config value, it's a usage-site
# advisory, not a hardcoded key. Strongly dampen.
_CODE_SYMBOL_CONTEXT_RE = re.compile(
    r"(?:"
    r"^\s*(?:import|from|package|use)\s+"                # Python/Go/Java/Rust
    r"|^\s*(?:public|private|protected|static|final)\s+.*\b(?:class|interface|enum)\b"
    r"|\bnew\s+\w+Verifier\b"                              # JWT/JOSE verifier ctor
    r"|\bnew\s+\w+Signer\b"
    r"|::\w+\s*\("                                          # C++/Rust method
    r"|\bextends\s+|\bimplements\s+"                       # Java class decl
    r"|\.(?:Verifier|Signer|KeyFactory)\b"
    r")",
    re.MULTILINE,
)

# Wordlist-line detection (Phase 3 B1 adjunct).
# A bare algorithm name on a line that is just one quoted token
# inside a long list — e.g. ``    "ecdsa",`` — is a wordlist entry,
# not a crypto declaration.
_WORDLIST_LINE_RE = re.compile(
    r'^\s*["\']?[a-z0-9_\-]{3,20}["\']?\s*,?\s*$',
    re.IGNORECASE,
)

# Genomic / read-quality noise dampener (Phase 3 B3).
# FASTQ-style quality strings and genomic read sequences often match
# provider-token shapes (e.g. ``hf_eefghihhii...``). Signature:
#   - captured value contains no digits
#   - sits inside a ≥50-char window of letters + underscores (FASTQ
#     reads sometimes include ``_`` as separators between segments)
#   - the window has no digits anywhere
# Real provider tokens almost always include digits or hyphens.
_GENOMIC_RUN_RE = re.compile(r"[A-Za-z_]{50,}")

_EXAMPLE_DOMAINS = {
    "example.com", "example.org", "example.net",
    "test.com", "localhost", "127.0.0.1",
    "foo.bar", "acme.com", "yourcompany.com",
    "myapp.local", "0.0.0.0",
}

_COMMENT_RE = re.compile(r"^\s*(?:#|//|/\*|\*|--|;|%|'|<!--)")

# Test framework import patterns — if present in file, the file is test code
_TEST_IMPORT_PATTERNS = re.compile(
    r"(?:import\s+(?:pytest|unittest|jest|mocha|chai|vitest|jasmine|rspec)|"
    r"from\s+(?:pytest|unittest)|"
    r"require\(['\"](?:jest|mocha|chai|supertest)['\"]|"
    r"describe\s*\(|it\s*\(['\"])",
    re.IGNORECASE,
)

# .gitignore cache: repo_root -> set of gitignored patterns
_gitignore_cache: dict[str, set[str]] = {}


def _load_gitignore_patterns(repo_root: str) -> set[str]:
    """Load .gitignore patterns from a repository root."""
    if repo_root in _gitignore_cache:
        return _gitignore_cache[repo_root]

    patterns = set()
    gitignore_path = os.path.join(repo_root, ".gitignore")
    if os.path.exists(gitignore_path):
        try:
            with open(gitignore_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        patterns.add(line.rstrip("/"))
        except Exception:
            pass
    _gitignore_cache[repo_root] = patterns
    return patterns


def _should_be_gitignored(file_path: str, repo_root: str = "") -> bool:
    """Check if a file matches common .gitignore patterns for sensitive files."""
    basename = os.path.basename(file_path)
    # These files should almost always be gitignored
    sensitive_names = {".env", ".env.local", ".env.production", ".env.staging",
                       ".npmrc", ".pypirc", ".netrc", ".pgpass", ".htpasswd",
                       "credentials", "credentials.json", "service-account.json"}
    if basename in sensitive_names:
        # If found in repo, it was NOT gitignored — this is a stronger signal
        return True

    if repo_root:
        patterns = _load_gitignore_patterns(repo_root)
        for pattern in patterns:
            if pattern in file_path or basename == pattern:
                return False  # It IS in .gitignore, so file being present is unexpected
    return False


def adjust_confidence(
    base_confidence: float,
    matched_value: str,
    file_path: str,
    line_content: str,
    full_file_content: str = "",
    repo_root: str = "",
) -> float:
    confidence = base_confidence
    lower_val = matched_value.lower().strip("'\"` ")
    lower_path = file_path.lower()

    # Test file path → reduce confidence
    if _TEST_PATH_RE.search(file_path):
        confidence *= 0.4

    # Placeholder value → strong reduction. ``busybox``, ``anonymous``,
    # ``changeme`` etc. — never real secrets. Use 0.1 factor so even
    # a 0.99 base drops just below the 0.10 emission threshold.
    if lower_val in _PLACEHOLDER_VALUES or any(lower_val.startswith(p) for p in _PLACEHOLDER_PREFIXES):
        confidence *= 0.1

    # Placeholder-shape regex (expanded 2026-04-19): catches things
    # like "00000000000000", "XXXXXXXXXXX", "${SECRET}", "<api_key>",
    # "test42" — shapes developers leave in real code that match our
    # rule regex but aren't real secrets.
    if _PLACEHOLDER_VALUE_RE.match(matched_value.strip("\"'` ")):
        confidence *= 0.2

    # ── Phase 2 A1: long-run-of-identical-chars ──
    # e.g. ``ghu_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`` — provider-valid
    # prefix + padding run. Strong dampener, not zero (real secrets
    # very rarely have 15+ identical chars but it's theoretically
    # possible for generated tokens).
    if _IDENTICAL_RUN_RE.search(matched_value.strip("\"'` ")):
        confidence *= 0.05

    # ── Phase 2 A1: explicit placeholder markers ──
    # ``ops_DUMMYWFp…``, ``RANDOMSTRINGHERE``, ``YOUR_TOKEN``,
    # ``xoxe.xoxp-1-initial`` — case-insensitive substring match on
    # well-known fixture labels. Strong dampener to push sub-threshold.
    if _PLACEHOLDER_MARKER_RE.search(matched_value):
        confidence *= 0.05

    # ── Phase 2 A2b: URL with stars/repeated-char password ──
    # Redacted test-fixture URLs like ``ftp://u:********@host``.
    if _URL_STARS_PW_RE.search(matched_value):
        confidence *= 0.05

    # ── Phase 2 A2: format-string / template placeholders ──
    # ``fmt.Sprintf("https://%s:%s@host", ...)`` — the captured span
    # is a template, not a live credential. Collapse to near-zero.
    if _FORMAT_TEMPLATE_RE.search(matched_value):
        confidence *= 0.05

    # ── Phase 3 B1: advisory-rule bare-algorithm in code-symbol context ──
    # Quantum-vulnerable advisory rules (ECDSA, RSA, DSA, X25519) fire
    # on any mention of the algorithm name. When the match is a bare
    # algorithm name AND the line/file looks like source-code symbol
    # usage (imports, class refs, method bodies) rather than a crypto
    # config, it's an advisory about code usage — not a hardcoded
    # key. Crypto advisories are only actionable in PEM/cert/config
    # contexts. Strong dampener on usage-site matches; zero dampener
    # when the match appears in a ``.pem``/``.key``/``.cnf`` file.
    stripped_adv = matched_value.strip("\"'` ")
    if _ADVISORY_BARE_ALGO_RE.match(stripped_adv):
        is_crypto_config = any(
            lower_path.endswith(ext)
            for ext in (".pem", ".key", ".crt", ".cer", ".p12",
                        ".pfx", ".jks", ".p8", ".cnf", ".conf")
        )
        is_code_symbol = bool(_CODE_SYMBOL_CONTEXT_RE.search(line_content))
        is_wordlist = bool(_WORDLIST_LINE_RE.match(line_content.strip()))
        if not is_crypto_config and (is_code_symbol or is_wordlist):
            confidence *= 0.05

    # ── Phase 3 B3: genomic / read-quality noise ──
    # If the captured value itself has no digits AND sits inside a
    # ≥50-char run of letters (typical of FASTQ quality strings,
    # read sequences, or hashed biological identifiers), dampen.
    # Real provider tokens always have digits or other separators
    # (``ghp_`` + hex, ``gsk_`` + alnum, etc.), so no-digits +
    # letter-run is a clean discriminator.
    if full_file_content and not re.search(r"[0-9]", matched_value):
        idx = full_file_content.find(matched_value)
        if idx >= 0:
            lo = max(0, idx - 80)
            hi = min(len(full_file_content), idx + len(matched_value) + 80)
            window = full_file_content[lo:hi]
            # No digits anywhere in the window AND a 50+ char letter run
            if (_GENOMIC_RUN_RE.search(window)
                    and not re.search(r"[0-9]", window)
                    and not re.search(r"\s{2,}", window)):
                confidence *= 0.05

    # ── Phase 2 A3: PEM header without matching END or body ──
    # ``-----BEGIN PRIVATE KEY-----`` as a standalone string literal
    # (no newline, no END marker) is a constant naming the delimiter,
    # not an actual key. Require at least one newline AND a matching
    # END marker inside the captured value before accepting a PEM hit.
    if _PEM_HEADER_RE.search(matched_value):
        has_end = bool(_PEM_END_RE.search(matched_value))
        # WS2 2026-06-05: accept BOTH real newlines AND the escaped-\n single-
        # line form. A PEM stored in JSON/.env/YAML as one line with literal
        # "\n" separators (``"-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END..."``)
        # is the #1 real-world key-leak shape and a genuine private key — not a
        # delimiter constant. Splitting on either separator lets its base64 body
        # be seen, so a full BEGIN+body+END escaped key is no longer crushed to
        # ENTROPY-BASE64. A bare delimiter string (no END / no body) still is.
        _pem_lines = re.split(r"\\n|\n", matched_value)
        has_body = any(
            len(ln.strip()) >= 40
            and re.match(r"^[A-Za-z0-9+/=]+$", ln.strip())
            for ln in _pem_lines
        )
        if not (has_end and has_body):
            confidence *= 0.05

    # Identifier-echo detection: catch ``API_KEY = API_KEY`` patterns
    # where the declared value is just the key name repeated. Uses a
    # strict shape (both sides must be bare identifiers, explicit ``=``
    # or ``:`` separator) to avoid catching JWTs in method-call bodies
    # or anywhere else the value happens to share characters with the
    # surrounding code. (Initial looser version dropped real JWT hits
    # in WebGoat test files — lesson: require explicit assignment.)
    stripped = matched_value.strip("\"'` ")
    if stripped and line_content and "=" in line_content:
        # Look for: IDENT = "IDENT"  or  IDENT: "IDENT"
        m = re.match(r'^\s*([A-Z][A-Z0-9_]{2,})\s*[=:]\s*["\']?([A-Z][A-Z0-9_]{2,})["\']?\s*[;,]?\s*$', line_content)
        if m and m.group(1) == m.group(2) == stripped:
            confidence *= 0.1

    # Example domain in connection strings
    for domain in _EXAMPLE_DOMAINS:
        if domain in matched_value.lower():
            confidence *= 0.2
            break

    # Comment line → reduce
    if _COMMENT_RE.match(line_content):
        confidence *= 0.5

    # Sequential or repeated characters
    if len(set(matched_value.replace("=", ""))) <= 4:
        confidence *= 0.1

    # Git commit hash shape: 7-40 hex chars. Common in changelogs,
    # .github/workflows/, docs. Keep conservative — don't collapse to
    # zero because some providers (e.g. Etherscan) have hex-only
    # tokens that could false-negative. A moderate dampener is enough
    # to push typical changelog entries below the 0.10 threshold.
    stripped_for_hash = matched_value.strip("\"'` ").lower()
    if re.match(r"^[a-f0-9]{7,40}$", stripped_for_hash):
        # Stronger dampener in changelogs / release notes / docs where
        # this shape is almost always a commit hash, not a secret.
        is_changelog_context = any(seg in lower_path for seg in (
            "changelog", "release_notes", "release-notes",
            "/docs/", "/doc/", "/documentation/", "/.github/",
        ))
        if is_changelog_context or lower_path.endswith((".md", ".rst", ".adoc")):
            confidence *= 0.2
        else:
            # Outside docs, still dampen moderately — real secrets usually
            # have more character variety than pure hex.
            confidence *= 0.6

    # Filename-shape values (foo.conf, app.py, .env.example). A rule
    # occasionally matches these as "secrets" when the value happens to
    # include enough entropy-like substring. File paths are never
    # secrets themselves — the secret is the file's CONTENT.
    if re.match(r"^[\w\-./]+\.[a-zA-Z0-9]{1,6}$", matched_value.strip()):
        # Only if the value is short-ish (filename-like) — full URLs
        # or long base64 with `.` in them shouldn't dampen.
        if len(matched_value.strip()) <= 60:
            confidence *= 0.3

    # Absolute/relative path values (/usr/bin/..., ./src/..., C:\...)
    # Same reasoning — paths aren't secrets.
    if re.match(r"^(?:[a-zA-Z]:[\\/]|\.{0,2}[\\/]|/)[\w\-./\\]+$",
                matched_value.strip()):
        confidence *= 0.15

    # Documentation/README files
    if any(lower_path.endswith(ext) for ext in (".md", ".rst", ".txt", ".adoc")):
        confidence *= 0.5

    # Lock files / generated files
    if any(seg in lower_path for seg in ("package-lock", "yarn.lock", "poetry.lock", "pipfile.lock", "go.sum")):
        confidence *= 0.1

    # Test framework imports in file → reduce (file is test code)
    if full_file_content and _TEST_IMPORT_PATTERNS.search(full_file_content[:3000]):
        confidence *= 0.4

    # .gitignore awareness — file that SHOULD be gitignored but wasn't → BOOST confidence
    if _should_be_gitignored(file_path, repo_root):
        confidence = min(confidence * 1.2, 1.0)  # Boost — this is a real leak

    # Minified/bundled files
    if any(seg in lower_path for seg in (".min.", ".bundle.", "/dist/", "/build/")):
        confidence *= 0.2

    # Vendor/third-party files
    if any(seg in lower_path for seg in ("/vendor/", "/third_party/", "/node_modules/")):
        confidence *= 0.1

    # Known benign values
    if lower_val in ("true", "false", "yes", "no", "on", "off", "1", "0"):
        confidence *= 0.05

    return round(min(max(confidence, 0.05), 1.0), 2)
