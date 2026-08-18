# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Secret scanner configuration — file types, thresholds, skip patterns."""

import re

# ── Scan Scope Definitions ───────────────────────────────────
# Each scope level includes extensions from the levels below it.
# Minimal ⊂ Standard ⊂ Extended

# Always-scan extensions — these exist specifically to hold credential
# material (private keys, certs, password files). Included in every scope
# regardless of user's minimal/standard/extended preference because missing
# one of these is a critical security gap.
_ALWAYS_SCAN_EXTENSIONS = {
    ".pem", ".key", ".p12", ".pfx", ".cer", ".crt", ".der",
    ".jks", ".keystore", ".p8", ".p7b", ".p7c",
    ".asc", ".gpg", ".pgp",  # PGP key files
    # WS1 2026-06-05 — key-material extensions the 61-repo audit found UNSCANNED.
    # `.keys` closes the wrongsecrets `.ssh/*.keys` false-negative (a real
    # private-key file that fell outside every allowlist). Force-scanning these
    # is pure recall gain — a non-key file with one of these names is rare and
    # simply yields no finding.
    ".keys", ".ppk", ".pk8", ".pkcs8", ".ovpn",
    # B1 2026-06-07 — extension belt for the 100-repo benchmark's confirmed
    # private-key FNs: flux2 `ecdsa.private`, step-ca `ca.priv`. These are rare,
    # key-specific extensions → forcing them is pure recall with ~0 FP cost.
    # NOTE: `.txt`/`.log` are DELIBERATELY NOT added here — blanket-scanning all
    # text/log files would balloon the FP surface. The PEM/token material that
    # actually lives in those files is caught instead by the content-promotion
    # net (CONTENT_PROMOTE_RE below), which is format-driven, not extension-wide.
    ".private", ".priv",
}

_MINIMAL_EXTENSIONS = {
    # Code
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".cs", ".rb", ".php",
    ".kt", ".swift", ".rs", ".scala", ".groovy", ".pl", ".r", ".m",
    # Config
    ".env", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".xml", ".plist", ".config", ".properties", ".hcl",
    # IaC (core infrastructure-as-code)
    ".tf", ".tfvars",
} | _ALWAYS_SCAN_EXTENSIONS

_STANDARD_EXTENSIONS = _MINIMAL_EXTENSIONS | {
    # Shell
    ".sh", ".bash", ".zsh", ".fish", ".bashrc", ".zshrc", ".profile",
    # Crypto
    ".pem", ".key", ".p12", ".pfx", ".cer", ".crt",
    # Data
    ".csv", ".sql",
    # Notebooks
    ".ipynb",
}

_EXTENDED_EXTENSIONS = _STANDARD_EXTENSIONS | {
    # Logs
    ".log",
    # Docs (sometimes contain secrets in examples)
    ".md", ".txt", ".rst",
    # Backup files
    ".bak", ".old", ".orig", ".backup",
}

# Default — used when scan_scope is not set
SCAN_EXTENSIONS = _STANDARD_EXTENSIONS

SCAN_SCOPE_MAP = {
    "minimal": _MINIMAL_EXTENSIONS,
    "standard": _STANDARD_EXTENSIONS,
    "extended": _EXTENDED_EXTENSIONS,
}


def get_scan_extensions(scope: str = "standard") -> set:
    """Get the file extensions set for a given scan scope.

    _ALWAYS_SCAN_EXTENSIONS (cert/key material) is unioned in regardless
    of scope — private keys and certs are security-critical enough that
    missing them would be a serious gap, even when the user picks minimal
    scope for speed.
    """
    return SCAN_SCOPE_MAP.get(scope, _STANDARD_EXTENSIONS) | _ALWAYS_SCAN_EXTENSIONS

SPECIAL_FILENAMES = {
    "credentials", "config", ".env", ".npmrc", ".pypirc",
    ".netrc", ".dockercfg", ".htpasswd", ".pgpass",
    "Dockerfile", "Jenkinsfile", "Vagrantfile",
    "docker-compose.yml", "docker-compose.yaml",
    ".gitlab-ci.yml", "Makefile",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "vendor", "dist", "build", ".next", ".nuxt", ".output",
    ".tox", ".mypy_cache", ".pytest_cache", "coverage",
    ".terraform", ".serverless",
    # WS1 2026-06-05 — additional vendored-dependency dirs (same intent as
    # `vendor`/`node_modules`: external code the repo owner can't change, dense
    # FP populations, no own secrets). `third_party` is the Google/Bazel
    # convention; `Pods` is CocoaPods; `bower_components` is Bower.
    "third_party", "Pods", "bower_components",
}

# Files where entropy detection is skipped (regex still runs).
# These are auto-generated dependency lock files containing only
# integrity hashes — always high-entropy, never real secrets.
ENTROPY_SKIP_FILES = {
    ".terraform.lock.hcl",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "Pipfile.lock",
    "Gemfile.lock",
    "go.sum",
    "Cargo.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "composer.lock",
    # Expanded 2026-04-19 — real-world-repo FP analysis surfaced
    # additional auto-generated files whose "secrets" are always
    # integrity hashes or version refs, never real credentials.
    "package-lock.yaml", "bun.lockb", "bun.lock",
    "mix.lock", "flake.lock",
    "podfile.lock", "pubspec.lock",
    "cabal.project.freeze",
}

# Files where ALL detection is skipped (lock files have regex-style hash
# strings that occasionally match generic API-key patterns by accident;
# these are auto-generated and carry no secret material).
FULLY_SKIPPED_FILES = {
    ".terraform.lock.hcl",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "package-lock.yaml",
    "bun.lockb",
    "bun.lock",
    "poetry.lock",
    "Pipfile.lock",
    "composer.lock",
    "Cargo.lock",
    "Gemfile.lock",
    "go.sum",
    "mix.lock",
    "flake.lock",
    "podfile.lock",
    "pubspec.lock",
    "cabal.project.freeze",
    # P1 (Opus×Vooda benchmark 2026-06): npm-shrinkwrap is the lockfile twin of
    # package-lock.json (integrity hashes only) — was missing here and FP'd ×4 on
    # juice-shop. serverless-state.json is a generated serverless deploy-state
    # mirror of serverless.yml (which IS scanned), so skipping is recall-safe.
    "npm-shrinkwrap.json",
    "serverless-state.json",
}

# Path GLOBS where ALL detection is skipped — vendored third-party code that
# the repo owner cannot meaningfully change. These paths produce dense
# false-positive populations across most rules (regex matches on imports,
# class declarations, crypto-algorithm name strings, integrity-hash blobs,
# bundled-JS minified payloads) without any actual secrets to find.
#
# Gold-label evidence (494 findings, Sonnet 4.5, 2026-04-24):
#   AzureGoat / cicd-goat .python_packages/lib/site-packages/  → 17 FPs
#                                                                across QUANTUM-002, QUANTUM-005, QUANTUM-008,
#                                                                CONFIG-ASSIGN — all vendored Python lib code
#   *bundle*.js / *.min.js                                     → 5 FPs across ABLY-001, SEGMENT-*, etc.
#
# Patterns use fnmatch globs (Python's fnmatch treats `*` as matching any
# character INCLUDING path separators, so `*` is enough — no `**` needed,
# but adding both forms keeps the intent readable).
FULLY_SKIPPED_PATH_PATTERNS = (
    # Python vendored / wheel metadata
    "*/site-packages/*", "site-packages/*",
    # P1 fix: glob is `*.dist-info/*` (not `*/.dist-info/*`) — wheel metadata dirs
    # are named `<pkg>-<version>.dist-info` (e.g. pytz-2021.1.dist-info), so a `/`
    # immediately before `.dist-info` never matched. (cloudgoat bundles pip wheels
    # into its lambda source dirs; the RECORD hashes are also content-gated by the
    # sha256= context, so this is defence-in-depth.)
    "*.dist-info/*", "*.egg-info/*",
    # Node.js vendored
    "*/node_modules/*", "node_modules/*",
    # Go / PHP / Ruby vendored (`vendor/` is the convention)
    "*/vendor/*", "vendor/*",
    # Webpack / Vite / Rollup bundled artifacts
    "*bundle*.js", "*.bundle.js", "*.bundle.dev.js",
    "*.min.js", "*-min.js",
    # Webpack source maps
    "*.js.map",
    # ── WS1 2026-06-05: generated & vendored noise the 61-repo audit surfaced ──
    # Protobuf / gRPC generated code (Go, C++, Python, Ruby, Dart, Swift). These
    # are machine-regenerated message structs — they cannot contain a
    # hand-written secret, so skipping is pure precision with zero recall cost.
    "*.pb.go", "*.pb.cc", "*.pb.h", "*.pb.swift",
    "*_pb2.py", "*_pb2_grpc.py", "*_pb.rb",
    "*.pb.dart", "*.pbenum.dart", "*.pbjson.dart", "*.pbserver.dart",
    # Other deterministic codegen (Dart build_runner / freezed). Same rationale.
    "*.g.dart", "*.freezed.dart",
    # Vendored third-party trees (Google/Bazel `third_party`, CocoaPods, Bower)
    # — same as the existing `vendor/`/`node_modules/` globs.
    "*/third_party/*", "third_party/*",
    "*/Pods/*", "Pods/*",
    "*/bower_components/*", "bower_components/*",
    # Minified CSS + CSS source maps (bundler output, parity with *.min.js).
    "*.min.css", "*-min.css", "*.css.map",
    # Yarn Berry bundled binaries/SDKs (large minified JS, never source secrets).
    "*/.yarn/releases/*", "*/.yarn/plugins/*", "*/.yarn/sdks/*",
)
# NOTE (recall guard): `*bindata*.go` and broad `*generated*` globs are
# DELIBERATELY NOT skipped — go-bindata and similar tools embed arbitrary asset
# files (which can include real `.pem`/key material) as base64, so they must
# still pass through the crypto/entropy detectors rather than be skipped wholesale.

# Directories where structured file parsing is skipped (regex still runs).
# Translation/i18n files contain keys like "PASSWORD_RESET" with translated
# UI strings as values — always flagged as secrets, never real credentials.
STRUCTURED_SKIP_DIRS = {
    "i18n", "l10n", "locale", "locales", "translations",
    "lang", "languages", "msgs", "messages",
}

ENTROPY_THRESHOLDS = {
    # base64 lowered from 5.3 → 5.0 (Track-A P1.3, 2026-05-20).
    # Boundary measurement against real-world tokens showed 5.3 was
    # leaving 1-3% of real secrets unflagged: GitHub PATs at ~5.27,
    # Stripe-shape keys at ~5.28, OpenAI ``sk-...`` keys hovering
    # around the same band.  5.0 catches that boundary zone while
    # the (already-strong) suffix filters (_is_known_hash_format,
    # _is_uuid, _is_sequential_or_repeated, _is_allowlisted_pattern)
    # keep false-positive rate steady.
    "base64": 5.0,
    "hex": 3.5,
    "generic": 4.5,
}

# Known placeholder/example values from official documentation.
# These are real-looking strings that appear in AWS docs, tutorials, and IaC
# examples. They are NOT real credentials — auto-classified as low confidence.
KNOWN_PLACEHOLDER_VALUES = {
    # AWS documented examples (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)
    "AKIAIOSFODNN7EXAMPLE",
    "AKIAI44QH8DHBEXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
    # AWS STS example
    "FwoGZXIvYXdzEBYaDHqa0AP1HONTBEXAMPLE",
    # Stripe test keys (always start with sk_test_ or pk_test_)
    "sk_test_4eC39HqLyjWDarjtT1zdp7dc",
    "pk_test_TYooMQauvdEDq54NiTphI7jx",
    # GitHub example tokens from docs
    "ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "github_pat_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    # Generic well-known placeholders
    "REPLACE_ME",
    "INSERT_YOUR_KEY_HERE",
    "your-api-key-here",
    "your_api_key_here",
    "changeme",
    "password123",
    "P@ssw0rd",
    "Password1",
    "mysecretpassword",
}

# Partial patterns — if the secret VALUE contains these substrings, lower confidence
KNOWN_PLACEHOLDER_PATTERNS = [
    "EXAMPLE",       # AWS example keys end with EXAMPLE/EXAMPLEKEY
    "example.com",   # Documentation URLs
    "localhost",     # Local development
    "127.0.0.1",    # Loopback
    "0.0.0.0",      # Bind-all
    "xxx",           # Redacted
    "XXX",           # Redacted
    "TODO",          # Placeholder
    "CHANGEME",      # Placeholder
    "REPLACE",       # Placeholder
    "INSERT",        # Placeholder
]

MIN_SECRET_LENGTH = 16
MAX_LINE_LENGTH = 2000
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB

# ── B1: Extension-agnostic content promotion (recall net) ────────────────
# A file whose EXTENSION would normally exclude it from scanning (e.g. a PEM
# private key inside a `.txt`/`.log`/`.cpp`, or any unusual extension) is still
# scanned if its CONTENT carries one of these high-signal secret markers.
#
# Why this exists: the extension allowlist (`_should_scan_file`) is the right
# default for performance, but it is *blind to content* — the 100-repo benchmark
# confirmed real private keys silently skipped purely because of their file
# extension (flux2 `.private`, step-ca `.priv`, trivy/checkov PEM-in-`.txt`/`.log`,
# zeromq PEM-in-`.cpp`). This net closes that class GENERICALLY: detection is
# driven by the secret's own canonical format, never by a repo-specific path or
# name. Promotion only ever ADDS a file to the scan set, so it can lower nothing —
# recall can only go up.
#
# Markers are restricted to anchored, near-zero-FP shapes so the precision cost
# of scanning a promoted file is negligible:
#   * PEM/OpenSSH/PGP PRIVATE KEY block headers — the literal "PRIVATE KEY-----"
#     substring covers RSA / EC / DSA / ENCRYPTED / OPENSSH / PGP variants.
#   * Provider tokens whose mandatory unique prefix essentially never occurs by
#     accident: AWS AKIA, GitHub gh[pousr]_, Slack xox[baprs]-, Google AIza,
#     GitLab glpat-, Stripe/related (sk|rk)_live_, OpenAI sk-.
# Quantifiers are upper-bounded to keep the scan linear on pathological lines.
_CONTENT_PROMOTE_PATTERN = (
    r"-----BEGIN[A-Z0-9 ]{0,40}PRIVATE KEY-----"
    r"|AKIA[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{30,80}"
    r"|xox[baprs]-[0-9A-Za-z-]{10,120}"
    r"|glpat-[0-9A-Za-z_-]{20}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|(?:sk|rk)_live_[0-9A-Za-z]{20,80}"
    r"|sk-[A-Za-z0-9]{20,80}"
)
# Compiled twice so both byte buffers (file reads) and str content (in-memory
# diff hunks) can be screened without re-encoding on the hot path.
CONTENT_PROMOTE_RE = re.compile(_CONTENT_PROMOTE_PATTERN.encode())
CONTENT_PROMOTE_RE_STR = re.compile(_CONTENT_PROMOTE_PATTERN)
# Only the first slice is null-screened to reject binaries (DER keys, images,
# archives) before the marker search; a text key sits well within this window.
PROMOTE_BINARY_SCREEN_BYTES = 8192
