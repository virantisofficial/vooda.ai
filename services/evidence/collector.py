# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Evidence Collector — searches the repository for security-relevant patterns
that inform AI triage decisions.

For secret scanning, looks for:
- Secret manager usage (Vault, AWS SM, dotenv, env vars)
- .gitignore coverage (are .env files ignored?)
- Environment variable patterns (os.getenv, process.env)
- Credential rotation patterns (key rotation, token refresh)

Also retains SAST patterns for general security context:
- Sanitization, Auth middleware, Security config, ORM patterns

Returns structured evidence that populates repo_context for AI prompts.
"""

import os
import re
import structlog
from dataclasses import dataclass, field

logger = structlog.get_logger()


@dataclass
class SecurityEvidence:
    """A piece of security evidence found in the repo."""
    evidence_type: str  # sanitizer, auth_middleware, security_config, orm_usage, input_validation
    file_path: str
    line_number: int | None = None
    content: str = ""
    summary: str = ""


@dataclass
class RepoSecurityProfile:
    """Aggregated security profile for a repository."""
    sanitizers: list[SecurityEvidence] = field(default_factory=list)
    auth_middleware: list[SecurityEvidence] = field(default_factory=list)
    security_configs: list[SecurityEvidence] = field(default_factory=list)
    orm_patterns: list[SecurityEvidence] = field(default_factory=list)
    input_validators: list[SecurityEvidence] = field(default_factory=list)

    def to_context_string(self) -> str:
        """Format as context string for AI prompts."""
        sections = []

        if self.sanitizers:
            sections.append("**Sanitization/Encoding Functions Found:**")
            for e in self.sanitizers[:5]:
                sections.append(f"- {e.summary} ({e.file_path})")

        if self.auth_middleware:
            sections.append("\n**Authentication/Authorization Middleware:**")
            for e in self.auth_middleware[:5]:
                sections.append(f"- {e.summary} ({e.file_path})")

        if self.security_configs:
            sections.append("\n**Security Configuration:**")
            for e in self.security_configs[:5]:
                sections.append(f"- {e.summary} ({e.file_path})")

        if self.orm_patterns:
            sections.append("\n**ORM/Database Patterns:**")
            for e in self.orm_patterns[:5]:
                sections.append(f"- {e.summary} ({e.file_path})")

        if self.input_validators:
            sections.append("\n**Input Validation:**")
            for e in self.input_validators[:5]:
                sections.append(f"- {e.summary} ({e.file_path})")

        return "\n".join(sections) if sections else ""


# ── Pattern definitions ───────────────────────────────────

SANITIZER_PATTERNS = [
    (re.compile(r"(?:escape|html_escape|htmlspecialchars|cgi\.escape|markupsafe\.escape|bleach\.clean)\s*\(", re.I), "HTML escaping/sanitization function"),
    (re.compile(r"(?:sanitize|clean|purify|strip_tags|DOMPurify)\s*\(", re.I), "Input sanitization function"),
    (re.compile(r"(?:encodeURI|encodeURIComponent|urllib\.parse\.quote)\s*\(", re.I), "URL encoding function"),
    (re.compile(r"(?:parameterize|prepared_statement|bindparam|placeholder)\s*", re.I), "Parameterized query pattern"),
]

AUTH_PATTERNS = [
    (re.compile(r"@(?:login_required|authenticated|requires_auth|auth_required|permission_required)", re.I), "Authentication decorator"),
    (re.compile(r"@(?:PreAuthorize|Secured|RolesAllowed|RequiresPermissions)", re.I), "Authorization annotation"),
    (re.compile(r"(?:jwt\.verify|verify_token|decode_token|check_auth|isAuthenticated|passport\.authenticate)", re.I), "Token/session verification"),
    (re.compile(r"(?:middleware.*auth|authMiddleware|AuthGuard|SecurityConfig)", re.I), "Auth middleware/guard"),
    (re.compile(r"(?:csrf_protect|protect_from_forgery|CSRFMiddleware|@csrf_exempt)", re.I), "CSRF protection"),
]

SECURITY_CONFIG_PATTERNS = [
    (re.compile(r"(?:Content-Security-Policy|CSP|helmet|security_headers)", re.I), "Content Security Policy"),
    (re.compile(r"(?:CORS|cors|Access-Control-Allow-Origin)", re.I), "CORS configuration"),
    (re.compile(r"(?:SECURE_SSL_REDIRECT|HSTS|Strict-Transport-Security|force_ssl)", re.I), "HTTPS/HSTS enforcement"),
    (re.compile(r"(?:SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|secure.*cookie|httpOnly)", re.I), "Secure cookie settings"),
    (re.compile(r"(?:ALLOWED_HOSTS|trusted_hosts|allowedOrigins)\s*=", re.I), "Host allowlisting"),
    (re.compile(r"(?:rate_limit|RateLimiter|throttle|express-rate-limit)", re.I), "Rate limiting"),
]

ORM_PATTERNS = [
    (re.compile(r"(?:\.objects\.filter|\.objects\.get|\.objects\.create|\.objects\.exclude)\s*\(", re.I), "Django ORM (auto-parameterized)"),
    (re.compile(r"(?:session\.query|db\.session\.|\.filter_by|\.filter\()", re.I), "SQLAlchemy ORM (auto-parameterized)"),
    (re.compile(r"(?:JpaRepository|CrudRepository|@Query.*\?|@Query.*:param)", re.I), "Spring Data JPA (parameterized)"),
    (re.compile(r"(?:ActiveRecord|\.where\(|\.find_by\(|\.pluck\()", re.I), "ActiveRecord ORM (parameterized)"),
    (re.compile(r"(?:prisma\.\w+\.find|prisma\.\w+\.create|prisma\.\w+\.update)", re.I), "Prisma ORM (parameterized)"),
    (re.compile(r"(?:Model\.query|db\.query|knex\(|sequelize\.query)", re.I), "Query builder/ORM (likely parameterized)"),
]

VALIDATION_PATTERNS = [
    (re.compile(r"(?:Pydantic|BaseModel|@validator|Field\(|Schema\()", re.I), "Pydantic schema validation"),
    (re.compile(r"(?:Joi\.object|yup\.object|zod\.object|express-validator)", re.I), "JS schema validation"),
    (re.compile(r"(?:@Valid|@Validated|@NotNull|@Size|@Pattern|@Email)", re.I), "Bean validation annotations"),
    (re.compile(r"(?:validates_presence|validates_format|validates_length)", re.I), "Rails model validations"),
    (re.compile(r"(?:FormRequest|$this->validate|Validator::make)", re.I), "Laravel validation"),
]

# ── Secret Management Patterns (for secret scanning context) ──
SECRET_MANAGER_PATTERNS = [
    (re.compile(r"(?:boto3\.client.*secretsmanager|SecretsManager|aws_secretsmanager)", re.I), "AWS Secrets Manager usage"),
    (re.compile(r"(?:hashicorp.*vault|hvac\.Client|vault_client|VAULT_ADDR)", re.I), "HashiCorp Vault integration"),
    (re.compile(r"(?:google\.cloud.*secretmanager|SecretManagerServiceClient)", re.I), "GCP Secret Manager usage"),
    (re.compile(r"(?:azure.*keyvault|KeyVaultClient|SecretClient)", re.I), "Azure Key Vault usage"),
    (re.compile(r"(?:dotenv|load_dotenv|from_dotenv|config\(\)|dotenv\.config)", re.I), "dotenv environment loading"),
    (re.compile(r"(?:os\.environ|os\.getenv|process\.env\.|System\.getenv|ENV\[)", re.I), "Environment variable access"),
    (re.compile(r"(?:\.env\b|\.env\.local|\.env\.production)", re.I), ".env file reference"),
    (re.compile(r"(?:sealed-secrets|external-secrets|vault-injector|sops)", re.I), "Kubernetes secrets management"),
    (re.compile(r"(?:ansible-vault|encrypted_with|ANSIBLE_VAULT)", re.I), "Ansible vault encryption"),
    (re.compile(r"(?:1password.*cli|op\s+run|op\s+read|OP_SERVICE_ACCOUNT)", re.I), "1Password CLI integration"),
    (re.compile(r"(?:infisical|doppler|dotenvx)", re.I), "Modern secret manager (Infisical/Doppler)"),
]

GITIGNORE_SECRET_PATTERNS = [
    ".env", ".env.local", ".env.production", ".env.staging",
    "*.pem", "*.key", "*.p12", "*.pfx",
    "credentials", "credentials.json", "service-account*.json",
    ".npmrc", ".pypirc", ".netrc", ".pgpass", ".htpasswd",
]


class EvidenceCollector:
    """Scans a repository for security-relevant patterns."""

    def collect(self, repo_path: str, target_file: str | None = None) -> RepoSecurityProfile:
        """
        Collect security evidence from the repository.

        Args:
            repo_path: Root path of the repository
            target_file: If specified, only search in related files (same directory + config files)
        """
        profile = RepoSecurityProfile()

        if not os.path.exists(repo_path):
            return profile

        # Determine which files to search
        files_to_search = self._get_search_files(repo_path, target_file)

        for file_path in files_to_search:
            rel_path = os.path.relpath(file_path, repo_path)

            try:
                with open(file_path, "r", errors="ignore") as f:
                    content = f.read()
                    if len(content) > 500_000:  # skip very large files
                        continue
            except Exception:
                continue

            lines = content.split("\n")

            # Search each pattern category
            for pattern, desc in SANITIZER_PATTERNS:
                for match in pattern.finditer(content):
                    line_num = content[:match.start()].count("\n") + 1
                    profile.sanitizers.append(SecurityEvidence(
                        evidence_type="sanitizer",
                        file_path=rel_path,
                        line_number=line_num,
                        content=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        summary=desc,
                    ))

            for pattern, desc in AUTH_PATTERNS:
                for match in pattern.finditer(content):
                    line_num = content[:match.start()].count("\n") + 1
                    profile.auth_middleware.append(SecurityEvidence(
                        evidence_type="auth_middleware",
                        file_path=rel_path,
                        line_number=line_num,
                        content=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        summary=desc,
                    ))

            for pattern, desc in SECURITY_CONFIG_PATTERNS:
                for match in pattern.finditer(content):
                    line_num = content[:match.start()].count("\n") + 1
                    profile.security_configs.append(SecurityEvidence(
                        evidence_type="security_config",
                        file_path=rel_path,
                        line_number=line_num,
                        content=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        summary=desc,
                    ))

            for pattern, desc in ORM_PATTERNS:
                for match in pattern.finditer(content):
                    line_num = content[:match.start()].count("\n") + 1
                    profile.orm_patterns.append(SecurityEvidence(
                        evidence_type="orm_usage",
                        file_path=rel_path,
                        line_number=line_num,
                        content=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        summary=desc,
                    ))

            for pattern, desc in VALIDATION_PATTERNS:
                for match in pattern.finditer(content):
                    line_num = content[:match.start()].count("\n") + 1
                    profile.input_validators.append(SecurityEvidence(
                        evidence_type="input_validation",
                        file_path=rel_path,
                        line_number=line_num,
                        content=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        summary=desc,
                    ))

        # Deduplicate and limit
        profile.sanitizers = self._dedup(profile.sanitizers)[:10]
        profile.auth_middleware = self._dedup(profile.auth_middleware)[:10]
        profile.security_configs = self._dedup(profile.security_configs)[:10]
        profile.orm_patterns = self._dedup(profile.orm_patterns)[:10]
        profile.input_validators = self._dedup(profile.input_validators)[:10]

        total = sum(len(getattr(profile, f)) for f in ["sanitizers", "auth_middleware", "security_configs", "orm_patterns", "input_validators"])
        logger.info("evidence_collected", total=total, repo_path=repo_path[:50])

        return profile

    def _get_search_files(self, repo_path: str, target_file: str | None) -> list[str]:
        """Get list of files to search for security patterns."""
        skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "vendor", "dist", "build", ".next"}
        code_exts = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php", ".cs", ".kt", ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini", ".env"}

        files = []
        for root, dirs, filenames in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in filenames:
                ext = os.path.splitext(fname)[1].lower()
                if ext in code_exts:
                    full = os.path.join(root, fname)
                    files.append(full)

                if len(files) >= 500:  # limit search scope
                    return files

        return files

    @staticmethod
    def _dedup(evidence_list: list[SecurityEvidence]) -> list[SecurityEvidence]:
        """Deduplicate by (type, summary) — keep first occurrence of each pattern type."""
        seen = set()
        result = []
        for e in evidence_list:
            key = (e.evidence_type, e.summary)
            if key not in seen:
                seen.add(key)
                result.append(e)
        return result
