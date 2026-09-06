# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Database connection string detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-DB-001",
        title="PostgreSQL Connection String",
        secret_type="postgresql_connection_string",
        severity="critical",
        pattern=r'postgres(?:ql)?://[^:\s]+:[^@\s]+@[^/\s]+',
        keywords=["postgres://", "postgresql://"],
        confidence=0.90,
        description="PostgreSQL connection string with embedded credentials.",
        fix_hint="Use environment variables (DATABASE_URL) or a secret manager. Never commit connection strings.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-DB-002",
        title="MySQL Connection String",
        secret_type="mysql_connection_string",
        severity="critical",
        pattern=r'mysql(?:\+[\w]+)?://[^:\s]+:[^@\s]+@[^/\s]+',
        keywords=["mysql://"],
        confidence=0.90,
        description="MySQL connection string with embedded credentials.",
        fix_hint="Use environment variables or a secret manager for database credentials.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-DB-003",
        title="MongoDB Connection String",
        secret_type="mongodb_connection_string",
        severity="critical",
        pattern=r'mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^/\s]+',
        keywords=["mongodb://", "mongodb+srv://"],
        confidence=0.90,
        description="MongoDB connection string with embedded credentials.",
        fix_hint="Use environment variables. Enable MongoDB SCRAM-SHA-256 authentication.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-DB-004",
        title="Redis Connection String with Password",
        secret_type="redis_connection_string",
        severity="high",
        pattern=r'redis://:[^@\s]+@[^/\s]+',
        keywords=["redis://"],
        confidence=0.90,
        description="Redis connection URL with embedded password.",
        fix_hint="Use environment variables for Redis connection. Enable Redis ACL.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-DB-005",
        title="Firebase Database URL with Key",
        secret_type="firebase_credential",
        severity="high",
        pattern=r'(?:firebase_(?:api_key|token|secret|database_url)|FIREBASE_(?:API_KEY|TOKEN|SECRET))\s*[=:]\s*["\']?([A-Za-z0-9\-_]{20,})["\']?',
        keywords=["firebase_", "FIREBASE_"],
        confidence=0.80,
        description="Firebase credential or API key.",
        fix_hint="Use Firebase Admin SDK with service account credentials from environment.",
    ),
    SecretRule(
        # Well-known container/database credential environment variables.
        # These keys are defined BY the images (postgres, mysql, redis,
        # rabbitmq, grafana, ...) to hold the live credential, so the key
        # alone is near-conclusive — which is what lets this rule accept
        # short, low-entropy values the generic rules deliberately floor
        # out. GEN-003 requires a QUOTED value of 8+ chars, so the most
        # common shape in compose/.env/k8s manifests — an unquoted
        # `POSTGRES_PASSWORD: devpass` — produced no finding at all,
        # while the same credential embedded in a DB URL two stanzas up
        # was caught. Same secret, caught in one spelling, missed in the
        # other.
        #
        # Deliberate exclusions:
        #   * value may not START with `$` — `${VAR}` / `$VAR` are
        #     references, not literals (the #1 FP shape in compose).
        #   * `*_PASSWORD_FILE: /run/secrets/...` (docker secrets, the
        #     RIGHT way) cannot match: `_FILE` breaks the `[=:]`
        #     connector right after the key.
        #   * MINIO_ROOT_PASSWORD stays with its existing rule in
        #     cloud_providers_ext.py.
        rule_id="VOODA-SEC-DB-006",
        title="Database Password Environment Variable",
        secret_type="database_password",
        severity="critical",
        pattern=(
            r"""(?i)\b(?:POSTGRES(?:QL)?_PASSWORD|PGPASSWORD|"""
            r"""MYSQL_(?:ROOT_)?PASSWORD|MYSQL_PWD|"""
            r"""MARIADB_(?:ROOT_)?PASSWORD|"""
            r"""MONGO_INITDB_ROOT_PASSWORD|"""
            r"""REDIS_PASSWORD|RABBITMQ_DEFAULT_PASS|"""
            r"""CLICKHOUSE_PASSWORD|(?:MSSQL_)?SA_PASSWORD|"""
            r"""COUCHDB_PASSWORD|CASSANDRA_PASSWORD|"""
            r"""INFLUXDB_(?:INIT_)?PASSWORD|"""
            r"""GF_SECURITY_ADMIN_PASSWORD|KEYCLOAK_ADMIN_PASSWORD)"""
            r"""\s*[=:]\s*['"]?([^\s'"$]{4,})['"]?"""
        ),
        keywords=[
            "POSTGRES", "PGPASSWORD", "MYSQL", "MARIADB", "MONGO_INITDB",
            "REDIS_PASSWORD", "RABBITMQ", "CLICKHOUSE", "SA_PASSWORD",
            "COUCHDB", "CASSANDRA", "INFLUXDB", "GF_SECURITY", "KEYCLOAK",
        ],
        # Same posture as GEN-003-WEAK: strong key signal, but the FP
        # rate on prose/docs is unmeasured — route through AI triage
        # rather than auto-treat. Calibrate before raising.
        confidence=0.70,
        description="Well-known database/service password environment variable with an inline value.",
        fix_hint="Use *_PASSWORD_FILE with docker secrets, or inject from a secret manager at deploy time.",
    ),
]
