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
]
