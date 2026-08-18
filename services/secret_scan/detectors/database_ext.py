# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Extended database and data platform detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(rule_id="VOODA-SEC-PLANETSCALE-001", title="PlanetScale Service Token", secret_type="planetscale_token", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(pscale_tkn_[A-Za-z0-9\-_]{32,})(?:[^A-Za-z0-9]|$)',
        keywords=["pscale_tkn_"], confidence=0.98, description="PlanetScale database service token.", fix_hint="Revoke at PlanetScale → Organization → Settings → Service tokens."),
    SecretRule(rule_id="VOODA-SEC-PLANETSCALE-002", title="PlanetScale OAuth Token", secret_type="planetscale_oauth", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(pscale_oauth_[A-Za-z0-9\-_]{32,})(?:[^A-Za-z0-9]|$)',
        keywords=["pscale_oauth_"], confidence=0.98, description="PlanetScale OAuth token.", fix_hint="Revoke at PlanetScale dashboard."),
    # Renamed 2026-05-22 (Track-A Phase 2, collision audit) from
    # VOODA-SEC-NEON-001 to VOODA-SEC-NEON-DB-URL-001.
    # The old id collided with the Neon API-token detector in
    # partner_patterns.py (different secret_type, different severity,
    # different pattern).  Last-wins dedup silently shadowed THIS
    # rule — Vooda has not been flagging leaked Neon connection
    # strings since the partner_patterns rule landed.  The rename
    # gives both detectors distinct ids so both fire from now on.
    SecretRule(rule_id="VOODA-SEC-NEON-DB-URL-001", title="Neon Database Connection String", secret_type="neon_connection_string", severity="critical",
        pattern=r'postgres(?:ql)?://[^:\s]+:[^@\s]+@[^/\s]*\.neon\.tech',
        keywords=["neon.tech"], confidence=0.95, description="Neon serverless PostgreSQL connection string.", fix_hint="Rotate password at Neon Console → Connection Details."),
    SecretRule(rule_id="VOODA-SEC-TURSO-001", title="Turso Database Token", secret_type="turso_token", severity="high",
        pattern=r'(?:turso[_-]?(?:auth[_-]?)?token|TURSO_AUTH_TOKEN)\s*[=:]\s*["\']?(eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)["\']?',
        keywords=["turso", "TURSO"], confidence=0.80, description="Turso SQLite database auth token.", fix_hint="Regenerate at Turso Dashboard → Settings."),
    SecretRule(rule_id="VOODA-SEC-UPSTASH-001", title="Upstash Redis Token", secret_type="upstash_token", severity="high",
        pattern=r'(?:upstash[_-]?redis[_-]?(?:rest[_-]?)?token|UPSTASH_REDIS_REST_TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9=]{30,})["\']?',
        keywords=["upstash", "UPSTASH"], confidence=0.80, description="Upstash serverless Redis REST token.", fix_hint="Rotate at Upstash Console → Database → REST API."),
    SecretRule(rule_id="VOODA-SEC-ELASTIC-001", title="Elasticsearch API Key", secret_type="elasticsearch_api_key", severity="high",
        pattern=r'(?:elastic[_-]?(?:search[_-]?)?api[_-]?key|ELASTICSEARCH_API_KEY|ELASTIC_API_KEY)\s*[=:]\s*["\']?([A-Za-z0-9\-_=]{30,})["\']?',
        keywords=["elastic", "ELASTIC", "elasticsearch"], confidence=0.75, description="Elasticsearch/Elastic Cloud API key.", fix_hint="Invalidate at Kibana → Stack Management → API Keys."),
    SecretRule(rule_id="VOODA-SEC-ELASTIC-002", title="Elastic Cloud ID", secret_type="elastic_cloud_id", severity="medium",
        pattern=r'(?:elastic[_-]?cloud[_-]?id|ELASTIC_CLOUD_ID)\s*[=:]\s*["\']?([A-Za-z0-9\-_:]{30,})["\']?',
        keywords=["elastic_cloud_id", "ELASTIC_CLOUD_ID"], confidence=0.75, description="Elastic Cloud deployment ID.", fix_hint="Rotate deployment credentials at cloud.elastic.co."),
    SecretRule(rule_id="VOODA-SEC-FAUNA-002", title="FaunaDB Key", secret_type="fauna_key", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(fnA[A-Za-z0-9\-_]{38,})(?:[^A-Za-z0-9]|$)',
        keywords=["fnA"], confidence=0.90, description="FaunaDB server or admin key.", fix_hint="Revoke at Fauna Dashboard → Security → Keys."),
    SecretRule(rule_id="VOODA-SEC-COCKROACH-001", title="CockroachDB Connection String", secret_type="cockroachdb_connection", severity="critical",
        pattern=r'postgres(?:ql)?://[^:\s]+:[^@\s]+@[^/\s]*\.cockroachlabs\.cloud',
        keywords=["cockroachlabs.cloud"], confidence=0.95, description="CockroachDB cloud connection string.", fix_hint="Rotate SQL user password at CockroachDB Cloud Console."),

    # ── Phase 5A: Additional connection string patterns ──────────

    SecretRule(rule_id="VOODA-SEC-JDBC-001", title="JDBC Connection String with Credentials", secret_type="jdbc_connection_string", severity="critical",
        pattern=r'(jdbc:[a-z:]+//[^:\s]+:[^@\s]+@[^\s"\']+)',
        keywords=["jdbc:"], confidence=0.90,
        description="JDBC connection string with embedded username and password. Common in Java Spring Boot, Hibernate, and JPA configurations.",
        fix_hint="Use JNDI datasource or environment variables. Never embed credentials in JDBC URLs."),

    SecretRule(rule_id="VOODA-SEC-ODBC-001", title="ODBC Connection String with Password", secret_type="odbc_connection_string", severity="critical",
        pattern=r'(?:DSN|Driver|DRIVER)\s*=[^;]*;[^;]*(?:PWD|Password|Pwd)\s*=\s*([^;"\s]{4,})',
        keywords=["DSN=", "Driver=", "DRIVER=", "PWD=", "Password="], confidence=0.85,
        description="ODBC connection string containing a password field. Common in .NET, PHP, and legacy applications.",
        fix_hint="Use Windows integrated authentication or store credentials in a secure config provider."),

    SecretRule(rule_id="VOODA-SEC-MSSQL-001", title="MSSQL/SQLServer Connection String", secret_type="mssql_connection_string", severity="critical",
        pattern=r'(?:Server|Data\s*Source)\s*=[^;]+;[^;]*(?:Password|Pwd)\s*=\s*([^;"\s]{4,})',
        keywords=["Server=", "Data Source=", "Password=", "Pwd="], confidence=0.85,
        description="Microsoft SQL Server connection string with embedded password.",
        fix_hint="Use Azure Managed Identity or integrated security. Remove password from connection string."),

    SecretRule(rule_id="VOODA-SEC-AMQP-001", title="AMQP/RabbitMQ Connection with Credentials", secret_type="amqp_connection_string", severity="critical",
        pattern=r'(amqps?://[^:\s]+:[^@\s]+@[^\s"\']+)',
        keywords=["amqp://", "amqps://"], confidence=0.90,
        description="AMQP connection string (RabbitMQ, Azure Service Bus) with embedded credentials.",
        fix_hint="Use environment variables or a secret manager for AMQP credentials."),

    SecretRule(rule_id="VOODA-SEC-LDAP-001", title="LDAP Connection with Bind Credentials", secret_type="ldap_connection_string", severity="critical",
        pattern=r'(ldaps?://[^:\s]+:[^@\s]+@[^\s"\']+)',
        keywords=["ldap://", "ldaps://"], confidence=0.85,
        description="LDAP connection URI with embedded bind credentials. Used for Active Directory and directory service authentication.",
        fix_hint="Use Kerberos or GSSAPI authentication instead of simple bind with embedded passwords."),

    SecretRule(rule_id="VOODA-SEC-DOCKER-ENV-001", title="Docker ENV/ARG with Secret Value", secret_type="docker_secret", severity="high",
        pattern=r'(?:ENV|ARG)\s+(\w*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|API_KEY)\w*)\s*=\s*["\']?([^\s"\']{8,})["\']?',
        keywords=["ENV ", "ARG "], confidence=0.80,
        description="Dockerfile ENV or ARG instruction setting a secret value. Secrets in Docker layers persist in image history.",
        fix_hint="Use Docker BuildKit secrets (--mount=type=secret) or multi-stage builds. Never set secrets via ENV/ARG."),

    # ── JDBC query-parameter credentials ─────────────────────────
    SecretRule(rule_id="VOODA-SEC-JDBC-002", title="JDBC Connection with Password in Query Params",
        secret_type="jdbc_connection_string", severity="critical",
        pattern=r'(jdbc:[a-z:]+//[^\s"\']+[?&](?:password|passwd|pwd)\s*=\s*[^&\s"\']{4,})',
        keywords=["jdbc:"], confidence=0.88,
        description="JDBC connection string with password embedded in query parameters.",
        fix_hint="Use JNDI datasource, environment variables, or a connection pool with external credential management."),

    # ── Spring Boot datasource password ──────────────────────────
    SecretRule(rule_id="VOODA-SEC-SPRING-001", title="Spring Datasource Password",
        secret_type="spring_datasource_password", severity="high",
        pattern=r'spring\.datasource\.password\s*[=:]\s*([^\s#]{4,})',
        keywords=["spring.datasource"], confidence=0.85,
        description="Spring Boot datasource password in application properties or YAML configuration.",
        fix_hint="Use Spring Cloud Config, Vault integration, or environment variables for database credentials."),

    # ── PostgreSQL keyword-style connection string ───────────────
    SecretRule(rule_id="VOODA-SEC-PG-001", title="PostgreSQL Connection with Password",
        secret_type="postgresql_connection", severity="high",
        pattern=r'(?:dbname|host)\s*=\s*\S+\s+.*password\s*=\s*["\']?([^\s"\']{4,})["\']?',
        keywords=["dbname=", "host=", "password="], confidence=0.80,
        description="PostgreSQL keyword-format connection string with embedded password (psycopg2/libpq style).",
        fix_hint="Use .pgpass file, environment variables (PGPASSWORD), or pg_service.conf for credential management."),
]
