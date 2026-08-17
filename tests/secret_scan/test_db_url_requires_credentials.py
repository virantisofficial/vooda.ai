"""P3 — DB connection-URL rules require embedded credentials (lock test).

The 20-repo Opus×Vooda benchmark flagged ``MONGODB-URL-001`` on credential-less
URIs like ``mongodb://localhost:27017/nodegoat`` (NodeGoat x4). That turned out
to be a STALE-WORKER artifact: the committed POSTGRES/MYSQL/MONGODB-URL-001
patterns already require a ``<user>:<pass>@`` segment
(``...://[A-Za-z0-9_-]+:[^@\\s/]{3,64}@host...``), so a bare host/port/db URL
with no credentials is not a secret and is not flagged. The worker had been
running a pre-fix module, so the benchmark over-reported it.

This test locks the credential-required behavior so the patterns can't regress
to the broad (credential-less) form, and asserts a real credentialed URL still
fires (recall guard).
"""
from __future__ import annotations

import pytest

from services.secret_scan.engine import SecretScanner


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


def _fires(scanner, url: str, rule_id: str) -> bool:
    # JS const assignment context so CONFIG-ASSIGN's `KEY=value` path doesn't add
    # noise — we assert specifically on the connection-URL rule.
    content = f"const u = '{url}'\n"
    return any(f.rule_id == rule_id
               for f in scanner.scan_file("config/db.js", content))


# (rule_id, credential-less URL [should NOT fire], credentialed URL [should fire])
_CASES = [
    ("VOODA-SEC-MONGODB-URL-001",
     "mongodb://localhost:27017/nodegoat",
     "mongodb://admin:secret123@cluster0.mongodb.net/appdb"),
    ("VOODA-SEC-POSTGRES-URL-001",
     "postgres://localhost:5432/app",
     "postgresql://dbuser:p4ssw0rd1@db.internal:5432/app"),
    ("VOODA-SEC-MYSQL-URL-001",
     "mysql://localhost:3306/app",
     "mysql://root:rootpw1234@db.internal:3306/app"),
]


@pytest.mark.parametrize("rule_id,nocreds,creds", _CASES)
def test_credentialless_url_not_flagged(scanner, rule_id, nocreds, creds):
    assert not _fires(scanner, nocreds, rule_id), (
        f"{rule_id} false-positived on a credential-less connection URL: {nocreds}"
    )


@pytest.mark.parametrize("rule_id,nocreds,creds", _CASES)
def test_credentialed_url_still_flagged(scanner, rule_id, nocreds, creds):
    assert _fires(scanner, creds, rule_id), (
        f"RECALL REGRESSION: {rule_id} missed a credentialed connection URL: {creds}"
    )
