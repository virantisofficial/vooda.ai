"""Tier B — suppress canonical documentation/example JWTs (recall-safe).

JWT-001 fires on any `eyJ…​.eyJ…​.sig` token, and the bulk of its false positives
are the copy-paste example JWTs in docs/tests (jwt.io's `"name":"John Doe"`,
issuer `example.com`). `_is_example_jwt` decodes the payload and suppresses a
token whose claims carry an UNAMBIGUOUS example marker. Value-level ground truth:
176 of 420 JWT-001 FP matched; the 16 example-claim "TP" are AI mislabels (an
example JWT is not a leaked secret). A JWT with real claims still fires.
"""
from __future__ import annotations

import base64
import json

import pytest

from services.secret_scan.engine import SecretScanner

JWT = "VOODA-SEC-JWT-001"


def _mk_jwt(payload: dict) -> str:
    def b64(d):
        return base64.urlsafe_b64encode(
            json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")
    header = b64({"alg": "HS256", "typ": "JWT"})
    return f"{header}.{b64(payload)}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


def _jwt_fires(scanner, jwt):
    return any((f.rule_id or "") == JWT
               for f in scanner.scan_file("src/auth.py", f'token = "{jwt}"\n'))


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


# ── FP dropped: canonical example JWTs ──
@pytest.mark.parametrize("payload", [
    {"sub": "1234567890", "name": "John Doe", "iat": 1516239022},  # jwt.io default
    {"sub": "jane.doe", "name": "Jane Doe"},
    {"iss": "https://example.com", "aud": "my-app"},
    {"email": "user@example.com", "role": "admin"},
])
def test_example_jwt_is_suppressed(scanner, payload):
    assert not _jwt_fires(scanner, _mk_jwt(payload)), (
        f"example JWT (claims {payload}) still flagged as a secret"
    )


# ── TP kept: JWTs with real claims still fire (recall) ──
@pytest.mark.parametrize("payload", [
    {"sub": "u_9f2a7b3c4d", "role": "admin", "iat": 1700000000},
    {"user_id": "acct_88213a", "scope": "read:billing write:billing"},
    {"sub": "svc-deploy-prod", "aud": "internal-api", "exp": 1893456000},
])
def test_real_jwt_still_fires(scanner, payload):
    assert _jwt_fires(scanner, _mk_jwt(payload)), (
        f"RECALL REGRESSION: a JWT with real claims {payload} was not detected"
    )
