"""P1 — generated / lockfile / build-artifact files are fully skipped.

The 20-repo Opus×Vooda benchmark surfaced false positives on auto-generated
files whose "secrets" are integrity hashes or serialized deploy-state, never
real credentials:

  - ``npm-shrinkwrap.json`` (lockfile twin of package-lock.json) -> FP x4 on
    juice-shop; was simply missing from FULLY_SKIPPED_FILES.
  - ``serverless-state.json`` (generated serverless deploy-state mirror of
    serverless.yml).
  - ``<pkg>-<ver>.dist-info/*`` Python wheel metadata -- the exclusion glob was
    malformed (``*/.dist-info/*`` never matched ``pytz-2021.1.dist-info`` because
    of the ``/`` before ``.dist-info``); fixed to ``*.dist-info/*``.

Skipping is recall-safe: each is a generated mirror of a scanned source
(serverless.yml, the package manifest) or pure integrity-hash data.
"""
from __future__ import annotations

import pytest

from services.secret_scan.engine import SecretScanner

# Real-shaped AWS key pair: WOULD flag on any *scanned* file, so an empty result
# proves the file itself was skipped (not that the content happened to be clean).
_SECRET = ("aws_access_key_id=AKIAZ7Q9XYZ12345WXYZ\n"
           "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYrealx9012")


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


def _rule_ids(scanner, path):
    return [f.rule_id for f in scanner.scan_file(path, _SECRET)]


@pytest.mark.parametrize("path", [
    "frontend/npm-shrinkwrap.json",
    "npm-shrinkwrap.json",
    "backend/src/functions/order-api/.serverless/serverless-state.json",
    "scenarios/x/lambda_source_code/lam_src/pytz-2021.1.dist-info/RECORD",
    "scenarios/x/lambda_source_code/lam_src/pytz-2021.1.dist-info/METADATA",
    "src/mypkg.egg-info/PKG-INFO",
])
def test_generated_file_fully_skipped(scanner, path):
    assert _rule_ids(scanner, path) == [], (
        f"generated/lockfile/build-artifact file was scanned (should be skipped): {path}"
    )


# Precision guard: a normal source/config file with the SAME content STILL flags
# — we excluded the artifacts, not the secret shape.
@pytest.mark.parametrize("path", [
    "cloudgoat/scenarios/x/terraform/config.tf",
    "src/app/config.py",
    "infra/main.json",
])
def test_normal_file_still_scanned(scanner, path):
    assert _rule_ids(scanner, path), (
        f"RECALL REGRESSION: a normal file stopped being scanned: {path}"
    )
