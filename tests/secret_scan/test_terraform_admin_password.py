"""R4 — Terraform admin-password attributes with literal values are flagged.

terragoat ships hardcoded Azure/AWS admin passwords like
``administrator_login_password = "AdminPassword123!"``. The 20-repo Opus×Vooda
benchmark (run against a stale worker module) reported terragoat's 7
``AdminPassword123!`` literals as missed, but the committed engine's GEN-003
already catches them — the attribute name ends in ``password``, so the generic
password rule fires. This locks that recall, plus the precision guard that
var-refs / random_password / ``${...}`` interpolations are NOT flagged.
"""
from __future__ import annotations

import pytest

from services.secret_scan.engine import SecretScanner


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


def _fires(scanner, content):
    return bool(scanner.scan_file("terraform/azure/sql.tf", content))


# Hardcoded literal admin passwords → must be flagged.
@pytest.mark.parametrize("content", [
    'administrator_login_password = "AdminPassword123!"',
    'administrator_login_password = "Aa12345678"',
    'admin_password = "P@ssw0rdVm123!"',
    'master_password = "MyR0otP4ssword9"',
    'rds_password = "Sup3rRdsPassw0rd1"',
])
def test_tf_literal_admin_password_flagged(scanner, content):
    assert _fires(scanner, content), f"missed TF admin password literal: {content!r}"


# Variable refs / generated passwords / interpolations are NOT secrets → []
@pytest.mark.parametrize("content", [
    'administrator_login_password = var.db_password',
    'administrator_login_password = random_password.x.result',
    'admin_password = "${var.secret}"',
    'admin_password = local.pw',
])
def test_tf_admin_password_reference_not_flagged(scanner, content):
    assert not _fires(scanner, content), f"FALSE POSITIVE on a non-literal: {content!r}"
