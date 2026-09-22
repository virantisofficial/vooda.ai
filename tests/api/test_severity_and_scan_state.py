# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Severity and scan status: one vocabulary, enforced by the database.

Both repeated the validity pattern — a typed enum existed, and a
parallel unconstrained ``String`` column sat beside it accepting
anything. Severity was worse: the PG enum stores the member NAME
('CRITICAL') while the incident table stores the value ('critical'), so
the same concept compared unequal across two tables.
"""
import pathlib
import re

from apps.api.app.core.severity import RANK, Severity, normalize, rank

MIGRATION = pathlib.Path(
    "apps/api/alembic/versions/m9h0i1j2k3l4_constrain_severity_and_scan_status.py"
)


def test_case_does_not_change_meaning():
    """The exact mismatch that existed between the two tables."""
    assert normalize("CRITICAL") is Severity.CRITICAL   # PG enum name
    assert normalize("critical") is Severity.CRITICAL   # varchar value
    assert normalize("Critical") is Severity.CRITICAL
    assert normalize("  HIGH ") is Severity.HIGH


def test_severity_never_sorts_lexically():
    """'high' > 'critical' alphabetically — the bug severity_rank exists
    to avoid. Rank must order by actual risk."""
    assert rank("critical") > rank("high") > rank("medium") > rank("low") > rank("info")
    assert sorted(Severity, key=lambda s: -RANK[s])[0] is Severity.CRITICAL


def test_an_unreadable_severity_never_becomes_critical():
    """An uninterpretable value must not drown the queue by claiming to
    be the most urgent thing in it."""
    assert normalize("wat") is Severity.INFO
    assert normalize(None) is Severity.INFO
    assert normalize("") is Severity.INFO


def test_incumbent_severity_spellings_import():
    assert normalize("blocker") is Severity.CRITICAL
    assert normalize("major") is Severity.HIGH
    assert normalize("moderate") is Severity.MEDIUM
    assert normalize("minor") is Severity.LOW
    assert normalize("informational") is Severity.INFO


def test_migration_and_runtime_normaliser_agree():
    sql = MIGRATION.read_text(encoding="utf-8")
    pairs = re.findall(r"WHEN '([a-z_]+)'\s+THEN '([a-z_]+)'", sql)
    assert pairs, "could not parse the migration's CASE expression"
    for legacy, target in pairs:
        assert normalize(legacy).value == target, (
            f"migration maps {legacy!r} -> {target!r}, "
            f"normalize() gives {normalize(legacy).value!r}"
        )


def test_the_dead_parallel_validation_engine_is_gone():
    """services/secret_validation was instantiated and never called.

    It carried a competing six-value status vocabulary and its
    validators used httpx directly, bypassing the egress guard, rate
    limiter and tenant context that secret_verification enforces.
    """
    assert not pathlib.Path("services/secret_validation").exists()
    offenders = []
    for root in ("apps", "services", "tests"):
        for path in pathlib.Path(root).rglob("*.py"):
            # validity.py and this file both name the package in prose.
            if "__pycache__" in path.parts or path.name in (
                "validity.py", pathlib.Path(__file__).name,
            ):
                continue
            src = path.read_text(encoding="utf-8", errors="replace")
            if "services.secret_validation" in src:
                offenders.append(str(path))
    assert not offenders, f"still importing the deleted package: {offenders}"


def test_outbound_verification_goes_through_the_guarded_client():
    """Any new verifier must not reach the network directly."""
    verifier = pathlib.Path("services/secret_verification/verifier.py")
    src = verifier.read_text(encoding="utf-8")
    assert "egress" in src or "http_client" in src, (
        "the verifier must use the egress-guarded HTTP client"
    )
