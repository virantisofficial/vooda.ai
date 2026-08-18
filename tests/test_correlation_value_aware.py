"""Correlation must be VALUE-AWARE before collapsing same-scanner findings.

Regression for the credential-pair bug: an AWS access-key id (AWS-001) and its
secret access key (AWS-005) sit on adjacent lines, same category, same scanner.
The old logic declared *any* same-scanner cluster "duplicates" and suppressed
all but one — so the access-key id vanished from the dashboard and the
AI-triage calibration counted 1 finding instead of 2. They are DISTINCT secrets
and must both survive (correlated). Only findings sharing the SAME secret value
are true duplicates and collapse to one.
"""
from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace

from services.correlation.engine import correlate_findings


def _finding(secret_hash, line, description):
    return SimpleNamespace(
        id=uuid.uuid4(), file_path="log-upload.php", line_start=line, line_end=line,
        cwe="CWE-798", vulnerability_category="secret", scanner_name="vooda_secret_scan",
        confidence=0.9, description=description,
        source_metadata={"secret_hash": secret_hash},
        fingerprint=secret_hash, stability_id=secret_hash,
        is_suppressed=False, suppression_reason=None,
        correlation_group_id=None, correlated_finding_ids=None,
        is_correlation_primary=False, aggregate_confidence=None,
    )


class _Result:
    def __init__(self, findings): self._f = findings
    def scalars(self): return self
    def all(self): return self._f


class _FakeDB:
    """Minimal async DB stub: execute() returns the findings, flush() no-ops."""
    def __init__(self, findings): self._f = findings
    async def execute(self, query): return _Result(self._f)
    async def flush(self): pass


def _correlate(findings):
    asyncio.run(correlate_findings(_FakeDB(findings), uuid.uuid4()))
    return findings


def test_credential_pair_not_suppressed():
    # access-key id + secret access key: DIFFERENT values, adjacent lines.
    pair = [
        _finding("AKIA_HASH", 10, "AWS Access Key ID"),
        _finding("SECRET_HASH", 11, "AWS Secret Access Key (SDK credential block)"),
    ]
    _correlate(pair)
    assert all(not f.is_suppressed for f in pair), "a credential pair must not be collapsed"
    assert pair[0].correlation_group_id is not None
    assert pair[0].correlation_group_id == pair[1].correlation_group_id, "pair should be correlated"


def test_true_duplicate_is_collapsed():
    # SAME secret value detected twice -> exactly one survives (best description).
    dup = [
        _finding("SAME", 10, "short"),
        _finding("SAME", 10, "a much longer, more detailed description"),
    ]
    _correlate(dup)
    assert sum(f.is_suppressed for f in dup) == 1, "true duplicates must collapse to one"
    survivor = [f for f in dup if not f.is_suppressed][0]
    assert survivor.description == "a much longer, more detailed description"
    suppressed = [f for f in dup if f.is_suppressed][0]
    assert suppressed.suppression_reason == "duplicate_same_scanner"
