"""Regression tests for normalize_severity — the single shared severity
normalizer used by BOTH the server storing loop and the CLI/CI findings-import
worker.

Guards QA bug B5: a finding imported with no `severity` (valid — the field is
optional on the import surface) previously crashed the worker with
`'NoneType' object has no attribute 'lower'`, FAILING the whole import batch
*after* a 202 and silently losing the findings. normalize_severity must never
raise on None / "" / a non-string; it defaults to MEDIUM.
"""
from __future__ import annotations

import pytest

from services.normalization.normalizer import normalize_severity
from apps.api.app.models.finding import Severity


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, Severity.MEDIUM),        # B5: the bug — must not crash
        ("", Severity.MEDIUM),
        (123, Severity.MEDIUM),          # non-string
        ([], Severity.MEDIUM),
        ("critical", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("  Medium  ", Severity.MEDIUM),
        ("informational", Severity.INFO),
        ("bogus", Severity.MEDIUM),      # unknown → default
    ],
)
def test_normalize_severity_never_crashes(raw, expected):
    assert normalize_severity(raw) == expected
