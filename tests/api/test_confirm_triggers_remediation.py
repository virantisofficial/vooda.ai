# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Triage never auto-generates a fix — generation is on-demand only.

For a leaked secret the remediation is revoke + rotate; a code patch is
a deliberate, per-incident request, not a side effect of recording a
triage verdict. Firing a model call on every confirmation does not
scale to an enterprise's finding volume, and no secret-scanning tool
works that way. Fix drafting happens only through the explicit
per-finding "Generate fix" action.
"""
import inspect

from apps.api.app.routers import findings


def test_single_triage_does_not_auto_generate():
    src = inspect.getsource(findings.triage_finding)
    assert "generate_remediation" not in src, (
        "confirming a finding must not fire a model call; drafting is "
        "on-demand via the per-finding action"
    )


def test_bulk_triage_does_not_auto_generate():
    """The scale invariant: bulk-confirming N findings must never fan
    out into N model calls."""
    src = inspect.getsource(findings.bulk_triage_findings)
    assert "generate_remediation" not in src


def test_the_on_demand_endpoint_still_exists():
    """Generation stays available — explicitly, per finding."""
    src = inspect.getsource(findings)
    assert "async def request_remediation" in src
    assert "generate_remediation.delay" in inspect.getsource(findings.request_remediation)
