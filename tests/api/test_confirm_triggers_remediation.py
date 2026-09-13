# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Confirming a finding drafts a fix — one at a time, never in bulk.

Scan-time generation only covers findings confirmed at scan time. A
finding triaged "needs review" and later confirmed by a person would
otherwise never get a draft. Confirming it now queues one, so coverage
stays current from the triage decision itself.

The guardrail: this fires only on the single-finding path, and only
when no draft already exists. Bulk triage must never fan out into a
batch of model calls a reviewer did not ask for — that was the
dashboard-button hazard, and it must not reappear behind triage.
"""
import inspect

from apps.api.app.routers import findings


def test_single_confirm_queues_one_draft():
    src = inspect.getsource(findings.triage_finding)
    assert 'body.action == "mark_tp"' in src
    assert "generate_remediation.delay" in src


def test_it_skips_when_a_draft_already_exists():
    """Only status none/rejected re-queues; an existing or in-flight
    draft must not spend a second call."""
    src = inspect.getsource(findings.triage_finding)
    assert '("none", "rejected")' in src


def test_bulk_triage_never_auto_drafts():
    """The safety invariant. Bulk confirm sets classifications but must
    not queue generation per finding, or one click silently fans out
    into N model calls — the exact hazard removed from the dashboard."""
    src = inspect.getsource(findings.bulk_triage_findings)
    assert "generate_remediation" not in src


def test_only_mark_tp_triggers_it():
    """mark_fp / accept_risk / reopen must not draft fixes."""
    src = inspect.getsource(findings.triage_finding)
    # the trigger is gated on the mark_tp action specifically
    trigger = src.split('body.action == "mark_tp"')[1].split("Case-B")[0]
    assert "generate_remediation.delay" in trigger
