# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Dashboard risk metrics count OPEN findings, not every detection.

A headline that counts every row ever written is dominated by findings
triage has already settled, and every percentage that divides by it is
skewed the same way.

What counts as open is defined by exclusion: everything except the
classifications that mean "settled", plus anything suppressed. Defining
it that way means a classification added later counts as open until
someone decides otherwise — the failure mode is over-reporting, never a
false all-clear.

NEEDS_REVIEW is the load-bearing inclusion, pinned below. An
un-adjudicated finding is open work, and excluding it would make a scan
whose triage failed render as zero risk.

Three endpoints deliberately stay unfiltered: scanner comparison and
AI accuracy measure detection and triage behaviour (removing false
positives from an FP-rate calculation forces it to zero), and MTTR
averages over findings that completed remediation — a population the
open-only scope would exclude.
"""
import inspect

import pytest

from apps.api.app.models.finding import Classification
from apps.api.app.routers import metrics
from apps.api.app.routers.metrics import _CLOSED_CLASSIFICATIONS


OVERVIEW_SRC = inspect.getsource(metrics.metrics_overview)
FILTER_SRC = inspect.getsource(metrics._build_finding_filters)


# ── what counts as settled ───────────────────────────────────────────

@pytest.mark.parametrize("closed", [
    Classification.LIKELY_FALSE_POSITIVE,
    Classification.CONFIRMED_FALSE_POSITIVE,
    Classification.TEST_CREDENTIAL,
    Classification.ROTATED,
    Classification.ACCEPTED_RISK,
    Classification.RESOLVED_FILE_DELETED,
    Classification.RESOLVED_ITEM_DELETED,
    Classification.RESOLVED_REPO_REMOVED,
    Classification.RESOLVED_SOURCE_REMOVED,
])
def test_settled_classifications_are_excluded(closed):
    assert closed in _CLOSED_CLASSIFICATIONS


@pytest.mark.parametrize("open_state", [
    Classification.NEEDS_REVIEW,
    Classification.LIKELY_TRUE_POSITIVE,
    Classification.CONFIRMED_TRUE_POSITIVE,
    Classification.NOT_ENOUGH_EVIDENCE,
])
def test_unresolved_classifications_still_count(open_state):
    assert open_state not in _CLOSED_CLASSIFICATIONS


def test_needs_review_is_never_excluded():
    """The dangerous one: triage failing must not read as zero risk."""
    assert Classification.NEEDS_REVIEW not in _CLOSED_CLASSIFICATIONS


def test_every_classification_is_deliberately_placed():
    """A new classification must be considered, not silently inherited."""
    known_open = {
        Classification.NEEDS_REVIEW,
        Classification.LIKELY_TRUE_POSITIVE,
        Classification.CONFIRMED_TRUE_POSITIVE,
        Classification.NOT_ENOUGH_EVIDENCE,
    }
    for c in Classification:
        assert c in _CLOSED_CLASSIFICATIONS or c in known_open, (
            f"{c} is new — decide whether it is open risk or settled, and "
            f"add it to _CLOSED_CLASSIFICATIONS or to this test"
        )


# ── the filter itself ────────────────────────────────────────────────

def test_filter_is_opt_in_so_nothing_changes_silently():
    sig = inspect.signature(metrics._build_finding_filters)
    assert sig.parameters["open_only"].default is False


def test_suppressed_findings_are_excluded():
    assert "is_suppressed" in FILTER_SRC


def test_suppressed_filter_tolerates_null():
    """A NULL is_suppressed means 'not suppressed', not 'unknown'."""
    assert "is_suppressed.is_(None)" in FILTER_SRC


# ── which endpoints opt in ───────────────────────────────────────────

_RISK_ENDPOINTS = [
    "findings_by_category",
    "top_leaking_repos",
    "findings_metrics",
    "finding_trends",
    "findings_breakdown",
]


@pytest.mark.parametrize("fn_name", _RISK_ENDPOINTS)
def test_risk_endpoints_count_open_findings(fn_name):
    fn = getattr(metrics, fn_name, None)
    assert fn is not None, (
        f"{fn_name} not found — if it was renamed, update this list; a "
        f"skip here would leave a risk endpoint unverified"
    )
    assert "open_only=True" in inspect.getsource(fn), (
        f"{fn_name} presents risk, so it must count open findings"
    )


def test_scanner_comparison_stays_unfiltered():
    """It computes FP rates — filtering FPs out forces them to zero."""
    src = inspect.getsource(metrics.scanner_comparison)
    assert "open_only=True" not in src


def test_mttr_stays_unfiltered():
    """MTTR averages over findings that COMPLETED remediation. A finding
    that finished its lifecycle (patched, then rotated/resolved) is the
    population — the open-only scope would remove it and hollow the
    metric out as the remediation flow starts actually closing things."""
    src = inspect.getsource(metrics.mttr_metrics)
    assert "open_only=True" not in src


# ── the overview response ────────────────────────────────────────────

def test_headline_and_severity_share_one_scope():
    """The tiles reconcile only if both read the same conditions."""
    assert "_build_finding_filters(db, user, open_only=True)" in OVERVIEW_SRC


def test_detection_volume_is_reported_separately():
    assert '"detected_total"' in OVERVIEW_SRC
    assert '"filtered_as_noise"' in OVERVIEW_SRC


def test_noise_count_cannot_go_negative():
    assert "max(_detected - _open, 0)" in OVERVIEW_SRC


def test_remediation_coverage_shares_the_headline_scope():
    """A percentage only means something when numerator and denominator
    share a scope. The standalone /remediation endpoint counts patches
    all-time across every classification; dividing that by the windowed
    open headline inflated the tile and could push it past 100%."""
    assert '"remediation_covered"' in OVERVIEW_SRC
    assert '"remediation_applied"' in OVERVIEW_SRC
    for anchor in ("_covered_q = await db.execute", "_applied_q = await db.execute"):
        m = OVERVIEW_SRC.find(anchor)
        assert m > 0, f"{anchor} not found"
        segment = OVERVIEW_SRC[m:m + 450]
        assert "*conditions," in segment, (
            "remediation counts must use the open+window `conditions`, "
            "not `all_conditions`"
        )


def test_covered_means_a_real_patch_exists():
    """"Covered" claims a fix was drafted, so it is counted from the
    patch artifacts, not the status column — a status flag can exist
    without the artifact behind it, and a patch whose diff is empty is
    not a draft either."""
    assert "_has_real_patch" in OVERVIEW_SRC
    assert "RemediationPatch.plan_id == RemediationPlan.id" in OVERVIEW_SRC
    assert 'func.length(func.coalesce(RemediationPatch.patch_diff, "")) > 20' in OVERVIEW_SRC
    # Both counts must require the artifact, not just the flag.
    for anchor in ("_covered_q = await db.execute", "_applied_q = await db.execute"):
        m = OVERVIEW_SRC.find(anchor)
        assert "_has_real_patch" in OVERVIEW_SRC[m:m + 450], (
            f"{anchor} does not require an actual patch"
        )


def test_covered_no_longer_trusts_the_status_flag_alone():
    m = OVERVIEW_SRC.find("_covered_q = await db.execute")
    segment = OVERVIEW_SRC[m:m + 450]
    assert "PATCH_GENERATED" not in segment, (
        "covered must be artifact-based; the status flag lies"
    )


def test_mttr_counts_only_actual_resolutions():
    """Resolved means the fix landed (applied) or the finding reached a
    resolved classification (rotated / removed) — a drafted or approved
    patch has remediated nothing yet."""
    src = inspect.getsource(metrics.mttr_metrics)
    assert '"patch_generated"' not in src and '"approved"' not in src, (
        "a drafted or approved patch has remediated nothing"
    )
    assert '== "applied"' in src
    assert "Classification.ROTATED" in src
    assert "RESOLVED_FILE_DELETED" in src


def test_needs_review_count_matches_the_queue_it_links_to():
    """The quick-action chip links to the review queue, which shows
    unsuppressed findings — so the count must be open-scoped, not read
    off the unfiltered classification breakdown."""
    assert '"needs_review_open"' in OVERVIEW_SRC
    m = OVERVIEW_SRC.find("_needs_review_q = await db.execute")
    assert m > 0
    assert "*conditions," in OVERVIEW_SRC[m:m + 350]


def test_classification_breakdown_is_not_filtered_by_classification():
    """Filtering it would erase the categories it exists to show."""
    # Anchor on the query, not the word — it also appears in the
    # endpoint's docstring.
    m = OVERVIEW_SRC.find("by_classification = await db.execute")
    assert m > 0, "classification breakdown query not found"
    segment = OVERVIEW_SRC[m:m + 400]
    assert "all_conditions" in segment
    assert "*conditions)" not in segment


def test_previous_period_uses_the_same_scope():
    """A delta between two differently-scoped counts is not a delta."""
    m = OVERVIEW_SRC.find("prev_conditions = await _build_finding_filters")
    assert m > 0
    assert "open_only=True" in OVERVIEW_SRC[m:m + 120]


def test_window_cutoff_applies_to_both_scopes():
    """Otherwise the noise rate mixes a windowed count with an all-time one."""
    m = OVERVIEW_SRC.find("if days is not None:")
    segment = OVERVIEW_SRC[m:m + 400]
    assert "conditions.append(NormalizedFinding.created_at >= cutoff)" in segment
    assert "all_conditions.append(NormalizedFinding.created_at >= cutoff)" in segment
