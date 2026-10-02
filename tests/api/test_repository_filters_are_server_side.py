# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""A filter that only searches the page you can see is not a filter.

Risk level and scan status were applied in the browser, to whichever
50 repositories had been loaded. Under that limit it looks correct;
above it, "show me the critical repositories" quietly omits the
critical repositories on page two — and that is the first question
anyone asks of this list, so a partial answer is worse than none.

Nothing errored and no count looked wrong, which is what made it
survive: the page simply showed fewer rows than it should have, and
fewer rows is what a filter is supposed to do.
"""
import inspect
import pathlib

import pytest

PAGE = pathlib.Path("apps/web/src/app/repositories/page.tsx")


def test_the_endpoint_takes_both_filters():
    from apps.api.app.routers.repositories import list_repositories
    params = set(inspect.signature(list_repositories).parameters)
    assert {"risk", "scan_status"} <= params


def test_the_page_sends_them_instead_of_filtering_locally():
    src = PAGE.read_text(encoding="utf-8")
    assert "params.risk = filterRisk" in src
    assert "params.scan_status = filterScanStatus" in src
    # The two client-side filter lines are gone.
    assert "items.filter((r) => getRisk(" not in src
    assert "repoStats[r.id]?.last_scan_status === filterScanStatus" not in src


def test_a_filter_change_refetches():
    """Sending the parameter is not enough — it has to be in the load
    callback's dependencies, or changing the filter leaves the old
    rows on screen."""
    src = PAGE.read_text(encoding="utf-8")
    deps = src[src.index("}, [page, serverSortBy"):]
    deps = deps[:deps.index("]")]
    assert "filterRisk" in deps
    assert "filterScanStatus" in deps


def test_risk_levels_are_mutually_exclusive():
    """Each rung excludes the ones above it, mirroring getRisk() in the
    page — otherwise a critical repository would also answer to
    "high" and the buckets would overlap."""
    src = pathlib.Path("apps/api/app/routers/repositories.py").read_text(encoding="utf-8")
    block = src[src.index('if risk == "critical"'):src.index('# ── Scan status')]
    assert "criticals > 0" in block
    assert "criticals == 0, highs > 0" in block
    assert "criticals == 0, highs == 0, total_findings > 0" in block
    assert "total_findings == 0" in block


def test_the_filter_counts_what_the_column_counts():
    """GET /{id}/stats counts every finding, not just open ones, and
    the Critical column shows that number. A filter using a different
    definition would disagree with the figure printed beside it."""
    src = pathlib.Path("apps/api/app/routers/repositories.py").read_text(encoding="utf-8")
    block = src[src.index("# ── Risk level"):src.index("# ── Scan status")]
    # No open/closed predicate in the filter, matching the stats query.
    assert "classification" not in block
    assert "is_open" not in block


def test_scan_status_matches_the_latest_scan():
    src = pathlib.Path("apps/api/app/routers/repositories.py").read_text(encoding="utf-8")
    block = src[src.index("# ── Scan status"):src.index("# Count total matching rows")]
    assert "order_by(ScanJob.created_at.desc())" in block
    assert "limit(1)" in block
