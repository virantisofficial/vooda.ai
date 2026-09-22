# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Phase 3: the lifecycle is the API's contract, not an internal detail.

Closing a finding requires a reason, and the reason the operator chose
is the reason that gets stored. The legacy Classification enum is
coarser than the reason vocabulary — mitigating_control and
acceptable_risk both collapse to ACCEPTED_RISK, revoked and rotated both
to ROTATED — so deriving the reason back from the classification
silently flattened the operator's actual disposition while returning
200 OK.
"""
import pathlib
import re

ROUTER = pathlib.Path("apps/api/app/routers/findings.py")
SCHEMA = pathlib.Path("apps/api/app/schemas/finding.py")
WEB = pathlib.Path("apps/web/src/app/findings/page.tsx")


def test_close_actions_require_a_reason():
    src = ROUTER.read_text(encoding="utf-8")
    assert "requires a resolution_reason" in src
    assert '_classification_for_close' in src


def test_the_operator_choice_is_not_flattened_by_the_legacy_enum():
    """The regression: an explicit reason must override the one derived
    from the coarser classification."""
    src = ROUTER.read_text(encoding="utf-8")
    assert "finding.resolution_reason = explicit_reason.value" in src


def test_a_legacy_action_rejects_a_redundant_reason():
    """mark_fp already implies its reason; accepting a conflicting one
    would let the stored reason disagree with the action taken."""
    src = ROUTER.read_text(encoding="utf-8")
    assert "already implies its resolution" in src


def test_every_reason_is_reachable_through_the_api():
    """A reason the API cannot express is a reason that does not exist.
    The fixed action set could not express mitigating_control at all —
    that gap is what motivated the generic close actions."""
    from apps.api.app.core.finding_status import (
        REASONS_FOR, FindingStatus, ResolutionReason,
    )
    src = ROUTER.read_text(encoding="utf-8")
    mapping = src[src.index("_CLOSE_REASON_TO_CLASSIFICATION = {"):]
    mapping = mapping[:mapping.index("}")]
    for reason in ResolutionReason:
        assert f'"{reason.value}"' in mapping, (
            f"{reason.value} has no route to a stored classification"
        )
    # and each is offered by the UI
    web = WEB.read_text(encoding="utf-8")
    for reason in ResolutionReason:
        assert f'value="{reason.value}"' in web, (
            f"{reason.value} is not offered in the findings filter"
        )
    assert set(REASONS_FOR[FindingStatus.RESOLVED]) | set(
        REASONS_FOR[FindingStatus.DISMISSED]) == set(ResolutionReason)


def test_the_list_endpoint_filters_on_the_lifecycle():
    src = ROUTER.read_text(encoding="utf-8")
    for clause in ("NormalizedFinding.status == status.lower()",
                   "NormalizedFinding.resolution_reason ==",
                   "NormalizedFinding.ai_verdict =="):
        assert clause in src, clause


def test_the_legacy_filter_is_marked_deprecated_not_removed():
    """Deep links and integrations still send it."""
    src = ROUTER.read_text(encoding="utf-8")
    m = re.search(r"classification: Optional\[str\] = Query\(\s*None,\s*deprecated=True", src)
    assert m, "classification filter should remain, marked deprecated"


def test_the_api_returns_the_lifecycle():
    src = SCHEMA.read_text(encoding="utf-8")
    for field in ("status: str", "resolution_reason: Optional[str]",
                  "resolved_at: Optional[datetime]", "ai_verdict: Optional[str]"):
        assert field in src, field


def test_the_ui_no_longer_offers_the_thirteen_value_list():
    """The single select fused four questions into one control."""
    web = WEB.read_text(encoding="utf-8")
    assert 'value="confirmed_false_positive"' not in web
    assert 'value="likely_false_positive"' not in web
    for st in ("open", "triaging", "resolved", "dismissed"):
        assert f'value="{st}"' in web, st


def test_reason_filter_is_scoped_to_closing_statuses():
    """Offering reasons beside `open` would present combinations that
    can never match a row — the CHECK constraint forbids them."""
    web = WEB.read_text(encoding="utf-8")
    assert 'filters.status === "resolved" || filters.status === "dismissed"' in web
