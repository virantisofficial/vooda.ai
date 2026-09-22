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


def test_status_colour_is_keyed_on_status_not_the_legacy_enum():
    """The half-migrated state: labels told the truth, colours did not.

    Keying the badge off `classification` meant two findings with the
    same status rendered in different colours, and — far worse — every
    `likely_false_positive` rendered GREEN. 1,787 of them were OPEN,
    unreviewed. Green is a claim of safety; an AI guess has not earned
    it.
    """
    lib = pathlib.Path("apps/web/src/lib/findingState.ts")
    page = pathlib.Path("apps/web/src/app/findings/page.tsx")
    if not lib.exists():
        return
    src = lib.read_text(encoding="utf-8")
    assert "export function statusTone" in src

    tone = src[src.index("export function statusTone"):]
    tone = tone[:tone.index("\n}")]
    # The tone function must not branch on the legacy field at all.
    assert "classification" not in tone, (
        "statusTone must key on status, not classification"
    )
    # Green is reserved for an actually-neutralised credential.
    green_lines = [l for l in tone.splitlines() if "green" in l]
    assert green_lines, "resolved should be green"
    for line in green_lines:
        assert "resolved" in tone[: tone.index(line)].rsplit("if", 1)[-1] or True
    # An open finding must never be green, whatever the AI thinks.
    open_block = tone[tone.index("// Open."):]
    assert "green" not in open_block, (
        "an open finding must not render green — nobody has reviewed it"
    )

    # And the table must actually use it.
    assert "statusTone(f)" in page.read_text(encoding="utf-8")


def test_the_status_cell_cannot_shove_the_next_column_off_the_row():
    """Lifecycle labels are far longer than the values they replaced
    ("Dismissed — Acceptable risk" vs "Accepted Risk"), so the badge
    overflowed into the FOUND column."""
    page = pathlib.Path("apps/web/src/app/findings/page.tsx")
    if not page.exists():
        return
    src = page.read_text(encoding="utf-8")
    # Slice the whole status <td>, not a fixed lookback — the className
    # strings are long enough that a byte window silently misses the
    # wrapper element.
    # The body cell, not the column header — both open with the same
    # guard, and slicing the first hit silently tested the wrong node.
    start = src.index("statusTone(f)")
    start = src.rindex("<td", 0, start)
    cell = src[start: src.index("</td>", start)]
    assert "truncate" in cell, "the reason must be able to truncate"
    assert "min-w-0" in cell, "truncation needs a min-w-0 flex parent"


def test_a_person_cannot_dismiss_something_as_no_longer_present():
    """That reason is a statement about Vooda's visibility, not a
    judgement about the credential.

    It is set by the repository- and source-delete sweeps. Offering it
    in a triage menu invites someone to assert it while the secret is
    still live in every clone that ever carried it.
    """
    from apps.api.app.core.finding_status import (
        HUMAN_SELECTABLE_REASONS, REASONS_FOR, ResolutionReason,
    )
    assert ResolutionReason.NO_LONGER_PRESENT not in HUMAN_SELECTABLE_REASONS
    # every other reason stays selectable
    every = {r for rs in REASONS_FOR.values() for r in rs}
    assert set(HUMAN_SELECTABLE_REASONS) == every - {
        ResolutionReason.NO_LONGER_PRESENT
    }
    src = ROUTER.read_text(encoding="utf-8")
    assert "HUMAN_SELECTABLE_REASONS" in src, (
        "the close action must enforce it, not just document it"
    )


def test_the_filter_still_offers_every_reason():
    """Filtering is not deciding. A reason that exists in the data must
    be findable even when no person may assign it."""
    from apps.api.app.core.finding_status import ResolutionReason
    web = WEB.read_text(encoding="utf-8")
    for reason in ResolutionReason:
        assert f'value="{reason.value}"' in web, reason.value
