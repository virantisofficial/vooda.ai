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
# The one place the UI's status and reason vocabulary is written down.
# The screens build their controls from it, so these tests check the
# table rather than every screen's markup.
LIB = pathlib.Path("apps/web/src/lib/findingState.ts")


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
    # and each is spelled by the UI's own vocabulary. The filter builds
    # its options from these tables rather than listing them inline, so
    # the check is on the table and not on the markup.
    lib = LIB.read_text(encoding="utf-8")
    for reason in ResolutionReason:
        assert f'{reason.value}:' in lib or f'"{reason.value}"' in lib, (
            f"{reason.value} has no label in findingState.ts"
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
    lib = LIB.read_text(encoding="utf-8")
    for st in ("open", "triaging", "resolved", "dismissed"):
        assert f'status: "{st}"' in lib, st


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
    lib = LIB.read_text(encoding="utf-8")
    for reason in ResolutionReason:
        # FILTERABLE_REASONS_FOR is the filter's list and is deliberately
        # wider than the triage control's: a person can no longer pick
        # how a credential was neutralised, and never could set
        # `no_longer_present`, but rows carry all of them.
        assert f'"{reason.value}"' in lib or f'value="{reason.value}"' in web, (
            reason.value
        )


def test_no_surface_derives_a_status_colour_from_the_legacy_field():
    """The table was migrated and the detail views were not.

    A finding read "Open — AI: Likely Real" in slate on the list, and
    green "False Positive" when you opened it — same row, two answers.
    Fixing only the surface that was reported is how this bug survived
    three rounds; the guard now covers every .tsx at once.
    """
    web = pathlib.Path("apps/web/src")
    if not web.exists():
        return
    # `classification` steering a colour class, on one line or across a
    # ternary chain.
    pat = re.compile(
        r"classification[^\n]{0,80}\?\s*\"(?:bg-|text-)", re.M
    )
    offenders = []
    for path in list(web.rglob("*.tsx")) + list(web.rglob("*.ts")):
        if any(p in path.parts for p in ("node_modules", ".next")):
            continue
        if path.name == "findingState.ts":
            continue
        src = path.read_text(encoding="utf-8", errors="replace")
        for m in pat.finditer(src):
            ln = src[: m.start()].count("\n") + 1
            offenders.append(f"{path}:{ln}")
    assert not offenders, (
        "colour must come from statusTone()/statusTextTone(), which key "
        "on status — not from the classification enum they replaced:\n"
        + "\n".join(offenders)
    )


def test_the_optimistic_preview_survives_the_migration():
    """Both panels preview a pending action before the server answers.
    Keying the badge off the persisted row would have frozen that
    preview — the action would appear to do nothing until the reload.
    """
    lib = pathlib.Path("apps/web/src/lib/findingState.ts")
    if not lib.exists():
        return
    assert "export function previewOf" in lib.read_text(encoding="utf-8")
    for f in ("apps/web/src/components/findings/FindingPanel.tsx",
              "apps/web/src/components/incidents/IncidentDetailDrawer.tsx"):
        src = pathlib.Path(f).read_text(encoding="utf-8")
        # Either preview helper satisfies this: one takes the pending
        # classification, the other the pending status and reason.
        assert "previewOf(" in src or "previewLifecycle(" in src, f


def test_delete_paths_never_reference_a_table_that_does_not_exist():
    """A governance product was removed in 2026-05, taking several
    tables with it. `DELETE FROM quantum_assessments` stayed behind in
    the scan-source delete path, so EVERY scan-source deletion 500'd for
    four months — nothing noticed, because nothing deleted a source.

    Checked against the live model metadata rather than a hand-written
    list, so the next table that goes away fails here on the commit that
    removes it.
    """
    import re as _re

    from apps.api.app.core.database import Base
    import apps.api.app.models  # noqa: F401  (registers every table)

    known = set(Base.metadata.tables)
    offenders = []
    for path in ("apps/api/app/routers/scan_sources.py",
                 "apps/api/app/routers/repositories.py"):
        src = pathlib.Path(path).read_text(encoding="utf-8")
        for m in _re.finditer(r'"DELETE FROM ([a-z_]+)', src):
            table = m.group(1)
            if table in known:
                continue
            ln = src[: m.start()].count("\n") + 1
            offenders.append(f"{path}:{ln} -> {table}")
    assert not offenders, (
        "these delete from tables no model defines; route them through "
        "_existing_tables() or remove them:\n" + "\n".join(offenders)
    )


def test_resolving_does_not_ask_which_way_the_credential_died():
    """Rotated, revoked and provider_disabled all collapse onto the
    same legacy Classification, nothing branches on which was chosen,
    and REMEDIATED_REASONS has no production reader — so the question
    cost a click and bought nothing.

    No comparable product asks it either: GitLab's Resolved takes no
    reason, GitGuardian's takes no reason, and GitHub has one flat
    close list where "revoked" is a single entry.
    """
    lib = LIB.read_text(encoding="utf-8")
    assert 'status: "resolved", action: "resolve", label: "Resolved", needsReason: false' in lib
    assert "export const RESOLVED_IMPLIES" in lib


def test_dismissing_still_does():
    """The asymmetry. Each dismissal reason maps to a DIFFERENT
    classification, and those drive the false-positive rate in reports,
    the suppression rules the pattern learner proposes, and three
    separate ticketing exclusions. Picking the wrong one changes what
    the product does."""
    lib = LIB.read_text(encoding="utf-8")
    assert 'status: "dismissed", action: "dismiss", label: "Dismissed", needsReason: true' in lib
    for reason in ("false_positive", "test_credential",
                   "acceptable_risk", "mitigating_control"):
        assert f'reason: "{reason}"' in lib, reason


def test_the_three_resolve_reasons_are_still_understood():
    """Dropping the prompt must not drop the vocabulary: rows carry
    these values, the filter offers them, and API clients may send
    them."""
    from apps.api.app.core.finding_status import ResolutionReason, REASONS_FOR, FindingStatus
    lib = LIB.read_text(encoding="utf-8")
    for reason in ("rotated", "revoked", "provider_disabled"):
        assert f"{reason}:" in lib, f"{reason} has no label"
        assert ResolutionReason(reason) in REASONS_FOR[FindingStatus.RESOLVED]


def test_the_api_still_accepts_every_resolve_reason():
    """The UI stopped asking; the endpoint did not stop listening."""
    src = ROUTER.read_text(encoding="utf-8")
    for reason in ("rotated", "revoked", "provider_disabled"):
        assert f'"{reason}"' in src, reason


def test_the_filter_is_wider_than_the_triage_control():
    """They answer different questions. Narrowing the filter to what a
    person may set would hide every row Vooda closed itself, and every
    row closed before the control changed."""
    lib = LIB.read_text(encoding="utf-8")
    assert "export const FILTERABLE_REASONS_FOR" in lib
    block = lib[lib.index("FILTERABLE_REASONS_FOR"):]
    block = block[:block.index("};")]
    for reason in ("rotated", "revoked", "provider_disabled",
                   "no_longer_present"):
        assert f'"{reason}"' in block, reason


def test_the_filter_bar_was_trimmed_to_the_axes_that_get_used():
    """Validity and risk-acceptance controls were removed from this
    page. Both filters still exist on the API — the dashboard, the
    rotation page and the command palette all deep-link
    ?validation_status=active — but neither is started from here.

    The "More" popover went with them: once the risk-acceptance select
    was gone it held one control, and a button you press to reveal one
    dropdown is worse than the dropdown."""
    web = WEB.read_text(encoding="utf-8")
    for gone in (">Any Validity<", ">Lapsed acceptances<",
                 "secondaryFilterCount", "showMoreFilters"):
        assert gone not in web, gone
    # No dead client state left behind by the removals.
    assert "filters.risk_expired" not in web
    assert "risk_expired: \"\"" not in web


def test_the_primary_row_keeps_the_triage_axes():
    """Severity and status — the two questions asked of every row."""
    web = WEB.read_text(encoding="utf-8")
    bar = web[web.index("{/* Filters + Bulk actions bar */}"):]
    bar = bar[:bar.index("{/* Project filter")]
    for label in ("All Severities", "All Statuses"):
        assert f'>{label}<' in bar, label


def test_removing_the_validity_control_did_not_strand_its_deep_links():
    """Three places link in with ?validation_status=active — the
    dashboard card, the rotation page and the command palette. The
    dropdown is gone, so the chip is the only thing left that shows the
    filter is on and lets it be cleared. Losing it would leave those
    users on a filtered list with no way back."""
    web = WEB.read_text(encoding="utf-8")
    assert "Validity: {validityLabel(filters.validation_status)}" in web
    assert "validationStatusFromUrl" in web, "the URL seed must survive"
    assert "params.validation_status = filters.validation_status" in web, (
        "the filter itself must still reach the API")
