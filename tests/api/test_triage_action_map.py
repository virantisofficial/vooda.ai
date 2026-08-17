"""Triage endpoint action_map coverage tests.

Bug discovered 2026-05-04: the findings UI dropdown exposed two
actions (`mark_rotated`, `mark_test`) that weren't in the backend
``action_map``. Clicking them returned a 200 but did NOT change the
finding's classification — the action key fell through to ``None``,
the ``if new_class:`` guard skipped the assignment, and the column
kept its previous value.

These tests guard against regressions in BOTH directions:

  1. Every action exposed in the UI dropdown is wired in the backend
     ``action_map`` (catches "added a button, forgot the backend").

  2. Every entry in ``action_map`` resolves to either a valid
     ``Classification`` enum member or to ``None`` (the explicit
     no-class-change sentinel, used by ``request_review``).

  3. The two specific closure-state values (``ROTATED`` and
     ``TEST_CREDENTIAL``) are present on the ``Classification`` enum
     with the expected names + values — a stronger assertion than
     just "the action_map has them" because it catches a future
     refactor that renames the enum members but forgets to update
     the action_map references.

Pure unit tests — no DB, no FastAPI test client. The action_map is a
plain dict at module scope so we can introspect it directly.
"""
from __future__ import annotations

from apps.api.app.models.finding import Classification


# ── The set of actions the UI dropdown exposes ────────────────
# Mirrors apps/web/src/components/findings/FindingPanel.tsx
# (the `[{action: ...}]` array around line 1514). Keep this in
# sync if the UI gains another dropdown option — the test will
# fail loudly if the backend forgets to wire a new action.
UI_DROPDOWN_ACTIONS = {
    "reopen",
    "mark_tp",
    "mark_rotated",
    "mark_fp",
    "mark_test",
    "accept_risk",
}


# ── Re-derive the action_map from the router source ───────────
# We don't import the router function (would require setting up the
# whole FastAPI app + DB). Instead we re-state the expected map and
# test that the live router code matches it via a textual check.

EXPECTED_ACTION_MAP = {
    "mark_fp": Classification.CONFIRMED_FALSE_POSITIVE,
    "mark_tp": Classification.CONFIRMED_TRUE_POSITIVE,
    "accept_risk": Classification.ACCEPTED_RISK,
    "reopen": Classification.NEEDS_REVIEW,
    "request_review": None,
    "mark_rotated": Classification.ROTATED,
    "mark_test": Classification.TEST_CREDENTIAL,
}


def _extract_router_action_map() -> dict:
    """Pull the action_map dict out of the live router source.

    Avoids importing the full router (which would pull in FastAPI +
    DB session deps + transitive model registration). Reads the
    source file as text and finds the literal dict — simpler and
    cheaper than a fixture, and the failure mode if the router
    refactors away from a literal dict is "test fails loudly", which
    is the right signal.
    """
    import re
    from pathlib import Path

    router_path = (
        Path(__file__).resolve().parents[2]
        / "apps" / "api" / "app" / "routers" / "findings.py"
    )
    src = router_path.read_text()
    # Match `action_map = { ... }` (multi-line). The dict lives in
    # the triage_finding endpoint, ~line 268.
    m = re.search(
        r"action_map\s*=\s*\{([^}]*)\}",
        src,
        re.DOTALL,
    )
    assert m is not None, "Could not locate action_map literal in findings.py"
    body = m.group(1)
    # Pull out every `"key": Classification.VALUE,` (or `: None,`)
    entries = re.findall(
        r'"(\w+)"\s*:\s*(?:Classification\.(\w+)|None)',
        body,
    )
    out: dict = {}
    for key, attr in entries:
        out[key] = getattr(Classification, attr) if attr else None
    return out


# ── Tests ─────────────────────────────────────────────────────


def test_action_map_matches_expected():
    """The literal action_map in findings.py contains every expected
    entry with the right Classification mapping."""
    actual = _extract_router_action_map()
    assert actual == EXPECTED_ACTION_MAP, (
        f"action_map drift detected. Expected:\n  {EXPECTED_ACTION_MAP}\n"
        f"Actual:\n  {actual}"
    )


def test_every_ui_action_is_wired_in_backend():
    """Bug guard: each action the UI dropdown exposes MUST have a
    corresponding entry in the backend action_map. Otherwise the
    button silently no-ops and the user sees a 200 but no state
    change."""
    actual = _extract_router_action_map()
    missing = UI_DROPDOWN_ACTIONS - set(actual.keys())
    assert not missing, (
        f"UI dropdown exposes actions the backend doesn't handle: "
        f"{sorted(missing)}. Each will return 200 but silently fail "
        f"to change classification — exactly the bug we shipped on "
        f"2026-05-04 and shouldn't repeat."
    )


def test_action_map_values_resolve_to_classification_or_none():
    """Every value in action_map must be either a Classification
    enum member or None — anything else would crash the endpoint."""
    actual = _extract_router_action_map()
    for action, target in actual.items():
        assert target is None or isinstance(target, Classification), (
            f"action_map['{action}'] = {target!r} is neither a "
            f"Classification member nor None"
        )


def test_rotated_classification_exists():
    """The Classification enum gains ROTATED 2026-05-04. Locks in
    the name + value so a future refactor that renames either
    breaks loudly here instead of silently in production."""
    assert hasattr(Classification, "ROTATED")
    assert Classification.ROTATED.value == "rotated"
    assert Classification.ROTATED.name == "ROTATED"


def test_test_credential_classification_exists():
    """Same guard for TEST_CREDENTIAL."""
    assert hasattr(Classification, "TEST_CREDENTIAL")
    assert Classification.TEST_CREDENTIAL.value == "test_credential"
    assert Classification.TEST_CREDENTIAL.name == "TEST_CREDENTIAL"


def test_classification_enum_has_all_six_closure_states():
    """The full set of closure-state classifications expected by
    the UI dropdown — guards against any single one being deleted."""
    expected_states = {
        # Open / pending
        "NEEDS_REVIEW",
        # Closed — bad detection
        "CONFIRMED_FALSE_POSITIVE",
        # Closed — confirmed real, still actionable
        "CONFIRMED_TRUE_POSITIVE",
        # Closed — real and addressed (just-added)
        "ROTATED",
        # Closed — real but accepted
        "ACCEPTED_RISK",
        # Closed — intentional fixture (just-added)
        "TEST_CREDENTIAL",
    }
    actual_names = {m.name for m in Classification}
    missing = expected_states - actual_names
    assert not missing, (
        f"Classification enum is missing closure states the UI relies "
        f"on: {sorted(missing)}"
    )
