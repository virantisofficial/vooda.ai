# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""One vocabulary for "is this credential live?", enforced by the DB.

Eight spellings of five states were in flight, produced by two engines
that never agreed: ``validation_error`` vs ``error``; ``not_validated``
vs ``unverified`` vs ``unknown`` vs NULL. The column had no enum and no
constraint, and on findings it lived inside a JSONB blob where nothing
could constrain it at all.
"""
import pathlib
import re

from apps.api.app.core.validity import (
    INCONCLUSIVE,
    PROVABLY_DEAD,
    Validity,
    normalize,
)

MIGRATION = pathlib.Path(
    "apps/api/alembic/versions/l8g9h0i1j2k3_canonical_validity_vocabulary.py"
)


def test_every_legacy_spelling_from_both_engines_maps():
    """The exact strings each subsystem actually emitted."""
    assert normalize("validation_error") is Validity.CHECK_FAILED   # worker
    assert normalize("error") is Validity.CHECK_FAILED              # API
    assert normalize("not_validated") is Validity.UNKNOWN           # worker
    assert normalize("unverified") is Validity.UNKNOWN              # dispatcher
    assert normalize(None) is Validity.UNKNOWN                      # database
    assert normalize("revoked") is Validity.INACTIVE                # worker
    assert normalize("unsupported") is Validity.UNSUPPORTED         # API


def test_incumbent_vocabularies_import_without_loss():
    """A customer migrating must not lose validity history at the door."""
    # GitHub Advanced Security
    assert normalize("active") is Validity.ACTIVE
    assert normalize("inactive") is Validity.INACTIVE
    # GitGuardian
    assert normalize("valid") is Validity.ACTIVE
    assert normalize("invalid") is Validity.INACTIVE
    assert normalize("failed_to_check") is Validity.CHECK_FAILED
    assert normalize("no_checker") is Validity.UNSUPPORTED
    assert normalize("unknown") is Validity.UNKNOWN


def test_an_unreadable_validity_is_never_read_as_safe():
    """Absence of evidence is not evidence of absence.

    A failed check must not be presented as a dead credential — that is
    the one mistake in this axis that gets a live secret ignored.
    """
    assert normalize("gibberish") is Validity.UNKNOWN
    assert Validity.CHECK_FAILED in INCONCLUSIVE
    assert Validity.UNSUPPORTED in INCONCLUSIVE
    assert Validity.UNKNOWN in INCONCLUSIVE
    assert PROVABLY_DEAD == (Validity.INACTIVE,)
    assert Validity.CHECK_FAILED not in PROVABLY_DEAD


def test_the_backfill_and_the_runtime_normaliser_cannot_diverge():
    """The migration rewrites history in SQL; normalize() runs at
    runtime. If they disagree, rows written before and after the
    migration mean different things."""
    sql = MIGRATION.read_text(encoding="utf-8")
    pairs = re.findall(r"WHEN '([a-z_]+)'\s+THEN '([a-z_]+)'", sql)
    assert pairs, "could not parse the migration's CASE expression"
    for legacy, target in pairs:
        assert normalize(legacy).value == target, (
            f"migration maps {legacy!r} -> {target!r} but normalize() "
            f"gives {normalize(legacy).value!r}"
        )


def test_no_verdict_reaches_storage_unnormalised():
    """Structural guard: every boundary where an engine's verdict is
    assigned to a column or to source_metadata must pass through
    normalize(). Raw ``= verification.status`` is how the vocabulary
    forked in the first place."""
    offenders = []
    raw_assign = re.compile(
        r"validation_status(\"\])?\s*=\s*(verification|result|cached|patch)\b"
    )
    for root in ("apps", "services"):
        for path in pathlib.Path(root).rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            for i, line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
            ):
                if raw_assign.search(line) and "_validity" not in line:
                    offenders.append(f"{path}:{i}: {line.strip()[:80]}")
    assert not offenders, (
        "verdicts reaching storage without normalize():\n" + "\n".join(offenders)
    )


def test_sql_predicates_use_the_constrained_column_not_the_json_blob():
    """The JSONB key cannot be constrained or indexed."""
    offenders = []
    for path in pathlib.Path("apps/api/app/routers").rglob("*.py"):
        src = path.read_text(encoding="utf-8", errors="replace")
        if "source_metadata->>'validation_status'" in src:
            offenders.append(str(path))
    assert not offenders, (
        "these query the unconstrained JSONB key instead of the "
        f"validation_status column: {offenders}"
    )


def test_every_canonical_value_survives_a_round_trip():
    """A canonical value missing from the alias table folds into
    UNKNOWN. `check_failed` was missing, so the UI's "Check Failed"
    filter returned all 1,374 unchecked findings instead of none.
    """
    for value in Validity:
        assert normalize(value.value) is value, value.value


def test_a_provider_with_no_verifier_is_recorded_as_unsupported():
    """"Not checked" and "No checker" are different facts.

    Both verification paths used to bail out with a bare `return`
    whenever they could not verify, so a provider Vooda will NEVER be
    able to check looked identical to one it simply had not got to
    yet. 1,129 findings were presented as pending a check that could
    never happen.

    The distinction is operational: "Not checked" invites a retry,
    "No checker" says this will not resolve — stop waiting for it.
    """
    src = pathlib.Path("apps/worker/tasks.py").read_text(encoding="utf-8")
    assert "Validity.UNSUPPORTED.value" in src, (
        "an unverifiable provider must be stamped, not silently skipped"
    )
    # and a checker that ran and broke is a third, retryable state
    assert src.count("Validity.CHECK_FAILED.value") >= 2, (
        "both verification paths must record a failed check"
    )


def test_the_three_not_verified_states_stay_distinct():
    """UNSUPPORTED / CHECK_FAILED / UNKNOWN must not collapse into
    each other — that collapse is what hid the gap."""
    assert len({Validity.UNSUPPORTED, Validity.CHECK_FAILED,
                Validity.UNKNOWN}) == 3
    for v in (Validity.UNSUPPORTED, Validity.CHECK_FAILED, Validity.UNKNOWN):
        assert v in INCONCLUSIVE, v
        assert v not in PROVABLY_DEAD, v


def test_every_verification_path_records_no_checker():
    """There are THREE places a finding can miss verification, and each
    had to learn this separately.

    The repository-scan path filters unsupported providers out BEFORE
    calling any verifier, so the two paths that were taught to stamp
    `unsupported` never saw them. An end-to-end scan of DVWA came back
    with postgresql and generic findings marked "Not checked" — a check
    that can never happen.
    """
    src = pathlib.Path("apps/worker/tasks.py").read_text(encoding="utf-8")
    assert src.count("Validity.UNSUPPORTED.value") >= 2, (
        "the pre-verification filter must stamp what it filters out"
    )
    # and the stamp must sit beside the filter that causes the skip
    idx = src.index("in SUPPORTED_PROVIDERS]")
    assert "Validity.UNSUPPORTED.value" in src[idx: idx + 1200]
