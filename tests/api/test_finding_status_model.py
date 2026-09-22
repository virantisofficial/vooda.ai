# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Phase 2: status + resolution_reason replace the 13-value enum.

Classification was doing four jobs at once, so every new reason
multiplied the list — four RESOLVED_* values existed that differ only
in what kind of thing disappeared.
"""
import pathlib
import re

import pytest

from apps.api.app.core.finding_status import (
    CLOSING_STATUSES,
    FROM_CLASSIFICATION,
    REASONS_FOR,
    REMEDIATED_REASONS,
    AiVerdict,
    FindingStatus,
    ResolutionReason,
    from_classification,
    from_incumbent,
    validate,
)
from apps.api.app.models.finding import Classification

MIGRATION = pathlib.Path(
    "apps/api/alembic/versions/n0i1j2k3l4m5_finding_status_and_reason.py"
)


def test_every_legacy_classification_decomposes():
    assert set(FROM_CLASSIFICATION) == set(Classification)


def test_an_ai_verdict_never_closes_a_finding():
    """The rule Phase 0 established, now enforced on the new axis too."""
    for cls in (Classification.LIKELY_TRUE_POSITIVE,
                Classification.LIKELY_FALSE_POSITIVE,
                Classification.NOT_ENOUGH_EVIDENCE):
        m = from_classification(cls)
        assert m.status is FindingStatus.OPEN, cls
        assert m.reason is None, cls
        assert m.ai_verdict is not None, cls


def test_a_confirmed_real_secret_is_open_until_rotated():
    m = from_classification(Classification.CONFIRMED_TRUE_POSITIVE)
    assert m.status is FindingStatus.TRIAGING
    assert m.reason is None


def test_the_four_deletion_values_collapse_to_one_reason():
    """They differed only in what disappeared — a note, not a status."""
    for cls in (Classification.RESOLVED_FILE_DELETED,
                Classification.RESOLVED_ITEM_DELETED,
                Classification.RESOLVED_REPO_REMOVED,
                Classification.RESOLVED_SOURCE_REMOVED):
        m = from_classification(cls)
        assert m.status is FindingStatus.DISMISSED, cls
        assert m.reason is ResolutionReason.NO_LONGER_PRESENT, cls


def test_losing_visibility_is_not_a_remediation():
    """Deleting a repository must never read as an instant fix."""
    assert ResolutionReason.NO_LONGER_PRESENT not in REMEDIATED_REASONS
    assert ResolutionReason.ROTATED in REMEDIATED_REASONS


def test_closing_without_a_reason_is_rejected():
    for status in CLOSING_STATUSES:
        with pytest.raises(ValueError, match="requires a resolution_reason"):
            validate(status, None)


def test_a_reason_cannot_cross_statuses():
    """A rotated credential is RESOLVED; a false positive is DISMISSED.
    Crossing them makes MTTR and compliance reporting meaningless."""
    with pytest.raises(ValueError, match="not valid for status"):
        validate(FindingStatus.DISMISSED, ResolutionReason.ROTATED)
    with pytest.raises(ValueError, match="not valid for status"):
        validate(FindingStatus.RESOLVED, ResolutionReason.FALSE_POSITIVE)


def test_an_open_finding_cannot_carry_a_reason():
    with pytest.raises(ValueError, match="must not carry"):
        validate(FindingStatus.OPEN, ResolutionReason.ROTATED)


def test_unknown_input_stays_open_never_silently_closed():
    m = from_classification("something_new")
    assert m.status is FindingStatus.OPEN
    assert m.reason is None


@pytest.mark.parametrize("product,state,reason,status", [
    ("github", "open", None, FindingStatus.OPEN),
    ("github", "resolved", "revoked", FindingStatus.RESOLVED),
    ("github", "resolved", "used_in_tests", FindingStatus.DISMISSED),
    ("github", "resolved", "wont_fix", FindingStatus.DISMISSED),
    ("gitguardian", "triggered", None, FindingStatus.OPEN),
    ("gitguardian", "assigned", None, FindingStatus.TRIAGING),
    ("gitguardian", "ignored", "test_credential", FindingStatus.DISMISSED),
    ("gitlab", "detected", None, FindingStatus.OPEN),
    ("gitlab", "confirmed", None, FindingStatus.TRIAGING),
    ("gitlab", "dismissed", "mitigating_control", FindingStatus.DISMISSED),
    ("gitlab", "dismissed", "used_in_tests", FindingStatus.DISMISSED),
])
def test_incumbent_triage_history_imports_without_loss(product, state, reason, status):
    """A customer migrating off another scanner must not lose triage
    history at the door — that is what makes replacement possible."""
    m = from_incumbent(product, state, reason)
    assert m is not None, f"{product}/{state}/{reason} did not map"
    assert m.status is status
    validate(m.status, m.reason)


def test_an_unrecognised_incumbent_state_is_reported_not_guessed():
    assert from_incumbent("github", "some_new_state") is None


def test_migration_and_runtime_mapping_agree():
    """The SQL backfill and from_classification() must not diverge, or
    rows written before and after the migration mean different things."""
    sql = MIGRATION.read_text(encoding="utf-8")

    def parsed(block: str) -> dict[str, str]:
        seg = sql[sql.index(block):]
        seg = seg[:seg.index('"""', seg.index('"""') + 3)]
        return dict(re.findall(r"WHEN '([a-z_]+)'\s+THEN '([a-z_]+)'", seg))

    for legacy, target in parsed("_STATUS_CASE = ").items():
        assert from_classification(legacy).status.value == target, legacy
    for legacy, target in parsed("_REASON_CASE = ").items():
        assert from_classification(legacy).reason.value == target, legacy
    for legacy, target in parsed("_VERDICT_CASE = ").items():
        assert from_classification(legacy).ai_verdict.value == target, legacy


def test_the_check_constraint_is_null_safe():
    """Regression: `reason IN (...)` yields NULL when reason IS NULL, the
    whole OR collapses to NULL, and PostgreSQL treats a NULL CHECK as
    SATISFIED — so `dismissed` with no reason sailed through the
    constraint written to forbid exactly that. One row slipped in before
    it was caught.
    """
    sql = MIGRATION.read_text(encoding="utf-8")
    seg = sql[sql.index("ck_{table}_status_reason"):]
    seg = seg[:seg.index("if f\"ck_{table}_ai_verdict\"")]
    assert seg.count("resolution_reason IS NOT NULL") == 2, (
        "both closing branches need an explicit IS NOT NULL guard"
    )


def test_core_updates_write_the_lifecycle_columns_too():
    """The blind spot that let 26 rows drift.

    mirror_lifecycle() runs on ORM attribute writes only. A Core
    ``update(...).values(classification=...)`` bypasses it entirely — the
    same blind spot that previously let classification_provenance go
    unwritten, which is why that module already carries a comment about
    it. Any Core UPDATE touching classification must set status in the
    same statement.
    """
    # Parse each .values(...) block across lines. The first version of
    # this guard matched one line at a time and so missed every
    # multi-line block — including the repository-delete sweep, which
    # left 173 incidents reading resolved_repo_removed on the legacy
    # column while status still said open.
    offenders = []
    for root in ("apps", "services"):
        for path in pathlib.Path(root).rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            src = path.read_text(encoding="utf-8", errors="replace")
            for m in re.finditer(r"\.values\(", src):
                depth, i = 0, m.end() - 1
                while i < len(src):
                    if src[i] == "(":
                        depth += 1
                    elif src[i] == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    i += 1
                block = src[m.end():i]
                if "classification" not in block:
                    continue
                # Must be the `status=` kwarg itself. A bare substring
                # test matches `review_status=`, which is a different
                # column — the guard then passes on the exact bug it
                # exists to catch. Verified by reintroducing it.
                if re.search(r"(?<![a-z_])status\s*=", block):
                    continue
                if "_lifecycle_values" in block:
                    continue
                ln = src[: m.start()].count("\n") + 1
                offenders.append(f"{path}:{ln}")
    assert not offenders, (
        "Core UPDATEs writing classification without the lifecycle "
        "columns:\n" + "\n".join(offenders)
    )


def test_propagation_derives_the_lifecycle_in_its_core_update():
    src = pathlib.Path("apps/api/app/core/occurrences.py").read_text(encoding="utf-8")
    assert "from_classification(classification)" in src
    for col in ('values["status"]', 'values["resolution_reason"]'):
        assert col in src, col


def test_set_classification_is_the_only_lifecycle_writer():
    """Structural guard: the two representations are both live, so a
    direct `.classification =` write would leave status stale."""
    offenders = []
    direct = re.compile(r"^\s*\w+\.classification\s*=\s*(?!=)")
    allowed = {
        # The helper itself.
        "apps/api/app/core/classification_provenance.py",
        # decision_cache writes its OWN table's classification column,
        # not a finding's — a different model with no lifecycle columns.
        "services/normalization/decision_cache.py",
    }
    for root in ("apps", "services"):
        for path in pathlib.Path(root).rglob("*.py"):
            if "__pycache__" in path.parts or str(path) in allowed:
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            for i, line in enumerate(lines, 1):
                if not direct.match(line):
                    continue
                # A direct write is fine when the very next line keeps
                # the lifecycle columns in step.
                nxt = lines[i] if i < len(lines) else ""
                if "mirror_lifecycle(" in nxt:
                    continue
                offenders.append(f"{path}:{i}: {line.strip()[:70]}")
    assert not offenders, (
        "write classifications through core.classification_provenance."
        "set_classification so status/resolution_reason stay in step:\n"
        + "\n".join(offenders)
    )
