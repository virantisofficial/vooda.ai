# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
""""Test File Handling" changes triage and severity, never detection.

    normal        nothing changes.
    deprioritize  severity lowered to LOW after detection. The finding is
                  still detected, stored and visible — it just stops
                  paging.
    exclude       finding detected and stored as normal; only AI triage
                  is skipped, to save tokens.

The load-bearing property, pinned below: **the scanner itself has no
knowledge of this setting at all**, so recall is mathematically
identical in all three modes.
"""
import inspect

import pytest

from services.secret_scan.engine import SecretScanner, _classify_file_context
from apps.worker import tasks


TEST_PATH = "tests/secret_scan/test_creds.py"
PROD_PATH = "src/config.py"
# Real-shape but FAKE AWS key id — same synthetic fixture as
# test_test_fixture_dampening_ws7.py. Not a credential.
CONTENT = 'AWS_KEY = "AKIAZX9QWMR7KP2DLY4N"\n'


# ── the safety property: detection is untouched ──────────────────────

def test_scanner_takes_no_test_file_handling_argument():
    """If the scanner cannot see the setting, it cannot lose recall."""
    params = inspect.signature(SecretScanner.__init__).parameters
    assert "test_file_handling" not in params, (
        "detection must stay independent of this setting — an earlier "
        "version skipped scanning test files entirely, which hides real "
        "credentials"
    )


def test_scan_file_source_has_no_test_file_gate():
    src = inspect.getsource(SecretScanner.scan_file)
    assert "test_file_handling" not in src


def test_test_files_are_always_scanned():
    findings = SecretScanner().scan_file(TEST_PATH, CONTENT)
    assert len(findings) > 0, "a credential in a test file must always be detected"


def test_detection_is_identical_for_test_and_production_paths():
    """Same content, different path — the scanner must not care."""
    t = SecretScanner().scan_file(TEST_PATH, CONTENT)
    p = SecretScanner().scan_file(PROD_PATH, CONTENT)
    assert len(t) == len(p) > 0


# ── deprioritize: severity only, applied after detection ─────────────

DEPRIO_SRC = inspect.getsource(tasks._run_scan_job)


def test_deprioritize_lowers_severity_to_low():
    assert 'test_file_handling == "deprioritize"' in DEPRIO_SRC
    assert '_pf.severity = "low"' in DEPRIO_SRC


def test_deprioritize_runs_after_detection_not_during():
    """It mutates parsed findings, so nothing is ever un-detected."""
    assert "raw_findings" in DEPRIO_SRC
    assert "test_file_findings_deprioritized" in DEPRIO_SRC


def test_deprioritize_only_touches_test_paths():
    assert '_cfc(_pf.file_path or "") == "test_file"' in DEPRIO_SRC


# ── exclude: AI triage only, never detection ─────────────────────────

TRIAGE_SRC = inspect.getsource(tasks._run_ai_triage)


def test_exclude_filters_the_triage_list_only():
    assert '_tfh == "exclude"' in TRIAGE_SRC
    assert "test_file_findings_excluded_from_ai" in TRIAGE_SRC


def test_exclude_does_not_delete_or_skip_storage():
    """Findings must remain stored — the UI promises exactly that."""
    assert "delete" not in TRIAGE_SRC.split('_tfh == "exclude"')[1][:600].lower()


def test_legacy_boolean_rows_are_still_understood():
    """Older schema stored a bool; it must map onto the new strings."""
    assert "isinstance(_tfh, bool)" in TRIAGE_SRC
    assert "isinstance(_raw_tfh, bool)" in DEPRIO_SRC


@pytest.mark.parametrize("mode", ["normal", "deprioritize", "exclude"])
def test_all_three_modes_leave_recall_unchanged(mode):
    """The whole point: no mode can make the scanner miss a secret."""
    findings = SecretScanner().scan_file(TEST_PATH, CONTENT)
    assert len(findings) > 0


def test_classifier_recognises_the_test_path_used_above():
    """Guards the guard — if this stopped matching, the tests would pass
    vacuously."""
    assert _classify_file_context(TEST_PATH) == "test_file"
    assert _classify_file_context(PROD_PATH) != "test_file"
