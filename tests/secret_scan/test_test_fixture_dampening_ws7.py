"""WS7 — test/snapshot fixture context DAMPENS confidence (never suppresses).

The bulk of WS7 already shipped (the comprehensive ``_TEST_PATH_PATTERNS`` list:
tests/specs/fixtures/golden/snapshots/cassettes/vcr/e2e + filename conventions).
This pins the one gap closed here — snapshot / approval-test FILE suffixes for
artifacts that sit next to the source rather than under a ``__snapshots__/`` dir
(Jest ``.snap``, syrupy ``.ambr``, ApprovalTests ``.approved.``/``.received.``).

Contract: DAMPEN, not suppress. A real key captured in a snapshot is still key
material, so the dampened confidence must stay at/above the 0.10 emission
threshold — the finding is routed to review, never dropped (recall preserved).
"""
from services.secret_scan.context import adjust_confidence

_VAL = "AKIAZX9QWMR7KP2DLY4N"          # a real-shape (fake) AWS key
_LINE = 'key = "AKIAZX9QWMR7KP2DLY4N"'
_BASE = 0.9

# Paths with NO test directory — so only the new file-suffix recognisers can fire.
_SNAPSHOT_PATHS = [
    "components/Button.snap",
    "api/responses.ambr",
    "src/output.approved.txt",
    "src/output.received.txt",
    "data/payload.snapshot.json",
]


def test_snapshot_suffixes_dampen_confidence():
    src_conf = adjust_confidence(_BASE, _VAL, "app/config.py", _LINE)
    for path in _SNAPSHOT_PATHS:
        damp = adjust_confidence(_BASE, _VAL, path, _LINE)
        assert damp < src_conf, f"{path}: not dampened ({damp} >= {src_conf})"


def test_snapshot_dampening_preserves_recall():
    """Dampened, NOT suppressed — a high-confidence secret in a snapshot must
    still clear the 0.10 emission threshold."""
    for path in _SNAPSHOT_PATHS:
        damp = adjust_confidence(_BASE, _VAL, path, _LINE)
        assert damp >= 0.10, (
            f"RECALL RISK: {path} dampened to {damp} — below the 0.10 emission "
            f"threshold means the finding would be dropped, not just deprioritized"
        )
