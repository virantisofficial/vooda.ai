"""WS1 — generic file-selection: force-scan key material, skip generated/vendored.

Two layers, tested at the layer each lives in:
  * ``_should_scan_file`` (walk-level allowlist) — decides whether the directory
    walk even hands a file to the scanner. Key-material extensions must always
    win here; build artifacts must not bloat the walk.
  * ``FULLY_SKIPPED_PATH_PATTERNS`` (scan_file-level glob skip) — exercised by
    the precision/recall harness (generated/vendored fixtures), so it is not
    re-tested here.

Recall is the hard gate: the force-scan cases below pin that key material is
NEVER dropped by the allowlist (the wrongsecrets ``.ssh/*.keys`` FN the audit
found), while the skip cases only ever drop non-source build output.
"""
import pytest

from services.secret_scan.engine import _should_scan_file
from services.secret_scan.config import _ALWAYS_SCAN_EXTENSIONS


# (filename, rel_path) that MUST be scanned — key material + normal source.
_MUST_SCAN = [
    # the audit's false negative: a real private-key file with a .keys extension
    ("team.keys", ".ssh/team.keys"),
    ("deploy.keys", "config/deploy.keys"),
    # extensionless key files (already worked — pin so a refactor can't break it)
    ("id_rsa", ".ssh/id_rsa"),
    ("id_ed25519", "home/.ssh/id_ed25519"),
    ("authorized_keys", ".ssh/authorized_keys"),
    # other key-material extensions added in WS1
    ("server.ppk", "keys/server.ppk"),
    ("signing.pkcs8", "certs/signing.pkcs8"),
    ("client.ovpn", "vpn/client.ovpn"),
    # always-scan crypto material that predates WS1
    ("tls.pem", "certs/tls.pem"),
    ("private.key", "secrets/private.key"),
    # ordinary source / config must still be scanned
    ("settings.py", "app/settings.py"),
    (".env.production", "deploy/.env.production"),
    ("values.yaml", "chart/values.yaml"),
]


@pytest.mark.parametrize("filename,rel_path", _MUST_SCAN, ids=[c[0] for c in _MUST_SCAN])
def test_key_material_and_source_are_force_scanned(filename, rel_path):
    assert _should_scan_file(filename, rel_path) is True, (
        f"RECALL REGRESSION: {rel_path} would be excluded from the walk"
    )


# Files the walk legitimately skips (not source, not key material).
_SHOULD_SKIP = [
    ("logo.png", "assets/logo.png"),
    ("photo.jpg", "img/photo.jpg"),
    ("app.wasm", "static/app.wasm"),
    ("archive.tgz", "dist/archive.tgz"),
    ("lib.so", "build/lib.so"),
]


@pytest.mark.parametrize("filename,rel_path", _SHOULD_SKIP, ids=[c[0] for c in _SHOULD_SKIP])
def test_binary_assets_not_in_walk_allowlist(filename, rel_path):
    assert _should_scan_file(filename, rel_path) is False, (
        f"{rel_path} is a binary asset and should not be walked"
    )


def test_keys_extension_present_in_always_scan():
    # Pins the specific fix for the wrongsecrets `.ssh/*.keys` false negative.
    for ext in (".keys", ".ppk", ".pkcs8", ".ovpn"):
        assert ext in _ALWAYS_SCAN_EXTENSIONS, f"{ext} missing from always-scan set"
