"""WS6 — over-broad vendor rules require provider context (recall-safe tightening).

YANDEX-002 / WEBEX-002 / OKTA-001 each matched a generic shape behind a no-op
(or file-level) keyword, so any base64/hex blob starting with the prefix could
fire the rule (audit: YANDEX-002 = 2094 findings / 8 TP). These are *secondary*
rules — a real high-entropy token is already caught by a primary rule
(OKTA-API-001, WEBEX-001) or the entropy pass; the only firings unique to these
weak rules were low-entropy prefix-blobs, i.e. the false positives.

Each now carries ``post_filter_keywords`` + ``post_filter_direction="both"`` so a
provider marker must appear in the proximity window (markers normally sit BEFORE
the token, e.g. ``YANDEX_TOKEN = "..."`` — the default "after" direction would
have missed them).

These tests pin the gate at the layer it lives in — ``passes_post_filter`` —
which isolates the change from entropy/dedup interactions in the full pipeline.
The recall safeguard is the env-var marker (``yc_token``) that keeps a bare
``YC_TOKEN=...`` detected even with no other 'yandex' string nearby.
"""
import pytest

from services.secret_scan.engine import SecretScanner


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


def _rule(scanner, rid):
    return next(r for r in scanner.rules if r.rule_id == rid)


# (rule_id, token, the var-name marker that should re-enable it)
_CASES = [
    ("VOODA-SEC-YANDEX-002", "YC" + "9f3Kq7Wm2Rt8Zp4Nc6Vb1Lf5Hd0Gj3Ya7Qe2Uo", "YANDEX"),
    ("VOODA-SEC-WEBEX-002", "OTk" + "9f3Kq7Wm2Rt8Zp4Nc6Vb1Lf5Hd0Gj3Ya7Qe2Uo" * 2 + "7x9Z", "WEBEX"),
    ("VOODA-SEC-OKTA-001", "00" + "9f3Kq7Wm2Rt8Zp4Nc6Vb1Lf5Hd0Gj3Ya7Qe2Uo7x", "OKTA"),
    # legacy Vault ``s.`` prefix collides with Go/JS ``s.methodCall`` — needs vault ctx
    ("VOODA-SEC-VAULT-005", "s." + "aB3dE6gH9jK2mN5pQ8sT1vW4", "VAULT"),
    # Cloudflare R2 key is MD5-shaped (32-hex) — needs a specific cloudflare/r2 marker
    ("VOODA-SEC-CLOUDFLARE-R2-001", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "CLOUDFLARE"),
]


@pytest.mark.parametrize("rule_id,token,marker", _CASES, ids=[c[0] for c in _CASES])
def test_post_filter_requires_provider_marker(scanner, rule_id, token, marker):
    rule = _rule(scanner, rule_id)
    assert rule.post_filter_keywords, f"{rule_id} has no post_filter_keywords (WS6 not applied)"

    # WITH a provider marker BEFORE the token → gate passes (recall preserved).
    with_ctx = f'{marker}_TOKEN = "{token}"'
    s = with_ctx.index(token)
    assert rule.passes_post_filter(with_ctx, s, s + len(token)) is True, (
        f"RECALL REGRESSION: {rule_id} gate rejected a token with provider context"
    )

    # NO provider marker anywhere → gate fails (the precision win).
    bare = f'opaque_value = "{token}"'
    s2 = bare.index(token)
    assert rule.passes_post_filter(bare, s2, s2 + len(token)) is False, (
        f"PRECISION: {rule_id} gate passed a bare token with no provider context"
    )


def test_yandex_env_var_marker_keeps_recall(scanner):
    """``YC_TOKEN=...`` carries no 'yandex' word — the env-var name itself is the
    recall safeguard, so the gate must still pass on it."""
    rule = _rule(scanner, "VOODA-SEC-YANDEX-002")
    token = "YC" + "9f3Kq7Wm2Rt8Zp4Nc6Vb1Lf5Hd0Gj3Ya7Qe2Uo"
    content = f"YC_TOKEN={token}"
    s = content.index(token)
    assert rule.passes_post_filter(content, s, s + len(token)) is True


def test_default_after_direction_would_have_missed_before_marker(scanner):
    """Regression pin for the actual bug found: a marker BEFORE the token is only
    seen with direction='both'. All three WS6 rules must use 'both'."""
    for rid in ("VOODA-SEC-YANDEX-002", "VOODA-SEC-WEBEX-002", "VOODA-SEC-OKTA-001"):
        assert _rule(scanner, rid).post_filter_direction == "both", (
            f"{rid} must use post_filter_direction='both' (marker precedes the token)"
        )
