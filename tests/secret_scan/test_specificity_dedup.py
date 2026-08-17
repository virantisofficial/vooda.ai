"""Overlap dedup must keep the SPECIFIC detector over a generic catch-all.

GEN-007 "Private Key (Generic PEM)" and the specific CRYPTO-001..005 key rules
all match the same `-----BEGIN ... PRIVATE KEY-----` block, so on every real
key BOTH fire. `_dedup_overlapping_findings` collapses them — but the final
tiebreak used to be `-len(rule_id)`, which prefers the SHORTER, GENERIC id
(`VOODA-SEC-GEN-007` < `VOODA-SEC-CRYPTO-005`). A `is_specific` tiebreak above
rule-id length makes the specific rule win deterministically (order-independent),
while a key type that ONLY the generic rule covers (DSA, ENCRYPTED) is preserved.
"""
import types

from services.secret_scan.engine import _dedup_overlapping_findings


def _mk(rule_id, secret_type, conf=0.90):
    return types.SimpleNamespace(
        file_path="id_rsa.pem", line_start=1, line_end=3,
        rule_id=rule_id, severity="critical", confidence=conf,
        raw_data={
            "secret_type": secret_type,
            "detection_method": "regex",
            "_raw_value_for_verification": "MIIEsamekeyvalue0123456789abcdef",
            "secret_hash": "h1",
        },
    )


def _gen():
    return _mk("VOODA-SEC-GEN-007", "generic_private_key")


def _crypto():
    return _mk("VOODA-SEC-CRYPTO-005", "pkcs8_private_key")


def test_specific_crypto_beats_generic_pem_either_order():
    for order in ([_gen(), _crypto()], [_crypto(), _gen()]):
        kept = _dedup_overlapping_findings(order)
        ids = [f.rule_id for f in kept]
        assert ids == ["VOODA-SEC-CRYPTO-005"], f"expected only CRYPTO-005, got {ids}"


def test_lone_generic_key_is_preserved():
    # A DSA / ENCRYPTED key has no specific CRYPTO rule — GEN-007 is the only
    # detector, so it must survive (no recall loss from the tiebreak change).
    kept = _dedup_overlapping_findings([_gen()])
    assert [f.rule_id for f in kept] == ["VOODA-SEC-GEN-007"]
