# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""A pairing entry naming a secret type no rule emits never fires.

Eight credential families can only be verified two values at a time,
and the scan picks that path with `if secret_type in
paired_primary_types`. The secret types in that table were written by
hand against the vendors' own vocabulary, not against what the detector
rules emit — so for AWS the table said `aws_access_key_id` while
VOODA-SEC-AWS-001 emits `aws_access_key`, the test was never true, and
`aws_paired` had never run on any scan since it was written.

Nothing failed. The finding was simply reported unverifiable, which is
indistinguishable from a provider Vooda does not support, so the gap
was invisible from the outside.

Four of the eight are still dead, for a reason a rename cannot fix:
the rule detects the *other* half of the pair. They are listed below
with what each would need, so the gap is recorded rather than
rediscovered.
"""
import pytest

#: Pairs whose primary is not emitted by any rule. Empty, and meant to
#: stay that way: all eight now key on the half a detector actually
#: finds. Kept as the escape hatch for a pair added before its detector,
#: so the guard below stays enforceable rather than being deleted the
#: first time it is inconvenient.
KNOWN_DEAD_PAIRS: dict[str, str] = {}


def _emitted_secret_types():
    from services.secret_scan.detectors.registry import get_all_rules
    return {(r.secret_type or "").lower() for r in get_all_rules()}


def test_every_live_pair_has_a_rule_that_can_trigger_it():
    from services.secret_verification.credential_pairing import KNOWN_PAIRS
    emitted = _emitted_secret_types()
    for pair in KNOWN_PAIRS:
        if pair.primary_secret_type in KNOWN_DEAD_PAIRS:
            continue
        assert pair.primary_secret_type in emitted, (
            f"{pair.verifier_key}: no rule emits "
            f"{pair.primary_secret_type!r}, so the pairing never fires"
        )


def test_the_dead_list_is_still_accurate():
    """If someone adds the missing detector, the entry has to come off
    this list — otherwise the pair stays excluded from the guard above
    and silently keeps not working."""
    from services.secret_verification.credential_pairing import KNOWN_PAIRS
    emitted = _emitted_secret_types()
    primaries = {p.primary_secret_type for p in KNOWN_PAIRS}
    for dead in KNOWN_DEAD_PAIRS:
        assert dead in primaries, f"{dead} is no longer in the pairing table"
        assert dead not in emitted, (
            f"a rule now emits {dead!r} — remove it from KNOWN_DEAD_PAIRS "
            "so the pairing is covered by the guard"
        )


def test_aws_pairing_fires_on_what_the_rule_actually_emits():
    """The regression this file exists for."""
    from services.secret_verification.verifier import paired_verifier_key
    assert paired_verifier_key({"secret_type": "aws_access_key"}) == "aws_paired"


@pytest.mark.asyncio
@pytest.mark.parametrize("partner", [
    "aws_secret_access_key",  # contextual + credentials-file rules
    "aws_secret_key",         # the two SDK/assignment rules
    "aws_secret",             # the inline regex in the pairing table
])
async def test_every_aws_secret_spelling_reaches_the_verifier(partner, monkeypatch):
    """A pair could be found and still verified with an empty secret:
    the lambda read two of the three spellings, so a secret detected by
    the SDK rules arrived and was dropped."""
    import services.secret_verification.verifier as v
    from services.secret_verification.credential_pairing import KNOWN_PAIRS

    aws = next(p for p in KNOWN_PAIRS if p.verifier_key == "aws_paired")
    assert partner in aws.partner_secret_types

    seen = {}

    async def _spy(access_key_id, secret_key):
        seen["secret"] = secret_key
        return None

    monkeypatch.setattr(v, "verify_aws_access_key", _spy)
    await v.VERIFIERS["aws_paired"]({"_raw_value": "AKIA...", partner: "s3cret"})
    assert seen.get("secret") == "s3cret", partner


def test_partner_types_are_things_rules_emit_or_regexes_produce():
    """A partner type that is neither detected nor matched inline can
    never be filled in."""
    from services.secret_verification.credential_pairing import KNOWN_PAIRS
    emitted = _emitted_secret_types()
    for pair in KNOWN_PAIRS:
        inline = set((pair.partner_inline_regex or {}).keys())
        reachable = [p for p in pair.partner_secret_types
                     if p in emitted or p in inline]
        assert reachable, (
            f"{pair.verifier_key}: none of {pair.partner_secret_types} "
            "is emitted by a rule or matched by an inline regex"
        )
