"""VOODA-SEC-CONVERTKIT-001 post-filter tuning (2026-06-14).

The capture group is a generic 22-char token, so the keyword proximity gate is
the ONLY thing that makes a match "ConvertKit" rather than "any 22-char string".

Bug (opus x vooda benchmark): in secrets-patterns-db/db/rules-stable.yml the rule
fired on line 6175 -- the literal *name* of a pattern definition,
trex_okta_client_token (exactly 22 chars) -- because api_secret (inside
twilio_api_secret, 8 lines below) was an accepted keyword within a 500-char
window. api_secret is an extremely common field name, so the rule effectively
flagged any 22-char token sharing a file region with the word api_secret.

Fix: drop api_secret from the keyword set (require real convertkit/kit.com
context), and switch the window to both-directions/64 chars to match the
canonical secrets-patterns-db pattern (convertkit within ~40 chars of the token).

These pin: the FP dies, AND every real ConvertKit shape still fires (recall
preserved -- and the keyword-BEFORE shape the old after-only rule missed is now
caught).
"""
from services.secret_scan.engine import SecretScanner

_scanner = SecretScanner()
_CK = "VOODA-SEC-CONVERTKIT-001"


def _rule_ids(path, content):
    return [f.rule_id for f in _scanner.scan_file(path, content)]


def test_convertkit_fp_on_pattern_name_does_not_fire():
    # Reproduces rules-stable.yml: a convertkit definition exists (prefilter
    # passes), then a 22-char pattern-name validated only by a nearby
    # *_api_secret. Must NOT be reported as a ConvertKit secret.
    content = (
        "  - pattern:\n      name: Convertkit\n      regex: convertkit.{0,40}\n"
        + "  - pattern:\n      name: spacer\n      regex: x\n" * 40
        + "  - pattern:\n      name: trex_okta_client_token\n"
        "      regex: trex[_-]?okta[_-]?client[_-]?token\n"
        "  - pattern:\n      name: twilio_api_secret\n"
        "      regex: twilio[_-]?api[_-]?secret\n"
    )
    assert _CK not in _rule_ids("db/rules-stable.yml", content)


def test_convertkit_keyword_before_value_now_fires():
    # Canonical shape CONVERTKIT_API_SECRET=<22> -- keyword BEFORE the value.
    # The old after-only window missed this; recall must now cover it.
    assert _CK in _rule_ids("src/config.py", "CONVERTKIT_API_SECRET=Abcd1234efgh5678ijkl90\n")


def test_convertkit_keyword_after_value_still_fires():
    assert _CK in _rule_ids("src/config.py", 'secret = "Abcd1234efgh5678ijkl90"  # convertkit\n')


def test_convertkit_kit_com_context_fires():
    # kit.com is a valid ConvertKit context keyword (was not honoured before).
    assert _CK in _rule_ids("src/config.py", "token: Zm9vYmFyYmF6cXV4MTIzNA\n# kit.com dashboard\n")


def test_random_22char_token_without_convertkit_context_does_not_fire():
    # A 22-char token next to api_secret but with NO convertkit/kit context
    # must not be mislabelled ConvertKit (the core of the FP).
    assert _CK not in _rule_ids("src/config.py", "twilio_api_secret = Abcd1234efgh5678ijkl90\n")
