"""G1 redaction safety net — no RAW secret may survive into stored/exported data.

A secret scanner's own database must never become a secret honeypot. When a
finding's code-snippet (a ±N-line window) is persisted, it can carry:
  * the finding's OWN secret value,
  * OTHER secrets co-located in the window that the triggering rule never
    flagged (false negatives),
  * a multi-line PEM key TRUNCATED at the window edge (BEGIN, no END),
  * the AI triager echoing the value back into its reasoning prose / patch.

This harness pins the at-rest invariant on the two store-time redaction entry
points every persistence path funnels through:
  * ``redact_snippet_for_storage`` — code_snippet / FindingEvidence,
  * ``scrub_secrets_in_obj``       — AI triage reason / remediation (G1b).

It is a committed HARD GATE, same pattern as the precision/recall harness: a
change that reintroduces a leak fails the build. The ONE known residual gap
(co-located NOVEL-format secret under a generic name) is encoded as an explicit
``xfail`` so it is documented, tracked, and auto-detected the day it's closed.

NOTE (scope): this guards the redaction PRIMITIVES. A follow-up should assert
every egress sink (webhook payload, SARIF/JSON export, events.json, API
response, structlog) actually invokes them — the primitives are the foundation.
"""
import pytest

from services.secret_scan.engine import (
    redact_snippet_for_storage,
    scrub_secrets_in_obj,
    SecretScanner,
    _mask_secret,
)


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


# ── Trap secrets (fake but format-valid) ──────────────────────────────────
# The "detected" pair is what the finding fired on. The rest are CO-LOCATED in
# the same snippet window and were NOT the finding's value.
DETECTED_AWS_ID = "AKIAZ7Q9XK4NQW2RTYUI"                          # 20-char AWS id
DETECTED_AWS_SEC = "wJaltS1yOEcfP5pvfqJ7ml36mF7AkyHsEU0IUxyz"    # 40-char AWS secret
COLOC_SLACK = "xoxb-2451234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
COLOC_GH_PAT = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"   # ghp_ + exactly 36
COLOC_STRIPE = "sk_live_" + "Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op"           # sk_live_ + 24
# Novel-format secret: 32 mixed chars, NO known provider prefix, generic name.
NOVEL_SECRET = "Zx9Qw3Vt7Bn2Mk5Lp8Rd1Fg4Hs6Jy0Cu"


def _assert_no_raw(out: str, *raws: str) -> None:
    for raw in raws:
        assert raw not in out, (
            f"REDACTION LEAK: raw secret survived at rest -> {raw[:8]}…"
        )


def test_detected_pair_is_masked(scanner):
    """The finding's own value + its paired credential never survive."""
    snip = (
        f'aws_access_key_id = "{DETECTED_AWS_ID}"\n'
        f'aws_secret_access_key = "{DETECTED_AWS_SEC}"\n'
    )
    out = redact_snippet_for_storage(
        snip, raw=DETECTED_AWS_ID, masked=_mask_secret(DETECTED_AWS_ID),
        paired_raw=DETECTED_AWS_SEC, paired_masked=_mask_secret(DETECTED_AWS_SEC),
        scanner=scanner,
    )
    _assert_no_raw(out, DETECTED_AWS_ID, DETECTED_AWS_SEC)


def test_colocated_known_shape_secrets_are_masked(scanner):
    """G1 core: the finding fired on the AWS id, but Slack / GitHub / Stripe
    tokens sit co-located in the window. The residual-shape scrub must mask
    them even though they were never the finding's value."""
    snip = (
        f'AWS_KEY = {DETECTED_AWS_ID}\n'
        f'# leftover slack hook token: {COLOC_SLACK}\n'
        f'gh_token = {COLOC_GH_PAT}\n'
        f'stripe = "{COLOC_STRIPE}"\n'
    )
    out = redact_snippet_for_storage(
        snip, raw=DETECTED_AWS_ID, masked=_mask_secret(DETECTED_AWS_ID),
        scanner=scanner,
    )
    _assert_no_raw(out, DETECTED_AWS_ID, COLOC_SLACK, COLOC_GH_PAT, COLOC_STRIPE)


def test_truncated_pem_is_masked(scanner):
    """A PEM key whose -----END----- marker is cut off by the snippet window
    must still be masked through end-of-text (the truncated-PEM pass)."""
    snip = (
        'tls_key = """\n'
        '-----BEGIN RSA PRIVATE KEY-----\n'
        'MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9OiJ2g7vQxY1pV8s4n5w0kq9zXr\n'
        '3mB7lF2hN8pQ6tW1yE4uI0oP5aS7dF9gH2jK3lM6nB8vC1xZ4qR7eT0yU2iO5p\n'
        # deliberately no -----END----- : truncated at the window edge
    )
    out = redact_snippet_for_storage(snip, raw="", masked="", scanner=scanner)
    assert "BEGIN RSA PRIVATE KEY" not in out, "PEM header survived"
    assert "MIIEpAIBAAKCAQEA" not in out, "PEM body survived (truncated-key leak)"


def test_ai_freetext_echoed_secret_is_scrubbed(scanner):
    """G1b: the AI triager is given the value and echoes it into its reason
    prose and remediation patch. ``scrub_secrets_in_obj`` must mask it."""
    ai_output = {
        "verdict": "true_positive",
        "reason": f"Confirmed AWS key ({DETECTED_AWS_ID}) plus a Slack token "
                  f"{COLOC_SLACK} in the same hunk.",
        "remediation": f"- aws_key={DETECTED_AWS_ID}\n+ aws_key=${{AWS_KEY}}",
    }
    out = scrub_secrets_in_obj(ai_output)
    _assert_no_raw(str(out), DETECTED_AWS_ID, COLOC_SLACK)


@pytest.mark.xfail(
    strict=False,
    reason="KNOWN GAP (tracked): a co-located NOVEL-format secret under a "
           "generic var name matches no known provider shape and isn't the "
           "finding's own value, so the residual scrub leaves it. Closing it "
           "= suggestion #2 (greedy entropy-based over-mask of STORED "
           "snippets). When implemented, this flips to xpass — convert to a "
           "hard assert then.",
)
def test_colocated_novel_secret_is_masked(scanner):
    """The honest open edge: residual scrub only knows KNOWN provider shapes
    (novel high-entropy is deliberately left visible to keep the Code tab
    usable). A co-located novel secret therefore survives today."""
    snip = (
        f'AWS_KEY = {DETECTED_AWS_ID}\n'
        f'internal_token = "{NOVEL_SECRET}"\n'
    )
    out = redact_snippet_for_storage(
        snip, raw=DETECTED_AWS_ID, masked=_mask_secret(DETECTED_AWS_ID),
        scanner=scanner,
    )
    _assert_no_raw(out, NOVEL_SECRET)
