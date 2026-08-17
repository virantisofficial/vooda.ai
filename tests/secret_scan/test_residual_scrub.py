"""G1 — residual shape-based scrub for the detection-bounded co-located leak.

`redact_with_scanner` only redacts secrets the ruleset RE-DETECTS in a
snippet. A secret the rules miss (a false negative) sitting inside another
finding's snippet window therefore used to survive to rest UNMASKED. The
`_scrub_residual_secrets` final pass masks unambiguous provider-token shapes
context-free so no raw secret persists. These tests pin both halves of the
contract: it MUST mask real token shapes, and it MUST NOT over-mask benign
high-entropy/structured tokens that legitimately appear in code.
"""
from services.secret_scan.engine import (
    SecretScanner,
    redact_with_scanner,
    redact_snippet_for_storage,
    scrub_secrets_in_obj,
    _scrub_residual_secrets,
)

# Obviously-fake but shape-valid tokens (never real credentials).
_SLACK = "xoxb-2444556677-99001122334-AbCdEfGhIjKlMnOpQrStUv"
_AWS = "AKIA" + "QWERTYUIOPASDFGH"
_GHP = "ghp_" + "A" * 36
_GLPAT = "glpat-" + "Ab3Def6Hij9Klm2Nop5q"  # 20 chars after prefix (real GitLab PAT length)
_STRIPE = "sk_live_" + "Ab3Def6Hij9Klm2Nop5Qrs8"
_GOOGLE = "AIza" + "Bc3Def6Hij9Klm2Nop5Qrs8Tuv1Wxy4Zab7"
_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA1234567890abcdef\n"
    "-----END RSA PRIVATE KEY-----"
)


def test_masks_known_provider_token_shapes():
    for tok in (_SLACK, _AWS, _GHP, _GLPAT, _STRIPE, _GOOGLE):
        out = _scrub_residual_secrets(f'x = "{tok}"')
        assert tok not in out, f"{tok!r} survived the scrub"
        assert "****" in out


def test_masks_pem_private_key_block():
    # A COMPLETE key block keeps its BEGIN/END marker lines (the key TYPE is not
    # secret) and masks ONLY the body to first4****last4 — the structured form
    # used everywhere a key appears in a snippet (GitGuardian/GitHub style), not
    # an opaque placeholder. The raw body must never survive.
    out = _scrub_residual_secrets(f"key = '''{_PEM}'''")
    assert "MIIEowIBAAKCAQEA1234567890abcdef" not in out   # raw body gone
    assert "-----BEGIN RSA PRIVATE KEY-----" in out         # type marker kept
    assert "-----END RSA PRIVATE KEY-----" in out           # type marker kept
    assert "MIIE****cdef" in out                            # body masked first4****last4


# Regression: a ~30-line code-context window TRUNCATES a long PEM key, so the
# stored snippet holds BEGIN + partial base64 body but NO -----END----- marker.
# The original single BEGIN…END regex missed these — 414/453 real PEM leaks at
# rest were exactly this shape. The scrub must mask BEGIN-to-end-of-snippet.
_PEM_TRUNCATED = (
    "private_key = '''\n"
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpgIBAAKCAQEAwvUH8dWABKfsK0iI24p1sN6ViA23+ey7rX14EvOIpWaXOzNs\n"
    "3rtUKz8oQnnS4Dz9EMSmz0ugEeUfw4mxEVnLoyglORQdGPaJiKTfyJpdl84Bolib\n"
    "EXAMPLEbase64keymaterialcontinuesbeyondthesnippetwindowwithnoEND\n"
    # snippet window ends here — no -----END RSA PRIVATE KEY-----
)


def test_masks_truncated_pem_no_end_marker():
    out = _scrub_residual_secrets(_PEM_TRUNCATED)
    assert "MIIEpgIBAAKCAQEAwvUH8dWABKfsK0iI24p1sN6ViA23" not in out, "truncated key body survived"
    assert "EXAMPLEbase64keymaterialcontinuesbeyond" not in out
    assert "REDACTED" in out
    # the code BEFORE the key is preserved (only the key body is masked)
    assert "private_key" in out
    # idempotent on the truncated path too
    assert _scrub_residual_secrets(out) == out


def test_does_not_overmask_benign_tokens():
    """Git SHAs, UUIDs, hashes, IAM action names, base64 asset headers are
    legitimately shown in snippets — the scrub must leave them untouched."""
    benign = "\n".join([
        "commit a1b2c3d4e5f67890abcdef1234567890abcdef12",   # 40-hex git SHA
        "id = 550e8400-e29b-41d4-a716-446655440000",          # UUID
        "digest = " + ("deadbeef" * 8),                        # 64-hex hash
        'actions = ["ListEnvironments", "CreateAppAuthorization"]',  # IAM names
        "png = iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ",  # base64 PNG header
    ])
    assert _scrub_residual_secrets(benign) == benign


def test_idempotent():
    once = _scrub_residual_secrets(f'tok = "{_SLACK}"')
    assert _scrub_residual_secrets(once) == once


def test_empty_and_none_safe():
    assert _scrub_residual_secrets("") == ""
    assert _scrub_residual_secrets(None) == ""


def test_redact_with_scanner_closes_colocated_false_negative_leak():
    """The G1 scenario end-to-end: several secrets co-located in one window.
    The scanner detects most; one (Slack under a non-canonical var name) is a
    false negative. After redact_with_scanner NONE may survive at rest."""
    secrets = {
        "aws": _AWS,
        "vault": "s." + "AbCdEf0123456789GhIjKl99",
        "slack": _SLACK,  # FN: `SLACK = "..."` doesn't trigger the gated rule
    }
    content = "\n".join([
        "import os",
        f'AWS_KEY = "{secrets["aws"]}"',
        f'VAULT_TOKEN = "{secrets["vault"]}"',
        f'SLACK = "{secrets["slack"]}"',
    ])
    sc = SecretScanner()
    findings = sc.scan_file("config/settings.py", content)
    assert findings, "expected at least one detected secret"
    for f in findings:
        stored = redact_with_scanner(getattr(f, "code_snippet", "") or "", sc)
        leaked = [k for k, v in secrets.items() if v in stored]
        assert not leaked, f"{f.rule_id}: leaked {leaked} at rest"


# ── redact_snippet_for_storage: the SHARED store-time redactor (B) ──
# The git-scan main loop AND the source-adapter loop now both call this ONE
# function, so co-located-secret masking can no longer drift between them (the
# duplication that let G1 exist on one path). A tiny stub scanner drives the
# no-raw-value branch (which routes through redact_with_scanner) without a
# full rule pack.
class _StubScanner:
    def scan_file(self, name, content):
        return []


def test_storage_redactor_masks_own_value_and_colocated_shape():
    # raw IS a substring → conditional takes the cheap-scrub branch. Own value
    # masked by targeted redaction; co-located Slack token (a false negative)
    # masked by the residual shape scrub.
    own = _AWS
    snippet = f'AWS_KEY = "{own}"\nSLACK = "{_SLACK}"'
    out = redact_snippet_for_storage(snippet, own, "AKIA****ASDFGH", scanner=_StubScanner())
    assert own not in out, "own value leaked"
    assert _SLACK not in out, "co-located FN leaked"


def test_storage_redactor_no_raw_routes_through_scanner_scrub():
    # No raw value → full-rescan branch (redact_with_scanner), whose final
    # residual scrub still masks the co-located shape.
    snippet = f'token = "{_GHP}"'
    out = redact_snippet_for_storage(snippet, "", "", scanner=_StubScanner())
    assert _GHP not in out


def test_storage_redactor_masks_paired_credential():
    paired = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"
    snippet = f'akid = "{_AWS}"\nsecret = "{paired}"'
    out = redact_snippet_for_storage(
        snippet, _AWS, "AKIA****ASDFGH", paired, "wJal****EKEY", scanner=_StubScanner())
    assert _AWS not in out
    assert paired not in out


def test_storage_redactor_masks_truncated_pem():
    # The shared store-time redactor must also close the truncated-PEM leak.
    snippet = ('key = """\n-----BEGIN RSA PRIVATE KEY-----\n'
               'MIIEpgIBAAKCAQEAtruncatedkeybodyXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n')
    out = redact_snippet_for_storage(snippet, "", "", scanner=_StubScanner())
    assert "MIIEpgIBAAKCAQEAtruncatedkeybody" not in out
    assert "REDACTED" in out


def test_storage_redactor_none_and_empty_safe():
    assert redact_snippet_for_storage("", "x", "y", scanner=_StubScanner()) == ""
    assert redact_snippet_for_storage(None, "x", "y", scanner=_StubScanner()) == ""


# ── scrub_secrets_in_obj: AI-generated free-text fields (G1b) ──
# The AI echoes the secret it was asked to triage into its reasoning, TP/FP
# reasons, and remediation summaries / patch diffs. This recursively masks
# secret shapes in any str/list/dict so none of those persist at rest or
# serve via API/UI — while leaving the surrounding prose and non-strings intact.
def test_scrub_secrets_in_obj_masks_nested_free_text():
    import json
    obj = {
        "reasoning_summary": f"Real AWS access key ({_AWS}) with sufficient entropy",
        "true_positive_reasons": [f"Slack token {_SLACK} present", "no secret in this one"],
        "confidence_score": 0.9,                                   # non-str: untouched
        "patch_diff": f'-AWS_KEY = "{_AWS}"\n+AWS_KEY = os.environ["AWS_KEY"]',
        "nested": {"developer_notes": [f"rotate {_GHP} immediately"]},
    }
    out = scrub_secrets_in_obj(obj)
    blob = json.dumps(out)
    assert _AWS not in blob, "AWS key survived in AI text"
    assert _SLACK not in blob, "Slack token survived"
    assert _GHP not in blob, "GitHub PAT survived in nested notes"
    # prose + non-string values preserved
    assert out["confidence_score"] == 0.9
    assert "sufficient entropy" in out["reasoning_summary"]
    assert "no secret in this one" in out["true_positive_reasons"]
    # the patch still reads as a removal of the (now-masked) secret line
    assert out["patch_diff"].startswith('-AWS_KEY = "AKIA')


def test_scrub_secrets_in_obj_passthrough_non_text():
    assert scrub_secrets_in_obj(None) is None
    assert scrub_secrets_in_obj(42) == 42
    assert scrub_secrets_in_obj([]) == []
