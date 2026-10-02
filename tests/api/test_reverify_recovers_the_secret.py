# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Re-verify has to be able to verify something.

Vooda never stores the secret — the scan pipeline strips
`_raw_value_for_verification` before the row is written, deliberately.
What nobody noticed is that the verifier needs exactly that field, so
`POST /findings/{id}/verify` had been answering "Raw secret value not
available for verification" for every finding whose provider it
supported, since the button shipped. Verification only ever really
happened mid-scan, while the value was still in memory.

The value is recovered from the repository clone at verify time and
never stored. These tests hold that line: the secret must come back,
must be matched by hash rather than by line number, and must not end up
anywhere it can be read afterwards.
"""
import hashlib
import os
import pathlib

import pytest

ROUTER = pathlib.Path("apps/api/app/routers/findings.py")
INCIDENTS = pathlib.Path("apps/api/app/routers/incidents.py")
PANEL = pathlib.Path("apps/web/src/components/findings/FindingPanel.tsx")


# ── The thing that was actually broken ──────────────────────────────

def test_the_secret_is_still_not_stored():
    """The fix must not become "keep the secret". If this ever fails,
    the recovery path has been replaced by a copy at rest."""
    from apps.worker import tasks
    src = pathlib.Path(tasks.__file__).read_text(encoding="utf-8")
    assert 'raw_data_persisted.pop("_raw_value_for_verification", None)' in src


def test_verify_recovers_the_value_before_calling_a_verifier():
    src = ROUTER.read_text(encoding="utf-8")
    assert "recover_secret_value(" in src
    # The verifier is handed the recovered value, and the row is not.
    assert '{**sm, "_raw_value": raw_value}' in src


def test_the_recovered_value_is_never_written_back_to_the_row():
    """`updated_sm` is what gets stored and returned to the browser."""
    src = ROUTER.read_text(encoding="utf-8")
    assert 'updated_sm.pop("_raw_value", None)' in src


def test_the_incident_path_was_fixed_too():
    """An incident verify hands the verifier an occurrence's metadata,
    which has the same empty field."""
    src = INCIDENTS.read_text(encoding="utf-8")
    assert "recover_secret_value(" in src
    assert '{**sm, "_raw_value": raw_value}' in src


# ── Recovery semantics ──────────────────────────────────────────────

@pytest.fixture
def clone(tmp_path, monkeypatch):
    """A repository clone on disk, with a secret in a file."""
    from apps.api.app.core.config import settings
    monkeypatch.setattr(settings, "STORAGE_PATH", str(tmp_path), raising=False)
    repo_id = "11111111-2222-3333-4444-555555555555"
    root = tmp_path / "repos" / repo_id
    (root / "cfg").mkdir(parents=True)
    # Assembled rather than written out. The digits are all zeros and
    # the tail is the alphabet, so it is obviously synthetic to a
    # reader — but it is a real Slack token SHAPE, and GitHub's push
    # protection blocks the file on sight. Building it at runtime keeps
    # the test honest (the detector still has to match it once written
    # to disk) without committing something that trips every scanner
    # between here and the remote.
    secret = "-".join(["xoxb", "0" * 10, "0" * 13, "abcdefghijklmnopqrstuvwx"])
    (root / "cfg" / "app.env").write_text(
        f"# config\nSLACK_BOT_TOKEN={secret}\n", encoding="utf-8")
    return {
        "repo_id": repo_id,
        "root": root,
        "secret": secret,
        "hash": hashlib.sha256(secret.encode()).hexdigest()[:32],
        "path": "cfg/app.env",
    }


def test_the_secret_comes_back(clone):
    from services.secret_verification.recovery import recover_secret_value
    got = recover_secret_value(
        repository_id=clone["repo_id"],
        file_path=clone["path"],
        secret_hash=clone["hash"],
    )
    assert got == clone["secret"]


def test_a_secret_that_has_been_removed_is_reported_as_such(clone):
    """Not "verification failed" — the secret being gone is the answer
    somebody re-verifying was hoping for."""
    from services.secret_verification.recovery import (
        recover_secret_value, RecoveryUnavailable,
    )
    (clone["root"] / "cfg" / "app.env").write_text("# config\n", encoding="utf-8")
    with pytest.raises(RecoveryUnavailable) as exc:
        recover_secret_value(
            repository_id=clone["repo_id"],
            file_path=clone["path"],
            secret_hash=clone["hash"],
        )
    assert "no longer in the file" in str(exc.value)


def test_a_different_secret_on_the_same_line_is_not_verified(clone):
    """Identity is the hash, not the line. Verifying whatever now sits
    where the old secret was would report a status for a credential
    nobody asked about."""
    from services.secret_verification.recovery import (
        recover_secret_value, RecoveryUnavailable,
    )
    # A DIFFERENT secret in the same place — see the note on the
    # fixture for why this is assembled rather than written out.
    other = "-".join(["xoxb", "9" * 10, "9" * 13, "zyxwvutsrqponmlkjihgfedc"])
    (clone["root"] / "cfg" / "app.env").write_text(
        f"# config\nSLACK_BOT_TOKEN={other}\n", encoding="utf-8")
    with pytest.raises(RecoveryUnavailable):
        recover_secret_value(
            repository_id=clone["repo_id"],
            file_path=clone["path"],
            secret_hash=clone["hash"],
        )


def test_a_missing_clone_says_to_rescan(clone):
    from services.secret_verification.recovery import (
        recover_secret_value, RecoveryUnavailable,
    )
    with pytest.raises(RecoveryUnavailable) as exc:
        recover_secret_value(
            repository_id="99999999-9999-9999-9999-999999999999",
            file_path=clone["path"],
            secret_hash=clone["hash"],
        )
    assert "Re-scan" in str(exc.value)


def test_a_source_scan_finding_says_why_it_cannot(clone):
    """Slack/Jira/S3 findings have no local copy to re-read."""
    from services.secret_verification.recovery import (
        recover_secret_value, RecoveryUnavailable,
    )
    with pytest.raises(RecoveryUnavailable) as exc:
        recover_secret_value(
            repository_id=None, file_path="x", secret_hash=clone["hash"])
    assert "repository scans" in str(exc.value)


def test_a_path_cannot_escape_the_clone(clone, tmp_path):
    """`file_path` is read from the database, but it got there from a
    scanner walking a tree."""
    from services.secret_verification.recovery import (
        recover_secret_value, RecoveryUnavailable,
    )
    (tmp_path / "outside.env").write_text(
        f"SLACK_BOT_TOKEN={clone['secret']}\n", encoding="utf-8")
    with pytest.raises(RecoveryUnavailable) as exc:
        recover_secret_value(
            repository_id=clone["repo_id"],
            file_path="../../outside.env",
            secret_hash=clone["hash"],
        )
    assert "not inside the repository" in str(exc.value)


# ── The button no longer offers what it cannot do ───────────────────

def test_can_verify_refuses_a_provider_with_no_verifier():
    from services.secret_verification.verifier import can_verify
    assert can_verify({"provider": "rsa", "detection_method": "regex"}) is False
    assert can_verify({"provider": "ssh", "detection_method": "regex"}) is False
    assert can_verify({"provider": "slack", "detection_method": "regex"}) is True


def test_can_verify_respects_the_global_kill_switch(monkeypatch):
    """Air-gapped deployments forbid all outbound verification; the
    button should be dead there too."""
    from apps.api.app.core.config import settings
    import services.secret_verification.verifier as v
    monkeypatch.setattr(settings, "VERIFICATION_ENABLED", False, raising=False)
    assert v.can_verify({"provider": "slack", "detection_method": "regex"}) is False


def test_the_api_tells_the_client_whether_to_offer_the_button():
    src = ROUTER.read_text(encoding="utf-8")
    assert '"verifier_available": verifier_available' in src


def test_the_button_is_disabled_rather_than_hidden():
    """Hidden, the user is left wondering where it went; disabled with
    a reason, they learn an RSA key has no issuer to ask."""
    web = PANEL.read_text(encoding="utf-8")
    assert 'verifier_available === false' in web
    assert "No verifier exists for" in web


# ── Paired credentials ──────────────────────────────────────────────
#
# Eight credential families are only verifiable two values at a time:
# an AWS access key id proves nothing without its secret key. VERIFIERS
# holds those under keys like "aws_paired", which no finding ever
# carries as its provider — they are reached by matching the finding's
# secret TYPE against the pairing table.
#
# The scan pipeline has always done that. Manual re-verify never did:
# it looked up the provider, found no "aws", and answered "unsupported"
# for a credential it had verified minutes earlier in the same scan.

def test_a_paired_primary_is_recognised():
    # The secret type here is what VOODA-SEC-AWS-001 actually emits.
    # This test first used the name the pairing table carried, which no
    # rule produces — which is exactly why the pairing had never fired.
    # See test_pairing_table_matches_the_detectors.py.
    from services.secret_verification.verifier import paired_verifier_key
    assert paired_verifier_key({"secret_type": "aws_access_key"}) == "aws_paired"
    assert paired_verifier_key(
        {"secret_type": "stripe_publishable_key"}) == "stripe_connect_paired"
    assert paired_verifier_key({"secret_type": "slack_webhook_url"}) is None


def test_every_paired_verifier_key_actually_exists():
    """A pairing table entry naming a verifier that was never
    registered would silently fall back to the single-value path."""
    from services.secret_verification.verifier import VERIFIERS
    from services.secret_verification.credential_pairing import KNOWN_PAIRS
    for pair in KNOWN_PAIRS:
        assert pair.verifier_key in VERIFIERS, pair.verifier_key


def test_the_button_is_offered_for_half_a_pair():
    """The regression: an AWS access key id has no `aws` verifier, so
    can_verify said no and the control was dead for all eight paired
    families."""
    from services.secret_verification.verifier import can_verify
    assert can_verify({
        "provider": "aws",
        "secret_type": "aws_access_key",
        "detection_method": "regex",
    }) is True


def test_the_manual_path_pairs_the_way_the_scan_does():
    for path in (ROUTER, INCIDENTS):
        src = path.read_text(encoding="utf-8")
        assert "verify_finding_with_pairing as _verify" in src, path
        assert "repo_root=repo_clone_root(" in src, path


@pytest.mark.asyncio
async def test_half_a_pair_with_no_partner_says_so(tmp_path, monkeypatch):
    """Not "unsupported provider" — the provider is supported; the
    other half of the credential is missing."""
    from apps.api.app.core.config import settings
    from services.secret_verification.verifier import verify_finding_with_pairing
    monkeypatch.setattr(settings, "STORAGE_PATH", str(tmp_path), raising=False)
    (tmp_path / "f.txt").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
                                    encoding="utf-8")
    result = await verify_finding_with_pairing(
        {
            "provider": "aws",
            "secret_type": "aws_access_key",
            "detection_method": "regex",
            "_raw_value": "AKIAIOSFODNN7EXAMPLE",
        },
        repo_root=str(tmp_path),
        file_path="f.txt",
        line_start=1,
    )
    assert result is not None
    assert result.status == "unsupported"
    assert "partner" in result.details.lower()


@pytest.mark.asyncio
async def test_an_unpaired_credential_still_takes_the_plain_path(monkeypatch):
    """Pairing must not swallow the ordinary case."""
    import services.secret_verification.verifier as v
    seen = {}

    async def _fake(sm):
        seen["sm"] = sm
        return v.VerificationResult(status="inactive", details="x", provider="slack")

    monkeypatch.setattr(v, "verify_finding", _fake)
    result = await v.verify_finding_with_pairing(
        {"provider": "slack", "secret_type": "slack_webhook_url",
         "detection_method": "regex", "_raw_value": "x"},
    )
    assert result.status == "inactive"
    assert seen["sm"]["provider"] == "slack"


def test_the_panel_leads_with_the_two_questions_that_matter():
    """Is it real, and is it still live. The masked value led this row
    before — it identifies the finding, but the header already names it
    and gives its path, so by the time anyone reads the tiles they know
    which secret they are looking at."""
    src = PANEL.read_text(encoding="utf-8")
    first_grid = src.index('<div className="grid grid-cols-2 gap-3">')
    row = src[first_grid:first_grid + 2200]
    assert ">AI Verdict<" in row
    assert ">Validation Status<" in row
    assert ">Masked Value<" not in row, "the masked value belongs with the provenance"


def test_no_screen_keeps_its_own_copy_of_the_validity_words():
    """Six screens carried a private label map, and every one of them
    was missing `unsupported` and `check_failed` — so both printed the
    raw enum word at the user. It kept recurring because copying five
    lines is easier than finding the shared helper, which is exactly
    why this is a test and not a comment.

    Tones may stay local; the WORDS may not."""
    import pathlib
    screens = [
        "apps/web/src/components/findings/FindingPanel.tsx",
        "apps/web/src/components/incidents/IncidentDetailDrawer.tsx",
        "apps/web/src/app/findings/page.tsx",
        "apps/web/src/app/incidents/[id]/page.tsx",
        "apps/web/src/app/secrets/[id]/page.tsx",
    ]
    for name in screens:
        src = pathlib.Path(name).read_text(encoding="utf-8")
        assert "const valLabels" not in src, name
        assert "validityLabel" in src, f"{name} must use the shared labels"
        # `not_validated` is a legacy spelling `validity()` folds into
        # `unknown`, so a map keyed on it has a branch that can never be
        # reached — and, every time, no branch for the two states that
        # replaced it. Comments explaining that are fine; keys are not.
        for line in src.splitlines():
            if "not_validated:" in line and not line.strip().startswith("//"):
                raise AssertionError(f"{name}: dead validity key — {line.strip()}")


def test_only_a_state_worth_reading_gets_a_chip():
    """A chip is a claim on attention. "No checker" and "Not checked"
    say nothing happened — drawn as a bordered pill on every row, which
    is what the findings table did, the column became a wall of
    identical grey boxes and the two states that matter stopped
    standing out."""
    import pathlib
    src = pathlib.Path("apps/web/src/app/findings/page.tsx").read_text(encoding="utf-8")
    block = src[src.index("const chip: Record<string, string> = {"):]
    block = block[:block.index("};")]
    for signal in ("active", "inactive", "check_failed"):
        assert f"{signal}:" in block, signal
    for quiet in ("unsupported", "unknown"):
        assert f"{quiet}:" not in block, f"{quiet} should not get a chip"


def test_an_uncheckable_credential_explains_itself_without_a_hover():
    """`unsupported` is a permanent answer for a private key, and the
    reason was reachable only by hovering a disabled button. The panel
    also rendered the raw enum word, because it carried its own label
    map which had no entry for `unsupported` or `check_failed` — the
    shared one in lib/validity.ts has both."""
    web = PANEL.read_text(encoding="utf-8")
    assert "validityLabel(valStatus)" in web
    assert "valLabels" not in web, "the duplicate label map should be gone"
    assert "will not resolve by re-checking" in web


def test_the_verdict_and_its_confidence_are_one_statement():
    """Apart they are each meaningless: a verdict with no confidence is
    a shrug, and a confidence attached to nothing is a number about
    nothing. Two bordered tiles for one sentence also forced a label
    ("AI VERDICT CONFIDENCE") too long for the box it sat in."""
    for path in (PANEL, pathlib.Path(
            "apps/web/src/components/incidents/IncidentDetailDrawer.tsx")):
        src = path.read_text(encoding="utf-8")
        assert "AI Verdict Confidence" not in src, path
        assert src.count(">AI Verdict<") == 1, path


def test_a_provider_is_not_rendered_by_css_capitalize():
    """`capitalize` on a lowercase slug renders "Ssh" and "Aws" — close
    enough to read, wrong enough to look like a defect."""
    src = PANEL.read_text(encoding="utf-8")
    assert "providerLabel(provider)" in src
    assert "capitalize\">{provider}" not in src


def test_provider_labels_are_spelled_the_way_the_vendor_spells_them():
    import subprocess, json
    lib = pathlib.Path("apps/web/src/lib/providerConsoles.ts").read_text(encoding="utf-8")
    # The acronym set and the override table are what stop "Ssh".
    for slug in ("ssh", "aws", "gcp", "rsa", "jdbc"):
        assert f'"{slug}"' in lib, slug
    for slug, name in (("pkcs8", "PKCS#8"), ("github", "GitHub"),
                       ("postgresql", "PostgreSQL")):
        assert f'{slug}: "{name}"' in lib, slug
