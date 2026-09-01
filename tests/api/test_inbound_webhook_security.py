"""The inbound webhook receiver must fail closed.

This endpoint is (meant to be) public — GitHub/GitLab/Bitbucket
authenticate with an HMAC signature, not a bearer token — so the
signature is the only thing between a real provider event and a forged
one. It was previously verified only when a secret happened to be
configured, and the default has none: with no secret set, ANY POST was
accepted and could trigger scans. These lock the secure behaviour in.
"""

import hashlib
import hmac
import json

import pytest


async def _set_secret(client, jwt, provider, secret, enable=None):
    """Set the signing secret, and enable the webhook when one is given.

    The receiver only loads secrets from ACTIVE configs — a disabled
    webhook is not processed at all — so a test that sets a secret
    without enabling is not exercising signature verification.
    """
    body = {"secret": secret}
    if enable is None:
        enable = bool(secret)
    body["enabled"] = enable
    return await client.put(
        f"/api/v1/webhooks/{provider}/config",
        json=body,
        headers={"Authorization": f"Bearer {jwt}"},
    )


@pytest.mark.asyncio(loop_scope="module")
async def test_cannot_enable_a_webhook_without_a_secret(client, admin_jwt):
    h = {"Authorization": f"Bearer {admin_jwt}"}
    # Clear any secret left by another test / prior run so this asserts
    # the no-secret path rather than depending on ordering.
    await client.put("/api/v1/webhooks/github/config", json={"secret": ""}, headers=h)

    r = await client.put("/api/v1/webhooks/github/config", json={"enabled": True}, headers=h)
    assert r.status_code == 400
    assert "secret" in r.text.lower()


@pytest.mark.asyncio(loop_scope="module")
async def test_receiver_rejects_when_no_secret_is_configured(client, admin_jwt):
    """No secret => cannot verify => must not process. (admin_jwt only
    bypasses the router scope check; the receiver's own fail-closed
    logic is what is under test.)"""
    # Ensure this provider has no secret.
    await _set_secret(client, admin_jwt, "bitbucket", "")

    r = await client.post(
        "/api/v1/webhooks/bitbucket",
        content=b'{"push":{}}',
        headers={
            "Authorization": f"Bearer {admin_jwt}",
            "X-Event-Key": "repo:push",
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 401
    assert "no signing secret" in r.text.lower()


@pytest.mark.asyncio(loop_scope="module")
async def test_receiver_rejects_a_bad_signature(client, admin_jwt):
    await _set_secret(client, admin_jwt, "github", "the-secret")

    body = b'{"ref":"refs/heads/main","repository":{"full_name":"x/y"}}'
    r = await client.post(
        "/api/v1/webhooks/github",
        content=body,
        headers={
            "Authorization": f"Bearer {admin_jwt}",
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": "sha256=deadbeef",  # wrong
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 401
    assert "invalid webhook signature" in r.text.lower()


@pytest.mark.asyncio(loop_scope="module")
async def test_receiver_accepts_a_correct_signature(client, admin_jwt):
    """A correctly-signed event passes verification (positive control).

    Uses a repository URL that does not resolve, and asserts only that
    verification passed — i.e. the response is NOT one of the 401
    rejections. Whatever the receiver does after verification (trigger a
    scan, ignore an irrelevant event) is out of scope here.
    """
    secret = "correct-secret"
    await _set_secret(client, admin_jwt, "github", secret)

    body = json.dumps(
        {"ref": "refs/heads/main",
         "repository": {"full_name": "nonexistent/none",
                        "clone_url": "https://github.com/nonexistent/none.git"}}
    ).encode()
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    r = await client.post(
        "/api/v1/webhooks/github",
        content=body,
        headers={
            "Authorization": f"Bearer {admin_jwt}",
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": sig,
            "Content-Type": "application/json",
        },
    )
    assert r.status_code != 401, f"a valid signature was rejected: {r.text}"


@pytest.mark.asyncio(loop_scope="module")
async def test_webhook_secret_is_encrypted_at_rest(client, admin_jwt):
    """The signing secret must not sit in the DB in plaintext.

    A plaintext secret in the DB is the exact value needed to forge
    signed events, so a database read would defeat the whole HMAC
    check. Every other integration encrypts; this one used not to.
    """
    canary = "ENCRYPTION-CANARY-a1b2c3d4"
    r = await client.put(
        "/api/v1/webhooks/gitlab/config",
        json={"secret": canary},
        headers={"Authorization": f"Bearer {admin_jwt}"},
    )
    assert r.status_code == 200

    from sqlalchemy import create_engine, text
    from apps.api.app.core.config import settings

    engine = create_engine(settings.DATABASE_URL_SYNC)
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT config::text FROM integration_configs WHERE provider='webhook_gitlab'")
        ).scalar_one()

    assert canary not in row, "signing secret is stored in plaintext"
    assert "enc:" in row, "signing secret is not encrypted"


@pytest.mark.asyncio(loop_scope="module")
async def test_config_masks_the_secret_and_reports_it_is_set(client, admin_jwt):
    await client.put(
        "/api/v1/webhooks/gitlab/config",
        json={"secret": "supersecretvalue"},
        headers={"Authorization": f"Bearer {admin_jwt}"},
    )
    r = await client.get(
        "/api/v1/webhooks/config",
        headers={"Authorization": f"Bearer {admin_jwt}"},
    )
    gl = [w for w in r.json()["webhooks"] if w["provider"] == "gitlab"][0]
    assert gl["secret_set"] is True
    assert "supersecretvalue" not in gl["secret"]
    assert gl["secret"].startswith("••••")


@pytest.mark.asyncio(loop_scope="module")
async def test_posting_the_mask_back_does_not_overwrite_the_secret(client, admin_jwt):
    h = {"Authorization": f"Bearer {admin_jwt}"}
    await client.put("/api/v1/webhooks/gitlab/config", json={"secret": "realsecret123"}, headers=h)

    masked = [w for w in (await client.get("/api/v1/webhooks/config", headers=h)).json()["webhooks"]
              if w["provider"] == "gitlab"][0]["secret"]
    # Save the config again sending the mask back — the real secret must survive.
    await client.put("/api/v1/webhooks/gitlab/config", json={"secret": masked}, headers=h)

    from sqlalchemy import create_engine, text
    from apps.api.app.core.config import settings
    from packages.common.encryption import decrypt_value

    engine = create_engine(settings.DATABASE_URL_SYNC)
    with engine.connect() as conn:
        import json as _json
        cfg = conn.execute(
            text("SELECT config FROM integration_configs WHERE provider='webhook_gitlab'")
        ).scalar_one()
    cfg = cfg if isinstance(cfg, dict) else _json.loads(cfg)
    assert decrypt_value(cfg["webhook_secret"]) == "realsecret123"


@pytest.mark.asyncio(loop_scope="module")
async def test_disabled_webhook_says_disabled_not_missing_secret(client, admin_jwt):
    """A configured-but-switched-off webhook must say so.

    The receiver only reads secrets from ACTIVE configs, so a disabled
    webhook with a perfectly good secret was reported as having none —
    sending the operator to set a secret that was already set, which
    changes nothing and leaves the webhook still disabled.
    """
    h = {"Authorization": f"Bearer {admin_jwt}"}
    # Configure and enable, then switch off while keeping the secret.
    await _set_secret(client, admin_jwt, "github", "still-configured")
    r = await client.put(
        "/api/v1/webhooks/github/config", json={"enabled": False}, headers=h
    )
    assert r.status_code < 400, r.text

    r = await client.post(
        "/api/v1/webhooks/github",
        content=b'{"ref":"refs/heads/main","repository":{"full_name":"x/y"}}',
        headers={**h, "X-GitHub-Event": "push", "Content-Type": "application/json"},
    )
    assert r.status_code == 401
    text = r.text.lower()
    assert "disabled" in text, f"expected a disabled diagnostic, got: {r.text}"
    assert "no signing secret" not in text, (
        "a secret IS configured — reporting it missing sends the operator "
        "to fix the wrong thing"
    )
