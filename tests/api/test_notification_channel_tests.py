"""Each notification channel's connection-test must run, not error out.

The email test imported aiosmtplib, which is not in requirements.txt, so
every email "Test" failed with "No module named 'aiosmtplib'" — while the
dispatcher sent real mail fine via stdlib smtplib. The channel worked but
could not be verified, and the error read as a platform fault.

The Teams test treated any HTTP 200 as delivered, but outlook.office.com
returns 200 with an empty body for any /webhook/ path, so a bogus URL
passed as "test message sent".
"""

import inspect

import pytest

from apps.api.app.routers import integrations


@pytest.mark.asyncio
async def test_email_test_runs_instead_of_import_erroring():
    """Behavioural: a bad host must yield a graceful failure, not crash.

    The old aiosmtplib import raised before any connection was attempted;
    the response then carried "No module named 'aiosmtplib'". Now it must
    reach a real SMTP attempt and fail on the host, not on an import.
    """
    resp = await integrations._test_email(
        {"smtp_host": "nonexistent.invalid.example", "smtp_port": "587",
         "smtp_user": "u", "smtp_password": "p", "use_tls": "true"}
    )
    assert resp.status in ("connection_failed", "auth_failed", "error")
    assert "aiosmtplib" not in (resp.message or "")
    assert "No module named" not in (resp.message or "")


@pytest.mark.asyncio
async def test_teams_empty_200_is_not_reported_as_success():
    """A bogus outlook.office.com URL returns an empty 200; a retired
    connector likewise no longer delivers. Neither may pass as success.

    Grounded in Microsoft's documented behaviour: the legacy connector
    is retired, and even a Workflow's 202 only means "accepted", not
    "delivered" — so an empty 200 is never a real delivery."""
    from unittest.mock import patch, AsyncMock

    class _R:
        def __init__(self, code, text):
            self.status_code = code
            self.text = text

    async def _teams_status(code, text):
        with patch("httpx.AsyncClient") as m:
            cli = AsyncMock()
            cli.__aenter__.return_value = cli
            cli.post = AsyncMock(return_value=_R(code, text))
            m.return_value = cli
            return await integrations._test_teams({"webhook_url": "https://x/y"})

    empty200 = await _teams_status(200, "")
    assert empty200.status != "success", empty200.message

    # A 202 (Workflow) is accepted, but the message must not claim the
    # card was delivered — only that the request was accepted.
    accepted = await _teams_status(202, "")
    assert accepted.status == "success"
    assert "accepted" in accepted.message.lower()
    assert "sent" not in accepted.message.lower(), (
        "must not claim delivery — a 202 can still fail downstream"
    )
