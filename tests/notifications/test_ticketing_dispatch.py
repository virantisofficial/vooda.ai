"""Every advertised ticketing provider must actually route to a handler.

Jira and ServiceNow had ticket-creation handlers; Linear and
custom_ticketing did not, so _send_to_channel fell through to
"Unknown channel: <provider>". Both were advertised in the UI,
configurable, and passed their Test Connection — yet a finding routed
to them silently produced no ticket. This guards against that whole
class: a provider offered in the ticketing UI that the dispatcher
cannot service.
"""

from types import SimpleNamespace

import pytest

from services.notifications.dispatcher import NotificationDispatcher, NotificationPayload


TICKETING_PROVIDERS = ["jira", "servicenow", "linear", "custom_ticketing"]


@pytest.mark.parametrize("provider", TICKETING_PROVIDERS)
@pytest.mark.asyncio
async def test_provider_routes_to_a_handler_not_unknown_channel(provider):
    d = NotificationDispatcher()

    # Stub the provider's own handler so this checks routing only, with
    # no network. If routing is missing, _send_to_channel returns the
    # "Unknown channel" error instead of reaching the stub.
    async def _stub(config, payload):
        from services.notifications.dispatcher import DispatchResult
        return DispatchResult(channel=provider, success=True)

    setattr(d, f"_send_{provider}", _stub)
    channel = SimpleNamespace(provider=provider, config={})
    result = await d._send_to_channel(channel, NotificationPayload(title="t", body="b", severity="high"))

    assert "Unknown channel" not in (result.error or ""), f"{provider} is not routed"
    assert result.success is True


@pytest.mark.asyncio
async def test_custom_ticketing_posts_the_finding_to_the_webhook():
    """The custom handler must POST to webhook_url and succeed on 2xx."""
    from unittest.mock import patch, AsyncMock

    d = NotificationDispatcher()
    payload = NotificationPayload(title="Hardcoded AWS key", body="found", severity="critical")

    class _R:
        status_code = 202

    posted = {}

    async def _post(url, **kw):
        posted["url"] = url
        posted["json"] = kw.get("json")
        return _R()

    client = AsyncMock()
    client.__aenter__.return_value = client
    client.post = _post

    with patch("httpx.AsyncClient", return_value=client):
        r = await d._send_custom_ticketing({"webhook_url": "https://tickets.example/hook"}, payload)

    assert r.success is True
    assert posted["url"] == "https://tickets.example/hook"
    assert posted["json"]["title"] == "Hardcoded AWS key"
    assert posted["json"]["source"] == "vooda_ai"


@pytest.mark.asyncio
async def test_linear_without_a_team_and_multiple_teams_asks_for_team_key():
    """A workspace with >1 team and no team_key must fail with guidance,
    not pick a team at random."""
    from unittest.mock import patch, AsyncMock

    d = NotificationDispatcher()

    class _R:
        status_code = 200
        def json(self):
            return {"data": {"teams": {"nodes": [{"id": "1", "key": "ENG"}, {"id": "2", "key": "SEC"}]}}}

    client = AsyncMock()
    client.__aenter__.return_value = client
    client.post = AsyncMock(return_value=_R())

    with patch("httpx.AsyncClient", return_value=client):
        r = await d._send_linear({"api_key": "lin_x"}, NotificationPayload(title="t", body="b"))

    assert r.success is False
    assert "team_key" in (r.error or "")
