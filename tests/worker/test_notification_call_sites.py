# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Every send_notification call must bind the arguments it intends.

The webhook (push / PR) call site passed five positional values against a
nine-parameter signature that had since changed shape, so every argument
landed one slot early: the task received a scan-job id as its tenant, an
event name as its severity, and the message text as its event type.

Nothing raised. A scan-job UUID parses as a UUID and simply matches no
channels, an unknown severity degrades to "info" and is filtered by any
threshold above "all", and an unrecognised event type matches no rule.
Push and PR scans therefore notified nobody, silently, and the task
reported success.

Positional binding is what made a signature change silently rebind five
values, so these tests require keyword arguments at every call site and
check the values that actually carry meaning.
"""
import ast
import inspect
import re

import pytest

from apps.worker import tasks


SRC = inspect.getsource(tasks)


def _call_sites():
    """Every `send_notification.delay(...)` in the worker, parsed."""
    tree = ast.parse(SRC)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if (isinstance(f, ast.Attribute) and f.attr == "delay"
                and isinstance(f.value, ast.Name) and f.value.id == "send_notification"):
            out.append(node)
    return out


def test_there_are_call_sites_to_check():
    """Guards the guard — an empty list would pass everything below."""
    assert len(_call_sites()) >= 3


@pytest.mark.parametrize("idx", range(len(_call_sites())))
def test_call_sites_use_keyword_arguments(idx):
    """Positional binding is how a signature change silently rebinds
    every value; keywords fail loudly instead."""
    node = _call_sites()[idx]
    assert not node.args, (
        f"send_notification.delay call #{idx + 1} (line {node.lineno}) passes "
        f"{len(node.args)} positional argument(s) — bind by keyword so a "
        f"signature change cannot shift them"
    )


@pytest.mark.parametrize("idx", range(len(_call_sites())))
def test_tenant_id_is_a_tenant(idx):
    """The failure that hid this: a scan-job id parses as a UUID, so the
    dispatcher matched zero channels rather than erroring."""
    node = _call_sites()[idx]
    kw = {k.arg: ast.unparse(k.value) for k in node.keywords}
    tid = kw.get("tenant_id", "")
    assert "tenant_id" in tid, (
        f"call #{idx + 1} (line {node.lineno}) passes {tid!r} as tenant_id"
    )


@pytest.mark.parametrize("idx", range(len(_call_sites())))
def test_event_type_is_a_known_rule(idx):
    """An unrecognised event type matches no rule, so the notification is
    dropped by the rule gate."""
    from apps.api.app.routers.notification_rules import DEFAULT_RULES
    known = {r["event_type"] for r in DEFAULT_RULES}
    node = _call_sites()[idx]
    kw = {k.arg: ast.unparse(k.value) for k in node.keywords}
    raw = kw.get("event_type", "")
    literal = raw.strip("\"'")
    if not literal or raw.startswith("f") or "{" in raw:
        pytest.fail(f"call #{idx + 1} (line {node.lineno}) event_type is not a literal: {raw!r}")
    assert literal in known, (
        f"call #{idx + 1} (line {node.lineno}) uses event_type={literal!r}, "
        f"which matches no notification rule — known: {sorted(known)}"
    )


@pytest.mark.parametrize("idx", range(len(_call_sites())))
def test_severity_is_a_recognised_level(idx):
    """An unknown severity degrades to 'info' and is filtered out by any
    threshold above 'all' — a silent drop, not an error."""
    node = _call_sites()[idx]
    kw = {k.arg: ast.unparse(k.value) for k in node.keywords}
    raw = kw.get("severity", "")
    literal = raw.strip("\"'")
    if not literal:
        pytest.fail(f"call #{idx + 1} (line {node.lineno}) passes no severity")
    if raw.startswith(("f", "notif", "_")) or "(" in raw or "." in raw:
        return  # computed at runtime; the dispatcher's own defaults apply
    assert literal in {"info", "low", "medium", "warning", "high", "critical"}, (
        f"call #{idx + 1} (line {node.lineno}) severity={literal!r} is not a "
        f"level the dispatcher recognises"
    )


def test_webhook_scan_notifies_with_repository_scope():
    """Project- and BU-scoped channels can only match when the payload
    carries the ids, so the webhook path must supply them."""
    m = re.search(r"webhook_notification_dispatched", SRC)
    assert m, "webhook notification dispatch not found"
    window = SRC[max(0, m.start() - 1600):m.start()]
    assert 'resource_type="repository"' in window
    assert "resource_id=str(repo.id)" in window
    assert "business_unit_id=" in window, (
        "without a business_unit_id, BU-scoped channels never fire"
    )
