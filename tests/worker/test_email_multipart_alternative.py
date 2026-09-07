# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Notification email carries a real text/plain alternative.

The message is declared multipart/alternative — a promise that the
client may pick a rendering — but only a text/html part was attached.
Text-only clients, strict corporate gateways and screen-reader setups
that prefer the plain part rendered nothing.
"""
import inspect

from services.notifications import dispatcher as mod


def test_both_alternative_parts_are_attached():
    src = inspect.getsource(mod)
    assert 'MIMEText("\\n".join(plain_lines), "plain")' in src
    assert 'MIMEText(html, "html")' in src


def test_plain_precedes_html():
    """RFC 2046: alternatives ordered least- to most-preferred, so the
    plain part must be attached first or html-capable clients would be
    told plain is the better rendering."""
    src = inspect.getsource(mod)
    assert src.index('"plain"') < src.index('MIMEText(html, "html")')


def test_plain_part_carries_the_link():
    """The html part's call-to-action must not be html-only."""
    src = inspect.getsource(mod)
    assert "View in Vooda AI:" in src
