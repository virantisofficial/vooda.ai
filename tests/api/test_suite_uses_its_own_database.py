# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""The suite must not be pointed at a deployment's database.

These are integration tests against a real Postgres, and for a long
time that Postgres was whichever one the install had configured. The
damage was not hypothetical: the inbound webhook tests set signing
secrets through the real config endpoint, so a full run replaced the
GitHub, GitLab and Bitbucket webhook secrets of the configured install.
Deliveries then failed signature verification, and nothing said why —
the provider simply retried until it gave up.

tests/conftest.py redirects to `<database>_test` before anything opens
a connection. This asserts the redirect actually took, because the
failure it prevents is silent and expensive, and a conftest is easy to
reorder without noticing what the order was for.
"""
from __future__ import annotations

import os

import pytest

from apps.api.app.core.config import settings


def _database_name(url: str) -> str:
    return url.rpartition("/")[2].partition("?")[0]


@pytest.mark.skipif(
    os.environ.get("VOODA_TEST_USE_CONFIGURED_DB") == "1",
    reason="running against the configured database on purpose",
)
@pytest.mark.parametrize("url_attr", ["DATABASE_URL", "DATABASE_URL_SYNC"])
def test_the_suite_talks_to_a_test_database(url_attr):
    name = _database_name(getattr(settings, url_attr))
    assert name.endswith("_test"), (
        f"{url_attr} points at {name!r} — a full run writes to it, and "
        f"the webhook tests will overwrite that install's signing secrets"
    )


@pytest.mark.skipif(
    os.environ.get("VOODA_TEST_USE_CONFIGURED_DB") == "1",
    reason="running against the configured database on purpose",
)
def test_both_urls_agree():
    """Async writes and sync reads landing in different databases would
    be worse than either mistake on its own."""
    assert _database_name(settings.DATABASE_URL) == _database_name(
        settings.DATABASE_URL_SYNC)


def test_the_opt_out_is_explicit():
    """Opting back in has to be a deliberate act, spelled the one way.

    The old behaviour was the default and nothing announced it, which
    is why it went unnoticed for so long.
    """
    import pathlib

    conftest = pathlib.Path("tests/conftest.py")
    if not conftest.exists():
        pytest.skip("run from a repository checkout")
    src = conftest.read_text()
    assert 'VOODA_TEST_USE_CONFIGURED_DB' in src
    assert '== "1"' in src, "a truthy check would make any value opt out"
