# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""A gate nobody can switch off is not a product boundary.

Every Enterprise feature reads one setting, `settings.EDITION`, which
the app takes from an environment variable of the same name. Compose
does not pass an operator's whole environment into a container — only
the variables named in the `environment:` block — and EDITION was not
one of them. Verified against the running stack: it was unset in api,
worker and worker-scans, so the app fell back to its hardcoded
"community" and a customer who had paid could not turn Enterprise on
without editing the compose file or the source.

Two things have to hold, and the second is the one that bites:

  1. The variable is passed through at all.
  2. Every service that evaluates a gate is given the SAME value. Two
     of the gates now live in the worker — the scheduler, and the
     custom-detector registry — so an install where only the API knew
     it was Enterprise would refuse to dispatch its own scheduled
     scans. That reads as a bug, not as a licence.
"""
from __future__ import annotations

import pathlib

import pytest

yaml = pytest.importorskip("yaml")

_COMPOSE = pathlib.Path("docker-compose.yml")

#: These read deploy configuration, which is not part of the runtime
#: image — the app container ships the application, not the compose
#: file that starts it. So they protect a repo checkout (a CI job, a
#: developer running the suite from the tree) and stand aside where
#: only the app is installed, rather than failing for the absence of a
#: file that was never meant to be there.
pytestmark = pytest.mark.skipif(
    not _COMPOSE.exists(),
    reason="deploy config not present — run from a repository checkout",
)

#: Every service that runs application code able to evaluate a gate.
#: beat is included because it drives the scheduled-scan tick.
_GATE_AWARE_SERVICES = ("api", "worker", "worker-scans", "beat")


def _services() -> dict:
    return yaml.safe_load(_COMPOSE.read_text())["services"]


@pytest.mark.parametrize("service", _GATE_AWARE_SERVICES)
def test_every_gate_aware_service_is_given_the_edition(service):
    env = _services()[service].get("environment") or {}
    if isinstance(env, list):
        env = dict(e.split("=", 1) for e in env if "=" in e)
    assert "EDITION" in env, (
        f"{service} evaluates edition gates but compose never passes "
        f"EDITION into it, so it silently runs as community"
    )


def test_they_all_read_the_same_variable():
    """A split brain is worse than either edition on its own."""
    values = set()
    for service in _GATE_AWARE_SERVICES:
        env = _services()[service].get("environment") or {}
        if isinstance(env, list):
            env = dict(e.split("=", 1) for e in env if "=" in e)
        values.add(env["EDITION"])
    assert len(values) == 1, f"services disagree about EDITION: {values}"


def test_the_default_is_community():
    """An install that sets nothing must not ship Enterprise features."""
    env = _services()["api"]["environment"]
    if isinstance(env, list):
        env = dict(e.split("=", 1) for e in env if "=" in e)
    assert env["EDITION"] == "${EDITION:-community}", (
        "the fallback is what protects an operator who sets nothing"
    )


def test_the_variable_is_documented():
    """An undocumented switch is one nobody finds."""
    example = pathlib.Path(".env.example")
    assert example.exists()
    assert "EDITION=" in example.read_text()
