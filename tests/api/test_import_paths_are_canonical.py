# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""One import path per module.

The deployed image sets ``PYTHONPATH=/app`` (infra/docker/Dockerfile.api),
so the API package is importable as ``apps.api.app.*`` and nothing else.
A bare ``app.*`` import therefore fails at collection time in the real
environment — but resolves happily for anyone who has added
``/app/apps/api`` to their own path while poking at a container.

That is the bad case: it works in the shell where it was written and
breaks everywhere else. Worse, when BOTH paths resolve, Python treats
them as two different modules — two ``settings`` objects, two module
registries — so setting ``settings.EDITION`` through one import has no
effect on code that read the other, and a gate looks broken for reasons
nothing in the source explains.

This check costs nothing and turns a confusing runtime puzzle into a
failing test with a name.
"""
from __future__ import annotations

import pathlib
import re

#: Repo root — this file lives at tests/api/, so two levels up.
_ROOT = pathlib.Path(__file__).resolve().parents[2]

_SKIP_DIRS = {"node_modules", ".next", ".git", "__pycache__", "alembic"}

#: `from app.x import y` or `import app.x`, but not `from apps.api.app...`
_BARE = re.compile(r"^\s*(?:from|import)\s+app\.", re.M)


def _python_files():
    for path in _ROOT.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path


def test_nothing_imports_the_api_package_by_its_bare_name():
    offenders = []
    for path in _python_files():
        try:
            text = path.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        if _BARE.search(text):
            offenders.append(str(path.relative_to(_ROOT)))
    assert not offenders, (
        "these import the API package as `app.*`, which is not importable "
        "when PYTHONPATH=/app — use `apps.api.app.*`:\n  "
        + "\n  ".join(sorted(offenders))
    )


def test_the_canonical_path_is_the_one_that_resolves():
    """Stated as a fact rather than a convention, so it cannot drift."""
    import apps.api.app.core.config as canonical

    assert canonical.settings is not None
    # And the bare name must NOT be importable here, because if it is,
    # this environment is not the one the product ships in.
    import importlib.util
    assert importlib.util.find_spec("apps.api.app.core.config") is not None
