"""A literal path must not be swallowed by a catch-all above it.

GET /ai-models/probe-results was defined after GET /ai-models/{model_id}.
FastAPI matches in definition order, so the literal path was parsed as
model_id="probe-results", failed UUID validation and returned 422.

Nothing errored loudly. The screen just never loaded a cached verdict,
so every readiness badge was missing and the caching the feature depends
on did nothing at all — the kind of break that looks like "the feature
doesn't work" rather than an exception anyone can search for.
"""
import re

import pytest

from apps.api.app.routers import ai_models


def _routes():
    return [r for r in ai_models.router.routes if hasattr(r, "path")]


def _index_of(path: str, method: str) -> int:
    for i, r in enumerate(_routes()):
        if r.path == path and method in (r.methods or set()):
            return i
    raise AssertionError(f"{method} {path} is not registered")


def test_literal_paths_are_registered_before_the_catch_all():
    catch_all = _index_of("/{model_id}", "GET")
    for literal in ("/probe-results", "/engine-settings", "/status"):
        assert _index_of(literal, "GET") < catch_all, (
            f"GET {literal} is shadowed by /{{model_id}} and will 422"
        )


def test_no_literal_get_route_sits_below_a_parameterised_one():
    """Stated generally so a future literal route is caught too."""
    first_param_at = None
    for i, r in enumerate(_routes()):
        if "GET" not in (r.methods or set()):
            continue
        is_param = bool(re.search(r"\{[^}]+\}", r.path))
        if is_param and first_param_at is None:
            first_param_at = i
        elif not is_param and first_param_at is not None:
            # A literal below a parameterised route only collides when
            # it could match that pattern — same segment count.
            param_path = _routes()[first_param_at].path
            if param_path.count("/") == r.path.count("/"):
                raise AssertionError(
                    f"GET {r.path} is declared after {param_path} and will be shadowed"
                )
