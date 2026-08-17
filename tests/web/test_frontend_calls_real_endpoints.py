"""Every endpoint the frontend calls must exist on the API.

This class of bug has now happened four times in this codebase:

  * SCIM was offered in a dropdown with no backend at all.
  * All five vault providers were advertised while PROVIDER_SCHEMAS knew
    none of them, so Configure answered "Unknown provider".
  * VaultSection kept calling the vault_api router deleted in May 2026 —
    GET /vault, POST /vault, /vault/{id}/test, /vault/{id}/sync — every
    one a 404, which is why the vault list was permanently empty.
  * lib/api.ts exported getCalibrationStats, pointing at
    GET /ai-models/calibration, which no endpoint has ever served.

Nothing catches it, because a frontend calling a route that does not
exist compiles, typechecks, lints and builds perfectly well. It only
fails in a browser, at the moment a user clicks — and when the handler
swallows errors, as VaultSection's did, not even then.

So compare the two sides directly. The route table is read from the
FastAPI app in-process, so this needs no running server.
"""

import re
from pathlib import Path

import pytest

WEB_SRC = Path(__file__).resolve().parents[2] / "apps/web/src"

# api.get("…") / api.post(`…`, body) etc. Deliberately not DOTALL and
# no newlines inside the quoted string: a greedy multi-line match runs
# past the call and swallows unrelated template literals, which is how
# a curl snippet in a CI-instructions block first showed up here as a
# phantom endpoint.
CALL_RE = re.compile(
    r"""\bapi\.(get|post|put|patch|delete)\s*\(\s*(["'`])([^"'`\n]*)\2"""
)


def _expand(path: str):
    """Yield the concrete paths a JS template literal can produce.

    ``/sso/${p === "saml" ? "saml/metadata" : "oidc/authorize"}`` is two
    real endpoints, not one path segment called ``{}``. Where an
    interpolation contains string literals, branch on them; otherwise
    it is a value substitution and becomes a path parameter.
    """
    m = re.search(r"\$\{([^}]*)\}", path)
    if not m:
        yield path
        return
    literals = re.findall(r"""["']([^"']*)["']""", m.group(1))
    for sub in literals or ["{}"]:
        yield from _expand(path[: m.start()] + sub + path[m.end() :])


def _collapse(path: str) -> str:
    """Strip query, trailing slash, and reduce path params to ``{}``."""
    return re.sub(r"\{[^}]*\}", "{}", path.split("?")[0].rstrip("/"))


def _normalise_call(path: str) -> str:
    """A frontend path, as the API will see it (axios prefixes /api/v1)."""
    if not path.startswith("/api/"):
        path = "/api/v1" + path
    return _collapse(path)


def _backend_routes() -> set[tuple[str, str]]:
    """The served surface, taken from the OpenAPI schema.

    Not ``app.routes`` — that yields 36 entries against 169 documented
    paths, because included routers do not flatten into it the way the
    schema does. Using it silently under-reports the API and would make
    this test fail on endpoints that plainly exist.
    """
    from apps.api.app.main import app

    return {
        (method.upper(), _collapse(path))
        for path, ops in app.openapi().get("paths", {}).items()
        for method in ops
        if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE")
    }


def _frontend_calls() -> dict[tuple[str, str], set[str]]:
    calls: dict[tuple[str, str], set[str]] = {}
    for f in list(WEB_SRC.rglob("*.tsx")) + list(WEB_SRC.rglob("*.ts")):
        for method, _q, raw in CALL_RE.findall(f.read_text()):
            if not raw.startswith("/"):
                continue          # a variable, not a literal route
            if "<" in raw:
                # A documentation placeholder, not a call. The API-keys
                # page renders copyable curl/JS samples containing
                # `api.post("/repositories/<REPO_ID>/scan")`; that is
                # text for the reader, and no real route ever contains
                # angle brackets.
                continue
            key = (method.upper(), raw)
            calls.setdefault(key, set()).add(str(f.relative_to(WEB_SRC)))
    return calls


@pytest.mark.skipif(not WEB_SRC.exists(), reason="frontend not present")
def test_no_frontend_call_targets_a_missing_endpoint():
    real = _backend_routes()
    dead = []

    for (method, raw), files in sorted(_frontend_calls().items()):
        # A call is satisfied if any branch of its template resolves to
        # a real route.
        if any((method, _normalise_call(c)) in real for c in _expand(raw)):
            continue
        dead.append(f"  {method:6s} {raw:48s} called from {sorted(files)}")

    assert not dead, (
        "The frontend calls endpoints the API does not serve. These "
        "compile and build fine and fail only in the browser:\n"
        + "\n".join(dead)
    )


@pytest.mark.skipif(not WEB_SRC.exists(), reason="frontend not present")
def test_the_check_would_actually_catch_a_dead_call():
    """Guard the guard.

    A regex that silently stops matching would make the test above pass
    forever while checking nothing — the exact failure mode it exists to
    prevent. Assert it still finds real calls, and still rejects a
    fabricated one.
    """
    calls = _frontend_calls()
    assert len(calls) > 100, f"only matched {len(calls)} api calls — regex likely broken"

    real = _backend_routes()
    assert ("GET", "/api/v1/repositories") in real
    assert ("GET", _normalise_call("/definitely/not/an/endpoint")) not in real
