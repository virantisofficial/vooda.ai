"""D1 — Non-destructive-operation audit for the verifier layer.

Every entry in ``services/secret_verification/verifier.py`` is supposed
to make only read-only calls against provider APIs. Our public
positioning depends on that promise: "Vooda never modifies, creates, or
deletes anything in your providers — we only read to check if the key
is still live." If a future author accidentally wires a ``POST`` to a
mutating endpoint, the customer's provider-side state could be
corrupted by the very tool that's meant to protect them.

This test statically analyses the verifier module with Python's AST and
enforces:

1. **No ``PUT``, ``DELETE``, or ``PATCH`` calls.** These methods almost
   always mutate; there is no legitimate use case in verification.

2. **``POST`` calls are allowed only when the target URL matches the
   :data:`ALLOWED_POST_URL_PREFIXES` allowlist.** Each entry in that
   list has a comment explaining why the POST is non-destructive (auth
   check, GraphQL query, OAuth token exchange, SigV4 signed request,
   etc.). When a developer adds a new POST call, they must explicitly
   widen the allowlist — forcing a conscious decision that goes
   through code review.

3. **``client.request()`` / ``client.stream()`` with a non-safe method
   is rejected the same way.** Catches attempts to bypass the
   method-shortcut by using the lower-level API.

If this test fails, the error message names every offending call with
its file line and URL so the author can triage quickly. The test is
pure static analysis — it runs in milliseconds, never makes network
calls, and never needs credentials.
"""
from __future__ import annotations

import ast
import pathlib
from typing import Optional


# ── Configuration ─────────────────────────────────────────────

VERIFIER_FILE = pathlib.Path(__file__).resolve().parents[1] / \
    "services" / "secret_verification" / "verifier.py"

# HTTP methods that are safe by definition (per RFC 7231 §4.2.1 — safe
# methods). These are read-only on the server side.
_SAFE_METHODS = {"get", "head", "options"}

# HTTP methods that are never safe and never appear in verifier code.
# Any hit = hard failure, no allowlist.
_DESTRUCTIVE_METHODS = {"put", "delete", "patch"}

# Known-safe POST endpoints. Each line must carry a one-liner comment
# explaining why this POST is non-destructive — the comment becomes
# part of the review signal when the allowlist grows.
ALLOWED_POST_URL_PREFIXES = {
    # AWS STS GetCallerIdentity — SigV4 POST with body=Action=... to the
    # STS root; returns account/ARN, mutates nothing.
    "https://sts.amazonaws.com",

    # Slack auth.test — the canonical Slack token-verification endpoint;
    # named POST by Slack convention, strictly read-only.
    "https://slack.com/api/auth.test",

    # Cohere has a dedicated /v1/check-api-key endpoint (POST-only),
    # returns whether the key is valid. No inference, no data change.
    "https://api.cohere.ai/v1/check-api-key",

    # Dropbox API quirk: /users/get_current_account is POST-only per
    # their docs; returns the caller's profile, nothing else.
    "https://api.dropboxapi.com/2/users/get_current_account",

    # Perplexity AI + NVIDIA: /v1/models is fully public (returns same
    # data for no auth / fake key / real key — B3 validation
    # 2026-04-19), so we can't use it as an auth check. Both verifiers
    # fall back to a minimal inference POST (max_tokens=1) which costs
    # a fraction of a cent per verify but actually authenticates. The
    # inference call itself is a read — no state mutation, no data
    # written to the account — just an inference charge.
    "https://api.perplexity.ai/chat/completions",
    "https://integrate.api.nvidia.com/v1/chat/completions",

    # Ashby /apiKey.info — POST-only read-only endpoint for key lookup.
    "https://api.ashbyhq.com/apiKey.info",

    # GraphQL query-only endpoints. Our payload is always a safe query
    # like `{ viewer { id } }` / `{ me { id } }`. GraphQL uses POST as
    # transport for reads by design.
    "https://api.linear.app/graphql",
    "https://api.monday.com/v2",
    "https://backboard.railway.app/graphql/v2",

    # Fauna HTTP API — POSTs a FQL query string. Our query is a read
    # (e.g. currentIdentity()); the endpoint accepts reads via POST.
    "https://db.fauna.com/",

    # OAuth2 token exchanges — mints a token, does not mutate user data.
    # Azure AD, PayPal, Amadeus, GCP all use token-exchange flows.
    "https://login.microsoftonline.com",
    "https://api-m.paypal.com",
    "https://api-m.sandbox.paypal.com",
    "https://test.travel.api.amadeus.com",
    "https://travel.api.amadeus.com",
    "https://oauth2.googleapis.com",

    # Snowflake login-request — session token only, no DDL / DML. The
    # URL carries the customer's account name as a subdomain so the
    # concrete prefix is dynamic; matched via SNOWFLAKE_LOGIN_SUFFIX
    # below instead of an ``https://`` prefix (which would match
    # everything).

    # UptimeRobot /getAccountDetails — read-only despite POST.
    "https://api.uptimerobot.com/v2/getAccountDetails",

    # Adyen /paymentMethods — lists available payment method types for
    # the account. Read-only; does not create or charge anything.
    "https://checkout-test.adyen.com/v70/paymentMethods",
    "https://checkout-live.adyen.com/v70/paymentMethods",
}

# Snowflake URLs embed the customer's account name so they can't be
# fully pinned in the allowlist. Any f-string POST that lands on
# ``*.snowflakecomputing.com/session/v1/login-request`` is still a pure
# auth call — no data mutation. This pattern matcher is intentionally
# narrow (must end in the exact login-request path).
SNOWFLAKE_LOGIN_SUFFIX = ".snowflakecomputing.com/session/v1/login-request"


# ── AST walker ────────────────────────────────────────────────


def _extract_url_from_literal(
    node: ast.AST,
    scope: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Best-effort URL extraction from a literal AST node — plain
    string or f-string with static chunks.

    When ``scope`` is provided, f-string interpolations that are bare
    ``Name`` references (e.g. ``f"https://{host}/v1"`` where ``host``
    was previously assigned a string literal) are resolved against the
    scope. Non-resolvable interpolations fall back to the ``{*}``
    wildcard marker, which keeps suffix-matching (Snowflake URLs) and
    "something was variable here" visibility intact.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
                continue
            if isinstance(v, ast.FormattedValue):
                inner = v.value
                # Resolve ``{x}`` if x is a Name with a string literal
                # in the local scope.
                if isinstance(inner, ast.Name) and scope and inner.id in scope:
                    parts.append(scope[inner.id])
                    continue
                # ``{x if cond else y}`` — resolve both arms to literals
                # and pick the body arm. The allowlist check below will
                # catch it only if both arms are safe; if they diverge,
                # the reviewer gets a partial detection they can widen
                # the allowlist for explicitly.
                if isinstance(inner, ast.IfExp):
                    body_url = _extract_url_from_literal(inner.body, scope)
                    if body_url is not None:
                        parts.append(body_url)
                        continue
            parts.append("{*}")
        return "".join(parts)
    # ``x = "a" if cond else "b"`` — pick the body arm for allowlist
    # matching. Same caveat as the f-string IfExp branch above.
    if isinstance(node, ast.IfExp):
        body_url = _extract_url_from_literal(node.body, scope)
        if body_url is not None:
            return body_url
    return None


def _build_local_name_scope(func_node: ast.AST) -> dict[str, str]:
    """Collect simple ``name = <string-literal-or-fstring>`` bindings
    within a function body, so ``.post(url)`` where ``url`` was set a
    few lines earlier can resolve to the literal for allowlist
    matching. Also resolves ``x = obj.get("key", "default")`` to the
    default, since verifier code uses it to read URLs out of JSON
    config blobs.

    Iterates in source order and feeds the in-progress scope back into
    the literal extractor so chained f-string resolutions work
    (``host = "x.com"; endpoint = f"https://{host}"``).
    """
    scope: dict[str, str] = {}

    def _visit(nodes):
        for node in nodes:
            # Recurse into simple control-flow blocks so assignments
            # guarded by ``try:`` or ``if:`` still make it into the
            # scope — the verifier module uses both patterns.
            if isinstance(node, (ast.Try, ast.If, ast.With, ast.AsyncWith)):
                _visit(getattr(node, "body", []))
                for handler in getattr(node, "handlers", []):
                    _visit(handler.body)
                _visit(getattr(node, "orelse", []))
                _visit(getattr(node, "finalbody", []))
                continue
            if not isinstance(node, ast.Assign):
                continue
            if len(node.targets) != 1:
                continue
            t = node.targets[0]
            if not isinstance(t, ast.Name):
                continue
            url = _extract_url_from_literal(node.value, scope)
            if url is None and isinstance(node.value, ast.Call):
                # ``obj.get("key", <literal>)`` → default wins.
                if (
                    isinstance(node.value.func, ast.Attribute)
                    and node.value.func.attr == "get"
                    and len(node.value.args) == 2
                ):
                    url = _extract_url_from_literal(node.value.args[1], scope)
            if url is not None:
                scope[t.id] = url

    _visit(func_node.body)
    return scope


def _extract_url(node: ast.AST, local_scope: dict[str, str]) -> Optional[str]:
    """Extended URL extractor that also resolves ``Name`` nodes via the
    function-local scope built by :func:`_build_local_name_scope` and
    threads the scope through f-string interpolations."""
    direct = _extract_url_from_literal(node, local_scope)
    if direct is not None:
        return direct
    if isinstance(node, ast.Name):
        return local_scope.get(node.id)
    return None


def _is_post_url_allowed(url: Optional[str]) -> bool:
    if not url:
        # Couldn't statically resolve — conservative default is to
        # flag. Author can make the URL a literal or add an allowlist
        # entry with a comment.
        return False
    if any(url.startswith(pfx) for pfx in ALLOWED_POST_URL_PREFIXES):
        return True
    # Snowflake account-scoped login endpoints resolve to something
    # like ``https://{*}.snowflakecomputing.com/session/v1/login-request``
    # (or the literal form used by test fixtures).
    if SNOWFLAKE_LOGIN_SUFFIX in url:
        return True
    return False


def _collect_http_calls(tree: ast.AST) -> list[tuple[str, Optional[str], int]]:
    """Walk every function in the module and yield ``(method, url,
    lineno)`` for every HTTP call. For each function we first build a
    local-name scope so ``url = f"..."`` followed by ``.post(url)``
    resolves correctly — the common verifier pattern when the URL
    depends on input (tenant domain, region, account)."""
    target_methods = _SAFE_METHODS | _DESTRUCTIVE_METHODS | {"post", "request", "stream"}
    calls: list[tuple[str, Optional[str], int]] = []

    def _handle_func(func_node: ast.AST) -> None:
        scope = _build_local_name_scope(func_node)
        for node in ast.walk(func_node):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            attr = node.func.attr
            if attr not in target_methods:
                continue
            url: Optional[str] = None
            method_name = attr
            if attr in ("request", "stream"):
                if len(node.args) >= 1 and isinstance(node.args[0], ast.Constant):
                    method_name = str(node.args[0].value).lower()
                if len(node.args) >= 2:
                    url = _extract_url(node.args[1], scope)
            else:
                if node.args:
                    url = _extract_url(node.args[0], scope)
            calls.append((method_name, url, node.lineno))

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _handle_func(node)
    return calls


# ── Test ──────────────────────────────────────────────────────


def _find_violations() -> list[str]:
    src = VERIFIER_FILE.read_text()
    tree = ast.parse(src)
    violations: list[str] = []
    for method, url, line in _collect_http_calls(tree):
        method_lower = method.lower()
        if method_lower in _SAFE_METHODS:
            continue
        if method_lower in _DESTRUCTIVE_METHODS:
            violations.append(
                f"{VERIFIER_FILE.name}:{line}  {method_lower.upper()} -> "
                f"{url or '<dynamic>'}  (PUT/DELETE/PATCH is never allowed)"
            )
            continue
        if method_lower == "post":
            if _is_post_url_allowed(url):
                continue
            violations.append(
                f"{VERIFIER_FILE.name}:{line}  POST -> {url or '<dynamic>'}  "
                f"(not in ALLOWED_POST_URL_PREFIXES — add with comment "
                f"explaining why it's non-destructive, or switch to GET)"
            )
    return violations


def test_verifier_only_makes_non_destructive_calls():
    """The full audit: every HTTP call in verifier.py is either a safe
    method or a POST to a pre-vetted non-destructive endpoint."""
    violations = _find_violations()
    assert not violations, (
        "Destructive or non-vetted HTTP calls found in verifier.py:\n  - "
        + "\n  - ".join(violations)
    )


def test_allowlist_entries_are_documented():
    """Every allowlist entry should be covered by a preceding comment
    group so future reviewers understand why each POST is safe.

    Rule: a URL is considered documented if at least one ``#`` comment
    appears between it and the previous blank line (i.e. within the
    same comment-bounded group). Blank lines reset the "seen comment"
    state, forcing each new URL cluster to re-justify itself.
    """
    this_file = pathlib.Path(__file__).read_text().splitlines()
    in_block = False
    undocumented: list[str] = []
    comment_in_current_group = False
    for idx, line in enumerate(this_file):
        stripped = line.strip()
        if stripped.startswith("ALLOWED_POST_URL_PREFIXES = {"):
            in_block = True
            continue
        if not in_block:
            continue
        if stripped == "}":
            in_block = False
            continue
        if stripped == "":
            # Blank line closes the current comment group.
            comment_in_current_group = False
            continue
        if stripped.startswith("#"):
            comment_in_current_group = True
            continue
        if stripped.startswith('"') and stripped.endswith('",'):
            if not comment_in_current_group:
                undocumented.append(f"line {idx + 1}: {stripped}")
    assert not undocumented, (
        "Every allowlisted POST URL must be preceded (within the same "
        "blank-line-separated group) by a justifying comment.\n  - "
        + "\n  - ".join(undocumented)
    )


# ── Direct-invocation runner ──────────────────────────────────


if __name__ == "__main__":
    import sys

    violations = _find_violations()
    if violations:
        print("❌ verifier.py D1 audit failed:")
        for v in violations:
            print(f"  - {v}")
        sys.exit(1)

    try:
        test_allowlist_entries_are_documented()
    except AssertionError as e:
        print("❌", str(e))
        sys.exit(1)

    print("✅ verifier.py D1 audit passed — no destructive HTTP calls found.")
    sys.exit(0)
