# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Network-layer error classifier — shared across all providers.

Covers everything that happens *before* an HTTP response — DNS
resolution, TCP connect, TLS handshake, proxy negotiation, plus
the various flavours of timeout (connect / read / write / pool).
Centralising these here means each provider's classifier only needs
to handle the HTTP-level errors (400+); transport-level errors all
look identical regardless of who's on the other end.

httpx exception hierarchy (relevant subset)::

    httpx.HTTPError
    ├── httpx.RequestError                     (base for transport)
    │   ├── httpx.TransportError
    │   │   ├── httpx.TimeoutException
    │   │   │   ├── httpx.ConnectTimeout       (TCP-level)
    │   │   │   ├── httpx.ReadTimeout          (response taking too long)
    │   │   │   ├── httpx.WriteTimeout         (request body upload stalled)
    │   │   │   └── httpx.PoolTimeout          (waiting for connection pool slot)
    │   │   ├── httpx.NetworkError
    │   │   │   ├── httpx.ConnectError         (DNS / refused / unreachable)
    │   │   │   ├── httpx.ReadError
    │   │   │   ├── httpx.WriteError
    │   │   │   └── httpx.CloseError
    │   │   ├── httpx.ProtocolError
    │   │   │   └── httpx.RemoteProtocolError  (server hung up)
    │   │   └── httpx.ProxyError               (proxy CONNECT failed)
    │   ├── httpx.DecodingError                (encoding / charset)
    │   └── httpx.UnsupportedProtocol          (e.g. ftp:// passed to httpx)
    └── httpx.HTTPStatusError                  (4xx/5xx — not our problem here)

Also recognises ssl.SSLError / ssl.SSLCertVerificationError that
sometimes leak through httpx without being wrapped (older versions).
"""

from __future__ import annotations

import ssl
from typing import Any

import httpx

from ..model import ErrorCategory, ErrorSeverity, IntegrationError
from ..redact import redact_secrets


def _is_tls_error(exc: Exception) -> bool:
    """Detect TLS handshake / certificate validation failures.

    httpx wraps SSL errors inside ``httpx.ConnectError`` whose
    ``__cause__`` is the original ``ssl.SSLError`` (or subclass).
    Older httpx versions sometimes raise ``ssl.SSLError`` directly.
    """
    if isinstance(exc, ssl.SSLError):
        return True
    cause = getattr(exc, "__cause__", None)
    if isinstance(cause, ssl.SSLError):
        return True
    msg = str(exc).lower()
    return any(t in msg for t in (
        "certificate verify failed", "ssl handshake", "tlsv1", "tls handshake",
        "certificate has expired", "self-signed certificate", "hostname mismatch",
    ))


def classify_network_error(
    exc: Exception, context: dict[str, Any] | None = None
) -> IntegrationError:
    """Map a transport-level exception to an :class:`IntegrationError`.

    Recognises the full httpx exception hierarchy plus standalone
    ``ssl.SSLError`` cases that occasionally bypass the wrapper.
    Order of checks matters: TLS first (most specific cause), proxy
    second (still pre-handshake), then the generic ConnectError /
    timeout buckets, then the catch-all.
    """
    ctx = dict(context or {})
    msg = str(exc)

    # ── TLS handshake / certificate validation ───────────────────
    # Single most common "looks like a connection error but isn't" —
    # corporate MITM proxies with their own CA, expired server
    # certs, hostname mismatches.  Conflated with ConnectError
    # otherwise, which gives misleading "is the server up?" advice.
    if _is_tls_error(exc):
        return IntegrationError(
            code="network.tls_error",
            category=ErrorCategory.NETWORK,
            severity=ErrorSeverity.ERROR,
            title="TLS / certificate error",
            summary=(
                "Vooda couldn't establish a secure connection to the provider. "
                "The most common causes are an expired certificate, a hostname "
                "mismatch, or a corporate MITM proxy with a private CA."
            ),
            fix_steps=[
                "Verify the URL hostname matches the certificate (no http→https swap, no trailing path)",
                "If you're behind a corporate proxy with its own CA, set REQUESTS_CA_BUNDLE / SSL_CERT_FILE on the Vooda host",
                "Check the certificate expiry at the provider's status page or via openssl s_client",
            ],
            doc_anchor="/docs?section=troubleshooting",
            raw=redact_secrets({"exception": msg[:500]}),
            context=ctx,
        )

    # ── Proxy CONNECT failure ────────────────────────────────────
    # Customer behind a proxy whose config is wrong (bad URL, bad
    # auth, blocked target).  Distinct from a TLS error because the
    # proxy itself rejected before the TLS layer started.
    if isinstance(exc, httpx.ProxyError):
        return IntegrationError(
            code="network.proxy_error",
            category=ErrorCategory.NETWORK,
            severity=ErrorSeverity.ERROR,
            title="Proxy refused the connection",
            summary=(
                "The HTTP proxy in front of Vooda rejected the CONNECT to the "
                "provider. The proxy may be misconfigured, require auth, or have "
                "blocked the target host."
            ),
            fix_steps=[
                "Check HTTPS_PROXY / NO_PROXY env vars on the Vooda host",
                "If the proxy needs auth, embed it as http://user:pass@proxy.host:port",
                "If the target host is blocked, ask your network admin to allow-list it",
            ],
            doc_anchor="/docs?section=troubleshooting",
            raw=redact_secrets({"exception": msg[:500]}),
            context=ctx,
        )

    # ── ConnectError (DNS / refused / unreachable) ───────────────
    if isinstance(exc, httpx.ConnectError):
        if "Name or service not known" in msg or "nodename" in msg.lower() or "no address associated" in msg.lower():
            return IntegrationError(
                code="network.dns_failure",
                category=ErrorCategory.NETWORK,
                severity=ErrorSeverity.ERROR,
                title="Could not resolve hostname",
                summary="Vooda couldn't find the server for the URL you provided.",
                fix_steps=[
                    "Double-check the URL — common typo: missing protocol or trailing path",
                    "Verify the host exists and is reachable from the Vooda host",
                ],
                doc_anchor="/docs?section=troubleshooting",
                raw=redact_secrets({"exception": msg[:500]}),
                context=ctx,
            )
        return IntegrationError(
            code="network.connection_refused",
            category=ErrorCategory.NETWORK,
            severity=ErrorSeverity.ERROR,
            title="Connection refused",
            summary="The server is reachable but rejected the TCP connection.",
            fix_steps=[
                "Confirm the URL includes the right protocol (https:// vs http://)",
                "Check whether the service is up at the provider's status page",
            ],
            raw=redact_secrets({"exception": msg[:500]}),
            context=ctx,
        )

    # ── Timeouts (sub-typed) ─────────────────────────────────────
    # Distinct sub-codes per timeout flavour because the actionable
    # fix differs:
    #   connect_timeout → bump CONNECT_TIMEOUT_S, check firewall / DNS
    #   read_timeout    → bump READ_TIMEOUT_S, look for slow upstream
    #   write_timeout   → bump WRITE_TIMEOUT_S, look for huge bodies
    #   pool_timeout    → adapter pool exhausted; tune CELERY_CONCURRENCY
    if isinstance(exc, httpx.ConnectTimeout):
        return IntegrationError(
            code="network.connect_timeout",
            category=ErrorCategory.NETWORK,
            severity=ErrorSeverity.ERROR,
            title="Connect timed out",
            summary="Vooda couldn't establish a TCP connection to the provider in time.",
            fix_steps=[
                "Retry once — single timeouts are usually transient",
                "If persistent, check the provider's status page or your egress firewall",
            ],
            raw=redact_secrets({"exception": msg[:500]}),
            context=ctx,
        )
    if isinstance(exc, httpx.ReadTimeout):
        return IntegrationError(
            code="network.read_timeout",
            category=ErrorCategory.NETWORK,
            severity=ErrorSeverity.ERROR,
            title="Read timed out",
            summary="The provider accepted the request but took too long to respond.",
            fix_steps=[
                "Retry once",
                "If persistent on a specific source, lower the page-size or item-count filter",
            ],
            raw=redact_secrets({"exception": msg[:500]}),
            context=ctx,
        )
    if isinstance(exc, httpx.WriteTimeout):
        return IntegrationError(
            code="network.write_timeout",
            category=ErrorCategory.NETWORK,
            severity=ErrorSeverity.ERROR,
            title="Write timed out",
            summary="Vooda couldn't finish uploading the request body in time.",
            fix_steps=[
                "Retry once",
                "If you're uploading a large attachment / SBOM, the request body may be too big",
            ],
            raw=redact_secrets({"exception": msg[:500]}),
            context=ctx,
        )
    if isinstance(exc, httpx.PoolTimeout):
        return IntegrationError(
            code="network.pool_timeout",
            category=ErrorCategory.NETWORK,
            severity=ErrorSeverity.ERROR,
            title="Connection pool exhausted",
            summary=(
                "Vooda's HTTP connection pool to this provider is full. Usually "
                "means too many in-flight scans for the configured concurrency."
            ),
            fix_steps=[
                "Lower CELERY_CONCURRENCY temporarily, or",
                "Increase the per-host connection pool size in the adapter config",
                "If this happens often, file a bug — the adapter may be leaking connections",
            ],
            doc_anchor="/docs?section=admin",
            raw=redact_secrets({"exception": msg[:500]}),
            context=ctx,
        )
    if isinstance(exc, httpx.TimeoutException):
        # Catch-all for any TimeoutException subclass we didn't
        # enumerate above — keeps forward-compat with future httpx
        # versions that might add new timeout flavours.
        return IntegrationError(
            code="network.timeout",
            category=ErrorCategory.NETWORK,
            severity=ErrorSeverity.ERROR,
            title="Connection timed out",
            summary="The provider didn't respond within the timeout window.",
            fix_steps=[
                "Retry — single timeouts are usually transient",
                "If it keeps failing, check the provider's status page",
            ],
            raw=redact_secrets({"exception": msg[:500]}),
            context=ctx,
        )

    # ── Server hung up mid-response ──────────────────────────────
    if isinstance(exc, httpx.RemoteProtocolError):
        return IntegrationError(
            code="network.protocol_error",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.ERROR,
            title="Provider hung up unexpectedly",
            summary="The remote server closed the connection mid-response.",
            fix_steps=[
                "Retry — usually transient on the provider side",
                "If persistent, check the provider's status page",
            ],
            raw=redact_secrets({"exception": msg[:500]}),
            context=ctx,
        )

    # ── Generic fallback ─────────────────────────────────────────
    return IntegrationError(
        code="network.unknown",
        category=ErrorCategory.NETWORK,
        severity=ErrorSeverity.ERROR,
        title="Network error",
        summary="The request to the provider failed before a response was received.",
        fix_steps=["Retry once", "If persistent, check the provider's status page"],
        raw=redact_secrets({"exception": f"{type(exc).__name__}: {exc}"[:500]}),
        context=ctx,
    )
