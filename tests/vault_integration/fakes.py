"""Local stand-ins for Azure Key Vault and GCP Secret Manager.

HashiCorp Vault, CyberArk Conjur and AWS Secrets Manager can all be run
for real on a laptop — official server images for the first two, and
LocalStack speaks genuine boto3 for the third — so those providers are
verified against the real thing.

Azure and GCP have no official emulator, and creating cloud accounts to
test with is not something this suite should require. Without something
standing in, their data planes are never exercised at all: connect,
list, pagination, metadata and write-back are exactly the code paths a
credential rejection never reaches, so "auth fails as expected against
the real endpoint" proves almost nothing about them.

These fakes implement the documented request and response shapes:

  * Azure Key Vault REST 7.4 — OAuth2 client-credentials token, then
    GET /secrets (paged via `nextLink`), GET /secrets/{name},
    PUT /secrets/{name}.
  * GCP Secret Manager v1 — GET /v1/projects/{p}/secrets (paged via
    `nextPageToken`), GET .../secrets/{name},
    POST .../secrets/{name}:addVersion.

They are deliberately strict about the things that break real clients:
a missing or wrong bearer token is rejected, pagination only advances
when the client passes the continuation token back, and Azure returns
its secret ids as full URLs so the name-parsing in the provider is
genuinely tested rather than assumed.

What they cannot prove: that Microsoft's and Google's live services
behave exactly this way. Treat a pass here as "the client is correct
against the published contract", not as a substitute for one run
against a real tenant.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

TOKEN = "fake-access-token"


class _Handler(BaseHTTPRequestHandler):
    secrets: dict[str, str] = {}
    flavour = "azure"
    page_size = 2

    def log_message(self, *_args):
        pass  # keep pytest output clean

    # ── helpers ────────────────────────────────────────────────────
    def _json(self, code: int, body: dict):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _authed(self) -> bool:
        return self.headers.get("Authorization") == f"Bearer {TOKEN}"

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    # ── token endpoint (Azure only; GCP mints via google-auth) ─────
    def do_POST(self):
        url = urlparse(self.path)
        # Azure posts client credentials to /{tenant}/oauth2/v2.0/token;
        # google-auth posts a signed JWT assertion to whatever token_uri
        # the service-account JSON names. Both end in /token.
        if url.path.endswith("/token"):
            return self._json(200, {"access_token": TOKEN, "expires_in": 3600})

        if not self._authed():
            return self._json(401, {"error": "unauthorized"})

        if self.flavour == "gcp" and url.path.endswith(":addVersion"):
            name = url.path.split("/secrets/")[1].split(":")[0]
            payload = self._body().get("payload", {})
            # Real Secret Manager takes base64 in payload.data.
            import base64
            self.secrets[name] = base64.b64decode(payload.get("data", "")).decode()
            return self._json(200, {"name": f"projects/p/secrets/{name}/versions/1"})

        return self._json(404, {"error": "not found"})

    # ── read paths ────────────────────────────────────────────────
    def do_GET(self):
        if not self._authed():
            return self._json(401, {"error": "unauthorized"})

        url = urlparse(self.path)
        q = parse_qs(url.query)
        names = sorted(self.secrets)

        if self.flavour == "azure":
            if url.path == "/secrets":
                start = int(q.get("skip", ["0"])[0])
                page = names[start : start + self.page_size]
                nxt = start + self.page_size
                body = {
                    "value": [
                        {
                            "id": f"https://fake.vault.azure.net/secrets/{n}",
                            "attributes": {"enabled": True, "created": 1, "updated": 2},
                        }
                        for n in page
                    ]
                }
                if nxt < len(names):
                    body["nextLink"] = f"http://{self.headers['Host']}/secrets?api-version=7.4&skip={nxt}"
                return self._json(200, body)
            if url.path.startswith("/secrets/"):
                name = url.path.split("/secrets/")[1]
                if name not in self.secrets:
                    return self._json(404, {"error": "not found"})
                return self._json(200, {
                    "id": f"https://fake.vault.azure.net/secrets/{name}",
                    "value": self.secrets[name],
                    "attributes": {"enabled": True, "created": 1, "updated": 2},
                })

        else:  # gcp
            if url.path.endswith("/secrets"):
                token = int(q.get("pageToken", ["0"])[0])
                page = names[token : token + self.page_size]
                nxt = token + self.page_size
                body = {"secrets": [{"name": f"projects/p/secrets/{n}"} for n in page]}
                if nxt < len(names):
                    body["nextPageToken"] = str(nxt)
                return self._json(200, body)
            if "/secrets/" in url.path:
                name = url.path.split("/secrets/")[1]
                if name not in self.secrets:
                    return self._json(404, {"error": "not found"})
                return self._json(200, {"name": f"projects/p/secrets/{name}", "createTime": "2026-01-01T00:00:00Z"})

        return self._json(404, {"error": "not found"})

    # ── Azure writes with PUT ─────────────────────────────────────
    def do_PUT(self):
        if not self._authed():
            return self._json(401, {"error": "unauthorized"})
        url = urlparse(self.path)
        if self.flavour == "azure" and url.path.startswith("/secrets/"):
            name = url.path.split("/secrets/")[1]
            self.secrets[name] = self._body().get("value", "")
            return self._json(200, {
                "id": f"https://fake.vault.azure.net/secrets/{name}",
                "value": self.secrets[name],
                "attributes": {"enabled": True},
            })
        return self._json(404, {"error": "not found"})


class FakeVaultServer:
    """Run one fake in a background thread; use as a context manager."""

    def __init__(self, flavour: str, secrets: dict[str, str]):
        handler = type(
            f"_{flavour}Handler",
            (_Handler,),
            {"flavour": flavour, "secrets": dict(secrets)},
        )
        self.handler = handler
        self.httpd = HTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"

    def __enter__(self):
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    @property
    def stored(self) -> dict[str, str]:
        return self.handler.secrets
