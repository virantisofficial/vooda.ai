# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Canonicalise a git remote URL to a form this platform can clone.

One function, used in two places so they cannot disagree: the create
endpoint (so the stored URL is already canonical) and the clone step in
the worker (so rows stored before this existed, or written by any other
path, are still fixed before git sees them).

Two problems it solves:

1. A URL with no scheme — "github.com/owner/repo" — is read by git as an
   scp-style host:path. It tries to reach a host literally named
   "github.com/owner" and fails with "repository does not exist". Every
   scan of such a repo failed. These get https://.

2. An SSH remote — "git@github.com:owner/repo.git" or
   "ssh://git@host/owner/repo" — cannot clone here at all: this platform
   authenticates over HTTPS with a token or username/password and has no
   SSH-key path whatsoever. Left as SSH, the clone always fails on auth.
   Rewriting to https means the existing token auth (private repos) or
   anonymous access (public repos) actually works — so a user who pastes
   the SSH URL out of habit gets a working scan instead of a dead one.

Anything already carrying an http(s) scheme is returned unchanged.
"""

from __future__ import annotations

import re

# git@host:owner/repo(.git)  — the scp-style shorthand git accepts.
_SCP_SSH = re.compile(r"^(?:ssh://)?git@([^:/]+)[:/](.+?)(?:\.git)?/?$")

# ssh://host/owner/repo(.git) — the full SSH URL form.
_SSH_URL = re.compile(r"^ssh://(?:[^@/]+@)?([^/]+)/(.+?)(?:\.git)?/?$")


def normalize_git_url(url: str | None) -> str:
    """Return a clone URL this platform can actually use.

    Empty stays empty — that is an upload-only repo with no remote, and
    inventing a URL for it would be wrong.
    """
    url = (url or "").strip()
    if not url:
        return ""

    # Already a web URL — leave it exactly as given. GitHub upgrades
    # http->https itself, so there is no reason to touch either.
    if url.startswith(("https://", "http://")):
        return url

    # SSH, in either shorthand or full form -> HTTPS, because SSH cannot
    # authenticate here. `git@host:owner/repo` and `ssh://git@host/owner/
    # repo` both become `https://host/owner/repo`.
    m = _SCP_SSH.match(url) or _SSH_URL.match(url)
    if m:
        host, path = m.group(1), m.group(2).lstrip("/")
        return f"https://{host}/{path}"

    # Anything else is a bare host/owner/repo with no scheme -> https.
    return "https://" + url


def url_match_candidates(repo_url: str | None) -> list[str]:
    """The stored-URL forms a webhook event's clone URL could match.

    A provider sends "https://github.com/owner/repo.git"; the stored URL
    is canonicalised to "https://github.com/owner/repo" (no .git, no
    trailing slash). An exact `==` misses on nearly every real event, so
    a webhook then fell through to a risky fuzzy name match. Comparing
    against this small set of obvious variants matches reliably instead.
    """
    norm = normalize_git_url(repo_url).rstrip("/")
    if not norm:
        return []
    base = norm[:-4] if norm.endswith(".git") else norm
    return list({
        norm,
        base,
        base + ".git",
        base + "/",
        base.replace("https://", "http://"),
    })
