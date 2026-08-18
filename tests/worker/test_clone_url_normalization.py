"""Canonicalising a git remote to a form this platform can actually clone.

Two failure modes this closes, both of which produced a scan that
failed for a reason only visible on the scan-job detail page:

  * A schemeless URL ("github.com/owner/repo") is read by git as an
    scp-style host:path and fails with "repository does not exist".

  * An SSH remote ("git@github.com:owner/repo.git") cannot authenticate
    here — the platform has no SSH-key path, only HTTPS token / basic
    auth — so it always fails on auth. Rewriting to https makes the
    existing auth model work.
"""

import pytest

from packages.common.git_url import normalize_git_url


@pytest.mark.parametrize(
    "raw,expected",
    [
        # Schemeless -> https (the original bug).
        ("github.com/OWASP/wrongsecrets", "https://github.com/OWASP/wrongsecrets"),
        ("gitlab.com/group/proj", "https://gitlab.com/group/proj"),
        ("  github.com/x/y  ", "https://github.com/x/y"),  # trimmed too

        # Already a web URL -> untouched.
        ("https://github.com/OWASP/wrongsecrets", "https://github.com/OWASP/wrongsecrets"),
        ("http://internal.git.example/repo", "http://internal.git.example/repo"),
        ("https://github.com/o/r.git", "https://github.com/o/r.git"),  # .git kept

        # scp-style SSH -> https, because SSH cannot authenticate here.
        ("git@github.com:OWASP/wrongsecrets.git", "https://github.com/OWASP/wrongsecrets"),
        ("git@github.com:owner/repo", "https://github.com/owner/repo"),
        ("git@gitlab.example.com:team/svc.git", "https://gitlab.example.com/team/svc"),

        # Full ssh:// URL -> https too.
        ("ssh://git@github.com/owner/repo.git", "https://github.com/owner/repo"),
        ("ssh://git@bitbucket.org/team/repo", "https://bitbucket.org/team/repo"),
    ],
)
def test_normalizes_to_a_cloneable_https_url(raw, expected):
    assert normalize_git_url(raw) == expected


def test_empty_is_left_empty():
    # An empty URL is an upload-only repo with no remote; normalising it
    # must not invent "https://".
    assert normalize_git_url("") == ""
    assert normalize_git_url(None) == ""


def test_no_ssh_form_survives_normalization():
    """Guard the class: nothing that reaches the cloner should be SSH,
    because there is no SSH auth path to make it work."""
    for raw in [
        "git@github.com:o/r.git",
        "ssh://git@github.com/o/r",
        "github.com/o/r",
        "https://github.com/o/r",
    ]:
        out = normalize_git_url(raw)
        assert not out.startswith(("git@", "ssh://")), out


@pytest.mark.parametrize(
    "event_url",
    [
        "https://github.com/OWASP/wrongsecrets.git",   # provider sends .git
        "https://github.com/OWASP/wrongsecrets",       # already canonical
        "https://github.com/OWASP/wrongsecrets/",      # trailing slash
        "github.com/OWASP/wrongsecrets.git",           # schemeless + .git
    ],
)
def test_webhook_url_candidates_cover_the_canonical_stored_form(event_url):
    """Whatever shape the provider sends, the canonical stored URL
    (https://…/wrongsecrets, no .git) must be among the candidates."""
    from packages.common.git_url import url_match_candidates

    assert "https://github.com/OWASP/wrongsecrets" in url_match_candidates(event_url)


def test_webhook_url_candidates_do_not_span_repos():
    """Candidates for one repo must never include another repo's URL."""
    from packages.common.git_url import url_match_candidates

    cands = url_match_candidates("https://github.com/OWASP/wrongsecrets.git")
    assert not any("other" in c or "leaky" in c for c in cands)


def test_webhook_url_candidates_empty_for_empty_input():
    from packages.common.git_url import url_match_candidates

    assert url_match_candidates("") == []
    assert url_match_candidates(None) == []
