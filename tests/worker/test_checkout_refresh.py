# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Scan checkouts must track the remote.

Regression cover for a bug where a repository was cloned once and never
refreshed again: every later standalone scan re-read the working tree as
the first clone left it, so commits pushed afterwards were invisible and
the scan reported on stale code without saying so.
"""
import subprocess

import pytest

from apps.worker.tasks import _refresh_checkout

# Assembled at runtime so no credential-shaped literal sits in the
# source — see test_commit_message_scanning for the reasoning. The shape
# still has to be one the detectors recognise.
TOKEN_A = "gh" + "p_" + "7Kq2Vb9Xn4Rt6Wm1Zc8Ld3Py5Hs0Jf2Gd4Ba"


def _git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True)


@pytest.fixture()
def remote_and_checkout(tmp_path):
    """A bare 'remote' plus a clone of it, as a scan would hold."""
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q", ".")
    _git(origin, "config", "user.email", "t@example.com")
    _git(origin, "config", "user.name", "Test")
    (origin / "app.py").write_text("x = 1\n")
    _git(origin, "add", "-A")
    _git(origin, "commit", "-q", "-m", "initial")
    branch = subprocess.run(
        ["git", "-C", str(origin), "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()

    checkout = tmp_path / "checkout"
    subprocess.run(["git", "clone", "-q", str(origin), str(checkout)],
                   check=True, capture_output=True)
    return origin, checkout, branch


@pytest.mark.asyncio
async def test_refresh_picks_up_a_new_commit(remote_and_checkout):
    """The bug in one test: a file added after the clone must be scannable."""
    origin, checkout, branch = remote_and_checkout
    (origin / "leaked.py").write_text(f'TOKEN = "{TOKEN_A}"\n')
    _git(origin, "add", "-A")
    _git(origin, "commit", "-q", "-m", "add secret")

    assert not (checkout / "leaked.py").exists()
    refreshed, failed = await _refresh_checkout(str(checkout), branch)

    assert (refreshed, failed) == (True, False)
    assert (checkout / "leaked.py").exists()


@pytest.mark.asyncio
async def test_refresh_removes_a_file_deleted_upstream(remote_and_checkout):
    """Deletion has to land too — it is what closes a finding."""
    origin, checkout, branch = remote_and_checkout
    _git(origin, "rm", "-q", "app.py")
    _git(origin, "commit", "-q", "-m", "remove app.py")

    await _refresh_checkout(str(checkout), branch)
    assert not (checkout / "app.py").exists()


@pytest.mark.asyncio
async def test_refresh_follows_a_rewritten_branch(remote_and_checkout):
    """Why reset --hard and not pull --ff-only.

    A force push leaves the checkout on a commit that is no longer in the
    remote's history. `pull --ff-only` refuses that outright, which would
    strand the checkout exactly when it is most out of date.
    """
    origin, checkout, branch = remote_and_checkout
    _git(origin, "checkout", "-q", "--orphan", "rewritten")
    (origin / "app.py").write_text("rewritten = True\n")
    _git(origin, "add", "-A")
    _git(origin, "commit", "-q", "-m", "rewritten history")
    _git(origin, "branch", "-M", "rewritten", branch)

    refreshed, failed = await _refresh_checkout(str(checkout), branch)

    assert (refreshed, failed) == (True, False)
    assert (checkout / "app.py").read_text() == "rewritten = True\n"


@pytest.mark.asyncio
async def test_unreachable_remote_reports_failure_without_raising(remote_and_checkout):
    """A scan still runs on the code it holds — but the caller is told."""
    origin, checkout, branch = remote_and_checkout
    _git(checkout, "remote", "set-url", "origin", str(origin) + "-gone")

    refreshed, failed = await _refresh_checkout(str(checkout), branch)

    assert (refreshed, failed) == (False, True)
    assert (checkout / "app.py").exists()  # existing content untouched


@pytest.mark.asyncio
async def test_missing_path_is_reported_not_raised(tmp_path):
    refreshed, failed = await _refresh_checkout(str(tmp_path / "nope"), "main")
    assert (refreshed, failed) == (False, True)


@pytest.mark.asyncio
async def test_unknown_branch_leaves_the_checkout_untouched(remote_and_checkout):
    """Refreshing a branch that does not exist must not silently succeed.

    The caller relies on the failure signal to fall back to the
    repository's default branch. If this reported success, a typo'd
    branch name would scan whatever the checkout was last left on.
    """
    origin, checkout, branch = remote_and_checkout
    before = (checkout / "app.py").read_text()

    refreshed, failed = await _refresh_checkout(str(checkout), "no-such-branch")

    assert (refreshed, failed) == (False, True)
    assert (checkout / "app.py").read_text() == before


@pytest.mark.asyncio
async def test_refresh_switches_between_branches(remote_and_checkout):
    """A scan of another branch must read THAT branch's files."""
    origin, checkout, branch = remote_and_checkout
    _git(origin, "checkout", "-q", "-b", "feature")
    (origin / "only_on_feature.py").write_text("x = 1\n")
    _git(origin, "add", "-A")
    _git(origin, "commit", "-q", "-m", "feature-only file")
    _git(origin, "checkout", "-q", branch)

    refreshed, failed = await _refresh_checkout(str(checkout), "feature")
    assert (refreshed, failed) == (True, False)
    assert (checkout / "only_on_feature.py").exists()

    # …and switching back removes it again.
    await _refresh_checkout(str(checkout), branch)
    assert not (checkout / "only_on_feature.py").exists()
