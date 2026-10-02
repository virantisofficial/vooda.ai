# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Recover a finding's secret value so it can be verified again.

Vooda never stores the secret. The scan pipeline strips
``_raw_value_for_verification`` before the row is written (see
apps/worker/tasks.py), which is the right call — a secret scanner that
keeps a copy of every credential it finds is a breach waiting to
happen.

The cost of that was Re-verify. The button called a verifier that needs
the raw value, got nothing, and returned "Raw secret value not
available for verification" for every finding whose provider it
otherwise supported. Verification only ever really happened during the
scan, while the value was still in memory.

This gets it back without storing anything: the repository clone is
still on disk, so re-read the file and re-run detection over it. The
value lives in memory for the length of one verification and is never
written, returned to a client, or logged.

Identity is by ``secret_hash``, not by line number. Lines move; a
sha256 match is proof it is the same secret, and a miss means the
secret is no longer in the working tree — which is a real answer
("rotated out", "deleted") rather than a reason to verify whatever
happens to sit on that line now.
"""
from __future__ import annotations

import os
from typing import Optional

import structlog

logger = structlog.get_logger("vooda.verification.recovery")


#: A single source file. Anything larger is not a credential file, and
#: reading it would cost more than the answer is worth.
_MAX_BYTES = 8 * 1024 * 1024


class RecoveryUnavailable(Exception):
    """The value cannot be recovered, with a reason fit to show a user.

    Raised rather than returned so a caller cannot mistake "could not
    find it" for "found nothing suspicious".
    """


def repo_clone_root(repository_id) -> str:
    """Where a repository's working tree lives on this host.

    Shared, because both halves of re-verification need it: recovering
    the secret, and finding the partner value of a paired credential in
    the same file.
    """
    from apps.api.app.core.config import settings
    return os.path.join(settings.STORAGE_PATH, "repos", str(repository_id))


def recover_secret_value(
    *,
    repository_id,
    file_path: str,
    secret_hash: str,
    detection_method: str = "",
) -> str:
    """Return the finding's secret value, re-read from the clone.

    Raises RecoveryUnavailable with a user-facing reason when the clone
    is gone, the file is gone, or nothing in it hashes to this finding's
    secret any more.
    """
    if not repository_id:
        # Source scans (Slack, Jira, S3 and friends) have no local copy
        # to re-read. Re-fetching from the provider is a different piece
        # of work and would need the integration's credentials.
        raise RecoveryUnavailable(
            "Re-verification needs the original file, which Vooda keeps "
            "only for repository scans."
        )
    if not secret_hash:
        # Without it there is no way to tell which of several secrets in
        # the file is this finding's. Verifying the wrong one would
        # report a status for a credential nobody asked about.
        raise RecoveryUnavailable(
            "This finding predates secret hashing, so the value cannot be "
            "matched back to it."
        )

    root = repo_clone_root(repository_id)
    if not os.path.isdir(root):
        raise RecoveryUnavailable(
            "The repository clone is no longer on disk. Re-scan the "
            "repository and try again."
        )

    # `file_path` comes from the database, but it reaches the database
    # from a scanner walking a tree, so treat it as untrusted: resolve
    # it and refuse anything that lands outside the clone.
    target = os.path.realpath(os.path.join(root, file_path))
    if not (target == os.path.realpath(root)
            or target.startswith(os.path.realpath(root) + os.sep)):
        logger.warning("recovery_path_escape", file_path=file_path)
        raise RecoveryUnavailable("The stored file path is not inside the repository.")

    if not os.path.isfile(target):
        raise RecoveryUnavailable(
            "The file no longer exists in the working tree — the secret "
            "may already have been removed."
        )
    if os.path.getsize(target) > _MAX_BYTES:
        raise RecoveryUnavailable("The file is too large to re-read.")

    try:
        with open(target, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError as exc:
        logger.warning("recovery_read_failed", error=str(exc))
        raise RecoveryUnavailable("The file could not be read.") from exc

    from services.secret_scan.engine import SecretScanner

    # Entropy only when the finding came from it. The entropy pass is
    # the expensive half, and a rule-detected secret does not need it.
    scanner = SecretScanner(enable_entropy=(detection_method == "entropy"))
    for hit in scanner.scan_file(file_path, content):
        rd = hit.raw_data or {}
        if rd.get("secret_hash") != secret_hash:
            continue
        value = rd.get("_raw_value_for_verification") or ""
        if value:
            return value

    raise RecoveryUnavailable(
        "This secret is no longer in the file. It may have been removed "
        "or replaced since the last scan."
    )
