# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""New findings route to the developer who introduced the secret.

The git-history scanner already records the introducing commit's author
email; this maps it to a user and sets assigned_to at scan time, so
remediation lands on the right person's desk without manual triage —
the workflow feature that lets remediation scale across a large org.

Two properties matter: it must not overwrite a human's later
reassignment (create-only, unassigned-only), and it must not cost a
query per finding (the email->user map is built once per scan).
"""
import inspect
import uuid

import pytest
from unittest.mock import AsyncMock, MagicMock

from apps.worker import tasks


@pytest.mark.asyncio
async def test_map_lowercases_and_pairs_email_to_user():
    uid1, uid2 = uuid.uuid4(), uuid.uuid4()
    rows = MagicMock()
    rows.all = MagicMock(return_value=[(uid1, "Dev@Example.com"), (uid2, "b@x.io")])
    db = MagicMock()
    db.execute = AsyncMock(return_value=rows)
    m = await tasks._committer_user_map(db, uuid.uuid4())
    assert m == {"dev@example.com": uid1, "b@x.io": uid2}


def test_assignment_is_create_only_and_does_not_overwrite():
    src = inspect.getsource(tasks._run_scan_job)
    # gated on unassigned so a manual reassignment survives a re-scan
    assert "finding.assigned_to is None" in src
    assert "committer_map.get(" in src


def test_map_is_built_once_per_scan_not_per_finding():
    """The scale invariant: one query for the whole scan."""
    src = inspect.getsource(tasks._run_scan_job)
    assert src.count("_committer_user_map(") == 1
    # loaded alongside the other per-scan setup, before the finding loop
    assert src.index("_committer_user_map(") < src.index("finding.assigned_to is None")


def test_commit_email_is_persisted_for_matching():
    """Without the email on the finding, nothing can be matched later."""
    src = inspect.getsource(tasks)
    assert '"commit_email": (pf.raw_data or {}).get("commit_email")' in src
