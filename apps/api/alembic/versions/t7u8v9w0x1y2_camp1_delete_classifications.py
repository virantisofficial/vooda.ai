# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""add RESOLVED_REPO_REMOVED + RESOLVED_SOURCE_REMOVED classification values

Revision ID: t7u8v9w0x1y2
Revises: s6t7u8v9w0x1
Create Date: 2026-05-12 09:00:00.000000

Why
---
When a user permanently deletes a repository or scan source, the
findings linked to it are removed.  Any SecretIncident those findings
belonged to needs a closure reason — and the reason matters for
downstream reporting:

* ``RESOLVED_FILE_DELETED``: the source-of-truth file was removed in
  a commit (genuine engineering hygiene — counts toward MTTR).
* ``RESOLVED_ITEM_DELETED``: a Slack message / Jira comment / Notion
  page that previously held a secret was deleted at the source.
* ``RESOLVED_REPO_REMOVED`` (this migration): the user removed the
  parent repo from Vooda.  Administrative action, NOT a cleanup
  outcome.  Excluded from MTTR / remediation-rate calculations because
  the credential may still be live at the provider.
* ``RESOLVED_SOURCE_REMOVED`` (this migration): the user removed the
  parent scan source (Slack / Confluence / Jira / S3 / …).  Same
  semantic distinction as RESOLVED_REPO_REMOVED.

The distinction matters operationally:
  - Dashboards must not conflate "user nuked the integration" with
    "team rotated the credential".  Without these values an orphaned
    incident has no choice but to land in some existing bucket
    (typically NEEDS_REVIEW or ACCEPTED_RISK), polluting metrics.
  - Compliance / SOC2 reporting needs to tell apart "we cleaned up the
    leak" from "we lost visibility because someone deleted the data
    source".  The latter is a finding that the credential *may still
    be live* but Vooda can no longer track it.

Same pattern as ``o2p3q4r5s6t7_add_resolved_file_deleted_classification``
— ``ALTER TYPE ADD VALUE`` in an autocommit block, idempotent via
``IF NOT EXISTS``.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "t7u8v9w0x1y2"
down_revision: Union[str, None] = "s6t7u8v9w0x1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        # Uppercase — the form SQLAlchemy native_enum persists.
        op.execute(
            "ALTER TYPE classification ADD VALUE IF NOT EXISTS 'RESOLVED_REPO_REMOVED'"
        )
        op.execute(
            "ALTER TYPE classification ADD VALUE IF NOT EXISTS 'RESOLVED_SOURCE_REMOVED'"
        )
        # Lowercase — defensive for any raw-SQL paths and for the
        # SecretIncident.classification VARCHAR column which stores the
        # enum .value form (lowercase).
        op.execute(
            "ALTER TYPE classification ADD VALUE IF NOT EXISTS 'resolved_repo_removed'"
        )
        op.execute(
            "ALTER TYPE classification ADD VALUE IF NOT EXISTS 'resolved_source_removed'"
        )


def downgrade() -> None:
    """No-op (Postgres can't DROP VALUE without recreating the type).

    Same rationale as ``o2p3q4r5s6t7`` / ``k8l9m0n1o2p3``: enum values
    are additive in Postgres.  Removing one requires a destructive
    table rewrite to find any rows holding the value and rewrite them
    to a different enum.  Leave the values in place; future code paths
    that don't reference them are unaffected.
    """
    pass
