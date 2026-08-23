# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""NULL jsonb columns must deserialise to an empty dict.

``scan_jobs.config`` and ``.stats`` are NULLABLE in Postgres with no
server default, while ``ScanJobResponse`` types them as ``dict``.
FastAPI validates the ENTIRE response list, so a single row with a NULL
jsonb column would fail the whole request rather than that one row.

Note a plain default (``config: dict = {}``) does NOT cover this: a
default applies to a MISSING field, while the ORM supplies the attribute
with an explicit None. Coercion has to happen in a before-validator.
"""
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from apps.api.app.schemas.repository import ScanJobResponse


def _row(**over):
    base = dict(
        id=uuid4(),
        repository_id=uuid4(),
        scan_type="STANDALONE",
        status="COMPLETED",
        progress_pct=100,
        status_message="[8/8] Complete",
        stats={},
        config={},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    base.update(over)
    return base


def test_null_config_is_coerced_not_rejected():
    m = ScanJobResponse(**_row(config=None))
    assert m.config == {}


def test_null_stats_is_coerced_not_rejected():
    m = ScanJobResponse(**_row(stats=None))
    assert m.stats == {}


def test_both_null_at_once():
    m = ScanJobResponse(**_row(config=None, stats=None))
    assert m.config == {} and m.stats == {}


def test_real_values_are_preserved_not_flattened():
    m = ScanJobResponse(**_row(
        config={"skip_ai": True, "branch": "master"},
        stats={"findings_total": 268, "untriaged_findings": 0},
    ))
    assert m.config["skip_ai"] is True
    assert m.stats["findings_total"] == 268
    assert m.stats["untriaged_findings"] == 0


def test_a_list_with_one_bad_row_still_serializes():
    """The actual failure mode: one NULL row among many broke them all."""
    rows = [_row(), _row(config=None), _row(stats=None), _row()]
    models = [ScanJobResponse(**r) for r in rows]
    assert len(models) == 4
    assert all(isinstance(m.config, dict) and isinstance(m.stats, dict) for m in models)
