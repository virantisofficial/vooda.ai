# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Base model for request bodies whose only client is our own UI.

Pydantic ignores unknown fields by default: a form posting a field name
the model does not define gets a 200, and the value is dropped. Renaming
a field on one side of the wire then fails silently on both.

`extra="forbid"` makes that a 422 at the first request instead.

Used only where we control both ends. The CLI and the CI action post to
/repositories and /findings, where an older client sending a field a
newer server does not know must keep working — those stay permissive on
purpose. /imports/scan is strict for an unrelated reason: there an
undeclared field is somewhere a raw secret value could ride in, so the
refusal is a redaction control rather than form validation.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Rejects unknown fields instead of discarding them."""

    model_config = ConfigDict(extra="forbid")
