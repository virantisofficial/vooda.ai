# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Cooperative cancellation signal, shared by the worker and services.

Lives here rather than in the worker so long-running service code
(AI triage, verification) can let it propagate without importing
``apps.worker``.

It is deliberately NOT a subclass of any error type that generic
``except Exception`` handlers are meant to absorb-in-place: a progress
callback that raises this is asking the run to STOP, not reporting a
recoverable fault. Any handler that swallows exceptions around a
progress or heartbeat callback must re-raise this one.
"""


class ScanCancelled(Exception):
    """The scan row was flipped to CANCELLED while the task was running."""
