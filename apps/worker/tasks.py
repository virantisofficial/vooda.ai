# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Celery task definitions for async processing.
"""

import os
import asyncio
import structlog
from typing import Optional
from uuid import UUID
from datetime import datetime, timezone
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from apps.worker.celery_app import (
    celery_app,
    SCAN_TASK_TIME_LIMIT,
    SCAN_TASK_SOFT_TIME_LIMIT,
)
from apps.api.app.core.config import settings

logger = structlog.get_logger()


def run_async(coro):
    """Helper to run async code in sync Celery tasks."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


import re as _re
# Paths that indicate a test/fixture context. Match common conventions across
# languages: Go `*_test.go`, JS `*.test.{js,ts}` / `*.spec.*`, Python `test_*.py`,
# plus directories like `tests/`, `test/`, `spec/`, `__tests__/`, `testdata/`,
# `fixtures/`. Kept deliberately broad — false-alarms on a tag are cheap.
_TEST_PATH_RE = _re.compile(
    r"(^|/)(tests?|spec|specs|__tests__|testdata|fixtures|e2e|integration-tests?)(/|$)"
    r"|(^|/)test_[^/]+\.py$"
    r"|_test\.(go|py|js|ts|tsx|jsx|java|rb|rs|cs|cpp|c)$"
    r"|\.(test|spec)\.(js|ts|tsx|jsx|mjs|cjs)$",
    _re.IGNORECASE,
)


def _derive_path_tags(file_path: str | None) -> list[str]:
    """Return auto-applied tags based on the file path (e.g. "test" for test fixtures)."""
    if not file_path:
        return []
    tags: list[str] = []
    if _TEST_PATH_RE.search(file_path):
        tags.append("test")
    return tags


# Severity rank used for escalate-only merges on the SecretIncident
# aggregate.  Higher = more severe.  Kept here (not just in config) so
# the ingest upsert below can map an incoming string severity to a
# numeric rank and feed it to a server-side GREATEST().
_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


async def _upsert_secret_incident(
    db: "AsyncSession",
    *,
    tenant_id,
    secret_hash: str,
    pf,
    now_ts,
    default_title: str,
    severity_normalizer,
    incident_cache: dict,
):
    """Concurrency-safe find-or-create-or-merge for a ``SecretIncident``.

    Shared by every scan-ingest path (source / repo / webhook).  Issued
    as a PostgreSQL ``INSERT ... ON CONFLICT (tenant_id, secret_hash)
    DO UPDATE`` **Core** statement, which makes the whole thing atomic
    against BOTH cross-scan races that used to crash ingest:

      1. the version-checked UPDATE race (two scans both load the same
         existing incident at ``version=v`` and the loser's
         ``... WHERE version=v`` matches 0 rows → ``StaleDataError`` →
         poisoned session → the whole scan's findings roll back), and
      2. the unique-INSERT race (two scans both SELECT-miss and both
         INSERT the same ``(tenant_id, secret_hash)`` → the loser hits
         ``uq_secret_incidents_tenant_hash`` → ``IntegrityError`` →
         same poisoned-session cascade).

    Because it runs as a Core statement against ``SecretIncident.__table__``
    (not by mutating a mapped instance), it deliberately **bypasses the
    ORM ``version_id_col`` plumbing**.  That plumbing exists for the
    *interactive human-triage* path (`PATCH /incidents/{id}` returns
    HTTP 409 so a reviewer whose draft was overwritten can reload); it
    is the wrong tool for an autonomous batch writer where there is no
    human to reload and the cost of a conflict is an entire lost scan.

    COLUMN-OWNERSHIP CONTRACT — do not break this:
      * Machine ingest (this function) OWNS and may write only:
        identity (``tenant_id``, ``secret_hash``), denormalized display
        fields (``title``, ``secret_type``, ``masked_value``), and the
        monotonic aggregates (``severity_max`` / ``severity_rank``,
        ``last_seen_at``, ``validation_status``) — plus ``first_seen_at``
        / ``occurrence_count`` / ``classification`` / ``review_status``
        only on the *initial INSERT* (seeding defaults for a brand-new
        credential).
      * Human triage OWNS the disposition columns (``classification``,
        ``review_status``, ``assigned_to``, ``rotation_status``) and the
        ``version`` counter.
      * The ``DO UPDATE SET`` below therefore touches ONLY ingest-owned
        columns and does NOT bump ``version``.  This disjointness is
        what lets a scan's severity merge and a reviewer's disposition
        edit race on the same row *without* a semantic conflict — and
        is why skipping the version bump here is correct rather than a
        shortcut.  Adding a human-owned column to the SET clause (or a
        ``version`` bump) would re-introduce spurious 409s for
        reviewers and quietly defeat the lock.

    ``occurrence_count`` is intentionally NOT aggregated here — it is
    recomputed post-scan from ``COUNT(*)`` on ``normalized_findings``
    (see the incident-stat refresh after each scan loop), which is
    idempotent under re-scan and task redelivery.

    Returns the incident ``id`` (UUID) for the finding FK, or ``None``
    when ``secret_hash`` is empty.
    """
    if not secret_hash:
        return None
    if secret_hash in incident_cache:
        # Already upserted in THIS scan — return the cached id.  Later
        # occurrences of the same credential in one scan would re-merge
        # identical values, so skip the round-trip.
        return incident_cache[secret_hash]

    from sqlalchemy import func, case
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from apps.api.app.models.finding import SecretIncident

    sev_in = severity_normalizer(pf.severity)
    sev_value = sev_in.value if hasattr(sev_in, "value") else str(sev_in).lower()
    sev_rank = _SEVERITY_RANK.get(sev_value, 1)
    raw = pf.raw_data or {}

    tbl = SecretIncident.__table__
    ins = pg_insert(tbl).values(
        tenant_id=tenant_id,
        secret_hash=secret_hash,
        title=(pf.title or default_title)[:500],
        secret_type=raw.get("secret_type"),
        masked_value=raw.get("masked_value"),
        severity_max=sev_value,
        severity_rank=sev_rank,
        occurrence_count=1,
        classification="needs_review",
        review_status="unreviewed",
        validation_status=raw.get("validation_status"),
        first_seen_at=now_ts,
        last_seen_at=now_ts,
        version=1,
    )
    excl = ins.excluded
    stmt = ins.on_conflict_do_update(
        constraint="uq_secret_incidents_tenant_hash",
        set_={
            # Escalate-only severity, decided numerically (lexical
            # GREATEST on the string enum would be wrong: 'high' > 'critical').
            "severity_rank": func.greatest(tbl.c.severity_rank, excl.severity_rank),
            "severity_max": case(
                (excl.severity_rank > tbl.c.severity_rank, excl.severity_max),
                else_=tbl.c.severity_max,
            ),
            # Denormalized display fields — prefer incoming when present.
            "title": func.coalesce(excl.title, tbl.c.title),
            "secret_type": func.coalesce(excl.secret_type, tbl.c.secret_type),
            "masked_value": func.coalesce(excl.masked_value, tbl.c.masked_value),
            # last_seen advances monotonically; GREATEST ignores NULLs.
            "last_seen_at": func.greatest(tbl.c.last_seen_at, excl.last_seen_at),
            # validation_status only-if-truthy → COALESCE(incoming, existing).
            "validation_status": func.coalesce(excl.validation_status, tbl.c.validation_status),
            # onupdate=now does NOT fire for ON CONFLICT DO UPDATE (it's an
            # INSERT construct), so stamp updated_at explicitly.
            "updated_at": now_ts,
            # NB: deliberately NOT touching classification / review_status /
            # assigned_to / rotation_status / first_seen_at / version.
        },
    ).returning(tbl.c.id)

    inc_id = (await db.execute(stmt)).scalar_one()
    incident_cache[secret_hash] = inc_id
    return inc_id


# Threshold above which we consider the triage batch "broken" and surface
# both an inline badge (via ai_model_configs.last_error) and a user-facing
# notification. Kept conservative: a single parse-retry doesn't trigger.
_TRIAGE_PARSE_FAILURE_THRESHOLD = 0.5


# Per-failure-type copy. Each entry drives both the last_error stamp (short
# one-liner for the provider-card badge hover) and the notification bell body
# (one or two sentences with concrete next step).
_FAILURE_TYPE_COPY = {
    "upstream_error": {
        "summary": "upstream provider error",
        "body": (
            "The LLM provider returned an error mid-generation (e.g. an "
            "upstream region crashed). Config is not the problem — consider "
            "switching the model_id to a different provider/route, or retry "
            "once the upstream recovers."
        ),
    },
    "truncated_response": {
        "summary": "responses truncated mid-JSON",
        "body": (
            "The model stopped emitting tokens before completing the "
            "classification JSON. Review stop_sequences and raise max_tokens "
            "on the primary model."
        ),
    },
    "invalid_json": {
        "summary": "model output was not valid JSON",
        "body": (
            "The model returned a response, but not in the expected JSON "
            "shape. Try enabling supports_json_mode, or consider a stricter "
            "model that follows the schema."
        ),
    },
    "empty_response": {
        "summary": "model returned no content",
        "body": (
            "The model returned an empty response (likely rate limit, "
            "timeout, or revoked API key). Check API key validity and rate "
            "limits on the primary model."
        ),
    },
}
_DEFAULT_FAILURE_COPY = {
    "summary": "triage classifications failing",
    "body": (
        "The AI model's responses could not be used to classify findings. "
        "Review the primary model configuration."
    ),
}


def _stability_id_for_pf(pf, repo_path: str) -> str:
    """Compute the stability_id for a PreFinding the SAME WAY the storing
    loop does (Phase-A L1).

    Centralised so the pre-loop bounded existing-finding probe and the
    in-loop dedup branch hit the same key — otherwise the probe could
    miss rows the loop would then double-create.

    Mirrors lines that previously lived inline in ``_run_scan_job``'s
    storing block.  See that block for the rationale:
      * with secret_hash (verified secret): ``secret_hash | path``
      * without secret_hash: ``rule_id | path | line_start``
    """
    # Delegate to the canonical shared formula (services.normalization.stability)
    # so the worker, the CLI/CI SARIF-import path, and policy-DOWN sync all
    # compute byte-identical keys. Behaviour here is unchanged — this used to
    # inline the same two-branch sha256; it now calls the single source of truth.
    from services.normalization.stability import compute_secret_stability_id
    fpc = pf.file_path or "unknown"
    if fpc.startswith(repo_path):
        fpc = fpc[len(repo_path):].lstrip("/")
    sh = (pf.raw_data or {}).get("secret_hash", "") if hasattr(pf, "raw_data") else ""
    return compute_secret_stability_id(
        secret_hash=sh,
        rule_id=pf.rule_id or "",
        file_path=fpc,
        line_start=pf.line_start,
    )


async def _store_imported_findings(
    db,
    job,
    repo,
    items: list,
    *,
    tenant_id,
    scanner_name: str = "vooda-cli",
    detection_engine: str = "vooda-cli-import",
):
    """Store CLI/CI-imported findings — P0 two-way sync (Approach B).

    Deliberately does NOT touch ``_run_scan_job`` (zero risk to server scans).
    Instead it REUSES the consistency-critical shared primitives so an
    imported finding dedupes against, and renders identically to, a server
    scan of the same secret:
      * ``_stability_id_for_pf`` → ``compute_secret_stability_id`` (the dedup key),
      * ``_upsert_secret_incident`` (the atomic, column-ownership-safe incident
        aggregation), and
      * the same ``NormalizedFinding`` field mapping the storing loop writes.

    Imports arrive ALREADY DETECTED and ALREADY MASKED (the import endpoint's
    redaction firewall guarantees no raw secret value is present), so the
    engine loop's on-disk snippet enrichment and raw-value redaction passes
    are intentionally absent here — there is no raw value to scrub and no repo
    checkout to read from.

    ``items``: list of server-validated finding dicts, each with
      rule_id, title, description, severity, vulnerability_category, cwe,
      file_path (repo-relative), line_start, line_end, confidence, code_snippet
      (already masked), secret_type, masked_value, secret_hash, detection_method.

    Returns ``(created_count, updated_count)``.
    """
    import hashlib as _hashlib
    from types import SimpleNamespace
    from datetime import datetime as _dt_imp, timezone as _tz_imp
    from sqlalchemy import select as _sa_select
    from apps.api.app.models.finding import NormalizedFinding, Classification
    from services.normalization.normalizer import normalize_severity
    from services.normalization.stability import compute_code_hash
    from packages.common.scanner_branding import brand_rule_id

    now = _dt_imp.now(_tz_imp.utc)
    incident_cache: dict = {}
    seen_sids: set = set()
    created = 0
    updated = 0

    for it in items:
        rule_id = it.get("rule_id") or ""
        file_path = it.get("file_path") or "unknown"   # CLI sends repo-relative
        line_start = it.get("line_start")
        secret_hash = it.get("secret_hash") or ""

        # Sanitize cwe the same way the storing loop does (≤20 / CWE-\d+).
        cwe_clean = it.get("cwe")
        if cwe_clean and len(cwe_clean) > 20:
            import re as _re_imp
            _m = _re_imp.match(r"(CWE-\d+)", cwe_clean)
            cwe_clean = _m.group(1) if _m else cwe_clean[:20]

        # PreFinding-shaped object so the SHARED helpers run unchanged.
        pf = SimpleNamespace(
            rule_id=rule_id,
            file_path=file_path,
            line_start=line_start,
            line_end=it.get("line_end"),
            severity=it.get("severity"),
            title=it.get("title"),
            description=it.get("description"),
            cwe=cwe_clean,
            category=it.get("vulnerability_category"),
            confidence=it.get("confidence"),
            code_snippet=it.get("code_snippet"),  # already masked by the CLI
            source_info=it.get("source_info") or {},
            sink_info=it.get("sink_info"),
            raw_data={
                "secret_hash": secret_hash,
                "masked_value": it.get("masked_value"),
                "secret_type": it.get("secret_type"),
                "detection_method": it.get("detection_method"),
                "validation_status": it.get("validation_status"),
                "provider": it.get("provider"),
                "entropy_score": it.get("entropy_score"),
                "commit_sha": it.get("commit_sha"),
            },
        )

        # file_path is already repo-relative → pass repo_path="" (the shared fn
        # only strips a prefix when present). Identical key to a server scan.
        sid = _stability_id_for_pf(pf, "")
        if sid in seen_sids:
            continue
        seen_sids.add(sid)

        fp = _hashlib.sha256(
            f"{rule_id}|{file_path}|{line_start or ''}|{it.get('vulnerability_category') or ''}".encode()
        ).hexdigest()[:16]
        chash = compute_code_hash(it.get("code_snippet") or "")

        existing = (
            await db.execute(
                _sa_select(NormalizedFinding).where(
                    NormalizedFinding.tenant_id == tenant_id,
                    NormalizedFinding.repository_id == repo.id,
                    NormalizedFinding.stability_id == sid,
                )
            )
        ).scalar_one_or_none()

        # Atomic incident upsert via the SHARED module-level helper.
        incident_id = await _upsert_secret_incident(
            db,
            tenant_id=tenant_id,
            secret_hash=secret_hash,
            pf=pf,
            now_ts=now,
            default_title="Hardcoded secret",
            severity_normalizer=normalize_severity,
            incident_cache=incident_cache,
        )

        if existing:
            # ── UPDATE (same secret seen again) — mirror the storing loop's
            # ingest-owned refreshes; never touch human-triage disposition.
            existing.last_seen_scan_job_id = job.id
            existing.last_seen_at = now
            existing.scan_count = (existing.scan_count or 1) + 1
            existing.line_start = line_start
            existing.line_end = it.get("line_end")
            existing.incident_id = incident_id
            new_sev = normalize_severity(it.get("severity"))
            if new_sev and existing.severity != new_sev:
                existing.severity = new_sev
            if it.get("title") and existing.title != (it.get("title") or "")[:500]:
                existing.title = (it.get("title") or "")[:500]
            updated += 1
        else:
            finding = NormalizedFinding(
                scan_job_id=job.id,
                repository_id=repo.id,
                tenant_id=tenant_id,
                scanner_name=scanner_name,
                scanner_rule_id=brand_rule_id(rule_id) if rule_id else rule_id,
                title=(it.get("title") or "Untitled")[:500],
                description=it.get("description"),
                vulnerability_category=(it.get("vulnerability_category") or "uncategorized")[:255],
                cwe=cwe_clean,
                severity=normalize_severity(it.get("severity")),
                file_path=file_path,
                line_start=line_start,
                line_end=it.get("line_end"),
                code_snippet=it.get("code_snippet"),
                confidence=it.get("confidence"),
                classification=Classification.NEEDS_REVIEW,
                fingerprint=fp,
                stability_id=sid,
                incident_id=incident_id,
                code_hash=chash,
                first_seen_at=now,
                last_seen_at=now,
                last_seen_scan_job_id=job.id,
                scan_count=1,
                source_metadata={
                    "detection_engine": detection_engine,
                    "original_rule_id": rule_id,
                    "secret_type": it.get("secret_type"),
                    "masked_value": it.get("masked_value"),   # masked only — never raw
                    "secret_hash": secret_hash,
                    "detection_method": it.get("detection_method"),
                    "provider": it.get("provider"),
                    "entropy_score": it.get("entropy_score"),
                    "validation_status": it.get("validation_status"),
                    "commit_sha": it.get("commit_sha"),
                    "imported": True,
                    "import_client": scanner_name,
                },
            )
            db.add(finding)
            created += 1

    # ── Refresh occurrence_count on touched incidents ──
    # Authoritative COUNT(*) on linked findings, mirroring the server
    # storing loop (tasks.py ~3582).  In-loop increments would double-count
    # on the update path, so the count is recomputed from the rows — which
    # is idempotent under re-import / task redelivery.
    if incident_cache:
        from sqlalchemy import update as _sa_update, func as _sa_func
        from apps.api.app.models.finding import SecretIncident as _SecretIncident
        inc_ids = list(incident_cache.values())
        await db.flush()  # make the just-added findings visible to COUNT(*)
        counts = await db.execute(
            _sa_select(NormalizedFinding.incident_id, _sa_func.count(NormalizedFinding.id))
            .where(NormalizedFinding.incident_id.in_(inc_ids))
            .group_by(NormalizedFinding.incident_id)
        )
        for inc_id, ct in counts.all():
            await db.execute(
                _sa_update(_SecretIncident)
                .where(_SecretIncident.id == inc_id)
                .values(occurrence_count=ct)
            )

    return created, updated


def _pick_failure_copy(failure_summary: dict[str, int] | None) -> tuple[str, str, str]:
    """Return (dominant_failure_type, short_summary, full_body) for the
    dominant failure class in the scan. Falls back to a generic message when
    the summary is empty or an unrecognised key dominates."""
    if not failure_summary:
        return ("unknown", _DEFAULT_FAILURE_COPY["summary"], _DEFAULT_FAILURE_COPY["body"])
    # Largest bucket wins; ties broken by dict order (Python 3.7+ insertion).
    dominant = max(failure_summary.items(), key=lambda kv: kv[1])[0]
    copy = _FAILURE_TYPE_COPY.get(dominant, _DEFAULT_FAILURE_COPY)
    return (dominant, copy["summary"], copy["body"])


async def _emit_triage_health_signal(
    db,
    tenant_id,
    scan_job_id,
    triaged: int,
    classified: int,
    parse_failure_rate: float,
    failure_summary: dict[str, int] | None = None,
) -> None:
    """Stamp model health + notify admins when triage is silently failing.

    When parse_failure_rate exceeds the threshold, update
    ai_model_configs.last_error on the primary model so the config card
    shows a "broken" badge, and insert a row into the notifications
    table so the header bell can surface it. The `failure_summary` dict
    (from _run_ai_triage) picks the message variant — upstream errors,
    truncated JSON, invalid schema, and empty responses each get distinct
    actionable guidance. On healthy runs, clear any stale last_error so
    the badge goes away after the user fixes the config.
    """
    from apps.api.app.models.ai_model import AIModelConfig
    from apps.api.app.models.notification import Notification
    from apps.api.app.models.user import User
    from sqlalchemy import select as _select

    mc_q = await db.execute(
        _select(AIModelConfig).where(
            AIModelConfig.tenant_id == tenant_id,
            AIModelConfig.is_active == True,  # noqa: E712
        ).order_by(AIModelConfig.is_primary.desc()).limit(1)
    )
    primary = mc_q.scalars().first()
    if not primary:
        return

    if triaged == 0 or parse_failure_rate < _TRIAGE_PARSE_FAILURE_THRESHOLD:
        # Healthy run — clear any stale "triage_parse_failure:" warning.
        if primary.last_error and primary.last_error.startswith("triage_parse_failure:"):
            primary.last_error = None
            await db.flush()
        return

    failed = triaged - classified
    dominant_type, short_summary, full_body = _pick_failure_copy(failure_summary)

    # Compact one-liner for the provider-card badge (hovering shows this).
    err_msg = (
        f"triage_parse_failure: {failed}/{triaged} findings — {short_summary} "
        f"(failure_type={dominant_type})."
    )
    primary.last_error = err_msg[:500]

    user_q = await db.execute(
        _select(User.id).where(User.tenant_id == tenant_id).limit(1)
    )
    user_id = user_q.scalar_one_or_none()
    if user_id is None:
        await db.flush()
        return

    notif = Notification(
        tenant_id=tenant_id,
        user_id=user_id,
        title=f"AI triage failing on {primary.name}",
        body=f"{failed} of {triaged} findings: {short_summary}. {full_body}",
        notification_type="triage_health",
        resource_type="ai_model",
        resource_id=str(primary.id),
        is_read=False,
        metadata_={
            "model_id": primary.model_id,
            "scan_job_id": str(scan_job_id),
            "triaged": triaged,
            "classified": classified,
            "parse_failure_rate": round(parse_failure_rate, 2),
            "dominant_failure_type": dominant_type,
            "failure_summary": failure_summary or {},
        },
    )
    db.add(notif)
    await db.flush()


async def _get_db_session():
    """Create a fresh async session with a new engine per task to avoid event loop issues."""
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
    engine = create_async_engine(
        settings.DATABASE_URL,
        pool_size=5,
        max_overflow=5,
        pool_pre_ping=True,
    )
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    return factory()


# Sprint G-2 — liveness heartbeat throttle state. Prefork runs one scan
# task per child process at a time, so a per-process dict is safe; the
# `job` key resets the throttle clock when a new scan reuses a recycled
# child.
_HB_STATE = {"job": None, "t": 0.0}


async def _stamp_heartbeat_main(job, db, *, commit: bool, force: bool = False, min_interval: float = 30.0) -> None:
    """Sprint G-2 — advance scan_jobs.heartbeat_at on the MAIN session.

    The stale-scan watchdog reaps a scan when COALESCE(heartbeat_at,
    created_at) has gone stale (no progress for the stall threshold,
    default 15m). Call this at REAL progress points only — each phase
    transition, each storing chunk-commit, each completed AI-triage
    batch — so the signal means "work is still completing", not merely
    "the event loop is alive" (a background ticker would keep stamping
    through an await-deadlock and the watchdog would never reap the
    wedged scan; tying it to real progress is what preserves deadlock
    detection).

    CRITICAL — always writes ``job.heartbeat_at`` on the passed-in (main)
    scan session, NEVER a second connection. An earlier version opened
    its own autocommit transaction to UPDATE the same scan_jobs row; at
    phase 1 the main txn already held that row's write lock (it had set
    job.status=RUNNING and flushed), so the heartbeat's separate txn
    blocked on the row lock while the main txn blocked awaiting the
    heartbeat — a self-deadlock that wedged the scan in select() forever
    (caught in G-2 regression on wrongsecrets). Sharing the main txn
    makes the write part of the scan's own row update — it can never
    deadlock against a lock the same transaction already holds.

      commit=False — caller commits imminently (phase emits, storing
                     chunk boundary), so just dirty the field and let
                     that commit carry it.
      commit=True  — caller has no imminent commit (AI triage's opaque
                     multi-minute process_batch), so commit here,
                     throttled to ~1/``min_interval`` s, to make the
                     heartbeat visible to the watchdog mid-phase.

    Best-effort: a heartbeat must never break a scan.
    """
    try:
        job.heartbeat_at = datetime.now(timezone.utc)
    except Exception:
        return
    if not commit:
        return
    import time as _time
    sid = str(getattr(job, "id", "") or "")
    now_mono = _time.monotonic()
    if _HB_STATE["job"] != sid:
        _HB_STATE["job"] = sid
        _HB_STATE["t"] = 0.0
    if not force and (now_mono - _HB_STATE["t"]) < min_interval:
        return
    _HB_STATE["t"] = now_mono
    try:
        await db.commit()
    except Exception as _hbe:
        logger.debug("heartbeat_commit_failed", error=str(_hbe)[:120])
    # Cooperative-cancellation checkpoint (see ScanCancelled). Piggybacks
    # on the throttled heartbeat commit so it costs one indexed PK read
    # per ~30s, and it runs at exactly the points where the scan is doing
    # real work — including the multi-minute AI-triage batch.
    await _raise_if_cancelled(job, db)


# Defined in packages.common so service-layer code (AI triage) can let it
# propagate without importing the worker. Re-exported here because this is
# where the cancellation checkpoint lives.
from packages.common.cancellation import ScanCancelled  # noqa: E402


async def _raise_if_cancelled(job, db) -> None:
    """Abort the scan if a user cancelled it in the API.

    Cancellation cannot rely on ``celery_app.control.revoke`` alone:

      * the cancel endpoint can only revoke when ``celery_task_id`` is
        recorded, so every dispatch site must persist it;
      * revoke is a best-effort broadcast — it can be missed if the
        worker reconnects, runs on another host, or the task has not been
        picked up yet.

    Cooperative cancellation is the signal-independent backstop: the
    worker asks the database whether it should still be running. Reads
    the status column directly (not ``db.refresh``) so no other in-memory
    attribute of the live job object is clobbered mid-scan.
    """
    try:
        from apps.api.app.models.scan import ScanJob as _SJ, ScanStatus as _SS
        current = await db.scalar(select(_SJ.status).where(_SJ.id == job.id))
    except Exception as e:  # never let the check itself break a scan
        logger.debug("cancel_check_failed", error=str(e)[:120])
        return
    if current == _SS.CANCELLED:
        logger.info(
            "scan_cancelled_cooperatively",
            scan_job_id=str(job.id),
            detail="row marked CANCELLED by an operator; aborting work",
        )
        raise ScanCancelled(str(job.id))


async def _scan_with_cpu_budget(scanner, repo_path, scan_job_id, **scan_kwargs):
    """Run ``scanner.scan_directory`` in a worker thread with an ADAPTIVE
    intra-scan ProcessPool size claimed from the global CPU budget (#146).

    Without this, K concurrent scans each spawn a ``min(8, cores)``-worker pool
    and oversubscribe the box K×workers/cores — at 8 cores / 8 scans / 8 workers
    that's 8×, which starves every scan's heartbeat loop and the stall watchdog
    false-reaps a healthy scan (root of the #165 false-reap family). The budget
    bounds the SUM of all pools to ≈cores: a lone scan gets the full 8 (fast);
    under load each scan gets ≈cores/active_scans.

    ``scan_cpu_slots`` is internally best-effort — it yields a share of 1 (never
    oversubscribe) if Redis is unreachable and does not raise — so a genuine
    scan error propagates here normally with the slot already released (we do
    NOT retry, which would double-scan and swallow the real error)."""
    from services.repo_scan.concurrency import scan_cpu_slots
    async with scan_cpu_slots(str(scan_job_id)) as _granted:
        return await asyncio.to_thread(
            scanner.scan_directory, repo_path, max_workers=_granted, **scan_kwargs
        )


# ═══════════════════════════════════════════════════════════════════
#  SCAN JOB — clone repo, analyze, run scanner, create findings
# ═══════════════════════════════════════════════════════════════════

@celery_app.task(
    bind=True,
    max_retries=3,
    # Sprint G-2 — per-task time limit override of the global 2h/2h15m
    # in celery_app.py. This is a COARSE fail-safe, not the primary
    # stall detector.
    #
    # History: G-1 set this to 25m/30m on the theory that a code scan
    # should never wedge a worker for hours. That was too tight and
    # became a regression — a legitimate large-repo scan (aws-cdk:
    # 25.8k files, ~5.4k findings, ~470 grouped for AI triage) needs
    # well over 30 min end-to-end (≈9.5m prepare+scan+store, then
    # ≈8m+ triage at the 60-rpm provider cap), so the 30m hard kill
    # SIGKILLed healthy scans before they could finish. Real-world
    # scan time is unbounded by design (repo size, history depth,
    # finding count), so no short fixed clock is correct.
    #
    # Primary stall detection now lives in the G-2 heartbeat watchdog
    # (_cleanup_stale_running_scans): it reaps a scan that stops making
    # progress for STALE_SCAN_THRESHOLD_MINUTES (default 15m of NO
    # heartbeat), which catches a real deadlock fast WITHOUT killing a
    # slow-but-progressing scan. This Celery limit is the ultimate
    # backstop for the case where the worker child itself is wedged so
    # hard it can't even be revoked — kept in the multi-hour range to
    # match CI norms (GitHub Actions 6h, GitLab 60m defaults). 4h hard
    # / 3h55m soft so the SoftTimeLimitExceeded handler below still has
    # a 5-min window to land a useful FAILED row before the hard kill.
    # Genuinely longer scans can opt in to a bigger budget via per-job
    # time_limit overrides on apply_async.
    # Imported from celery_app, NOT repeated as a literal: the broker's
    # visibility_timeout is derived from this value, and the two silently
    # drifting apart is precisely what caused hourly duplicate executions
    # of long scans. Change it in one place; the invariant test enforces
    # that the broker ceiling still clears it.
    time_limit=SCAN_TASK_TIME_LIMIT,
    soft_time_limit=SCAN_TASK_SOFT_TIME_LIMIT,
)
def run_scan_job(self, scan_job_id: str):
    """Execute a standalone scan job.

    Wraps the actual scan in a SoftTimeLimitExceeded handler so a
    repo that legitimately exceeds the configured soft-limit gets a
    FAILED row with a USEFUL error_detail instead of a silent
    FAILED-with-blank-message that requires log grep to diagnose.
    Track-A 2026-05-23 — discovered when a pulumi history scan was
    killed at exactly 30:00 by the old 30m soft cap and left zero
    diagnostic trace in the row.
    """
    from celery.exceptions import SoftTimeLimitExceeded

    logger.info("scan_job_started", scan_job_id=scan_job_id)
    try:
        run_async(_run_scan_job(scan_job_id))
    except ScanCancelled:
        # Requested stop, not a failure. The row is ALREADY CANCELLED
        # (the API set it); deliberately don't touch status here so the
        # operator's "Scan cancelled by <user>" message survives. The
        # repo lock is released by the context manager as the exception
        # unwinds, which is what frees the repository for a new scan —
        # without it the next Run Scan silently coalesces and the button
        # looks broken.
        logger.info("scan_job_cancelled", scan_job_id=scan_job_id)
        return
    except SoftTimeLimitExceeded:
        # Soft-limit handler — Celery has signalled that we're past
        # the configured budget.  We have ~15 min (gap to hard limit)
        # to write a useful row before SIGKILL closes the worker.
        logger.warning(
            "scan_job_soft_time_limit_exceeded",
            scan_job_id=scan_job_id,
        )
        try:
            run_async(_mark_scan_failed_with_timeout(scan_job_id))
        except Exception as mark_err:
            # If even the failure-marking errors, log loudly and let
            # the watchdog catch the row as zombie.  Don't re-raise —
            # we want the task to exit cleanly so the worker survives.
            logger.error(
                "scan_job_mark_failed_after_timeout_errored",
                scan_job_id=scan_job_id,
                error=str(mark_err)[:300],
            )
        # Re-raise so Celery records the task as failed (used by
        # observability / Flower / retry metrics).  Don't retry —
        # the same scan with the same input will hit the same limit.
        raise
    except Exception as exc:
        # ── Last-resort terminal-state guarantee ─────────────────────
        # Every inner handler is expected to stamp the row itself. This
        # exists for the paths that CANNOT: an error raised before `job`
        # is loaded, inside the failure handler, or from a poisoned
        # session. Without it the row could stay RUNNING/ANALYZING until
        # the stall watchdog notices, and the UI would report a scan as
        # in progress after the task had already stopped.
        #
        # Writes on a fresh session and never masks the original error.
        try:
            run_async(_force_terminal_failure(
                scan_job_id,
                f"{type(exc).__name__}: {exc}",
                message="Scan failed — worker error (see error detail)",
            ))
        except Exception as mark_err:
            logger.error(
                "scan_job_terminal_guarantee_failed",
                scan_job_id=scan_job_id, error=str(mark_err)[:300],
            )
        raise


async def _force_terminal_failure(scan_job_id: str, detail: str, message: str | None = None) -> bool:
    """Record a scan as FAILED on a FRESH session. Never raises.

    A failure handler must not write through the session that just
    failed. After a flush error SQLAlchemy poisons the transaction:
    every subsequent statement raises PendingRollbackError until the
    caller rolls back. Writing ``job.status = FAILED`` through that same
    session would therefore re-raise on commit and never persist the
    terminal state.

    Without this last-resort write a task can die with its row left
    mid-flight, so the UI keeps reporting a scan that is no longer
    running until the stall watchdog eventually clears it.

    Opening an independent session is the standard compensating-write
    pattern: the new connection has no poisoned transaction, so the
    terminal state lands even when the scan's own session is unusable.

    Returns True if a row was stamped. Swallows every exception — this
    runs on the error path and must never mask the original failure.
    """
    try:
        from apps.api.app.models.scan import ScanJob, ScanStatus
        from sqlalchemy import select
        from uuid import UUID

        async with await _get_db_session() as fresh:
            res = await fresh.execute(select(ScanJob).where(ScanJob.id == UUID(scan_job_id)))
            job = res.scalar_one_or_none()
            if job is None:
                return False
            # Don't clobber a terminal state — the scan may have been
            # cancelled by an operator, or genuinely completed in the gap.
            if job.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
                return False
            job.status = ScanStatus.FAILED
            job.error_detail = (detail or "unknown error")[:2000]
            if message:
                job.status_message = message[:500]
            await fresh.commit()
            logger.info("scan_forced_terminal_failure", scan_job_id=scan_job_id)
            return True
    except Exception as e:
        logger.error(
            "scan_force_terminal_failure_failed",
            scan_job_id=scan_job_id,
            error=str(e)[:200],
            detail="scan row may remain non-terminal until the stall watchdog reaps it",
        )
        return False


async def _mark_scan_failed_with_timeout(scan_job_id: str) -> None:
    """Stamp the scan row FAILED with an honest, actionable error_detail.

    Called from the SoftTimeLimitExceeded handler in run_scan_job.
    Preserves whatever progress_pct / status_message the worker last
    committed (so the operator can see "we got to [4/8] 40% before
    timing out") and surfaces both the percentage and the configured
    limit so the next action is obvious.
    """
    from apps.api.app.models.scan import ScanJob, ScanStatus
    from sqlalchemy import select
    from uuid import UUID

    async with await _get_db_session() as db:
        result = await db.execute(
            select(ScanJob).where(ScanJob.id == UUID(scan_job_id))
        )
        job = result.scalar_one_or_none()
        if not job:
            return

        # Only stamp if the row is still in a non-terminal state — if
        # the scan actually completed in the gap between the soft
        # signal firing and this handler running, don't clobber the
        # success status.
        if job.status not in (ScanStatus.RUNNING, ScanStatus.PENDING, ScanStatus.ANALYZING):
            return

        last_pct = job.progress_pct or 0
        last_phase = job.status_message or "an early phase"
        # Read the configured soft limit from celery so the message
        # auto-updates if ops change it via env override.
        try:
            soft_seconds = celery_app.conf.task_soft_time_limit or 7200
        except Exception:
            soft_seconds = 7200
        soft_minutes = int(soft_seconds / 60)

        msg = (
            f"Scan exceeded the {soft_minutes}-minute time limit while at "
            f"{last_pct}% ({last_phase!r}). This repo may be too large for "
            f"the default scan budget. Options: (a) try 'Scan Current Code' "
            f"instead of 'Scan Git History' for faster feedback; (b) reduce "
            f"history depth via the scan config; (c) contact support to "
            f"raise the per-tenant time budget."
        )
        job.status = ScanStatus.FAILED
        job.status_message = msg
        job.error_detail = msg
        await db.commit()
        logger.info(
            "scan_job_marked_failed_on_timeout",
            scan_job_id=scan_job_id,
            progress_pct=last_pct,
            soft_minutes=soft_minutes,
        )


# ═══════════════════════════════════════════════════════════════════
#  P0 TWO-WAY SYNC — ingest CLI/CI-imported findings.
#
#  The import API (routers/imports.py) has already: authenticated the
#  client (write-only `findings:import` scope), derived the tenant from
#  the key, run the redaction firewall, created the ScanJob (scan_type
#  CLI|CI, provenance columns populated) + one ImportedFinding row per
#  masked finding, and enqueued THIS task on the `scans` queue.
#
#  This task does the heavy lifting OFF the request path: it loads the
#  ImportedFinding rows, runs the authoritative 946-rule scanner scrub
#  over each snippet (belt-and-suspenders, identical to the server
#  storing loop's final redaction pass), then calls the SHARED
#  `_store_imported_findings` helper — so an imported finding dedupes
#  against, and renders identically to, a server scan of the same secret.
#
#  Idempotent: a COMPLETED job short-circuits (at-least-once redelivery),
#  and `_store_imported_findings` dedups by stability_id so a retry after
#  a transient failure UPDATEs rather than double-creates.
# ═══════════════════════════════════════════════════════════════════
@celery_app.task(bind=True, max_retries=2, time_limit=3600, soft_time_limit=3540)
def ingest_imported_findings(self, scan_job_id: str):
    """Celery entrypoint for the CLI/CI findings-import job."""
    logger.info("ingest_imported_findings_started", scan_job_id=scan_job_id)
    run_async(_ingest_imported_findings(scan_job_id))


async def _ingest_imported_findings(scan_job_id: str) -> None:
    from uuid import UUID
    from sqlalchemy import select
    from apps.api.app.models.scan import ScanJob, ScanStatus
    from apps.api.app.models.repository import Repository
    from apps.api.app.models.finding import ImportedFinding

    async with await _get_db_session() as db:
        job = (
            await db.execute(select(ScanJob).where(ScanJob.id == UUID(scan_job_id)))
        ).scalar_one_or_none()
        if not job:
            logger.warning("ingest_job_not_found", scan_job_id=scan_job_id)
            return
        # Idempotent re-delivery: a successfully-completed import must not
        # be re-stored.  (A FAILED row is allowed to re-run on retry —
        # _store_imported_findings dedups, so re-running is safe.)
        if job.status == ScanStatus.COMPLETED:
            logger.info("ingest_already_completed", scan_job_id=scan_job_id)
            return

        repo = (
            await db.execute(select(Repository).where(Repository.id == job.repository_id))
        ).scalar_one_or_none()
        if not repo:
            job.status = ScanStatus.FAILED
            job.status_message = "Import failed: repository no longer exists."
            job.error_detail = "repository_id not found at ingest time"
            await db.commit()
            return

        import_cfg = (job.config or {}).get("import") or {}
        client_label = (import_cfg.get("client") or "vooda-cli")[:100]

        try:
            # ── Mark running + heartbeat so the watchdog never reaps us ──
            job.status = ScanStatus.RUNNING
            job.progress_pct = 10
            job.status_message = f"Importing findings from {client_label}…"
            await _stamp_heartbeat_main(job, db, commit=False, force=True)
            await db.commit()

            rows = (
                await db.execute(
                    select(ImportedFinding).where(ImportedFinding.scan_job_id == job.id)
                )
            ).scalars().all()
            items = [dict(r.raw_data or {}) for r in rows]

            # ── Authoritative belt-and-suspenders snippet scrub ──
            # The CLI pre-masks and the API entropy-scrubs, but the 946-rule
            # scanner is the SAME final redaction pass the server storing
            # loop runs — so the worst-case snippet an import can persist is
            # at parity with a server scan.  Best-effort: a scanner build
            # failure must not block the import (snippets are already masked).
            try:
                from services.secret_scan.engine import SecretScanner, redact_with_scanner
                from services.secret_scan.detectors.registry import get_all_rules
                scanner = SecretScanner(rules=get_all_rules())
                for it in items:
                    snip = it.get("code_snippet")
                    if snip:
                        it["code_snippet"] = redact_with_scanner(snip, scanner)
            except Exception as scrub_err:
                logger.warning(
                    "ingest_snippet_scrub_failed",
                    scan_job_id=scan_job_id, error=str(scrub_err)[:200],
                )

            job.progress_pct = 56
            job.status_message = f"[storing] {len(items):,} imported findings…"
            await _stamp_heartbeat_main(job, db, commit=False, force=True)
            await db.commit()

            detection_engine = (
                "vooda-ci-import"
                if (job.scan_type.value if hasattr(job.scan_type, "value") else str(job.scan_type)) == "ci"
                else "vooda-cli-import"
            )
            created, updated = await _store_imported_findings(
                db, job, repo, items,
                tenant_id=job.tenant_id,
                scanner_name=client_label,
                detection_engine=detection_engine,
            )
            await db.flush()

            # ── Finalize ──
            job.status = ScanStatus.COMPLETED
            job.progress_pct = 100
            job.status_message = (
                f"Imported {created:,} new + {updated:,} existing findings from {client_label}"
            )
            job.stats = {
                **(job.stats or {}),
                "findings_count": created + updated,
                "imported_created": created,
                "imported_updated": updated,
                "import_total": len(items),
                "snippets_scrubbed": import_cfg.get("snippets_scrubbed", 0),
            }
            await _stamp_heartbeat_main(job, db, commit=False, force=True)
            await db.commit()

            logger.info(
                "ingest_imported_findings_done",
                scan_job_id=scan_job_id, created=created, updated=updated, total=len(items),
            )

            # ── Best-effort live progress publish (no DB write) ──
            try:
                from services.pubsub.redis_pubsub import publish_scan_progress
                await publish_scan_progress(
                    scan_job_id, "completed", 100, job.status_message,
                    {"imported_created": created, "imported_updated": updated},
                )
            except Exception:
                pass

        except Exception as exc:
            # Single-transaction model: nothing was committed mid-store
            # (the shared helpers only execute, never commit), so a rollback
            # leaves the DB clean and a retry starts fresh.
            await db.rollback()
            try:
                fresh = (
                    await db.execute(select(ScanJob).where(ScanJob.id == UUID(scan_job_id)))
                ).scalar_one_or_none()
                if fresh and fresh.status != ScanStatus.COMPLETED:
                    fresh.status = ScanStatus.FAILED
                    fresh.status_message = "Import failed while storing findings."
                    fresh.error_detail = str(exc)[:500]
                    await db.commit()
            except Exception:
                pass
            logger.error(
                "ingest_imported_findings_failed",
                scan_job_id=scan_job_id, error=str(exc)[:300],
            )
            raise


# ═══════════════════════════════════════════════════════════════════
#  ONE-SHOT MAINTENANCE: redact raw secrets from existing code_snippet
#  and FindingEvidence content rows.  Required after shipping the
#  "mask at storage" feature so historical rows are brought in line
#  with the new at-rest contract.  Idempotent — safe to run multiple
#  times; rows already redacted are skipped because the scanner won't
#  find the masked form as a secret.
# ═══════════════════════════════════════════════════════════════════
@celery_app.task(bind=True, max_retries=0)
def redact_existing_snippets(self, dry_run: bool = False):
    """Re-scan every persisted code_snippet + FindingEvidence content
    and replace the in-line raw secret with its masked form.

    Approach:
      1. Pull every finding with a non-empty code_snippet
      2. Run the secret scanner against the snippet text directly
      3. For each match, redact the matched value using `_redact_in_snippet`
      4. Update the row if anything changed
      5. Repeat for FindingEvidence rows whose evidence_type='code_context'

    Safe + idempotent: if a snippet has no secrets (already masked),
    nothing changes.  Cheap: only touches rows that need fixing.
    """
    logger.info("redact_existing_snippets_started", dry_run=dry_run)
    run_async(_redact_existing_snippets(dry_run=dry_run))


async def _redact_existing_snippets(dry_run: bool = False):
    import apps.api.app.models  # noqa
    from apps.api.app.models.finding import NormalizedFinding, FindingEvidence
    from services.secret_scan.engine import SecretScanner, _redact_in_snippet, _scrub_residual_secrets
    from services.secret_scan.detectors.registry import get_all_rules

    scanner = SecretScanner(rules=get_all_rules())
    findings_updated = 0
    evidence_updated = 0
    findings_total = 0
    evidence_total = 0

    async with await _get_db_session() as db:
        # ── Findings ──
        result = await db.execute(
            select(NormalizedFinding).where(NormalizedFinding.code_snippet.isnot(None))
        )
        for f in result.scalars().all():
            findings_total += 1
            snippet = f.code_snippet or ""
            if not snippet:
                continue
            try:
                # Scan the snippet text directly — the scanner will find
                # whatever secret(s) are still embedded in it.
                hits = scanner.scan_file(f.file_path or "<snippet>", snippet)
            except Exception as e:
                logger.warning("redact_scan_failed", finding_id=str(f.id), error=str(e)[:160])
                continue
            new_snippet = snippet
            for hit in hits or []:
                raw_val = (hit.raw_data or {}).get("_raw_value_for_verification") or ""
                masked = (hit.raw_data or {}).get("masked_value") or ""
                if raw_val:
                    new_snippet = _redact_in_snippet(new_snippet, raw_val, masked)
            # Align with redact_with_scanner: mask provider-token shapes the
            # re-scan missed (co-located false negatives) so old at-rest rows
            # get cleaned too (G1).
            new_snippet = _scrub_residual_secrets(new_snippet)
            if new_snippet != snippet:
                if not dry_run:
                    f.code_snippet = new_snippet
                findings_updated += 1

        # ── Finding evidence (separate table for code_context rows) ──
        ev_result = await db.execute(
            select(FindingEvidence).where(
                FindingEvidence.evidence_type == "code_context",
                FindingEvidence.content.isnot(None),
            )
        )
        for ev in ev_result.scalars().all():
            evidence_total += 1
            content = ev.content or ""
            if not content:
                continue
            try:
                hits = scanner.scan_file(ev.file_path or "<snippet>", content)
            except Exception as e:
                logger.warning("redact_evidence_scan_failed", evidence_id=str(ev.id), error=str(e)[:160])
                continue
            new_content = content
            for hit in hits or []:
                raw_val = (hit.raw_data or {}).get("_raw_value_for_verification") or ""
                masked = (hit.raw_data or {}).get("masked_value") or ""
                if raw_val:
                    new_content = _redact_in_snippet(new_content, raw_val, masked)
            new_content = _scrub_residual_secrets(new_content)
            if new_content != content:
                if not dry_run:
                    ev.content = new_content
                evidence_updated += 1

        if not dry_run:
            await db.commit()

    logger.info(
        "redact_existing_snippets_complete",
        dry_run=dry_run,
        findings_total=findings_total,
        findings_updated=findings_updated,
        evidence_total=evidence_total,
        evidence_updated=evidence_updated,
    )
    return {
        "dry_run": dry_run,
        "findings_total": findings_total,
        "findings_updated": findings_updated,
        "evidence_total": evidence_total,
        "evidence_updated": evidence_updated,
    }


# ═══════════════════════════════════════════════════════════════════
#  SOURCE SCAN — extract content from non-git sources (Slack, Jira,
#  Confluence, S3, etc.) and run the secret detector over it.
#
#  Per-source scope (target_repository_id / target_business_unit_id)
#  is honoured via the parent ScanJob, which inherits the binding at
#  dispatch time in apps/api/app/routers/scan_sources.py. Findings
#  created here just copy job.repository_id, so per-repo features
#  (ticketing destination, BU access, dashboards) Just Work for
#  source-derived findings the same way they do for git scans.
#  Bug fix / feature 2026-04-29.
# ═══════════════════════════════════════════════════════════════════

async def _emit_retro_phase(db, job, scan_job_id: str, status: str, pct: int,
                            msg: str, step: int, stats: dict = None):
    """Standalone phase emit for the AI-triage-retro task. Mirrors
    `_run_scan_job._emit_phase` so the scan-card progress bar AND the live side
    drawer stay in sync during a retroactive triage: persists an append-only
    `ScanPhaseEvent` (what the drawer seeds from on open/refresh) and publishes
    to Redis (what the live WS relays). `_run_ai_triage` already publishes the
    intermediate per-batch progress; this brackets it with start/completed so
    the drawer transitions off the old scan's timeline.
    """
    from uuid import UUID as _UUID
    from packages.common.logging_config import _redact_string
    from apps.api.app.models.scan import ScanPhaseEvent
    safe = _redact_string(msg or "")
    try:
        job.status_message = safe
        job.progress_pct = int(pct)  # retro is a fresh phase — intentionally not
                                     # clamped against the old completed scan's 100%
    except Exception:
        pass
    try:
        db.add(ScanPhaseEvent(
            scan_job_id=_UUID(scan_job_id), step=step, total_steps=8,
            phase_label=safe[:1000], status=status, progress_pct=int(pct),
            stats_snapshot=stats or None,
        ))
        await db.flush()
    except Exception as e:
        logger.warning("retro_phase_persist_failed", scan_job_id=scan_job_id, error=str(e)[:160])
    try:
        from services.pubsub.redis_pubsub import publish_scan_progress
        await publish_scan_progress(scan_job_id, status, int(pct), safe, stats)
    except Exception as e:
        logger.warning("retro_phase_publish_failed", scan_job_id=scan_job_id, error=str(e)[:160])


@celery_app.task(bind=True, max_retries=0, time_limit=3600, soft_time_limit=3540)
def run_ai_triage_retro(self, scan_job_id: str):
    """Re-run AI triage on an ALREADY-COMPLETED scan whose triage was skipped.

    Powers the "Run AI Triage" button on the scan-history card: when a scan
    finished with no AI model configured (or skip_ai), the user can configure a
    model and trigger triage retroactively WITHOUT re-scanning every file. Reuses
    the same `_run_ai_triage` core the live scan uses, on the findings already in
    the DB.
    """
    logger.info("ai_triage_retro_started", scan_job_id=scan_job_id)
    run_async(_run_ai_triage_retro(scan_job_id))


async def _run_ai_triage_retro(scan_job_id: str):
    import os
    import apps.api.app.models  # noqa: F401
    from datetime import datetime, timezone
    from sqlalchemy import select, func as sa_func
    from apps.api.app.models.scan import ScanJob, ScanStatus
    from apps.api.app.models.repository import Repository
    from apps.api.app.models.finding import NormalizedFinding, Classification as Cls

    async with await _get_db_session() as db:
        job = (await db.execute(select(ScanJob).where(ScanJob.id == scan_job_id))).scalar_one_or_none()
        if not job:
            logger.error("ai_triage_retro_no_job", scan_job_id=scan_job_id)
            return
        repo = (await db.execute(select(Repository).where(Repository.id == job.repository_id))).scalar_one_or_none()
        if not repo:
            logger.error("ai_triage_retro_no_repo", scan_job_id=scan_job_id)
            job.status = ScanStatus.COMPLETED
            job.status_message = "AI triage failed — repository not found"
            await db.commit()
            return

        # Reuse the cached clone; re-clone only if it was cleaned up — AI triage
        # needs the working tree for code-context extraction.
        repo_path = f"/app/storage/repos/{repo.id}"
        if not os.path.isdir(repo_path):
            try:
                repo_path = await _clone_repository(repo.url, str(repo.id), repo.default_branch)
            except Exception as e:
                logger.error("ai_triage_retro_clone_failed", scan_job_id=scan_job_id, error=str(e)[:200])
                job.status = ScanStatus.COMPLETED
                job.status_message = "AI triage failed — could not access repository files"
                await db.commit()
                return

        # Drive progress so the card bar AND the live side drawer (WS + the
        # persisted phase timeline) stay in sync — a real phase emit, not a
        # silent DB status flip the drawer never sees.
        job.status = ScanStatus.ANALYZING
        try:
            job.heartbeat_at = datetime.now(timezone.utc)
        except Exception:
            pass
        await _emit_retro_phase(db, job, scan_job_id, "analyzing", 62,
                                "AI triage — analyzing findings…", step=7)
        await db.commit()

        try:
            triaged, dedup_saved, failure_summary = await _run_ai_triage(db, job, repo_path)
            fp_after = (await db.execute(select(sa_func.count(NormalizedFinding.id)).where(
                NormalizedFinding.scan_job_id == job.id,
                NormalizedFinding.classification.in_([Cls.LIKELY_FALSE_POSITIVE, Cls.CONFIRMED_FALSE_POSITIVE]),
            ))).scalar() or 0
            tp_after = (await db.execute(select(sa_func.count(NormalizedFinding.id)).where(
                NormalizedFinding.scan_job_id == job.id,
                NormalizedFinding.classification == Cls.LIKELY_TRUE_POSITIVE,
            ))).scalar() or 0
            # Reflect the triage in the `stats` JSONB the scan card reads. The
            # card's "AI triage pending" gate is `ai_triaged === 0`, so without
            # this the findings get classified but the card never updates. Merge
            # (don't rebuild) to preserve files_analyzed / findings_total / etc.
            _stats = dict(job.stats or {})
            _stats["ai_triaged"] = fp_after + tp_after
            _stats["false_positives"] = fp_after
            _stats["true_positives"] = tp_after
            job.stats = _stats
            job.status = ScanStatus.COMPLETED
            try:
                job.heartbeat_at = datetime.now(timezone.utc)
            except Exception:
                pass
            await _emit_retro_phase(
                db, job, scan_job_id, "completed", 100,
                f"AI triage complete — {fp_after} false positives, {tp_after} true positives identified",
                step=8, stats={"false_positives": fp_after, "true_positives": tp_after},
            )
            await db.commit()
            logger.info("ai_triage_retro_done", scan_job_id=scan_job_id, triaged=triaged, fp=fp_after, tp=tp_after)
        except Exception as e:
            logger.error("ai_triage_retro_failed", scan_job_id=scan_job_id, error=str(e)[:300])
            # Never leave the job stuck in ANALYZING — revert to COMPLETED.
            job.status = ScanStatus.COMPLETED
            job.status_message = "AI triage encountered errors — findings left unreviewed"
            job.progress_pct = 100
            await db.commit()


@celery_app.task(bind=True, max_retries=2)
def run_source_scan(self, scan_job_id: str, scan_source_id: str):
    """Execute a non-git source scan (Slack, Jira, Confluence, S3, …).

    Args:
        scan_job_id: ScanJob row created in trigger_source_scan().
        scan_source_id: Configured ScanSource describing what to scan.
    """
    logger.info("source_scan_started", scan_job_id=scan_job_id, source_id=scan_source_id)
    run_async(_run_source_scan(scan_job_id, scan_source_id))


async def _run_source_scan(scan_job_id: str, scan_source_id: str):
    import apps.api.app.models  # noqa: F401
    import asyncio
    import hashlib
    import time as _time
    from datetime import datetime, timezone
    from apps.api.app.models.scan import ScanJob, ScanStatus
    from apps.api.app.models.scan_source import ScanSource
    from apps.api.app.models.integration import IntegrationConfig
    from apps.api.app.models.finding import NormalizedFinding, Severity, Classification, SecretIncident
    from services.secret_scan.engine import SecretScanner
    from services.source_scanners.factory import create_source_adapter
    from packages.common.encryption import decrypt_config_dict
    # Inline live validation (mirrors _run_scan_job's Step 4b path).
    # Validates the raw secret value against the upstream provider
    # BEFORE persisting the finding. Reduces noise on the dashboard:
    # a JIRA ticket with `password = "admin"` from 2019 is much less
    # interesting if the credential has since been rotated; conversely
    # a still-live AWS key in a Confluence page is a P0.
    try:
        from services.secret_verification.verifier import (
            verify_finding as _verify_finding,
            SUPPORTED_PROVIDERS as _SUPPORTED_PROVIDERS,
        )
        from services.secret_verification.blast_radius import analyze_blast_radius as _analyze_blast_radius
        _validation_available = True
    except Exception:
        _validation_available = False
        _SUPPORTED_PROVIDERS = set()

    def _normalize_severity(sev: str) -> Severity:
        s = (sev or "").lower()
        if s == "critical": return Severity.CRITICAL
        if s == "high": return Severity.HIGH
        if s == "medium": return Severity.MEDIUM
        if s == "low": return Severity.LOW
        return Severity.INFO

    # ── Source-level concurrency lock ──────────────────────────
    # Two scans on the same source can race on `sync_state`: the
    # first commits its watermark while the second is mid-scan,
    # and the second's writeback overwrites — items appear "lost"
    # on the next run. Acquired via Redis SETNX with TTL so a
    # crashed worker auto-clears in 30 min. Acquire-or-skip — if
    # we lose the race, mark this job as cancelled-with-reason
    # and exit cleanly so the UI shows what happened.
    from services.source_scanners.concurrency import (
        source_scan_lock, LockNotAcquired,
    )

    async with await _get_db_session() as db:
        # ── Load job + source + integration ──
        job = (await db.execute(select(ScanJob).where(ScanJob.id == UUID(scan_job_id)))).scalar_one_or_none()
        if not job:
            logger.error("source_scan_no_job", scan_job_id=scan_job_id)
            return
        source = (await db.execute(select(ScanSource).where(ScanSource.id == UUID(scan_source_id)))).scalar_one_or_none()
        if not source:
            job.status = ScanStatus.FAILED
            job.error_detail = "Scan source not found"
            await db.commit()
            return
        integration = (await db.execute(
            select(IntegrationConfig).where(IntegrationConfig.id == source.integration_config_id)
        )).scalar_one_or_none()
        if not integration:
            job.status = ScanStatus.FAILED
            job.error_detail = "Integration config not found"
            await db.commit()
            return

        # Try to claim the source. Failure here means another scan
        # is already running for this source; mark the job as
        # cancelled (not failed — nothing's wrong, just redundant)
        # and exit. Source.stats is left untouched; the in-flight
        # scan will update it when it completes.
        try:
            scan_lock_cm = source_scan_lock(str(source.id), holder=str(job.id))
            await scan_lock_cm.__aenter__()
        except LockNotAcquired as e:
            logger.info("source_scan_skipped_concurrent",
                        scan_job_id=scan_job_id, source_id=scan_source_id,
                        reason=str(e))
            job.status = ScanStatus.CANCELLED
            job.error_detail = "Skipped — another scan is already running for this source."
            job.progress_pct = 0
            job.stats = {"skipped": True, "reason": "concurrent_scan_in_progress"}
            await db.commit()
            return

        # Single source of truth for releasing the lock. Reused by
        # every post-acquire exit path so an early failure (adapter
        # init, preflight, …) can't strand the key. Without this the
        # next scan attempt for the same source gets a spurious
        # LockNotAcquired until the TTL expires; the periodic
        # cleanup_stale_source_scan_locks task is the belt-and-braces
        # against the cases this can't catch (SIGKILL'd worker, etc).
        async def _release_lock():
            try:
                await scan_lock_cm.__aexit__(None, None, None)
            except Exception as rel_err:
                logger.warning("source_scan_lock_release_failed",
                               source_id=scan_source_id, error=str(rel_err)[:160])

        # Mark running so the UI shows progress.
        job.status = ScanStatus.RUNNING
        job.progress_pct = 5
        await db.commit()

        # ── Build adapter with decrypted credentials ──
        # When the IntegrationConfig is in OAuth mode, inject a token
        # provider that hits refresh_atlassian_token_if_needed so the
        # adapter always sees a fresh bearer (cheap when not expired,
        # one upstream call when refreshed). The provider closes
        # over the integration_id and uses a fresh DB session per
        # call so it doesn't conflict with the scan's session.
        try:
            creds = decrypt_config_dict(dict(integration.config or {}))
            if (creds.get("auth_type") or "basic").lower() == "oauth2":
                from apps.api.app.routers.integrations_oauth import (
                    refresh_atlassian_token_if_needed,
                )
                _integration_id = integration.id

                async def _atlassian_token_provider() -> str:
                    async with await _get_db_session() as token_db:
                        return await refresh_atlassian_token_if_needed(
                            token_db, _integration_id,
                        )

                creds["_token_provider"] = _atlassian_token_provider

            adapter = create_source_adapter(
                source_type=source.source_type,
                config=dict(source.config or {}),
                credentials=creds,
            )
        except Exception as e:
            logger.exception("source_adapter_create_failed", error=str(e)[:300])
            job.status = ScanStatus.FAILED
            job.error_detail = f"Adapter init failed: {e}"[:500]
            await db.commit()
            await _release_lock()
            return

        scanner = SecretScanner()
        items_scanned = 0
        findings_total = 0
        validated_count = 0
        active_count = 0
        seen_stability: set[str] = set()
        now = datetime.now(timezone.utc)

        # ── Rule-override pre-gate (source-scan path) ──────────────
        # Twin of the repo-scan setup at apps/worker/tasks.py:~2250.
        # Preloads active scanner_rule_ids muted for this (tenant,
        # source) — both source-scoped overrides and org-wide.  The
        # persist loop checks the set in O(1) per finding and the
        # block counter is written back via record_blocks() after the
        # loop completes.
        from apps.worker.rule_overrides import (
            load_active_rule_ids as _load_src_overrides,
            new_block_counter as _new_src_block_counter,
            record_blocks as _record_src_blocks,
        )
        from packages.common.scanner_branding import brand_rule_id as _brand_rule_id
        src_muted_rule_ids: set[str] = await _load_src_overrides(
            db, job.tenant_id, scan_source_id=source.id,
        )
        src_block_counts = _new_src_block_counter()

        # In-memory cache of incidents we've already upserted in THIS
        # scan run.  Keyed by secret_hash — avoids re-querying the DB
        # for every duplicate finding of the same credential within a
        # single scan.  Maps hash → SecretIncident.id (UUID).
        incident_cache: dict[str, "UUID"] = {}

        async def _upsert_incident_for(sh: str, pf, now_ts):
            """Find-or-create the SecretIncident for `sh` (source-scan path).

            Thin wrapper over the shared, concurrency-safe
            :func:`_upsert_secret_incident` (atomic ON CONFLICT upsert).
            See that function for the column-ownership contract and the
            two cross-scan races it closes.  ``occurrence_count`` is
            still recomputed post-scan from ``COUNT(*)``.
            """
            return await _upsert_secret_incident(
                db,
                tenant_id=job.tenant_id,
                secret_hash=sh,
                pf=pf,
                now_ts=now_ts,
                default_title="Hardcoded secret in source",
                severity_normalizer=_normalize_severity,
                incident_cache=incident_cache,
            )

        # ── Full-sweep mode (weekly safety net) ──────────────────
        # When dispatched with ``config.force_full = true`` (manual
        # operator trigger OR the weekly Beat sweep), we ignore the
        # source's saved ``sync_state`` and pass an empty dict to
        # the adapter. The adapter then re-walks every item the
        # source exposes, regardless of timestamp watermark.
        #
        # Three correctness wins:
        #  1. Watermark drift recovery: a stuck cursor / malformed
        #     watermark gets bypassed automatically.
        #  2. Deletion detection: every item NOT seen in the sweep
        #     gets tombstoned by the post-scan pass below.
        #  3. First-scan recovery: a partial first scan (rate
        #     limited halfway through) gets re-baselined.
        #
        # Cost: the full sweep runs the full adapter API budget,
        # so for high-volume sources (Slack workspaces with 1M+
        # messages) this can be expensive. Mitigation: weekly
        # cadence keeps the cost amortized, and the per-source
        # concurrency lock prevents two sweeps colliding.
        force_full_sweep = bool((job.config or {}).get("force_full", False))
        sync_state_for_adapter = {} if force_full_sweep else dict(source.sync_state or {})

        # Locators seen this scan — needed for the tombstone pass on
        # full sweeps. Tracked at the ``item`` granularity (one per
        # Slack message / Jira issue / S3 object), not the finding
        # granularity, so a rule-pack change that no longer flags an
        # otherwise-still-present item doesn't get mis-tombstoned as
        # "item deleted." On incremental scans this set is
        # intentionally partial (only changed items appear) and the
        # tombstone pass is gated off, so the partial set is harmless.
        seen_locators: set[str] = set()

        # Per-surface yield accounting. Lets the customer (and us)
        # see whether opt-in surfaces (custom_field, attachment) are
        # actually paying off on their tenant — if findings_by_surface
        # shows 0 from custom_field after a few scans, they can turn
        # the toggle off and reclaim the runtime cost.
        #
        # Buckets cover both adapter-provided content_type values
        # (message / page / comment / file / env_var / log_line —
        # see services/source_scanners/base.py:ScanableContent) AND
        # the Jira-specific sub-buckets the Jira adapter recognises
        # via its locator suffix (summary / description / customfield
        # / attachment). Anything we don't recognise falls into
        # "other" which keeps the schema stable as new adapters land.
        findings_by_surface: dict[str, int] = {
            # Adapter-level content_type values
            "message": 0, "page": 0, "comment": 0,
            "file": 0, "env_var": 0, "log_line": 0,
            # Jira-locator sub-buckets — finer-grained than `page`
            # alone and worth surfacing because each maps to a
            # different cost/yield tradeoff in the schema's hint
            # text (e.g. "scan_custom_fields adds 5-15% scan time").
            "summary": 0, "description": 0,
            "custom_field": 0, "attachment": 0,
            "other": 0,
        }

        def _surface_for(locator: str, content_type: str | None) -> str:
            """Bucket a finding by surface — prefer the Jira-locator
            sub-bucket when present (finer-grained), else use the
            adapter's content_type, else fall through to 'other'.

            Bug fix 2026-05-03: we previously regex-matched the
            locator and called everything non-Jira "other". Caused
            Slack messages, Confluence pages, S3 files, etc. to all
            collapse into the same bucket. Now adapter-provided
            content_type values get their own buckets.
            """
            if "/summary" in locator:
                return "summary"
            if "/description" in locator:
                return "description"
            if "/customfield/" in locator:
                return "custom_field"
            if "/attachment/" in locator:
                return "attachment"
            # Comment locators (Jira "/comment/", GitHub Issues
            # "/comment/", Bitbucket "/comment/", Linear comment, …)
            if "/comment/" in locator:
                return "comment"
            # Fall through to the adapter's categorical tag.
            if content_type and content_type in findings_by_surface:
                return content_type
            return "other"

        # Per-scan budget for live validation. Mirrors the git path:
        # 60s for all upstream-provider checks combined, then we
        # surface remaining findings as NOT_VALIDATED. Stops a single
        # source scan from spinning forever if a provider is slow.
        verify_budget_s = 60
        verify_budget_start = _time.monotonic()

        async def _validate_pf(pf):
            """Validate one ParsedFinding inline; mutate raw_data in-place.

            Returns True if validation actually ran (success or fail),
            False if skipped (no raw value, unsupported provider,
            budget exhausted, or validation infra unavailable).
            """
            nonlocal validated_count, active_count
            if not _validation_available:
                return False
            rd = pf.raw_data or {}
            raw_val = rd.get("_raw_value_for_verification", "")
            provider = (rd.get("provider") or "").lower()
            if not raw_val or provider not in _SUPPORTED_PROVIDERS:
                return False
            if _time.monotonic() - verify_budget_start > verify_budget_s:
                return False
            verify_sm = {
                "_raw_value": raw_val,
                "provider": provider,
                "detection_method": rd.get("detection_method", "regex"),
            }
            try:
                # S1: cache-first + per-provider rate limit (see _verify_with_cache).
                result = await _verify_with_cache(verify_sm, job.tenant_id, rd.get("secret_hash", ""))
            except (asyncio.TimeoutError, Exception) as ve:
                logger.warning("source_validation_failed", provider=provider, error=str(ve)[:160])
                return False
            if not result or result.status not in ("active", "inactive"):
                return False
            rd["validation_status"] = result.status
            rd["verification_details"] = result.details
            rd["verification_permissions"] = getattr(result, "permissions", None)
            rd["verification_source"] = "live"
            rd["verified_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            validated_count += 1
            if result.status == "active":
                active_count += 1
                # Active credential found in a JIRA ticket / Slack
                # message / S3 object → upgrade severity. Same rule
                # the git path uses: a verified-active key beats any
                # detector confidence calibration.
                if (pf.severity or "").lower() in ("medium", "low"):
                    pf.severity = "critical"
                # Blast-radius mapping for actives — non-fatal if it
                # times out; we still keep the validation result.
                try:
                    blast = await asyncio.wait_for(_analyze_blast_radius(verify_sm), timeout=10.0)
                    if blast:
                        rd["blast_radius"] = {
                            "provider": blast.provider,
                            "identity": blast.identity,
                            "impact_score": blast.impact_score,
                            "impact_level": blast.impact_level,
                            "resources": [
                                {"type": r.resource_type, "name": r.name,
                                 "access": r.access_level, "risk": r.risk}
                                for r in (blast.resources or [])
                            ],
                            "summary": blast.summary,
                            "can_write": blast.can_write,
                            "can_admin": blast.can_admin,
                        }
                except (asyncio.TimeoutError, Exception) as br_err:
                    logger.warning(
                        "source_blast_radius_failed",
                        provider=provider, error=str(br_err)[:160],
                    )
            return True

        # ── Preflight: test_connection ──
        # extract_content() is permissive about per-page failures by
        # design (one bad page shouldn't kill the scan), so an auth
        # bounce silently returns 0 items. Running test_connection
        # first lets us distinguish "scanned, found nothing" from
        # "couldn't auth" and stamp the failure-pill stats accordingly.
        try:
            preflight = await adapter.test_connection()
            if (preflight or {}).get("status") != "success":
                err = (preflight or {}).get("message") or "Connection test failed"
                raise RuntimeError(f"Preflight: {err}")
        except Exception as pre:
            logger.warning("source_scan_preflight_failed", source=source.name, error=str(pre)[:200])
            job.status = ScanStatus.FAILED
            job.error_detail = str(pre)[:500]
            job.progress_pct = 0
            # Stamp BOTH the column (so the source card sorts by
            # freshness and "Never scanned" never lies) and the stats
            # JSONB (so the UI sees the failure status + message
            # without cracking the scan_jobs table). Bug fix 2026-05-08:
            # before, preflight failures only logged a warning,
            # leaving the source card showing "Never scanned"
            # indefinitely.
            now = datetime.now(timezone.utc)
            try:
                source.last_scan_at = now
                source.stats = {
                    **(source.stats or {}),
                    "last_scan_status": "failed",
                    "last_error": str(pre)[:200],
                    "last_scan_at": now.isoformat(),
                }
            except Exception:
                pass
            await db.commit()
            await _release_lock()
            return

        # ── Iterate the source, scan each chunk of text ──
        try:
            # ``sync_state_for_adapter`` is the per-source watermark
            # for incremental scans, or {} when force_full_sweep is
            # on (full re-walk; tombstone pass after the loop).
            async for item in adapter.extract_content(sync_state_for_adapter):
                items_scanned += 1
                # Use the locator as a synthetic file path so the scan
                # engine's filename / extension heuristics still work
                # (they're a no-op for "slack://" but harmless).
                synthetic_path = item.source_locator or f"{source.source_type}://item/{items_scanned}"
                # Record locator BEFORE scanning so an item that
                # produced no findings (because rules didn't match)
                # is still counted as "seen this sweep" — otherwise
                # the tombstone pass would erroneously close findings
                # for items the source still has but no longer flags.
                seen_locators.add(synthetic_path)
                try:
                    # Pass the adapter's content_type ("message" /
                    # "page" / "comment" / "file" / …) so any rule
                    # with confidence_by_context overrides scores
                    # this content with the right base confidence.
                    # Backward compat: if the rule has no override,
                    # the scanner falls back to the default value.
                    raw = scanner.scan_file(
                        synthetic_path,
                        item.content or "",
                        content_type=item.content_type,
                    )
                except Exception as scan_err:
                    logger.warning("source_scan_item_failed", locator=synthetic_path[:120], error=str(scan_err)[:200])
                    continue

                for pf in raw:
                    # ── Idempotent-ingest stability ID ──
                    # Formula: sha256(synthetic_path|line_start|secret_hash)
                    # — same shape as the repo-scan path uses
                    # (secret_hash + file_path, with line_start added so
                    # the same credential at two different lines on the
                    # same page produces two separate cleanup records).
                    #
                    # Crucially: rule_id is NOT in the hash.  If a
                    # re-scan reclassifies the same secret with a more
                    # specific rule (e.g. the original high-entropy hit
                    # later detected as "Atlassian API Token" once the
                    # vendor-specific regex landed), the sid stays
                    # identical and the existing record is updated
                    # in-place — no duplicate row created.
                    secret_hash_val = (pf.raw_data or {}).get("secret_hash") or ""
                    masked_val = secret_hash_val or (pf.raw_data or {}).get("masked_value", "")
                    sid = hashlib.sha256(
                        f"{synthetic_path}|{pf.line_start or ''}|{masked_val}".encode()
                    ).hexdigest()[:20]
                    if sid in seen_stability:
                        continue
                    seen_stability.add(sid)

                    # Live validation. Run BEFORE we strip the raw
                    # value out of pf.raw_data (which the dict spread
                    # below would otherwise hand off to the
                    # NormalizedFinding source_metadata, where it
                    # would get persisted — a security regression).
                    try:
                        await _validate_pf(pf)
                    except Exception as ve:
                        logger.warning("source_validation_step_failed", error=str(ve)[:200])

                    # Strip the raw value before persistence — exact
                    # parity with the git path. Validation result
                    # (status, details, blast radius) was already
                    # captured inside _validate_pf.
                    raw_data_persisted = dict(pf.raw_data or {})
                    raw_data_persisted.pop("_raw_value_for_verification", None)
                    raw_data_persisted.pop("_source_b64_token", None)
                    # If validation didn't run / wasn't supported,
                    # mark explicitly so the UI can surface it.
                    raw_data_persisted.setdefault("validation_status", "not_validated")

                    # ── Redact the raw secret in pf.code_snippet ──
                    # Industry-standard mask-at-write so the line
                    # context never persists with the raw value.
                    # Mirrors the git-scan path.  The raw value is still
                    # available in `pf.raw_data` until the pop above, so
                    # we use the local copy before stripping.
                    from services.secret_scan.engine import redact_snippet_for_storage
                    _src_raw = ((pf.raw_data or {}).get("_source_b64_token")
                                or (pf.raw_data or {}).get("_raw_value_for_verification") or "")
                    _src_masked = (pf.raw_data or {}).get("masked_value") or ""
                    _src_paired = (pf.raw_data or {}).get("paired_raw") or ""
                    _src_paired_masked = (pf.raw_data or {}).get("paired_masked") or ""
                    # Same shared store-time redactor the git-scan path uses —
                    # masks own value + paired credential + co-located residual
                    # secrets (G1) through one tested code path (no drift).
                    pf.code_snippet = redact_snippet_for_storage(
                        pf.code_snippet, _src_raw, _src_masked,
                        _src_paired, _src_paired_masked, scanner=scanner)

                    # ── Cross-scan dedup lookup ──
                    # Check whether this (source, file_path, line, hash)
                    # already has a finding from a prior scan.  Lookup
                    # is by NATURAL KEY (not stability_id) so legacy
                    # records that were written with the old stability
                    # formula are still matched and updated rather than
                    # treated as misses.
                    existing_q = await db.execute(
                        select(NormalizedFinding).where(
                            NormalizedFinding.scan_source_id == source.id,
                            NormalizedFinding.file_path == synthetic_path[:1024],
                            NormalizedFinding.line_start == pf.line_start,
                            # secret_hash lives inside source_metadata
                            # (JSONB); ``.astext`` does a text comparison
                            # without forcing a column cast.
                            NormalizedFinding.source_metadata["secret_hash"].astext == secret_hash_val,
                        ).limit(1)
                    )
                    existing_f = existing_q.scalar_one_or_none() if secret_hash_val else None

                    if existing_f is not None:
                        # ── UPDATE existing finding (idempotent re-scan) ──
                        # Refresh scan-time metadata so the latest
                        # classification, severity, and rule label win.
                        # Preserve: id, created_at, classification,
                        # review_status, remediation_status, tags,
                        # assigned_to — anything the user has triaged.
                        existing_f.scanner_rule_id = pf.rule_id
                        existing_f.title = (pf.title or "Hardcoded secret in source")[:500]
                        existing_f.description = pf.description
                        existing_f.vulnerability_category = (pf.category or "Hardcoded Secret")[:255]
                        existing_f.cwe = pf.cwe
                        existing_f.severity = _normalize_severity(pf.severity)
                        # Link to the SecretIncident for this credential
                        # (find-or-create).  Idempotent within the scan
                        # via incident_cache.  Existing rows that were
                        # backfilled already have incident_id set; this
                        # also refreshes display fields on the incident.
                        existing_f.incident_id = await _upsert_incident_for(secret_hash_val, pf, now)
                        existing_f.code_snippet = pf.code_snippet
                        existing_f.confidence = pf.confidence
                        existing_f.stability_id = sid  # backfill new sid format
                        existing_f.last_seen_at = now
                        existing_f.last_seen_scan_job_id = job.id
                        existing_f.scan_count = (existing_f.scan_count or 1) + 1
                        # Merge source_metadata — refresh scan-time
                        # fields while preserving anything the prior
                        # scan or user attached (e.g. verification
                        # results, manual notes).
                        existing_f.source_metadata = {
                            **(existing_f.source_metadata or {}),
                            **raw_data_persisted,
                            "source_type": source.source_type,
                            "source_name": source.name,
                            "source_locator": item.source_locator,
                            "deep_link_url": item.deep_link_url,
                            "content_type": item.content_type,
                            "author": item.author,
                            "metadata": item.metadata,
                        }
                        findings_total += 1
                        findings_by_surface[_surface_for(synthetic_path, item.content_type)] += 1
                        continue

                    # ── Rule-override gate (source-scan path) ────────
                    # Source-scan storage keeps the raw VOODA-SEC-* form
                    # in scanner_rule_id (unlike repo scans which strip).
                    # The override lookup must compare against the SAME
                    # stripped form used by the repo path, so admins get
                    # one mental model of "what rule id do I mute".
                    _branded_pf_rule_id = (
                        _brand_rule_id(pf.rule_id) if pf.rule_id else pf.rule_id
                    )
                    if _branded_pf_rule_id and _branded_pf_rule_id in src_muted_rule_ids:
                        src_block_counts[_branded_pf_rule_id] += 1
                        # Mark sid as seen so any future stale-cleanup pass
                        # on source scans (none today, but mirror the repo
                        # path) doesn't auto-resolve historical findings
                        # for this rule + location.
                        seen_stability.add(sid)
                        continue

                    # ── INSERT new finding (first time we've seen this
                    # (source, location, secret) tuple) ──
                    # Upsert the incident first so we have the FK to
                    # set on the finding below.  Returns None when no
                    # secret_hash is available (rare for source scans
                    # but handled — finding will carry NULL incident_id
                    # and behave as before).
                    incident_uuid = await _upsert_incident_for(secret_hash_val, pf, now)
                    finding = NormalizedFinding(
                        scan_job_id=job.id,
                        # repository_id inherited from the job (set at
                        # dispatch time from source.target_repository_id)
                        repository_id=job.repository_id,
                        scan_source_id=source.id,
                        tenant_id=job.tenant_id,
                        scanner_name="vooda_engine",
                        scanner_rule_id=pf.rule_id,
                        title=(pf.title or "Hardcoded secret in source")[:500],
                        description=pf.description,
                        vulnerability_category=(pf.category or "Hardcoded Secret")[:255],
                        cwe=pf.cwe,
                        # Pull severity AFTER validation may have
                        # escalated medium/low → critical for
                        # verified-active credentials.
                        severity=_normalize_severity(pf.severity),
                        file_path=synthetic_path[:1024],
                        line_start=pf.line_start,
                        code_snippet=pf.code_snippet,
                        confidence=pf.confidence,
                        classification=Classification.NEEDS_REVIEW,
                        stability_id=sid,
                        incident_id=incident_uuid,
                        first_seen_at=now,
                        last_seen_at=now,
                        last_seen_scan_job_id=job.id,
                        scan_count=1,
                        source_metadata={
                            **raw_data_persisted,
                            "source_type": source.source_type,
                            "source_name": source.name,
                            "source_locator": item.source_locator,
                            "deep_link_url": item.deep_link_url,
                            "content_type": item.content_type,
                            "author": item.author,
                            "metadata": item.metadata,
                        },
                    )
                    db.add(finding)
                    findings_total += 1
                    findings_by_surface[_surface_for(synthetic_path, item.content_type)] += 1

                # Periodic flush so progress survives a crash and the UI
                # can show partial results on big sources.
                if items_scanned % 50 == 0:
                    job.progress_pct = min(90, 10 + items_scanned // 10)
                    await db.commit()

            # ── Refresh occurrence_count on touched incidents ──
            # The in-loop _upsert_incident_for sets occurrence_count=1
            # for new incidents but doesn't increment on updates (to
            # avoid double-counting on re-scan, since the same finding
            # being updated isn't a new occurrence).  Authoritative
            # value comes from COUNT(*) on the linked findings — run
            # that once per scan for the set of incidents we touched.
            if incident_cache:
                from sqlalchemy import update as sa_update, select as _sa_select, func as _sa_func
                inc_ids = list(incident_cache.values())
                counts = await db.execute(
                    _sa_select(
                        NormalizedFinding.incident_id,
                        _sa_func.count(NormalizedFinding.id),
                    )
                    .where(NormalizedFinding.incident_id.in_(inc_ids))
                    .group_by(NormalizedFinding.incident_id)
                )
                for inc_id, ct in counts.all():
                    await db.execute(
                        sa_update(SecretIncident)
                        .where(SecretIncident.id == inc_id)
                        .values(occurrence_count=ct)
                    )

            # ── Persist sync state + stats ──
            # Stats now also carry per-scan status + last error so the
            # FE can show "Last scan failed" / "X findings · 8 desc / 3
            # comments / 1 attachment" on the connected-source card
            # without an extra round-trip to /scan-jobs. JSONB → no
            # migration needed; everything is opportunistic keys.
            try:
                source.sync_state = adapter.get_updated_sync_state()
            except Exception:
                # Adapter may not implement it — non-fatal.
                pass
            source.last_scan_at = now

            # ── Tombstone pass (full sweep only) ────────────────
            # Items present in the DB as open findings but NOT seen
            # in this sweep have been deleted from the source.
            # Resolve them with classification = RESOLVED_ITEM_DELETED
            # so dashboards / SLA metrics drop them, while preserving
            # the audit trail in source_metadata (when, by which scan,
            # at which sweep cycle).
            #
            # Gated on force_full_sweep: incremental scans by design
            # only see CHANGED items, so an incremental's seen_locators
            # set would mis-tombstone every unchanged finding.
            #
            # Only touches OPEN classifications — won't overwrite a
            # user's manual ACCEPTED_RISK / CONFIRMED_FALSE_POSITIVE
            # decision, same rule as the repo-side tombstone pass.
            tombstoned_count = 0
            if force_full_sweep:
                try:
                    import json as _json
                    from datetime import datetime as _dt, timezone as _tz
                    meta_patch = {
                        "resolved_by_scan_job_id": str(job.id),
                        "resolved_by_sweep": True,
                        "resolved_at": _dt.now(_tz.utc).isoformat(),
                        "resolution_reason": "item_deleted",
                    }
                    # ``locators_seen`` arrives as a JSON array bound
                    # to a JSONB param — same trick as the repo-side
                    # tombstone (avoids asyncpg's
                    # IndeterminateDatatypeError on ``ANY(text[])``
                    # bindings through CAST).
                    update_result = await db.execute(
                        text(
                            """
                            UPDATE normalized_findings
                               SET classification  = 'RESOLVED_ITEM_DELETED',
                                   updated_at      = now(),
                                   source_metadata = COALESCE(source_metadata, '{}'::jsonb)
                                                     || CAST(:meta_patch AS jsonb)
                             WHERE scan_source_id = :sid
                               AND tenant_id      = :tid
                               AND classification::text IN
                                   ('NEEDS_REVIEW','LIKELY_TRUE_POSITIVE','LIKELY_FALSE_POSITIVE',
                                    'needs_review','likely_true_positive','likely_false_positive')
                               AND COALESCE(source_metadata->>'source_locator', file_path) NOT IN (
                                   SELECT jsonb_array_elements_text(CAST(:locators_seen AS jsonb))
                               )
                            """
                        ),
                        {
                            "sid": source.id,
                            "tid": job.tenant_id,
                            "meta_patch": _json.dumps(meta_patch),
                            "locators_seen": _json.dumps(sorted(seen_locators)),
                        },
                    )
                    tombstoned_count = update_result.rowcount or 0
                    if tombstoned_count > 0:
                        logger.info(
                            "source_sweep_tombstones_applied",
                            scan_job_id=str(job.id),
                            source_id=str(source.id),
                            source_type=source.source_type,
                            items_seen=len(seen_locators),
                            findings_resolved=tombstoned_count,
                        )
                    # Stamp the sweep timestamp so the weekly Beat
                    # task knows this source is fresh.
                    source.last_full_sweep_at = now
                except Exception as te:
                    logger.warning(
                        "source_sweep_tombstone_failed",
                        scan_job_id=str(job.id),
                        source_id=str(source.id),
                        error=str(te)[:200],
                    )

            # ── Persist rule-override block counts (source path) ──
            # Mirror the repo-scan post-loop write-back: aggregate the
            # per-rule block tallies into one UPDATE per rule_id so the
            # admin's "blocked N findings" stat stays accurate.
            await _record_src_blocks(
                db, job.tenant_id, src_block_counts, scan_source_id=source.id,
            )

            # findings_count = distinct findings (by stability_id)
            # ever seen on this source. Each scan creates new
            # NormalizedFinding rows, so naive COUNT(*) inflates the
            # number on repeat scans of the same content. Counting
            # distinct stability_ids matches the dedup vocabulary the
            # rest of the platform uses (NormalizedFinding.stability_id
            # is the cross-scan identity key).
            from sqlalchemy import func as sa_func
            cum_result = await db.execute(
                select(sa_func.count(sa_func.distinct(NormalizedFinding.stability_id))).where(
                    NormalizedFinding.scan_source_id == source.id,
                    NormalizedFinding.stability_id.isnot(None),
                )
            )
            cumulative_findings = int(cum_result.scalar() or 0)

            source.stats = {
                **(source.stats or {}),
                "last_items_scanned": items_scanned,
                "last_findings_count": findings_total,
                "last_findings_by_surface": findings_by_surface,
                "findings_count": cumulative_findings,
                "last_scan_status": "success",
                "last_error": None,
                "last_scan_at": now.isoformat(),
            }

            job.status = ScanStatus.COMPLETED
            job.progress_pct = 100
            job.stats = {
                "items_scanned": items_scanned,
                "findings_total": findings_total,
                "findings_by_surface": findings_by_surface,
                "validated": validated_count,
                "active_credentials": active_count,
                "source_type": source.source_type,
                "scoped_repository_id": str(job.repository_id) if job.repository_id else None,
                # Sweep telemetry — surfaced for dashboards and SLA
                # reporting. ``force_full`` distinguishes a manual /
                # weekly sweep from a normal incremental scan;
                # ``findings_tombstoned`` shows how many items were
                # closed because the source no longer contains them.
                "force_full": force_full_sweep,
                "findings_tombstoned": tombstoned_count,
            }
            await db.commit()
            logger.info(
                "source_scan_complete",
                scan_job_id=str(job.id), source=source.name,
                items=items_scanned, findings=findings_total,
                by_surface=findings_by_surface,
                validated=validated_count, active=active_count,
                force_full=force_full_sweep,
                tombstoned=tombstoned_count,
            )

            # ── Hand off to triage if AI is configured ──
            # Reuses the same normalize_and_triage pipeline as git scans
            # so source findings get classified the same way (true
            # positive / false positive / needs review).
            if findings_total > 0:
                try:
                    has_ai_env = bool(settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY)
                    has_ai_db = False
                    if not has_ai_env:
                        try:
                            from apps.api.app.models.ai_model import AIModelConfig
                            ai_r = await db.execute(
                                select(AIModelConfig).where(
                                    AIModelConfig.tenant_id == job.tenant_id,
                                    AIModelConfig.is_active == True,
                                ).limit(1)
                            )
                            has_ai_db = ai_r.scalar_one_or_none() is not None
                        except Exception:
                            pass
                    if has_ai_env or has_ai_db:
                        from apps.worker.tasks import normalize_and_triage as _nt
                        _nt.delay(str(job.id))
                except Exception as triage_err:
                    logger.warning("source_scan_triage_dispatch_failed", error=str(triage_err)[:200])

        except Exception as e:
            logger.exception("source_scan_failed", error=str(e)[:300])
            job.status = ScanStatus.FAILED
            job.error_detail = str(e)[:500]
            job.progress_pct = 0
            # Mirror the success path's stamping so the FE has one
            # consistent place to read "what happened on the last
            # scan?" regardless of outcome — column update + stats
            # JSONB. Bug fix 2026-05-08: column was previously only
            # written on success, so "Never scanned" lingered after
            # any failure.
            now = datetime.now(timezone.utc)
            try:
                source.last_scan_at = now
                source.stats = {
                    **(source.stats or {}),
                    "last_scan_status": "failed",
                    "last_error": str(e)[:200],
                    "last_scan_at": now.isoformat(),
                }
            except Exception:
                # Stats stamping is best-effort. The job error_detail
                # is the source of truth for forensic reads.
                pass
            await db.commit()
        finally:
            # Always release the source lock, regardless of outcome.
            # CAS-on-release in the lock helper means we never delete
            # someone else's lock if our TTL had already expired.
            await _release_lock()


@celery_app.task(bind=True, max_retries=2)
def run_webhook_scan(self, provider: str, event_type: str, repo_url: str, repo_name: str,
                     branch: str = None, base_sha: str = None, head_sha: str = None,
                     author: str = None, pr_number: int = None, pr_title: str = None):
    """Execute an incremental scan triggered by a webhook event."""
    logger.info("webhook_scan_started", provider=provider, event_type=event_type,
                repo=repo_name, base=base_sha[:8] if base_sha else "?", head=head_sha[:8] if head_sha else "?")
    run_async(_run_webhook_scan(
        provider=provider, event_type=event_type, repo_url=repo_url, repo_name=repo_name,
        branch=branch, base_sha=base_sha, head_sha=head_sha,
        author=author, pr_number=pr_number, pr_title=pr_title,
    ))


async def _run_webhook_scan(provider: str, event_type: str, repo_url: str, repo_name: str,
                            branch: str = None, base_sha: str = None, head_sha: str = None,
                            author: str = None, pr_number: int = None, pr_title: str = None):
    """Async implementation of incremental webhook scan."""
    import apps.api.app.models  # noqa: F401
    from apps.api.app.models.scan import ScanJob, ScanStatus, ScanType
    from apps.api.app.models.repository import Repository
    from apps.api.app.models.finding import NormalizedFinding, Severity, Classification, SecretIncident
    from services.secret_scan.engine import SecretScanner, scan_diff
    from services.normalization.normalizer import normalize_severity
    from packages.common.scanner_branding import brand_rule_id
    import hashlib
    from datetime import datetime, timezone
    import uuid as uuid_mod

    async with await _get_db_session() as db:
        try:
            # Match by URL, robustly. A provider sends the clone URL as
            # e.g. "https://github.com/owner/repo.git", while the stored
            # URL is canonicalised to "https://github.com/owner/repo"
            # (no .git, no trailing slash). An exact `==` therefore
            # missed on nearly every real event and fell through to a
            # fuzzy name match below. Compare the normalised forms and
            # their obvious variants instead.
            from packages.common.git_url import url_match_candidates

            url_candidates = url_match_candidates(repo_url)
            result = await db.execute(
                select(Repository).where(Repository.url.in_(url_candidates))
            )
            matches = result.scalars().all()
            # Only act on an unambiguous match. If two repos share the
            # URL (possible across tenants), scanning a guessed one would
            # be wrong — skip rather than pick.
            repo = matches[0] if len(matches) == 1 else None

            if not repo and repo_name:
                # Exact name fallback, not a substring match: `ILIKE
                # %name%` could resolve an event for "api" to a repo
                # named "internal-api-gateway", triggering a scan of the
                # wrong project (and, in multi-tenant, another tenant's).
                result = await db.execute(
                    select(Repository).where(Repository.name == repo_name)
                )
                named = result.scalars().all()
                repo = named[0] if len(named) == 1 else None

            if not repo:
                logger.warning(
                    "webhook_repo_not_found",
                    repo_url=repo_url,
                    repo_name=repo_name,
                    url_matches=len(matches),
                )
                return

            # Create scan job
            scan_job = ScanJob(
                id=uuid_mod.uuid4(),
                repository_id=repo.id,
                tenant_id=repo.tenant_id,
                scan_type=ScanType.STANDALONE,
                status=ScanStatus.RUNNING,
                status_message=f"Webhook scan: {event_type} by {author or 'unknown'}",
                config={
                    "trigger": "webhook",
                    "provider": provider,
                    "event_type": event_type,
                    "base_sha": base_sha,
                    "head_sha": head_sha,
                    "author": author,
                    "pr_number": pr_number,
                    "pr_title": pr_title,
                    "incremental": True,
                },
            )
            db.add(scan_job)
            await db.commit()

            # Clone repo (reuse existing clone if available)
            repo_path = f"/app/storage/repos/{repo.id}"
            if not os.path.exists(repo_path):
                repo_path = await _clone_repository(repo.url, str(repo.id), branch)

            # Fetch latest commits
            import subprocess
            subprocess.run(["git", "-C", repo_path, "fetch", "origin"], capture_output=True, timeout=60)
            if head_sha:
                subprocess.run(["git", "-C", repo_path, "checkout", head_sha], capture_output=True, timeout=10)

            # Load custom rules for this tenant
            from services.secret_scan.detectors.registry import get_all_rules_with_custom
            all_rules = await get_all_rules_with_custom(repo.tenant_id, db)
            scanner = SecretScanner(rules=all_rules)

            # Run incremental scan — only changed files
            if base_sha and head_sha:
                raw_findings = scan_diff(repo_path, base_sha, head_sha, scanner=scanner)
                logger.info("incremental_scan_complete", findings=len(raw_findings),
                            base=base_sha[:8], head=head_sha[:8], repo=repo_name)
            else:
                # Fallback to full scan if no sha range (first webhook for
                # this repo, or a force-push that broke the diff range).
                # Gap #3b: a large-repo full scan here is a single blocking
                # call — run it in a thread and stamp heartbeat_at every N
                # files so the stale-scan watchdog can't false-reap a
                # healthy scan (this scan_job is a RUNNING, watchdog-tracked
                # row). Separate session for the stamp: the main txn
                # committed the scan_job above and only reads until here,
                # so the UPDATE never contends its row lock. timezone.utc
                # (instance) — the bare `timezone` class raises and silently
                # kills the heartbeat (the bug fixed in c2d873d).
                import asyncio as _aio_wh
                from sqlalchemy import update as _upd_wh
                _wh_loop = _aio_wh.get_running_loop()
                _wh_sid = scan_job.id
                _wh_last = {"t": 0.0}

                async def _wh_heartbeat(files_done: int):
                    try:
                        async with await _get_db_session() as _db_wh:
                            await _db_wh.execute(
                                _upd_wh(ScanJob).where(ScanJob.id == _wh_sid).values(
                                    heartbeat_at=datetime.now(timezone.utc),
                                    status_message=f"Full scan — {files_done:,} files scanned...",
                                )
                            )
                            await _db_wh.commit()
                    except Exception:
                        pass

                def _wh_on_progress(files_done: int, findings_so_far: int):
                    import time as _t_wh
                    _now = _t_wh.monotonic()
                    if _now - _wh_last["t"] < 5.0:
                        return
                    _wh_last["t"] = _now
                    try:
                        _aio_wh.run_coroutine_threadsafe(_wh_heartbeat(files_done), _wh_loop)
                    except Exception:
                        pass

                raw_findings = await _scan_with_cpu_budget(
                    scanner, repo_path, _wh_sid,
                    progress_callback=_wh_on_progress,
                    progress_every_n_files=200,
                )
                logger.info("full_scan_fallback", findings=len(raw_findings), repo=repo_name)

            # Store findings (same dedup logic as regular scan)
            now = datetime.now(timezone.utc)
            created_count = 0

            # Load existing findings for dedup
            existing_r = await db.execute(
                select(NormalizedFinding).where(
                    NormalizedFinding.repository_id == repo.id,
                    NormalizedFinding.tenant_id == repo.tenant_id,
                    NormalizedFinding.stability_id.isnot(None),
                )
            )
            existing_by_sid = {f.stability_id: f for f in existing_r.scalars().all()}

            # ── Rule-override pre-gate (webhook-scan variant) ─────────
            # Same as the main scan path: preload muted rule_ids once,
            # check per-finding in O(1) in the CREATE branch, write back
            # aggregated block counts after the loop.  Identical contract
            # so the two paths can never diverge in behaviour.
            from apps.worker.rule_overrides import (
                load_active_rule_ids as _load_wh_overrides,
                new_block_counter as _new_wh_block_counter,
                record_blocks as _record_wh_blocks,
            )
            wh_muted_rule_ids: set[str] = await _load_wh_overrides(
                db, repo.tenant_id, repo.id,
            )
            wh_block_counts = _new_wh_block_counter()

            # ── Incident upsert helper (webhook-scan variant) ──
            # Mirrors the main path's `_upsert_incident_for_repo` so
            # webhook-triggered scans correctly link findings to the
            # SecretIncident dedup row.  Without this, webhook findings
            # land with `incident_id=NULL` and don't roll up into the
            # tenant's incident view, dashboard, or rotation tracking.
            incident_cache: dict[str, "uuid_mod.UUID"] = {}

            async def _upsert_incident_for_webhook(sh: str, pf, now_ts):
                """Find-or-create the SecretIncident for `sh` (webhook path).

                Thin wrapper over the shared, concurrency-safe
                :func:`_upsert_secret_incident` (atomic ON CONFLICT
                upsert).  Webhook scans carry ``repo`` directly, so the
                tenant comes from ``repo.tenant_id``.
                """
                return await _upsert_secret_incident(
                    db,
                    tenant_id=repo.tenant_id,
                    secret_hash=sh,
                    pf=pf,
                    now_ts=now_ts,
                    default_title="Hardcoded secret",
                    severity_normalizer=normalize_severity,
                    incident_cache=incident_cache,
                )

            # Same scrub-at-write helper as main + source paths.
            from services.secret_scan.engine import _redact_in_snippet, redact_with_scanner

            for pf in raw_findings:
                secret_hash = (pf.raw_data or {}).get("secret_hash", "")
                file_path = pf.file_path or ""
                if secret_hash:
                    sid = hashlib.sha256(f"{secret_hash}|{file_path}".encode()).hexdigest()[:20]
                else:
                    sid = hashlib.sha256(f"{pf.rule_id or ''}|{file_path}|{pf.line_start or ''}".encode()).hexdigest()[:20]

                # ── Redact pf.code_snippet before any path persists it ──
                _wh_raw = (pf.raw_data or {}).get("_raw_value_for_verification") or ""
                _wh_masked = (pf.raw_data or {}).get("masked_value") or ""
                if _wh_raw and pf.code_snippet:
                    pf.code_snippet = _redact_in_snippet(pf.code_snippet, _wh_raw, _wh_masked)
                _wh_paired = (pf.raw_data or {}).get("paired_raw") or ""
                _wh_paired_masked = (pf.raw_data or {}).get("paired_masked") or ""
                if _wh_paired and pf.code_snippet:
                    pf.code_snippet = _redact_in_snippet(pf.code_snippet, _wh_paired, _wh_paired_masked)
                # Belt-and-suspenders pass — see main scan path for rationale.
                if pf.code_snippet:
                    pf.code_snippet = redact_with_scanner(pf.code_snippet, scanner)

                existing = existing_by_sid.get(sid)
                if existing:
                    existing.last_seen_at = now
                    existing.scan_count = (existing.scan_count or 1) + 1
                    existing.last_seen_scan_job_id = scan_job.id
                    # Late-link to incident if the previous record landed
                    # without one (existing rows from before the webhook
                    # incident-wiring fix).  Cheap: same hash lookup.
                    if existing.incident_id is None and secret_hash:
                        existing.incident_id = await _upsert_incident_for_webhook(secret_hash, pf, now)
                    elif secret_hash:
                        # Touch the incident's last_seen_at via the same
                        # helper so dashboard stats stay current.
                        await _upsert_incident_for_webhook(secret_hash, pf, now)
                    continue

                branded = brand_rule_id(pf.rule_id) if pf.rule_id else pf.rule_id

                # ── Rule-override gate (webhook path) ────────────────
                # Same contract as the main path: only short-circuit the
                # CREATE branch (the UPDATE branch above already
                # `continue`d), tally the block count for write-back.
                if branded and branded in wh_muted_rule_ids:
                    wh_block_counts[branded] += 1
                    continue

                # Upsert incident BEFORE inserting the finding so we have
                # the FK ready and don't need a follow-up UPDATE.
                incident_uuid = await _upsert_incident_for_webhook(secret_hash, pf, now) if secret_hash else None
                finding = NormalizedFinding(
                    scan_job_id=scan_job.id,
                    repository_id=repo.id,
                    tenant_id=repo.tenant_id,
                    scanner_name="vooda_engine",
                    scanner_rule_id=branded,
                    title=(pf.title or "Untitled")[:500],
                    description=pf.description,
                    vulnerability_category=(pf.category or "Hardcoded Secret")[:255],
                    cwe=pf.cwe,
                    severity=normalize_severity(pf.severity),
                    file_path=file_path,
                    line_start=pf.line_start,
                    code_snippet=pf.code_snippet,
                    confidence=pf.confidence,
                    classification=Classification.NEEDS_REVIEW,
                    stability_id=sid,
                    incident_id=incident_uuid,
                    first_seen_at=now,
                    last_seen_at=now,
                    last_seen_scan_job_id=scan_job.id,
                    scan_count=1,
                    source_metadata={
                        **(pf.raw_data or {}),
                        "webhook_provider": provider,
                        "webhook_event": event_type,
                        "commit_author": author,
                    },
                )
                db.add(finding)
                created_count += 1

            # ── Refresh occurrence_count on touched incidents ──
            # Same post-scan stat refresh as the main + source paths.
            # COUNT(*) is authoritative; in-loop increments would
            # double-count when an existing finding is "touched" and a
            # new one is inserted in the same scan.
            if incident_cache:
                from sqlalchemy import update as sa_update, func as sa_func
                inc_ids = list(incident_cache.values())
                counts = await db.execute(
                    select(
                        NormalizedFinding.incident_id,
                        sa_func.count(NormalizedFinding.id),
                    )
                    .where(NormalizedFinding.incident_id.in_(inc_ids))
                    .group_by(NormalizedFinding.incident_id)
                )
                for inc_id, ct in counts.all():
                    await db.execute(
                        sa_update(SecretIncident)
                        .where(SecretIncident.id == inc_id)
                        .values(occurrence_count=ct)
                    )

            # Update scan job
            scan_job.status = ScanStatus.COMPLETED
            scan_job.progress_pct = 100
            scan_job.stats = {
                "files_analyzed": len(raw_findings),
                "findings_total": created_count,
                "incremental": True,
                "base_sha": base_sha,
                "head_sha": head_sha,
            }
            # Advance both the per-branch checkpoint AND the legacy
            # single-checkpoint column. The webhook payload's
            # ``branch`` is the authoritative branch name for this
            # scan; without per-branch tracking, a feature-branch push
            # would overwrite ``main``'s checkpoint and the next manual
            # main scan would walk a wrong, cross-branch diff.
            if head_sha:
                wh_branch = branch or repo.default_branch or "main"
                try:
                    await db.execute(
                        text(
                            """
                            INSERT INTO repo_branch_checkpoints (
                                tenant_id, repository_id, branch,
                                last_scanned_commit, last_scanned_at
                            ) VALUES (
                                :tid, :rid, :br, :sha, now()
                            )
                            ON CONFLICT (repository_id, branch)
                            DO UPDATE SET
                                last_scanned_commit = EXCLUDED.last_scanned_commit,
                                last_scanned_at     = EXCLUDED.last_scanned_at,
                                updated_at          = now()
                            """
                        ),
                        {
                            "tid": repo.tenant_id,
                            "rid": repo.id,
                            "br": wh_branch,
                            "sha": head_sha,
                        },
                    )
                except Exception as _wcw:
                    logger.warning(
                        "webhook_branch_checkpoint_write_failed",
                        repo=repo_name,
                        branch=wh_branch,
                        error=str(_wcw)[:200],
                    )
                # Legacy column — only update if scanning the default
                # branch, so a feature-branch webhook doesn't corrupt
                # the main-branch watermark.
                if wh_branch == (repo.default_branch or "main"):
                    repo.last_scanned_commit = head_sha

            # ── Persist rule-override block counts (webhook path) ───
            # Mirrors the main-path post-loop write-back.  Safe to call
            # before the commit because record_blocks() is itself
            # transaction-aware and only issues UPDATEs.
            await _record_wh_blocks(db, repo.tenant_id, wh_block_counts, repository_id=repo.id)

            await db.commit()

            logger.info("webhook_scan_complete", repo=repo_name, created=created_count,
                        event_type=event_type, provider=provider)

            # ── Post PR comment with findings ──
            if pr_number and created_count > 0:
                try:
                    from services.git_integration.pr_comments import post_pr_comment
                    from apps.api.app.models.integration import IntegrationConfig

                    # Find auth token from integration configs
                    auth_token = ""
                    token_result = await db.execute(
                        select(IntegrationConfig).where(
                            IntegrationConfig.tenant_id == repo.tenant_id,
                            IntegrationConfig.provider == provider,
                            IntegrationConfig.is_active == True,
                        ).limit(1)
                    )
                    token_cfg = token_result.scalar_one_or_none()
                    if token_cfg and token_cfg.config:
                        creds = token_cfg.config
                        auth_token = creds.get("token") or creds.get("personal_access_token") or creds.get("pat") or ""

                    # Build findings list for comment.  Includes
                    # secret_type (used by the rotation-suggestion
                    # block in _format_findings_comment) and
                    # branded_rule_id so the rotation hint can be
                    # looked up by exact rule when secret_type isn't
                    # set (covers the long tail of generic detectors).
                    comment_findings = []
                    for pf in raw_findings[:20]:
                        rd = pf.raw_data or {}
                        comment_findings.append({
                            "title": pf.title,
                            "severity": pf.severity,
                            "file_path": pf.file_path,
                            "line_start": pf.line_start,
                            "masked_value": rd.get("masked_value", "****"),
                            "secret_type": rd.get("secret_type"),
                            "rule_id": brand_rule_id(pf.rule_id) if pf.rule_id else None,
                        })

                    result = await post_pr_comment(
                        provider=provider,
                        repo_url=repo_url,
                        pr_number=pr_number,
                        findings=comment_findings,
                        repo_name=repo_name,
                        scan_job_id=str(scan_job.id),
                        base_sha=base_sha or "",
                        head_sha=head_sha or "",
                        auth_token=auth_token,
                    )
                    logger.info("pr_comment_posted", success=result.success, pr=pr_number,
                                url=result.comment_url, error=result.error)
                except Exception as pr_err:
                    logger.warning("pr_comment_error", error=str(pr_err)[:200])

            # ── Dispatch notification ──
            if created_count > 0:
                try:
                    from apps.worker.tasks import send_notification
                    send_notification.delay(
                        str(scan_job.id), str(repo.tenant_id), str(repo.id),
                        "webhook_scan_complete",
                        f"PR #{pr_number}: {created_count} secret{'s' if created_count != 1 else ''} detected" if pr_number
                        else f"Push scan: {created_count} secret{'s' if created_count != 1 else ''} detected",
                    )
                    logger.info("webhook_notification_dispatched", findings=created_count)
                except Exception as notif_err:
                    logger.warning("webhook_notification_error", error=str(notif_err)[:100])

                # Per-finding ticket fan-out (Jira / ServiceNow / Linear).
                # See _run_scan_job for the rationale — webhook scans
                # need the same dev-team-on-the-board behaviour as
                # standard scans.
                try:
                    dispatch_findings_to_tickets.delay(str(scan_job.id))
                    logger.info("webhook_ticket_fanout_dispatched", findings=created_count)
                except Exception as ticket_err:
                    logger.warning("webhook_ticket_fanout_error", error=str(ticket_err)[:100])

        except Exception as e:
            logger.error("webhook_scan_error", error=str(e)[:200], repo=repo_name)
            try:
                scan_job.status = ScanStatus.FAILED
                scan_job.status_message = str(e)[:500]
                await db.commit()
            except Exception:
                pass


async def _verify_with_cache(verify_sm: dict, tenant_id, secret_hash: str):
    """``verify_finding`` wrapped with the Redis result-cache + per-provider
    rate limiter — the same infra the on-demand re-verify task already uses,
    now applied to the SCAN-TIME verification path (S1).

    * Cache HIT — the same ``secret_hash`` was verified active/inactive within
      the 6h TTL (this scan, a prior scan, or another repo in the tenant):
      returns a ``VerificationResult`` synthesised from cache with NO provider
      call. This is the dedup that stops a scan re-checking the same leaked key
      hundreds of times.
    * MISS — acquires a per-provider rate-limit token (token bucket, fail-open),
      calls ``verify_finding`` under a 5s timeout, then writes active/inactive
      results back to cache for the rest of this (and future) scans to reuse.

    Non-breaking: the cache misses on Redis failure and the limiter fails open,
    so with no Redis this degrades to exactly today's behaviour. The global
    ``VERIFICATION_ENABLED`` kill-switch is honored inside ``verify_finding``.
    """
    import asyncio as _asyncio
    from services.secret_verification.verifier import (
        verify_finding as _vf, VerificationResult as _VR,
    )
    from services.secret_verification.verification_cache import (
        get_cached_verification as _cache_get,
        set_cached_verification as _cache_set,
    )
    from services.secret_verification.rate_limiter import acquire as _rl_acquire

    provider = (verify_sm.get("provider") or "").lower()
    tid = str(tenant_id) if tenant_id else ""

    # 1. Result-cache lookup — reuse a recent active/inactive verdict.
    if secret_hash and tid:
        try:
            cached = await _cache_get(tid, secret_hash)
        except Exception:
            cached = None
        if cached and cached.get("status") in ("active", "inactive"):
            return _VR(
                status=cached["status"],
                details=cached.get("details", "") or "",
                provider=provider,
                permissions=cached.get("permissions"),
                permissions_detail=cached.get("permissions_detail"),
                risk_level=cached.get("risk_level"),
                blast_radius_summary=cached.get("blast_radius_summary"),
            )

    # 2. Per-provider rate limit (fail-open) before any upstream call.
    try:
        await _rl_acquire(provider)
    except Exception:
        pass

    # 3. Verify (5s budget per credential; honors the global kill-switch).
    result = await _asyncio.wait_for(_vf(verify_sm), timeout=5.0)

    # 4. Cache active/inactive verdicts for reuse across findings/scans.
    if result and result.status in ("active", "inactive") and secret_hash and tid:
        try:
            await _cache_set(
                tid, secret_hash,
                status=result.status,
                details=result.details,
                provider=result.provider,
                permissions=result.permissions,
                transient=getattr(result, "transient", False),
                permissions_detail=getattr(result, "permissions_detail", None),
                risk_level=getattr(result, "risk_level", None),
                blast_radius_summary=getattr(result, "blast_radius_summary", None),
            )
        except Exception:
            pass

    return result


async def _verify_batch(verifiable, tenant_id, *, concurrency=8, abs_budget_s=120, blast_fn=None, on_progress=None):
    """Bounded-concurrent credential verification over a list of ParsedFindings (S2).

    Replaces the old 60s SEQUENTIAL verify loop. Each finding is verified
    independently via ``_verify_with_cache`` (cache → per-provider rate limit →
    provider); a semaphore caps concurrent in-flight checks and the per-provider
    token bucket prevents hammering any single provider. An absolute wall-clock
    backstop guarantees the phase can never hang — stragglers are cancelled and
    their findings simply stay not_validated.

    Concurrency-safe by construction: each coroutine mutates ONLY its own
    ParsedFinding (validation_status / verification_* / severity / blast_radius
    in ``raw_data``) and NEVER the caller's AsyncSession or job row — so there is
    no shared-state race. Counters are aggregated after the gather and returned
    as a stats dict. ``blast_fn`` (analyze_blast_radius) is injected so it can be
    stubbed in tests; when None, blast-radius mapping is skipped.

    Concurrency does NOT change a finding's verdict (that comes from the provider
    / cache, not the loop) — it only changes how many findings get verified
    within the budget and how fast.
    """
    import asyncio as _asyncio
    sem = _asyncio.Semaphore(max(1, int(concurrency or 1)))

    async def _one(pf):
        rd = pf.raw_data or {}
        verify_sm = {
            "_raw_value": rd.get("_raw_value_for_verification", ""),
            "provider": (rd.get("provider", "unknown") or "unknown").lower(),
            "detection_method": rd.get("detection_method", ""),
        }
        provider = verify_sm["provider"]
        async with sem:
            try:
                result = await _verify_with_cache(verify_sm, tenant_id, rd.get("secret_hash", ""))
            except (_asyncio.TimeoutError, Exception) as ve:
                logger.warning("inline_verify_error", provider=provider, error=str(ve)[:120])
                return "error"
            if not (result and result.status in ("active", "inactive")):
                return "skipped"
            rd["validation_status"] = result.status
            rd["verification_details"] = result.details
            rd["verification_permissions"] = result.permissions
            if result.status != "active":
                return "inactive"
            # verified-active → escalate severity + (optional) blast radius
            if pf.severity in ("medium", "low"):
                pf.severity = "critical"
            if blast_fn is not None:
                try:
                    blast = await _asyncio.wait_for(blast_fn(verify_sm), timeout=10.0)
                    if blast:
                        rd["blast_radius"] = {
                            "provider": blast.provider,
                            "identity": blast.identity,
                            "impact_score": blast.impact_score,
                            "impact_level": blast.impact_level,
                            "resources": [{"type": r.resource_type, "name": r.name,
                                           "access": r.access_level, "risk": r.risk}
                                          for r in (blast.resources or [])],
                            "summary": blast.summary,
                            "can_write": blast.can_write,
                            "can_admin": blast.can_admin,
                        }
                except (_asyncio.TimeoutError, Exception) as br_err:
                    logger.warning("blast_radius_failed", provider=provider, error=str(br_err)[:200])
            return "active"

    tasks = [_asyncio.create_task(_one(pf)) for pf in verifiable]
    total = len(verifiable)
    # S2 + live bar: iterate in COMPLETION order so on_progress can fire a
    # k/N tick after each credential resolves. as_completed yields from THIS
    # single coroutine (never the concurrent _one workers), and _one touches
    # neither the caller's db session nor job row — so a callback that updates
    # them here is race-free. The absolute wall-clock backstop is preserved:
    # as_completed(timeout=) raises TimeoutError at the deadline, after which
    # we cancel + drain stragglers exactly like the old wait_for(gather) did.
    done = 0
    try:
        for _fut in _asyncio.as_completed(tasks, timeout=max(1, int(abs_budget_s or 120))):
            try:
                await _fut
            except _asyncio.TimeoutError:
                # Budget deadline — as_completed signals it by raising here.
                # MUST propagate to the outer handler to cancel stragglers;
                # asyncio.TimeoutError is an Exception subclass, so it would
                # otherwise be swallowed by the verdict-tolerant except below.
                raise
            except Exception:
                pass  # a single verdict error; read authoritatively from tasks below
            done += 1
            if on_progress is not None:
                try:
                    await on_progress(done, total)
                except Exception:
                    pass  # progress is best-effort; never break verification
    except _asyncio.TimeoutError:
        for t in tasks:
            if not t.done():
                t.cancel()
        # Drain so cancellations settle (avoids "pending task destroyed" noise).
        await _asyncio.gather(*tasks, return_exceptions=True)
        logger.warning("verify_abs_budget_exceeded", budget_s=abs_budget_s, total=total)

    # Authoritative outcome read — from the Task objects (NOT the as_completed
    # futures) so it is identical on the happy path and the timeout path:
    # completed tasks carry their verdict; cancelled stragglers count as error.
    outcomes = []
    for t in tasks:
        # NB: t.result() on a CANCELLED task raises CancelledError, which is
        # a BaseException (not Exception) — so guard on t.cancelled() first.
        if t.cancelled():
            outcomes.append("error")             # cancelled straggler
        else:
            try:
                outcomes.append(t.result())      # completed → its verdict
            except Exception:
                outcomes.append("error")

    norm = [o if isinstance(o, str) else "error" for o in outcomes]
    return {
        "active": norm.count("active"),
        "inactive": norm.count("inactive"),
        "verified": norm.count("active") + norm.count("inactive"),
        "error": norm.count("error"),
        "skipped": norm.count("skipped"),
        "total": len(verifiable),
    }


# ── S3: verified-inactive suppression allowlist ──────────────────────
# Providers whose verifier returns status="inactive" ONLY on a definitive
# rejection (HTTP 401/403, or an explicit revoked / valid=false field) — audited
# against every inactive-return site in verifier.py. A DEAD credential from one
# of these is safe to auto-suppress. Deliberately EXCLUDES ambiguous mappers
# (e.g. azure_devops / servicenow map 404 → inactive, which can mean wrong
# org/endpoint rather than a dead key) and low-volume data APIs whose "inactive"
# leans on a generic error field. Conservative by design — expand as audited.
SUPPRESSION_ALLOWLIST: frozenset = frozenset({
    "github", "gitlab", "slack", "stripe", "sendgrid", "openai", "anthropic",
    "gcp", "datadog", "cloudflare", "npm", "pagerduty", "mailgun", "postmark",
    "digitalocean", "dockerhub", "heroku", "sentry", "newrelic", "hubspot",
    "okta", "auth0", "mailchimp", "figma", "notion", "square", "shopify",
})

# Providers explicitly REFUSED from auto-suppression (ambiguous inactive guard).
SUPPRESSION_DENYLIST: frozenset = frozenset({"azure_devops", "servicenow"})


def _should_suppress_inactive(rd: dict) -> bool:
    """True iff this finding's credential was verified DEAD by an allowlisted
    provider AND global suppression is enabled.

    Suppresses ONLY on validation_status=="inactive" (a definitive provider
    rejection) — never on error / unsupported / unknown / not_validated, and
    never for a provider outside the audited allowlist.
    """
    if not getattr(settings, "VERIFICATION_SUPPRESS_INACTIVE", True):
        return False
    if (rd or {}).get("validation_status") != "inactive":
        return False
    provider = ((rd or {}).get("provider") or "").lower()
    return provider in SUPPRESSION_ALLOWLIST and provider not in SUPPRESSION_DENYLIST


def _is_duplicate_live_execution(status, heartbeat_at, threshold_seconds, now=None):
    """Is another execution of this scan job still alive?

    Returns ``(is_duplicate, heartbeat_age_seconds_or_None)``.

    Every distributed queue delivers AT LEAST once, so a second copy of
    the same task can arrive legitimately: the broker reclaimed a slow
    message, a worker was SIGKILLed and ``task_reject_on_worker_lost``
    requeued it, a container was redeployed, or an operator retried by
    hand. Exactly-once is a fallacy; the standard answer is to make the
    duplicate a no-op while the original is alive.

    Liveness deliberately reuses the stale-scan watchdog's own threshold
    rather than inventing a second definition:

      * job not in a running state  -> not a duplicate (fresh start)
      * no heartbeat recorded yet   -> not a duplicate (never ran; a
                                       redelivery that beat the first
                                       heartbeat should proceed rather
                                       than deadlock the scan forever)
      * heartbeat fresher than the threshold -> DUPLICATE, skip
      * heartbeat older than the threshold   -> original is dead, this
                                       delivery is the legitimate retry
    """
    from apps.api.app.models.scan import ScanStatus as _ScanStatus

    if status not in (_ScanStatus.RUNNING, _ScanStatus.ANALYZING):
        return False, None
    if heartbeat_at is None:
        return False, None
    _now = now or datetime.now(timezone.utc)
    if heartbeat_at.tzinfo is None:
        heartbeat_at = heartbeat_at.replace(tzinfo=timezone.utc)
    age = (_now - heartbeat_at).total_seconds()
    return age < threshold_seconds, round(age)


def _triage_coverage_warning(untriaged_count: int):
    """Completion-banner warning when a scan finished with gaps.

    A scan must not report clean success while findings it was supposed
    to triage carry no AI verdict, so any shortfall is surfaced on the
    completion banner rather than left for the operator to notice.
    """
    if untriaged_count and untriaged_count > 0:
        return (
            f"⚠ {untriaged_count} findings not triaged "
            f"(AI incomplete — re-run AI analysis)"
        )
    return None


async def _run_scan_job(scan_job_id: str):
    from sqlalchemy import func as sa_func
    # Import ALL models to ensure FK metadata is registered before session creation
    import apps.api.app.models  # noqa: F401 — registers all table metadata
    from apps.api.app.models.scan import ScanJob, ScanStatus
    from apps.api.app.models.repository import Repository, RepositorySnapshot
    from apps.api.app.models.finding import NormalizedFinding, FindingEvidence, Severity, Classification, SecretIncident
    from services.repo_analysis.analyzer import analyze_repository, extract_code_context
    from services.secret_scan.engine import SecretScanner
    from services.normalization.normalizer import normalize_severity

    async def _publish(status: str, pct: int, msg: str, stats: dict = None):
        """Publish progress to Redis pub/sub for WebSocket clients."""
        try:
            from services.pubsub.redis_pubsub import publish_scan_progress
            await publish_scan_progress(scan_job_id, status, pct, msg, stats)
        except Exception:
            pass

    # Sprint S / WS-1 — canonical phase denominator.  Written once so
    # the UI never shows the [6/7]→[7/8] drift observed in production
    # (history scans have 8 phases; the value is fixed here regardless
    # of which branch sets the message).
    _TOTAL_PHASES = 8
    # Tracks the highest progress_pct we've emitted so _emit_phase can
    # clamp monotonically — fixes the live-observed 70→65 regression at
    # the RUNNING→ANALYZING boundary.
    _last_pct = {"v": 0}

    async def _emit_phase(
        status: str,
        pct: int,
        msg: str,
        step: int,
        stats: dict = None,
    ):
        """Single source of truth for a phase transition (Sprint S / WS-1).

        Does three things atomically-ish:
          1. Persists an append-only ``scan_phase_events`` row so the
             timeline survives refresh / drawer-reopen / completion.
          2. Updates ``scan_jobs.status_message`` + ``progress_pct``
             (monotonic — never regresses).
          3. Publishes to Redis for live WS clients (existing behaviour).

        WS-6: ``msg`` is redacted via the shared log-stream redactor
        BEFORE it touches Postgres OR Redis — a secret scanner must
        never persist the secrets it finds into its own telemetry.
        """
        from packages.common.logging_config import _redact_string
        from apps.api.app.models.scan import ScanPhaseEvent

        safe_msg = _redact_string(msg or "")
        # Monotonic clamp. Also respect job.progress_pct so an intra-phase
        # climb written directly on the row (P0 live triage counter raises
        # it 70->95 during AI triage) is never regressed by a later
        # coarse phase emit (e.g. the post-triage "FP complete" at 75).
        clamped = max(int(pct), _last_pct["v"], int(getattr(job, "progress_pct", 0) or 0))
        _last_pct["v"] = clamped

        # 2 — update the job row (monotonic pct)
        try:
            job.status_message = safe_msg
            job.progress_pct = clamped
        except Exception:
            pass

        # 1 — persist the append-only event row
        try:
            db.add(ScanPhaseEvent(
                scan_job_id=UUID(scan_job_id),
                step=step,
                total_steps=_TOTAL_PHASES,
                phase_label=safe_msg[:1000],
                status=status,
                progress_pct=clamped,
                stats_snapshot=stats or None,
            ))
            await db.flush()
        except Exception as _pe:
            # Telemetry must never break the scan — log + carry on.
            logger.warning("phase_event_persist_failed",
                           scan_job_id=scan_job_id, error=str(_pe)[:160])

        # 3 — live WS publish (redacted)
        await _publish(status, clamped, safe_msg, stats)

        # Sprint G-2 — a phase transition is real progress. Advance the
        # liveness heartbeat on THIS (main) session so it commits with
        # the phase row the caller writes next. Never a second connection
        # — that self-deadlocks against the scan_jobs row lock the main
        # txn already holds (caught in regression).
        await _stamp_heartbeat_main(job, db, commit=False)

    # Lazy-imported here so the worker module doesn't depend on Redis
    # at import time (some tests stub _run_scan_job out).
    from services.repo_scan.concurrency import repo_scan_lock, LockNotAcquired

    # ── WS-5 — bind scan_job_id into structlog context ───────────────
    # Every worker log line for this scan now carries scan_job_id so a
    # support engineer can `grep <scan_id>` and get the complete trail.
    # CLEAR FIRST so a prior task on this prefork worker that exited via
    # an early return (coalesce / not-found) can't leak its scan_job_id
    # into this task's logs.  Re-cleared in the finally for the common
    # path.  (Early-return paths below rely on this top-of-task clear by
    # the NEXT scan task rather than their own finally — acceptable: the
    # only residue is a non-scan beat task logging a stale id, cosmetic.)
    try:
        from packages.common.logging_config import bind_request_context, clear_request_context
        clear_request_context()
        bind_request_context(scan_job_id=scan_job_id)
    except Exception:
        clear_request_context = None  # type: ignore

    async with await _get_db_session() as db:
        result = await db.execute(select(ScanJob).where(ScanJob.id == UUID(scan_job_id)))
        job = result.scalar_one_or_none()
        if not job:
            logger.error("scan_job_not_found", scan_job_id=scan_job_id)
            return

        # ── Duplicate-execution guard (at-least-once delivery) ───────
        # Every distributed queue delivers AT LEAST once. A second copy
        # of this exact task can legitimately arrive because the broker
        # reclaimed a slow message, a worker was SIGKILLed mid-run and
        # `task_reject_on_worker_lost` requeued it, a container was
        # redeployed, or an operator retried by hand. Chasing
        # exactly-once is a fallacy; the standard answer is to make the
        # second copy a no-op when the first is still alive.
        #
        # Liveness deliberately reuses the SAME definition the stale-scan
        # watchdog uses (`_stale_scan_threshold_seconds`) rather than
        # inventing a second one. If the watchdog would still consider
        # this scan alive, then a second execution of it is a duplicate
        # and must bail; if the heartbeat is stale, the original is dead
        # and this delivery is the legitimate retry that should proceed.
        #
        # The row is left completely untouched on the duplicate path —
        # no status write, no progress reset — so a duplicate delivery
        # can never move progress backwards or overwrite the state the
        # live execution is maintaining.
        _dup, _hb_age = _is_duplicate_live_execution(
            status=job.status,
            heartbeat_at=getattr(job, "heartbeat_at", None),
            threshold_seconds=_stale_scan_threshold_seconds(),
        )
        if _dup:
            logger.warning(
                "scan_job_duplicate_execution_skipped",
                scan_job_id=scan_job_id,
                status=job.status.value,
                heartbeat_age_s=_hb_age,
                detail=(
                    "another execution of this scan job is alive; "
                    "this delivery is a duplicate and was skipped"
                ),
            )
            return

        # Pull repo + branch up FIRST so the concurrency lock can be
        # acquired before any expensive work (clone / analyze / scan).
        # If a duplicate scan is already running for this (repo,
        # branch), we want to coalesce immediately — not after walking
        # 100k files for nothing.
        repo_result = await db.execute(
            select(Repository).where(Repository.id == job.repository_id)
        )
        repo = repo_result.scalar_one_or_none()
        if not repo:
            job.status = ScanStatus.FAILED
            job.error_detail = "Repository not found"
            await db.commit()
            return

        # Branch resolution: webhook scans pass the pushed branch
        # via ``job.config["branch"]``; manual scans default to the
        # repo's default branch. Lock per (repo, branch) so a feature
        # branch push doesn't block ``main``.
        scan_branch = (job.config or {}).get("branch") or repo.default_branch or "main"

        # ── Concurrent-scan dedup ────────────────────────────────────
        # Acquire the per-(repo, branch) advisory lock. If another
        # scan is already in flight, mark this scan_job as CANCELLED
        # with a status_message that names the running scan, and
        # return cleanly. The dispatched Celery task is still
        # accounted for (the row exists in the DB and Beat metrics
        # capture it), it just doesn't redo the work.
        #
        # Why CANCELLED, not FAILED: this isn't an error condition —
        # it's the intended outcome of a push storm or a double-click.
        # The UI surfaces CANCELLED with a friendly message linking
        # to the live scan; FAILED would page the on-call.
        try:
            lock_cm = repo_scan_lock(
                repository_id=str(repo.id),
                branch=scan_branch,
                holder=scan_job_id,
            )
            scan_lock_token = await lock_cm.__aenter__()
        except LockNotAcquired as e:
            holder_msg = f" (running scan: {e.holder})" if e.holder else ""
            job.status = ScanStatus.CANCELLED
            job.progress_pct = 0
            job.status_message = (
                f"Coalesced — another scan is already in progress for "
                f"branch '{scan_branch}'{holder_msg}. The running scan's "
                f"results will appear when it completes."
            )
            # WS-3′ — populate error_detail on the coalesce path.  Before
            # this, coalesced/CANCELLED scans left error_detail empty
            # (confirmed on live scans 2b9a8629 + 6849c2cd), so the UI
            # showed a red CANCELLED badge with no machine-readable
            # reason.  This is NOT an error — it's the intended dedup
            # outcome — but the field must still carry the cause so the
            # operator + audit trail know why.
            job.error_detail = (
                f"coalesced_into={e.holder or 'unknown'}; "
                f"branch={scan_branch}; not an error — duplicate scan deduplicated."
            )
            job.stats = {
                **(job.stats or {}),
                "coalesced_into": e.holder,
                "coalesced_branch": scan_branch,
            }
            await db.commit()
            logger.info(
                "scan_job_coalesced",
                scan_job_id=scan_job_id,
                repository_id=str(repo.id),
                branch=scan_branch,
                running_holder=e.holder,
            )
            return

        try:
            job.status = ScanStatus.RUNNING
            job.progress_pct = 5
            job.status_message = "[1/8] Preparing repository..."
            await _emit_phase("running", 5, "Preparing repository...", step=1)
            await db.commit()

            # Repository row already loaded above (needed for branch
            # resolution / lock acquisition). Skip the redundant fetch.
            # Kept the assignment style symmetric with the prior code
            # so downstream blocks read the same.

            # Check for existing snapshot
            snap_result = await db.execute(
                select(RepositorySnapshot)
                .where(RepositorySnapshot.repository_id == repo.id)
                .order_by(RepositorySnapshot.created_at.desc())
                .limit(1)
            )
            snapshot = snap_result.scalar_one_or_none()
            repo_path = snapshot.storage_path if snapshot else None

            # If repo has a URL and no snapshot, clone it
            scan_type_val = job.scan_type.value if hasattr(job.scan_type, 'value') else str(job.scan_type) if hasattr(job, 'scan_type') else "standalone"
            need_full_history = (scan_type_val == "history")

            # If history scan requested, ensure the existing clone has the
            # FULL history of ALL branches (Sprint A-1 + A-2). The clone may
            # be shallow and/or single-branch from a prior standalone scan;
            # `git fetch --unshallow` alone deepens only the tracked branch,
            # so widen the refspec to all branches first, then deepen/fetch.
            # _run_git enforces a hard timeout AND kills the git process
            # group on expiry so a hung fetch can't orphan a subprocess.
            if need_full_history and repo_path and os.path.exists(repo_path):
                shallow_file = os.path.join(repo_path, ".git", "shallow")
                job.status_message = "[2/8] Fetching full history (all branches)..."
                job.progress_pct = 10
                await _emit_phase("running", 10, job.status_message, step=2)
                await db.commit()
                logger.info("unshallowing_existing_clone", repo_id=str(repo.id))
                await _run_git(
                    ["git", "-C", repo_path, "remote", "set-branches", "origin", "*"],
                    label="set-branches",
                )

                # Live fetch progress + heartbeat — the history-scan twin of the
                # clone-phase F2 fix. A full-history `--unshallow` on a large
                # repo can stream for many minutes with no DB write; without a
                # heartbeat the 15-min stale-scan watchdog false-reaps a healthy,
                # still-downloading fetch (the same class of bug that reaped
                # superset/trivy mid-clone). Stream git's `--progress` to climb
                # the bar 10→20 AND stamp heartbeat_at each tick. Same in-stack
                # main-session pattern as _clone_cb (no concurrent-session race).
                import time as _ft
                _fetch_last_emit = [0.0]
                async def _fetch_cb(phase: str, pct: int):
                    if phase == "Receiving objects":
                        band = 11.0 + pct * 0.07      # 11 → 18 (the bulk)
                    elif phase == "Resolving deltas":
                        band = 18.0 + pct * 0.02       # 18 → 20
                    else:                               # Counting / Compressing
                        band = 10.0 + pct * 0.01        # 10 → 11
                    if (job.progress_pct or 0) < int(band):
                        job.progress_pct = int(band)
                    job.status_message = f"[2/8] Fetching history… {phase.split()[0].lower()} {pct}%"
                    now = _ft.monotonic()
                    do_emit = (now - _fetch_last_emit[0]) >= 3.0
                    try:
                        await _stamp_heartbeat_main(job, db, commit=False)
                        if do_emit:
                            _fetch_last_emit[0] = now
                            await _emit_phase("running", int(band), job.status_message, step=2)
                        await db.commit()
                    except Exception:
                        pass  # progress is best-effort; never break the fetch

                # `--progress` forces git to emit progress even though stderr is
                # a pipe (not a TTY); without it _run_git's streaming parser sees
                # nothing and the bar/heartbeat stay frozen for the whole fetch.
                fetch_args = ["git", "-C", repo_path, "fetch", "--progress", "--tags", "origin"]
                if os.path.exists(shallow_file):
                    fetch_args.insert(5, "--unshallow")
                await _run_git(fetch_args, label="fetch-unshallow", on_progress=_fetch_cb)
                job.progress_pct = 20  # fetch band complete
                await _stamp_heartbeat_main(job, db, commit=False)
                await db.commit()

            if repo.url and not repo_path:
                job.status_message = "[2/8] Cloning repository%s..." % (" (full history)" if need_full_history else "")
                job.progress_pct = 5
                await _emit_phase("running", 5, job.status_message, step=2)
                await db.commit()

                # ── live clone progress + heartbeat ───────────────────────
                # Streams `git clone --progress`; each tick advances the bar
                # within the clone band (5→20%) AND stamps heartbeat_at so the
                # 15-min stale-scan watchdog never reaps a healthy, still-
                # downloading clone (the superset/trivy false-reap, F2). Runs
                # in-stack on the main db session (no concurrent-session race).
                import time as _ct
                _clone_last_emit = [0.0]
                async def _clone_cb(phase: str, pct: int):
                    if phase == "Receiving objects":
                        band = 8.0 + pct * 0.09        # 8 → 17 (the bulk)
                    elif phase == "Resolving deltas":
                        band = 17.0 + pct * 0.02       # 17 → 19
                    else:                               # Counting / Compressing
                        band = 5.0 + pct * 0.03         # 5 → 8
                    job.progress_pct = int(band)
                    job.status_message = f"[2/8] Cloning… {phase.split()[0].lower()} {pct}%"
                    now = _ct.monotonic()
                    do_emit = (now - _clone_last_emit[0]) >= 3.0
                    try:
                        await _stamp_heartbeat_main(job, db, commit=False)
                        if do_emit:
                            _clone_last_emit[0] = now
                            await _emit_phase("running", int(band), job.status_message, step=2)
                        await db.commit()
                    except Exception:
                        pass  # progress is best-effort; never break the clone

                # Extract auth from repo metadata (stored during creation)
                repo_auth = (repo.metadata_ or {}).get("auth")
                repo_path = await _clone_repository(repo.url, str(repo.id), repo.default_branch, auth=repo_auth, full_history=need_full_history, on_progress=_clone_cb)
                job.progress_pct = 20  # clone band complete
                await _stamp_heartbeat_main(job, db, commit=False)
                await db.commit()

                snapshot = RepositorySnapshot(
                    repository_id=repo.id,
                    branch=repo.default_branch or "main",
                    storage_path=repo_path,
                )
                db.add(snapshot)
                await db.flush()

            if not repo_path or not os.path.exists(repo_path):
                job.status = ScanStatus.FAILED
                job.error_detail = "No repository content available. Upload source code or provide a valid URL."
                await db.commit()
                return

            # ── Step 2: Analyze repository ──────────────────────────
            job.status_message = "[3/8] Analyzing repository — detecting languages and frameworks..."
            job.progress_pct = 20
            await _emit_phase("running", 20, job.status_message, step=3)
            await db.commit()

            # analyze_repository walks the entire tree synchronously. Two
            # problems on a large monorepo: (1) it BLOCKS the event loop for
            # the whole walk — starving every other coroutine on this worker
            # (including a co-running scan's heartbeat); (2) no heartbeat
            # advances, so a walk long enough to exceed the 15-min stale-scan
            # threshold trips an F2-class false-reap. Run it in the default
            # executor so the loop stays free, and pump heartbeat_at every
            # ~20s (throttled to ~1/30s inside _stamp_heartbeat_main) while it
            # runs. There's no upfront file count, so step 3 is an honest
            # INDETERMINATE liveness signal — the bar holds at 20% with a live
            # heartbeat rather than a faked percentage. The pump shares the
            # MAIN session safely: the driving coroutine is parked in
            # run_in_executor (not touching db) and analyze_repository is pure
            # filesystem (never touches db), so the pump is the sole db user
            # for that window — no concurrent-connection race, no self-deadlock
            # (it's the same txn, which already committed at the emit above).
            import asyncio as _aio_an
            _an_done = _aio_an.Event()
            async def _analyze_heartbeat():
                while not _an_done.is_set():
                    try:
                        await _aio_an.wait_for(_an_done.wait(), timeout=20)
                    except _aio_an.TimeoutError:
                        try:
                            await _stamp_heartbeat_main(job, db, commit=True)
                        except Exception:
                            pass  # liveness is best-effort; never break analyze
            _an_hb = _aio_an.create_task(_analyze_heartbeat())
            try:
                analysis = await _aio_an.get_running_loop().run_in_executor(
                    None, analyze_repository, repo_path)
            finally:
                _an_done.set()
                try:
                    await _an_hb  # let the pump drain before post-analyze writes
                except Exception:
                    pass
            snapshot.file_count = analysis.total_files
            snapshot.total_size_bytes = analysis.total_size
            snapshot.file_index = {k: v for k, v in list(analysis.file_index.items())[:500]}
            snapshot.analysis_result = {
                "languages": analysis.languages,
                "frameworks": analysis.frameworks,
                "config_files": analysis.config_files[:50],
            }
            # Update repo metadata
            repo.languages = list(analysis.languages.keys())[:10]
            repo.frameworks = analysis.frameworks[:10]
            await db.commit()

            logger.info("repo_analyzed",
                scan_job_id=scan_job_id,
                files=analysis.total_files,
                languages=list(analysis.languages.keys()),
                frameworks=analysis.frameworks,
            )

            # ── Step 3: Run scanner ─
            job.status_message = f"[4/8] Scanning {analysis.total_files} files for secrets..."
            job.progress_pct = 40
            await _emit_phase("running", 40, job.status_message, step=4, stats={"files_to_scan": analysis.total_files})
            await db.commit()

            from packages.common.scanner_branding import get_internal_scanner_name, brand_rule_id
            scanner_name = get_internal_scanner_name()  # "vooda_engine" in DB
            detection_engine = "secret_scan"  # internal tracking
            detected_langs = list(analysis.languages.keys())

            # Load custom rules for this tenant (built-in + org-specific)
            from services.secret_scan.detectors.registry import get_all_rules_with_custom
            all_rules = await get_all_rules_with_custom(job.tenant_id, db)

            # Load scan_scope + test-file handling from engine settings
            scan_scope = "standard"
            test_file_handling = "normal"   # no-op default; never hides findings
            es = None  # initialised here so the stats block at the
                        # end of the scan can read it even if the load
                        # below raises (e.g. brand new tenant with no
                        # row yet — a None ``es`` is fine; the
                        # ``_compute_ai_settings_hash`` helper handles
                        # that case explicitly).
            try:
                from apps.api.app.models.ai_engine_settings import AIEngineSettings
                es_result = await db.execute(
                    select(AIEngineSettings).where(AIEngineSettings.tenant_id == job.tenant_id).limit(1)
                )
                es = es_result.scalar_one_or_none()
                if es and hasattr(es, 'scan_scope') and es.scan_scope:
                    scan_scope = es.scan_scope
                # "Test File Handling".
                # Legacy rows may hold a bool (older schema); anything not
                # recognised falls back to "normal", which is a no-op.
                _raw_tfh = getattr(es, "deprioritize_test_files", None) if es else None
                if isinstance(_raw_tfh, bool):
                    _raw_tfh = "deprioritize" if _raw_tfh else "normal"
                if _raw_tfh in ("normal", "deprioritize", "exclude"):
                    test_file_handling = _raw_tfh
            except Exception:
                pass

            if test_file_handling != "normal":
                logger.info("test_file_handling_active",
                            scan_job_id=scan_job_id, mode=test_file_handling)
            # NOTE: detection is deliberately NOT affected by this setting.
            # `deprioritize` lowers severity after detection and `exclude`
            # only skips AI triage — matching what the UI promises and
            # guaranteeing the scanner never loses recall.
            scanner = SecretScanner(rules=all_rules, scan_scope=scan_scope)

            # Determine the new checkpoint commit BEFORE scanning so a
            # mid-scan push doesn't desync the watermark. We fall back
            # to None when the repo isn't git-backed (uploaded archives
            # have no .git), and the worker treats that as "no
            # checkpointing possible — full scan as before".
            current_head_sha: Optional[str] = _get_head_sha(repo_path)

            # Honor an explicit ``force_full`` flag in the scan job
            # config (UI surfaces this as the "Force Full Re-Scan"
            # menu option). Used after rule pack updates or when the
            # user suspects the prior checkpoint missed something.
            job_cfg = job.config or {}
            force_full = bool(job_cfg.get("force_full"))
            # ── Per-branch checkpoint resolution ─────────────────────
            # Read the per-(repo, branch) checkpoint first. Falls back
            # to the legacy ``repositories.last_scanned_commit`` if no
            # row exists yet (e.g. brand-new branch on a repo that's
            # been scanned before, or pre-migration repos that haven't
            # gotten their first per-branch row written yet).
            #
            # ``force_full`` skips the read entirely — user wants a
            # ground-truth re-walk regardless of any saved checkpoint.
            base_sha_checkpoint: Optional[str] = None
            if not force_full:
                try:
                    cp_row = await db.execute(
                        text(
                            """
                            SELECT last_scanned_commit
                              FROM repo_branch_checkpoints
                             WHERE repository_id = :rid
                               AND branch        = :br
                            """
                        ),
                        {"rid": repo.id, "br": scan_branch},
                    )
                    cp_val = cp_row.scalar_one_or_none()
                    if cp_val:
                        base_sha_checkpoint = cp_val
                except Exception as _cp_err:
                    logger.warning(
                        "branch_checkpoint_read_failed",
                        scan_job_id=scan_job_id,
                        branch=scan_branch,
                        error=str(_cp_err)[:200],
                    )
                # Backfill / safety net — if the per-branch lookup
                # turned up empty AND the scan is on the default
                # branch, use the legacy column. Avoids a wasted full
                # scan immediately after the migration deploys.
                if base_sha_checkpoint is None and scan_branch == (repo.default_branch or "main"):
                    base_sha_checkpoint = repo.last_scanned_commit or None
            incremental_used = False
            incremental_files = 0
            # Files DELETED in this incremental's diff window. Captured
            # here so the tombstone pass after storage can resolve any
            # ``NormalizedFinding`` rows that point at them. Stays
            # empty for full-scan paths (a full scan_directory on the
            # current working tree implicitly handles deletions because
            # the deleted file isn't there to scan; existing findings
            # for it just don't get a ``last_seen_at`` bump). The
            # incremental path is where the leak was happening.
            deleted_files_in_diff: list[str] = []

            # ── File-level cache warm-up ─────────────────────────────
            # Pre-load every cached result for this
            # (repository, rule_pack_version, scan_scope). The cache
            # is consulted per-file inside the engine so an
            # unchanged file with an unchanged rule pack reuses its
            # prior findings without re-running 883 regexes. A rule
            # pack bump (or any custom-rule edit) produces a different
            # rule_pack_version, so the warm step returns an empty
            # snapshot and every file is re-scanned correctly.
            #
            # ``force_full`` skips the warm — the user asked for a
            # ground-truth re-walk, so we don't even consult the
            # cache. The flush still runs at the end so the new
            # results populate the cache for the next run.
            from services.secret_scan.file_cache import warm_cache as _warm_cache
            from services.secret_scan.file_cache import flush_cache as _flush_cache
            from services.secret_scan.file_cache import FileScanCacheView

            file_cache_view = None
            try:
                if force_full:
                    # Empty view → every file misses → engine runs the
                    # rule pack on everything. Misses still buffer
                    # writes that get flushed at the end.
                    file_cache_view = FileScanCacheView(snapshot={})
                else:
                    file_cache_view = await _warm_cache(
                        db,
                        tenant_id=job.tenant_id,
                        repository_id=repo.id,
                        rule_pack_version=scanner.rule_pack_version,
                        scan_scope=scan_scope,
                    )
            except Exception as _wce:
                logger.warning("file_cache_warm_failed",
                               scan_job_id=scan_job_id,
                               error=str(_wce)[:200])
                file_cache_view = None  # Engine treats None as "no cache"

            # ── Standalone full-scan mid-phase progress (Gap #3) ──────
            # scan_directory() (the HEAD / incremental-fallback / full
            # paths below) is a single blocking call that walks the
            # whole working tree — minutes on a large repo. Mirror the
            # history-scan hook: fire every N files to sweep the bar
            # 40→55 AND stamp heartbeat_at so the stale-scan watchdog
            # never false-reaps a healthy large-repo scan. Live
            # 2026-05-31: aws-cdk force_full sat at 40% for ~13m with
            # heartbeat climbing to 763s — only 137s shy of the 900s
            # reap threshold; a slightly bigger repo reaps every time.
            #
            # Same threadsafe-schedule pattern as the history branch.
            # Safe from the G-2 self-deadlock: the main session
            # committed its last scan_jobs write at the step-4 emit and
            # only reads until the scan runs, so this separate-session
            # UPDATE never contends a row lock the main txn is holding.
            import asyncio as _aio_dir
            _loop_for_dir = _aio_dir.get_running_loop()
            _dir_total_hint = max(int(getattr(analysis, "total_files", 0) or 0), 1)
            _dir_last_pub = {"t": 0.0}
            _DIR_PUB_MIN_S = 2.0

            async def _do_dir_publish(files_done: int, findings_so_far: int):
                """Update the scan_jobs row + WS publish for one tick."""
                try:
                    frac = min(1.0, files_done / _dir_total_hint)
                    pct = max(41, min(54, 40 + int(round(15 * frac))))
                    msg = (
                        f"[4/8] Scanning {files_done:,}/{_dir_total_hint:,} files — "
                        f"{findings_so_far:,} raw findings so far..."
                    )
                    try:
                        async with await _get_db_session() as _db_dir:
                            from sqlalchemy import update as _sa_update_dir
                            from datetime import datetime as _dt_dir, timezone as _tz_dir
                            await _db_dir.execute(
                                _sa_update_dir(ScanJob)
                                .where(ScanJob.id == UUID(scan_job_id))
                                .values(
                                    progress_pct=pct,
                                    status_message=msg,
                                    # Walking files is real progress —
                                    # advance the liveness heartbeat so a
                                    # long full-scan is never reaped mid-walk.
                                    # NB: timezone.utc (an instance), NOT the
                                    # `timezone` class — datetime.now() rejects
                                    # the class ("tzinfo argument must be ...
                                    # not type 'type'"), which silently broke
                                    # every mid-scan heartbeat until 2026-05-31.
                                    heartbeat_at=_dt_dir.now(_tz_dir.utc),
                                )
                            )
                            await _db_dir.commit()
                    except Exception as _dbe:
                        logger.warning("dir_progress_db_update_failed",
                                       scan_job_id=scan_job_id, error=str(_dbe)[:200])
                    await _publish("running", pct, msg, {
                        "files_scanned": files_done,
                        "files_total": _dir_total_hint,
                        "raw_findings_count": findings_so_far,
                    })
                except Exception as _pe:
                    logger.warning("dir_progress_publish_failed",
                                   scan_job_id=scan_job_id, error=str(_pe)[:200])

            def _on_dir_progress(files_done: int, findings_so_far: int):
                """Sync hook called from inside scan_directory's walk;
                schedules the async update on the main loop, throttled
                to one publish per ~2s wall clock."""
                import time as _t_dir
                now = _t_dir.monotonic()
                if now - _dir_last_pub["t"] < _DIR_PUB_MIN_S:
                    return
                _dir_last_pub["t"] = now
                try:
                    _aio_dir.run_coroutine_threadsafe(
                        _do_dir_publish(files_done, findings_so_far), _loop_for_dir,
                    )
                except Exception as _ce:
                    try:
                        logger.warning("dir_progress_schedule_failed", error=str(_ce)[:200])
                    except Exception:
                        pass

            # Choose scan mode: HEAD (default) or full git history
            if scan_type_val == "history":
                from services.secret_scan.engine import scan_git_history
                import asyncio as _aio_inner
                job.status_message = "[4/8] Scanning full git history for secrets..."
                await db.commit()
                # History scans walk the commit graph rather than the
                # working tree — the file cache (keyed on file path +
                # working-tree content_sha) doesn't apply.
                #
                # ── Mid-phase progress callback ─────────────────────
                # scan_git_history is CPU-bound for several minutes on
                # large repos.  Without intermediate publishes the UI
                # sat at [4/8] 40% for the entire phase (live monitor
                # 2026-05-23: pulumi pegged at 100% CPU for 7m+ with
                # zero progress events).  Hook fires every 250 commits
                # to sweep progress_pct from 40 → 55 across the walk.
                #
                # We pin the running loop here so the sync callback
                # (running inside the to_thread worker) can schedule
                # the async DB update + publish back onto the main
                # event loop via run_coroutine_threadsafe.  Running
                # scan_git_history itself in a thread keeps the main
                # loop responsive to those scheduled callbacks during
                # the long CPU-bound phase.
                _loop_for_progress = _aio_inner.get_running_loop()

                # Throttle ref so we never schedule a publish faster
                # than once per ~2s wall-clock even if commits stream
                # through extremely fast on a tiny repo.
                _last_publish_ts = {"t": 0.0}
                _PUBLISH_MIN_INTERVAL_S = 2.0

                async def _do_history_publish(commits_done: int, max_commits_arg: int, findings_so_far: int):
                    """Update DB row + push Redis publish for mid-phase progress."""
                    try:
                        pct = 40 + int(15 * commits_done / max(1, max_commits_arg))
                        # Clamp to (40, 54] — phase 5's 55% transition
                        # is the next official boundary and we don't
                        # want the bar to overshoot before that fires.
                        pct = max(41, min(54, pct))
                        msg = (
                            f"[4/8] Scanned {commits_done:,}/{max_commits_arg:,} commits — "
                            f"{findings_so_far:,} raw findings so far..."
                        )
                        stats_payload = {
                            "commits_scanned": commits_done,
                            "commits_total": max_commits_arg,
                            "raw_findings_count": findings_so_far,
                        }
                        # Update the DB row so the 5s polling fallback
                        # also picks up the progress (not just WS).
                        try:
                            async with await _get_db_session() as _db_inner:
                                from sqlalchemy import update as _sa_update
                                from datetime import datetime as _dt_hb, timezone as _tz_hb
                                await _db_inner.execute(
                                    _sa_update(ScanJob).where(ScanJob.id == UUID(scan_job_id)).values(
                                        progress_pct=pct,
                                        status_message=msg,
                                        # Sprint G-2 — walking commits is real
                                        # progress; advance the liveness
                                        # heartbeat so the watchdog never reaps
                                        # a deep-history scan mid-walk. Free —
                                        # this row already commits here.
                                        # NB: timezone.utc (instance), not the
                                        # `timezone` class — the class form
                                        # raised "tzinfo argument must be ...
                                        # not type 'type'" and silently broke
                                        # this whole mid-walk update from the
                                        # day G-2 added this heartbeat line.
                                        heartbeat_at=_dt_hb.now(_tz_hb.utc),
                                    )
                                )
                                await _db_inner.commit()
                        except Exception as _db_err:
                            logger.warning(
                                "mid_phase_db_update_failed",
                                scan_job_id=scan_job_id,
                                error=str(_db_err)[:200],
                            )
                        # Push to Redis for the WS drawer (sub-second
                        # latency vs the 5s poll).
                        await _publish("running", pct, msg, stats_payload)
                    except Exception as _pe:
                        logger.warning(
                            "mid_phase_publish_failed",
                            scan_job_id=scan_job_id,
                            error=str(_pe)[:200],
                        )

                def _on_history_progress(commits_done: int, max_commits_arg: int, findings_so_far: int):
                    """Sync callback invoked from inside scan_git_history's loop.

                    Schedules the async DB+publish coroutine on the main
                    event loop.  Throttled to one publish per ~2s wall
                    clock so an unexpectedly fast scan can't flood
                    Redis or the WS client.
                    """
                    import time as _time_inner
                    now = _time_inner.monotonic()
                    if now - _last_publish_ts["t"] < _PUBLISH_MIN_INTERVAL_S:
                        return
                    _last_publish_ts["t"] = now
                    try:
                        _aio_inner.run_coroutine_threadsafe(
                            _do_history_publish(commits_done, max_commits_arg, findings_so_far),
                            _loop_for_progress,
                        )
                    except Exception as _ce:
                        # Final safety net — if scheduling fails the
                        # scan still runs to completion, just without
                        # mid-phase progress.
                        try:
                            logger.warning("mid_phase_schedule_failed", error=str(_ce)[:200])
                        except Exception:
                            pass

                # Run the BLOCKING scan in a thread so the event loop
                # is free to process the progress callbacks above.
                # asyncio.to_thread uses the default executor; concurrency=2
                # workers each get their own thread so this is safe.
                raw_findings = await _aio_inner.to_thread(
                    scan_git_history,
                    repo_path,
                    scanner=scanner,
                    max_commits=5000,
                    progress_callback=_on_history_progress,
                    progress_every_n_commits=250,
                )
                detection_engine = "secret_scan_history"
            elif (
                base_sha_checkpoint
                and current_head_sha
                and base_sha_checkpoint != current_head_sha
                and _is_commit_reachable(repo_path, base_sha_checkpoint)
            ):
                # Incremental path — reuses the engine's diff-mode that
                # was already powering webhook scans. Only files
                # changed between last_scanned_commit and HEAD are
                # re-scanned. Findings dedup downstream by stability_id
                # so unchanged files keep their existing rows.
                from services.secret_scan.engine import scan_diff
                from services.secret_scan.git_history import get_diff_files
                try:
                    diff_files = get_diff_files(repo_path, base_sha_checkpoint, current_head_sha)
                    incremental_files = len(diff_files)
                except Exception as _e:
                    logger.warning("incremental_diff_listing_failed",
                                   scan_job_id=scan_job_id,
                                   base=base_sha_checkpoint[:8] if base_sha_checkpoint else None,
                                   head=current_head_sha[:8] if current_head_sha else None,
                                   error=str(_e)[:200])
                    diff_files = None

                if diff_files is None:
                    # Diff failed (force-pushed history, missing
                    # commit, etc.) — fall back to full scan rather
                    # than report partial results. Run in a thread w/
                    # the progress hook so the fallback (a full walk)
                    # gets the same heartbeat protection as the else
                    # branch below.
                    raw_findings = await _scan_with_cpu_budget(
                        scanner, repo_path, scan_job_id,
                        file_cache=file_cache_view,
                        progress_callback=_on_dir_progress,
                        progress_every_n_files=200,
                    )
                    detection_engine = "secret_scan"
                    logger.info("incremental_fallback_to_full",
                                scan_job_id=scan_job_id,
                                base=base_sha_checkpoint[:8] if base_sha_checkpoint else None,
                                head=current_head_sha[:8] if current_head_sha else None)
                else:
                    job.status_message = (
                        f"[4/8] Incremental scan — {incremental_files} changed file(s) since "
                        f"{base_sha_checkpoint[:8]}..."
                    )
                    await db.commit()
                    raw_findings = scan_diff(
                        repo_path, base_sha_checkpoint, current_head_sha,
                        scanner=scanner, file_cache=file_cache_view,
                    )
                    detection_engine = "secret_scan_incremental"
                    incremental_used = True
                    # Capture deletions in the same diff window so we
                    # can tombstone their findings after storage. Done
                    # here (next to scan_diff) so the base/head SHAs
                    # we just confirmed reachable are the same ones
                    # used for the deletion enumeration — no risk of
                    # the user pushing again mid-scan and us walking
                    # a different commit range.
                    try:
                        from services.secret_scan.git_history import get_deleted_files
                        deleted_files_in_diff = get_deleted_files(
                            repo_path, base_sha_checkpoint, current_head_sha,
                        )
                    except Exception as _del_e:
                        logger.warning(
                            "deleted_files_enum_failed",
                            scan_job_id=scan_job_id,
                            error=str(_del_e)[:200],
                        )
                    logger.info("incremental_scan_complete",
                                scan_job_id=scan_job_id,
                                base=base_sha_checkpoint[:8],
                                head=current_head_sha[:8],
                                changed_files=incremental_files,
                                deleted_files=len(deleted_files_in_diff),
                                findings=len(raw_findings))
            else:
                # Full scan — first run on this repo, force_full
                # requested, no HEAD SHA available (uploaded archive),
                # or HEAD == checkpoint (no diff to walk). With the
                # file cache warmed, an "HEAD == checkpoint" no-source
                # change re-scan turns into "every file is a cache hit"
                # — the engine walks the tree, hashes each file, sees
                # the cached row, and returns the cached findings
                # without ever touching the rule pack. Same result,
                # ~10× faster on real repos.
                #
                # Run in a thread w/ the progress hook (Gap #3) so the
                # event loop stays free to service the heartbeat/bar
                # callbacks during the multi-minute walk.
                raw_findings = await _scan_with_cpu_budget(
                    scanner, repo_path, scan_job_id,
                    file_cache=file_cache_view,
                    progress_callback=_on_dir_progress,
                    progress_every_n_files=200,
                )
                detection_engine = "secret_scan"

            # ── Test File Handling: "deprioritize" ───────────────────
            # Lowers severity to LOW for findings in test/spec files, as
            # the UI describes: "They remain visible in the findings list
            # but won't trigger high-priority alerts."
            #
            # Applied HERE — after detection, before persistence — for
            # three reasons:
            #   * detection is untouched, so recall is identical to
            #     `normal` and no real credential can ever be hidden;
            #   * it sits after every scan path (full, incremental, diff)
            #     converges, so one implementation covers all of them;
            #   * the file cache stores raw scanner output, so changing
            #     this setting needs no cache invalidation — the override
            #     is re-applied on every scan regardless of cache hits.
            if test_file_handling == "deprioritize" and raw_findings:
                from services.secret_scan.engine import _classify_file_context as _cfc
                _lowered = 0
                for _pf in raw_findings:
                    try:
                        if _cfc(_pf.file_path or "") == "test_file" and _pf.severity != "low":
                            _pf.severity = "low"
                            _lowered += 1
                    except Exception:
                        continue
                if _lowered:
                    logger.info("test_file_findings_deprioritized",
                                scan_job_id=scan_job_id, lowered=_lowered,
                                total=len(raw_findings))

            # ── File-cache stats + flush ──────────────────────────────
            # Pull the counters before flushing (flush doesn't reset
            # them but is allowed to clear the writes buffer).
            #
            # Names are prefixed ``file_cache_*`` to keep them distinct
            # from the AI decision-cache counters (``cache_hits``,
            # ``cache_invalidated``, ``cache_new``) populated later in
            # ``Step 4d``. Two completely separate caches that both
            # report hit-rate stats — keep them un-aliased so the
            # mental model and the dashboards line up.
            file_cache_hits = file_cache_view.hits if file_cache_view is not None else 0
            file_cache_misses = file_cache_view.misses if file_cache_view is not None else 0
            file_cache_hit_rate = (
                file_cache_view.hit_rate() if file_cache_view is not None else 0.0
            )
            file_cache_rows_written = 0
            if file_cache_view is not None:
                try:
                    # Persist new entries (cache misses) so the next
                    # scan benefits. Hit rows are NOT touched —
                    # they'll naturally fall out via TTL prune if
                    # nobody ever scans the file again, and re-warm
                    # via the cache miss → flush cycle if anyone does.
                    # Saves a UPDATE-per-scan on potentially thousands
                    # of rows for no correctness gain.
                    file_cache_rows_written = await _flush_cache(
                        db, file_cache_view,
                        tenant_id=job.tenant_id,
                        repository_id=repo.id,
                        rule_pack_version=scanner.rule_pack_version,
                        scan_scope=scan_scope,
                    )
                    await db.commit()
                except Exception as _fce:
                    logger.warning("file_cache_flush_failed",
                                   scan_job_id=scan_job_id,
                                   error=str(_fce)[:200])

            logger.info("scan_complete",
                scan_job_id=scan_job_id,
                scanner=scanner_name,
                raw_findings=len(raw_findings),
                incremental=incremental_used,
                checkpoint_base=base_sha_checkpoint[:8] if base_sha_checkpoint else None,
                head=current_head_sha[:8] if current_head_sha else None,
                file_cache_hits=file_cache_hits,
                file_cache_misses=file_cache_misses,
                file_cache_hit_rate=round(file_cache_hit_rate, 3),
                rule_pack_version=scanner.rule_pack_version[:12],
            )

            # ── Step 4b: Inline Credential Verification + Blast Radius ──
            # Verify secrets BEFORE DB storage (raw value is still in memory).
            # After storage, _raw_value_for_verification is stripped for security.
            verified_count = 0
            active_count = 0
            try:
                from services.secret_verification.verifier import verify_finding as _verify_finding, SUPPORTED_PROVIDERS
                from services.secret_verification.blast_radius import analyze_blast_radius
                import asyncio

                # ── "Credential Verification" setting (per tenant) ──────
                # Controls whether outbound verification runs.
                # Precedence, most specific first:
                #   1. tenant setting `auto_verify_credentials` (this UI toggle)
                #   2. global `VERIFICATION_ENABLED` env kill-switch, which
                #      is enforced inside verify_finding() and remains the
                #      documented air-gapped control.
                # Turning it off is never an error: findings simply stay
                # `not_validated`, exactly as the env kill-switch behaves.
                _auto_verify = True
                try:
                    from apps.api.app.models.ai_engine_settings import AIEngineSettings as _AES
                    _aes = (await db.execute(
                        select(_AES).where(_AES.tenant_id == job.tenant_id).limit(1)
                    )).scalar_one_or_none()
                    if _aes is not None and _aes.auto_verify_credentials is not None:
                        _auto_verify = bool(_aes.auto_verify_credentials)
                except Exception as _ave:
                    logger.debug("auto_verify_setting_read_failed", error=str(_ave)[:120])

                verifiable = [pf for pf in raw_findings
                              if (pf.raw_data or {}).get("_raw_value_for_verification")
                              and (pf.raw_data or {}).get("provider", "unknown").lower() in SUPPORTED_PROVIDERS]

                if verifiable and not _auto_verify:
                    logger.info(
                        "credential_verification_disabled_by_setting",
                        scan_job_id=scan_job_id, skipped=len(verifiable),
                    )
                    verifiable = []

                if verifiable:
                    _vtotal = len(verifiable)
                    job.status_message = f"[5/8] Verifying {_vtotal} credentials..."
                    job.progress_pct = 55
                    await _emit_phase("running", 55, f"Verifying {_vtotal} credentials...", step=5)
                    await db.commit()

                    # Live verify progress + heartbeat — climbs 55→60 as each
                    # credential resolves (k/N), mirroring the clone/scan/triage
                    # bars the operator already trusts. Safe on the main db
                    # session: _verify_batch fires on_progress serially from its
                    # as_completed loop and the worker coroutines touch neither
                    # `db` nor `job`, so there's no concurrent-session race. Also
                    # stamps heartbeat_at so a slow-provider tail can't trip the
                    # 15-min stale-scan watchdog mid-verify.
                    import time as _vt
                    _verify_last_emit = [0.0]
                    async def _verify_cb(done: int, total: int):
                        frac = (done / total) if total else 1.0
                        band = 55 + int(round(5 * min(1.0, frac)))   # 55 → 60
                        if (job.progress_pct or 0) < band:
                            job.progress_pct = band
                        job.status_message = f"[5/8] Verifying credentials… {done:,}/{total:,}"
                        now = _vt.monotonic()
                        do_emit = (now - _verify_last_emit[0]) >= 3.0 or done >= total
                        try:
                            await _stamp_heartbeat_main(job, db, commit=False)
                            if do_emit:
                                _verify_last_emit[0] = now
                                await _emit_phase("running", band, job.status_message, step=5,
                                                  stats={"verified_so_far": done, "verifiable_total": total})
                            await db.commit()
                        except Exception:
                            pass  # progress is best-effort; never break verify

                    # S2: bounded-concurrent verification (replaces the old 60s
                    # sequential loop). _verify_batch fans verifications out under
                    # a semaphore + per-provider rate limit, mutating each pf's
                    # raw_data in place; the DB session is never touched
                    # concurrently. An absolute backstop guarantees no hang.
                    _vc = max(1, int(getattr(settings, "VERIFICATION_CONCURRENCY", 8) or 8))
                    _vb = max(1, int(getattr(settings, "VERIFICATION_ABS_BUDGET_S", 120) or 120))
                    _vstats = await _verify_batch(
                        verifiable, job.tenant_id,
                        concurrency=_vc, abs_budget_s=_vb, blast_fn=analyze_blast_radius,
                        on_progress=_verify_cb,
                    )
                    verified_count = _vstats["verified"]
                    active_count = _vstats["active"]

                    logger.info("inline_verification_done",
                        scan_job_id=scan_job_id, verified=verified_count, active=active_count,
                        inactive=_vstats["inactive"], errors=_vstats["error"], concurrency=_vc)

                    if active_count > 0:
                        job.status_message = f"[5/8] Credential analysis complete — {active_count} active, {verified_count - active_count} inactive"
                    elif verified_count > 0:
                        job.status_message = f"[5/8] Credential analysis complete — {verified_count} verified, none active"
                    else:
                        job.status_message = f"[5/8] Credential verification complete"
                    # Land deterministically at the band end so the handoff to
                    # storing (56→70, monotonic-clamped) is clean regardless of
                    # how the per-credential throttle happened to fall.
                    job.progress_pct = 60
                    await db.commit()
                else:
                    job.status_message = f"[5/8] No verifiable credentials found"
                    job.progress_pct = 60
                    await db.commit()

            except Exception as verify_err:
                logger.warning("inline_verification_step_failed", error=str(verify_err)[:300])

            # ── Step 5: Store findings (update existing or create new) ──
            job.status_message = f"[6/8] Storing {len(raw_findings)} findings..."
            # P0 — start storing at 56 so the per-chunk counter can climb
            # 56 -> 70 (the chunk boundary updates job.progress_pct). Still
            # >= the verify phase (55) so no backward jump if it fired.
            job.progress_pct = 56
            await _emit_phase("running", 56, job.status_message, step=6, stats={"raw_findings_count": len(raw_findings)})
            await db.commit()

            from services.normalization.stability import compute_stability_id, compute_code_hash
            from datetime import datetime, timezone

            seen_fps = set()
            created_count = 0
            updated_count = 0
            suppressed_inactive_count = 0  # S3: findings auto-suppressed as verified-dead
            # #1b: incident validation_status flips collected on the UPDATE path
            # (the CREATE path already sets it via the incident upsert). Applied
            # as a bulk UPDATE after the persist loop so a re-scanned dead-cred
            # incident hides from the dashboard immediately, not only after a
            # re-verify pass.
            _mark_incident_inactive: set = set()
            _mark_incident_active: set = set()
            now = datetime.now(timezone.utc)
            # Track stability_ids processed in THIS scan run to skip scanner-level
            # duplicates (same rule + file + content appearing multiple times in output).
            # Without this, two raw findings with identical stability_ids both pass
            # through the `existing_by_stability` dict as misses on re-scans, leaving
            # one copy permanently orphaned under the original scan's job_id.
            seen_stability_ids: set = set()

            # ── Phase-A L1: bounded existing-finding probe ──
            # Pre-compute the stability_ids THIS scan needs, then load only
            # the existing rows that match. Old: SELECT ... WHERE stability_id
            # IS NOT NULL — loads every finding the repo has ever had, so
            # re-scan time grew with cumulative repo history. New: scope by
            # the current scan's stability_id footprint — load cost is
            # bounded by O(scan_findings), not O(repo_history). Chunked at
            # 5k IDs per IN to stay friendly to the planner. Same stability_id
            # formula as the in-loop branch (centralised in
            # `_stability_id_for_pf`).
            needed_sids: set[str] = {
                _stability_id_for_pf(pf, repo_path) for pf in raw_findings
            }
            existing_by_stability: dict[str, NormalizedFinding] = {}
            if needed_sids:
                sids_list = list(needed_sids)
                CHUNK = 5000
                for _i in range(0, len(sids_list), CHUNK):
                    _chunk = sids_list[_i:_i + CHUNK]
                    existing_r = await db.execute(
                        select(NormalizedFinding).where(
                            NormalizedFinding.repository_id == repo.id,
                            NormalizedFinding.tenant_id == job.tenant_id,
                            NormalizedFinding.stability_id.in_(_chunk),
                        )
                    )
                    for f in existing_r.scalars().all():
                        existing_by_stability[f.stability_id] = f
            logger.info(
                "existing_findings_loaded",
                count=len(existing_by_stability),
                needed=len(needed_sids),
                repo_id=str(repo.id),
            )

            # ── Rule-override pre-gate ────────────────────────────────
            # Load the set of scanner_rule_ids the admin has muted for
            # this tenant + repo (or org-wide) BEFORE the persist loop.
            # The loop will check this set in O(1) per finding and
            # short-circuit the CREATE branch when matched.  See
            # apps/worker/rule_overrides.py for the trade-offs.
            from apps.worker.rule_overrides import (
                load_active_rule_ids,
                new_block_counter,
                record_blocks,
            )
            muted_rule_ids: set[str] = await load_active_rule_ids(
                db, job.tenant_id, repo.id,
            )
            block_counts = new_block_counter()

            # In-scan SecretIncident cache (Case-B aggregation).  Same
            # contract as the source-scan path's incident_cache: same
            # secret_hash within a single scan → one DB upsert, N
            # finding.incident_id links.  Cache is reset per scan to
            # avoid cross-scan staleness.
            incident_cache: dict[str, "UUID"] = {}

            async def _upsert_incident_for_repo(sh: str, pf, now_ts):
                """Find-or-create the SecretIncident for `sh` (repo-scan path).

                Thin wrapper over the shared, concurrency-safe
                :func:`_upsert_secret_incident` (atomic ON CONFLICT
                upsert).  See that function for the column-ownership
                contract and the two cross-scan races it closes.
                """
                return await _upsert_secret_incident(
                    db,
                    tenant_id=job.tenant_id,
                    secret_hash=sh,
                    pf=pf,
                    now_ts=now_ts,
                    default_title="Hardcoded secret",
                    severity_normalizer=normalize_severity,
                    incident_cache=incident_cache,
                )

            # Phase-A L2: chunked commits. The storing phase used to run for
            # minutes inside one transaction — row locks held the whole time,
            # nothing visible until the end, a worker crash mid-storing rolled
            # the whole phase back. Commit every CHUNK_SIZE successfully-
            # processed findings (created or updated) so locks release, a
            # progress signal lands in the DB, and a retry resumes near where
            # the failure happened. Generic operational hygiene — no change
            # to per-finding semantics.
            STORING_CHUNK_SIZE = 500
            _last_chunk_count = 0
            # Keep ORM-loaded existing findings live across the chunked
            # commits — otherwise each commit would expire them and the
            # next iteration's attribute access (the UPDATE branch reads
            # current values before mutating) would round-trip a SELECT
            # per finding, defeating the win. Restored after the loop.
            _prev_expire_on_commit = db.sync_session.expire_on_commit
            db.sync_session.expire_on_commit = False
            for pf in raw_findings:
                # Compute fingerprint for within-scan dedup
                import hashlib
                fp_parts = [pf.rule_id or "", pf.file_path or "", str(pf.line_start or ""), pf.category or ""]
                fp = hashlib.sha256("|".join(fp_parts).encode()).hexdigest()[:16]

                if fp in seen_fps:
                    continue
                seen_fps.add(fp)

                # Brand the rule ID
                branded_rule_id = brand_rule_id(pf.rule_id) if pf.rule_id else pf.rule_id

                # Sanitize fields
                cwe_clean = pf.cwe
                if cwe_clean and len(cwe_clean) > 20:
                    import re as _re
                    cwe_match = _re.match(r"(CWE-\d+)", cwe_clean)
                    cwe_clean = cwe_match.group(1) if cwe_match else cwe_clean[:20]

                category_clean = (pf.category or "uncategorized")[:255]
                file_path_clean = pf.file_path or "unknown"
                if file_path_clean.startswith(repo_path):
                    file_path_clean = file_path_clean[len(repo_path):].lstrip("/")

                # Enrich code snippet
                enriched_snippet = pf.code_snippet or ""
                if pf.file_path and pf.line_start and repo_path:
                    try:
                        full_path = os.path.join(repo_path, pf.file_path)
                        if os.path.exists(full_path):
                            with open(full_path, "r", errors="ignore") as sf:
                                all_lines = sf.readlines()
                            # The snippet's FIRST line must be line_start - 5 so
                            # the UI gutter (CodeSnippet.tsx: startLine =
                            # max(1, line_start - 5)) and the engine's own
                            # hit-line masking (_mask_snippet: hit = line_num -
                            # max(1, line_num - 5)) both land the highlight on the
                            # real secret line. The old -16 leading offset started
                            # the window 10 lines too high, so every gutter label
                            # was shifted +10 (secret on line 19 rendered as "29",
                            # highlight stuck on an import). Keep the generous
                            # trailing window (+15) for multi-line secrets.
                            snippet_start = max(0, pf.line_start - 6)
                            snippet_end = min(len(all_lines), pf.line_start + 15)
                            enriched_snippet = "".join(all_lines[snippet_start:snippet_end])
                    except Exception:
                        pass

                # ── Redact the raw secret in the snippet BEFORE storage.
                # Industry standard (GitGuardian/Wiz/Orca/TruffleHog Ent.):
                # mask at write time so the raw value never sits at rest.
                # `_raw_value_for_verification` is the in-memory raw value
                # (used by the validator earlier in this scan); it gets
                # stripped from `source_metadata` later in this loop, and
                # we use it here to scrub the line context too.  Also
                # handles paired credentials when present (e.g. AWS access
                # key + secret combo).
                from services.secret_scan.engine import redact_snippet_for_storage
                # Base64-wrapped findings: the snippet holds the SOURCE base64
                # token, so redact that EXACT token. Re-encoding the decoded
                # value is lossy and leaves a trailing-byte artifact
                # (e.g. "...C28=o="); the exact token replaces cleanly.
                raw_for_redact = ((pf.raw_data or {}).get("_source_b64_token")
                                  or (pf.raw_data or {}).get("_raw_value_for_verification") or "")
                masked_for_redact = (pf.raw_data or {}).get("masked_value") or ""
                paired_raw = (pf.raw_data or {}).get("paired_raw") or ""
                paired_masked = (pf.raw_data or {}).get("paired_masked") or ""
                # Mask BOTH the enriched window and the short snippet through
                # the SINGLE shared store-time redactor. De-duped from the
                # source-adapter path (run_source_scan) so every store path
                # masks the finding's own value + co-located residual secrets
                # (G1) identically and can never drift again. The targeted
                # own/paired redaction AND the conditional Fix-3 rescan/scrub
                # now live inside redact_snippet_for_storage().
                enriched_snippet = redact_snippet_for_storage(
                    enriched_snippet, raw_for_redact, masked_for_redact,
                    paired_raw, paired_masked, scanner=scanner)
                pf.code_snippet = redact_snippet_for_storage(
                    pf.code_snippet, raw_for_redact, masked_for_redact,
                    paired_raw, paired_masked, scanner=scanner)

                # Compute stability ID via the shared helper so the in-loop
                # branch and the pre-loop bounded probe (Phase-A L1) always
                # produce the same key — drift here would silently re-create
                # rows the loop should match.
                secret_hash = (pf.raw_data or {}).get("secret_hash", "")
                sid = _stability_id_for_pf(pf, repo_path)
                chash = compute_code_hash(enriched_snippet or pf.code_snippet or "")

                # Skip scanner-level duplicates: if we've already processed a raw
                # finding with this exact stability_id in this scan run, skip it.
                # This prevents creating multiple DB rows for the same logical finding
                # (which would cause orphaned duplicates on every subsequent re-scan).
                if sid in seen_stability_ids:
                    logger.warning("scanner_duplicate_skipped",
                        stability_id=sid, file=file_path_clean,
                        rule=pf.rule_id[:40] if pf.rule_id else "",
                    )
                    continue
                seen_stability_ids.add(sid)

                # Check if this finding already exists
                existing = existing_by_stability.get(sid)
                if not existing and created_count < 3:
                    # Debug: log first few misses
                    existing_sids = list(existing_by_stability.keys())[:3]
                    logger.warning("stability_miss_debug",
                        computed_sid=sid, file=file_path_clean, rule=pf.rule_id[:40] if pf.rule_id else "",
                        existing_sample=existing_sids,
                    )

                if existing:
                    # ── UPDATE existing finding ──
                    # Update scan linkage and timestamps
                    existing.last_seen_scan_job_id = job.id
                    existing.last_seen_at = now
                    existing.scan_count = (existing.scan_count or 1) + 1
                    existing.line_start = pf.line_start  # Line may shift
                    existing.line_end = pf.line_end
                    # Case-B link: ensure the existing finding points at
                    # the right incident.  Backfilled rows already have
                    # incident_id set; this call refreshes the incident's
                    # display fields + aggregate stats and is a no-op for
                    # the row's own incident_id when it's already correct.
                    existing.incident_id = await _upsert_incident_for_repo(secret_hash, pf, now)

                    # Backfill path-derived tags on existing findings
                    path_tags = _derive_path_tags(file_path_clean)
                    if path_tags:
                        cur = list(existing.tags or [])
                        if any(t not in cur for t in path_tags):
                            existing.tags = list({*cur, *path_tags})

                    # Refresh rule-derived fields so rule updates (severity
                    # rebalance, title fixes, description tweaks) propagate
                    # to existing findings on re-scan. Without this, a rule
                    # change (e.g., cert severity HIGH→info) only affects
                    # newly-detected instances, never existing DB rows.
                    new_severity = normalize_severity(pf.severity)
                    if new_severity and existing.severity != new_severity:
                        existing.severity = new_severity
                    if pf.title and existing.title != (pf.title or "")[:500]:
                        existing.title = (pf.title or "")[:500]
                    if pf.description is not None and existing.description != pf.description:
                        existing.description = pf.description

                    # Always refresh the snippet to the latest scan's redaction
                    # and line context. The old "only if longer" gate froze stale
                    # snippets on re-scan — leaving wrong-line highlights, old
                    # over-masking, and pre-fix cleartext in place. The snippet is
                    # a presentation field (line_start/line_end already refresh
                    # above), so the latest detection should always win.
                    if enriched_snippet:
                        existing.code_snippet = enriched_snippet
                        existing.code_hash = chash

                    # DON'T reset classification, AI analysis, or remediation
                    # These persist across scans — that's the whole point

                    # Merge new source_metadata fields (commit info, file_context, verification)
                    # without overwriting existing AI/verification data
                    rd = pf.raw_data or {}
                    merge_fields = ["file_context", "is_placeholder", "commit_sha", "commit_author", "commit_date", "commit_message",
                                    "validation_status", "verification_details", "blast_radius"]
                    updated_sm = dict(existing.source_metadata or {})
                    for mf in merge_fields:
                        val = rd.get(mf)
                        if val is not None:
                            updated_sm[mf] = val
                    existing.source_metadata = updated_sm

                    # S3: keep verified-dead suppression in sync on re-seen
                    # findings. Suppress when newly verified inactive; REVERSE
                    # our own suppression if the credential is live again (only
                    # touch rows WE suppressed — never override other reasons
                    # like correlation's "duplicate_same_scanner").
                    if _should_suppress_inactive(rd):
                        if not existing.is_suppressed:
                            suppressed_inactive_count += 1
                        existing.is_suppressed = True
                        existing.suppression_reason = "verified_inactive"
                        if existing.incident_id:
                            _mark_incident_inactive.add(existing.incident_id)
                    elif (rd.get("validation_status") == "active"
                          and existing.suppression_reason == "verified_inactive"):
                        existing.is_suppressed = False
                        existing.suppression_reason = None
                        if existing.incident_id:
                            _mark_incident_active.add(existing.incident_id)

                    updated_count += 1
                    # Track for later steps
                    existing.scan_job_id = job.id  # Point to current scan for stats

                else:
                    # ── Rule-override gate ────────────────────────────
                    # An admin has muted this rule for this repo (or
                    # org-wide); skip the CREATE so no NormalizedFinding
                    # row is written.  Only applies to NEW findings:
                    # the UPDATE branch above keeps existing rows fresh
                    # so muting a rule doesn't accidentally auto-resolve
                    # historical findings (which the stale-cleanup at the
                    # end of the loop would otherwise do).
                    if branded_rule_id and branded_rule_id in muted_rule_ids:
                        block_counts[branded_rule_id] += 1
                        # Mark this stability_id as seen so the
                        # stale-cleanup pass DOES NOT auto-resolve any
                        # existing finding for this rule + location
                        # (the rule "fired", we just didn't persist).
                        # Without this, every muted-rule hit would race
                        # the stale-cleanup branch.
                        seen_stability_ids.add(sid)
                        continue

                    # ── CREATE new finding ──
                    # Upsert incident first so we have the FK ready.
                    incident_uuid = await _upsert_incident_for_repo(secret_hash, pf, now)
                    # S3: auto-suppress a brand-new finding whose credential was
                    # verified DEAD this scan by an allowlisted provider. Stored
                    # (audit-preserving) but is_suppressed → hidden from default
                    # active-risk views.
                    _supp_inactive = _should_suppress_inactive(pf.raw_data or {})
                    if _supp_inactive:
                        suppressed_inactive_count += 1
                    finding = NormalizedFinding(
                        scan_job_id=job.id,
                        repository_id=repo.id,
                        tenant_id=job.tenant_id,
                        scanner_name=scanner_name,
                        scanner_rule_id=branded_rule_id,
                        title=(pf.title or "Untitled")[:500],
                        description=pf.description,
                        vulnerability_category=category_clean,
                        cwe=cwe_clean,
                        severity=normalize_severity(pf.severity),
                        file_path=file_path_clean,
                        line_start=pf.line_start,
                        line_end=pf.line_end,
                        code_snippet=enriched_snippet if enriched_snippet else pf.code_snippet,
                        confidence=pf.confidence,
                        classification=Classification.NEEDS_REVIEW,
                        is_suppressed=_supp_inactive,
                        suppression_reason=("verified_inactive" if _supp_inactive else None),
                        fingerprint=fp,
                        stability_id=sid,
                        incident_id=incident_uuid,
                        code_hash=chash,
                        tags=_derive_path_tags(file_path_clean) or None,
                        first_seen_at=now,
                        last_seen_at=now,
                        last_seen_scan_job_id=job.id,
                        scan_count=1,
                        source_metadata={
                            **(pf.source_info or {}),
                            "detection_engine": detection_engine,
                            "original_rule_id": pf.rule_id,
                            "secret_type": (pf.raw_data or {}).get("secret_type"),
                            "masked_value": (pf.raw_data or {}).get("masked_value"),
                            "secret_hash": (pf.raw_data or {}).get("secret_hash"),
                            "detection_method": (pf.raw_data or {}).get("detection_method"),
                            "entropy_score": (pf.raw_data or {}).get("entropy_score"),
                            "provider": (pf.raw_data or {}).get("provider"),
                            # Inline verification results (populated pre-storage, raw value stripped)
                            "validation_status": (pf.raw_data or {}).get("validation_status"),
                            "verification_details": (pf.raw_data or {}).get("verification_details"),
                            "verification_permissions": (pf.raw_data or {}).get("verification_permissions"),
                            "blast_radius": (pf.raw_data or {}).get("blast_radius"),
                            "file_context": (pf.raw_data or {}).get("file_context"),
                            "is_placeholder": (pf.raw_data or {}).get("is_placeholder"),
                            "commit_sha": (pf.raw_data or {}).get("commit_sha"),
                            "commit_author": (pf.raw_data or {}).get("commit_author"),
                            "commit_date": (pf.raw_data or {}).get("commit_date"),
                            "commit_message": (pf.raw_data or {}).get("commit_message"),
                            # _raw_value_for_verification is intentionally NOT included — never persisted
                        },
                        sink_metadata=pf.sink_info,
                    )
                    db.add(finding)
                    created_count += 1

                    # Store code evidence for new findings only
                    if enriched_snippet:
                        await db.flush()
                        evidence = FindingEvidence(
                            finding_id=finding.id,
                            evidence_type="code_context",
                            file_path=pf.file_path,
                            line_start=max(1, (pf.line_start or 1) - 15),
                            content=enriched_snippet,
                            summary=f"Code at {pf.file_path}:{pf.line_start} (±15 lines)",
                        )
                        db.add(evidence)

                # Phase-A L2: chunk boundary. Flush all pending changes and
                # release locks every STORING_CHUNK_SIZE successfully-handled
                # findings. The single `!= _last_chunk_count` guard makes the
                # check idempotent across iterations that fell through
                # without incrementing the counters (e.g. seen_fps /
                # seen_stability_ids skips). On a finding-dense scan this
                # turns one minutes-long row-lock hold into ~N short ones,
                # surfaces partial progress, and means a mid-storing crash
                # only loses the current chunk.
                _processed = created_count + updated_count
                if _processed and _processed % STORING_CHUNK_SIZE == 0 and _processed != _last_chunk_count:
                    _last_chunk_count = _processed
                    # P0 — live storing counter + bar climb (56 -> 70) so the
                    # storing phase shows motion instead of a frozen 70%.
                    # Monotonic (job.progress_pct only ever increases; the
                    # _emit_phase clamp respects it too).
                    _store_total = max(len(raw_findings), 1)
                    _store_pct = 56 + int(round(14 * min(1.0, _processed / _store_total)))
                    job.status_message = f"[6/8] Storing {_processed:,}/{_store_total:,} findings..."
                    if (job.progress_pct or 0) < _store_pct:
                        job.progress_pct = _store_pct
                    # Sprint G-2 — committing a storing chunk is real
                    # progress; advance heartbeat_at on the main session
                    # so it rides this chunk's commit (no second
                    # connection → no row-lock self-deadlock). Keeps the
                    # watchdog satisfied through a long (minutes) storing
                    # phase.
                    await _stamp_heartbeat_main(job, db, commit=False)
                    await db.flush()
                    await db.commit()
                    # Live WS publish (cheap; no DB write).
                    try:
                        from services.pubsub.redis_pubsub import publish_scan_progress
                        await publish_scan_progress(
                            scan_job_id, "running", _store_pct, job.status_message,
                            {"stored": _processed, "store_total": _store_total},
                        )
                    except Exception:
                        pass

            # Phase-A L2: restore the session's expire_on_commit so the
            # rest of the scan behaves identically to before this block.
            db.sync_session.expire_on_commit = _prev_expire_on_commit

            # ── Persist rule-override block counts ────────────────
            # Aggregate the per-rule block tallies into a single
            # UPDATE per rule_id so admin "blocked N findings" stats
            # stay accurate.  No-op when nothing was blocked.
            await record_blocks(db, job.tenant_id, block_counts, repository_id=repo.id)

            # ── Refresh occurrence_count on touched incidents ──
            # Same post-scan stat refresh as the source-scan path:
            # COUNT(*) on linked findings is authoritative; in-loop
            # increments would double-count on re-scan + update path.
            if incident_cache:
                from sqlalchemy import update as sa_update
                inc_ids = list(incident_cache.values())
                counts = await db.execute(
                    select(
                        NormalizedFinding.incident_id,
                        sa_func.count(NormalizedFinding.id),
                    )
                    .where(NormalizedFinding.incident_id.in_(inc_ids))
                    .group_by(NormalizedFinding.incident_id)
                )
                for inc_id, ct in counts.all():
                    await db.execute(
                        sa_update(SecretIncident)
                        .where(SecretIncident.id == inc_id)
                        .values(occurrence_count=ct)
                    )

            # ── Mark stale findings as resolved ──────────────────
            # Findings that existed in a previous scan but were NOT produced by
            # this scan are "stale" — the detection rule no longer fires (either
            # the code was remediated, or the rule was refined to skip FPs).
            # Mark them as resolved so they no longer show up as active findings.
            stale_count = 0
            from apps.api.app.models.finding import RemediationStatus as RS
            for sid, existing_f in existing_by_stability.items():
                if sid not in seen_stability_ids:
                    # This finding was NOT reproduced by the current scan
                    # Only auto-resolve if it hasn't been manually triaged
                    cur_status = existing_f.remediation_status
                    if cur_status is None or cur_status == RS.NONE or str(cur_status).lower() in ("none", "remediationstatus.none"):
                        existing_f.remediation_status = RS.APPLIED
                        sm = dict(existing_f.source_metadata or {})
                        sm["auto_resolved"] = True
                        sm["auto_resolved_reason"] = "not_found_in_rescan"
                        sm["auto_resolved_scan_id"] = str(job.id)
                        existing_f.source_metadata = sm
                        stale_count += 1

            # #1b: flip incident validation_status for re-seen findings whose
            # credential went dead/live this scan (the CREATE path already does
            # this via the incident upsert). Bulk UPDATEs so the #1 dashboard
            # filter hides/shows the incident without waiting for a re-verify.
            # Reactivation only flips incidents we'd previously marked inactive.
            if _mark_incident_inactive or _mark_incident_active:
                from sqlalchemy import update as _sa_update
                if _mark_incident_inactive:
                    await db.execute(
                        _sa_update(SecretIncident)
                        .where(SecretIncident.id.in_(_mark_incident_inactive))
                        .values(validation_status="inactive")
                    )
                if _mark_incident_active:
                    await db.execute(
                        _sa_update(SecretIncident)
                        .where(SecretIncident.id.in_(_mark_incident_active),
                               SecretIncident.validation_status == "inactive")
                        .values(validation_status="active")
                    )

            await db.commit()

            logger.info("findings_stored",
                scan_job_id=scan_job_id,
                created=created_count,
                updated=updated_count,
                stale_resolved=stale_count,
                suppressed_verified_inactive=suppressed_inactive_count,
                total_raw=len(raw_findings),
            )

            # ── Step 4b: Apply org-wide learned suppressions ──────
            if created_count > 0:
                try:
                    from services.learning.pattern_learner import apply_learned_suppressions
                    new_findings_result = await db.execute(
                        select(NormalizedFinding).where(NormalizedFinding.scan_job_id == job.id)
                    )
                    new_findings = new_findings_result.scalars().all()
                    suppressed = await apply_learned_suppressions(db, job.tenant_id, new_findings)
                    if suppressed > 0:
                        logger.info("org_learning_applied", suppressed=suppressed, scan_job_id=scan_job_id)
                        await db.commit()
                except Exception as le:
                    logger.warning("org_learning_failed", error=str(le)[:200])

            # ── Step 4c: Run multi-scanner correlation ────────────
            if created_count > 0:
                try:
                    from services.correlation.engine import correlate_findings
                    groups = await correlate_findings(db, repo.id, job.id)
                    if groups > 0:
                        logger.info("correlation_complete", groups=groups, scan_job_id=scan_job_id)
                        await db.commit()
                except Exception as ce:
                    logger.warning("correlation_failed", error=str(ce)[:200])

            # ── Step 4c: Deleted-file tombstones ──────────────────
            # When the incremental scan's diff window includes file
            # deletions, every existing finding pointing at one of
            # those paths is no longer actionable — the source file
            # is gone. Mark them ``RESOLVED_FILE_DELETED`` so:
            #   - dashboard "open findings" counts drop appropriately
            #   - MTTR / SLA metrics see the closure event
            #   - audit trail is preserved (the row stays, just with
            #     a different classification)
            #
            # ``last_seen_at`` is intentionally NOT updated — the
            # finding wasn't seen in this scan; it was *resolved*.
            # We DO record the resolving scan via a tag in
            # ``source_metadata`` so the audit trail can answer
            # "which scan / commit / author closed this finding?".
            tombstoned_count = 0
            if incremental_used and deleted_files_in_diff:
                try:
                    from apps.api.app.models.finding import Classification as _Cls
                    # Only tombstone findings that are still "open" —
                    # don't overwrite a user's manual classification
                    # (e.g. they marked it ACCEPTED_RISK and the file
                    # was later deleted; the accepted-risk audit
                    # trail is more valuable than the file-deleted
                    # one).
                    open_classifications = (
                        _Cls.NEEDS_REVIEW,
                        _Cls.LIKELY_TRUE_POSITIVE,
                        _Cls.LIKELY_FALSE_POSITIVE,
                    )
                    # asyncpg's prepared-statement protocol resolves
                    # parameter types at bind time, BEFORE evaluating
                    # any CAST/jsonb_build_object expressions. Passing
                    # raw text params into ``jsonb_build_object``
                    # produces ``IndeterminateDatatypeError``, and so
                    # does ``ANY(CAST(:paths AS text[]))``.
                    #
                    # Workaround: precompute BOTH the metadata patch
                    # AND the path list as JSON strings in Python,
                    # bind each as JSONB. Both have unambiguous
                    # asyncpg types. The SQL becomes a clean
                    # ``COALESCE || :patch`` and a clean
                    # ``IN (jsonb_array_elements_text(:paths))`` —
                    # no CAST through a parameter, no
                    # jsonb_build_object on bound params.
                    import json as _json
                    from datetime import datetime as _dt, timezone as _tz
                    metadata_patch = {
                        "resolved_by_scan_job_id": str(job.id),
                        "resolved_by_commit": current_head_sha,
                        "resolved_at": _dt.now(_tz.utc).isoformat(),
                        "resolution_reason": "file_deleted",
                    }
                    update_result = await db.execute(
                        text(
                            """
                            UPDATE normalized_findings
                               SET classification   = 'RESOLVED_FILE_DELETED',
                                   updated_at       = now(),
                                   source_metadata  = COALESCE(source_metadata, '{}'::jsonb)
                                                      || CAST(:meta_patch AS jsonb)
                             WHERE repository_id = :rid
                               AND tenant_id     = :tid
                               AND file_path IN (
                                   SELECT jsonb_array_elements_text(
                                       CAST(:paths AS jsonb)
                                   )
                               )
                               AND classification::text IN
                                   ('NEEDS_REVIEW','LIKELY_TRUE_POSITIVE','LIKELY_FALSE_POSITIVE',
                                    'needs_review','likely_true_positive','likely_false_positive')
                            """
                        ),
                        {
                            "rid": repo.id,
                            "tid": job.tenant_id,
                            "meta_patch": _json.dumps(metadata_patch),
                            "paths": _json.dumps(list(deleted_files_in_diff)),
                        },
                    )
                    tombstoned_count = update_result.rowcount or 0
                    if tombstoned_count > 0:
                        await db.commit()
                        logger.info(
                            "deleted_file_tombstones_applied",
                            scan_job_id=scan_job_id,
                            repository_id=str(repo.id),
                            deleted_files=len(deleted_files_in_diff),
                            findings_resolved=tombstoned_count,
                        )
                except Exception as te:
                    logger.warning(
                        "deleted_file_tombstone_failed",
                        scan_job_id=scan_job_id,
                        error=str(te)[:200],
                    )

            # ── Step 4d: Apply decision cache (Stability ID) ────────
            cache_hits = 0
            cache_invalidated = 0
            cache_new = 0
            if created_count > 0:
                try:
                    from services.normalization.stability import compute_stability_id, compute_code_hash, compute_pattern_hash
                    from services.normalization.decision_cache import lookup_cache

                    findings_for_cache = await db.execute(
                        select(NormalizedFinding).where(
                            NormalizedFinding.scan_job_id == job.id,
                            NormalizedFinding.classification == Classification.NEEDS_REVIEW,
                        )
                    )
                    all_findings = findings_for_cache.scalars().all()

                    # ── Test File Handling: "exclude" ────────────────
                    # The AI decision cache runs BEFORE _run_ai_triage and
                    # stamps ai_explanation / classification straight from
                    # a previous verdict, so filtering the triage list
                    # alone is not enough — the cache has to honour
                    # `exclude` as well.
                    #
                    # These findings remain stored and visible; they
                    # simply carry no AI verdict.
                    if test_file_handling == "exclude" and all_findings:
                        from services.secret_scan.engine import _classify_file_context as _cfc3
                        _pre = len(all_findings)
                        all_findings = [
                            f for f in all_findings
                            if _cfc3(f.file_path or "") != "test_file"
                        ]
                        if _pre != len(all_findings):
                            logger.info(
                                "test_file_findings_excluded_from_decision_cache",
                                scan_job_id=scan_job_id,
                                skipped=_pre - len(all_findings),
                            )

                    for f in all_findings:
                        # Only compute stability ID if not already set
                        if not f.stability_id:
                            sid = compute_stability_id(
                                f.scanner_rule_id or "",
                                f.file_path or "",
                                f.code_snippet or "",
                                f.function_name,
                                f.cwe,
                            )
                            f.stability_id = sid
                        else:
                            sid = f.stability_id

                        chash = compute_code_hash(f.code_snippet or "")
                        f.code_hash = chash

                        # Check cache (exact match only — same file, same code, same location)
                        cache_result = await lookup_cache(
                            db=db,
                            tenant_id=job.tenant_id,
                            repository_id=repo.id,
                            stability_id=sid,
                            code_hash=chash,
                        )

                        if cache_result.hit:
                            # Apply cached classification — skip AI for this finding
                            classification_map = {
                                "likely_true_positive": Classification.LIKELY_TRUE_POSITIVE,
                                "likely_false_positive": Classification.LIKELY_FALSE_POSITIVE,
                                "confirmed_true_positive": Classification.CONFIRMED_TRUE_POSITIVE,
                                "confirmed_false_positive": Classification.CONFIRMED_FALSE_POSITIVE,
                                "accepted_risk": Classification.ACCEPTED_RISK,
                                "needs_review": Classification.NEEDS_REVIEW,
                            }
                            f.classification = classification_map.get(
                                cache_result.classification, Classification.NEEDS_REVIEW
                            )
                            # G1b — a cached triage result may predate the
                            # scrub (or come from another finding's run), so
                            # mask secret shapes in its free text on apply too.
                            from services.secret_scan.engine import scrub_secrets_in_obj as _scrub_obj
                            f.ai_confidence = cache_result.ai_confidence
                            f.ai_explanation = _scrub_obj(cache_result.ai_explanation)
                            f.exploitability_score = cache_result.exploitability_score
                            f.true_positive_reasons = _scrub_obj(cache_result.true_positive_reasons)
                            f.false_positive_reasons = _scrub_obj(cache_result.false_positive_reasons)
                            f.compensating_controls = _scrub_obj(cache_result.compensating_controls)
                            f.ai_evidence_refs = cache_result.ai_evidence_refs
                            f.cache_hit = True
                            f.cache_source = f"{cache_result.decided_by}_{cache_result.hit_type}"
                            cache_hits += 1
                        elif cache_result.invalidated:
                            cache_invalidated += 1
                        else:
                            cache_new += 1

                    await db.commit()
                    logger.info("decision_cache_applied",
                        scan_job_id=scan_job_id,
                        cache_hits=cache_hits,
                        cache_invalidated=cache_invalidated,
                        cache_new=cache_new,
                        total=len(all_findings),
                    )
                except Exception as cache_err:
                    logger.warning("decision_cache_failed", error=str(cache_err)[:200])

            # ── Step 5: Run AI false positive analysis ────────────
            triaged = 0
            dedup_saved = 0
            skip_ai = (job.config or {}).get("skip_ai", False)

            # Check for AI availability: env vars OR DB-configured models
            has_ai_env = bool(settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY)
            has_ai_db = False
            if not has_ai_env and not skip_ai:
                try:
                    from apps.api.app.models.ai_model import AIModelConfig
                    db_models = await db.execute(
                        select(AIModelConfig).where(
                            AIModelConfig.tenant_id == job.tenant_id,
                            AIModelConfig.is_active == True,
                        ).limit(1)
                    )
                    has_ai_db = db_models.scalar_one_or_none() is not None
                except Exception:
                    pass

            has_ai = (has_ai_env or has_ai_db) and not skip_ai

            # Count untriaged findings for this repo (new + re-scanned still NEEDS_REVIEW).
            # This ensures AI triage runs on re-scans too, catching findings the user
            # has been waiting for since a previous scan when no AI model was configured.
            from apps.api.app.models.finding import Classification as _Cls
            untriaged_count_q = await db.execute(
                select(sa_func.count(NormalizedFinding.id)).where(
                    NormalizedFinding.repository_id == repo.id,
                    NormalizedFinding.tenant_id == job.tenant_id,
                    NormalizedFinding.classification == _Cls.NEEDS_REVIEW,
                    NormalizedFinding.remediation_status != "APPLIED",
                )
            )
            untriaged_count = untriaged_count_q.scalar() or 0

            # Run AI triage when there are new findings OR existing findings
            # still pending triage. Previously only gated on created_count > 0,
            # which silently skipped triage on every re-scan.
            if (created_count > 0 or untriaged_count > 0) and has_ai:
                triage_target = max(created_count, untriaged_count)
                job.status = ScanStatus.ANALYZING
                job.status_message = f"[7/8] AI False Positive Analysis — analyzing {triage_target} findings..."
                job.progress_pct = 65
                try:
                    await _emit_phase("analyzing", 65, job.status_message, step=7)
                except Exception:
                    pass
                await db.commit()

                try:
                    triaged, dedup_saved, failure_summary = await _run_ai_triage(db, job, repo_path)

                    # Count results
                    from apps.api.app.models.finding import Classification as Cls
                    fp_after_triage = await db.execute(
                        select(sa_func.count(NormalizedFinding.id)).where(
                            NormalizedFinding.scan_job_id == job.id,
                            NormalizedFinding.classification.in_([Cls.LIKELY_FALSE_POSITIVE, Cls.CONFIRMED_FALSE_POSITIVE]),
                        )
                    )
                    tp_after_triage = await db.execute(
                        select(sa_func.count(NormalizedFinding.id)).where(
                            NormalizedFinding.scan_job_id == job.id,
                            NormalizedFinding.classification == Cls.LIKELY_TRUE_POSITIVE,
                        )
                    )
                    fp_count_after = fp_after_triage.scalar() or 0
                    tp_count_after = tp_after_triage.scalar() or 0

                    job.status_message = f"[7/8] FP Analysis complete — {fp_count_after} false positives, {tp_count_after} true positives identified"
                    job.progress_pct = 75
                    await _emit_phase("analyzing", 75, job.status_message, step=7, stats={"false_positives": fp_count_after, "true_positives": tp_count_after})
                    await db.commit()
                    logger.info("ai_triage_done", scan_job_id=scan_job_id, triaged=triaged, fp=fp_count_after, tp=tp_count_after, failure_summary=failure_summary)

                    # ── Triage health check ─────────────────────────────
                    # When triage runs but produces no classifications (both
                    # TP and FP are 0 despite triaged > 0), something upstream
                    # is broken. The `failure_summary` dict classifies the
                    # root cause (upstream_error, truncated_response,
                    # invalid_json, empty_response) so the UI badge and
                    # notification can give actionable guidance instead of a
                    # one-size-fits-all "check stop_sequences" hint.
                    try:
                        classified = fp_count_after + tp_count_after
                        parse_failure_rate = (
                            1.0 - (classified / triaged) if triaged > 0 else 0.0
                        )
                        await _emit_triage_health_signal(
                            db=db,
                            tenant_id=job.tenant_id,
                            scan_job_id=job.id,
                            triaged=triaged,
                            classified=classified,
                            parse_failure_rate=parse_failure_rate,
                            failure_summary=failure_summary,
                        )
                    except Exception as sig_err:
                        logger.warning("triage_health_signal_failed", error=str(sig_err)[:200])

                except ScanCancelled:
                    # A cancel is a requested stop, not an AI failure —
                    # "continue with unreviewed findings" is the wrong
                    # response to it.
                    raise
                except Exception as ai_err:
                    logger.error("ai_triage_failed_continuing", scan_job_id=scan_job_id, error=str(ai_err)[:300])
                    job.status_message = f"[7/8] AI analysis encountered errors — continuing with {created_count} unreviewed findings"
                    job.progress_pct = 75
                    await db.commit()

            elif created_count > 0 and not has_ai:
                if skip_ai:
                    job.status_message = f"[7/8] AI analysis skipped by user"
                    logger.info("ai_triage_skipped_by_user", scan_job_id=scan_job_id)
                else:
                    job.status_message = f"[7/8] AI analysis skipped — no API key configured"
                    logger.warning("ai_triage_skipped_no_key", scan_job_id=scan_job_id)
                job.progress_pct = 75
                await db.commit()

            # ── Step 5b: Auto-generate remediation for ALL true positives ──
            # Remediation code is generated automatically so users see fixes
            # immediately. Applying the fix (PR/branch) is user-action driven.
            auto_remediated = 0
            if triaged > 0 and has_ai:
                try:
                    # Find ALL true positives from this scan
                    tp_findings = await db.execute(
                        select(NormalizedFinding).where(
                            NormalizedFinding.scan_job_id == job.id,
                            NormalizedFinding.classification == Cls.LIKELY_TRUE_POSITIVE,
                        )
                    )
                    tp_list = tp_findings.scalars().all()

                    if tp_list:
                        job.status_message = f"[7b/8] Auto Remediation — generating secure code fixes for {len(tp_list)} true positives..."
                        job.progress_pct = 85
                        try:
                            await _emit_phase("analyzing", 85, job.status_message, step=7)
                        except Exception:
                            pass
                        await db.commit()

                    for finding in tp_list:
                        finding.remediation_status = "pending"
                        generate_remediation.delay(str(finding.id))
                        auto_remediated += 1

                    if auto_remediated > 0:
                        await db.commit()
                        logger.info("auto_remediation_queued", scan_job_id=scan_job_id, count=auto_remediated)

                except Exception as ar_err:
                    logger.warning("auto_remediation_failed", error=str(ar_err)[:200])

            elif created_count > 0 and not has_ai:
                if skip_ai:
                    job.status_message = "[7b/8] Auto Remediation skipped by user"
                else:
                    job.status_message = "[7b/8] Auto Remediation skipped — no API key configured"
                job.progress_pct = 90
                await db.commit()

            # ── Step 5c: Secret Validation (verify if detected secrets are active) ──
            try:
                from services.secret_validation.engine import SecretValidationEngine, ValidationStatus
                validation_engine = SecretValidationEngine()

                tp_findings = await db.execute(
                    select(NormalizedFinding).where(
                        NormalizedFinding.scan_job_id == job.id,
                        NormalizedFinding.classification.notin_(["likely_false_positive", "confirmed_false_positive"]),
                        NormalizedFinding.is_suppressed == False,
                    )
                )
                tp_list = tp_findings.scalars().all()

                validated_count = 0
                for finding in tp_list:
                    sm = finding.source_metadata or {}
                    secret_type = sm.get("secret_type")
                    if not secret_type:
                        continue

                    # We don't have the raw secret value in DB (by design — security).
                    # Validation runs on findings that the scanner just found,
                    # using the secret_hash for dedup. In a production setup,
                    # validation would run in the scanner process before DB storage.
                    # For now, mark as NOT_VALIDATED and let users trigger validation
                    # manually via the API for specific findings.
                    if not sm.get("validation_status"):
                        sm["validation_status"] = ValidationStatus.NOT_VALIDATED.value
                        sm["validated_at"] = None
                        finding.source_metadata = {**sm}
                        validated_count += 1

                if validated_count > 0:
                    await db.commit()
                    logger.info("secret_validation_status_set", scan_job_id=scan_job_id, count=validated_count)

            except Exception as ve:
                logger.warning("secret_validation_step_failed", error=str(ve)[:200])

            # ── Step 6: Complete ────────────────────────────────────
            # Compute stats
            severity_counts = {}
            for sev in ["critical", "high", "medium", "low", "info"]:
                cnt_result = await db.execute(
                    select(sa_func.count(NormalizedFinding.id)).where(
                        NormalizedFinding.scan_job_id == job.id,
                        NormalizedFinding.severity == sev,
                    )
                )
                severity_counts[sev] = cnt_result.scalar() or 0

            fp_count_result = await db.execute(
                select(sa_func.count(NormalizedFinding.id)).where(
                    NormalizedFinding.scan_job_id == job.id,
                    NormalizedFinding.classification.in_(["likely_false_positive", "confirmed_false_positive"]),
                )
            )
            # Count of findings that carry an AI verdict (FP OR TP) — INCLUDING the
            # ones whose verdict was inherited via dedup from a prior scan (this
            # scan's own ``triaged`` is 0 in that case). The scan card gates the
            # "AI triage pending — configure AI model" text AND the Run-AI-Triage
            # button on ``ai_triaged === 0``; a clean re-scan whose findings are
            # already triaged must report them here or the card falsely reads
            # "pending" / re-offers triage. (Consistent with how false_positives
            # above is a classification-based count, not a this-run count.)
            ai_classified_result = await db.execute(
                select(sa_func.count(NormalizedFinding.id)).where(
                    NormalizedFinding.scan_job_id == job.id,
                    NormalizedFinding.classification.in_([
                        "likely_false_positive", "confirmed_false_positive",
                        "likely_true_positive", "confirmed_true_positive",
                    ]),
                )
            )

            # Step 7 (policy evaluation) removed 2026-05-16 — the
            # services.policy_engine module was deleted along with the
            # governance surfaces.  These two flags stay around as constants
            # because downstream completion-summary + scan-metrics payloads
            # still reference them; the metric will now always read "passed".
            policy_passed = True
            policy_violations = 0

            # ── Step 8: Generate metrics snapshot ─────────────────
            try:
                from services.reporting.generator import generate_scan_metrics
                await generate_scan_metrics(db, job.id, job.tenant_id, repo.id)
            except Exception as me:
                logger.warning("metrics_snapshot_failed", error=str(me)[:200])

            # ── Step 9: Complete ──────────────────────────────────
            # Re-read the status before claiming success: an operator may
            # have cancelled while the last phase was running, and a
            # cancelled scan must not be reported as COMPLETED. This is
            # the final guard — cooperative cancellation normally aborts
            # long before here — so it only has to be correct, not fast.
            _final_status = await db.scalar(
                select(ScanJob.status).where(ScanJob.id == job.id)
            )
            if _final_status == ScanStatus.CANCELLED:
                logger.info(
                    "scan_completion_suppressed_by_cancel",
                    scan_job_id=str(job.id),
                )
                raise ScanCancelled(str(job.id))

            job.status = ScanStatus.COMPLETED
            fp_count = fp_count_result.scalar() or 0
            ai_classified_count = ai_classified_result.scalar() or 0
            job.progress_pct = 100

            # Build completion message with pipeline summary.
            #
            # AI-status messaging precision (Track-A, Vooda Scan Intel
            # audit follow-up 2026-05-24): the old branch said
            # "AI analysis pending (configure API key)" whenever
            # `has_ai` was False — but `has_ai` is False in three
            # very different situations:
            #   1. User deliberately set ``config.skip_ai=true`` from
            #      the UI's "Scan Without AI" option.
            #   2. Tenant has no AI provider configured at all.
            #   3. AI was effectively a no-op (every new finding hit
            #      the decision_cache so no AI call was needed).
            # Showing "configure API key" for cases 1 and 3 is misleading
            # and erodes trust ("why is the message telling me to
            # configure something I already configured?").  Emit the
            # right label per case.
            # ── Triage-coverage assertion ────────────────────────────
            # A scan must not report clean success while findings it
            # was supposed to triage carry no AI verdict. `triaged > 0`
            # is not sufficient on its own: partial coverage would
            # otherwise be indistinguishable from total coverage, so the
            # count is asserted explicitly and surfaced to the UI.
            #
            # Counted from the DB rather than in-memory counters, so it
            # reflects what a user actually sees in the findings list.
            # NB: named distinctly from the pre-triage `untriaged_count`
            # above (which is repo-wide and decides WHETHER to run
            # triage). This one is scan-scoped and measures what THIS
            # scan actually covered — so a previous scan's deliberate
            # skip_ai is never blamed on this run. `ai_explanation IS
            # NULL` also excludes genuine AI abstentions (the model
            # answered "needs a human"), leaving only findings that
            # never got a verdict at all.
            untriaged_after_count = 0
            if has_ai and not skip_ai:
                untriaged_after_q = await db.execute(
                    select(sa_func.count(NormalizedFinding.id)).where(
                        NormalizedFinding.scan_job_id == job.id,
                        NormalizedFinding.classification == Classification.NEEDS_REVIEW,
                        NormalizedFinding.ai_explanation.is_(None),
                    )
                )
                untriaged_after_count = untriaged_after_q.scalar() or 0

            parts = [f"[8/8] Complete — {created_count} findings"]
            if triaged > 0:
                parts.append(f"{fp_count} FP removed")
            _coverage_warning = _triage_coverage_warning(untriaged_after_count)
            if _coverage_warning:
                # Surfaced in the completion banner, not buried in logs —
                # the operator must see that coverage was incomplete.
                parts.append(_coverage_warning)
                logger.warning(
                    "scan_completed_with_incomplete_triage",
                    scan_job_id=str(job.id),
                    untriaged=untriaged_after_count,
                    triaged=triaged,
                    findings_total=created_count,
                )
            if auto_remediated > 0:
                parts.append(f"{auto_remediated} fixes generated")
            if created_count > 0 and triaged == 0:
                if skip_ai:
                    parts.append("AI triage skipped (user choice)")
                elif not has_ai:
                    parts.append("AI triage skipped — no provider configured")
                elif cache_hits >= created_count:
                    # Healthy fast-path: every new finding had a prior
                    # AI classification cached.  Don't surface a
                    # warning — this is the system working as designed.
                    pass
                else:
                    # has_ai=True + skip_ai=False + ai_triaged=0 + not
                    # all-cached → AI was supposed to run but didn't.
                    # That's the real "something broke" case.
                    parts.append("AI triage did not run — check provider health")
            job.status_message = " · ".join(parts)

            job.stats = {
                "files_analyzed": analysis.total_files,
                # Use sum of severity_counts (DB-queried) rather than created+updated
                # to avoid double-counting when scanner emits duplicate raw findings
                # that share a stability_id (same rule+file+content).
                "findings_total": sum(severity_counts.values()),
                "findings_new": created_count,
                "findings_existing": updated_count,
                "findings_by_severity": severity_counts,
                "false_positives": fp_count,
                # Machine-readable coverage signal: >0 means the scan
                # completed with findings that never received an AI
                # verdict. Lets the API/UI flag an incomplete scan
                # instead of relying on operators parsing the message.
                "untriaged_findings": untriaged_after_count,
                # ── Credential verification funnel (S1–S3) ──
                # How many findings were live-verified this scan, the
                # active/dead split, and how many dead ones were auto-
                # suppressed (allowlist-gated). Surfaces the FP-reduction
                # lever in the scan card / scan-job stats.
                "credentials_verified": verified_count,
                "credentials_active": active_count,
                "credentials_inactive": max(0, verified_count - active_count),
                "credentials_suppressed": suppressed_inactive_count,
                # AI-triaged = findings carrying an AI verdict (this run's
                # `triaged` OR an inherited verdict), so a clean re-scan reads
                # "N AI-triaged" instead of a false "AI triage pending".
                "ai_triaged": max(triaged, ai_classified_count),
                "auto_remediated": auto_remediated,
                "cache_hits": cache_hits,
                "cache_invalidated": cache_invalidated,
                "cache_new": cache_new,
                "ai_calls_saved": cache_hits + dedup_saved,  # Cache hits + dedup savings
                "dedup_saved": dedup_saved,
                "languages": list(analysis.languages.keys()),
                "engine": "Vooda AI Engine",
                "policy_passed": policy_passed,
                "policy_violations": policy_violations,
                # Incremental-scan telemetry — surfaced in the UI so
                # users can see whether a given run walked the whole
                # repo or only the diff since last_scanned_commit.
                "incremental": incremental_used,
                "incremental_files": incremental_files if incremental_used else None,
                "checkpoint_base": base_sha_checkpoint if incremental_used else None,
                "checkpoint_head": current_head_sha,
                "force_full": force_full,
                # Deleted-file tombstones — count of findings closed
                # this scan because their source file was removed.
                # Surfaced for SLA dashboards: a closure-via-deletion
                # is fundamentally different from a closure-via-rotation
                # for compliance reporting.
                "deleted_files_in_diff": len(deleted_files_in_diff),
                "findings_tombstoned": tombstoned_count,
                # File-level cache telemetry. ``rule_pack_version`` is
                # the input fingerprint that cached entries are bound
                # to — when the rule pack changes (built-in or
                # custom), this string changes and every cached row
                # invalidates automatically. Surfacing it in stats
                # gives auditors / debuggers a way to confirm exactly
                # which rule set produced the findings on a given
                # scan, and gives the dashboard a "cached vs
                # re-scanned" breakdown without an extra DB query.
                "rule_pack_version": scanner.rule_pack_version,
                "file_cache_hits": file_cache_hits,
                "file_cache_misses": file_cache_misses,
                "file_cache_hit_rate": round(file_cache_hit_rate, 3),
                "file_cache_rows_written": file_cache_rows_written,
            }

            # Advance the per-(repo, branch) checkpoint so the NEXT
            # scan on this branch only walks files changed after this
            # commit. History scans don't write a checkpoint — they
            # cover the entire commit graph and would otherwise turn
            # the next standalone scan into a no-op for any commits
            # older than the history scan's HEAD.
            if current_head_sha and scan_type_val != "history":
                # 1) New per-branch table — the source of truth from
                #    here on. Upserts so the row evolves as the branch
                #    advances.
                try:
                    await db.execute(
                        text(
                            """
                            INSERT INTO repo_branch_checkpoints (
                                tenant_id, repository_id, branch,
                                last_scanned_commit, last_scanned_at
                            ) VALUES (
                                :tid, :rid, :br, :sha, now()
                            )
                            ON CONFLICT (repository_id, branch)
                            DO UPDATE SET
                                last_scanned_commit = EXCLUDED.last_scanned_commit,
                                last_scanned_at     = EXCLUDED.last_scanned_at,
                                updated_at          = now()
                            """
                        ),
                        {
                            "tid": job.tenant_id,
                            "rid": repo.id,
                            "br": scan_branch,
                            "sha": current_head_sha,
                        },
                    )
                except Exception as _cw_err:
                    logger.warning(
                        "branch_checkpoint_write_failed",
                        scan_job_id=scan_job_id,
                        branch=scan_branch,
                        error=str(_cw_err)[:200],
                    )

                # 2) Legacy single-checkpoint column — still updated
                #    so any external tool / dashboard reading
                #    ``repositories.last_scanned_commit`` directly
                #    gets a sensible value. Only writes when the
                #    scanned branch IS the repo's default branch —
                #    otherwise a feature-branch scan would corrupt
                #    the legacy main-branch checkpoint, which is
                #    exactly the bug this whole gap was fixing.
                if scan_branch == (repo.default_branch or "main"):
                    repo.last_scanned_commit = current_head_sha
            # WS-1: emit the terminal phase event BEFORE the commit so the
            # completed/100% row lands in the SAME transaction as the final
            # job state.  Emitting it after db.commit() (as it was) only
            # db.add()+flush()ed the row into a session that was never
            # committed again — so the persisted timeline ended at step
            # 7/85% and the "done" row silently vanished (validated live,
            # scan 47c8dbb4).
            await _emit_phase("completed", 100, job.status_message, step=8, stats=job.stats)
            await db.commit()

            # ── Step 10: Send notifications ──────────────────────
            try:
                critical_count = severity_counts.get("critical", 0)
                high_count = severity_counts.get("high", 0)
                notif_severity = "critical" if critical_count > 0 else "warning" if high_count > 0 else "info"
                send_notification.delay(
                    str(job.tenant_id),
                    f"Scan complete: {repo.name}",
                    f"Found {created_count} findings ({critical_count} critical, {high_count} high). "
                    f"Policy: {'PASSED' if policy_passed else 'FAILED'}.",
                    notif_severity,
                    "scan_complete",
                    "repository",
                    str(repo.id),
                    None,  # url
                    str(repo.business_unit_id) if repo.business_unit_id else None,
                )
            except Exception:
                pass  # Don't fail scan if notification fails

            # ── Step 11: Per-finding ticketing dispatch ───────────
            # Notification (above) is a single summary message to
            # humans on Slack/email. Ticketing wants one ticket per
            # finding on the dev team's Jira/ServiceNow/Linear board
            # with the full defect details. The dispatcher honors
            # the push rules (severity threshold + the four
            # exclusions) saved by the integrations UI per channel.
            try:
                if created_count > 0:
                    dispatch_findings_to_tickets.delay(scan_job_id)
            except Exception:
                pass  # Don't fail the scan if ticketing dispatch fails

        except ScanCancelled:
            # Not a failure. Let it reach run_scan_job, which leaves the
            # row CANCELLED with the operator's own message and releases
            # the repository lock as the exception unwinds.
            raise
        except Exception as e:
            # WS-3′ — guarantee a non-empty, machine-useful error_detail.
            # ``str(asyncio.TimeoutError())`` is the EMPTY STRING, which
            # is exactly why timed-out scans (live: 2c1d1ba4) showed a
            # FAILED badge with a blank reason.  Fall back to the
            # exception type + (for timeouts) an actionable hint.
            from packages.common.logging_config import _redact_string
            detail = _redact_string(str(e)).strip()
            if not detail:
                if isinstance(e, (asyncio.TimeoutError, TimeoutError)):
                    detail = (
                        "Operation timed out (likely git fetch/clone on a large "
                        "repo). Re-run the scan; if it recurs, the repo may exceed "
                        "the fetch timeout — raise GIT_FETCH_TIMEOUT_SECONDS."
                    )
                else:
                    detail = type(e).__name__  # never empty
            logger.error("scan_job_failed", scan_job_id=scan_job_id,
                         error_type=type(e).__name__, error=detail[:200])
            # Recording the failure must itself be failure-proof.
            #
            # If `e` came from a flush, this session is already poisoned
            # and EVERY statement on it — including the commit below —
            # raises PendingRollbackError — which would leave the row
            # stuck at ANALYZING (see _force_terminal_failure).
            #
            # 1) roll back so the session is usable again,
            # 2) write the terminal state,
            # 3) if anything still fails, stamp it from a FRESH session.
            _stamped = False
            try:
                await db.rollback()
                job = await db.get(type(job), job.id)  # re-attach after rollback
                if job is not None:
                    job.status = ScanStatus.FAILED
                    job.error_detail = detail[:2000]
                    await db.commit()
                    _stamped = True
            except Exception as _persist_err:
                logger.warning(
                    "scan_failure_write_on_own_session_failed",
                    scan_job_id=scan_job_id, error=str(_persist_err)[:200],
                )
            if not _stamped:
                await _force_terminal_failure(scan_job_id, detail)
            # WS-9 — emit a scan.failed notification so the same dispatch
            # path that fires on scan_complete (Slack / Teams / PagerDuty /
            # outbound webhook, per the tenant's notification rules) also
            # tells operators a scan FAILED — instead of the failure being
            # visible only to someone watching the dashboard. detail is
            # already redacted (WS-6). Best-effort: never let a notify
            # error mask the original scan failure we're about to re-raise.
            try:
                send_notification.delay(
                    str(job.tenant_id),
                    f"Scan failed: {repo.name}",
                    f"Scan of {repo.name} (branch {scan_branch}) failed: {detail[:500]}",
                    "critical",
                    "scan_failed",
                    "repository",
                    str(repo.id),
                    None,  # url
                    str(repo.business_unit_id) if repo.business_unit_id else None,
                )
            except Exception:
                pass
            raise
        finally:
            # Always release the per-(repo, branch) lock so a follow-up
            # scan can acquire it. The Redis CAS-delete is no-op-safe
            # if the TTL already fired (cleanup beat task or expired
            # via the 2-hour ceiling), so a double-release is fine.
            try:
                await lock_cm.__aexit__(None, None, None)
            except Exception:
                # The lock will TTL-expire if the explicit release
                # somehow misses; the cleanup beat task is the long
                # tail. Never let a lock-release error mask a real
                # scan error from the surrounding except.
                pass
            # WS-5 — clear the bound scan_job_id so it can't leak into
            # the next task this worker process picks up.
            try:
                if clear_request_context is not None:
                    clear_request_context()
            except Exception:
                pass

    logger.info("scan_job_completed", scan_job_id=scan_job_id)

    # Trigger async verification of detected secrets (non-blocking)
    try:
        from apps.worker.celery_app import celery_app as _app
        _app.send_task(
            "apps.worker.tasks.verify_scan_findings",
            kwargs={"scan_job_id": scan_job_id, "tenant_id": str(job.tenant_id)},
        )
        logger.info("verification_task_dispatched", scan_job_id=scan_job_id)
    except Exception as e:
        logger.warning("verification_dispatch_failed", error=str(e)[:100])


def _get_head_sha(repo_path: str) -> Optional[str]:
    """Return the current HEAD commit SHA, or None if the path isn't a git
    working tree (uploaded archive, deleted checkout, etc.).

    Used by the incremental-scan path in ``_run_scan_job`` to compute the
    ``head`` argument for ``scan_diff(base, head)`` and to advance the
    per-repository ``last_scanned_commit`` checkpoint after a successful
    scan finishes.
    """
    import subprocess
    if not repo_path or not os.path.exists(os.path.join(repo_path, ".git")):
        return None
    try:
        # Mark safe.directory in case the working tree is owned by a
        # different uid than the worker process (matches the same
        # treatment used in services/secret_scan/git_history.py).
        subprocess.run(
            ["git", "config", "--global", "--add", "safe.directory", repo_path],
            capture_output=True, timeout=5,
        )
        result = subprocess.run(
            ["git", "-C", repo_path, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            sha = (result.stdout or "").strip()
            return sha or None
    except Exception:
        pass
    return None


def _is_commit_reachable(repo_path: str, sha: str) -> bool:
    """Check whether ``sha`` exists in the cloned repository.

    Returns False when the previous checkpoint commit was rewritten away
    by a force-push, dropped by a rebase, or simply isn't fetched into
    this clone. The worker uses this gate to decide whether the
    incremental ``scan_diff`` path is viable — when False we silently
    fall back to a full ``scan_directory`` re-walk so the user never
    sees stale findings from a dangling checkpoint.
    """
    import subprocess
    if not sha:
        return False
    try:
        # ``git cat-file -e <sha>`` exits 0 if the object exists,
        # non-zero otherwise. Doesn't print anything on success.
        result = subprocess.run(
            ["git", "-C", repo_path, "cat-file", "-e", f"{sha}^{{commit}}"],
            capture_output=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


async def _run_git(args: list[str], *, timeout: int | None = None, label: str = "git", on_progress=None) -> tuple[int, bytes, bytes]:
    """Run a git subprocess with a hard wall-clock timeout that also KILLS
    the spawned process group on expiry (Sprint A-1).

    ``asyncio.wait_for(proc.communicate(), timeout)`` only cancels the
    *await* — it does NOT terminate the child.  A slow ``git fetch`` thus
    kept running as an orphan after the scan had already timed out and
    moved on (live: the aws-cdk hung clone left a git process behind,
    holding the work dir and a connection).  We start the child in its
    own session (``start_new_session=True`` → its own process group) and,
    on timeout, ``SIGKILL`` the whole group (clone forks helpers like
    git-remote-https), reap it, then re-raise ``TimeoutError`` so the
    caller's WS-3′ handler writes the actionable message.

    Returns ``(returncode, stdout, stderr)``.  ``timeout`` defaults to
    ``settings.GIT_FETCH_TIMEOUT_SECONDS``.
    """
    import signal as _signal
    if timeout is None:
        timeout = settings.GIT_FETCH_TIMEOUT_SECONDS
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )

    async def _on_timeout() -> None:
        # Kill the whole process GROUP (clone forks git-remote-https helpers)
        # then reap it so it doesn't linger as a zombie (Sprint A-1).
        try:
            os.killpg(os.getpgid(proc.pid), _signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=10)
        except Exception:
            pass
        # Log without the authenticated URL (may embed a token).
        logger.warning(
            "git_command_timeout", label=label, timeout_s=timeout,
            cmd=" ".join(a for a in args if "://" not in a),
        )

    # ── Fast path: unchanged blocking behaviour for every non-streaming
    # caller (fetch / pull / log / rev-list / …). on_progress is set only
    # by the clone path, so existing callers are byte-for-byte identical. ──
    if on_progress is None:
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode, out, err
        except (asyncio.TimeoutError, TimeoutError):
            await _on_timeout()
            raise

    # ── Streaming path (clone): parse `git --progress` on stderr so the
    # caller gets LIVE progress + a heartbeat, under the SAME absolute
    # wall-clock cap and process-group kill. git writes its progress to
    # stderr (\r-delimited) and negligible stdout, so we stream stderr and
    # drain stdout at the end. Progress callbacks are best-effort. ──
    import time as _time
    import re as _re
    _PROG = _re.compile(rb"(Receiving objects|Resolving deltas|Counting objects|Compressing objects):\s+(\d+)%")
    deadline = _time.monotonic() + timeout
    err_buf = bytearray()
    out_buf = bytearray()
    last_emit = 0.0
    try:
        while True:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError()
            try:
                chunk = await asyncio.wait_for(proc.stderr.read(512), timeout=min(remaining, 30))
            except asyncio.TimeoutError:
                if _time.monotonic() >= deadline:
                    raise
                continue  # git momentarily silent but still within budget
            if not chunk:
                break  # stderr EOF — git finished writing
            err_buf.extend(chunk)
            m = None
            for m in _PROG.finditer(chunk):
                pass  # keep only the latest progress token in this chunk
            if m is not None:
                now = _time.monotonic()
                if now - last_emit >= 1.5:  # throttle DB/UI writes
                    last_emit = now
                    try:
                        await on_progress(m.group(1).decode("ascii", "replace"), int(m.group(2)))
                    except Exception:
                        pass  # progress is best-effort; never break the clone
        try:
            out_buf.extend(await asyncio.wait_for(proc.stdout.read(), timeout=max(1.0, deadline - _time.monotonic())))
        except Exception:
            pass
        await asyncio.wait_for(proc.wait(), timeout=max(1.0, deadline - _time.monotonic()))
        return proc.returncode, bytes(out_buf), bytes(err_buf)
    except (asyncio.TimeoutError, TimeoutError):
        await _on_timeout()
        raise


async def _clone_repository(url: str, repo_id: str, branch: str | None = None, auth: dict | None = None, full_history: bool = False, on_progress=None) -> str:
    """Clone a git repository to local storage. Supports auth via token or username/password."""
    import asyncio

    base_path = os.path.join(settings.STORAGE_PATH, "repos", repo_id)
    os.makedirs(os.path.dirname(base_path), exist_ok=True)

    # Normalise the remote before anything touches it — see
    # packages.common.git_url for the why. Covers rows written before
    # the create endpoint started normalising, and any other write path.
    from packages.common.git_url import normalize_git_url
    url = normalize_git_url(url)

    # Build authenticated URL if credentials provided
    clone_url = url
    if auth and url.startswith("https://"):
        token = auth.get("token") or auth.get("personal_access_token") or auth.get("pat")
        username = auth.get("username")
        password = auth.get("password") or auth.get("app_password")

        if token:
            # Insert token into URL: https://oauth2:TOKEN@github.com/...
            clone_url = url.replace("https://", f"https://oauth2:{token}@")
            logger.info("clone_with_token", repo_id=repo_id)
        elif username and password:
            # Insert user:pass into URL
            clone_url = url.replace("https://", f"https://{username}:{password}@")
            logger.info("clone_with_credentials", repo_id=repo_id)

    if os.path.exists(base_path):
        # Already cloned — check if we need full history
        shallow_file = os.path.join(base_path, ".git", "shallow")
        if full_history:
            # History scan needs the FULL history of ALL branches. A
            # prior standalone scan cloned this repo shallow + single
            # branch (--depth 1 implies --single-branch), so the remote
            # refspec tracks only one branch. `git fetch --unshallow`
            # alone would deepen just that branch and `git log --all`
            # would still see one branch (Sprint A-2, live: history scans
            # silently covered only the default branch). Widen the
            # refspec to all branches first, then deepen/fetch.
            await _run_git(
                ["git", "-C", base_path, "remote", "set-branches", "origin", "*"],
                label="set-branches",
            )
            fetch_args = ["git", "-C", base_path, "fetch", "--tags", "origin"]
            if os.path.exists(shallow_file):
                fetch_args.insert(4, "--unshallow")
            logger.info("unshallowing_clone", repo_id=repo_id)
            await _run_git(fetch_args, label="fetch-unshallow")
        else:
            # Normal pull (incremental standalone scan).
            await _run_git(
                ["git", "-C", base_path, "pull", "--ff-only"],
                label="pull", timeout=min(settings.GIT_FETCH_TIMEOUT_SECONDS, 600),
            )
        return base_path

    async def _run_clone(clone_branch: str | None) -> tuple[int, str]:
        """Attempt a single clone with the given branch (or default if None)."""
        # --progress: git only emits "Receiving objects: N%" to stderr when
        # asked (worker stderr is a pipe, not a TTY). Streamed by _run_git's
        # on_progress path for the live clone bar + heartbeat.
        c = ["git", "clone", "--progress"]
        if not full_history:
            c += ["--depth", "1"]
        else:
            # History scan needs every branch. --depth implies
            # --single-branch; be explicit that we want them all so
            # `git log --all` later walks the whole commit graph (A-2).
            c += ["--no-single-branch"]
        if clone_branch:
            c += ["--branch", clone_branch]
        c += [clone_url, base_path]
        try:
            rc, _out, err_bytes = await _run_git(c, label="clone", on_progress=on_progress)
            return rc, err_bytes.decode()[:500]
        except (asyncio.TimeoutError, TimeoutError):
            # _run_git already SIGKILLed the whole process group (incl. the
            # git-remote-https helper). Surface as a retryable transient failure
            # rather than aborting the scan — see _clone_with_transient_retry.
            return 124, "clone timed out"

    # ── WS3 Phase C: bounded transient-failure retry ──────────────────────
    # A transient clone failure (timeout, DNS/network blip, TLS reset, 5xx)
    # should retry with backoff instead of FAILING the whole scan — a failed
    # scan = zero coverage for that repo (a recall hole). PERMANENT errors
    # (auth, repo-not-found, branch-mismatch) are NOT transient, so they fall
    # through to the branch-alternate logic / honest failure below.
    _TRANSIENT_CLONE_ERR = (
        "timed out", "timeout", "could not resolve", "couldn't resolve host",
        "connection", "network is unreachable", "reset by peer", "broken pipe",
        "early eof", "rpc failed", "remote end hung up", "ssl", "tls",
        "unable to access", "gnutls", "503", "502", "500", "temporary failure",
    )

    async def _clone_with_transient_retry(clone_branch, attempts: int = 3):
        rc, txt = 1, ""
        for i in range(attempts):
            rc, txt = await _run_clone(clone_branch)
            if rc == 0:
                return rc, txt
            low = txt.lower()
            is_transient = (rc == 124) or any(e in low for e in _TRANSIENT_CLONE_ERR)
            if not is_transient or i == attempts - 1:
                return rc, txt
            # Wipe the partial clone dir, back off, retry.
            if os.path.exists(base_path):
                import shutil
                shutil.rmtree(base_path, ignore_errors=True)
            backoff = min((2 ** i) * 3, 30)  # 3s, 6s, 12s…
            logger.info("clone_retry_transient", repo_id=repo_id,
                        attempt=i + 1, backoff_s=backoff, reason=low[:80])
            await asyncio.sleep(backoff)
        return rc, txt

    rc, stderr_text = await _clone_with_transient_retry(branch)

    # If the requested branch doesn't exist, retry with alternates. Common case:
    # repo.default_branch defaulted to "main" in the DB but the repo is still on
    # "master" (or vice versa). Fall back to the other common default, then to
    # letting git pick HEAD automatically.
    if rc != 0 and "not found in upstream" in stderr_text:
        # Wipe any partial clone dir before retry
        if os.path.exists(base_path):
            import shutil
            shutil.rmtree(base_path, ignore_errors=True)
        alternates = []
        if branch and branch.lower() == "main":
            alternates = ["master", None]
        elif branch and branch.lower() == "master":
            alternates = ["main", None]
        elif branch:
            alternates = [None]  # unknown branch → let git pick HEAD
        for alt in alternates:
            logger.info("clone_retry_with_branch", repo_id=repo_id, branch=alt or "(default)")
            rc, stderr_text = await _run_clone(alt)
            if rc == 0:
                break
            if os.path.exists(base_path):
                import shutil
                shutil.rmtree(base_path, ignore_errors=True)

    if rc != 0:
        err = stderr_text
        # Sanitize error message — remove any auth tokens from the output
        for sensitive in [clone_url, auth.get("token", "") if auth else ""]:
            if sensitive and sensitive != url:
                err = err.replace(sensitive, "[REDACTED]")
        raise RuntimeError(f"Git clone failed: {err}")

    logger.info("repo_cloned", repo_id=repo_id, path=base_path)
    return base_path


# ═══════════════════════════════════════════════════════════════════
#  AI TRIAGE — run false-positive analysis on findings
# ═══════════════════════════════════════════════════════════════════

# Source-scan finding locators carry a URL-shaped scheme (`slack://`,
# `jira://`, etc.) instead of a filesystem path. Used by
# `_run_ai_triage` to pick the right code-context strategy per
# finding. Listed schemes mirror what the source-scanner adapters in
# services/source_scanners/adapters/ emit. The catch-all `://` in
# the first 32 chars handles any future scheme we forget here.
_SOURCE_URL_SCHEMES = (
    "slack://", "jira://", "confluence://", "notion://",
    "salesforce://", "linear://", "asana://", "mattermost://",
    "azuredevops://", "azureblob://", "bitbucket://",
    "servicenow://", "github-issues://",
    "s3://", "m365://", "box://",
    "container://", "docker://", "postman://",
    "gdrive://",
)


def _is_source_locator(file_path: str) -> bool:
    """Return True for source-scan finding locators (URL-shaped)
    where ``extract_rich_context`` would do a wasted disk read.

    Defensive check: any URL-shaped path with `://` in the first 32
    chars is treated as a source locator. The COLLAB surface is the
    only place that emits these shapes.
    """
    if not file_path:
        return False
    if file_path.startswith(_SOURCE_URL_SCHEMES):
        return True
    return "://" in file_path[:32]


def _is_local_endpoint(base_url: str) -> bool:
    """True when an inference endpoint is on this host or a private LAN.

    Judged from the URL rather than the provider label, because the label
    is an operator's dropdown choice and both kinds speak the same
    OpenAI-compatible protocol — a mislabelled cloud model produces no
    error, just silent single-request serialization.
    """
    from urllib.parse import urlparse
    import ipaddress

    raw = (base_url or "").strip()
    if not raw:
        return False
    parsed = urlparse(raw if "//" in raw else f"//{raw}", scheme="http")
    host = (parsed.hostname or "").lower()
    if not host:
        return False

    # Reserved private-use suffixes: mDNS (RFC 6762) and the conventional
    # internal zones. `localhost` is reserved by RFC 6761.
    if host == "localhost" or host.endswith((".local", ".internal", ".localdomain")):
        return True
    # A single-label hostname has no public DNS meaning — it resolves only
    # inside a container network or a LAN (covers "ollama", "lm-studio",
    # or whatever the service happens to be called).
    if "." not in host:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        pass
    # A public hostname is not local, whatever port it is on — an Ollama
    # default port on someone else's domain is still a remote call.
    return False


async def _run_ai_triage(db: AsyncSession, job, repo_path: str) -> tuple[int, int, dict[str, int]]:
    """Run AI triage on all normalized findings for a scan job using batch processing."""
    from apps.api.app.models.finding import NormalizedFinding, Classification
    from apps.api.app.models.repository import RepositorySnapshot
    from services.ai_triage.provider import create_provider, get_provider_for_task
    from services.ai_triage.engine import TriageEngine
    from services.ai_triage.batch import BatchTriageProcessor, BatchTriageConfig
    from services.code_context.extractor import extract_rich_context

    # Load AI Engine Settings from DB
    ai_settings = {"context_mode": "smart", "analysis_mode": "batch_similar", "skip_ai_for_info": True,
                    "ai_confidence_threshold": 0.6, "max_tokens_per_finding": 4096}
    try:
        from apps.api.app.models.ai_engine_settings import AIEngineSettings
        settings_r = await db.execute(select(AIEngineSettings).where(AIEngineSettings.tenant_id == job.tenant_id).limit(1))
        db_settings = settings_r.scalar_one_or_none()
        if db_settings:
            ai_settings = {
                "context_mode": db_settings.context_mode,
                "analysis_mode": db_settings.analysis_mode,
                "skip_ai_for_info": db_settings.skip_ai_for_info,
                "ai_confidence_threshold": db_settings.ai_confidence_threshold,
                "max_tokens_per_finding": db_settings.max_tokens_per_finding,
                "batch_size": db_settings.batch_size,
                "max_concurrent": db_settings.max_concurrent,
                "rate_limit_rpm": db_settings.rate_limit_rpm,
            }
        logger.info("ai_engine_settings_loaded", **{k: v for k, v in ai_settings.items() if k in ("context_mode", "analysis_mode", "skip_ai_for_info")})
    except Exception as se:
        logger.warning("ai_engine_settings_fallback", error=str(se)[:100])

    # Try DB-configured model first, fall back to env vars
    provider = await get_provider_for_task("triage", str(job.tenant_id), db=db)
    model_config_dict = {}
    if not provider:
        provider = create_provider(
            settings.AI_PROVIDER,
            settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY,
            settings.AI_MODEL,
        )
    else:
        # Load model config for advanced settings (stop_sequences, compact prompt, etc.)
        try:
            from apps.api.app.models.ai_model import AIModelConfig
            mc_result = await db.execute(
                select(AIModelConfig).where(
                    AIModelConfig.tenant_id == job.tenant_id,
                    AIModelConfig.is_active == True,
                ).order_by(AIModelConfig.is_primary.desc())
            )
            mc = mc_result.scalars().first()
            if mc:
                model_config_dict = {
                    "use_compact_prompt": mc.use_compact_prompt or False,
                    "system_prompt_override": mc.system_prompt_override or "",
                    "prompt_strategy": mc.prompt_strategy or "recommended",
                    "stop_sequences": mc.stop_sequences or [],
                    "supports_json_mode": mc.supports_json_mode or False,
                    "context_window": mc.context_window or 4096,
                    "_provider_name": mc.provider or "",
                    "_provider_config": mc.provider_config or {},
                }
        except Exception:
            pass
    engine = TriageEngine(provider, model_config=model_config_dict)

    # Configure batch processing — adjust rate limits per provider
    # Google Gemini free tier: ~15 RPM, Anthropic: ~60 RPM, OpenAI: ~60 RPM
    is_google = False
    try:
        from services.ai_triage.provider import GoogleProvider as GP
        is_google = isinstance(provider, GP)
    except Exception:
        is_google = False

    # Detect local/CPU-bound providers (Ollama, LM Studio, vLLM, etc.)
    # These can only process ONE request at a time on a CPU — concurrent requests
    # queue up inside Ollama and cause 120 s timeout cascades.
    # The ENDPOINT decides this, not the provider label. The label is a
    # dropdown value an operator picks, and choosing "Ollama" for a model
    # served over the public internet is an easy mistake: the request path
    # is identical (both are OpenAI-compatible), so nothing fails — the
    # scan just serializes to one call at a time and runs far below the
    # configured throughput, with no error to explain why.
    #
    # A loopback or private-network URL cannot be a shared cloud endpoint,
    # and a public host is not CPU-bound local inference. Only when there
    # is no endpoint to judge does the label decide.
    _local_provider_names = ("ollama", "lm_studio", "vllm", "localai", "huggingface_tgi")
    _provider_label = model_config_dict.get("_provider_name", "").lower()
    _base = (getattr(provider, "_base_url", "") or "").strip()
    if _base:
        is_local = _is_local_endpoint(_base)
        if is_local != (_provider_label in _local_provider_names):
            logger.info(
                "local_model_detection_from_endpoint",
                provider_label=_provider_label or "(unset)",
                endpoint=_base,
                treated_as_local=is_local,
                detail="endpoint overrides the provider label",
            )
    else:
        is_local = _provider_label in _local_provider_names
    if is_local:
        # Increase per-request timeout — CPU inference is slow
        try:
            provider._timeout = 300  # 5 min per request for 7B on CPU
        except Exception:
            pass
        logger.info("local_model_detected_serializing", provider=model_config_dict.get("_provider_name", "ollama"))

    # Start with conservative defaults — adaptive rate limiting in batch.py
    # will auto-adjust on 429s regardless of provider
    if is_google:
        rate_limit = 10
        max_concurrent = 2
        batch_size = 3
        retry_delay = 5.0
        max_retries = 5
    elif is_local:
        # CPU-only local model: serialize completely — 1 request at a time
        rate_limit = 60
        max_concurrent = 1
        batch_size = 1
        retry_delay = 10.0
        max_retries = 3
    else:
        # Conservative start for cloud providers — adaptive backoff handles the rest
        rate_limit = ai_settings.get("rate_limit_rpm", settings.AI_RATE_LIMIT_RPM)
        max_concurrent = ai_settings.get("max_concurrent", settings.AI_TRIAGE_MAX_CONCURRENT)
        batch_size = ai_settings.get("batch_size", settings.AI_TRIAGE_BATCH_SIZE)
        retry_delay = 2.0
        max_retries = 3

    # Per-call timeout. OpenAI-compatible providers now STREAM with their own
    # industry-standard timeout model (connect fast-fail + idle timeout
    # between chunks + a total deadline derived from the effective
    # max_tokens) — for those, this outer wait_for is only a BACKSTOP set
    # just above the provider's self-imposed deadline. Non-streaming
    # providers (Claude/Google native paths) keep the legacy wall-clock:
    # 300 s local, 120 s cloud.
    from services.ai_triage.provider import OpenAIProvider as _OAIP
    if isinstance(provider, _OAIP):
        _eff_max_tokens = (model_config_dict.get("_provider_config") or {}).get("max_tokens") or 4096
        request_timeout = _OAIP.deadline_for(_eff_max_tokens) + 30.0
    else:
        request_timeout = 300.0 if is_local else 120.0

    batch_config = BatchTriageConfig(
        batch_size=batch_size,
        max_concurrent=max_concurrent,
        rate_limit_rpm=rate_limit,
        max_retries=max_retries,
        retry_base_delay=retry_delay,
        request_timeout=request_timeout,
    )
    processor = BatchTriageProcessor(engine, batch_config)

    # Load findings — optionally skip info severity based on AI engine settings
    # Scope to the parent (repository OR scan_source), not just this
    # job_id, so re-scans can triage previously-untriaged findings as
    # well. Branch on job type:
    #   - Source-scan jobs (scan_source_id set) → filter by scan_source_id.
    #     Earlier code filtered by repository_id which is NULL for source
    #     jobs; `NULL == NULL` evaluates to NULL (not TRUE) in SQL, so
    #     the filter excluded ALL source findings and AI triage silently
    #     no-op'd. Bug fix 2026-05-04.
    #   - Git-scan jobs (repository_id set, scan_source_id NULL)
    #     → filter by repository_id (preserves existing behaviour).
    #   - Edge case (neither set, e.g. import jobs) → fall back to
    #     this job's findings only.
    conditions = [
        NormalizedFinding.tenant_id == job.tenant_id,
        NormalizedFinding.classification == Classification.NEEDS_REVIEW,
        NormalizedFinding.remediation_status != "APPLIED",
    ]
    if job.scan_source_id is not None:
        conditions.append(NormalizedFinding.scan_source_id == job.scan_source_id)
    elif job.repository_id is not None:
        conditions.append(NormalizedFinding.repository_id == job.repository_id)
    else:
        conditions.append(NormalizedFinding.scan_job_id == job.id)
    if ai_settings.get("skip_ai_for_info", True):
        conditions.append(NormalizedFinding.severity != "info")

    findings_result = await db.execute(select(NormalizedFinding).where(*conditions))
    findings = findings_result.scalars().all()

    # ── Test File Handling: "exclude" (from AI) ──────────────────────
    # The UI is explicit: "Skip AI false positive analysis for test file
    # findings entirely. Saves AI tokens — findings are still detected
    # and stored but not AI-classified."
    #
    # So this filters the TRIAGE list only. The findings exist in the
    # database and appear in the UI exactly as with `normal`; they simply
    # never reach the model. Detection is untouched, so this setting can
    # never hide a real credential — it only declines to spend tokens
    # classifying a corpus the operator already knows is synthetic.
    if findings:
        try:
            from apps.api.app.models.ai_engine_settings import AIEngineSettings as _AES2
            _aes2 = (await db.execute(
                select(_AES2).where(_AES2.tenant_id == job.tenant_id).limit(1)
            )).scalar_one_or_none()
            _tfh = getattr(_aes2, "deprioritize_test_files", None) if _aes2 else None
            if isinstance(_tfh, bool):
                _tfh = "deprioritize" if _tfh else "normal"
            if _tfh == "exclude":
                from services.secret_scan.engine import _classify_file_context as _cfc2
                _before = len(findings)
                findings = [
                    f for f in findings
                    if _cfc2(f.file_path or "") != "test_file"
                ]
                _skipped = _before - len(findings)
                if _skipped:
                    logger.info(
                        "test_file_findings_excluded_from_ai",
                        scan_job_id=str(job.id), skipped=_skipped,
                        still_triaged=len(findings),
                        detail="findings remain stored and visible; only AI triage was skipped",
                    )
        except Exception as _tfhe:
            logger.debug("test_file_handling_read_failed", error=str(_tfhe)[:120])

    if not findings:
        return 0, 0, {}

    # Get framework context from snapshot — only meaningful for git-
    # scan jobs (a Slack workspace doesn't have a `requirements.txt`).
    # Source-scan jobs skip this step and run with empty framework
    # context; the AI prompt handles missing framework hints fine.
    framework_info = ""
    detected_frameworks = []
    snapshot = None
    if job.repository_id is not None:
        snap_result = await db.execute(
            select(RepositorySnapshot)
            .where(RepositorySnapshot.repository_id == job.repository_id)
            .order_by(RepositorySnapshot.created_at.desc())
            .limit(1)
        )
        snapshot = snap_result.scalar_one_or_none()
    if snapshot and snapshot.analysis_result:
        detected_frameworks = snapshot.analysis_result.get("frameworks", [])
        if detected_frameworks:
            # Build rich framework context using the framework knowledge base
            from packages.prompts.framework_context import get_framework_context
            framework_info = get_framework_context(detected_frameworks)
            if not framework_info:
                framework_info = f"Detected frameworks: {', '.join(detected_frameworks)}"

    # Prepare data for batch processing
    finding_data_list = []
    code_contexts = {}
    finding_map = {}  # id -> ORM object

    for _hb_i, finding in enumerate(findings):
        fid = str(finding.id)
        finding_map[fid] = finding

        # Smart context extraction — sends only function body + imports, not 500 raw lines.
        # Source-scan findings carry URL-shaped locators (`slack://`,
        # `jira://`, `s3://`, `m365://`, etc.) rather than filesystem
        # paths. The scanner adapter already populated `code_snippet`
        # with the message body / page text / object content the
        # COLLAB rules matched against — reuse it as the AI's
        # file_context instead of an empty CodeContext from a wasted
        # disk read.
        if _is_source_locator(finding.file_path) or not repo_path:
            snippet = finding.code_snippet or ""
            code_ctx = {
                "code_snippet": snippet,
                "file_context": snippet,
                "language": "",
                "total_lines": snippet.count("\n") + 1,
                "imports": "",
                "enclosing_function": "",
                "enclosing_function_name": "",
                "class_context": "",
                "class_name": "",
                "decorators": [],
                "call_targets": [],
            }
        else:
            code_ctx = extract_rich_context(repo_path, finding.file_path, finding.line_start)
        code_contexts[fid] = code_ctx

        finding_data_list.append({
            "id": fid,
            "title": finding.title,
            "description": finding.description,
            "vulnerability_category": finding.vulnerability_category,
            "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
            "cwe": finding.cwe,
            "scanner_name": finding.scanner_name,
            "scanner_rule_id": finding.scanner_rule_id,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "code_snippet": finding.code_snippet,
            # Plumbed so engine.triage_finding can apply tenant-specific
            # calibration (closes the customer-feedback loop — see comment
            # in services/ai_triage/engine.py near "calibration_applied").
            "tenant_id": str(finding.tenant_id) if finding.tenant_id else None,
        })

        # bug #165 / G-2 prep-loop heartbeat (task #95): extract_rich_context
        # does a disk read + AST parse per finding; over thousands of findings
        # this prep loop can run >15m with NO db write, so the stall watchdog
        # false-reaped a healthy AI-triage prep — the "rate-limit tail stall"
        # class of reap this bug tracks. Stamp a REAL-PROGRESS heartbeat every
        # 50 findings (throttled to ~1/30s inside the helper, so calling it
        # often is cheap). Real progress: a wedged loop stops advancing _hb_i →
        # stops stamping → is still reaped, preserving the design's deadlock
        # detection (a background ticker would mask the wedge — see
        # _stamp_heartbeat_main docstring).
        if (_hb_i + 1) % 50 == 0:
            await _stamp_heartbeat_main(job, db, commit=True)

    # ── Pre-AI Deduplication (honours the "Finding Analysis" setting) ──
    # `batch_similar` groups same CWE + file + rule findings — triage ONE,
    # apply the verdict to all members. `individual` gives every finding
    # its own AI call, which is what the UI promises for that option.
    #
    # This gate is the fix for a dead control: `analysis_mode` was read
    # from the database and logged, but nothing ever branched on it, so
    # grouping ran unconditionally and choosing "Individual" changed
    # nothing. A setting that silently does nothing is worse than no
    # setting — the operator believes they made a decision.
    from services.ai_triage.dedup import (
        group_findings_for_triage, apply_group_results, FindingGroup,
    )

    _analysis_mode = (ai_settings.get("analysis_mode") or "batch_similar").lower()
    if _analysis_mode == "individual":
        # One AI call per finding: every finding is its own single-member
        # group. Must be real FindingGroup objects — apply_group_results
        # reads `group.member_ids`, so a plain list would raise here.
        deduped_list = list(finding_data_list)
        groups_map = {}
        for _f in finding_data_list:
            _fid = str(_f.get("id"))
            groups_map[_fid] = FindingGroup(
                representative_id=_fid,
                member_ids=[_fid],
                group_key=f"individual:{_fid}",
                cwe=_f.get("cwe", "") or "",
                file_path=_f.get("file_path", "") or "",
                rule_id=_f.get("scanner_rule_id", "") or "",
            )
        dedup_saved = 0
    else:
        deduped_list, groups_map = group_findings_for_triage(finding_data_list)
        dedup_saved = len(finding_data_list) - len(deduped_list)
    logger.info("pre_ai_dedup_applied", analysis_mode=_analysis_mode,
                original=len(finding_data_list), deduped=len(deduped_list), saved=dedup_saved)

    # Collect security evidence from the repo
    related_context = ""
    try:
        from services.evidence.collector import EvidenceCollector
        collector = EvidenceCollector()
        security_profile = collector.collect(repo_path)
        related_context = security_profile.to_context_string()
    except Exception as ev_err:
        logger.warning("evidence_collection_failed", error=str(ev_err)[:200])

    repo_ctx = {
        "related_files_context": related_context,
        "framework_context": framework_info,
    }

    # Sprint G-2 — progress-tied liveness heartbeat. process_batch is a
    # single multi-minute await with no DB checkpoint; without this the
    # stall-based watchdog would see no heartbeat for the entire triage
    # phase and could reap a healthy scan (the exact regression that
    # killed aws-cdk at 15.4 min, mid-triage). on_progress fires after
    # EACH finding actually completes, so heartbeat_at advances only on
    # real progress — a genuine await-deadlock inside process_batch stops
    # the heartbeat and the watchdog still correctly reaps the wedged
    # scan. commit=True (throttled ~1/30s) because process_batch never
    # commits the main session itself; process_batch does NOT touch `db`,
    # so committing here mid-phase is safe and (expire_on_commit=False)
    # leaves the finding ORM objects usable for the result-apply loop.

    import time as _t_mod
    _triage_start = _t_mod.monotonic()
    _triage_pub = {"t": 0.0}

    async def _triage_progress(completed: int, total: int):
        # P0 — climb the otherwise-frozen bar + publish a live counter and
        # ETA so the long AI-triage phase shows motion instead of a static
        # "analyzing N findings". `total` is the deduped representative
        # count (the actual AI calls). Still does the G-2 heartbeat.
        _total = max(int(total or 0), 1)
        _frac = min(1.0, max(0, completed) / _total)
        _pct = 70 + int(round(25 * _frac))  # 70 (post-storing) -> 95
        _elapsed = _t_mod.monotonic() - _triage_start
        _eta = ""
        # Only show ETA once there's a stable signal — the first few
        # samples give a wild estimate (e.g. "37m" at 1/273).
        if completed >= 5 and completed < _total and _elapsed > 2:
            _rem = _elapsed * (_total - completed) / completed
            _eta = (f" · ~{int(_rem // 60)}m {int(_rem % 60)}s left"
                    if _rem >= 60 else f" · ~{int(_rem)}s left")
        _msg = f"[7/8] AI analysis — {completed:,}/{_total:,} findings triaged{_eta}"
        # Persist on the main session; the heartbeat commit (~30s) carries
        # it to the 5s poll + page reload.
        try:
            job.status_message = _msg
            if (job.progress_pct or 0) < _pct:
                job.progress_pct = _pct
        except Exception:
            pass
        await _stamp_heartbeat_main(job, db, commit=True)
        # Live WS publish, throttled ~2s (cheap; no DB write).
        _now = _t_mod.monotonic()
        if _now - _triage_pub["t"] >= 2.0 or completed >= _total:
            _triage_pub["t"] = _now
            try:
                from services.pubsub.redis_pubsub import publish_scan_progress
                await publish_scan_progress(
                    str(job.id), "analyzing", _pct, _msg,
                    {"triage_done": completed, "triage_total": _total},
                )
            except Exception:
                pass

    # Run batch triage on DEDUPED list (fewer AI calls)
    results = await processor.process_batch(
        findings=deduped_list,  # Only representatives, not all findings
        code_contexts=code_contexts,
        repo_context=repo_ctx,
        on_progress=_triage_progress,
    )

    # Expand results back to all group members
    # Build result map keyed by finding ID
    raw_result_map = {}
    for r in results:
        if r.success and r.result:
            raw_result_map[r.finding_id] = r.result

    expanded_results = apply_group_results(groups_map, raw_result_map)

    # Rebuild results list with expanded IDs for the existing apply loop
    from services.ai_triage.batch import TriageResult
    expanded_result_list = []
    for fid, result in expanded_results.items():
        expanded_result_list.append(TriageResult(finding_id=fid, success=True, result=result))
    # Also include failures from the original results
    for r in results:
        if not r.success and r.finding_id not in expanded_results:
            expanded_result_list.append(r)

    results = expanded_result_list
    logger.info("dedup_results_expanded", original_results=len(raw_result_map), expanded=len(expanded_results), saved_calls=dedup_saved)

    # Apply results to DB
    classification_map = {
        "likely_true_positive": Classification.LIKELY_TRUE_POSITIVE,
        "likely_false_positive": Classification.LIKELY_FALSE_POSITIVE,
        "needs_review": Classification.NEEDS_REVIEW,
    }
    triaged = 0
    # Aggregate failure types across all AI calls so the triage-health signal
    # can pick the right notification copy (parse error vs upstream error vs
    # empty response vs invalid JSON). Keyed by the `_parse_failure` value
    # set by engine._parse_response() / the upstream-error handler.
    failure_summary: dict[str, int] = {}
    # Verdicts held at NEEDS_REVIEW because the model's confidence fell
    # below the tenant's "AI Confidence Level" threshold.
    below_threshold_count = 0

    # ── Stale-row guard before applying verdicts ─────────────────────
    # `finding_map` holds ORM objects loaded BEFORE the AI phase, which
    # runs for minutes (13 min on a fast model, 52 on a slow one). Rows
    # can disappear in that window — a re-scan deletes and recreates
    # findings, an operator deletes one, a suppression sweep runs.
    #
    # Mutating an ORM object whose row is gone makes the flush emit
    # `UPDATE ... expected to update 1 row(s); 0 were matched`, which
    # poisons the whole transaction: every OTHER verdict in the batch
    # would be lost too and the scan would die, over a single row that
    # went away during a long AI phase.
    #
    # One indexed id-only query re-validates the set, so a vanished
    # finding is skipped instead of destroying the batch.
    _candidate_ids = [
        tr.finding_id for tr in results
        if tr.success and tr.result and finding_map.get(tr.finding_id) is not None
    ]
    _alive_ids: set[str] = set()
    if _candidate_ids:
        try:
            from uuid import UUID as _UUID
            _uuids = []
            for _cid in _candidate_ids:
                try:
                    _uuids.append(_cid if isinstance(_cid, _UUID) else _UUID(str(_cid)))
                except (ValueError, AttributeError, TypeError):
                    continue
            if _uuids:
                _alive_rows = await db.execute(
                    select(NormalizedFinding.id).where(NormalizedFinding.id.in_(_uuids))
                )
                _alive_ids = {str(r) for r in _alive_rows.scalars().all()}
        except Exception as _av_err:
            # If the probe itself fails, fall through and apply as before
            # rather than dropping every verdict.
            logger.warning("triage_apply_liveness_probe_failed", error=str(_av_err)[:160])
            _alive_ids = {str(c) for c in _candidate_ids}
        _vanished = len(_candidate_ids) - len(_alive_ids)
        if _vanished > 0:
            logger.warning(
                "triage_apply_skipped_deleted_findings",
                scan_job_id=str(job.id), vanished=_vanished,
                total_verdicts=len(_candidate_ids),
                detail="findings deleted during the AI phase; verdicts skipped to protect the batch",
            )

    for triage_result in results:
        if not triage_result.success or not triage_result.result:
            continue

        finding = finding_map.get(triage_result.finding_id)
        if not finding:
            continue

        # Row vanished mid-scan — skip rather than poison the transaction.
        if _alive_ids and str(triage_result.finding_id) not in _alive_ids:
            continue

        result = triage_result.result
        # G1b — the AI is given the secret value to triage and echoes it back
        # into its free-text reasoning / TP-FP reasons. Scrub secret shapes
        # from the result BEFORE it's persisted on the finding + incident and
        # served via API/UI — same at-rest guarantee as code_snippet.
        from services.secret_scan.engine import scrub_secrets_in_obj as _scrub_obj
        result = _scrub_obj(result)
        # ── "AI Confidence Level" setting ────────────────────────────
        # A verdict the model is not confident about must not silently
        # become a decision. Below the tenant's threshold the finding is
        # held at NEEDS_REVIEW (a human looks at it) while the model's
        # reasoning and score are still persisted, so the operator sees
        # WHAT the AI thought and WHY it was not accepted.
        _ai_conf = result.get("confidence_score")
        _proposed = classification_map.get(
            result.get("classification", "needs_review"),
            Classification.NEEDS_REVIEW,
        )
        try:
            _conf_threshold = float(ai_settings.get("ai_confidence_threshold", 0.6) or 0.0)
        except (TypeError, ValueError):
            _conf_threshold = 0.6
        if (
            _proposed is not Classification.NEEDS_REVIEW
            and _ai_conf is not None
            and float(_ai_conf) < _conf_threshold
        ):
            finding.classification = Classification.NEEDS_REVIEW
            below_threshold_count += 1
        else:
            finding.classification = _proposed
        finding.ai_confidence = _ai_conf
        finding.ai_explanation = result.get("reasoning_summary")
        finding.exploitability_score = result.get("exploitability_score")
        finding.true_positive_reasons = result.get("true_positive_reasons", [])
        finding.false_positive_reasons = result.get("false_positive_reasons", [])
        finding.compensating_controls = result.get("compensating_controls_found", [])
        finding.ai_evidence_refs = result.get("evidence", [])
        triaged += 1

        # ── Case-B: cascade AI verdict UP to the parent incident ──
        # When the AI triages a finding, the verdict really applies to
        # the CREDENTIAL (all occurrences of the same secret share the
        # same classification reasoning).  Mirror the result onto the
        # parent SecretIncident so the /incidents view reflects AI
        # decisions, and cascade to sibling occurrences so the
        # per-finding views stay in sync.
        #
        # Without this, AI runs to completion but `/incidents` still
        # shows every incident as "needs_review" — the AI value is
        # hidden behind a stale incident-level classification.
        if finding.incident_id is not None:
            from apps.api.app.models.finding import SecretIncident
            from sqlalchemy import update as sa_update, select as _select
            ai_class_value = finding.classification.value if finding.classification else "needs_review"
            inc_q = await db.execute(
                _select(SecretIncident).where(SecretIncident.id == finding.incident_id).limit(1)
            )
            inc_row = inc_q.scalar_one_or_none()
            if inc_row is not None:
                # Only overwrite incident state if it's still default
                # ("needs_review") — preserve any prior USER triage so
                # AI doesn't silently demote/escalate a human decision.
                # Industry pattern: human triage wins over AI on
                # subsequent scans.
                if (inc_row.classification or "needs_review") == "needs_review":
                    inc_row.classification = ai_class_value
                # AI explanation + confidence always refresh — they're
                # informational, not authoritative, and the freshest
                # reasoning is the most useful one to display.
                if finding.ai_explanation:
                    inc_row.ai_explanation = finding.ai_explanation
                if finding.ai_confidence is not None:
                    inc_row.ai_confidence = finding.ai_confidence
                # Cascade classification to sibling occurrences too so
                # the legacy per-finding list stays consistent with the
                # incident-level decision.  Only when the sibling is
                # itself still NEEDS_REVIEW — same "don't override
                # human triage" rule.
                await db.execute(
                    sa_update(NormalizedFinding)
                    .where(
                        NormalizedFinding.incident_id == finding.incident_id,
                        NormalizedFinding.id != finding.id,
                        NormalizedFinding.classification == Classification.NEEDS_REVIEW,
                    )
                    .values(
                        classification=finding.classification,
                        ai_explanation=finding.ai_explanation,
                        ai_confidence=finding.ai_confidence,
                    )
                )

        # Track failure classes for the health signal. Engine stamps
        # `_parse_failure` whenever the AI call didn't produce a usable
        # classification (upstream error, truncated JSON, invalid JSON,
        # empty response). Successful classifications have no key.
        ftype = result.get("_parse_failure")
        if ftype:
            failure_summary[ftype] = failure_summary.get(ftype, 0) + 1

        # Store in decision cache for future scans
        if finding.stability_id:
            try:
                from services.normalization.decision_cache import store_in_cache
                from services.normalization.stability import compute_pattern_hash
                await store_in_cache(
                    db=db,
                    tenant_id=finding.tenant_id,
                    repository_id=finding.repository_id,
                    # Source-scan findings have repository_id=None
                    # and the parent is `scan_source_id` instead.
                    # Pass it through so the cache row is valid
                    # against the now-nullable repository_id column
                    # (migration l9m0n1o2p3q4).
                    scan_source_id=getattr(finding, "scan_source_id", None),
                    stability_id=finding.stability_id,
                    code_hash=finding.code_hash or "",
                    pattern_hash=compute_pattern_hash(finding.scanner_rule_id or "", finding.code_snippet or "", finding.cwe),
                    classification=result.get("classification", "needs_review"),
                    ai_confidence=result.get("confidence_score"),
                    ai_explanation=result.get("reasoning_summary"),
                    exploitability_score=result.get("exploitability_score"),
                    true_positive_reasons=result.get("true_positive_reasons", []),
                    false_positive_reasons=result.get("false_positive_reasons", []),
                    compensating_controls=result.get("compensating_controls_found", []),
                    ai_evidence_refs=result.get("evidence", []),
                    decided_by="ai",
                    source_scan_job_id=job.id,
                    rule_id=finding.scanner_rule_id,
                    file_path=finding.file_path,
                    function_name=finding.function_name,
                    cwe=finding.cwe,
                    finding_title=finding.title,
                )
            except Exception as cache_err:
                logger.warning("cache_store_failed", finding_id=str(finding.id), error=str(cache_err)[:100])

    await db.commit()
    if below_threshold_count:
        # Makes the threshold's effect observable: how many verdicts it
        # held back on this scan.
        logger.info(
            "ai_triage_confidence_threshold_applied",
            scan_job_id=str(job.id),
            threshold=ai_settings.get("ai_confidence_threshold", 0.6),
            held_for_review=below_threshold_count,
            triaged=triaged,
        )
    return triaged, dedup_saved, failure_summary


# ═══════════════════════════════════════════════════════════════════
#  NORMALIZE + TRIAGE — for imported findings
# ═══════════════════════════════════════════════════════════════════

@celery_app.task(bind=True, max_retries=3)
def normalize_and_triage(self, scan_job_id: str):
    """Normalize imported findings and run AI triage."""
    logger.info("normalize_triage_started", scan_job_id=scan_job_id)
    run_async(_normalize_and_triage(scan_job_id))


async def _normalize_and_triage(scan_job_id: str):
    from apps.api.app.models.scan import ScanJob
    from apps.api.app.models.repository import RepositorySnapshot
    from apps.api.app.models.finding import NormalizedFinding
    from services.normalization.normalizer import normalize_imported_findings
    from sqlalchemy import func as _sa_func

    async with await _get_db_session() as db:
        result = await db.execute(select(ScanJob).where(ScanJob.id == UUID(scan_job_id)))
        job = result.scalar_one_or_none()
        if not job:
            return

        count = await normalize_imported_findings(
            db=db,
            scan_job_id=job.id,
            tenant_id=job.tenant_id,
            repository_id=job.repository_id,
        )
        await db.commit()
        logger.info("normalization_complete", scan_job_id=scan_job_id, normalized=count)

        # ── Source-scan path: count findings directly ──
        # Source-scan adapters (Slack/Jira/S3/etc.) persist
        # NormalizedFinding rows DIRECTLY during the scan — they
        # never go through the ImportedFinding → normalize pipeline.
        # `normalize_imported_findings` therefore returns 0 even
        # when the job produced dozens of findings, and the
        # `if count > 0 ...` gate below would silently skip AI
        # triage. Count NormalizedFinding rows for this job
        # directly so the gate reflects reality. Bug fix 2026-05-04
        # (Blocker 4 of the source-scan triage bug).
        if count == 0 and job.scan_source_id is not None:
            cnt_r = await db.execute(
                select(_sa_func.count(NormalizedFinding.id)).where(
                    NormalizedFinding.scan_job_id == job.id
                )
            )
            count = int(cnt_r.scalar_one() or 0)
            logger.info(
                "source_scan_findings_counted",
                scan_job_id=scan_job_id, normalized=count,
            )

        # AI triage — check env vars AND DB-configured models (Ollama, Groq, etc.)
        has_ai_env = bool(settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY)
        has_ai_db = False
        if not has_ai_env:
            try:
                from apps.api.app.models.ai_model import AIModelConfig
                db_model_result = await db.execute(
                    select(AIModelConfig).where(
                        AIModelConfig.tenant_id == job.tenant_id,
                        AIModelConfig.is_active == True,
                    ).limit(1)
                )
                has_ai_db = db_model_result.scalar_one_or_none() is not None
            except Exception:
                pass

        if count > 0 and (has_ai_env or has_ai_db):
            # Snapshot lookup only makes sense for git-scan jobs —
            # a Slack workspace doesn't get cloned to /app/storage.
            # Source-scan jobs run with empty repo_path; the
            # `_is_source_locator` branch in _run_ai_triage skips
            # the filesystem extract and uses the finding's pre-
            # populated code_snippet as the AI's file_context.
            repo_path = ""
            if job.repository_id is not None:
                snap_result = await db.execute(
                    select(RepositorySnapshot)
                    .where(RepositorySnapshot.repository_id == job.repository_id)
                    .order_by(RepositorySnapshot.created_at.desc())
                    .limit(1)
                )
                snapshot = snap_result.scalar_one_or_none()
                repo_path = snapshot.storage_path if snapshot else ""

            triaged, _dedup, _failure_summary = await _run_ai_triage(db, job, repo_path)
            logger.info("ai_triage_complete", scan_job_id=str(job.id), triaged=triaged)


@celery_app.task(bind=True, max_retries=3)
def generate_remediation(self, finding_id: str):
    """Generate AI-powered remediation for a finding."""
    logger.info("remediation_started", finding_id=finding_id)
    run_async(_generate_remediation(finding_id))


async def _generate_remediation(finding_id: str):
    from apps.api.app.models.finding import NormalizedFinding
    from apps.api.app.models.remediation import RemediationPlan, RemediationPatch, PatchStatus
    from apps.api.app.models.repository import RepositorySnapshot
    from services.ai_triage.provider import create_provider, get_provider_for_task
    from services.ai_remediation.engine import RemediationEngine
    from services.code_context.extractor import extract_rich_context

    async with await _get_db_session() as db:
        result = await db.execute(
            select(NormalizedFinding).where(NormalizedFinding.id == UUID(finding_id))
        )
        finding = result.scalar_one_or_none()
        if not finding:
            return

        # Get AI provider — DB model first, env vars fallback
        provider = await get_provider_for_task("remediation", str(finding.tenant_id), db=db)
        if not provider:
            if not (settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY):
                logger.warning("no_ai_key_for_remediation", finding_id=finding_id)
                return
            provider = create_provider(
                settings.AI_PROVIDER,
                settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY,
                settings.AI_MODEL,
            )

        snap_result = await db.execute(
            select(RepositorySnapshot)
            .where(RepositorySnapshot.repository_id == finding.repository_id)
            .order_by(RepositorySnapshot.created_at.desc())
            .limit(1)
        )
        snapshot = snap_result.scalar_one_or_none()
        repo_path = snapshot.storage_path if snapshot else ""

        code_ctx = extract_rich_context(repo_path, finding.file_path, finding.line_start)
        code_ctx["vulnerable_code"] = code_ctx.get("code_snippet", "")
        code_ctx["available_imports"] = ""

        engine = RemediationEngine(provider)

        finding_data = {
            "title": finding.title,
            "description": finding.description,
            "vulnerability_category": finding.vulnerability_category,
            "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
            "cwe": finding.cwe,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
        }
        triage_result = {"reasoning_summary": finding.ai_explanation or ""}
        repo_ctx = {"framework_context": ""}

        rem_result = await engine.generate_remediation(finding_data, triage_result, code_ctx, repo_ctx)

        # G1b — the AI remediation result is free text that can echo the
        # secret: the summary/root-cause/fix-rationale/notes describe the
        # finding, and the patch_diff's `-` line is the original secret line.
        # Scrub every string in the result before it's persisted + served.
        from services.secret_scan.engine import scrub_secrets_in_obj as _scrub_obj
        rem_result = _scrub_obj(rem_result)
        plan = RemediationPlan(
            finding_id=finding.id,
            generated_by=f"{settings.AI_PROVIDER}/{settings.AI_MODEL}",
            vulnerability_summary=rem_result.get("summary", ""),
            root_cause=rem_result.get("root_cause", ""),
            fix_rationale=rem_result.get("fix_rationale", ""),
            developer_notes=rem_result.get("developer_notes", []),
            validation_steps=rem_result.get("validation_steps", []),
            risk_of_breakage=rem_result.get("risk_of_breakage", "unknown"),
            confidence_score=rem_result.get("confidence_score"),
        )
        db.add(plan)
        await db.flush()

        # PATCH_GENERATED claims a draft fix exists, so it is only
        # stamped when a patch with a real diff is persisted alongside
        # it. A plan-only result (no diff from the model) leaves the
        # finding PENDING so it re-enters the queue instead of being
        # reported as covered.
        _diff = (rem_result.get("patch_diff") or "").strip()
        if len(_diff) > 20:
            patch = RemediationPatch(
                plan_id=plan.id,
                patch_diff=rem_result["patch_diff"],
                files_changed=rem_result.get("files_changed", []),
                status=PatchStatus.PROPOSED,
                confidence_score=rem_result.get("confidence_score"),
                safety_score=rem_result.get("safety_score"),
            )
            db.add(patch)
            finding.remediation_status = "patch_generated"
        else:
            finding.remediation_status = "pending"
            logger.info(
                "remediation_plan_only",
                finding_id=str(finding.id),
                detail="model returned a plan but no patch diff",
            )
        await db.commit()

    logger.info("remediation_complete", finding_id=finding_id)


# ═══════════════════════════════════════════════════════════════════
#  PR CREATION — push fixes to git
# ═══════════════════════════════════════════════════════════════════

@celery_app.task(bind=True, max_retries=2)
def create_fix_pr(self, finding_id: str):
    """Create a PR with the approved fix for a finding."""
    logger.info("pr_creation_started", finding_id=finding_id)
    run_async(_create_fix_pr(finding_id))


async def _create_fix_pr(finding_id: str):
    from services.pr_pipeline.engine import PRPipelineEngine

    async with await _get_db_session() as db:
        engine = PRPipelineEngine()
        result = await engine.create_fix_pr(db, UUID(finding_id))
        await db.commit()

        if result.success:
            logger.info("pr_created", finding_id=finding_id, pr_url=result.pr_url)
        else:
            logger.error("pr_creation_failed", finding_id=finding_id, error=result.error)


# ═══════════════════════════════════════════════════════════════════
#  BATCH REMEDIATION — fix multiple findings at once
# ═══════════════════════════════════════════════════════════════════

@celery_app.task(bind=True, max_retries=2)
def batch_remediate(self, repository_id: str, finding_ids: list[str], tenant_id: str):
    """Generate fixes for a batch of findings."""
    logger.info("batch_remediation_started", repo_id=repository_id, count=len(finding_ids))
    run_async(_batch_remediate(repository_id, finding_ids, tenant_id))


async def _batch_remediate(repository_id: str, finding_ids: list[str], tenant_id: str):
    from services.batch_remediation.engine import BatchRemediationEngine

    async with await _get_db_session() as db:
        engine = BatchRemediationEngine()
        result = await engine.remediate_batch(
            db=db,
            repository_id=UUID(repository_id),
            finding_ids=[UUID(fid) for fid in finding_ids],
            tenant_id=UUID(tenant_id),
        )
        await db.commit()

    logger.info(
        "batch_remediation_done",
        remediated=result.remediated,
        failed=result.failed,
        errors=len(result.errors),
    )


# ═══════════════════════════════════════════════════════════════════
#  CALIBRATION — background recalibration
# ═══════════════════════════════════════════════════════════════════

@celery_app.task(bind=True)
def recalibrate_tenant(self, tenant_id: str):
    """Recompute calibration tables after user feedback."""
    logger.info("recalibration_started", tenant_id=tenant_id[:8])
    run_async(_recalibrate(tenant_id))


async def _recalibrate(tenant_id: str):
    from services.ai_triage.calibration import ConfidenceCalibrator

    async with await _get_db_session() as db:
        calibrator = ConfidenceCalibrator()
        calibration = await calibrator.compute_calibration(db, UUID(tenant_id))
        await calibrator.cache_calibration(UUID(tenant_id), calibration)

    logger.info("recalibration_complete", tenant_id=tenant_id[:8], entries=len(calibration))


# ═══════════════════════════════════════════════════════════════════
#  SCHEDULED SCANS — periodic scan execution
# ═══════════════════════════════════════════════════════════════════

@celery_app.task(bind=True)
def run_scheduled_scans_task(self):
    """Check and trigger all due scheduled scans. Called by Celery Beat."""
    logger.info("scheduled_scan_check_started")
    run_async(_run_scheduled_scans())


async def _run_scheduled_scans():
    from services.scheduler.engine import run_scheduled_scans

    async with await _get_db_session() as db:
        triggered = await run_scheduled_scans(db)
    logger.info("scheduled_scan_check_complete", triggered=triggered)


# ═══════════════════════════════════════════════════════════════════
#  WEEKLY SOURCE FULL-SWEEP — drift recovery + deletion detection
#
#  Polling adapters use ``sync_state`` watermarks for the cheap
#  incremental path. That covers normal operation but leaves three
#  failure modes uncaught:
#    1. Watermark drift — a stuck or malformed cursor returns 0 items
#       forever; nobody notices until a customer complains.
#    2. Deletion blindness — most APIs don't surface deletions to
#       polling consumers; deleted Slack messages / closed Jira issues
#       keep their findings open forever.
#    3. First-scan recovery — a partial first scan (rate-limited
#       halfway through) advances the watermark, leaving the unscanned
#       tail silently skipped.
#
#  Industry pattern (GitGuardian / Nightfall): a periodic full sweep
#  that ignores the watermark and re-walks everything. Vooda's
#  ``_run_source_scan`` already accepts ``config.force_full=true`` to
#  trigger this mode; the post-scan tombstone pass closes findings
#  for items that were in the DB but not in the sweep.
#
#  This Beat task finds every active source whose ``last_full_sweep_at``
#  is NULL or older than ``FULL_SWEEP_INTERVAL_DAYS`` (default 7) and
#  dispatches a force_full scan for each. Runs every 6 hours so a
#  source that just became overdue waits at most ~6h for its sweep.
#
#  Stagger: 30s between dispatches so a tenant with 100 sources
#  doesn't fire 100 simultaneous adapter calls. Each scan still goes
#  through the per-source concurrency lock for safety.
# ═══════════════════════════════════════════════════════════════════

@celery_app.task(bind=True)
def weekly_source_full_sweep_task(self):
    """Find sources overdue for a full sweep and dispatch force_full scans.

    Called by Celery Beat every 6 hours. Per-source TTL is 7 days
    (``FULL_SWEEP_INTERVAL_DAYS`` env var). Idempotent within the TTL
    window — a source swept yesterday is skipped today.
    """
    logger.info("source_full_sweep_check_started")
    result = run_async(_run_weekly_source_full_sweep())
    logger.info("source_full_sweep_check_complete", **result)


async def _run_weekly_source_full_sweep() -> dict:
    """Dispatch a force_full source-scan job for each overdue source."""
    import asyncio
    from apps.api.app.models.scan_source import ScanSource
    from apps.api.app.models.scan import ScanJob, ScanStatus, ScanType

    # 7-day default — operators with chattier APIs can lower this via
    # env var; defended below at min=1, max=30 to dodge accidental
    # zero-second sweeps from a bad config that would DoS the
    # upstream provider.
    ttl_raw = os.environ.get("FULL_SWEEP_INTERVAL_DAYS", "")
    try:
        ttl_days = int(ttl_raw) if ttl_raw else 7
        ttl_days = max(1, min(30, ttl_days))
    except ValueError:
        ttl_days = 7

    # Stagger gap between successive dispatches. Stops 100 sources
    # all firing at second 0 and starving the worker pool. Cheap
    # back-pressure — total dispatch latency is bounded by
    # (N_overdue * STAGGER_S), rarely more than a few minutes.
    STAGGER_S = 30

    dispatched = 0
    skipped_inactive = 0
    skipped_recent = 0

    async with await _get_db_session() as db:
        # Overdue = active source whose last full sweep is NULL or
        # older than the TTL window. Manual / on-demand schedule
        # types are still swept — the sweep is a correctness layer
        # independent of the user's scan cadence.
        rows = await db.execute(
            text(
                """
                SELECT id, tenant_id, name, source_type, last_full_sweep_at
                  FROM scan_sources
                 WHERE is_active = true
                   AND (last_full_sweep_at IS NULL
                        OR last_full_sweep_at < NOW() - make_interval(days => :ttl))
                 ORDER BY COALESCE(last_full_sweep_at, '1970-01-01'::timestamptz) ASC
                """
            ),
            {"ttl": ttl_days},
        )
        overdue = rows.all()
        skipped_inactive = 0  # captured for completeness; query already filters

        for row in overdue:
            src_id, tenant_id, name, source_type, last_sweep = row

            # Create the scan_job row directly here (mirrors the
            # API endpoint's dispatch shape). Cleaner than re-using
            # the API path which would require a fake user / auth
            # context.
            job = ScanJob(
                tenant_id=tenant_id,
                scan_source_id=src_id,
                scan_type=ScanType.STANDALONE,
                status=ScanStatus.PENDING,
                config={
                    "force_full": True,
                    "trigger": "weekly_full_sweep",
                },
            )
            db.add(job)
            await db.flush()

            # Dispatch the Celery task. Concurrency lock inside
            # _run_source_scan handles the case where another scan
            # is already running for this source (the sweep gets
            # CANCELLED with a clear status_message; the next sweep
            # cycle catches up).
            # Store celery_task_id so this sweep scan stays cancellable —
            # the cancel endpoint no-ops without it.
            _sweep_task = run_source_scan.delay(str(job.id), str(src_id))
            job.celery_task_id = _sweep_task.id
            dispatched += 1
            logger.info(
                "source_full_sweep_dispatched",
                source_id=str(src_id),
                source_type=source_type,
                source_name=name,
                last_sweep=last_sweep.isoformat() if last_sweep else None,
                scan_job_id=str(job.id),
            )

            # Stagger between dispatches. Skip the sleep on the
            # last item (no point sleeping after the last dispatch).
            if dispatched < len(overdue):
                await asyncio.sleep(STAGGER_S)

        await db.commit()

    return {
        "dispatched": dispatched,
        "skipped_inactive": skipped_inactive,
        "skipped_recent": skipped_recent,
        "ttl_days": ttl_days,
    }


# ═══════════════════════════════════════════════════════════════════
#  STALE-LOCK CLEANUP — release source-scan locks whose holder job
#  is in a terminal state (COMPLETED / FAILED / CANCELLED).
#
#  Defence-in-depth against stranded locks: the in-process release
#  in `_run_source_scan` covers the normal exit paths, but a
#  SIGKILL'd worker, an OOM, or a Celery `revoke(terminate=True)`
#  during a prefork pool can all bypass the finally block. The lock
#  TTL eventually clears the key, but until then the next scan for
#  that source bounces with "Skipped — another scan is already
#  running". Running this every 5 min keeps the worst-case stranded
#  window short without depending on the TTL alone.
# ═══════════════════════════════════════════════════════════════════

@celery_app.task(bind=True)
def cleanup_stale_source_scan_locks_task(self):
    """Sweep `vooda:source_scan:lock:*` keys; release the ones whose
    holder scan_job has reached a terminal state. Called by Beat."""
    logger.info("source_scan_lock_cleanup_started")
    result = run_async(_cleanup_stale_source_scan_locks())
    logger.info("source_scan_lock_cleanup_complete", **result)


# ═══════════════════════════════════════════════════════════════════
#  STALE RUNNING SCAN-JOB SWEEP
#
#  Worker crashes (SIGKILL, OOM, container restart) leave scan_jobs
#  rows stuck in RUNNING / ANALYZING / PENDING because the in-process
#  state machine never got to flip the status to FAILED. The lock
#  cleanup above releases the redis advisory lock — but the scan_job
#  row stays "RUNNING" forever, misleading every downstream view:
#    - Source-card pill (no failure surfaces)
#    - "Is the scan in progress?" check → yes (incorrectly)
#    - Per-source recent_scans strip → shows a perpetual in-flight dot
#    - Dashboard MTTR → never closes the bucket
#
#  This task scans for jobs older than STALE_SCAN_THRESHOLD_HOURS
#  whose status is still in a non-terminal bucket and force-marks
#  them FAILED with a synthetic error message. 4-hour threshold
#  chosen to be longer than every legitimate scan we've seen
#  (largest repo + AI-triage on 100+ findings runs ~30 min worst
#  case at concurrency=4) so a real long scan won't be force-failed
#  out from under itself, but a worker death is caught within the
#  first beat pass after the threshold.
#
#  Runs every 5 min on the same beat cadence as the lock-cleanup —
#  cheap query (status in tuple, indexed; created_at compared to a
#  scalar) so no risk of contention.
#  Bug fix 2026-05-08.
# ═══════════════════════════════════════════════════════════════════

def _stale_scan_threshold_hours() -> int:
    """Read the stale-scan threshold from env, default 4h.

    Made configurable 2026-05-20 (Track-A P1.4) so slower on-prem
    deployments — large monorepos, AI triage on 500+ findings — can
    push it out without code changes.  Set ``STALE_SCAN_THRESHOLD_HOURS``
    to override; values <1 fall back to the safe 4h default so a
    misconfiguration can't accidentally kill legitimate scans early.

    Kept for backwards-compat — the cleanup task now prefers
    ``_stale_scan_threshold_seconds()`` so sub-hour thresholds (Sprint
    G-1: default 15 min) work without abusing this int-of-hours
    interface.
    """
    import os
    raw = os.getenv("STALE_SCAN_THRESHOLD_HOURS", "4")
    try:
        v = int(raw)
        return v if v >= 1 else 4
    except (ValueError, TypeError):
        return 4


def _stale_scan_threshold_seconds() -> int:
    """Effective stale-scan threshold in seconds (Sprint G-1).

    Resolution order (first that resolves wins):
      1. ``STALE_SCAN_THRESHOLD_MINUTES`` env (sub-hour granularity).
      2. ``STALE_SCAN_THRESHOLD_HOURS`` env (legacy, hour-grain).
      3. Default 90 minutes of no heartbeat (stall) — see below.

    Why 90m, not the old 15m: the heartbeat watchdog still has a
    coverage gap on giant-repo HISTORY scans — the clone/extract phase
    can run for >15m without emitting a heartbeat, so a 15m stall
    threshold FALSE-REAPED legitimate large scans (rustdesk / AutoGPT /
    youtube-dl in the Top-100 benchmark), marking them FAILED and
    dropping real secrets the detectors DO catch (recall gaps R1-R3:
    Firebase .plist key, AWS secret, Supabase JWTs). For a secret
    scanner a false-reap (a missed secret) is worse than a slow zombie
    reap, so the stall threshold is generous; the 4h ABSOLUTE backstop
    (`_stale_scan_threshold_hours`) still kills genuinely-stuck jobs.
    Proper fix (tracked separately, bug #165): emit heartbeats through
    clone/extract so even a tight stall threshold never trips a healthy
    scan. Per-env override via STALE_SCAN_THRESHOLD_MINUTES.
    """
    import os
    raw_min = os.getenv("STALE_SCAN_THRESHOLD_MINUTES")
    if raw_min is not None:
        try:
            v = int(raw_min)
            if v >= 1:
                return v * 60
        except (ValueError, TypeError):
            pass
    raw_h = os.getenv("STALE_SCAN_THRESHOLD_HOURS")
    if raw_h is not None:
        try:
            v = int(raw_h)
            if v >= 1:
                return v * 3600
        except (ValueError, TypeError):
            pass
    return 90 * 60  # 90m stall default — see docstring (R1-R3 false-reap fix)


# Module-level constant kept for backwards-compat with imports / tests
# that referenced it directly; the runtime value lives in
# ``_stale_scan_threshold_hours()`` so env overrides take effect
# without a worker restart on the next beat tick.
STALE_SCAN_THRESHOLD_HOURS = _stale_scan_threshold_hours()

@celery_app.task(bind=True)
def cleanup_stale_running_scans_task(self):
    """Mark zombie RUNNING/PENDING/ANALYZING scan_jobs as FAILED.

    Each sweep also lands:
      • One ``scan_watchdog_failed`` audit event per job (compliance
        trail — answers "when did this scan die and was anything
        notified?").
      • One bell notification to the scan's initiator (when known —
        webhook/system-triggered scans have no initiator and are
        silent on the notification path, the audit row still lands).

    Threshold is env-tunable via STALE_SCAN_THRESHOLD_HOURS (see
    _stale_scan_threshold_hours docstring).
    """
    logger.info("stale_running_scans_cleanup_started")
    result = run_async(_cleanup_stale_running_scans())
    logger.info("stale_running_scans_cleanup_complete", **result)


async def _cleanup_stale_running_scans() -> dict:
    from apps.api.app.models.scan import ScanJob, ScanStatus
    from apps.api.app.models.notification import Notification
    from apps.api.app.models.audit import AuditEvent
    from datetime import datetime, timedelta, timezone

    # Re-read thresholds every tick so an ops-side env change picks up on
    # the next beat without a worker restart.
    #
    # Sprint G-2 — STALL-based detection (the real fix). Two independent
    # reap conditions, OR'd together in the candidate query below:
    #
    #   1. STALL — COALESCE(heartbeat_at, created_at) older than
    #      `stall_seconds` (STALE_SCAN_THRESHOLD_MINUTES, default 15m).
    #      The worker stamps heartbeat_at at every REAL progress point
    #      (phase transition, storing chunk-commit, each completed AI
    #      triage finding), so "no heartbeat for 15m" means genuinely no
    #      progress — a deadlock or a dead worker — NOT merely a slow
    #      large scan. This is precisely what G-1 got wrong: it applied
    #      15m to created_at (total AGE) and so killed legitimately-long
    #      scans (aws-cdk reaped at 15.4m mid-triage while actively
    #      working). Rows with NULL heartbeat_at (created before this
    #      column existed, or not yet past their first progress point)
    #      fall back to created_at via COALESCE — identical to the old
    #      behaviour for those, and still bounded by the backstop below.
    #
    #   2. ABSOLUTE backstop — created_at older than `absolute_seconds`
    #      (STALE_SCAN_THRESHOLD_HOURS, default 4h) regardless of
    #      heartbeat. Catches the pathological "heartbeating but wedged"
    #      case and bounds worst-case runtime, matching CI-runner norms
    #      (GitHub Actions 6h, GitLab 60m defaults).
    stall_seconds = _stale_scan_threshold_seconds()
    absolute_seconds = _stale_scan_threshold_hours() * 3600
    # Defensive: never let the stall threshold exceed the absolute
    # backstop (a misconfigured STALE_SCAN_THRESHOLD_MINUTES > the hours
    # backstop would make condition 1 dead code). Clamp so stall is
    # always the tighter of the two.
    if stall_seconds > absolute_seconds:
        stall_seconds = absolute_seconds
    threshold_hours = round(absolute_seconds / 3600.0, 2)
    _now = datetime.now(timezone.utc)
    stall_cutoff = _now - timedelta(seconds=stall_seconds)
    absolute_cutoff = _now - timedelta(seconds=absolute_seconds)
    non_terminal = (ScanStatus.RUNNING, ScanStatus.PENDING, ScanStatus.ANALYZING)

    def _human(secs: float) -> str:
        secs = int(secs)
        return f"{secs // 3600}h" if secs >= 3600 else f"{secs // 60}m"

    _human_stall = _human(stall_seconds)
    _human_absolute = _human(absolute_seconds)

    async with await _get_db_session() as db:
        # Find candidates first so we can return a useful count and
        # also stamp source.stats for source-scan jobs (so the source
        # card flips to "Last scan failed" without waiting for the
        # next manual scan).
        from sqlalchemy import select as sa_select, or_ as sa_or, func as sa_func
        candidates = (await db.execute(
            sa_select(ScanJob).where(
                ScanJob.status.in_(non_terminal),
                sa_or(
                    # 1. stalled — no progress (heartbeat) for stall_seconds
                    sa_func.coalesce(ScanJob.heartbeat_at, ScanJob.created_at) < stall_cutoff,
                    # 2. absolute backstop — older than absolute_seconds
                    ScanJob.created_at < absolute_cutoff,
                ),
            ).limit(500)  # Bound the per-pass batch — anything bigger
                          # than 500 zombies in one tick is a sign of
                          # something larger going wrong; let beat
                          # catch the rest on the next pass instead of
                          # holding a long-running transaction.
        )).scalars().all()

        if not candidates:
            return {"swept": 0, "source_jobs": 0, "repo_jobs": 0, "audited": 0, "notified": 0}

        from apps.api.app.models.scan_source import ScanSource
        source_count = 0
        repo_count = 0
        audited = 0
        notified = 0
        now = datetime.now(timezone.utc)

        for job in candidates:
            # Per-job reason: which condition actually fired? This fixes
            # the old always-"no worker progress" string, which was
            # misleading whenever the kill was age-based.
            _last_progress = job.heartbeat_at or job.created_at
            if _last_progress < stall_cutoff:
                _reason_human = f"no worker progress for {_human_stall}"
            else:
                _reason_human = f"exceeded the {_human_absolute} maximum scan runtime"
            job.status = ScanStatus.FAILED
            job.error_detail = (
                f"Scan abandoned — {_reason_human}. Marked FAILED by stale-scan "
                f"sweeper. Rerun via the source / repository page; the original "
                f"worker likely stalled (deadlock, OOM, SIGKILL, or container "
                f"restart) before completing."
            )
            if job.scan_source_id:
                # Mirror the per-source stats so the source card
                # immediately shows the failure state. Same pattern
                # as the in-flight failure path in _run_source_scan.
                src = (await db.execute(
                    sa_select(ScanSource).where(ScanSource.id == job.scan_source_id)
                )).scalar_one_or_none()
                if src is not None:
                    src.last_scan_at = now
                    src.stats = {
                        **(src.stats or {}),
                        "last_scan_status": "failed",
                        "last_error": (job.error_detail or "")[:200],
                        "last_scan_at": now.isoformat(),
                    }
                source_count += 1
            else:
                repo_count += 1

            # ── Audit event ─────────────────────────────────────
            # Compliance trail: every force-fail needs a record so
            # auditors can answer "when did this scan die and was
            # anyone told?".  user_id=None (system actor) — the
            # watchdog isn't a person.  Wrapped in try/except so a
            # malformed row can't poison the whole batch.
            try:
                db.add(AuditEvent(
                    tenant_id=job.tenant_id,
                    user_id=None,
                    action="scan_watchdog_failed",
                    resource_type="scan_job",
                    resource_id=str(job.id),
                    detail=f"Scan force-failed by watchdog — {_reason_human}",
                    metadata_={
                        "scan_job_id": str(job.id),
                        "repository_id": str(job.repository_id) if job.repository_id else None,
                        "scan_source_id": str(job.scan_source_id) if job.scan_source_id else None,
                        "scan_type": job.scan_type.value if hasattr(job.scan_type, "value") else str(job.scan_type),
                        "initiated_by": str(job.initiated_by) if job.initiated_by else None,
                        "reason": _reason_human,
                        "stall_threshold": _human_stall,
                        "absolute_threshold": _human_absolute,
                        "last_progress_at": _last_progress.isoformat() if _last_progress else None,
                    },
                ))
                audited += 1
            except Exception as e:
                # Audit failure should not poison the cleanup — log and
                # keep sweeping.  The DB row still gets the FAILED
                # status update, which is the load-bearing piece.
                logger.warning("watchdog_audit_emit_failed", scan_job_id=str(job.id), error=str(e))

            # ── Bell notification ───────────────────────────────
            # Surface the failure to the user who kicked the scan off
            # so they don't have to discover it by spotting a missing
            # spinner.  Webhook/system-triggered scans (initiated_by
            # is NULL) skip the notification — the audit row + source
            # card update still land for those.
            if job.initiated_by is not None:
                try:
                    db.add(Notification(
                        tenant_id=job.tenant_id,
                        user_id=job.initiated_by,
                        title="Scan abandoned",
                        body=(
                            f"A scan you started was marked failed — {_reason_human}. "
                            f"You can retry it from the source or repository page."
                        ),
                        notification_type="scan",
                        resource_type="scan_job",
                        resource_id=str(job.id),
                        is_read=False,
                        metadata_={
                            "scan_job_id": str(job.id),
                            "repository_id": str(job.repository_id) if job.repository_id else None,
                            "scan_source_id": str(job.scan_source_id) if job.scan_source_id else None,
                            "reason": "watchdog_force_fail",
                        },
                    ))
                    notified += 1
                except Exception as e:
                    logger.warning(
                        "watchdog_notification_emit_failed",
                        scan_job_id=str(job.id),
                        user_id=str(job.initiated_by),
                        error=str(e),
                    )

            # ── Sprint G-1: actually free the worker slot ──
            # Marking the DB row FAILED does not terminate the running
            # Python coroutine inside the worker child. Without this
            # revoke a deadlocked task keeps holding its prefork slot
            # until the Celery hard time limit fires (30m post-G-1, was
            # 2h15m). `terminate=True, signal='SIGKILL'` sends an
            # unblockable signal — even an asyncio event loop wedged
            # in `select()` cannot ignore it. Idempotent: a revoke
            # against a task that already finished is a harmless no-op.
            tid = (job.celery_task_id or "").strip()
            if tid:
                try:
                    celery_app.control.revoke(tid, terminate=True, signal="SIGKILL")
                except Exception as _re:
                    logger.warning(
                        "watchdog_revoke_failed",
                        scan_job_id=str(job.id),
                        task_id=tid,
                        error=str(_re)[:200],
                    )

        await db.commit()
        return {
            "swept": len(candidates),
            "source_jobs": source_count,
            "repo_jobs": repo_count,
            "audited": audited,
            "notified": notified,
            "stall_seconds": stall_seconds,
            "absolute_seconds": absolute_seconds,
            "threshold_hours": threshold_hours,
        }


async def _cleanup_stale_source_scan_locks() -> dict:
    from apps.api.app.models.scan import ScanJob, ScanStatus
    from services.source_scanners.concurrency import cleanup_stale_locks as _cleanup_source_locks
    from services.repo_scan.concurrency import cleanup_stale_locks as _cleanup_repo_locks

    terminal_statuses = {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}

    # A non-terminal holder whose progress heartbeat is older than the stall
    # threshold is a ZOMBIE: its worker was hard-killed (container restart, OOM,
    # SIGKILL) before the lock's `finally` could release it, so the scan_jobs row
    # is stuck RUNNING and the Redis lock is orphaned. Without this, a duplicate
    # scan coalesce-cancels into the phantom holder until the 2h20m TTL — observed
    # live when a `docker compose restart worker` killed in-flight large scans.
    # Same threshold as the stall reaper, so we never free a lock the watchdog
    # would still consider live (no risk to a genuinely-slow scan).
    from datetime import datetime, timezone, timedelta
    stale_cutoff = datetime.now(timezone.utc) - timedelta(seconds=_stale_scan_threshold_seconds())

    async with await _get_db_session() as db:
        async def _is_lock_releasable(holder_id: str) -> bool:
            # Holder is the scan_job_id (UUID string). Release the lock when its
            # owner is provably DONE, GONE, or a dead-worker ZOMBIE.
            try:
                job_uuid = UUID(holder_id)
            except (ValueError, TypeError):
                return False  # malformed holder — leave to the TTL
            row = await db.execute(
                select(ScanJob.status, ScanJob.heartbeat_at, ScanJob.created_at)
                .where(ScanJob.id == job_uuid)
            )
            rec = row.first()
            if rec is None:
                # Holder scan no longer exists (deleted) — lock is orphaned.
                return True
            status, hb, created = rec
            if status in terminal_statuses:
                return True
            # Non-terminal but no progress heartbeat past the stall threshold:
            # the worker that owned this lock is dead. Free it.
            last = hb or created
            if last is not None:
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                if last < stale_cutoff:
                    return True
            return False

        # Sweep both lock keyspaces in the same pass — they share the same
        # releasability predicate, so splitting them into separate cron entries
        # would just double the beat-task cost.
        source_result = await _cleanup_source_locks(_is_lock_releasable)
        repo_result = await _cleanup_repo_locks(_is_lock_releasable)
        # #146: heal the adaptive scan-CPU gauge. Reset it to the true count of
        # non-terminal scans so a SIGKILL'd worker that never released its slot
        # can't permanently inflate the gauge (which would shrink every later
        # scan's ProcessPool toward 1). Rides the existing 5-min cleanup beat.
        active_recon = None
        try:
            from services.repo_scan.concurrency import reconcile_scan_active
            from sqlalchemy import func as _func, select as _sel
            running_n = (await db.execute(
                _sel(_func.count(ScanJob.id)).where(ScanJob.status.in_(
                    (ScanStatus.RUNNING, ScanStatus.PENDING, ScanStatus.ANALYZING)
                ))
            )).scalar() or 0
            active_recon = await reconcile_scan_active(int(running_n))
        except Exception as _recon_e:
            logger.debug("scan_active_reconcile_failed", error=str(_recon_e)[:120])
        return {
            "source_scan": source_result,
            "repo_scan": repo_result,
            "scan_active_reconciled": active_recon,
        }


# ═══════════════════════════════════════════════════════════════════
#  FILE-SCAN-CACHE TTL — daily prune of stale entries
#
#  The file_scan_cache table accumulates rows across:
#   - Every (file, content_sha, rule_pack_version) ever seen
#   - Every rule pack bump (built-in changes) leaves the prior
#     version's rows orphaned (different rule_pack_version → never
#     hit again, but they linger)
#   - Custom-rule additions per tenant compound the above
#
#  Without a prune cycle the table grows unboundedly. The TTL is
#  conservative (30 days by default — see DEFAULT_TTL_DAYS in
#  services/secret_scan/file_cache.py) so an active repo's files keep
#  their entries warm across normal dev cycles, and only entries
#  abandoned by a rule update + 30 days of no re-touches get dropped.
#
#  Runs once per day. The prune helper batches at 5000 rows per
#  DELETE so a long-overdue prune doesn't lock the table.
# ═══════════════════════════════════════════════════════════════════

@celery_app.task(bind=True)
def prune_file_scan_cache_task(self):
    """Daily TTL eviction for the file_scan_cache table. Called by Beat."""
    logger.info("file_scan_cache_prune_started")
    result = run_async(_prune_file_scan_cache())
    logger.info("file_scan_cache_prune_complete", rows_deleted=result)


async def _prune_file_scan_cache() -> int:
    """Delete cache rows older than ``FILE_CACHE_TTL_DAYS`` (default 30)."""
    from services.secret_scan.file_cache import prune_stale, DEFAULT_TTL_DAYS
    # Allow operators to tune the TTL without a code change. Falls
    # back to the conservative 30-day default if the env var is unset
    # or malformed.
    ttl_raw = os.environ.get("FILE_CACHE_TTL_DAYS", "")
    try:
        ttl_days = int(ttl_raw) if ttl_raw else DEFAULT_TTL_DAYS
        if ttl_days < 1:
            ttl_days = DEFAULT_TTL_DAYS
    except ValueError:
        ttl_days = DEFAULT_TTL_DAYS

    async with await _get_db_session() as db:
        return await prune_stale(db, ttl_days=ttl_days)


# ═══════════════════════════════════════════════════════════════════
#  NOTIFICATIONS — dispatch after events
# ═══════════════════════════════════════════════════════════════════

@celery_app.task(bind=True)
def send_notification(self, tenant_id: str, title: str, body: str, severity: str = "info", event_type: str = "scan_complete", resource_type: str = None, resource_id: str = None, url: str = None, business_unit_id: str = None):
    """Send notification to scoped channels only (Org/BU/Project)."""
    run_async(_send_notification(tenant_id, title, body, severity, event_type, resource_type, resource_id, url, business_unit_id))


async def _send_notification(tenant_id, title, body, severity, event_type, resource_type, resource_id, url, business_unit_id=None):
    from services.notifications.dispatcher import NotificationDispatcher, NotificationPayload

    async with await _get_db_session() as db:
        dispatcher = NotificationDispatcher()
        payload = NotificationPayload(
            title=title, body=body, severity=severity,
            event_type=event_type, resource_type=resource_type,
            resource_id=resource_id, url=url,
            business_unit_id=business_unit_id,
            repository_id=resource_id if resource_type == "repository" else None,
        )
        results = await dispatcher.dispatch(db, UUID(tenant_id), payload)
        await db.commit()

    for r in results:
        if r.success:
            logger.info("notification_sent", channel=r.channel)
        else:
            logger.warning("notification_failed", channel=r.channel, error=r.error)


# ─── Per-finding ticketing dispatch ────────────────────────────────
#
# Fired right after a scan completes. Loads every finding from the
# scan and asks the dispatcher to fan-out one ticket per finding to
# every active Jira / ServiceNow / Linear / custom-ticketing channel,
# honoring the push rules (severity threshold + the four exclusions)
# saved by the integrations UI.
#
# Decoupled from `send_notification` because notifications and
# ticketing have different shapes: notifications want one summary
# message to humans on Slack/email; ticketing wants one ticket per
# finding with full defect details on the dev team's board. Bundling
# them produced one Jira ticket per scan that just said "27 findings"
# — which is what the user reported was useless.

@celery_app.task(bind=True, max_retries=2)
def dispatch_findings_to_tickets(self, scan_job_id: str):
    """Create per-finding tickets on every configured ticketing channel."""
    logger.info("ticket_fanout_started", scan_job_id=scan_job_id)
    try:
        run_async(_dispatch_findings_to_tickets(scan_job_id))
    except Exception as e:
        logger.warning("ticket_fanout_failed", scan_job_id=scan_job_id, error=str(e)[:200])
        raise self.retry(exc=e, countdown=60)


async def _dispatch_findings_to_tickets(scan_job_id: str):
    from services.notifications.dispatcher import NotificationDispatcher
    from apps.api.app.models.finding import NormalizedFinding
    from apps.api.app.models.scan import ScanJob
    from apps.api.app.models.repository import Repository

    base_url = getattr(settings, "WEB_BASE_URL", None) or "http://localhost:3001"

    async with await _get_db_session() as db:
        job = (await db.execute(
            select(ScanJob).where(ScanJob.id == UUID(scan_job_id))
        )).scalar_one_or_none()
        if not job:
            logger.warning("ticket_fanout_no_scan_job", scan_job_id=scan_job_id)
            return

        # Pull every finding produced by this scan. We do NOT filter by
        # classification here — the dispatcher applies the per-channel
        # push rules itself (so the same scan can fan-out differently
        # to two channels with different thresholds).
        findings = (await db.execute(
            select(NormalizedFinding)
            .where(NormalizedFinding.scan_job_id == UUID(scan_job_id))
            .where(NormalizedFinding.is_suppressed == False)  # noqa: E712
        )).scalars().all()

        repository = None
        if job.repository_id:
            repository = (await db.execute(
                select(Repository).where(Repository.id == job.repository_id)
            )).scalar_one_or_none()

        dispatcher = NotificationDispatcher()
        results = await dispatcher.dispatch_finding_tickets(
            db,
            job.tenant_id,
            findings,
            repository=repository,
            scan_job=job,
            base_url=base_url,
        )
        # The dispatcher mutates finding.tags in place after a
        # successful ticket creation (dedup marker — see
        # NotificationDispatcher.dispatch_finding_tickets). Commit
        # those mutations so re-runs don't fire duplicate tickets.
        await db.commit()

    successes = sum(1 for r in results if r.success)
    failures = sum(1 for r in results if not r.success)
    logger.info(
        "ticket_fanout_completed",
        scan_job_id=scan_job_id,
        attempted=len(results),
        succeeded=successes,
        failed=failures,
    )
    for r in results:
        if not r.success:
            logger.warning("ticket_fanout_channel_failed",
                           scan_job_id=scan_job_id,
                           channel=r.channel, error=r.error)


# ═══════════════════════════════════════════════════════════════════
#  PR CREATION — push fixes to git after patch approval
# ═══════════════════════════════════════════════════════════════════

@celery_app.task(bind=True, max_retries=2)
def create_fix_pr(self, finding_id: str):
    """Create a PR or push branch with the approved patch."""
    logger.info("create_fix_pr_started", finding_id=finding_id)
    run_async(_create_fix_pr(finding_id))


async def _create_fix_pr(finding_id: str):
    from apps.api.app.models.finding import NormalizedFinding
    from apps.api.app.models.remediation import RemediationPlan, RemediationPatch, PatchStatus
    from apps.api.app.models.repository import Repository

    async with await _get_db_session() as db:
        finding = (await db.execute(
            select(NormalizedFinding).where(NormalizedFinding.id == UUID(finding_id))
        )).scalar_one_or_none()
        if not finding:
            logger.error("finding_not_found_for_pr", finding_id=finding_id)
            return

        # Get the latest approved patch
        patch_result = await db.execute(
            select(RemediationPatch)
            .join(RemediationPlan, RemediationPatch.plan_id == RemediationPlan.id)
            .where(RemediationPlan.finding_id == finding.id)
            .order_by(RemediationPatch.created_at.desc())
            .limit(1)
        )
        patch = patch_result.scalar_one_or_none()

        if not patch or not patch.patch_diff:
            logger.warning("no_patch_for_pr", finding_id=finding_id)
            return

        # Get repo info
        repo = (await db.execute(
            select(Repository).where(Repository.id == finding.repository_id)
        )).scalar_one_or_none()

        if not repo:
            logger.error("repo_not_found_for_pr", finding_id=finding_id)
            return

        try:
            from services.git_integration.pr_manager import PRManager
            pr_mgr = PRManager()
            result = await pr_mgr.create_fix_pr(
                repo=repo,
                finding=finding,
                patch_diff=patch.patch_diff,
                files_changed=patch.files_changed or [],
                branch_name="vooda-secure-code",
            )

            if result.get("pr_url"):
                patch.pr_url = result["pr_url"]
                patch.status = PatchStatus.APPLIED
                finding.remediation_status = "applied"
                logger.info("pr_created", finding_id=finding_id, pr_url=result["pr_url"])
            else:
                logger.info("branch_pushed", finding_id=finding_id, branch=result.get("branch"))

            await db.commit()

        except Exception as e:
            logger.error("pr_creation_failed", finding_id=finding_id, error=str(e)[:300])
            # Don't fail the task — patch is still approved, PR creation is best-effort


# ═══════════════════════════════════════════════════════════════════
#  BATCH REMEDIATION — generate fixes for multiple findings
# ═══════════════════════════════════════════════════════════════════

@celery_app.task(bind=True, max_retries=2)
def batch_remediate(self, repository_id: str, finding_ids: list, tenant_id: str):
    """Generate AI remediation for multiple findings."""
    logger.info("batch_remediate_started", repo=repository_id, count=len(finding_ids))
    run_async(_batch_remediate(repository_id, finding_ids, tenant_id))


async def _batch_remediate(repository_id: str, finding_ids: list, tenant_id: str):
    from apps.api.app.models.finding import NormalizedFinding

    async with await _get_db_session() as db:
        for fid in finding_ids:
            try:
                finding = (await db.execute(
                    select(NormalizedFinding).where(
                        NormalizedFinding.id == UUID(fid),
                        NormalizedFinding.tenant_id == UUID(tenant_id),
                    )
                )).scalar_one_or_none()

                if finding and finding.remediation_status in ("none", "rejected"):
                    finding.remediation_status = "pending"
                    await db.flush()
                    # Queue individual remediation
                    generate_remediation.delay(fid)
                    logger.info("batch_remediate_queued", finding_id=fid)

            except Exception as e:
                logger.warning("batch_remediate_item_failed", finding_id=fid, error=str(e)[:200])
                continue

        await db.commit()

    logger.info("batch_remediate_done", count=len(finding_ids))

# ── Secret Verification Task ─────────────────────────────────

@celery_app.task(bind=True, max_retries=1)
def verify_scan_findings(self, scan_job_id: str, tenant_id: str):
    """Verify detected secrets against provider APIs (post-scan, async)."""
    logger.info("verification_task_started", scan_job_id=scan_job_id)
    run_async(_verify_scan_findings(scan_job_id, tenant_id))


async def _verify_scan_findings(scan_job_id: str, tenant_id: str):
    """Async implementation: load regex findings, verify each, update validation_status.

    Stage 3: Before single-call verification, attempt credential pairing —
    if a finding is one half of a known credential pair (AWS access+secret,
    Azure client+secret+tenant, MongoDB Atlas public+private, etc.), look in
    the same file for the complementary value(s) and use the multi-cred
    verifier instead.
    """
    import apps.api.app.models  # noqa: F401
    from apps.api.app.models.finding import NormalizedFinding
    from services.secret_verification.verifier import (
        verify_finding, SUPPORTED_PROVIDERS, VERIFIERS,
    )
    from services.secret_verification.credential_pairing import (
        find_partner_credential, enrich_source_metadata_with_pair, KNOWN_PAIRS,
        _read_file_safely, _resolve_file_path,
    )
    from services.secret_verification.tenant_context import (
        enrich_source_metadata_with_tenant, _TENANT_PATTERNS,
    )
    from services.secret_verification.verification_cache import (
        get_cached_verification, set_cached_verification, is_fresh,
    )
    from services.secret_verification.rate_limiter import acquire as _rl_acquire
    from apps.api.app.models.rotation_event import CredentialRotationEvent
    from datetime import datetime as _dt_mod, timezone as _tz_mod

    def _parse_iso(s: str):
        """Robust ISO-8601 parse; returns aware datetime or None."""
        if not s:
            return None
        try:
            dt = _dt_mod.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_tz_mod.utc)
            return dt
        except Exception:
            return None

    async def _maybe_record_rotation(
        db_session,
        finding,
        prev_status: str,
        prev_first_seen_active: str,
        prev_verified_at: str,
        new_status: str,
        provider: str,
        secret_hash: str,
        detected_via: str,
    ) -> bool:
        """When a credential flips active→inactive, append a rotation event.

        Uses prev_first_seen_active as the anchor for time_to_rotation
        (never overwritten while active). Falls back to prev_verified_at
        when we didn't stamp first-seen (older records before B3).
        """
        if prev_status != "active" or new_status != "inactive":
            return False
        now_utc = _dt_mod.now(_tz_mod.utc)
        first_seen = _parse_iso(prev_first_seen_active) or _parse_iso(prev_verified_at) or now_utc
        ttr_s = max(0, int((now_utc - first_seen).total_seconds()))
        try:
            evt = CredentialRotationEvent(
                tenant_id=finding.tenant_id,
                finding_id=finding.id,
                repository_id=getattr(finding, "repository_id", None),
                provider=provider or "unknown",
                secret_hash=secret_hash or "",
                first_seen_active_at=first_seen,
                rotated_at=now_utc,
                time_to_rotation_s=ttr_s,
                detected_via=detected_via,
                extra={},  # column is named "extra_data" in the DB; attr is "extra"
            )
            db_session.add(evt)
            logger.info(
                "credential_rotation_detected",
                provider=provider,
                secret_hash_prefix=(secret_hash or "")[:12],
                time_to_rotation_s=ttr_s,
                detected_via=detected_via,
            )
            return True
        except Exception as e:
            logger.warning("rotation_event_insert_failed", error=str(e)[:150])
            return False

    # Providers that benefit from tenant extraction (union of main keys and
    # composite role keys like "jira_email"). We strip suffix to get base provider.
    tenant_scoped_providers = {
        key.split("_")[0] for key in _TENANT_PATTERNS.keys()
    } | set(_TENANT_PATTERNS.keys())

    # Per-verification-run cache so we don't re-read the same file N times
    # across findings. key=(repo_id, relative_file_path) → content string.
    file_content_cache: dict = {}

    def _get_file_content(repo_id, file_path: str, repo_root: str) -> str:
        if not file_path:
            return ""
        cache_key = (repo_id, file_path)
        if cache_key in file_content_cache:
            return file_content_cache[cache_key]
        abs_path = _resolve_file_path(file_path, repo_root)
        content = _read_file_safely(abs_path)
        file_content_cache[cache_key] = content
        return content

    # Quick lookup: secret_type → whether it has a pair spec
    paired_primary_types = {p.primary_secret_type for p in KNOWN_PAIRS}

    async with await _get_db_session() as db:
        try:
            # Load all regex-detected findings for this tenant. The previous
            # hard cap of .limit(200) meant repos with more than 200 findings
            # silently ignored the rest forever. We now process all of them
            # with three safety nets:
            #   1. Redis cache (A4) dedups same-hash repeats — bulk of work
            #   2. Incremental commit every COMMIT_EVERY_N so a crash
            #      doesn't lose the whole pass
            #   3. Wall-time budget prevents a runaway task from pinning a
            #      Celery worker slot on a giant repo
            result = await db.execute(
                select(NormalizedFinding).where(
                    NormalizedFinding.tenant_id == tenant_id,
                    NormalizedFinding.source_metadata["detection_method"].astext.in_(
                        ["regex", "regex_base64", "config_key", "entropy", "structured_parse"]
                    ),
                ).order_by(NormalizedFinding.created_at.desc())
            )
            findings = result.scalars().all()

            verified_count = 0
            active_count = 0
            paired_count = 0
            cache_hits = 0
            cache_writes = 0
            rotations_detected = 0

            # ── Scale safety nets (C3) ──
            import time as _time
            COMMIT_EVERY_N = 100
            VERIFICATION_TIME_BUDGET_S = 25 * 60  # 25 minutes
            _start_monotonic = _time.monotonic()
            _pending_ops_since_commit = 0
            _time_budget_hit = False

            # Resolve repo_root for file reads (for inline partner regex)
            repo_paths_by_repo_id: dict = {}

            for _idx, finding in enumerate(findings):
                # Hard time budget — leftover findings stay "unverified"
                # and get picked up on the next scan-triggered verification
                # pass (their source_metadata has no fresh verified_at).
                if _time.monotonic() - _start_monotonic > VERIFICATION_TIME_BUDGET_S:
                    logger.warning(
                        "verification_time_budget_exhausted",
                        scan_job_id=scan_job_id,
                        processed=_idx,
                        total=len(findings),
                    )
                    _time_budget_hit = True
                    break

                # Incremental commit — periodically persist progress so a
                # crash or time-budget break doesn't discard work done so
                # far. Runs before each iteration body so the commit is
                # safely past the last completed mutation.
                if _pending_ops_since_commit >= COMMIT_EVERY_N:
                    await db.commit()
                    _pending_ops_since_commit = 0
                sm = finding.source_metadata or {}
                provider = (sm.get("provider") or "").lower()
                secret_type = (sm.get("secret_type") or "").lower()
                secret_hash = sm.get("secret_hash") or ""

                # ── Freshness-aware skip ──
                # Previously this was a hard skip on any active/inactive
                # status — which meant once a key was marked, we never
                # re-verified even after customer rotation. Now we only
                # skip when the stamp is still within CACHE_TTL.
                if sm.get("validation_status") in ("active", "inactive"):
                    if is_fresh(sm.get("verified_at", "")):
                        continue
                    # else: fall through and re-verify below

                # ── Stage 5: verification-result cache lookup ──
                # If the same secret_hash was verified within the TTL
                # window (could be another finding this pass, or a prior
                # scan on any repo in this tenant), reuse that result
                # instead of calling the provider again.
                if secret_hash:
                    cached = await get_cached_verification(tenant_id, secret_hash)
                    if cached and cached.get("status") in ("active", "inactive"):
                        prev_status = sm.get("validation_status", "")
                        prev_first_seen = sm.get("first_seen_active_at", "")
                        prev_verified_at = sm.get("verified_at", "")

                        updated_sm = dict(sm)
                        updated_sm["validation_status"] = cached["status"]
                        updated_sm["verification_details"] = cached.get("details", "")
                        updated_sm["verification_permissions"] = cached.get("permissions")
                        updated_sm["verified_at"] = cached.get("verified_at", "")
                        updated_sm["verification_source"] = "cache"
                        # B3: anchor first-seen-active so future rotation
                        # events measure from true leak-visible-live moment.
                        if cached["status"] == "active" and not prev_first_seen:
                            updated_sm["first_seen_active_at"] = cached.get("verified_at", "")
                        # B1: pull structured perms through the cache path
                        # too so Blast Radius data survives TTL reuse.
                        if cached.get("permissions_detail") is not None:
                            updated_sm["verification_permissions_detail"] = cached["permissions_detail"]
                        if cached.get("risk_level"):
                            updated_sm["verification_risk_level"] = cached["risk_level"]
                        if cached.get("blast_radius_summary"):
                            updated_sm["blast_radius_summary"] = cached["blast_radius_summary"]
                        finding.source_metadata = updated_sm
                        cache_hits += 1
                        verified_count += 1
                        _pending_ops_since_commit += 1

                        # B3: detect active→inactive rotation via cache.
                        if await _maybe_record_rotation(
                            db, finding, prev_status, prev_first_seen,
                            prev_verified_at, cached["status"], provider,
                            secret_hash, detected_via="cache",
                        ):
                            rotations_detected += 1

                        if cached["status"] == "active":
                            active_count += 1
                            if finding.severity and finding.severity.value in ("medium", "low"):
                                from apps.api.app.models.finding import Severity
                                finding.severity = Severity.HIGH
                        continue

                # ── Stage 4: tenant-context auto-extraction ──
                # Many verifiers (Okta, Auth0, Zendesk, Supabase, Algolia,
                # Jira, Shopify, etc.) need a tenant_domain / app_id /
                # project_url that the scanner didn't capture. Before
                # dispatching, read the surrounding file and regex-extract
                # those identifiers so the verifier can actually run.
                if provider in tenant_scoped_providers:
                    repo_id = finding.repository_id
                    if repo_id and repo_id not in repo_paths_by_repo_id:
                        repo_paths_by_repo_id[repo_id] = f"/app/storage/repos/{repo_id}"
                    repo_root = repo_paths_by_repo_id.get(repo_id, "")
                    file_content = _get_file_content(
                        repo_id, finding.file_path or "", repo_root
                    )
                    if file_content:
                        try:
                            sm = enrich_source_metadata_with_tenant(
                                sm, provider, file_content, finding.line_start or 0
                            )
                        except Exception as te:
                            logger.warning("tenant_extract_error",
                                provider=provider, error=str(te)[:150])

                # ── Stage 3: try credential pairing first ──
                verification = None
                if secret_type in paired_primary_types:
                    # Lookup repo root for file reading
                    repo_id = finding.repository_id
                    if repo_id and repo_id not in repo_paths_by_repo_id:
                        repo_paths_by_repo_id[repo_id] = f"/app/storage/repos/{repo_id}"
                    repo_root = repo_paths_by_repo_id.get(repo_id, "")
                    try:
                        partners = find_partner_credential(
                            primary_secret_type=secret_type,
                            primary_file_path=finding.file_path or "",
                            primary_line=finding.line_start or 0,
                            all_findings=findings,
                            repo_root=repo_root,
                        )
                    except Exception as pe:
                        logger.warning("pairing_error", error=str(pe)[:150])
                        partners = None

                    if partners:
                        enriched = enrich_source_metadata_with_pair(sm, partners)
                        pair_key = partners.get("_pair_key")
                        verifier_fn = VERIFIERS.get(pair_key)
                        if verifier_fn:
                            # C1: cross-process token-bucket rate limit.
                            # Fail-open: if bucket is exhausted past the
                            # wait budget we still proceed, logging the
                            # over-rate event. Correctness > quota.
                            await _rl_acquire(provider)
                            try:
                                verification = await verifier_fn(enriched)
                                paired_count += 1
                                logger.info("paired_verification",
                                    pair_key=pair_key,
                                    file=finding.file_path,
                                    status=verification.status if verification else "none",
                                )
                            except Exception as ve:
                                logger.warning("paired_verification_failed",
                                    pair_key=pair_key, error=str(ve)[:150])

                # Fall back to single-call verification if pairing wasn't done
                if verification is None:
                    if provider not in SUPPORTED_PROVIDERS:
                        continue
                    # C1 rate-limit gate on single-call path too.
                    await _rl_acquire(provider)
                    verification = await verify_finding(sm)

                if verification and verification.status in ("active", "inactive"):
                    # Update source_metadata with verification result
                    from datetime import datetime as _dt, timezone as _tz
                    verified_at_iso = _dt.now(_tz.utc).isoformat(timespec="seconds")
                    prev_status = sm.get("validation_status", "")
                    prev_first_seen = sm.get("first_seen_active_at", "")
                    prev_verified_at = sm.get("verified_at", "")

                    updated_sm = dict(sm)
                    updated_sm["validation_status"] = verification.status
                    updated_sm["verification_details"] = verification.details
                    updated_sm["verification_permissions"] = verification.permissions
                    updated_sm["verified_at"] = verified_at_iso
                    updated_sm["verification_source"] = "live"
                    # B3: anchor first-seen-active on the initial active
                    # observation; never overwrite while the credential
                    # remains active so time_to_rotation measures the
                    # full leak-live-to-rotated window.
                    if verification.status == "active" and not prev_first_seen:
                        updated_sm["first_seen_active_at"] = verified_at_iso
                    # B1: structured permission data for the Blast Radius UI.
                    pd = getattr(verification, "permissions_detail", None)
                    rl = getattr(verification, "risk_level", None)
                    brs = getattr(verification, "blast_radius_summary", None)
                    # Risk-level fallback: only 30 of 246 verifiers emit an
                    # explicit risk_level. For the other 216 we consult a
                    # per-provider default map so the UI still gets a pill
                    # to render. Explicit value always wins over inferred.
                    if rl is None:
                        try:
                            from services.secret_verification.provider_risk import inferred_risk
                            rl = inferred_risk(provider)
                        except Exception:
                            rl = None
                    if pd is not None:
                        updated_sm["verification_permissions_detail"] = pd
                    if rl:
                        updated_sm["verification_risk_level"] = rl
                    if brs:
                        updated_sm["blast_radius_summary"] = brs
                    finding.source_metadata = updated_sm

                    # Populate cache so duplicates within this pass and
                    # subsequent scans within the TTL window skip the
                    # network call. Transient errors are never cached.
                    if secret_hash:
                        wrote = await set_cached_verification(
                            tenant_id,
                            secret_hash,
                            status=verification.status,
                            details=verification.details,
                            provider=verification.provider,
                            permissions=verification.permissions,
                            transient=getattr(verification, "transient", False),
                            permissions_detail=pd,
                            risk_level=rl,
                            blast_radius_summary=brs,
                        )
                        if wrote:
                            cache_writes += 1

                    verified_count += 1
                    _pending_ops_since_commit += 1
                    if verification.status == "active":
                        active_count += 1
                        # Escalate severity for active secrets
                        if finding.severity and finding.severity.value in ("medium", "low"):
                            from apps.api.app.models.finding import Severity
                            finding.severity = Severity.HIGH

                    # B3: detect active→inactive rotation via live call.
                    if await _maybe_record_rotation(
                        db, finding, prev_status, prev_first_seen,
                        prev_verified_at, verification.status, provider,
                        secret_hash, detected_via="live",
                    ):
                        rotations_detected += 1

            # Final commit for anything pending after the loop exits
            # (natural end or time-budget break).
            await db.commit()
            logger.info(
                "verification_task_complete",
                scan_job_id=scan_job_id,
                total_findings=len(findings),
                verified=verified_count,
                active=active_count,
                paired=paired_count,
                cache_hits=cache_hits,
                cache_writes=cache_writes,
                rotations_detected=rotations_detected,
                time_budget_hit=_time_budget_hit,
                elapsed_s=round(_time.monotonic() - _start_monotonic, 2),
            )

        except Exception as e:
            logger.error("verification_task_error", scan_job_id=scan_job_id, error=str(e)[:200])


# ═══════════════════════════════════════════════════════════════════
#  POST-ROTATION RE-VERIFICATION
#  ─────────────────────────────────────────────────────────────────
#  When an admin clicks "Mark rotated" (single or bulk), Vooda
#  flags the incident with rotation_status="rotated" but does NOT
#  re-validate with the provider that the credential is actually
#  revoked.  That left a compliance hole: an incident could sit in
#  the dashboard with rotation_status="rotated" AND validation_status
#  ="active" (still live on the provider) — a contradiction that
#  misled compliance reviewers and gave a false-positive sign-off
#  on rotation work.
#
#  This task fixes the gap by re-running verification asynchronously
#  after the rotation transaction commits.  Async-not-sync because:
#    1. The user shouldn't wait for N × ~2s of provider calls in the
#       response of a bulk operation.
#    2. Verification failures (provider rate-limit, network blip,
#       transient 5xx) must never roll back the rotation flag.
#    3. The result lands in the same incident.validation_status the
#       UI already reads, so no new surface is needed — the truth
#       just becomes visible on the next page load.
#
#  Audit-log lands a "incident_reverified_post_rotation" event so
#  the History tab shows the verification attempt alongside the
#  rotation entry — auditors can correlate "X rotated Y, verifier
#  confirmed revoked" or "X rotated Y, verifier still sees active".
#
#  Added 2026-05-20 for Track-A P0 #3 — closes the false-compliance-
#  signal gap flagged in the product audit.
# ═══════════════════════════════════════════════════════════════════


@celery_app.task(bind=True, max_retries=2)
def reverify_incident_after_rotation(self, incident_id: str, tenant_id: str, actor_user_id: str | None = None):
    """Re-validate a single incident's credential against the provider.

    Args:
        incident_id: SecretIncident UUID (as str so Celery can serialise it).
        tenant_id:   Tenant scope so the worker can't accidentally cross
                     boundaries.  Re-verified against the loaded row.
        actor_user_id: Optional UUID of the human who triggered the
                     rotation.  Threaded into the audit row as the actor
                     when present; falls back to system attribution
                     when None (e.g. automated rotation playbooks).

    Retries: 2 with exponential backoff for transient failures
    (network blips, provider 5xx).  After exhaustion, the audit row
    still lands with status="error" so the trail isn't lost.
    """
    logger.info(
        "reverify_after_rotation_started",
        incident_id=incident_id[:8],
        tenant_id=tenant_id[:8],
    )
    try:
        run_async(_reverify_incident(incident_id, tenant_id, actor_user_id))
    except Exception as exc:  # noqa: BLE001
        # Retry transient failures; on final attempt, fall through so
        # the audit row at least records the failure (handled inside
        # the async helper).
        logger.warning(
            "reverify_after_rotation_failed",
            incident_id=incident_id[:8],
            error=str(exc)[:200],
            retry=self.request.retries,
        )
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc, countdown=2 ** self.request.retries * 30)


async def _reverify_incident(
    incident_id: str,
    tenant_id: str,
    actor_user_id: str | None,
) -> None:
    """Async core of the post-rotation re-verification.

    Mirrors the per-incident verify endpoint logic but runs in the
    worker so the API request returns immediately.  Updates are
    confined to incident.validation_status + last_validated_at +
    every occurrence's source_metadata.validation block — we
    explicitly DO NOT touch rotation_status, so a verifier that
    reports "still active" can't accidentally reopen the incident.
    """
    from datetime import datetime as _dt
    from sqlalchemy import select as _select, update as _update

    from apps.api.app.models.finding import NormalizedFinding, SecretIncident
    from apps.api.app.models.user import User
    from apps.api.app.core.audit import log_audit
    from services.secret_verification.verifier import (
        verify_finding as _verify,
        SUPPORTED_PROVIDERS,
    )

    inc_uuid = UUID(incident_id)
    tenant_uuid = UUID(tenant_id)
    actor_uuid = UUID(actor_user_id) if actor_user_id else None

    async with await _get_db_session() as db:
        # Tenant-scoped lookup — defence in depth against a misrouted
        # task picking up the wrong tenant's incident.
        inc_q = await db.execute(
            _select(SecretIncident).where(
                SecretIncident.id == inc_uuid,
                SecretIncident.tenant_id == tenant_uuid,
            )
        )
        incident = inc_q.scalar_one_or_none()
        if incident is None:
            logger.warning(
                "reverify_incident_not_found",
                incident_id=incident_id[:8],
                tenant_id=tenant_id[:8],
            )
            return

        # Pick the most-recently-seen occurrence as the canonical
        # source — same pattern as the synchronous verify endpoint.
        occ_q = await db.execute(
            _select(NormalizedFinding)
            .where(NormalizedFinding.incident_id == incident.id)
            .order_by(
                NormalizedFinding.last_seen_at.desc().nullslast(),
                NormalizedFinding.created_at.desc(),
            )
            .limit(1)
        )
        occurrence = occ_q.scalar_one_or_none()
        if occurrence is None:
            logger.warning("reverify_incident_no_occurrences", incident_id=incident_id[:8])
            return

        sm = occurrence.source_metadata or occurrence.raw_data or {}
        provider = (sm.get("provider") or "").lower()

        # ── Synthesise an "actor" for log_audit() ──
        # log_audit only needs .tenant_id + .id; build a stub when no
        # human actor is provided (system rotation) so the call shape
        # stays uniform.
        class _StubUser:
            def __init__(self, uid, tid):
                self.id = uid
                self.tenant_id = tid

        actor = _StubUser(actor_uuid or incident.tenant_id, tenant_uuid)
        # Pull the real user record when we have an id — gives the
        # audit row a meaningful user_id rather than a tenant_id.
        if actor_uuid:
            u_q = await db.execute(_select(User).where(User.id == actor_uuid))
            real_user = u_q.scalar_one_or_none()
            if real_user is not None:
                actor = real_user

        if provider not in SUPPORTED_PROVIDERS:
            await log_audit(
                db, actor, "incident_reverified_post_rotation", "secret_incident",
                resource_id=incident.id,
                detail=f"unsupported_provider={provider} (no verifier ships for this provider yet)",
                metadata={
                    "incident_id": str(incident.id),
                    "status": "unsupported",
                    "via": "post_rotation_auto",
                    "provider": provider,
                },
            )
            await db.commit()
            return

        try:
            verification = await _verify(sm)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "reverify_verifier_exception",
                incident_id=incident_id[:8],
                provider=provider,
                error=str(exc)[:200],
            )
            await log_audit(
                db, actor, "incident_reverified_post_rotation", "secret_incident",
                resource_id=incident.id,
                detail=f"verifier_exception={str(exc)[:200]}",
                metadata={
                    "incident_id": str(incident.id),
                    "status": "error",
                    "via": "post_rotation_auto",
                    "provider": provider,
                },
            )
            await db.commit()
            return

        if verification is None:
            return

        previous_status = incident.validation_status
        incident.validation_status = verification.status
        incident.last_validated_at = _dt.utcnow()

        # Propagate the verifier's verdict into each occurrence's
        # source_metadata so the per-finding Validation card shows the
        # same truth.  Single-statement UPDATE via jsonb merge would be
        # marginally faster, but the Python loop is explicit + matches
        # what the synchronous verify endpoint does.
        all_occ_q = await db.execute(
            _select(NormalizedFinding).where(NormalizedFinding.incident_id == incident.id)
        )
        for o in all_occ_q.scalars().all():
            o_sm = dict(o.source_metadata or {})
            o_sm["validation_status"] = verification.status
            o_sm["validation_details"] = verification.details
            o_sm["validation_provider"] = verification.provider
            o_sm["last_validated_at"] = _dt.utcnow().isoformat()
            o.source_metadata = o_sm

        # Compliance-grade audit: surface the FACT that the verifier
        # was rerun, the previous + new validation_status, and the
        # provider's verdict.  This is the row that lets an auditor
        # answer "did we confirm revocation after rotation?".
        await log_audit(
            db, actor, "incident_reverified_post_rotation", "secret_incident",
            resource_id=incident.id,
            detail=(
                f"Post-rotation re-verify: {previous_status} → {verification.status} "
                f"({verification.details[:120]})"
            )[:500],
            metadata={
                "incident_id": str(incident.id),
                "status": verification.status,
                "previous_validation_status": previous_status,
                "provider": verification.provider,
                "via": "post_rotation_auto",
                # When a verifier still sees the credential as ACTIVE
                # after rotation was claimed, flag it loudly in the
                # metadata so compliance dashboards can highlight the
                # contradiction.
                "stale_rotation_marker": verification.status == "active",
            },
        )
        await db.commit()
        logger.info(
            "reverify_after_rotation_complete",
            incident_id=incident_id[:8],
            previous=previous_status,
            new=verification.status,
            stale_marker=(verification.status == "active"),
        )


# ═══════════════════════════════════════════════════════════════════
#  NOTIFICATION RETRY QUEUE
#
#  Track-A P1.5 (2026-05-22): processes pending_retry rows in the
#  notification_deliveries table.  See
#  apps/api/app/models/notification_delivery.py for the model docstring
#  and services/notifications/dispatcher.py for where rows are first
#  persisted.
#
#  Why a periodic task and not a Celery retry on the original task:
#  the original dispatch happens inside the API request lifecycle
#  (e.g. POST /scans triggers notifications synchronously).  Adding
#  Celery's task-level retry there would either block the request
#  (sync mode) or require a separate task chain (complex).  A
#  separate periodic task that reads from a state table is simpler,
#  visible (DB query at any time shows queue depth), and resilient
#  to worker restarts (state is in the DB, not in-memory Celery).
#
#  Cadence: 60s.  Tight enough that the first 1-min-backoff retry
#  lands within ~1m of the original failure; loose enough that the
#  DB query cost is negligible.
# ═══════════════════════════════════════════════════════════════════


@celery_app.task(bind=True)
def process_notification_retries_task(self):
    """Pump the notification retry queue: pick due rows, re-attempt,
    update state, dead-letter after MAX_RETRY_ATTEMPTS exhausted."""
    logger.info("notification_retries_started")
    result = run_async(_process_notification_retries())
    logger.info("notification_retries_complete", **result)


async def _process_notification_retries() -> dict:
    from apps.api.app.models.notification_delivery import (
        NotificationDelivery, RETRY_BACKOFF_SECONDS, MAX_RETRY_ATTEMPTS,
    )
    from apps.api.app.models.integration import IntegrationConfig
    from apps.api.app.models.audit import AuditEvent
    from apps.api.app.models.notification import Notification
    from apps.api.app.models.user import User
    from services.notifications.dispatcher import (
        NotificationDispatcher, NotificationPayload, _is_retryable_error,
    )
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select as sa_select
    from sqlalchemy.orm.exc import StaleDataError

    now = datetime.now(timezone.utc)

    # ── Pick a bounded batch of due rows ───────────────────────
    # Bounded so a worker tick can't be hijacked by a backlog
    # spike.  150 ≈ ~2.5/sec processing rate at 60s cadence.
    BATCH_LIMIT = 150

    async with await _get_db_session() as db:
        candidates = (await db.execute(
            sa_select(NotificationDelivery).where(
                NotificationDelivery.status == "pending_retry",
                NotificationDelivery.next_retry_at <= now,
            ).order_by(NotificationDelivery.next_retry_at.asc()).limit(BATCH_LIMIT)
        )).scalars().all()

        if not candidates:
            return {"processed": 0, "succeeded": 0, "still_retrying": 0, "dead_lettered": 0}

        dispatcher = NotificationDispatcher()
        succeeded = 0
        still_retrying = 0
        dead_lettered = 0

        for row in candidates:
            # ── Look up the integration config (may have been deleted)
            config = None
            if row.integration_config_id is not None:
                config = (await db.execute(
                    sa_select(IntegrationConfig).where(IntegrationConfig.id == row.integration_config_id)
                )).scalar_one_or_none()
            if config is None:
                # Config gone — can't retry without credentials.  DLQ.
                row.status = "dead_lettered"
                row.dead_lettered_at = now
                row.last_error = "Integration config deleted before retry could attempt"
                dead_lettered += 1
                continue

            # ── Reconstruct the payload from the persisted JSON ──
            try:
                payload_kwargs = dict(row.payload or {})
                payload = NotificationPayload(**payload_kwargs)
            except Exception as e:
                # Malformed persisted payload — can't reconstruct.  DLQ
                # rather than infinite-retry a broken row.
                row.status = "dead_lettered"
                row.dead_lettered_at = now
                row.last_error = f"Could not reconstruct payload: {str(e)[:200]}"
                dead_lettered += 1
                continue

            # ── Re-attempt the dispatch through the channel handler ──
            try:
                result = await dispatcher._send_to_channel(config, payload)
            except Exception as e:
                # Synthesise a failed DispatchResult so the rest of the
                # state-machine logic is uniform.
                from services.notifications.dispatcher import DispatchResult
                result = DispatchResult(channel=config.provider, success=False, error=str(e)[:200])

            row.last_attempted_at = now
            row.attempt_count += 1

            if result.success:
                row.status = "succeeded"
                row.succeeded_at = now
                row.last_error = None
                row.next_retry_at = None
                succeeded += 1
                continue

            # Failure path.
            row.last_error = (result.error or "")[:2000]

            if not _is_retryable_error(result.error):
                # Permanent failure surfaced on retry — promote
                # straight to permanent_failure terminal state.
                row.status = "permanent_failure"
                row.dead_lettered_at = now
                row.next_retry_at = None
                dead_lettered += 1
                continue

            if row.attempt_count > MAX_RETRY_ATTEMPTS:
                # Retry budget exhausted.
                row.status = "dead_lettered"
                row.dead_lettered_at = now
                row.next_retry_at = None
                dead_lettered += 1
                # ── DLQ side effects: audit event + admin notification ──
                # Compliance trail: every dead-lettered delivery lands an
                # audit row so reviewers can answer "why didn't I get
                # alerted about X."  System actor (user_id=None) since
                # the watchdog is automated.
                try:
                    db.add(AuditEvent(
                        tenant_id=row.tenant_id,
                        user_id=None,
                        action="notification_dead_lettered",
                        resource_type="notification_delivery",
                        resource_id=str(row.id),
                        detail=(
                            f"Notification to {row.channel} dead-lettered after "
                            f"{MAX_RETRY_ATTEMPTS} retries: {row.last_error[:200]}"
                        ),
                        metadata_={
                            "channel": row.channel,
                            "event_type": row.event_type,
                            "resource_id": row.resource_id,
                            "attempts": row.attempt_count,
                            "final_error": row.last_error[:500] if row.last_error else None,
                        },
                    ))
                except Exception:
                    pass  # never fail the retry loop on audit issues
                continue

            # Still retrying — schedule the next attempt.
            # attempt_count is now 1-indexed POST-increment, so the
            # backoff index is (attempt_count - 1) but with a bounds
            # guard for safety.
            backoff_idx = min(row.attempt_count - 1, MAX_RETRY_ATTEMPTS - 1)
            row.next_retry_at = now + timedelta(seconds=RETRY_BACKOFF_SECONDS[backoff_idx])
            still_retrying += 1

        try:
            await db.commit()
        except StaleDataError:
            # Another retry worker beat us to one of these rows.
            # Roll back; next tick will pick up the remainder.
            await db.rollback()
            logger.warning("notification_retry_stale_data_collision")
            return {"processed": 0, "succeeded": 0, "still_retrying": 0, "dead_lettered": 0, "stale_collision": True}

        return {
            "processed": len(candidates),
            "succeeded": succeeded,
            "still_retrying": still_retrying,
            "dead_lettered": dead_lettered,
        }

