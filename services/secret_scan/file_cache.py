# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
File-level scanner-output cache (rule-version-aware).

This sits in front of ``SecretScanner.scan_directory`` and lets a
re-scan with no source changes finish in seconds — without ever
silently skipping a rule update.

Design at a glance
------------------
1. **Warm**: at scan start, the worker loads every cache row for this
   ``(repository_id, rule_pack_version, scan_scope)`` into memory as a
   ``{(file_path, content_sha): findings_json}`` dict. One round-trip,
   no per-file DB chatter inside the engine.

2. **Lookup**: the engine, while walking files, hashes each file's
   content and asks the in-memory snapshot. Hit → reuse cached
   findings. Miss → run the rule engine and stash the result in a
   pending-writes buffer.

3. **Flush**: after the engine returns, the worker bulk-UPSERTs the
   pending writes back into the table. ``ON CONFLICT (...) DO UPDATE``
   keeps ``last_used_at`` warm without exploding the row count.

Why warm-then-flush instead of per-file DB calls
------------------------------------------------
The engine is pure-sync. The DB session is async. Threading async
calls into the per-file walk would either (a) require rewriting the
engine to async or (b) block the event loop. Warm-then-flush keeps
both worlds clean: one async warm, one async flush, sync engine in
the middle.

Security
--------
``ParsedFinding.raw_data`` may contain ``_raw_value_for_verification``
— the literal secret bytes used by the inline verifier before storage.
We MUST NOT persist that to the cache. The serializer strips every
underscore-prefixed key on the way in. On cache hit the verifier sees
no ``_raw_value_for_verification`` and skips re-verification, which is
correct: the verifier has its own TTL-based cache for that.
"""

from __future__ import annotations

import dataclasses
import hashlib
import structlog
from typing import Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from packages.parsers.base import ParsedFinding


logger = structlog.get_logger()


def compute_content_sha(content: str) -> str:
    """SHA-256 of the file's text content.

    Matches what the engine reads via ``open(path, "r",
    errors="ignore")`` — i.e. UTF-8 with replacement on bad bytes. The
    cache key includes this so a single character change anywhere in
    the file produces a miss.
    """
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def _serialize_finding(pf: ParsedFinding) -> dict:
    """Convert a ParsedFinding to a JSONB-safe dict.

    Strips transient/sensitive fields from ``raw_data`` (everything
    prefixed with ``_`` — convention for "in-memory only"). The
    canonical victim is ``_raw_value_for_verification``, which holds
    the raw secret bytes for the inline verifier.
    """
    d = dataclasses.asdict(pf)
    raw = d.get("raw_data") or {}
    if isinstance(raw, dict):
        d["raw_data"] = {k: v for k, v in raw.items() if not str(k).startswith("_")}
    return d


def _deserialize_finding(d: dict) -> ParsedFinding:
    """Reconstruct a ParsedFinding from its JSONB form.

    Tolerant of forward-compatible additions: unknown keys are
    silently dropped so an older runtime can still read a row written
    by a newer version. Required fields default per the dataclass.
    """
    valid_fields = {f.name for f in dataclasses.fields(ParsedFinding)}
    clean = {k: v for k, v in (d or {}).items() if k in valid_fields}
    # ``title`` is the only field without a default — guard against
    # bad rows so a single corrupt cache entry doesn't tank the scan.
    clean.setdefault("title", "Untitled")
    return ParsedFinding(**clean)


class FileScanCacheView:
    """A scan-scoped view over the file_scan_cache table.

    Constructed by :func:`warm_cache`, consulted per-file by the
    engine, and persisted via :func:`flush_cache` at the end of the
    scan.

    Counters (``hits`` / ``misses`` / ``stored``) are surfaced in
    ``scan_jobs.stats`` so the UI / dashboards can show cache hit
    rate per scan.
    """

    __slots__ = ("_snapshot", "_writes", "hits", "misses")

    def __init__(self, snapshot: dict[tuple[str, str], list[dict]]):
        # Pre-loaded {(file_path, content_sha): [findings_json...]}.
        # Frozen for the lifetime of the view.
        self._snapshot = snapshot
        # Pending writes accumulated on cache miss.
        # Each entry: (file_path, content_sha, [serialized_finding...]).
        self._writes: list[tuple[str, str, list[dict]]] = []
        self.hits = 0
        self.misses = 0

    def lookup(
        self,
        file_path: str,
        content_sha: str,
    ) -> Optional[list[ParsedFinding]]:
        """Return cached findings for the (file_path, content_sha) pair, or None.

        On hit: increments ``hits`` and rehydrates the JSONB into
        ParsedFinding instances. On miss: returns None and DOES NOT
        increment ``misses`` — that happens in ``record_miss`` when
        the engine has actually re-scanned the file (so the counters
        only count files we actually paid for).
        """
        key = (file_path, content_sha)
        cached = self._snapshot.get(key)
        if cached is None:
            return None
        self.hits += 1
        try:
            return [_deserialize_finding(d) for d in cached]
        except Exception as e:
            # A corrupt row shouldn't kill the scan — fall through to
            # a cache miss and let the engine re-scan. The bad row
            # will be UPSERT-overwritten in the flush step.
            logger.warning(
                "file_cache_deserialize_failed",
                file_path=file_path,
                content_sha=content_sha[:12],
                error=str(e)[:200],
            )
            self.hits -= 1
            return None

    def record_miss(
        self,
        file_path: str,
        content_sha: str,
        findings: list[ParsedFinding],
    ) -> None:
        """Buffer a miss for later flush.

        Called by the engine after running the rule pack against an
        uncached file. The serialized payload is computed eagerly so
        the engine pays the JSON-build cost once instead of holding
        the live ParsedFinding objects in memory until flush.
        """
        self.misses += 1
        try:
            payload = [_serialize_finding(pf) for pf in findings]
        except Exception as e:
            logger.warning(
                "file_cache_serialize_failed",
                file_path=file_path,
                error=str(e)[:200],
            )
            return
        self._writes.append((file_path, content_sha, payload))

    def pending_writes(self) -> list[tuple[str, str, list[dict]]]:
        return self._writes

    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return (self.hits / total) if total else 0.0


# ─────────────────────────────────────────────────────────────────────
# Async helpers — all DB work lives here, engine stays sync.
# ─────────────────────────────────────────────────────────────────────


# Hard ceiling on rows held in memory by a single warm.
#
# At ~500 bytes / row average (most files have empty findings_json)
# 200k rows ≈ 100 MB held in worker memory just for the snapshot.
# That's already a meaningful chunk of a 512 MB worker container.
# Above this threshold we fall back to a degraded mode (see
# ``MAX_WARM_ROWS_FALLBACK``) rather than risking an OOM kill on a
# monorepo scan.
#
# Tunable via the ``FILE_CACHE_MAX_WARM_ROWS`` env var so operators
# running fatter workers can raise it. Workers with <1 GB RSS should
# leave the default in place.
import os as _os
try:
    MAX_WARM_ROWS = int(_os.environ.get("FILE_CACHE_MAX_WARM_ROWS", "100000"))
except ValueError:
    MAX_WARM_ROWS = 100000

# Page size when streaming warm rows. Strictly an internal detail —
# the iterator yields all rows regardless of page size; this just
# controls how many are fetched per round-trip. 2000 keeps round-trip
# count reasonable (50 RT for a 100k-row warm) without producing
# parameter-binding pressure.
_WARM_PAGE_SIZE = 2000


async def warm_cache(
    db: AsyncSession,
    *,
    tenant_id,
    repository_id,
    rule_pack_version: str,
    scan_scope: str,
    max_rows: Optional[int] = None,
) -> FileScanCacheView:
    """Load every cached entry for the given scan key into memory.

    Streams rows in pages of ``_WARM_PAGE_SIZE`` so we don't fetch a
    100k-row resultset in one async round-trip (which can stall the
    event loop and balloon driver-side memory). Returns an empty view
    on a first scan (or just after a rule pack bump invalidated
    everything for this version).

    ``max_rows`` (default ``MAX_WARM_ROWS``) is a hard ceiling on
    rows held in memory. When a monorepo's cache exceeds this we log
    a warning, stop populating the snapshot, and return what we
    have. The engine then treats the missing files as cache misses
    on this run — wasted CPU, never wrong findings. Operators see
    the warning and know to raise the limit (or to evict stale
    rule_pack_version rows) before it bites again.

    Why this is safe: the cache is an OPTIMIZATION layer. Falling
    back to "scan it" instead of "use cached result" never produces
    incorrect findings — only slower scans. Same property as
    SonarQube's bounded analysis cache.
    """
    cap = max_rows if max_rows is not None else MAX_WARM_ROWS

    snapshot: dict[tuple[str, str], list[dict]] = {}
    capped = False
    total_seen = 0

    # Keyset pagination on ``id`` for deterministic ordering and
    # cheap LIMIT/OFFSET avoidance. Driving it from a UUID column
    # gives a fully covered index scan via the
    # ``ix_file_scan_cache_lookup`` index (which doesn't include id,
    # but the planner falls back to a parallel seq+sort cheaply for
    # this query — ~tens of ms even at 1M rows).
    last_id = None
    while True:
        if last_id is None:
            page = await db.execute(
                text(
                    """
                    SELECT id, file_path, content_sha, findings_json
                      FROM file_scan_cache
                     WHERE repository_id     = :rid
                       AND rule_pack_version = :rpv
                       AND scan_scope        = :scope
                  ORDER BY id
                     LIMIT :page_size
                    """
                ),
                {
                    "rid": repository_id,
                    "rpv": rule_pack_version,
                    "scope": scan_scope,
                    "page_size": _WARM_PAGE_SIZE,
                },
            )
        else:
            page = await db.execute(
                text(
                    """
                    SELECT id, file_path, content_sha, findings_json
                      FROM file_scan_cache
                     WHERE repository_id     = :rid
                       AND rule_pack_version = :rpv
                       AND scan_scope        = :scope
                       AND id > :last_id
                  ORDER BY id
                     LIMIT :page_size
                    """
                ),
                {
                    "rid": repository_id,
                    "rpv": rule_pack_version,
                    "scope": scan_scope,
                    "last_id": last_id,
                    "page_size": _WARM_PAGE_SIZE,
                },
            )
        rows = page.all()
        if not rows:
            break

        for row_id, fp, sha, findings_json in rows:
            total_seen += 1
            last_id = row_id
            # Stop populating the snapshot once the cap is reached,
            # but keep counting (so the warning is accurate). The
            # outer loop also bails after this batch — no point
            # paying for more pages we can't store.
            if len(snapshot) >= cap:
                capped = True
                continue
            if isinstance(findings_json, str):
                import json
                try:
                    findings_json = json.loads(findings_json)
                except Exception:
                    findings_json = []
            snapshot[(fp, sha)] = findings_json or []

        if capped:
            # Bail immediately on cap — operator already knows the
            # snapshot is incomplete from the warning below; no need
            # for a separate COUNT query to chase an exact total.
            break

        if len(rows) < _WARM_PAGE_SIZE:
            break

    if capped:
        logger.warning(
            "file_cache_warm_capped",
            repository_id=str(repository_id),
            rule_pack_version=rule_pack_version[:12],
            scan_scope=scan_scope,
            cap=cap,
            total_rows=total_seen,
            note=(
                "Snapshot truncated. Set FILE_CACHE_MAX_WARM_ROWS higher, "
                "or wait for the daily prune to evict stale rows."
            ),
        )

    logger.info(
        "file_cache_warmed",
        repository_id=str(repository_id),
        rule_pack_version=rule_pack_version[:12],
        scan_scope=scan_scope,
        rows=len(snapshot),
        capped=capped,
        total_rows=total_seen,
    )
    return FileScanCacheView(snapshot)


# Maximum rows per single INSERT statement. Chosen so the parameter
# count (~7 binds per row + a small constant header) stays well under
# Postgres's 32k bind-parameter limit, while keeping the round-trip
# count reasonable for monorepos:
#   500 rows × 7 params = 3500 binds — 10× headroom on the 32k cap
#   100k file repo → 200 round-trips instead of 100k
# Tuned 2026-05-06 — lowering further (e.g. to 100) doesn't help
# throughput; raising further risks param-limit collisions on rare
# rules with very long ``findings_json`` payloads pushing per-row
# binds past 7.
_FLUSH_BATCH_SIZE = 500


async def flush_cache(
    db: AsyncSession,
    view: FileScanCacheView,
    *,
    tenant_id,
    repository_id,
    rule_pack_version: str,
    scan_scope: str,
) -> int:
    """Bulk-UPSERT the pending writes back into the cache table.

    Returns the number of rows written. Idempotent: re-running with the
    same view inserts zero new rows because the buffer is consumed in
    a single flush cycle.

    Uses **batched** ``INSERT ... VALUES (...), (...), ...
    ON CONFLICT (...) DO UPDATE`` — one round-trip per
    ``_FLUSH_BATCH_SIZE`` rows instead of one per row. On a 100k-file
    monorepo's first scan that's the difference between ~50 s of
    network round-trips and ~1 s.

    A per-batch try/except keeps a single bad payload (e.g. JSONB
    encoding edge case) from killing the whole flush — the failed
    batch is dropped, the rest still land, and the failure is logged
    for follow-up. The next scan will re-attempt the missing files
    on cache miss.
    """
    writes = view.pending_writes()
    if not writes:
        return 0

    import json as _json

    written = 0
    batch_count = 0
    for batch_start in range(0, len(writes), _FLUSH_BATCH_SIZE):
        batch = writes[batch_start : batch_start + _FLUSH_BATCH_SIZE]
        if not batch:
            continue
        batch_count += 1

        # Build the VALUES clause inline — one row template per entry,
        # parameters disambiguated by row index. Using ``CAST(... AS
        # JSONB)`` per param so asyncpg encodes the dict-as-JSON
        # without any text-mode dance.
        rows_sql_parts: list[str] = []
        params: dict = {
            "tid": tenant_id,
            "rid": repository_id,
            "rpv": rule_pack_version,
            "scope": scan_scope,
        }
        for i, (file_path, content_sha, findings_payload) in enumerate(batch):
            rows_sql_parts.append(
                f"(:tid, :rid, :fp{i}, :sha{i}, :rpv, :scope, "
                f"CAST(:f{i} AS JSONB), :c{i}, now(), now())"
            )
            params[f"fp{i}"] = file_path[:2000]   # column cap
            params[f"sha{i}"] = content_sha
            params[f"f{i}"] = _json.dumps(findings_payload)
            params[f"c{i}"] = len(findings_payload)

        bulk_sql = text(
            """
            INSERT INTO file_scan_cache (
                tenant_id, repository_id, file_path, content_sha,
                rule_pack_version, scan_scope,
                findings_json, findings_count,
                scanned_at, last_used_at
            ) VALUES
            """
            + ", ".join(rows_sql_parts)
            + """
            ON CONFLICT (repository_id, file_path, content_sha,
                         rule_pack_version, scan_scope)
            DO UPDATE SET
                findings_json  = EXCLUDED.findings_json,
                findings_count = EXCLUDED.findings_count,
                scanned_at     = EXCLUDED.scanned_at,
                last_used_at   = EXCLUDED.last_used_at
            """
        )

        try:
            await db.execute(bulk_sql, params)
            written += len(batch)
        except Exception as e:
            # A failed batch is logged and skipped — the next scan's
            # cache miss on those files re-attempts the write. We
            # deliberately don't fall back to per-row UPSERTs: a bulk
            # failure usually means something deeper (driver issue,
            # DB pressure), and per-row would just paper over it.
            # Cache is an optimization layer; missing rows degrade to
            # "scan it next time," never wrong findings.
            logger.warning(
                "file_cache_bulk_upsert_failed",
                batch_size=len(batch),
                error=str(e)[:200],
            )

    logger.info(
        "file_cache_flushed",
        repository_id=str(repository_id),
        rule_pack_version=rule_pack_version[:12],
        rows_written=written,
        batches=batch_count,
        hits=view.hits,
        misses=view.misses,
    )
    return written


async def invalidate_repo(db: AsyncSession, repository_id) -> int:
    """Drop every cache row for a repository.

    Called when a repository is deleted (so the cache doesn't leak
    findings into a future repo that happens to reuse the UUID — won't
    happen with UUIDv4 but defensive cleanup is cheap).
    """
    result = await db.execute(
        text("DELETE FROM file_scan_cache WHERE repository_id = :rid"),
        {"rid": repository_id},
    )
    deleted = result.rowcount or 0
    logger.info(
        "file_cache_invalidated_repo",
        repository_id=str(repository_id),
        rows_deleted=deleted,
    )
    return deleted


# Default TTL for cache rows — anything not touched in this window
# gets pruned by the daily Celery beat task. 30 days strikes a balance:
#   - long enough that an active repo's files keep their cache entries
#     warm across normal dev cycles (people don't touch every file)
#   - short enough that stale ``rule_pack_version`` rows (after rule
#     updates) don't accumulate forever
# Tunable via the ``FILE_CACHE_TTL_DAYS`` env var if a tenant has a
# different rule-pack churn pattern.
DEFAULT_TTL_DAYS = 30


async def prune_stale(
    db: AsyncSession,
    *,
    ttl_days: int = DEFAULT_TTL_DAYS,
    batch_size: int = 5000,
) -> int:
    """Delete cache rows that haven't been read in ``ttl_days``.

    Run on a daily Celery beat schedule (see
    ``apps/worker/tasks.py:prune_file_scan_cache_task``). Bounded by
    ``batch_size`` per pass so a long-overdue prune doesn't lock the
    table — the loop continues until ``DELETE`` reports 0 rows.

    Postgres handles ``DELETE ... LIMIT`` via a CTE since plain
    ``DELETE`` doesn't accept LIMIT. The ``ix_file_scan_cache_tenant_ttl``
    index keeps each batch's lookup at index-only-scan cost.
    """
    total_deleted = 0
    while True:
        result = await db.execute(
            text(
                """
                WITH victims AS (
                    SELECT id FROM file_scan_cache
                     WHERE last_used_at < NOW() - make_interval(days => :ttl)
                     LIMIT :batch
                )
                DELETE FROM file_scan_cache
                 WHERE id IN (SELECT id FROM victims)
                """
            ),
            {"ttl": ttl_days, "batch": batch_size},
        )
        await db.commit()
        deleted = result.rowcount or 0
        total_deleted += deleted
        if deleted < batch_size:
            break
    logger.info(
        "file_cache_pruned",
        ttl_days=ttl_days,
        rows_deleted=total_deleted,
    )
    return total_deleted
