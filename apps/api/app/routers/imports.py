# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""CLI / CI findings-import endpoint — P0 two-way sync (ingest side).

This is the **UP** half of Vooda's two-way CLI↔platform sync: a developer
running ``vooda scan`` locally, or a CI pipeline running ``vooda monitor``,
POSTs the findings its *client-side* Vooda engine produced back to the
platform so the dashboard, incident management, history and policy gate all
see the same secrets the CLI saw.  The **DOWN** half (policy + suppressions
pushed to the CLI) lives elsewhere.

Why a dedicated router (Approach B)
-----------------------------------
The server-side scan pipeline (``apps/worker/tasks._run_scan_job``) is
deliberately **not touched**.  This endpoint validates + persists an import
job and hands off to a Celery task that calls the focused
``_store_imported_findings`` helper, which reuses the SAME consistency
primitives the server scan uses (``compute_secret_stability_id`` for the
dedup key and ``_upsert_secret_incident`` for incident aggregation).  Net
effect: an imported CI finding dedupes against, and renders identically to,
a server scan of the same secret — with ZERO risk to the existing pipeline.

Security model (enforced here, at the trust boundary)
-----------------------------------------------------
1. **Scope gate** — ``require_scope("findings:import")``.  CI keys are
   provisioned write-only with exactly this scope, never ``admin``.
2. **Tenant isolation** — ``tenant_id`` is derived from the authenticated
   API key's owning user (``user.tenant_id``), *never* from the request
   body.  A key can only ever import into its own tenant, and only against
   a repository that already belongs to that tenant.
3. **Redaction firewall (WS-6 at the edge)** — the platform must never
   accept, store, or log a *raw* secret value:
     a. Pydantic ``extra="forbid"`` on every model → an allowlist schema;
        any unexpected field (a place a raw value could hide) is a 422.
     b. A recursive forbidden-key tripwire over the whole body rejects
        payloads carrying high-signal raw-value field names.
     c. Each ``masked_value`` is checked to actually BE masked; a long,
        high-entropy, mask-free value is rejected as a probable raw secret.
     d. Each ``code_snippet`` is scrubbed of high-entropy unmasked tokens
        (non-fatal — a legitimate import is never broken; the worker then
        runs the authoritative 946-rule scanner scrub before storage).
4. **Idempotency** — an ``Idempotency-Key`` (header or body) collapses CI
   retries / at-least-once runners to a single scan job via the partial-
   unique ``(tenant_id, idempotency_key)`` index; a replay returns the
   existing job (HTTP 200) instead of double-creating.

The endpoint returns ``202 Accepted`` with the created ``scan_job_id`` and
enqueues ``ingest_imported_findings`` on the dedicated ``scans`` queue.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Header
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.database import get_db
from apps.api.app.core.security import require_scope
from apps.api.app.models.user import User
from apps.api.app.models.repository import Repository
from apps.api.app.models.scan import ScanJob, ScanType, ScanStatus
from apps.api.app.models.finding import ImportedFinding

router = APIRouter()

# ── Caps (DoS guards — a write-only key must not be able to OOM the API) ──
MAX_FINDINGS_PER_IMPORT = 50_000
MAX_SNIPPET_LEN = 8_000  # truncate oversized snippets defensively

# ── Redaction-firewall constants ─────────────────────────────────────────
# High-signal raw-value field names.  No legitimate field in our allowlist
# schema uses these (we carry ``masked_value`` + ``secret_hash`` only), so an
# exact, case-insensitive key match is a near-zero-false-positive tripwire
# for a client that forgot to mask.  Deliberately NOT including generic names
# like "value"/"secret"/"password" — those collide with benign nested data
# (``stats`` is the only free-form surface) and ``extra="forbid"`` already
# rejects unknown finding-level keys.
_FORBIDDEN_KEYS = {
    "raw_value",
    "raw_secret",
    "rawsecret",
    "plaintext",
    "plain_text",
    "cleartext",
    "clear_text",
    "unmasked",
    "unmasked_value",
    "_raw_value_for_verification",
    "paired_raw",
}
# Markers that indicate a token was masked, used by the NON-FATAL snippet
# scrub.  Broad set (includes x/X) — over-matching here just means we scrub
# slightly less aggressively, which is safe.
_MASK_MARKERS = ("*", "…", "...", "•", "x", "X", "[REDACTED]", "REDACTED", "‹", "▒")
# STRICT marker set for the FATAL masked_value check.  Deliberately excludes
# plain x/X (they collide with legitimate hex/base64/text — e.g. the "X" in
# "AKIAIOSFODNN7EXAMPLE") so a raw AWS key is NOT mistaken for a masked one.
# A real masked value (e.g. "AKIA************Q7QF", "ghp_••••") always
# carries one of these unambiguous markers.
_STRICT_MASK_MARKERS = ("*", "…", "•", "▒", "[REDACTED]", "REDACTED", "‹", "›", "◦", "·")
_ENTROPY_BITS_THRESHOLD = 4.0
_UNMASKED_MIN_LEN = 20
# A masked_value at least this long with NO strict mask marker is treated as
# an unmasked raw secret and rejected (422).  Short tail-only reveals like
# "Q7QF" stay under the bar and pass.
_MASKED_VALUE_MARKER_MIN_LEN = 12


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char — high for random secrets, low for prose."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_unmasked(token: str) -> bool:
    """True when a contiguous token looks like a raw (unmasked) secret:
    long enough, no mask marker present, and high Shannon entropy.

    Tuned conservatively so it does NOT trip on prose or short identifiers.
    It CAN trip on a bare 40-char git SHA / UUID embedded in a snippet — that
    is acceptable here because (a) the snippet is display-only context and
    (b) the snippet path SCRUBS rather than rejects, so an import is never
    broken, only slightly over-redacted in its rendered code preview.

    Uses the STRICT marker set (no plain x/X): base64 secret bodies (PEM keys,
    JWTs, tokens) routinely contain x/X, so treating those as "masked" would
    let a high-entropy base64 token slip past this defense-in-depth backstop.
    Over-redacting a benign high-entropy token in the display snippet is the
    safe failure direction.
    """
    if len(token) < _UNMASKED_MIN_LEN:
        return False
    if any(m in token for m in _STRICT_MASK_MARKERS):
        return False
    return _shannon_entropy(token) >= _ENTROPY_BITS_THRESHOLD


def _masked_value_is_unmasked(mv: str) -> bool:
    """FATAL check: True when a ``masked_value`` is non-trivially long but
    carries NO strict mask marker — i.e. the client sent a raw value where a
    masked one was required.  Marker-presence based (not entropy) so it
    reliably catches low-entropy structured secrets like AWS access key IDs
    (``AKIA…``) that the entropy heuristic would miss.
    """
    if not mv or len(mv) < _MASKED_VALUE_MARKER_MIN_LEN:
        return False
    return not any(m in mv for m in _STRICT_MASK_MARKERS)


def _assert_no_forbidden_keys(obj, _depth: int = 0) -> None:
    """Recursively reject any forbidden raw-value key anywhere in the body.

    Backstop for the one free-form surface (``stats``); the typed models are
    already locked down by ``extra="forbid"``.  Bounded recursion depth.
    """
    if _depth > 8:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and k.strip().lower() in _FORBIDDEN_KEYS:
                raise HTTPException(
                    status_code=422,
                    detail=(
                        f"Payload carries a forbidden raw-secret field '{k}'. "
                        "Vooda never accepts unmasked secret values — send "
                        "masked_value + secret_hash only."
                    ),
                )
            _assert_no_forbidden_keys(v, _depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _assert_no_forbidden_keys(item, _depth + 1)


def _scrub_snippet(snippet: Optional[str]) -> tuple[Optional[str], int]:
    """Replace high-entropy unmasked tokens in a snippet with a marker.

    Non-fatal belt-and-suspenders so a raw value accidentally left in the
    code preview never reaches storage.  Returns (scrubbed, n_scrubbed).
    """
    if not snippet:
        return snippet, 0
    if len(snippet) > MAX_SNIPPET_LEN:
        snippet = snippet[:MAX_SNIPPET_LEN]
    scrubbed = 0
    # Split on common code delimiters while keeping the delimiters so the
    # snippet structure (and line breaks) survive the re-join.
    parts = re.split(r"([\s\"'`=:,;()\[\]{}<>]+)", snippet)
    out: list[str] = []
    for tok in parts:
        if tok and _looks_unmasked(tok):
            out.append("[REDACTED-HIGH-ENTROPY]")
            scrubbed += 1
        else:
            out.append(tok)
    return "".join(out), scrubbed


# ── Request schemas (allowlist — extra="forbid" is part of the firewall) ──
class ImportFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    file_path: str  # repo-relative — required for a stable, server-matching dedup key
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    vulnerability_category: Optional[str] = None
    cwe: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    confidence: Optional[float] = None
    code_snippet: Optional[str] = None  # MUST be pre-masked by the client
    secret_type: Optional[str] = None
    masked_value: Optional[str] = None  # masked only — never the raw value
    secret_hash: Optional[str] = None
    detection_method: Optional[str] = None
    validation_status: Optional[str] = None
    provider: Optional[str] = None
    entropy_score: Optional[float] = None
    commit_sha: Optional[str] = None


class ImportProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    commit_sha: Optional[str] = None
    branch: Optional[str] = None
    actor: Optional[str] = None  # UNTRUSTED, self-reported by the runner — display only
    ci_provider: Optional[str] = None  # github_actions, gitlab_ci, ...
    ci_pipeline_url: Optional[str] = None
    scan_type: Optional[str] = None  # "cli" | "ci" (defaults inferred from ci_provider)


class ImportScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repository_id: Optional[UUID] = None
    repository_ref: Optional[str] = None  # git remote URL or repo name (flat route)
    provenance: ImportProvenance = Field(default_factory=ImportProvenance)
    findings: list[ImportFinding] = Field(default_factory=list)
    stats: Optional[dict] = None
    client: Optional[str] = None  # e.g. "vooda-cli/1.4.0"
    idempotency_key: Optional[str] = None  # body fallback for the header


class ImportAccepted(BaseModel):
    scan_job_id: str
    status: str
    scan_type: str
    repository_id: str
    findings_received: int
    findings_scrubbed: int
    idempotent_replay: bool


def _remote_slug(s: str) -> str:
    """Normalize a git remote to a comparable ``host/org/repo`` slug.

    Handles the common CI mismatch where the runner reports
    ``git@github.com:org/repo.git`` or ``https://github.com/org/repo.git``
    but Vooda stored ``https://github.com/org/repo``.
    """
    if not s:
        return ""
    v = s.strip().lower()
    v = re.sub(r"^[a-z]+://", "", v)  # strip scheme
    v = re.sub(r"^[^@/]+@", "", v)  # strip user@ (ssh)
    v = v.replace(":", "/", 1) if "@" not in v and "/" not in v.split(":", 1)[0] else v
    v = re.sub(r"^git@", "", v)
    v = v.replace(".git", "")
    v = v.rstrip("/")
    # Collapse ssh "host:org/repo" form to "host/org/repo"
    v = v.replace(":", "/")
    return v


async def _resolve_repo(
    db: AsyncSession,
    user: User,
    repo_id: Optional[UUID],
    repository_ref: Optional[str],
) -> Repository:
    """Tenant-scoped repository resolution.  The tenant filter is the hard
    security boundary — a ``findings:import`` key can only import against a
    repository already onboarded under its own tenant.  No auto-create in P0.
    """
    if repo_id is None and not repository_ref:
        raise HTTPException(
            status_code=422,
            detail="Provide repository_id (preferred) or repository_ref (git remote URL / name).",
        )

    base = select(Repository).where(Repository.tenant_id == user.tenant_id)

    if repo_id is not None:
        repo = (await db.execute(base.where(Repository.id == repo_id))).scalar_one_or_none()
        if not repo:
            raise HTTPException(status_code=404, detail="Repository not found for this tenant.")
        return repo

    # repository_ref path: exact match first, then normalized git-slug match.
    repo = (
        await db.execute(
            base.where(or_(Repository.url == repository_ref, Repository.name == repository_ref)).limit(1)
        )
    ).scalar_one_or_none()
    if repo:
        return repo

    want = _remote_slug(repository_ref)
    if want:
        candidates = (
            await db.execute(base.where(Repository.url.isnot(None)).limit(500))
        ).scalars().all()
        for c in candidates:
            if _remote_slug(c.url or "") == want:
                return c

    raise HTTPException(
        status_code=404,
        detail=(
            f"No repository matching '{repository_ref}' is onboarded under this tenant. "
            "Add the repository in Vooda before importing findings."
        ),
    )


async def _ingest(
    *,
    db: AsyncSession,
    user: User,
    request: Request,
    response: Response,
    body: ImportScanRequest,
    repo: Repository,
    idempotency_key_header: Optional[str],
) -> ImportAccepted:
    """Shared handler for both the repo-scoped and flat ingest routes."""
    # ── Firewall step 1: forbidden-key tripwire over the raw body ──
    try:
        raw_body = await request.json()
    except Exception:
        raw_body = None
    if raw_body is not None:
        _assert_no_forbidden_keys(raw_body)

    if len(body.findings) > MAX_FINDINGS_PER_IMPORT:
        raise HTTPException(
            status_code=413,
            detail=f"Too many findings ({len(body.findings)}); max {MAX_FINDINGS_PER_IMPORT} per import.",
        )

    idem = (idempotency_key_header or body.idempotency_key or "").strip() or None
    if idem and len(idem) > 64:
        idem = idem[:64]

    # ── Idempotent replay: a prior import with this key already exists ──
    if idem:
        existing = (
            await db.execute(
                select(ScanJob).where(
                    ScanJob.tenant_id == user.tenant_id,
                    ScanJob.idempotency_key == idem,
                )
            )
        ).scalar_one_or_none()
        if existing:
            response.status_code = 200
            return ImportAccepted(
                scan_job_id=str(existing.id),
                status=existing.status.value if hasattr(existing.status, "value") else str(existing.status),
                scan_type=existing.scan_type.value if hasattr(existing.scan_type, "value") else str(existing.scan_type),
                repository_id=str(existing.repository_id),
                findings_received=len(body.findings),
                findings_scrubbed=0,
                idempotent_replay=True,
            )

    # ── scan_type: explicit wins; else infer CI when a ci_provider is set ──
    prov = body.provenance
    st_raw = (prov.scan_type or "").strip().lower()
    if st_raw == "ci":
        scan_type = ScanType.CI
    elif st_raw == "cli":
        scan_type = ScanType.CLI
    else:
        scan_type = ScanType.CI if (prov.ci_provider or "").strip() else ScanType.CLI

    api_key = getattr(request.state, "api_key", None)
    client_label = (body.client or (api_key.name if api_key else None) or "vooda-cli")[:100]

    # ── Validate + normalize each finding through the firewall ──
    total_scrubbed = 0
    validated_items: list[dict] = []
    for f in body.findings:
        # Firewall step 2: masked_value must actually be masked (carry a
        # strict mask marker) — catches a client that sent a raw value here.
        mv = f.masked_value or ""
        if _masked_value_is_unmasked(mv):
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Finding '{f.rule_id}' masked_value appears to be a raw secret (no mask "
                    "marker). Send a masked representation (e.g. 'AKIA************Q7QF')."
                ),
            )
        # Firewall step 3: scrub high-entropy tokens from the snippet (non-fatal).
        scrubbed_snippet, n = _scrub_snippet(f.code_snippet)
        total_scrubbed += n
        item = f.model_dump()
        item["code_snippet"] = scrubbed_snippet
        # provenance commit_sha falls back to the scan-level one for dedup parity.
        if not item.get("commit_sha"):
            item["commit_sha"] = prov.commit_sha
        validated_items.append(item)

    # ── Create the scan job (provenance is first-class; actor is untrusted) ──
    job = ScanJob(
        repository_id=repo.id,
        tenant_id=user.tenant_id,
        initiated_by=user.id,
        scan_type=scan_type,
        status=ScanStatus.PENDING,
        progress_pct=0,
        status_message=f"Importing {len(validated_items):,} findings from {client_label}…",
        commit_sha=(prov.commit_sha or None),
        branch=(prov.branch or None),
        actor=(prov.actor or None),  # UNTRUSTED — display only, never authz
        ci_provider=(prov.ci_provider or None),
        ci_pipeline_url=(prov.ci_pipeline_url or None),
        idempotency_key=idem,
        config={
            "import": {
                "client": client_label,
                "count": len(validated_items),
                "snippets_scrubbed": total_scrubbed,
                "stats": body.stats or {},
            }
        },
    )
    db.add(job)
    try:
        await db.flush()  # surfaces the partial-unique (tenant, idempotency_key) violation
    except IntegrityError:
        # Lost an idempotency race — another concurrent import created the
        # job first.  Roll back and return that existing job (HTTP 200).
        await db.rollback()
        existing = (
            await db.execute(
                select(ScanJob).where(
                    ScanJob.tenant_id == user.tenant_id,
                    ScanJob.idempotency_key == idem,
                )
            )
        ).scalar_one_or_none()
        if existing:
            response.status_code = 200
            return ImportAccepted(
                scan_job_id=str(existing.id),
                status=existing.status.value if hasattr(existing.status, "value") else str(existing.status),
                scan_type=existing.scan_type.value if hasattr(existing.scan_type, "value") else str(existing.scan_type),
                repository_id=str(existing.repository_id),
                findings_received=len(body.findings),
                findings_scrubbed=total_scrubbed,
                idempotent_replay=True,
            )
        raise

    # ── Persist the masked findings as ImportedFinding rows for the task ──
    for item in validated_items:
        db.add(
            ImportedFinding(
                scan_job_id=job.id,
                tenant_id=user.tenant_id,
                scanner_name=client_label,
                scanner_rule_id=(item.get("rule_id") or "")[:255] or None,
                external_id=None,
                raw_data=item,  # masked-only payload
                parser_used="vooda-native-import",
                title=(item.get("title") or None),
                severity=(item.get("severity") or None),
                file_path=(item.get("file_path") or None),
                line_start=item.get("line_start"),
                cwe=(item.get("cwe") or None),
                category=(item.get("vulnerability_category") or None),
            )
        )

    from apps.api.app.core.audit import log_audit

    await log_audit(
        db,
        user,
        "findings_imported",
        "scan_job",
        job.id,
        f"{len(validated_items)} findings imported into {repo.name} "
        f"({scan_type.value}, client={client_label}, scrubbed={total_scrubbed})",
        request=request,
    )

    # ── Hand off to the dedicated scans queue (decoupled from the API) ──
    from apps.worker.celery_app import celery_app

    task = celery_app.send_task(
        "apps.worker.tasks.ingest_imported_findings",
        args=[str(job.id)],
        queue="scans",
    )
    job.celery_task_id = task.id
    await db.flush()

    response.status_code = 202
    return ImportAccepted(
        scan_job_id=str(job.id),
        status=ScanStatus.PENDING.value,
        scan_type=scan_type.value,
        repository_id=str(repo.id),
        findings_received=len(validated_items),
        findings_scrubbed=total_scrubbed,
        idempotent_replay=False,
    )


@router.post(
    "/repositories/{repo_id}/import/findings",
    response_model=ImportAccepted,
    status_code=202,
    summary="Import client-side (CLI/CI) Vooda findings for a repository",
)
async def import_findings_for_repo(
    repo_id: UUID,
    body: ImportScanRequest,
    request: Request,
    response: Response,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_scope("findings:import")),
):
    """Repo-scoped ingest.  The path ``repo_id`` overrides any body value."""
    repo = await _resolve_repo(db, user, repo_id, None)
    return await _ingest(
        db=db,
        user=user,
        request=request,
        response=response,
        body=body,
        repo=repo,
        idempotency_key_header=idempotency_key,
    )


@router.get(
    "/imports/scan/{scan_job_id}",
    summary="Status of an import job (readable by the same write-only key)",
)
async def import_status(
    scan_job_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_scope("findings:import")),
):
    """Let a CI runner's write-only ``findings:import`` key poll the outcome of
    its OWN import (so ``vooda monitor --wait`` can report "synced: N created").

    Deliberately scoped TIGHT: the key can read ONLY import jobs (scan_type
    CLI|CI) in ITS OWN tenant — never a server scan, never findings, never
    another repo.  This preserves the "write-only — cannot read findings or
    other repos" guarantee while still closing the CI feedback loop.
    """
    job = (
        await db.execute(
            select(ScanJob).where(
                ScanJob.id == scan_job_id,
                ScanJob.tenant_id == user.tenant_id,
                ScanJob.scan_type.in_([ScanType.CLI, ScanType.CI]),
            )
        )
    ).scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Import job not found for this tenant.")
    return {
        "scan_job_id": str(job.id),
        "status": job.status.value if hasattr(job.status, "value") else str(job.status),
        "scan_type": job.scan_type.value if hasattr(job.scan_type, "value") else str(job.scan_type),
        "progress_pct": job.progress_pct,
        "status_message": job.status_message,
        "stats": job.stats or {},
    }


@router.post(
    "/imports/scan",
    response_model=ImportAccepted,
    status_code=202,
    summary="Import client-side (CLI/CI) Vooda findings (repo identified in body)",
)
async def import_scan(
    body: ImportScanRequest,
    request: Request,
    response: Response,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_scope("findings:import")),
):
    """Flat ingest — the CI runner identifies its repo by ``repository_id`` or
    ``repository_ref`` (git remote URL), which it knows without needing
    Vooda's internal UUID."""
    repo = await _resolve_repo(db, user, body.repository_id, body.repository_ref)
    return await _ingest(
        db=db,
        user=user,
        request=request,
        response=response,
        body=body,
        repo=repo,
        idempotency_key_header=idempotency_key,
    )
