# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from apps.api.app.core.database import get_db
from apps.api.app.core.config import settings
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.models.repository import Repository
from apps.api.app.models.integration import IntegrationConfig
from apps.api.app.models.scan import ScanJob, ScanType, ScanStatus, ScanPhaseEvent
from apps.api.app.schemas.repository import (
    RepositoryCreate,
    RepositoryResponse,
    ScanRequest,
    ScanJobResponse,
    ScanPhaseEventResponse,
    ScanConfigUpdate,
)

router = APIRouter()


async def _existing_tables(db, candidates) -> set[str]:
    """Of `candidates`, the tables that actually exist in this database.

    The repo- and scan-delete cascades list child tables by name and
    DELETE from each. Several of those names — policy_evaluation_results,
    supply_chain_*, sbom_records, policy_definitions, policies — belong
    to product lines removed in 2026-05, so their tables are never
    created. The first DELETE against a missing table raised
    UndefinedTableError and aborted the whole transaction, so deleting
    ANY repository or scan returned 500.

    Filtering to the tables that exist fixes it without hardcoding which
    features are present, so it stays correct whether one of these
    tables comes back or another is dropped later.
    """
    from sqlalchemy import text as _text

    rows = await db.execute(
        _text(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = ANY(:names)"
        ),
        {"names": list(candidates)},
    )
    return {r[0] for r in rows}


# ── Access control helper ─────────────────────────────────────
async def _get_repo_with_access_check(repo_id: UUID, db: AsyncSession, user: User) -> Repository:
    """Load a repository and verify the user has access. Raises 403 or 404."""
    from apps.api.app.core.access_control import can_access_repository
    if not await can_access_repository(db, user, repo_id):
        raise HTTPException(status_code=403, detail="Access denied — you don't have permission to access this project")
    result = await db.execute(
        select(Repository).where(Repository.id == repo_id, Repository.tenant_id == user.tenant_id)
    )
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    return repo


# ── Scanner provider enrichment ───────────────────────────────
async def _enrich_repo(db: AsyncSession, repos):
    """Add business_unit_name + is_archived to repo dicts."""
    from apps.api.app.models.access import BusinessUnit

    is_single = not isinstance(repos, list)
    repo_list = [repos] if is_single else repos

    # Resolve business unit names
    bu_ids = {r.business_unit_id for r in repo_list if r.business_unit_id}
    bu_name_map = {}
    if bu_ids:
        bu_result = await db.execute(
            select(BusinessUnit.id, BusinessUnit.name).where(BusinessUnit.id.in_(bu_ids))
        )
        bu_name_map = {row.id: row.name for row in bu_result}

    enriched = []
    for repo in repo_list:
        data = RepositoryResponse.model_validate(repo).model_dump()
        # Resolve BU name
        if repo.business_unit_id and repo.business_unit_id in bu_name_map:
            data["business_unit_name"] = bu_name_map[repo.business_unit_id]
        else:
            data["business_unit_name"] = None
        # Surface archived state so the FE can render the badge +
        # Unarchive action without leaking the whole metadata blob.
        meta = repo.metadata_ or {}
        data["is_archived"] = meta.get("archived") is True
        enriched.append(data)

    return enriched[0] if is_single else enriched


# ── Probe schemas ──────────────────────────────────────────────
class RepoProbeRequest(BaseModel):
    url: str
    token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None


class BranchInfo(BaseModel):
    name: str
    is_default: bool = False


class RepoProbeResponse(BaseModel):
    status: str  # "public", "private", "auth_required", "not_found", "error"
    message: str
    provider: Optional[str] = None
    default_branch: Optional[str] = None
    branches: list[BranchInfo] = []
    languages: dict[str, float] = {}  # lang -> percentage
    frameworks: list[str] = []
    topics: list[str] = []
    description: Optional[str] = None
    stars: Optional[int] = None
    is_fork: Optional[bool] = None
    source_type: str = "git_url"


# ── Probe endpoint ─────────────────────────────────────────────
@router.post("/probe", response_model=RepoProbeResponse)
async def probe_repository(
    body: RepoProbeRequest,
    user: User = Depends(get_current_user),
):
    """
    Probe a repository URL to check accessibility, detect branches,
    languages, and frameworks. Works with GitHub, GitLab, Bitbucket APIs
    and falls back to git ls-remote for generic repos.
    """
    import httpx
    import re

    url = body.url.strip().rstrip("/").removesuffix(".git")
    provider = _detect_provider(url)

    try:
        if provider == "github":
            return await _probe_github(url, body.token)
        elif provider == "gitlab":
            return await _probe_gitlab(url, body.token)
        elif provider == "bitbucket":
            return await _probe_bitbucket(url, body.username, body.password)
        else:
            return await _probe_git_generic(body.url, body.username, body.password, body.token)
    except Exception as e:
        return RepoProbeResponse(
            status="error",
            message=f"Failed to probe repository: {str(e)}",
            provider=provider,
        )


def _detect_provider(url: str) -> str:
    url_lower = url.lower()
    if "github.com" in url_lower:
        return "github"
    elif "gitlab" in url_lower:
        return "gitlab"
    elif "bitbucket" in url_lower:
        return "bitbucket"
    elif "dev.azure.com" in url_lower or "visualstudio.com" in url_lower:
        return "azure"
    return "generic"


def _extract_github_owner_repo(url: str) -> tuple[str, str]:
    """Extract owner/repo from GitHub URL."""
    import re
    url = url.rstrip("/").removesuffix(".git")
    # https://github.com/owner/repo or git@github.com:owner/repo
    m = re.search(r"github\.com[:/]([^/]+)/([^/]+)", url)
    if m:
        return m.group(1), m.group(2)
    raise ValueError(f"Cannot parse GitHub URL: {url}")


def _extract_gitlab_project_path(url: str) -> str:
    """Extract project path from GitLab URL."""
    import re
    url = url.rstrip("/").removesuffix(".git")
    m = re.search(r"gitlab[^/]*[:/](.+)", url)
    if m:
        return m.group(1)
    raise ValueError(f"Cannot parse GitLab URL: {url}")


def _extract_bitbucket_owner_repo(url: str) -> tuple[str, str]:
    import re
    url = url.rstrip("/").removesuffix(".git")
    m = re.search(r"bitbucket\.org[:/]([^/]+)/([^/]+)", url)
    if m:
        return m.group(1), m.group(2)
    raise ValueError(f"Cannot parse Bitbucket URL: {url}")


FRAMEWORK_HINTS = {
    "Python": {
        "django": "Django", "flask": "Flask", "fastapi": "FastAPI",
        "tornado": "Tornado", "pyramid": "Pyramid",
    },
    "JavaScript": {
        "react": "React", "next": "Next.js", "express": "Express",
        "vue": "Vue.js", "angular": "Angular", "nestjs": "NestJS", "svelte": "Svelte",
    },
    "TypeScript": {
        "react": "React", "next": "Next.js", "angular": "Angular",
        "nestjs": "NestJS", "svelte": "Svelte",
    },
    "Java": {
        "spring": "Spring Boot", "quarkus": "Quarkus", "micronaut": "Micronaut",
    },
    "Go": {
        "gin": "Gin", "echo": "Echo", "fiber": "Fiber",
    },
    "Ruby": {
        "rails": "Rails", "sinatra": "Sinatra",
    },
    "PHP": {
        "laravel": "Laravel", "symfony": "Symfony",
    },
    "C#": {
        "aspnet": "ASP.NET", "blazor": "Blazor",
    },
}


async def _probe_github(url: str, token: str | None) -> RepoProbeResponse:
    import httpx

    owner, repo = _extract_github_owner_repo(url)
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=15) as client:
        # 1. Check repo info
        r = await client.get(f"https://api.github.com/repos/{owner}/{repo}", headers=headers)

        if r.status_code == 404:
            # Could be private — check if auth would help
            if not token:
                return RepoProbeResponse(
                    status="auth_required",
                    message="Repository not found or is private. Please provide a Personal Access Token.",
                    provider="github",
                )
            return RepoProbeResponse(
                status="not_found",
                message="Repository not found. Check the URL and your access permissions.",
                provider="github",
            )
        elif r.status_code == 401 or r.status_code == 403:
            return RepoProbeResponse(
                status="auth_required",
                message="Authentication required. Please provide a valid Personal Access Token.",
                provider="github",
            )
        elif r.status_code != 200:
            return RepoProbeResponse(
                status="error",
                message=f"GitHub API returned status {r.status_code}",
                provider="github",
            )

        repo_data = r.json()
        is_private = repo_data.get("private", False)
        default_branch = repo_data.get("default_branch", "main")

        # 2. Get branches
        br = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/branches?per_page=100",
            headers=headers,
        )
        branches = []
        if br.status_code == 200:
            for b in br.json():
                branches.append(BranchInfo(
                    name=b["name"],
                    is_default=(b["name"] == default_branch),
                ))

        # 3. Get languages
        lr = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/languages",
            headers=headers,
        )
        languages = {}
        if lr.status_code == 200:
            raw_langs = lr.json()
            total = sum(raw_langs.values()) or 1
            languages = {lang: round(bytes_count / total * 100, 1) for lang, bytes_count in raw_langs.items()}

        # 4. Detect frameworks from topics and languages
        topics = repo_data.get("topics", [])
        frameworks = _detect_frameworks(languages, topics)

        return RepoProbeResponse(
            status="public" if not is_private else "private",
            message="Connection successful" if not is_private else "Private repository — authenticated successfully",
            provider="github",
            default_branch=default_branch,
            branches=branches,
            languages=languages,
            frameworks=frameworks,
            topics=topics,
            description=repo_data.get("description"),
            stars=repo_data.get("stargazers_count"),
            is_fork=repo_data.get("fork", False),
        )


async def _probe_gitlab(url: str, token: str | None) -> RepoProbeResponse:
    import httpx
    import urllib.parse

    project_path = _extract_gitlab_project_path(url)
    encoded_path = urllib.parse.quote(project_path, safe="")

    # Determine GitLab host
    import re
    host_match = re.match(r"https?://([^/]+)", url)
    host = host_match.group(1) if host_match else "gitlab.com"
    base = f"https://{host}/api/v4"

    headers = {}
    if token:
        headers["PRIVATE-TOKEN"] = token

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{base}/projects/{encoded_path}", headers=headers)

        if r.status_code == 404:
            if not token:
                return RepoProbeResponse(
                    status="auth_required",
                    message="Repository not found or is private. Please provide a Personal Access Token.",
                    provider="gitlab",
                )
            return RepoProbeResponse(status="not_found", message="Repository not found.", provider="gitlab")
        elif r.status_code in (401, 403):
            return RepoProbeResponse(
                status="auth_required",
                message="Authentication required. Please provide a valid GitLab Personal Access Token.",
                provider="gitlab",
            )
        elif r.status_code != 200:
            return RepoProbeResponse(status="error", message=f"GitLab API returned {r.status_code}", provider="gitlab")

        data = r.json()
        project_id = data.get("id")
        default_branch = data.get("default_branch", "main")
        is_private = data.get("visibility") == "private"

        # Branches
        br = await client.get(f"{base}/projects/{project_id}/repository/branches?per_page=100", headers=headers)
        branches = []
        if br.status_code == 200:
            for b in br.json():
                branches.append(BranchInfo(name=b["name"], is_default=(b["name"] == default_branch)))

        # Languages
        lr = await client.get(f"{base}/projects/{project_id}/languages", headers=headers)
        languages = lr.json() if lr.status_code == 200 else {}

        topics = data.get("topics", []) or data.get("tag_list", [])
        frameworks = _detect_frameworks(languages, topics)

        return RepoProbeResponse(
            status="public" if not is_private else "private",
            message="Connection successful" if not is_private else "Private repository — authenticated successfully",
            provider="gitlab",
            default_branch=default_branch,
            branches=branches,
            languages=languages,
            frameworks=frameworks,
            topics=topics,
            description=data.get("description"),
            stars=data.get("star_count"),
            is_fork=data.get("forked_from_project") is not None,
        )


async def _probe_bitbucket(url: str, username: str | None, password: str | None) -> RepoProbeResponse:
    import httpx

    owner, repo = _extract_bitbucket_owner_repo(url)
    auth = (username, password) if username and password else None

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"https://api.bitbucket.org/2.0/repositories/{owner}/{repo}", auth=auth)

        if r.status_code == 404:
            if not auth:
                return RepoProbeResponse(
                    status="auth_required",
                    message="Repository not found or is private. Please provide credentials.",
                    provider="bitbucket",
                )
            return RepoProbeResponse(status="not_found", message="Repository not found.", provider="bitbucket")
        elif r.status_code in (401, 403):
            return RepoProbeResponse(
                status="auth_required",
                message="Authentication required. Provide username and app password.",
                provider="bitbucket",
            )
        elif r.status_code != 200:
            return RepoProbeResponse(status="error", message=f"Bitbucket API returned {r.status_code}", provider="bitbucket")

        data = r.json()
        main_branch = data.get("mainbranch", {}).get("name", "main")
        is_private = data.get("is_private", False)

        # Branches
        br = await client.get(f"https://api.bitbucket.org/2.0/repositories/{owner}/{repo}/refs/branches?pagelen=100", auth=auth)
        branches = []
        if br.status_code == 200:
            for b in br.json().get("values", []):
                branches.append(BranchInfo(name=b["name"], is_default=(b["name"] == main_branch)))

        languages = {}
        lang = data.get("language")
        if lang:
            languages = {lang: 100.0}

        return RepoProbeResponse(
            status="public" if not is_private else "private",
            message="Connection successful" if not is_private else "Private repository — authenticated successfully",
            provider="bitbucket",
            default_branch=main_branch,
            branches=branches,
            languages=languages,
            description=data.get("description"),
        )


async def _probe_git_generic(url: str, username: str | None, password: str | None, token: str | None) -> RepoProbeResponse:
    """Fallback: use git ls-remote to check accessibility."""
    import asyncio

    env = {}
    auth_url = url
    if token:
        # Insert token into URL for HTTPS
        auth_url = url.replace("https://", f"https://oauth2:{token}@")
    elif username and password:
        auth_url = url.replace("https://", f"https://{username}:{password}@")

    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "ls-remote", "--heads", "--quiet", auth_url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**__import__("os").environ, **env},
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)

        if proc.returncode == 0:
            branches = []
            default = None
            for line in stdout.decode().strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split("\t")
                if len(parts) >= 2:
                    ref = parts[1].replace("refs/heads/", "")
                    is_def = ref in ("main", "master")
                    if is_def and not default:
                        default = ref
                    branches.append(BranchInfo(name=ref, is_default=is_def))

            return RepoProbeResponse(
                status="public",
                message="Connection successful",
                provider="generic",
                default_branch=default or (branches[0].name if branches else "main"),
                branches=branches,
            )
        else:
            err = stderr.decode().strip()
            if "Authentication" in err or "could not read Username" in err or "401" in err or "403" in err:
                return RepoProbeResponse(
                    status="auth_required",
                    message="Authentication required. Please provide credentials or a token.",
                    provider="generic",
                )
            return RepoProbeResponse(
                status="not_found",
                message=f"Cannot access repository: {err[:200]}",
                provider="generic",
            )
    except asyncio.TimeoutError:
        return RepoProbeResponse(status="error", message="Connection timed out", provider="generic")
    except FileNotFoundError:
        return RepoProbeResponse(status="error", message="Git not available on server", provider="generic")


def _detect_frameworks(languages: dict, topics: list[str]) -> list[str]:
    """Heuristic framework detection from language + topics."""
    frameworks = []
    all_topics = " ".join(t.lower() for t in topics)

    for lang, hints in FRAMEWORK_HINTS.items():
        if lang in languages:
            for keyword, name in hints.items():
                if keyword in all_topics and name not in frameworks:
                    frameworks.append(name)

    # Direct topic matches
    topic_frameworks = {
        "django": "Django", "flask": "Flask", "fastapi": "FastAPI",
        "react": "React", "nextjs": "Next.js", "vue": "Vue.js",
        "angular": "Angular", "express": "Express", "nestjs": "NestJS",
        "spring-boot": "Spring Boot", "rails": "Rails", "laravel": "Laravel",
        "gin": "Gin", "svelte": "Svelte",
    }
    for topic in topics:
        t = topic.lower()
        if t in topic_frameworks and topic_frameworks[t] not in frameworks:
            frameworks.append(topic_frameworks[t])

    return frameworks


# ── Existing CRUD endpoints ────────────────────────────────────

@router.post("", response_model=RepositoryResponse, status_code=201)
async def create_repository(
    body: RepositoryCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Check for duplicate project name within the tenant
    existing = await db.execute(
        select(Repository).where(
            Repository.tenant_id == user.tenant_id,
            Repository.name == body.name,
            Repository.is_active == True,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"A project named '{body.name}' already exists")

    # Build metadata with auth credentials (if provided for private repos)
    metadata = {}
    if body.provider:
        metadata["provider"] = body.provider
    if body.auth:
        # Store auth credentials in metadata
        # NOTE: In production, encrypt these values at rest
        metadata["auth"] = body.auth
    # Canonicalise the URL before storing, so the database never holds a
    # form the cloner cannot use: a schemeless "github.com/o/r" becomes
    # https://, and an SSH remote (which has no auth path here) becomes
    # https too. The worker normalises again at clone time as a
    # backstop, but storing it canonical means the UI shows the real URL
    # and a bad paste is fixed at the point of entry.
    from packages.common.git_url import normalize_git_url
    repo = Repository(
        name=body.name,
        url=normalize_git_url(body.url),
        source_type=body.source_type,
        default_branch=body.default_branch,
        tenant_id=user.tenant_id,
        metadata_=metadata if metadata else {},
        ticketing_integration_id=body.ticketing_integration_id,
        languages=[],
    )
    db.add(repo)
    await db.flush()
    await db.refresh(repo)

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "repo_created", "repository", repo.id, f"Created project: {body.name}")

    return await _enrich_repo(db, repo)


@router.get("")
async def list_repositories(
    search: Optional[str] = Query(None),
    language: Optional[str] = Query(None),
    framework: Optional[str] = Query(None),
    sort_by: str = Query("created_at"),
    sort_dir: str = Query("desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    # Default hides archived repos — they're paused-not-deleted and
    # shouldn't clutter the active list.  FE toggles ?include_archived=true
    # to surface them (greyed, with an Unarchive action).
    include_archived: bool = Query(False),
    # Show ONLY archived repos — used by the "Archived" tab/filter view.
    archived_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    from apps.api.app.core.access_control import get_accessible_repo_ids
    from sqlalchemy import func, or_

    base_query = select(Repository).where(
        Repository.tenant_id == user.tenant_id,
        Repository.is_active == True,
    )

    # Archive filter.  metadata_->>'archived' is a TEXT cast of the
    # JSON value; missing key → NULL → treated as not-archived.
    from sqlalchemy import literal_column
    archived_text = literal_column("metadata->>'archived'")
    if archived_only:
        base_query = base_query.where(archived_text == "true")
    elif not include_archived:
        base_query = base_query.where(
            or_(archived_text.is_(None), archived_text != "true")
        )

    # Access control
    accessible = await get_accessible_repo_ids(db, user)
    if accessible is not None:
        base_query = base_query.where(Repository.id.in_(accessible))

    # Search (name or URL)
    if search:
        base_query = base_query.where(
            or_(
                Repository.name.ilike(f"%{search}%"),
                Repository.url.ilike(f"%{search}%"),
            )
        )

    # Language filter (JSONB array contains)
    if language:
        base_query = base_query.where(Repository.languages.contains([language]))

    # Framework filter (JSONB array contains)
    if framework:
        base_query = base_query.where(Repository.frameworks.contains([framework]))

    # Count total matching rows
    count_q = select(func.count()).select_from(base_query.subquery())
    total: int = (await db.execute(count_q)).scalar() or 0

    # Sort
    sort_col = Repository.name if sort_by == "name" else Repository.created_at
    if sort_dir == "asc":
        base_query = base_query.order_by(sort_col.asc())
    else:
        base_query = base_query.order_by(sort_col.desc())

    # Paginate
    base_query = base_query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(base_query)
    repos = result.scalars().all()
    items = await _enrich_repo(db, repos)

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }


@router.get("/facets")
async def get_repository_facets(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return all distinct languages and frameworks for filter dropdowns."""
    from apps.api.app.core.access_control import get_accessible_repo_ids

    base_query = select(Repository.languages, Repository.frameworks).where(
        Repository.tenant_id == user.tenant_id,
        Repository.is_active == True,
    )
    accessible = await get_accessible_repo_ids(db, user)
    if accessible is not None:
        base_query = base_query.where(Repository.id.in_(accessible))

    result = await db.execute(base_query)
    rows = result.all()

    languages: set[str] = set()
    frameworks: set[str] = set()
    for row in rows:
        for lang in (row.languages or []):
            if isinstance(lang, str):
                languages.add(lang)
        for fw in (row.frameworks or []):
            if isinstance(fw, str):
                frameworks.add(fw)

    return {"languages": sorted(languages), "frameworks": sorted(frameworks)}


@router.get("/{repo_id}", response_model=RepositoryResponse)
async def get_repository(
    repo_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    repo = await _get_repo_with_access_check(repo_id, db, user)
    return await _enrich_repo(db, repo)


@router.get("/{repo_id}/branches")
async def get_repository_branches(
    repo_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Fetch branches for a repository. Uses the repo URL to query the git provider API.
    Returns cached branches from snapshot if available, otherwise probes live.
    """
    import httpx
    import re

    repo = await _get_repo_with_access_check(repo_id, db, user)

    if not repo.url:
        return {"branches": [], "default_branch": repo.default_branch}

    # Check if we have cached branches in metadata
    cached = (repo.metadata_ or {}).get("branches")
    if cached:
        return {"branches": cached, "default_branch": repo.default_branch}

    # Probe live
    url = repo.url.strip().rstrip("/").removesuffix(".git")
    provider = _detect_provider(url)
    branches = []
    default_branch = repo.default_branch or "main"

    try:
        if provider == "github":
            owner, repo_name = _extract_github_owner_repo(url)
            async with httpx.AsyncClient(timeout=15) as client:
                # Get repo info for default branch
                r = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo_name}",
                    headers={"Accept": "application/vnd.github.v3+json"},
                )
                if r.status_code == 200:
                    default_branch = r.json().get("default_branch", "main")

                # Get branches
                br = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo_name}/branches?per_page=100",
                    headers={"Accept": "application/vnd.github.v3+json"},
                )
                if br.status_code == 200:
                    branches = [
                        {"name": b["name"], "is_default": b["name"] == default_branch}
                        for b in br.json()
                    ]

        elif provider == "gitlab":
            import urllib.parse
            project_path = _extract_gitlab_project_path(url)
            encoded = urllib.parse.quote(project_path, safe="")
            host_match = re.match(r"https?://([^/]+)", url)
            host = host_match.group(1) if host_match else "gitlab.com"
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(f"https://{host}/api/v4/projects/{encoded}")
                if r.status_code == 200:
                    default_branch = r.json().get("default_branch", "main")
                    pid = r.json().get("id")
                    br = await client.get(f"https://{host}/api/v4/projects/{pid}/repository/branches?per_page=100")
                    if br.status_code == 200:
                        branches = [
                            {"name": b["name"], "is_default": b["name"] == default_branch}
                            for b in br.json()
                        ]

        else:
            # Generic: use git ls-remote
            import asyncio
            proc = await asyncio.create_subprocess_exec(
                "git", "ls-remote", "--heads", "--quiet", repo.url,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            if proc.returncode == 0:
                for line in stdout.decode().strip().split("\n"):
                    if not line.strip():
                        continue
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        ref = parts[1].replace("refs/heads/", "")
                        branches.append({"name": ref, "is_default": ref in ("main", "master")})

    except Exception:
        pass  # Return whatever we have

    # Cache in metadata
    if branches:
        meta = repo.metadata_ or {}
        meta["branches"] = branches
        repo.metadata_ = meta
        await db.flush()

    # Ensure default is in the list
    if branches and not any(b["name"] == default_branch for b in branches):
        branches.insert(0, {"name": default_branch, "is_default": True})

    return {"branches": branches, "default_branch": default_branch}


class RepositoryUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    default_branch: Optional[str] = None
    scan_schedule: Optional[str] = None  # on_demand, daily, weekly, on_pr
    scan_paths: Optional[list[str]] = None
    exclude_patterns: Optional[list[str]] = None
    team_owner: Optional[str] = None
    # Per-repo ticketing destination override (FK to integration_configs).
    # When set, every finding from this repo routes to this exact
    # integration, ignoring the integration's scope_level. NULL clears
    # the override (falls back to scope-based routing). Bug fix /
    # feature 2026-04-27 for the user's "Repo A → JIRA A" UX.
    ticketing_integration_id: Optional[UUID] = None


@router.put("/{repo_id}", response_model=RepositoryResponse)
async def update_repository(
    repo_id: UUID,
    body: RepositoryUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    repo = await _get_repo_with_access_check(repo_id, db, user)

    update_data = body.model_dump(exclude_unset=True)
    # Store scan config in metadata
    config_fields = {"scan_schedule", "scan_paths", "exclude_patterns", "team_owner"}
    meta_updates = {k: v for k, v in update_data.items() if k in config_fields}
    direct_updates = {k: v for k, v in update_data.items() if k not in config_fields}

    for field, value in direct_updates.items():
        setattr(repo, field, value)
    if meta_updates:
        current_meta = repo.metadata_ or {}
        current_meta.update(meta_updates)
        repo.metadata_ = current_meta

    await db.flush()
    await db.refresh(repo)

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "repo_updated", "repository", repo_id, f"Updated project: {repo.name}")

    return await _enrich_repo(db, repo)


@router.patch("/{repo_id}/scan-config", response_model=RepositoryResponse)
async def update_scan_config(
    repo_id: UUID,
    body: ScanConfigUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Per-repo push/PR scan toggle + branch-pattern monitoring.

    Customers running monorepos or noisy default branches use this to
    keep webhooks subscribed (so the health badge stays green) while
    opting out of one event type, or to restrict scanning to specific
    branches via fnmatch globs.

    Matches the granularity GitGuardian, Snyk Code, and Aikido expose.
    Permission: any user with repo write access (security-lead+ in
    the default role tree)."""
    repo = await _get_repo_with_access_check(repo_id, db, user)

    update_data = body.model_dump(exclude_unset=True)
    if not update_data:
        # No fields supplied — short-circuit rather than write an
        # audit row for a no-op PATCH.
        return await _enrich_repo(db, repo)

    # ── Normalise + validate branch_patterns ──────────────────────────
    # Empty list (``[]``) is semantically the same as ``None`` for the
    # branch filter (both mean "monitor all branches"), but the JSONB
    # column distinguishes them.  Coerce to ``None`` so the FE only has
    # one "monitor all" state to read, and so a customer toggling between
    # custom-patterns and all-branches doesn't accumulate empty arrays
    # in the DB.  Patterns themselves are trimmed + capped to keep a
    # misconfigured form from filling the column with garbage.
    if "branch_patterns" in update_data:
        patterns = update_data["branch_patterns"]
        if patterns is None:
            update_data["branch_patterns"] = None
        else:
            cleaned = [
                p.strip()[:200]  # cap each pattern to 200 chars
                for p in patterns
                if isinstance(p, str) and p.strip()
            ][:50]  # cap list length to 50 patterns
            update_data["branch_patterns"] = cleaned if cleaned else None

    for field, value in update_data.items():
        setattr(repo, field, value)
    await db.flush()
    await db.refresh(repo)

    from apps.api.app.core.audit import log_audit
    # Build a human-readable detail string for the audit log.  Branch
    # patterns get a special render so the audit row reads as
    # "branch_patterns=['main', 'release/*']" rather than its raw JSON.
    def _fmt(k: str, v) -> str:
        if k == "branch_patterns":
            if v is None:
                return "branch_patterns=all"
            return f"branch_patterns={v}"
        return f"{k}={v}"
    changes = ", ".join(_fmt(k, v) for k, v in update_data.items())
    await log_audit(
        db, user, "repo_scan_config_updated", "repository", repo_id,
        f"Scan config updated on {repo.name}: {changes}",
    )

    return await _enrich_repo(db, repo)


@router.get("/{repo_id}/severity-trend")
async def get_severity_trend(
    repo_id: UUID,
    days: int = 30,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Daily severity-weighted finding counts for the past N days.
    Feeds the mini sparkline on the /repositories list view.

    Returns a fixed-length series — exactly `days` entries, oldest
    first, zero-padded for days with no findings.  Keeps the sparkline
    visually consistent across repos (50d-old repo with 3 findings
    last week still gets a 30-bar chart, not a 3-bar stub)."""
    from datetime import datetime, timezone, timedelta
    from sqlalchemy import cast, Date
    from apps.api.app.models.finding import NormalizedFinding

    repo = await _get_repo_with_access_check(repo_id, db, user)
    days = max(1, min(days, 90))

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    q = await db.execute(
        select(
            cast(NormalizedFinding.created_at, Date).label("day"),
            NormalizedFinding.severity,
            func.count(NormalizedFinding.id),
        )
        .where(
            NormalizedFinding.repository_id == repo.id,
            NormalizedFinding.tenant_id == user.tenant_id,
            NormalizedFinding.created_at >= cutoff,
            NormalizedFinding.is_suppressed == False,
        )
        .group_by(cast(NormalizedFinding.created_at, Date), NormalizedFinding.severity)
        .order_by(cast(NormalizedFinding.created_at, Date))
    )

    # Bucket per day → {critical, high, medium, low, info}.
    per_day: dict[str, dict] = {}
    for day, sev, count in q.all():
        key = str(day)
        if key not in per_day:
            per_day[key] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        sev_name = (sev.value if hasattr(sev, "value") else str(sev)).split(".")[-1].lower()
        if sev_name in per_day[key]:
            per_day[key][sev_name] = count

    # Pad to a fixed-length series — fills missing days with zeros so
    # the sparkline's x-axis is always exactly `days` long.
    today = datetime.now(timezone.utc).date()
    series = []
    for i in range(days - 1, -1, -1):
        day = (today - timedelta(days=i)).isoformat()
        bucket = per_day.get(day, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
        # Sparkline plots the severity-weighted total: a critical-heavy
        # day reads as a taller bar than a low-heavy day with the same
        # raw count.  Weights match the dashboard's Findings-by-Source
        # severity blend (4x crit, 3x high, 2x medium, 1x low, 0x info).
        weighted = (
            bucket["critical"] * 4
            + bucket["high"] * 3
            + bucket["medium"] * 2
            + bucket["low"] * 1
        )
        series.append({
            "date": day,
            "weighted": weighted,
            "total": sum(bucket.values()),
            "severity": bucket,
        })

    return {"repository_id": str(repo_id), "days": days, "series": series}


@router.get("/{repo_id}/delete-preview")
async def get_delete_preview(
    repo_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Impact preview for a permanent delete.

    Returns the counts the UI needs to render the destructive-action
    confirmation modal: findings, incidents that will close vs.
    survive (cross-scope), active credentials, scan history.  This is
    the single source of truth — the same query shape runs before the
    delete (preview) and after (audit log entry counts), so the
    numbers shown to the user match what was actually destroyed.

    Mirrors what GitGuardian / Wiz / Orca surface on their hard-delete
    confirmation screens.
    """
    from sqlalchemy import func as sa_func
    from apps.api.app.models.finding import NormalizedFinding, SecretIncident

    repo = await _get_repo_with_access_check(repo_id, db, user)

    # Total findings tied to this repo
    findings_q = await db.execute(
        select(sa_func.count(NormalizedFinding.id)).where(
            NormalizedFinding.repository_id == repo_id,
            NormalizedFinding.tenant_id == user.tenant_id,
        )
    )
    findings_count = findings_q.scalar() or 0

    # Active credentials — verified live at the provider.  These are
    # the most important number on the preview because deleting the
    # repo does NOT rotate the credentials; users need to act on them
    # at the provider BEFORE removing the repo.
    from sqlalchemy import literal_column
    active_q = await db.execute(
        select(sa_func.count(NormalizedFinding.id)).where(
            NormalizedFinding.repository_id == repo_id,
            NormalizedFinding.tenant_id == user.tenant_id,
            literal_column("source_metadata->>'validation_status'") == "active",
        )
    )
    active_credentials = active_q.scalar() or 0

    # Incidents touched by this delete.  Computed in two clean queries
    # rather than a single GROUP BY with conditional aggregates — easier
    # to reason about and trivially auditable against the actual delete
    # cascade below.
    #
    #   Touched   = incidents with at least one occurrence in this repo
    #   Surviving = touched incidents that ALSO have occurrences elsewhere
    #   Closing   = touched − surviving
    from sqlalchemy import and_
    touched_q = await db.execute(
        select(NormalizedFinding.incident_id).where(
            NormalizedFinding.repository_id == repo_id,
            NormalizedFinding.incident_id.isnot(None),
        ).distinct()
    )
    touched_ids = [row[0] for row in touched_q.all()]
    incidents_affected = len(touched_ids)
    will_survive = 0
    if touched_ids:
        survive_q = await db.execute(
            select(NormalizedFinding.incident_id).where(
                NormalizedFinding.incident_id.in_(touched_ids),
                # "Elsewhere" = a different repo, OR a scan source (which
                # has no repository_id).  Either way: the incident has
                # data Vooda can still see after this repo is gone.
                and_(
                    NormalizedFinding.tenant_id == user.tenant_id,
                    NormalizedFinding.id.isnot(None),
                ),
            ).where(
                # Exclude the to-be-deleted rows from the survival check
                ~(NormalizedFinding.repository_id == repo_id)
            ).distinct()
        )
        will_survive = len(set(row[0] for row in survive_q.all()))
    will_close = incidents_affected - will_survive

    # Scan history — count of scan jobs for this repo
    from apps.api.app.models.scan import ScanJob
    scan_q = await db.execute(
        select(sa_func.count(ScanJob.id)).where(ScanJob.repository_id == repo_id)
    )
    scan_history_count = scan_q.scalar() or 0

    return {
        "scope": "repository",
        "id": str(repo_id),
        "name": repo.name,
        "findings_count": findings_count,
        "incidents_affected": incidents_affected,
        "incidents_will_close": will_close,
        "incidents_will_survive": will_survive,
        "active_credentials": active_credentials,
        "scan_history_count": scan_history_count,
    }


class BulkDeletePreviewRequest(BaseModel):
    # Field is named ``ids`` (not ``repository_ids``) — keep the body
    # short for what's already a /repositories-prefixed route.
    ids: list[UUID] = Field(
        ...,
        examples=[["3fa85f64-5717-4562-b3fc-2c963f66afa6"]],
        description="Repository UUIDs to preview deletion impact for.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [{"ids": ["3fa85f64-5717-4562-b3fc-2c963f66afa6"]}],
        },
    }


@router.post("/bulk-delete-preview")
async def bulk_delete_preview(
    body: BulkDeletePreviewRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Aggregated impact preview for a bulk delete.

    Returns the same shape as the single-repo preview but rolled up
    across all selected repos.  The key correctness property: incidents
    that span multiple selected repos are counted once, not N times —
    we cannot just sum per-repo previews on the client.

    Survival semantics: an incident "will survive" iff it has at least
    one occurrence OUTSIDE the entire selected set (in another repo NOT
    being deleted, or in a scan_source).  This is the only definition
    that doesn't break when the user selects "delete every repo this
    secret touches".
    """
    from sqlalchemy import func as sa_func, literal_column, and_, not_
    from apps.api.app.models.finding import NormalizedFinding
    from apps.api.app.models.scan import ScanJob
    from apps.api.app.core.access_control import can_access_repository

    if not body.ids:
        return {
            "scope": "repository",
            "count": 0,
            "names": [],
            "findings_count": 0,
            "incidents_affected": 0,
            "incidents_will_close": 0,
            "incidents_will_survive": 0,
            "active_credentials": 0,
            "scan_history_count": 0,
        }

    # Access check on every id — refuse the whole bulk if any one is denied.
    for rid in body.ids:
        if not await can_access_repository(db, user, rid):
            raise HTTPException(status_code=403, detail="Access denied to one or more selected repositories")

    # Pull repo names for the modal list (and tenant scoping).
    repo_rows = await db.execute(
        select(Repository.id, Repository.name).where(
            Repository.id.in_(body.ids),
            Repository.tenant_id == user.tenant_id,
        )
    )
    repo_pairs = [(row[0], row[1]) for row in repo_rows.all()]
    if len(repo_pairs) != len(body.ids):
        raise HTTPException(status_code=404, detail="One or more repositories not found")
    names = [name for _, name in repo_pairs]

    # Sum-of-findings (correct — findings don't dedupe across repos).
    findings_q = await db.execute(
        select(sa_func.count(NormalizedFinding.id)).where(
            NormalizedFinding.repository_id.in_(body.ids),
            NormalizedFinding.tenant_id == user.tenant_id,
        )
    )
    findings_count = findings_q.scalar() or 0

    # Active credentials (sum — also correct, these are findings).
    active_q = await db.execute(
        select(sa_func.count(NormalizedFinding.id)).where(
            NormalizedFinding.repository_id.in_(body.ids),
            NormalizedFinding.tenant_id == user.tenant_id,
            literal_column("source_metadata->>'validation_status'") == "active",
        )
    )
    active_credentials = active_q.scalar() or 0

    # Touched incidents = distinct incident_ids appearing in ANY selected repo.
    touched_q = await db.execute(
        select(NormalizedFinding.incident_id).where(
            NormalizedFinding.repository_id.in_(body.ids),
            NormalizedFinding.incident_id.isnot(None),
            NormalizedFinding.tenant_id == user.tenant_id,
        ).distinct()
    )
    touched_ids = [row[0] for row in touched_q.all()]
    incidents_affected = len(touched_ids)

    # Surviving = touched incidents that have at least one occurrence
    # outside the selected set (in a different repo, or in a scan_source).
    will_survive = 0
    if touched_ids:
        survive_q = await db.execute(
            select(NormalizedFinding.incident_id).where(
                NormalizedFinding.incident_id.in_(touched_ids),
                NormalizedFinding.tenant_id == user.tenant_id,
                not_(NormalizedFinding.repository_id.in_(body.ids)),
            ).distinct()
        )
        will_survive = len(set(row[0] for row in survive_q.all()))
    will_close = incidents_affected - will_survive

    # Scan history (sum — scan jobs are per-repo, no dedup concern).
    scan_q = await db.execute(
        select(sa_func.count(ScanJob.id)).where(ScanJob.repository_id.in_(body.ids))
    )
    scan_history_count = scan_q.scalar() or 0

    return {
        "scope": "repository",
        "count": len(body.ids),
        "names": names,
        "findings_count": findings_count,
        "incidents_affected": incidents_affected,
        "incidents_will_close": will_close,
        "incidents_will_survive": will_survive,
        "active_credentials": active_credentials,
        "scan_history_count": scan_history_count,
    }


@router.delete("/{repo_id}", status_code=204)
async def delete_repository(
    repo_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    repo = await _get_repo_with_access_check(repo_id, db, user)
    repo_name = repo.name

    from sqlalchemy import text, func as sa_func, literal_column, update as sa_update
    from apps.api.app.models.finding import NormalizedFinding, SecretIncident

    rid = str(repo_id)

    # ── Camp-1 Pre-delete instrumentation ──────────────────────────
    # Capture the same numbers the FE preview surfaced + the set of
    # incident_ids touched by the deletion.  We need both BEFORE the
    # cascade runs so the audit log can record accurate counts and so
    # we can do the orphan-incident sweep AFTER the finding deletes.
    findings_count_q = await db.execute(
        select(sa_func.count(NormalizedFinding.id)).where(
            NormalizedFinding.repository_id == repo_id,
        )
    )
    findings_count = findings_count_q.scalar() or 0
    active_q = await db.execute(
        select(sa_func.count(NormalizedFinding.id)).where(
            NormalizedFinding.repository_id == repo_id,
            literal_column("source_metadata->>'validation_status'") == "active",
        )
    )
    active_credentials = active_q.scalar() or 0
    touched_q = await db.execute(
        select(NormalizedFinding.incident_id).where(
            NormalizedFinding.repository_id == repo_id,
            NormalizedFinding.incident_id.isnot(None),
        ).distinct()
    )
    touched_incident_ids = [row[0] for row in touched_q.all()]

    # Hard delete — remove all associated data before deleting the repository.
    # Tables are deleted in dependency order (children before parents).
    # Tables that have ondelete="CASCADE" on their FK are handled automatically
    # when their parent is deleted; the rest must be deleted explicitly.
    #
    # Discovered FK map (from pg_constraint on repositories + scan_jobs):
    #   repositories  ← finding_decision_cache, metric_snapshots,
    #                    policy_evaluation_results, supply_chain_components,
    #                    supply_chain_scans, sbom_records, policy_definitions,
    #                    policies, user_access_grants, integration_configs,
    #                    scan_jobs, repository_snapshots, normalized_findings
    #   scan_jobs     ← normalized_findings, imported_findings, metric_snapshots,
    #                    policy_evaluation_results, scan_artifacts (CASCADE)

    # --- repo-level children ---
    _repo_child_tables = (
        "finding_decision_cache",
        # File-level scanner-output cache. No FK on the table (the
        # cache is intentionally decoupled from repositories.id so
        # cleanup is in the repo-delete handler's hands), so we drop
        # rows explicitly here. Otherwise the next scan of a future
        # repo that happens to reuse the UUID could hit stale entries
        # — won't happen with UUIDv4 in practice but defensive cleanup
        # is essentially free.
        "file_scan_cache",
        # Per-(repo, branch) incremental checkpoints — same explicit
        # cleanup pattern: no FK on repository_id, so we drop here.
        "repo_branch_checkpoints",
        "credential_rotation_events",  # no FK cascade — clean explicitly so dashboard rotation SLA resets
        "metric_snapshots",
        # policy_* / supply_chain_* / sbom_records are from product lines
        # removed 2026-05; their tables do not exist and are filtered out
        # below rather than deleted from. Kept in the list so that if a
        # feature returns, its cleanup is already wired.
        "policy_evaluation_results",
        "supply_chain_components",
        "supply_chain_scans",
        "sbom_records",
        "policy_definitions",
        "policies",
        "user_access_grants",
        "integration_configs",
        "normalized_findings",   # finding_evidence/decisions/remediation cascade from this
    )
    _present = await _existing_tables(db, _repo_child_tables)
    for tbl in _repo_child_tables:
        if tbl not in _present:
            continue
        await db.execute(text(f"DELETE FROM {tbl} WHERE repository_id = :rid"), {"rid": rid})

    # --- scan_job-level children (for jobs belonging to this repo) ---
    scan_job_subq = "SELECT id FROM scan_jobs WHERE repository_id = :rid"
    _job_child_tables = (
        "normalized_findings",       # catch any linked by scan_job_id only
        "imported_findings",
        "metric_snapshots",
        "policy_evaluation_results",
        "scan_artifacts",
    )
    _present_job = await _existing_tables(db, _job_child_tables)
    for tbl in _job_child_tables:
        if tbl not in _present_job:
            continue
        await db.execute(
            text(f"DELETE FROM {tbl} WHERE scan_job_id IN ({scan_job_subq})"),
            {"rid": rid},
        )

    # --- scan_jobs and snapshots ---
    await db.execute(text("DELETE FROM scan_jobs WHERE repository_id = :rid"), {"rid": rid})
    await db.execute(text("DELETE FROM repository_snapshots WHERE repository_id = :rid"), {"rid": rid})

    # ── Camp-1 orphan-incident sweep ───────────────────────────────
    # The finding cascade above destroyed normalized_findings rows for
    # this repo.  Any SecretIncident those rows belonged to needs
    # recomputed aggregates (or a closure marker if it now has zero
    # surviving occurrences).  Mirrors what delete_scan_source does;
    # rationale lives in that router's docstring.
    incidents_closed = 0
    incidents_survived = 0
    if touched_incident_ids:
        remaining_q = await db.execute(
            select(
                NormalizedFinding.incident_id,
                sa_func.count(NormalizedFinding.id),
                sa_func.max(NormalizedFinding.last_seen_at),
            )
            .where(NormalizedFinding.incident_id.in_(touched_incident_ids))
            .group_by(NormalizedFinding.incident_id)
        )
        remaining_by_inc = {row[0]: (row[1], row[2]) for row in remaining_q.all()}

        orphan_ids = [iid for iid in touched_incident_ids if iid not in remaining_by_inc]
        if orphan_ids:
            await db.execute(
                sa_update(SecretIncident)
                .where(SecretIncident.id.in_(orphan_ids))
                .values(
                    classification="resolved_repo_removed",
                    review_status="reviewed",
                    occurrence_count=0,
                )
            )
        incidents_closed = len(orphan_ids)

        for inc_id, (cnt, last_seen) in remaining_by_inc.items():
            await db.execute(
                sa_update(SecretIncident)
                .where(SecretIncident.id == inc_id)
                .values(occurrence_count=cnt, last_seen_at=last_seen)
            )
        incidents_survived = len(remaining_by_inc)

    # --- finally the repository row itself ---
    await db.delete(repo)
    await db.flush()

    from apps.api.app.core.audit import log_audit
    # Enriched audit detail — captures the same cleanup numbers shown
    # in the impact preview so the trail aligns with what the user saw
    # before confirming.
    await log_audit(
        db, user, "repo_deleted", "repository", repo_id,
        (
            f"Deleted project '{repo_name}'. "
            f"Findings: {findings_count} · Incidents closed: {incidents_closed} "
            f"· Incidents survived: {incidents_survived} · Active creds: {active_credentials}"
        ),
        request=request,
        metadata={
            "repo_name": repo_name,
            "findings_deleted": findings_count,
            "incidents_closed": incidents_closed,
            "incidents_survived": incidents_survived,
            "active_credentials_at_delete": active_credentials,
        },
    )


@router.post("/{repo_id}/archive", status_code=200)
async def archive_repository(
    repo_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Archive a repository — soft-pause without destroying data.

    Effect of archiving:
      - Scheduler skips the repo (no new scheduled scans)
      - Default list view hides it (use ?include_archived=true to see)
      - All findings, incidents, scan history, triage preserved
      - User can Unarchive at any time to resume

    Idempotent.  Audit-logged.
    """
    repo = await _get_repo_with_access_check(repo_id, db, user)
    meta = dict(repo.metadata_ or {})
    was_archived = meta.get("archived") is True
    meta["archived"] = True
    from datetime import datetime, timezone
    meta["archived_at"] = datetime.now(timezone.utc).isoformat()
    meta["archived_by"] = str(user.id)
    repo.metadata_ = meta
    await db.flush()

    if not was_archived:
        from apps.api.app.core.audit import log_audit
        await log_audit(
            db, user, "repo_archived", "repository", repo_id,
            f"Archived project '{repo.name}' — scanning paused, data preserved",
            request=request,
            metadata={"repo_name": repo.name},
        )
    await db.commit()

    return {"status": "archived", "name": repo.name}


@router.post("/{repo_id}/unarchive", status_code=200)
async def unarchive_repository(
    repo_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Unarchive — resume scanning + restore to default list view.

    Clears archived markers from metadata.  Audit-logged.  Idempotent.
    """
    repo = await _get_repo_with_access_check(repo_id, db, user)
    meta = dict(repo.metadata_ or {})
    was_archived = meta.get("archived") is True
    meta.pop("archived", None)
    meta.pop("archived_at", None)
    meta.pop("archived_by", None)
    repo.metadata_ = meta
    await db.flush()

    if was_archived:
        from apps.api.app.core.audit import log_audit
        await log_audit(
            db, user, "repo_unarchived", "repository", repo_id,
            f"Unarchived project '{repo.name}' — scanning resumed",
            request=request,
            metadata={"repo_name": repo.name},
        )
    await db.commit()

    return {"status": "unarchived", "name": repo.name}


@router.get("/{repo_id}/stats")
async def get_repository_stats(
    repo_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    repo = await _get_repo_with_access_check(repo_id, db, user)

    from sqlalchemy import func
    from apps.api.app.models.finding import NormalizedFinding

    # Total findings
    total_r = await db.execute(
        select(func.count(NormalizedFinding.id)).where(
            NormalizedFinding.repository_id == repo_id,
            NormalizedFinding.tenant_id == user.tenant_id,
        )
    )
    total = total_r.scalar() or 0

    # By severity
    sev_r = await db.execute(
        select(NormalizedFinding.severity, func.count(NormalizedFinding.id))
        .where(NormalizedFinding.repository_id == repo_id, NormalizedFinding.tenant_id == user.tenant_id)
        .group_by(NormalizedFinding.severity)
    )
    by_severity = {str(s): c for s, c in sev_r.all()}

    # Last scan
    last_scan_r = await db.execute(
        select(ScanJob)
        .where(ScanJob.repository_id == repo_id, ScanJob.tenant_id == user.tenant_id)
        .order_by(ScanJob.created_at.desc())
        .limit(1)
    )
    last_scan = last_scan_r.scalar_one_or_none()

    open_criticals = by_severity.get("Severity.CRITICAL", by_severity.get("critical", 0))
    open_highs = by_severity.get("Severity.HIGH", by_severity.get("high", 0))

    # Policy gate evaluation
    # FAILED: has unresolved criticals or policy violations
    # WARNING: has open high findings
    # PASSED: no criticals or highs, all within thresholds
    # NOT_SCANNED: no scans run
    if not last_scan:
        policy_status = "not_scanned"
    elif open_criticals > 0:
        policy_status = "failed"
    elif open_highs > 0:
        policy_status = "warning"
    elif total > 0:
        policy_status = "passed"
    else:
        policy_status = "passed"

    # Check for active/running scan
    active_scan_r = await db.execute(
        select(ScanJob)
        .where(
            ScanJob.repository_id == repo_id,
            ScanJob.tenant_id == user.tenant_id,
            ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING, ScanStatus.ANALYZING]),
        )
        .order_by(ScanJob.created_at.desc())
        .limit(1)
    )
    active_scan = active_scan_r.scalar_one_or_none()

    return {
        "total_findings": total,
        "by_severity": by_severity,
        "open_criticals": open_criticals,
        "open_highs": open_highs,
        "last_scan_date": str(last_scan.created_at) if last_scan else None,
        "last_scan_status": last_scan.status.value if last_scan and hasattr(last_scan.status, 'value') else (last_scan.status if last_scan else None),
        "policy_status": policy_status,
        "active_scan": {
            "id": str(active_scan.id),
            "status": active_scan.status.value if hasattr(active_scan.status, 'value') else str(active_scan.status),
            "progress_pct": active_scan.progress_pct,
            "status_message": active_scan.status_message,
        } if active_scan else None,
    }


@router.post("/{repo_id}/scan", response_model=ScanJobResponse, status_code=201)
async def trigger_scan(
    repo_id: UUID,
    body: ScanRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    repo = await _get_repo_with_access_check(repo_id, db, user)

    scan_job = ScanJob(
        repository_id=repo.id,
        tenant_id=user.tenant_id,
        initiated_by=user.id,
        scan_type=ScanType(body.scan_type),
        status=ScanStatus.PENDING,
        config=body.config,
    )
    db.add(scan_job)
    await db.flush()
    await db.refresh(scan_job)

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "scan_started", "scan_job", scan_job.id,
                   f"Scan on {repo.name} ({body.scan_type})")
    from apps.worker.tasks import run_scan_job
    result = run_scan_job.delay(str(scan_job.id))

    scan_job.celery_task_id = result.id
    await db.flush()

    return scan_job


@router.post("/{repo_id}/scans/{scan_id}/ai-triage", status_code=202)
async def trigger_ai_triage_retro(
    repo_id: UUID,
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Re-run AI triage on an already-completed scan whose triage was skipped.

    For when a scan finished with no AI model configured: the user configures a
    model, then triggers triage retroactively WITHOUT re-scanning every file.
    Guards: scan must belong to this repo/tenant and be COMPLETED, an AI model
    must be configured, and no triage may already be in flight.
    """
    repo = await _get_repo_with_access_check(repo_id, db, user)

    scan_job = (await db.execute(
        select(ScanJob).where(
            ScanJob.id == scan_id,
            ScanJob.repository_id == repo.id,
            ScanJob.tenant_id == user.tenant_id,
        )
    )).scalar_one_or_none()
    if not scan_job:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan_job.status == ScanStatus.ANALYZING:
        raise HTTPException(status_code=409, detail="AI triage is already running for this scan")
    if scan_job.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=409, detail="AI triage can only run on a completed scan")

    # An AI model must be configured — env key OR an active DB model for the tenant.
    from apps.api.app.core.config import settings as _settings
    has_ai = bool(getattr(_settings, "ANTHROPIC_API_KEY", None) or getattr(_settings, "OPENAI_API_KEY", None))
    if not has_ai:
        from apps.api.app.models.ai_model import AIModelConfig
        m = (await db.execute(
            select(AIModelConfig).where(
                AIModelConfig.tenant_id == user.tenant_id,
                AIModelConfig.is_active == True,
            ).limit(1)
        )).scalar_one_or_none()
        has_ai = m is not None
    if not has_ai:
        raise HTTPException(status_code=400, detail="No AI model configured — add one in Settings → AI Providers")

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "ai_triage_retro_started", "scan_job", scan_job.id,
                    f"Manual AI triage on {repo.name}")
    from apps.worker.tasks import run_ai_triage_retro
    result = run_ai_triage_retro.delay(str(scan_job.id))
    scan_job.celery_task_id = result.id
    # Optimistically reflect the queued state so the card flips to live progress
    # immediately (the worker task re-confirms ANALYZING when it starts).
    scan_job.status = ScanStatus.ANALYZING
    scan_job.status_message = "AI triage — queued…"
    scan_job.progress_pct = 60
    await db.flush()

    return {"status": "queued", "scan_job_id": str(scan_job.id), "task_id": result.id}


@router.get("/{repo_id}/scans", response_model=list[ScanJobResponse])
async def list_scans(
    repo_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    await _get_repo_with_access_check(repo_id, db, user)
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.repository_id == repo_id, ScanJob.tenant_id == user.tenant_id)
        .order_by(ScanJob.created_at.desc())
        .limit(20)
    )
    return result.scalars().all()


@router.get("/{repo_id}/scans/{scan_id}", response_model=ScanJobResponse)
async def get_scan_status(
    repo_id: UUID,
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    await _get_repo_with_access_check(repo_id, db, user)
    result = await db.execute(
        select(ScanJob).where(
            ScanJob.id == scan_id,
            ScanJob.repository_id == repo_id,
            ScanJob.tenant_id == user.tenant_id,
        )
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@router.get("/{repo_id}/scans/{scan_id}/events", response_model=list[ScanPhaseEventResponse])
async def get_scan_events(
    repo_id: UUID,
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Append-only per-phase timeline for a scan (Sprint S / WS-1 + WS-7).

    Returns one row per phase transition, oldest-first, so the live
    progress drawer and the /scan-jobs/{id} page can seed the FULL
    timeline from the backend — surviving refresh, drawer-reopen, and
    scan completion (which the client-side-only timeline could not).

    WS-7 — authorization reuses the same tenant→repo→scan chain as every
    other scan endpoint: the repo access check scopes to the caller's
    tenant, and the event query is additionally bounded by the parent
    job's id so one tenant can never read another's scan telemetry.
    """
    await _get_repo_with_access_check(repo_id, db, user)

    # Confirm the scan belongs to this repo + tenant before exposing its
    # events (404 rather than an empty list so a cross-tenant / wrong-repo
    # id is indistinguishable from a non-existent one).
    job_r = await db.execute(
        select(ScanJob.id).where(
            ScanJob.id == scan_id,
            ScanJob.repository_id == repo_id,
            ScanJob.tenant_id == user.tenant_id,
        )
    )
    if job_r.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Scan job not found")

    # Ordered read driven by ix_scan_phase_events_job_created.
    result = await db.execute(
        select(ScanPhaseEvent)
        .where(ScanPhaseEvent.scan_job_id == scan_id)
        .order_by(ScanPhaseEvent.created_at.asc())
    )
    return result.scalars().all()


@router.post("/{repo_id}/scans/{scan_id}/cancel")
async def cancel_scan(
    repo_id: UUID,
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Cancel a running or pending scan job."""
    await _get_repo_with_access_check(repo_id, db, user)
    result = await db.execute(
        select(ScanJob).where(
            ScanJob.id == scan_id,
            ScanJob.repository_id == repo_id,
            ScanJob.tenant_id == user.tenant_id,
        )
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    # Only cancel if still running or pending
    if job.status not in (ScanStatus.PENDING, ScanStatus.RUNNING, ScanStatus.ANALYZING):
        raise HTTPException(status_code=400, detail=f"Cannot cancel scan in '{job.status.value}' state")

    # Revoke the Celery task — best effort either way.  For a healthy
    # in-flight scan this lands a SIGTERM that the worker handles
    # gracefully; for a zombie the task is already gone and revoke
    # is a no-op.
    if job.celery_task_id:
        try:
            from apps.worker.celery_app import celery_app
            celery_app.control.revoke(job.celery_task_id, terminate=True, signal="SIGTERM")
        except Exception as e:
            import structlog
            structlog.get_logger().warning("celery_revoke_failed", task_id=job.celery_task_id, error=str(e))
    else:
        # No task id recorded — revoke is impossible. All dispatch sites
        # persist the id, and the worker self-aborts at its next
        # cooperative-cancellation checkpoint, so the stop still happens
        # regardless — but log it, because landing here means some
        # dispatch path forgot to store the id.
        import structlog
        structlog.get_logger().warning(
            "cancel_without_task_id",
            scan_job_id=str(job.id),
            detail="no celery_task_id; relying on the worker's cooperative cancel",
        )

    # ── Release this scan's repo lock immediately ────────────────
    # Revoking with SIGTERM kills the worker mid-statement, so the
    # lock's `finally` never runs and the key survives its full 2h20m
    # TTL. The beat sweeper does reclaim locks whose holder is terminal,
    # but only every 5 minutes — and cancel-then-immediately-rerun is
    # the single most common thing an operator does. In that window the
    # new scan coalesces and is CANCELLED with "another scan is already
    # in progress", which is both confusing and untrue: the user just
    # cancelled that scan. They then click Run Scan again, and again.
    #
    # Releasing here makes cancel deterministic; the sweeper stays as
    # the belt-and-braces for crashes that never reach this code.
    try:
        from services.repo_scan.concurrency import cleanup_stale_locks

        _cancelled_id = str(job.id)

        async def _is_this_scan(holder: str) -> bool:
            return holder == _cancelled_id

        await cleanup_stale_locks(_is_this_scan)
    except Exception as e:
        # Never fail the cancel because lock cleanup hiccuped — the
        # sweeper will still collect it within ~5 minutes.
        import structlog
        structlog.get_logger().warning(
            "cancel_lock_release_failed", scan_job_id=str(job.id), error=str(e)[:200]
        )

    # ── Zombie detection ────────────────────────────────────────
    # When the worker dies (OOM / SIGKILL / container restart) it
    # cannot update the scan row before exit.  `updated_at` freezes
    # at the last successful commit, so a long gap since updated_at
    # is the strongest signal we have that the cancel is really
    # "clear the corpse" rather than "stop live work".  Threshold
    # of 5 min is well past any reasonable in-phase gap on a healthy
    # scan (per Track-A Live UX audit 2026-05-22; the longest silent
    # phase in `_run_scan_job` is the history walk at [4/8] which
    # publishes at 40% then again at 55% — typically < 3 min on
    # mid-size repos).
    #
    # Why this matters: stamping "Scan cancelled by Administrator"
    # on a scan whose worker has been dead for half an hour is
    # actively misleading during incident review — on-call would
    # waste time hunting for the user instead of investigating the
    # OOM.  Switching the status to FAILED also lets dashboard
    # "scan health" KPIs count worker crashes correctly.
    from datetime import datetime, timezone
    last_update = job.updated_at
    if last_update is not None and last_update.tzinfo is None:
        last_update = last_update.replace(tzinfo=timezone.utc)
    silence_s = (datetime.now(timezone.utc) - last_update).total_seconds() if last_update else 0
    is_zombie = silence_s > 5 * 60

    if is_zombie:
        silence_min = max(1, int(silence_s / 60))
        job.status = ScanStatus.FAILED
        job.status_message = (
            f"Scan aborted at {job.progress_pct}%. Worker silent for "
            f"{silence_min}m before {user.full_name} cancelled — process "
            f"likely crashed (OOM, SIGKILL, or container restart). "
            f"Retry from this page."
        )
        job.error_detail = job.status_message
        audit_action = "scan_aborted_zombie"
        audit_detail = (
            f"Scan force-failed at {job.progress_pct}% on user-cancel after "
            f"worker silent for {silence_min}m (likely worker crash)"
        )
    else:
        job.status = ScanStatus.CANCELLED
        job.status_message = f"Scan cancelled by {user.full_name}"
        audit_action = "scan_cancelled"
        audit_detail = f"Scan cancelled at {job.progress_pct}% progress"

    await db.flush()

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, audit_action, "scan_job", scan_id, audit_detail)

    return {
        "status": job.status.value.lower(),
        "scan_id": str(scan_id),
        "message": job.status_message,
        "zombie_detected": is_zombie,
    }


@router.delete("/{repo_id}/scans/{scan_id}", status_code=204)
async def delete_scan(
    repo_id: UUID,
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Permanently delete a scan job and all its associated data (findings, artifacts, etc.)."""
    await _get_repo_with_access_check(repo_id, db, user)
    result = await db.execute(
        select(ScanJob).where(
            ScanJob.id == scan_id,
            ScanJob.repository_id == repo_id,
            ScanJob.tenant_id == user.tenant_id,
        )
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    # Block deletion of in-progress scans — cancel first
    if job.status in (ScanStatus.PENDING, ScanStatus.RUNNING, ScanStatus.ANALYZING):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete an active scan (status: '{job.status.value}'). Cancel it first.",
        )

    from sqlalchemy import text

    sid = str(scan_id)

    # Delete all child rows in dependency order before removing the scan_job row.
    # NOTE: every scan_job child with an ORM relationship MUST be cleared here —
    # `db.delete(job)` would otherwise try to NULL the child's scan_job_id (the
    # default ORM "nullify" cascade), which fails on NOT-NULL FKs. scan_phase_events
    # was missed when WS-1 added it → "Failed to delete scan" (NotNullViolation).
    # ── Preserve findings that outlived this scan ────────────────────
    # A finding's `scan_job_id` is re-pointed to the CURRENT scan on every
    # re-scan (worker: "Point to current scan for stats"), so after a few
    # scans every finding a repository has ever accumulated is anchored to
    # its most recent one. Deleting rows by `scan_job_id` alone therefore
    # discards the repository's whole finding history — including secrets
    # first discovered long before the scan being deleted.
    #
    # `scan_count` is what separates the two cases. It is incremented on
    # every ingest path when a finding is seen again, so:
    #
    #   scan_count <= 1  this scan was the finding's only sighting; it has
    #                    no history to preserve and is deleted with it.
    #   scan_count  > 1  the finding predates this scan. Re-anchor it to
    #                    the newest SURVIVING scan and decrement the count.
    #
    # `scan_job_id` is NOT NULL, so a survivor is required to keep a
    # finding. When the scan being deleted is the repository's last one
    # there is nothing left to anchor to and the findings go with it.
    _survivor = await db.scalar(
        select(ScanJob.id)
        .where(ScanJob.repository_id == repo_id, ScanJob.id != scan_id)
        .order_by(ScanJob.created_at.desc())
        .limit(1)
    )
    if _survivor is not None:
        _preserved = await db.execute(
            text(
                """
                UPDATE normalized_findings
                   SET scan_job_id = CAST(:survivor AS uuid),
                       last_seen_scan_job_id = CASE
                           WHEN last_seen_scan_job_id = CAST(:sid AS uuid)
                           THEN CAST(:survivor AS uuid)
                           ELSE last_seen_scan_job_id
                       END,
                       scan_count = GREATEST(COALESCE(scan_count, 1) - 1, 1)
                 WHERE scan_job_id = CAST(:sid AS uuid)
                   AND COALESCE(scan_count, 1) > 1
                """
            ),
            {"sid": sid, "survivor": str(_survivor)},
        )
        import structlog
        structlog.get_logger().info(
            "scan_delete_preserved_findings",
            scan_job_id=sid,
            preserved=_preserved.rowcount,
            reanchored_to=str(_survivor),
        )

    # Everything still anchored here was only ever seen by this scan.
    _scan_child_tables = (
        "normalized_findings",       # finding_evidence / decisions / remediation cascade from here
        "imported_findings",
        "metric_snapshots",
        "policy_evaluation_results",  # removed product line — filtered out if absent
        "scan_artifacts",            # has ondelete=CASCADE but listed explicitly for clarity
        "scan_phase_events",         # WS phase timeline — NOT NULL scan_job_id, ondelete=CASCADE
    )
    _present_scan = await _existing_tables(db, _scan_child_tables)
    for tbl in _scan_child_tables:
        if tbl not in _present_scan:
            continue
        await db.execute(
            text(f"DELETE FROM {tbl} WHERE scan_job_id = :sid"),
            {"sid": sid},
        )

    await db.delete(job)
    await db.flush()

    from apps.api.app.core.audit import log_audit
    await log_audit(
        db, user, "scan_deleted", "scan_job", scan_id,
        f"Deleted scan job (was {job.status.value}, {job.progress_pct}% complete)",
    )


@router.post("/{repo_id}/upload", status_code=201)
async def upload_repository(
    repo_id: UUID,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    repo = await _get_repo_with_access_check(repo_id, db, user)

    import os
    import tempfile
    import zipfile
    import tarfile
    import shutil

    # Save the uploaded file temporarily
    content = await file.read()
    filename = file.filename or "upload"

    # Determine extraction directory
    extract_dir = os.path.join(settings.STORAGE_PATH, "repos", str(repo.id))
    os.makedirs(extract_dir, exist_ok=True)

    # Extract the archive
    try:
        if filename.endswith(".zip"):
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            with zipfile.ZipFile(tmp_path, "r") as zf:
                zf.extractall(extract_dir)
            os.unlink(tmp_path)
        elif filename.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar")):
            suffix = ".tar.gz" if filename.endswith((".tar.gz", ".tgz")) else ".tar.bz2" if filename.endswith(".tar.bz2") else ".tar"
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            with tarfile.open(tmp_path, "r:*") as tf:
                tf.extractall(extract_dir, filter="data")
            os.unlink(tmp_path)
        else:
            raise HTTPException(status_code=400, detail="Unsupported archive format. Use .zip, .tar.gz, .tgz, or .tar.bz2")

        # If the archive contains a single root directory, use that as the source
        entries = os.listdir(extract_dir)
        if len(entries) == 1 and os.path.isdir(os.path.join(extract_dir, entries[0])):
            # Move contents up one level
            inner_dir = os.path.join(extract_dir, entries[0])
            for item in os.listdir(inner_dir):
                shutil.move(os.path.join(inner_dir, item), os.path.join(extract_dir, item))
            os.rmdir(inner_dir)

    except (zipfile.BadZipFile, tarfile.TarError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid archive file: {str(e)}")

    # Run repo analysis to detect languages and frameworks
    from services.repo_analysis.analyzer import analyze_repository
    analysis = analyze_repository(extract_dir)
    repo.languages = list(analysis.languages.keys())[:10]
    repo.frameworks = analysis.frameworks[:10]

    from apps.api.app.models.repository import RepositorySnapshot
    snapshot = RepositorySnapshot(
        repository_id=repo.id,
        branch=repo.default_branch or "main",
        storage_path=extract_dir,
        file_count=analysis.total_files,
        total_size_bytes=analysis.total_size,
        analysis_result={
            "languages": analysis.languages,
            "frameworks": analysis.frameworks,
            "config_files": analysis.config_files[:50],
        },
    )
    db.add(snapshot)
    await db.flush()

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "repo_uploaded", "repository", repo.id, f"Uploaded artifact for {repo.name}")

    return {
        "snapshot_id": str(snapshot.id),
        "storage_path": extract_dir,
        "files": analysis.total_files,
        "languages": list(analysis.languages.keys()),
        "frameworks": analysis.frameworks,
    }
