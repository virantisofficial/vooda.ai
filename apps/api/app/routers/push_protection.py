# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Push Protection API — inline scan endpoint for blocking pushes with secrets.

Called by git server hooks, GitHub Apps, or CI/CD pipelines.
Returns pass/fail with found secrets in <500ms.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import time

from services.secret_scan.engine import SecretScanner

router = APIRouter()


class ScanRequest(BaseModel):
    """Request body for inline secret scan."""
    files: list[dict]  # [{"path": "config.py", "content": "..."}]
    policy: Optional[str] = "block_critical"  # block_critical, block_all, audit_only


class SecretFound(BaseModel):
    rule_id: str
    title: str
    severity: str
    file_path: str
    line: int
    masked_value: str
    provider: str
    confidence: float


class ScanResponse(BaseModel):
    blocked: bool
    secrets_found: int
    scan_time_ms: int
    policy: str
    secrets: list[SecretFound]
    message: str


@router.post("/scan/inline", response_model=ScanResponse)
async def inline_scan(request: ScanRequest):
    """
    Scan file contents for secrets inline. Returns pass/fail.

    Use this endpoint in:
    - Git pre-receive hooks (server-side push protection)
    - GitHub App check runs
    - CI/CD pipeline gates

    Target latency: <500ms for typical PR diff.
    """
    start = time.time()
    scanner = SecretScanner(enable_entropy=True)

    all_findings = []
    for file_entry in request.files:
        path = file_entry.get("path", "unknown")
        content = file_entry.get("content", "")
        if not content:
            continue
        findings = scanner.scan_file(path, content)
        all_findings.extend(findings)

    elapsed_ms = int((time.time() - start) * 1000)

    # Apply policy
    policy = request.policy or "block_critical"

    secrets = []
    for f in all_findings:
        secrets.append(SecretFound(
            rule_id=f.rule_id or "",
            title=f.title,
            severity=f.severity,
            file_path=f.file_path or "",
            line=f.line_start or 0,
            masked_value=(f.raw_data or {}).get("masked_value", "****"),
            provider=(f.raw_data or {}).get("provider", "unknown"),
            confidence=f.confidence,
        ))

    # Determine if blocked
    blocked = False
    if policy == "block_all" and len(secrets) > 0:
        blocked = True
    elif policy == "block_critical":
        blocked = any(s.severity in ("critical", "high") for s in secrets)
    # audit_only never blocks

    message = "No secrets detected." if not secrets else (
        f"BLOCKED: {len(secrets)} secret(s) detected." if blocked else
        f"WARNING: {len(secrets)} secret(s) detected (audit mode)."
    )

    return ScanResponse(
        blocked=blocked,
        secrets_found=len(secrets),
        scan_time_ms=elapsed_ms,
        policy=policy,
        secrets=secrets,
        message=message,
    )


@router.get("/scan/health")
async def scan_health():
    """Health check for push protection endpoint."""
    from services.secret_scan.detectors.registry import get_rule_count
    return {
        "status": "healthy",
        "rules_loaded": get_rule_count(),
        "engine": "vooda_secret_scanner",
    }
