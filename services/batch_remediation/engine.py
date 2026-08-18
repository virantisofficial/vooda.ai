# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Batch Remediation Engine — fixes all findings of the same category at once.

Groups findings by (file, category), generates a combined patch per file,
validates each patch, and creates a single PR for the entire batch.
"""

import structlog
from uuid import UUID
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

logger = structlog.get_logger()


@dataclass
class BatchRemediationResult:
    """Result from a batch remediation operation."""
    total_findings: int = 0
    remediated: int = 0
    failed: int = 0
    skipped: int = 0
    pr_url: Optional[str] = None
    errors: list[str] = field(default_factory=list)
    file_patches: dict[str, str] = field(default_factory=dict)  # file_path -> patch


class BatchRemediationEngine:
    """
    Processes multiple findings of the same category together.

    Groups by file to minimize the number of patches and avoid conflicts.
    Generates one AI remediation call per file (with all findings in context),
    validates each patch, then creates a single PR.
    """

    async def remediate_batch(
        self,
        db: AsyncSession,
        repository_id: UUID,
        finding_ids: list[UUID],
        tenant_id: UUID,
    ) -> BatchRemediationResult:
        """
        Generate fixes for a batch of findings.

        Args:
            db: Database session
            repository_id: Target repository
            finding_ids: List of finding IDs to fix
            tenant_id: Tenant context

        Returns:
            BatchRemediationResult with stats and PR URL
        """
        from apps.api.app.models.finding import NormalizedFinding
        from apps.api.app.models.repository import Repository, RepositorySnapshot
        from apps.api.app.models.remediation import RemediationPlan, RemediationPatch, PatchStatus
        from apps.api.app.core.config import settings

        result = BatchRemediationResult(total_findings=len(finding_ids))

        # Load findings
        findings_result = await db.execute(
            select(NormalizedFinding).where(
                NormalizedFinding.id.in_(finding_ids),
                NormalizedFinding.repository_id == repository_id,
            )
        )
        findings = findings_result.scalars().all()

        if not findings:
            result.errors.append("No findings found")
            return result

        # Group by file
        file_groups: dict[str, list] = {}
        for f in findings:
            key = f.file_path
            if key not in file_groups:
                file_groups[key] = []
            file_groups[key].append(f)

        # Get repo path
        snap_result = await db.execute(
            select(RepositorySnapshot)
            .where(RepositorySnapshot.repository_id == repository_id)
            .order_by(RepositorySnapshot.created_at.desc())
            .limit(1)
        )
        snapshot = snap_result.scalar_one_or_none()
        repo_path = snapshot.storage_path if snapshot else ""

        # Check AI is available
        if not (settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY):
            result.errors.append("No AI API key configured")
            return result

        from services.ai_triage.provider import create_provider
        from services.ai_remediation.engine import RemediationEngine
        from services.code_context.extractor import extract_rich_context

        provider = create_provider(
            settings.AI_PROVIDER,
            settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY,
            settings.AI_MODEL,
        )
        rem_engine = RemediationEngine(provider)

        # Process each file group
        for file_path, file_findings in file_groups.items():
            try:
                # Build combined context with all findings in this file
                code_ctx = extract_rich_context(repo_path, file_path, file_findings[0].line_start)
                code_ctx["vulnerable_code"] = code_ctx.get("code_snippet", "")
                code_ctx["available_imports"] = code_ctx.get("imports", "")

                # Build combined finding description
                combined_desc = f"Fix {len(file_findings)} vulnerabilities in {file_path}:\n"
                for i, f in enumerate(file_findings, 1):
                    sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                    combined_desc += f"\n{i}. [{sev}] {f.title[:80]} (line {f.line_start})"
                    if f.cwe:
                        combined_desc += f" — {f.cwe}"

                finding_data = {
                    "title": f"Batch fix: {len(file_findings)} findings in {file_path}",
                    "description": combined_desc,
                    "vulnerability_category": file_findings[0].vulnerability_category,
                    "severity": file_findings[0].severity.value if hasattr(file_findings[0].severity, "value") else str(file_findings[0].severity),
                    "cwe": file_findings[0].cwe,
                    "file_path": file_path,
                    "line_start": min(f.line_start or 0 for f in file_findings),
                    "line_end": max(f.line_end or f.line_start or 0 for f in file_findings),
                }

                triage_result = {
                    "reasoning_summary": combined_desc,
                }
                repo_ctx = {"framework_context": ""}

                # Generate remediation
                rem_result = await rem_engine.generate_remediation(
                    finding_data, triage_result, code_ctx, repo_ctx
                )

                # G1b — the AI remediation result is free text that can echo
                # a secret (summary / root-cause / patch_diff `-` line). Scrub
                # every string before it's persisted + served via API/UI.
                from services.secret_scan.engine import scrub_secrets_in_obj as _scrub_obj
                rem_result = _scrub_obj(rem_result)
                # Store plan and patch for each finding in the group
                for f in file_findings:
                    plan = RemediationPlan(
                        finding_id=f.id,
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

                    if rem_result.get("patch_diff"):
                        patch = RemediationPatch(
                            plan_id=plan.id,
                            patch_diff=rem_result["patch_diff"],
                            files_changed=rem_result.get("files_changed", [file_path]),
                            status=PatchStatus.PROPOSED,
                            confidence_score=rem_result.get("confidence_score"),
                            safety_score=rem_result.get("safety_score"),
                        )
                        db.add(patch)

                    f.remediation_status = "patch_generated"
                    result.remediated += 1

                if rem_result.get("patch_diff"):
                    result.file_patches[file_path] = rem_result["patch_diff"]

            except Exception as e:
                result.failed += len(file_findings)
                result.errors.append(f"{file_path}: {str(e)[:200]}")
                logger.error("batch_remediation_file_error", file=file_path, error=str(e)[:200])

        await db.flush()

        logger.info(
            "batch_remediation_complete",
            total=result.total_findings,
            remediated=result.remediated,
            failed=result.failed,
            files=len(result.file_patches),
        )

        return result
