# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
AI Remediation Engine — generates secure code patches for confirmed vulnerabilities.
"""

import json
import hashlib
import structlog

from services.ai_triage.provider import AIProvider, AIResponse
from packages.prompts.remediation import (
    REMEDIATION_SYSTEM_PROMPT,
    REMEDIATION_PROMPT_V1,
    REMEDIATION_PROMPT_VERSION,
)

logger = structlog.get_logger()


class RemediationEngine:
    def __init__(self, provider: AIProvider):
        self.provider = provider

    async def generate_remediation(
        self,
        finding: dict,
        triage_result: dict,
        code_context: dict,
        repo_context: dict,
    ) -> dict:
        """
        Generate a remediation plan and patch for a finding.

        Args:
            finding: Canonical finding data
            triage_result: Output from triage engine
            code_context: {vulnerable_code, file_context, language, available_imports}
            repo_context: {framework_context}

        Returns:
            Structured remediation result.
        """
        prompt = REMEDIATION_PROMPT_V1.format(
            title=finding.get("title", ""),
            category=finding.get("vulnerability_category", ""),
            cwe=finding.get("cwe", ""),
            severity=finding.get("severity", ""),
            file_path=finding.get("file_path", ""),
            line_start=finding.get("line_start", ""),
            line_end=finding.get("line_end", ""),
            description=finding.get("description", ""),
            triage_summary=triage_result.get("reasoning_summary", ""),
            language=code_context.get("language", ""),
            vulnerable_code=self._truncate(code_context.get("vulnerable_code", ""), 2000),
            file_context=self._truncate(code_context.get("file_context", ""), 6000),
            available_imports=code_context.get("available_imports", "Not determined"),
            framework_context=repo_context.get("framework_context", "Not determined"),
        )

        # Append remediation template if available
        try:
            from packages.remediation_templates.registry import get_template
            language = code_context.get("language", "")
            category = finding.get("vulnerability_category", "")
            template = get_template(category, language)
            if template:
                prompt += f"\n\n## Reference Fix Pattern\nHere is a proven fix pattern for this vulnerability type:\n```\n{template}\n```\nUse this pattern as guidance but adapt to the specific code context."
        except Exception:
            pass

        response = await self.provider.complete(
            system_prompt=REMEDIATION_SYSTEM_PROMPT,
            user_prompt=prompt,
            max_tokens=4096,
        )

        result = self._parse_response(response)

        # Safety scoring
        result["safety_score"] = self._compute_safety_score(result)

        # Audit metadata
        result["_audit"] = {
            "prompt_version": REMEDIATION_PROMPT_VERSION,
            "model": response.model,
            "input_tokens": response.input_tokens,
            "output_tokens": response.output_tokens,
            "latency_ms": response.latency_ms,
            "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()[:16],
        }

        logger.info(
            "remediation_generated",
            finding_title=finding.get("title"),
            confidence=result.get("confidence_score"),
            safety=result.get("safety_score"),
            risk=result.get("risk_of_breakage"),
        )

        return result

    def _parse_response(self, response: AIResponse) -> dict:
        content = response.content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        try:
            result = json.loads(content)
        except json.JSONDecodeError:
            logger.warning("remediation_parse_error", content_preview=content[:200])
            return {
                "remediation_type": "failed",
                "confidence_score": 0.0,
                "summary": "AI could not generate a valid remediation. Manual fix required.",
                "risk_of_breakage": "unknown",
                "patch_diff": "",
                "files_changed": [],
                "developer_notes": ["Automatic remediation failed — manual review needed"],
                "validation_steps": [],
            }

        # Validate patch is present
        if not result.get("patch_diff"):
            result["confidence_score"] = max(0.0, result.get("confidence_score", 0.0) - 0.3)
            result.setdefault("developer_notes", []).append("No patch diff generated")

        return result

    def _compute_safety_score(self, result: dict) -> float:
        """Heuristic safety scoring for the generated patch."""
        score = 0.7  # base

        # Penalty for high breakage risk
        risk = result.get("risk_of_breakage", "medium").lower()
        if risk == "high":
            score -= 0.3
        elif risk == "medium":
            score -= 0.1

        # Bonus for validation steps
        steps = result.get("validation_steps", [])
        if len(steps) >= 3:
            score += 0.1
        elif len(steps) >= 1:
            score += 0.05

        # Penalty for many files changed
        files = result.get("files_changed", [])
        if len(files) > 3:
            score -= 0.15
        elif len(files) > 1:
            score -= 0.05

        # Bonus for developer notes
        if result.get("developer_notes"):
            score += 0.05

        return max(0.0, min(1.0, round(score, 2)))

    @staticmethod
    def _truncate(text: str, max_chars: int) -> str:
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + "\n... [truncated]"
