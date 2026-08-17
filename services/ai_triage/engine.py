# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
AI Triage Engine — false positive reduction pipeline.

Pipeline stages:
1. Parse finding metadata
2. Extract local code context (surrounding lines)
3. Extract wider repository context (imports, related files)
4. Detect framework-specific protections
5. Detect sanitization or safe APIs
6. Assess reachability and exploit preconditions
7. Classify finding
8. Generate evidence-backed explanation
9. Assign confidence and recommended action
"""

import json
import hashlib
import structlog
from typing import Optional

from services.ai_triage.provider import AIProvider, AIResponse
from packages.prompts.triage import TRIAGE_SYSTEM_PROMPT, TRIAGE_PROMPT_V1, TRIAGE_PROMPT_VERSION

logger = structlog.get_logger()


class TriageEngine:
    def __init__(self, provider: AIProvider, model_config: dict | None = None):
        self.provider = provider
        self._config = model_config or {}

    async def triage_finding(
        self,
        finding: dict,
        code_context: dict,
        repo_context: dict,
    ) -> dict:
        """
        Run the full triage pipeline for a single finding.

        Args:
            finding: Canonical finding data (from NormalizedFinding)
            code_context: {code_snippet, file_context, language}
            repo_context: {related_files, framework_info, config_info}

        Returns:
            Structured triage result dict.
        """
        # ── Phase 1: verifier short-circuit (ACTIVE credentials) ────────
        # If the secret-verification step already authenticated against the
        # provider's API (validation_status == "active"), we have definitive
        # proof this is a real, currently-working credential. Bypass the AI
        # entirely — no prompt can legitimately argue against a successful
        # 200 OK from the provider. Saves an AI call AND eliminates the
        # risk of the AI overruling verified-real signal.
        #
        # INACTIVE status is intentionally NOT a bypass — see the Phase 2
        # verification_context enrichment below for why the revoked-leak
        # case still needs AI reasoning.
        sm_preview = finding.get("source_metadata") or finding.get("raw_data") or {}
        if str(sm_preview.get("validation_status", "")).lower() == "active":
            details = sm_preview.get("verification_details", "") or ""
            perms = sm_preview.get("verification_permissions", "") or ""
            provider = sm_preview.get("provider", "unknown")
            return {
                "classification": "likely_true_positive",
                "confidence_score": 0.99,
                "exploitability_score": 0.95,
                "reasoning_summary": (
                    f"Credential authenticated against {provider} provider API "
                    f"(validation_status=active). This is a confirmed live secret — "
                    f"no probabilistic classification needed. {details}".strip()
                ),
                "true_positive_reasons": [
                    f"Verified active — successful API call to {provider}",
                    f"Permissions observed: {perms}" if perms else "Verified active credential",
                ],
                "false_positive_reasons": [],
                "compensating_controls_found": [],
                "required_human_review": False,
                "evidence": [{
                    "file": finding.get("file_path", ""),
                    "line_start": finding.get("line_start"),
                    "line_end": finding.get("line_end", finding.get("line_start")),
                    "summary": f"Verifier confirmed ACTIVE credential against {provider}.",
                }],
                "recommended_next_action": "remediate",
                "_audit": {
                    "prompt_version": "verifier-bypass-active",
                    "model": "verifier-short-circuit",
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "latency_ms": 0,
                    "prompt_hash": "",
                },
                "_bypass_reason": "validation_status=active",
            }

        # Build prompt — select template based on model config
        use_compact = self._config.get("use_compact_prompt", False)
        stop_seqs = self._config.get("stop_sequences") or []
        json_mode = self._config.get("supports_json_mode", False)

        # Resolve system prompt: strategy → override → default
        prompt_strategy = self._config.get("prompt_strategy", "recommended")
        system_override = self._config.get("system_prompt_override", "")
        if not system_override and prompt_strategy not in ("recommended", "custom"):
            # Load built-in strategy prompt (strict, sensitive)
            from packages.prompts.strategies import PROMPT_STRATEGIES
            strategy_def = PROMPT_STRATEGIES.get(prompt_strategy, {})
            system_override = strategy_def.get("system_prompt") or ""

        if use_compact:
            # Compact prompt for small local models (< 7B params)
            from packages.prompts.triage_compact import (
                TRIAGE_SYSTEM_PROMPT_COMPACT, TRIAGE_PROMPT_COMPACT, TRIAGE_COMPACT_VERSION,
            )
            system_prompt = system_override or TRIAGE_SYSTEM_PROMPT_COMPACT
            prompt = TRIAGE_PROMPT_COMPACT.format(
                title=finding.get("title", ""),
                severity=finding.get("severity", ""),
                file_path=finding.get("file_path", ""),
                line_start=finding.get("line_start", ""),
                description=self._truncate(finding.get("description", ""), 200),
                code_snippet=self._truncate(code_context.get("code_snippet", ""), 500),
            )
            prompt_version = TRIAGE_COMPACT_VERSION
        elif False:
            pass  # placeholder for elif chain below

        from packages.prompts.triage_v2 import build_triage_v2_prompt

        has_framework = bool(repo_context.get("framework_context", "").strip())
        has_enhanced = bool(code_context.get("enclosing_function") or code_context.get("imports"))

        if use_compact:
            pass  # Already built above
        elif has_framework or has_enhanced:
            # Rich-context path: richer USER prompt (imports, enclosing_function,
            # decorators, call_targets, framework section) + the currently-active
            # tuned SYSTEM prompt. build_triage_v2_prompt now returns
            # TRIAGE_SYSTEM_PROMPT (the V2.2 pattern-catalog + anti-hedging
            # version) as its first tuple element — prior to 2026-04-24 it
            # returned an unrelated thin TRIAGE_V2_SYSTEM_PROMPT, which silently
            # bypassed every V2 / V2.1 / V2.2 prompt improvement for findings
            # in Python / JS / Java / Go / Ruby / PHP / C# files (any file with
            # detected imports or an enclosing function).
            system_prompt, prompt = build_triage_v2_prompt(finding, code_context, repo_context)
            prompt_version = TRIAGE_PROMPT_VERSION
        else:
            # Build verification context from source_metadata.
            #
            # Phase 2 (2026-04-25): INACTIVE is intentionally NOT treated as
            # an auto-FP override. "Inactive" collapses several distinct
            # cases — regex matched random garbage (true FP), credential
            # was real but customer rotated it (still a TP — historical leak
            # evidence), real key that our verifier checked against the
            # wrong API endpoint (false negative on verification), etc. The
            # text below gives the model the nuance needed to make that
            # call rather than silently auto-suppressing revoked-leak
            # signal that security teams explicitly want to see.
            sm = finding.get("source_metadata") or finding.get("raw_data") or {}
            val_status = sm.get("validation_status", "not_validated")
            val_details = sm.get("verification_details", "")
            val_perms = sm.get("verification_permissions", "")
            if val_status == "active":
                # Note: this path is rarely hit now that the top-of-function
                # Phase 1 bypass short-circuits ACTIVE findings before any
                # prompt is built. Kept for defense-in-depth (e.g. if a
                # future caller bypasses the short-circuit).
                verification_context = (
                    f"VERIFIED ACTIVE — This credential was tested against the provider "
                    f"API and confirmed to be live and working. {val_details}. "
                    f"Permissions: {val_perms}. This is a confirmed true positive."
                )
            elif val_status == "inactive":
                verification_context = (
                    f"VERIFIED INACTIVE — The credential was tested against the provider "
                    f"API and does NOT currently authenticate. {val_details}. "
                    f"IMPORTANT: inactive does NOT automatically mean false positive. "
                    f"Weigh these cases when classifying:\n"
                    f"  * Regex matched random garbage that was never real → likely FP.\n"
                    f"  * Credential was real but has since been rotated/revoked → "
                    f"TREAT AS TRUE POSITIVE. This is historical leak evidence; security "
                    f"teams explicitly want to know a credential was ever exposed in the "
                    f"repo, even after rotation.\n"
                    f"  * Value has real provider-format entropy (AKIA... for AWS, "
                    f"ghp_... for GitHub, xoxb-... for Slack, etc.) and appears in a "
                    f"realistic config/credential file → treat as TRUE POSITIVE even "
                    f"when inactive; the value was plausibly real at some point.\n"
                    f"  * Value is a placeholder/example (CHANGE_ME, example.com, "
                    f"all-zero UUID, etc.) → FP regardless of inactive status.\n"
                    f"Use the code context below to decide which case applies."
                )
            else:
                verification_context = (
                    "Not verified — credential has not been tested against the provider API."
                )

            # Surface deterministic scanner signals to the AI as
            # explicit facts (Option B from the commercial-grade audit
            # gap #6).  These flags are computed by the scanner BEFORE
            # the AI runs — passing them in lets the AI calibrate
            # against ground-truth rather than re-deriving the same
            # signal probabilistically from the code context (or
            # missing it entirely).  Drives the SuggestionChips UI on
            # the drawers/standalone-page: when AI agrees with a
            # signal, the chip becomes a one-click confirm; when AI
            # confidently disagrees, the chip is hidden so the human
            # isn't fighting the AI's verdict.
            sm_signals = sm_preview or finding.get("source_metadata") or finding.get("raw_data") or {}
            sig_lines: list[str] = []
            if sm_signals.get("is_placeholder") is True:
                sig_lines.append(
                    "- is_placeholder=true — value matched the scanner's "
                    "KNOWN_PLACEHOLDER_VALUES / KNOWN_PLACEHOLDER_PATTERNS set "
                    "(e.g. 'changeme', '<your-api-key>', 'xxxxxxxx').  Strong "
                    "false-positive signal unless surrounding code shows the "
                    "value is later overridden with a real credential."
                )
            if sm_signals.get("file_context") == "test_file":
                sig_lines.append(
                    "- file_context=test_file — path segments / extensions "
                    "indicate this is a test/spec/fixture file (e.g. "
                    "tests/, __tests__/, .test.ts, .spec.py).  Real prod "
                    "secrets in test files DO happen — don't auto-FP, but "
                    "the prior is heavily toward test-credential."
                )
            if sm_signals.get("detection_engine") == "secret_scan_history":
                commit_sha = (sm_signals.get("commit_sha") or "")[:8]
                sig_lines.append(
                    f"- detection_engine=secret_scan_history — value is NOT "
                    f"in current code; only present in a historical commit "
                    f"({commit_sha or 'unknown'}).  Rotation is still "
                    f"required even if file is clean now."
                )
            if sm_signals.get("is_placeholder") is False and not sig_lines:
                # When the scanner explicitly checked and the value is
                # NOT a placeholder, surface that too — it's evidence
                # AGAINST a placeholder classification.
                sig_lines.append(
                    "- is_placeholder=false — scanner's placeholder check "
                    "ran and did NOT match.  Value is a real-looking secret."
                )
            pre_detected_signals = (
                "\n".join(sig_lines) if sig_lines else "_No deterministic signals triggered._"
            )

            prompt = TRIAGE_PROMPT_V1.format(
                title=finding.get("title", ""),
                category=finding.get("vulnerability_category", ""),
                severity=finding.get("severity", ""),
                cwe=finding.get("cwe", ""),
                scanner_name=finding.get("scanner_name", ""),
                rule_id=finding.get("scanner_rule_id", ""),
                file_path=finding.get("file_path", ""),
                line_start=finding.get("line_start", ""),
                description=finding.get("description", ""),
                language=code_context.get("language", ""),
                code_snippet=self._truncate(code_context.get("code_snippet", ""), 2000),
                file_context=self._truncate(code_context.get("file_context", ""), 4000),
                related_context=self._truncate(repo_context.get("related_files_context", ""), 3000),
                framework_context=self._truncate(repo_context.get("framework_context", ""), 1000),
                verification_context=verification_context,
                pre_detected_signals=pre_detected_signals,
            )
            system_prompt = TRIAGE_SYSTEM_PROMPT
            prompt_version = TRIAGE_PROMPT_VERSION

        # Apply system prompt override if configured (non-compact mode)
        if system_override and not use_compact:
            system_prompt = system_override

        # Call AI with optional stop sequences and JSON mode.
        # Catch provider-level upstream errors (nested `choice.error` in an
        # otherwise-200 response) and surface them through the same
        # _parse_failure channel the parser uses, so downstream telemetry
        # (badge, notification, logs) can classify the failure correctly.
        try:
            response = await self.provider.complete(
                system_prompt=system_prompt,
                user_prompt=prompt,
                stop_sequences=stop_seqs if stop_seqs else None,
                json_mode=json_mode,
            )
        except RuntimeError as upstream_exc:
            err_text = str(upstream_exc)
            logger.warning(
                "ai_response_upstream_error",
                failure_type="upstream_error",
                error=err_text[:300],
                model=getattr(self.provider, "model", "unknown"),
            )
            return {
                "classification": "needs_review",
                "confidence_score": 0.0,
                "exploitability_score": 0.5,
                "reasoning_summary": err_text,
                "true_positive_reasons": [],
                "false_positive_reasons": [],
                "compensating_controls_found": [],
                "required_human_review": True,
                "evidence": [],
                "recommended_next_action": "request_human_review",
                "_parse_failure": "upstream_error",
            }

        # Parse and validate response
        result = self._parse_response(response)

        # Retry on parse failure with simplified fallback prompt
        if result.get("required_human_review") and result.get("confidence_score", 0) == 0.0:
            logger.info("triage_retry_with_fallback", finding_title=finding.get("title"))
            try:
                from packages.prompts.triage_compact import TRIAGE_FALLBACK_PROMPT, TRIAGE_SYSTEM_PROMPT_COMPACT
                fallback_prompt = TRIAGE_FALLBACK_PROMPT.format(
                    title=finding.get("title", ""),
                    file_path=finding.get("file_path", ""),
                    line_start=finding.get("line_start", ""),
                    code_snippet_short=self._truncate(code_context.get("code_snippet", ""), 200),
                )
                retry_response = await self.provider.complete(
                    system_prompt=TRIAGE_SYSTEM_PROMPT_COMPACT,
                    user_prompt=fallback_prompt,
                    max_tokens=150,
                    temperature=0,
                    stop_sequences=["\n\n"],
                    json_mode=json_mode,
                )
                retry_result = self._parse_response(retry_response)
                if retry_result.get("confidence_score", 0) > 0:
                    result = retry_result
                    result["_retry"] = True
                    logger.info("triage_retry_succeeded", classification=result.get("classification"))
            except Exception as retry_err:
                logger.warning("triage_retry_failed", error=str(retry_err)[:100])

        # Attach audit metadata
        result["_audit"] = {
            "prompt_version": prompt_version,
            "model": response.model,
            "input_tokens": response.input_tokens,
            "output_tokens": response.output_tokens,
            "latency_ms": response.latency_ms,
            "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()[:16],
        }

        # ── Customer feedback loop: apply tenant-specific calibration ──
        # The recalibrate_tenant task (apps/worker/tasks.py) recomputes a
        # per-(scanner, rule, category) adjustment factor every time a user
        # marks a finding TP/FP. Until 2026-04-25 the factors were computed
        # and cached but never read — closing the loop here applies the
        # learned correction to the AI's raw confidence score whenever the
        # tenant has at least MIN_DECISIONS=10 reviewed findings for the
        # matching key. Below MIN_DECISIONS the factor is 1.0 (no-op),
        # so this is safe to enable immediately and gets stronger with
        # every customer correction.
        try:
            tenant_id = finding.get("tenant_id") or self._config.get("tenant_id")
            if tenant_id:
                from services.ai_triage.calibration import ConfidenceCalibrator
                from uuid import UUID as _UUID
                calibrator = ConfidenceCalibrator()
                cached = await calibrator.get_cached_calibration(_UUID(str(tenant_id)))
                if cached:
                    raw = float(result.get("confidence_score", 0.5) or 0.5)
                    adjusted = calibrator.calibrate_score(
                        raw,
                        scanner_name=finding.get("scanner_name", ""),
                        rule_id=finding.get("scanner_rule_id"),
                        category=finding.get("vulnerability_category"),
                        calibration=cached,
                    )
                    if adjusted != raw:
                        result["confidence_score"] = adjusted
                        result["_audit"]["calibration_applied"] = {
                            "raw": raw,
                            "adjusted": adjusted,
                        }
        except Exception as cal_err:
            # Calibration is best-effort — never block triage if Redis
            # is down or the calibration table is malformed.
            logger.debug("calibration_skipped", error=str(cal_err)[:100])

        # Validate groundedness
        result = self._validate_groundedness(result, code_context, repo_context)

        logger.info(
            "triage_complete",
            finding_title=finding.get("title"),
            classification=result.get("classification"),
            confidence=result.get("confidence_score"),
        )

        return result

    def _parse_response(self, response: AIResponse) -> dict:
        """Parse AI response into structured result, with retry-safe fallback."""
        content = response.content.strip()

        # Strip markdown code fences if present
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        try:
            result = json.loads(content)
        except json.JSONDecodeError as je:
            # Classify the failure so users/ops can distinguish between
            # an empty response, a truncated response, and a format error.
            if not content or len(content.strip()) < 5:
                failure_type = "empty_response"
                reason = "AI model returned no content (likely timeout or quota issue)."
            elif content.rstrip().endswith((".", ",", ":", "{", "[", "\"")):
                failure_type = "truncated_response"
                reason = (f"AI model truncated output mid-JSON — {type(response).__name__} "
                          f"emitted {response.output_tokens} completion tokens before stopping. "
                          "Consider switching to a model with more reliable structured output "
                          "(Claude, Gemini, Llama) or increasing max_tokens.")
            else:
                failure_type = "invalid_json"
                reason = f"AI response was not valid JSON: {je.msg}"
            logger.warning("ai_response_parse_error",
                failure_type=failure_type,
                content_preview=content[:200],
                output_tokens=response.output_tokens,
                model=response.model,
            )
            return {
                "classification": "needs_review",
                "confidence_score": 0.0,
                "exploitability_score": 0.5,
                "reasoning_summary": reason,
                "true_positive_reasons": [],
                "false_positive_reasons": [],
                "compensating_controls_found": [],
                "required_human_review": True,
                "evidence": [],
                "recommended_next_action": "request_human_review",
                "_parse_failure": failure_type,
            }

        # Validate required fields
        required = ["classification", "confidence_score", "reasoning_summary"]
        for field in required:
            if field not in result:
                result["required_human_review"] = True
                result.setdefault("classification", "needs_review")

        # Clamp scores
        for score_field in ["confidence_score", "exploitability_score"]:
            if score_field in result:
                result[score_field] = max(0.0, min(1.0, float(result[score_field])))

        return result

    def _validate_groundedness(self, result: dict, code_context: dict, repo_context: dict) -> dict:
        """
        Post-process: verify that evidence references actually exist in provided context.
        Demote confidence if evidence can't be grounded.
        """
        code_text = code_context.get("file_context", "") + code_context.get("code_snippet", "")
        related_text = repo_context.get("related_files_context", "")
        all_context = code_text + related_text

        grounded_evidence = []
        ungrounded = 0

        for ev in result.get("evidence", []):
            file_ref = ev.get("file", "")
            summary = ev.get("summary", "")
            # Check if the file is mentioned in context
            if file_ref and file_ref in all_context:
                grounded_evidence.append(ev)
            else:
                ungrounded += 1
                logger.warning("ungrounded_evidence", file=file_ref, summary=summary[:100])

        result["evidence"] = grounded_evidence

        if ungrounded > 0:
            # Reduce confidence proportionally
            penalty = 0.1 * ungrounded
            result["confidence_score"] = max(0.0, result.get("confidence_score", 0.5) - penalty)
            if result["confidence_score"] < 0.4:
                result["required_human_review"] = True

        return result

    @staticmethod
    def _truncate(text: str, max_chars: int) -> str:
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + "\n... [truncated]"
