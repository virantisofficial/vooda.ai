# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Confidence Calibration — learns from user FP/TP feedback to adjust
AI confidence scores over time.

When users mark findings as FP or TP, this module tracks the accuracy
of AI predictions per (scanner, rule_id, category) and applies Bayesian
adjustments to future confidence scores.

Example: If AI says "likely_true_positive" with 0.8 confidence, but users
mark 70% of those as false positive, future scores are reduced.
"""

import json
import structlog
from uuid import UUID
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

logger = structlog.get_logger()

CALIBRATION_CACHE_KEY = "vooda:calibration:{tenant_id}"
CALIBRATION_CACHE_TTL = 3600  # 1 hour


@dataclass
class CalibrationEntry:
    """Calibration stats for a (scanner, rule, category) tuple."""
    key: str
    total_decisions: int = 0
    ai_correct: int = 0      # AI said TP and user confirmed, or AI said FP and user confirmed
    ai_incorrect: int = 0    # AI said TP but user said FP, or vice versa
    accuracy: float = 0.5    # ai_correct / total
    adjustment_factor: float = 1.0  # multiply AI confidence by this


class ConfidenceCalibrator:
    """
    Adjusts AI confidence scores based on historical user feedback.

    The calibration works per (scanner_name, scanner_rule_id, vulnerability_category):
    - If users consistently agree with AI → adjustment_factor stays near 1.0
    - If users consistently disagree → adjustment_factor drops (reduces confidence)
    - Minimum 10 decisions required before applying adjustments (cold start protection)
    """

    MIN_DECISIONS = 10  # Minimum feedback events before calibrating
    FLOOR_FACTOR = 0.3  # Never reduce confidence below 30% of original
    CEILING_FACTOR = 1.3  # Never boost confidence above 130% of original

    async def compute_calibration(
        self,
        db: AsyncSession,
        tenant_id: UUID,
    ) -> dict[str, CalibrationEntry]:
        """
        Compute calibration tables from all historical user decisions.

        Returns a dict mapping calibration_key → CalibrationEntry.
        """
        from apps.api.app.models.finding import NormalizedFinding, FindingDecision

        # Query all decisions with their finding metadata
        result = await db.execute(
            select(
                NormalizedFinding.scanner_name,
                NormalizedFinding.scanner_rule_id,
                NormalizedFinding.vulnerability_category,
                NormalizedFinding.classification,  # AI's classification
                FindingDecision.action,  # User's action
            )
            .join(FindingDecision, FindingDecision.finding_id == NormalizedFinding.id)
            .where(
                NormalizedFinding.tenant_id == tenant_id,
                FindingDecision.action.in_(["mark_fp", "mark_tp", "accept_risk"]),
            )
        )
        rows = result.all()

        calibration: dict[str, CalibrationEntry] = {}

        for scanner, rule_id, category, ai_class, user_action in rows:
            # Build calibration key
            key = f"{scanner}|{rule_id or 'any'}|{category or 'any'}"

            if key not in calibration:
                calibration[key] = CalibrationEntry(key=key)

            entry = calibration[key]
            entry.total_decisions += 1

            ai_class_str = ai_class.value if hasattr(ai_class, 'value') else str(ai_class)

            # Determine if AI was correct
            ai_said_tp = "true_positive" in ai_class_str
            ai_said_fp = "false_positive" in ai_class_str
            user_said_fp = user_action == "mark_fp"
            user_said_tp = user_action in ("mark_tp", "accept_risk")

            if (ai_said_tp and user_said_tp) or (ai_said_fp and user_said_fp):
                entry.ai_correct += 1
            elif (ai_said_tp and user_said_fp) or (ai_said_fp and user_said_tp):
                entry.ai_incorrect += 1
            # needs_review decisions don't count as correct or incorrect

        # Compute accuracy and adjustment factors
        for entry in calibration.values():
            total = entry.ai_correct + entry.ai_incorrect
            if total > 0:
                entry.accuracy = entry.ai_correct / total
            else:
                entry.accuracy = 0.5  # neutral

            if entry.total_decisions >= self.MIN_DECISIONS:
                # Scale adjustment based on accuracy
                # accuracy=1.0 → factor=1.2 (slight boost)
                # accuracy=0.5 → factor=1.0 (neutral)
                # accuracy=0.0 → factor=0.3 (strong reduction)
                entry.adjustment_factor = max(
                    self.FLOOR_FACTOR,
                    min(self.CEILING_FACTOR, 0.4 + entry.accuracy * 0.9)
                )
            else:
                entry.adjustment_factor = 1.0  # not enough data

        logger.info(
            "calibration_computed",
            tenant_id=str(tenant_id)[:8],
            entries=len(calibration),
            calibrated=sum(1 for e in calibration.values() if e.total_decisions >= self.MIN_DECISIONS),
        )

        return calibration

    def calibrate_score(
        self,
        raw_score: float,
        scanner_name: str,
        rule_id: str | None,
        category: str | None,
        calibration: dict[str, CalibrationEntry],
    ) -> float:
        """
        Apply calibration adjustment to an AI confidence score.

        Tries increasingly general keys:
        1. Exact: scanner|rule_id|category
        2. Scanner+category: scanner|any|category
        3. Category only: any|any|category
        """
        keys_to_try = [
            f"{scanner_name}|{rule_id or 'any'}|{category or 'any'}",
            f"{scanner_name}|any|{category or 'any'}",
            f"any|any|{category or 'any'}",
        ]

        for key in keys_to_try:
            entry = calibration.get(key)
            if entry and entry.total_decisions >= self.MIN_DECISIONS:
                adjusted = raw_score * entry.adjustment_factor
                return max(0.0, min(1.0, round(adjusted, 3)))

        return raw_score  # no calibration data available

    # ── Redis caching ─────────────────────────────────────

    async def get_cached_calibration(
        self,
        tenant_id: UUID,
    ) -> Optional[dict[str, CalibrationEntry]]:
        """Try to load calibration from Redis cache."""
        try:
            import redis.asyncio as aioredis
            from apps.api.app.core.config import settings

            r = aioredis.from_url(settings.REDIS_URL)
            cache_key = CALIBRATION_CACHE_KEY.format(tenant_id=str(tenant_id))
            cached = await r.get(cache_key)
            await r.aclose()

            if cached:
                data = json.loads(cached)
                return {
                    k: CalibrationEntry(**v) for k, v in data.items()
                }
        except Exception as e:
            logger.debug("calibration_cache_miss", error=str(e)[:100])
        return None

    async def cache_calibration(
        self,
        tenant_id: UUID,
        calibration: dict[str, CalibrationEntry],
    ) -> None:
        """Store calibration in Redis cache."""
        try:
            import redis.asyncio as aioredis
            from apps.api.app.core.config import settings

            r = aioredis.from_url(settings.REDIS_URL)
            cache_key = CALIBRATION_CACHE_KEY.format(tenant_id=str(tenant_id))
            data = {
                k: {
                    "key": v.key,
                    "total_decisions": v.total_decisions,
                    "ai_correct": v.ai_correct,
                    "ai_incorrect": v.ai_incorrect,
                    "accuracy": v.accuracy,
                    "adjustment_factor": v.adjustment_factor,
                }
                for k, v in calibration.items()
            }
            await r.set(cache_key, json.dumps(data), ex=CALIBRATION_CACHE_TTL)
            await r.aclose()
        except Exception as e:
            logger.debug("calibration_cache_store_failed", error=str(e)[:100])

    async def invalidate_cache(self, tenant_id: UUID) -> None:
        """Invalidate cached calibration when new feedback arrives."""
        try:
            import redis.asyncio as aioredis
            from apps.api.app.core.config import settings

            r = aioredis.from_url(settings.REDIS_URL)
            cache_key = CALIBRATION_CACHE_KEY.format(tenant_id=str(tenant_id))
            await r.delete(cache_key)
            await r.aclose()
        except Exception:
            pass

    async def get_or_compute_calibration(
        self,
        db: AsyncSession,
        tenant_id: UUID,
    ) -> dict[str, CalibrationEntry]:
        """Get calibration from cache, or compute and cache it."""
        cached = await self.get_cached_calibration(tenant_id)
        if cached:
            logger.debug("calibration_cache_hit", tenant_id=str(tenant_id)[:8])
            return cached

        calibration = await self.compute_calibration(db, tenant_id)
        await self.cache_calibration(tenant_id, calibration)
        return calibration
