# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Custom Detectors API — CRUD for user-defined secret detection regex rules.

Enterprise admins define org-specific patterns (e.g. mycompany_sk_[a-zA-Z0-9]{32})
that are loaded at scan time alongside the 415+ built-in rules.
"""

import re
import signal
from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.models.custom_detector import CustomDetector

router = APIRouter()

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
RULE_ID_PREFIX = "CUSTOM-"
MAX_PATTERN_LENGTH = 2000
REGEX_TIMEOUT_SECONDS = 2.0


# ── Schemas ───────────────────────────────────────────────

class CustomDetectorCreate(BaseModel):
    # Stable identifier — appears in audit rows + finding.scanner_rule_id
    # so changing it would orphan historical findings.  Kebab-case
    # recommended (mirrors the built-in 925-rule catalog convention).
    rule_id: str = Field(
        ..., examples=["acme-internal-token-v1"],
        description="Stable machine ID. Lowercase, hyphenated.",
    )
    title: str = Field(..., examples=["ACME Internal API Token (v1)"])
    secret_type: str = Field(..., examples=["api_token", "private_key"])
    severity: str = Field("high", examples=["critical", "high", "medium", "low"])
    # Pattern is compiled by the hybrid engine (re2 fast path; Python
    # regex fallback).  See services/secret_scan/.  Avoid backreferences
    # and lookahead when possible — they force the slow path.
    pattern: str = Field(
        ..., examples=["acme_[a-z0-9]{32}"],
        description="Regex pattern. Tested live by POST /custom-detectors/test-regex.",
    )
    keywords: list[str] = Field(
        default_factory=list,
        examples=[["acme", "internal"]],
        description="Post-filter terms — file must contain ≥1 within the match window.",
    )
    confidence: float = Field(0.9, examples=[0.95], ge=0.0, le=1.0)
    description: str = Field("", examples=["Internal token format adopted 2024-Q3."])
    fix_hint: str = Field(
        "", examples=["Rotate via the internal-secrets vault, then revoke."],
    )
    cwe: str = Field("CWE-798", examples=["CWE-798"])
    multiline: bool = Field(False, description="Whether the regex spans newlines.")
    test_cases: list[dict] = Field(
        default_factory=list,
        examples=[[{"input": "acme_abc...", "should_match": True}]],
    )

    model_config = {
        "json_schema_extra": {
            "examples": [{
                "rule_id": "acme-internal-token-v1",
                "title": "ACME Internal API Token",
                "secret_type": "api_token",
                "severity": "high",
                "pattern": "acme_[a-z0-9]{32}",
                "keywords": ["acme", "internal"],
                "confidence": 0.95,
                "description": "Internal token format adopted 2024-Q3.",
                "fix_hint": "Rotate via internal-secrets vault.",
                "cwe": "CWE-798",
            }],
        },
    }


class CustomDetectorUpdate(BaseModel):
    title: Optional[str] = None
    secret_type: Optional[str] = None
    severity: Optional[str] = None
    pattern: Optional[str] = None
    keywords: Optional[list[str]] = None
    confidence: Optional[float] = None
    description: Optional[str] = None
    fix_hint: Optional[str] = None
    cwe: Optional[str] = None
    multiline: Optional[bool] = None
    test_cases: Optional[list[dict]] = None


class CustomDetectorResponse(BaseModel):
    id: UUID
    rule_id: str
    title: str
    secret_type: str
    severity: str
    pattern: str
    keywords: list
    confidence: float
    description: str
    fix_hint: str
    cwe: str
    multiline: bool
    is_enabled: bool
    created_by: UUID
    test_cases: list
    match_count: int
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


class RegexTestRequest(BaseModel):
    pattern: str = Field(
        ..., examples=["acme_[a-z0-9]{32}"],
        description="The regex pattern to compile and test.",
    )
    # ``test_strings`` is a LIST — each entry is tested independently
    # and returned with its match status.  Common UI mistake is to send
    # the entire sample as a single concatenated string.
    test_strings: list[str] = Field(
        ...,
        examples=[["acme_" + "a" * 32, "not_a_token", "acme_short"]],
        description=(
            "Test each string independently. Each returns "
            "{input, matched, match_text, groups}."
        ),
    )
    multiline: bool = Field(
        False, description="Whether to enable multiline mode (^ / $ match line boundaries).",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [{
                "pattern": "acme_[a-z0-9]{32}",
                "test_strings": [
                    "acme_abcdef0123456789abcdef0123456789",
                    "totally-different-string",
                    "acme_short",
                ],
            }],
        },
    }


class RegexTestResult(BaseModel):
    input: str
    matched: bool
    match_text: Optional[str] = None
    groups: list[str] = []


class RegexTestResponse(BaseModel):
    valid: bool
    error: Optional[str] = None
    results: list[RegexTestResult] = []


# ── Regex validation helpers ──────────────────────────────

def _validate_regex(pattern: str, multiline: bool = False) -> tuple[bool, Optional[str]]:
    """Validate a regex pattern for correctness and safety (no catastrophic backtracking)."""
    if len(pattern) > MAX_PATTERN_LENGTH:
        return False, f"Pattern too long ({len(pattern)} chars, max {MAX_PATTERN_LENGTH})"

    # Step 1: Compile check
    flags = re.IGNORECASE | re.MULTILINE
    if multiline:
        flags |= re.DOTALL
    try:
        compiled = re.compile(pattern, flags)
    except re.error as e:
        return False, f"Invalid regex: {e}"

    # Step 2: Catastrophic backtracking check — run against adversarial input
    # Uses SIGALRM (Unix) to interrupt C-level regex execution after timeout.
    adversarial = "a" * 5000 + "!"

    def _alarm_handler(signum, frame):
        raise TimeoutError("Regex backtracking timeout")

    old_handler = signal.getsignal(signal.SIGALRM)
    try:
        signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(int(REGEX_TIMEOUT_SECONDS))
        compiled.search(adversarial)
        signal.alarm(0)  # Cancel alarm — pattern is safe
    except TimeoutError:
        return False, "Pattern causes catastrophic backtracking. Simplify quantifiers (avoid nested `(a+)+` patterns)."
    except Exception:
        signal.alarm(0)
    finally:
        signal.signal(signal.SIGALRM, old_handler)

    return True, None


def _run_regex_test(pattern: str, test_strings: list[str], multiline: bool = False) -> RegexTestResponse:
    """Run a regex pattern against test strings and return structured results."""
    valid, error = _validate_regex(pattern, multiline)
    if not valid:
        return RegexTestResponse(valid=False, error=error)

    flags = re.IGNORECASE | re.MULTILINE
    if multiline:
        flags |= re.DOTALL
    compiled = re.compile(pattern, flags)

    results = []
    for s in test_strings:
        match = compiled.search(s)
        if match:
            # Extract captured group (group 1) or full match
            groups = [g for g in match.groups() if g is not None] if match.lastindex else []
            match_text = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group()
            results.append(RegexTestResult(input=s, matched=True, match_text=match_text, groups=groups))
        else:
            results.append(RegexTestResult(input=s, matched=False))

    return RegexTestResponse(valid=True, results=results)


def _normalize_rule_id(rule_id: str) -> str:
    """Ensure rule_id has the CUSTOM- prefix."""
    rule_id = rule_id.strip().upper().replace(" ", "-")
    if not rule_id.startswith(RULE_ID_PREFIX):
        rule_id = RULE_ID_PREFIX + rule_id
    return rule_id


def _to_response(det: CustomDetector) -> CustomDetectorResponse:
    """Convert a CustomDetector model to a response schema."""
    return CustomDetectorResponse(
        id=det.id,
        rule_id=det.rule_id,
        title=det.title,
        secret_type=det.secret_type,
        severity=det.severity,
        pattern=det.pattern,
        keywords=det.keywords or [],
        confidence=det.confidence or 0.9,
        description=det.description or "",
        fix_hint=det.fix_hint or "",
        cwe=det.cwe or "CWE-798",
        multiline=det.multiline or False,
        is_enabled=det.is_enabled,
        created_by=det.created_by,
        test_cases=det.test_cases or [],
        match_count=det.match_count or 0,
        created_at=str(det.created_at),
        updated_at=str(det.updated_at),
    )


# ── Endpoints ─────────────────────────────────────────────

@router.get("", response_model=list[CustomDetectorResponse])
async def list_custom_detectors(
    is_enabled: Optional[bool] = Query(None),
    severity: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = select(CustomDetector).where(CustomDetector.tenant_id == user.tenant_id)

    if is_enabled is not None:
        query = query.where(CustomDetector.is_enabled == is_enabled)
    if severity:
        query = query.where(CustomDetector.severity == severity)

    query = query.order_by(CustomDetector.created_at.desc())
    result = await db.execute(query)
    detectors = result.scalars().all()
    return [_to_response(d) for d in detectors]


@router.post("", response_model=CustomDetectorResponse, status_code=201)
async def create_custom_detector(
    body: CustomDetectorCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Validate severity
    if body.severity not in VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Invalid severity. Must be one of: {', '.join(VALID_SEVERITIES)}")

    # Validate confidence range
    confidence = max(0.0, min(1.0, body.confidence))

    # Normalize rule_id
    rule_id = _normalize_rule_id(body.rule_id)

    # Check uniqueness within tenant
    existing = await db.execute(
        select(CustomDetector).where(
            CustomDetector.tenant_id == user.tenant_id,
            CustomDetector.rule_id == rule_id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Rule ID '{rule_id}' already exists for this tenant")

    # Validate regex pattern
    valid, error = _validate_regex(body.pattern, body.multiline)
    if not valid:
        raise HTTPException(status_code=400, detail=error)

    # Validate test cases if provided
    if body.test_cases:
        test_result = _run_regex_test(body.pattern, [tc["input"] for tc in body.test_cases], body.multiline)
        for i, tc in enumerate(body.test_cases):
            expected = tc.get("should_match", True)
            actual = test_result.results[i].matched if i < len(test_result.results) else False
            if expected != actual:
                action = "match" if expected else "not match"
                raise HTTPException(
                    status_code=400,
                    detail=f"Test case failed: pattern should {action} '{tc['input']}' but {'matched' if actual else 'did not match'}"
                )

    detector = CustomDetector(
        tenant_id=user.tenant_id,
        rule_id=rule_id,
        title=body.title,
        secret_type=body.secret_type,
        severity=body.severity,
        pattern=body.pattern,
        keywords=body.keywords,
        confidence=confidence,
        description=body.description,
        fix_hint=body.fix_hint,
        cwe=body.cwe,
        multiline=body.multiline,
        is_enabled=True,
        created_by=user.id,
        test_cases=body.test_cases,
    )
    db.add(detector)
    await db.flush()
    await db.refresh(detector)
    return _to_response(detector)


@router.get("/{detector_id}", response_model=CustomDetectorResponse)
async def get_custom_detector(
    detector_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(CustomDetector).where(
            CustomDetector.id == detector_id,
            CustomDetector.tenant_id == user.tenant_id,
        )
    )
    detector = result.scalar_one_or_none()
    if not detector:
        raise HTTPException(status_code=404, detail="Custom detector not found")
    return _to_response(detector)


@router.put("/{detector_id}", response_model=CustomDetectorResponse)
async def update_custom_detector(
    detector_id: UUID,
    body: CustomDetectorUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(CustomDetector).where(
            CustomDetector.id == detector_id,
            CustomDetector.tenant_id == user.tenant_id,
        )
    )
    detector = result.scalar_one_or_none()
    if not detector:
        raise HTTPException(status_code=404, detail="Custom detector not found")

    updates = body.model_dump(exclude_unset=True)

    # Validate severity if being updated
    if "severity" in updates and updates["severity"] not in VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Invalid severity. Must be one of: {', '.join(VALID_SEVERITIES)}")

    # Clamp confidence
    if "confidence" in updates:
        updates["confidence"] = max(0.0, min(1.0, updates["confidence"]))

    # Validate pattern if being updated
    if "pattern" in updates:
        multiline = updates.get("multiline", detector.multiline)
        valid, error = _validate_regex(updates["pattern"], multiline)
        if not valid:
            raise HTTPException(status_code=400, detail=error)

    # Validate test cases if provided
    if "test_cases" in updates and updates["test_cases"]:
        pattern = updates.get("pattern", detector.pattern)
        multiline = updates.get("multiline", detector.multiline)
        test_result = _run_regex_test(pattern, [tc["input"] for tc in updates["test_cases"]], multiline)
        for i, tc in enumerate(updates["test_cases"]):
            expected = tc.get("should_match", True)
            actual = test_result.results[i].matched if i < len(test_result.results) else False
            if expected != actual:
                action = "match" if expected else "not match"
                raise HTTPException(
                    status_code=400,
                    detail=f"Test case failed: pattern should {action} '{tc['input']}'"
                )

    for field, value in updates.items():
        setattr(detector, field, value)

    await db.flush()
    await db.refresh(detector)
    return _to_response(detector)


@router.delete("/{detector_id}", status_code=204)
async def delete_custom_detector(
    detector_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(CustomDetector).where(
            CustomDetector.id == detector_id,
            CustomDetector.tenant_id == user.tenant_id,
        )
    )
    detector = result.scalar_one_or_none()
    if not detector:
        raise HTTPException(status_code=404, detail="Custom detector not found")
    await db.delete(detector)


@router.post("/{detector_id}/toggle", response_model=CustomDetectorResponse)
async def toggle_custom_detector(
    detector_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(CustomDetector).where(
            CustomDetector.id == detector_id,
            CustomDetector.tenant_id == user.tenant_id,
        )
    )
    detector = result.scalar_one_or_none()
    if not detector:
        raise HTTPException(status_code=404, detail="Custom detector not found")

    detector.is_enabled = not detector.is_enabled
    await db.flush()
    await db.refresh(detector)
    return _to_response(detector)


@router.post("/test-regex", response_model=RegexTestResponse)
async def test_regex(body: RegexTestRequest):
    """
    Stateless regex test endpoint — no DB access required.
    Validates the pattern, runs it against test strings, returns matches.
    Used by the frontend for live regex testing before saving.
    """
    if not body.test_strings:
        raise HTTPException(status_code=400, detail="At least one test string is required")
    if len(body.test_strings) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 test strings allowed")

    return _run_regex_test(body.pattern, body.test_strings, body.multiline)


@router.get("/stats/summary")
async def custom_detector_stats(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get custom detector statistics for the tenant."""
    total = await db.execute(
        select(func.count(CustomDetector.id)).where(CustomDetector.tenant_id == user.tenant_id)
    )
    active = await db.execute(
        select(func.count(CustomDetector.id)).where(
            CustomDetector.tenant_id == user.tenant_id,
            CustomDetector.is_enabled == True,
        )
    )
    total_matches = await db.execute(
        select(func.sum(CustomDetector.match_count)).where(
            CustomDetector.tenant_id == user.tenant_id,
        )
    )

    return {
        "total_detectors": total.scalar() or 0,
        "active_detectors": active.scalar() or 0,
        "total_matches": total_matches.scalar() or 0,
    }
