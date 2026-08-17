# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Batch AI Triage Processor — processes findings concurrently with rate
limiting and a library-grade circuit breaker (Sprint B-1).

Replaces the home-grown adaptive Semaphore(1) swap, which deadlocked under
sustained 429s: when the swap fired mid-flight, a single stuck call held
the only slot forever and the whole batch wedged for the Celery hard
time-limit (~2h). Now each provider call goes through a pybreaker
circuit, the per-call wait_for ALWAYS fires, and concurrency stays fixed.
"""

import asyncio
import time
import structlog
# The circuit breaker is an OPTIONAL hardening layer. Guard the import so a
# missing/uninstalled `purgatory` can NEVER silently disable AI triage. Before
# this guard, an absent purgatory made the whole module fail to import → every
# scan's _run_ai_triage raised → ai_triaged=0 with a generic "check provider
# health". When the lib is unavailable we fall back to a no-op breaker; retries
# and the rate limiter still protect against a failing provider.
try:
    import purgatory
    from purgatory.domain.model import OpenedState as _CircuitOpen
    _HAS_PURGATORY = True
except ImportError:  # pragma: no cover — exercised only on dependency drift
    purgatory = None
    _HAS_PURGATORY = False

    class _CircuitOpen(Exception):
        """Sentinel so ``except _CircuitOpen`` stays harmless when purgatory is
        unavailable (the no-op breaker below never raises it)."""


class _NullBreaker:
    """No-op async circuit breaker used when purgatory isn't installed.

    Keeps ``async with self._breaker:`` working unchanged — triage just runs
    without the CB (retries + rate-limiting still apply)."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


from dataclasses import dataclass, field
from typing import Optional, Callable, Any

from services.ai_triage.engine import TriageEngine

logger = structlog.get_logger()


class RateLimitedError(Exception):
    """Provider returned 429 (or equivalent).

    Distinct from generic failure on purpose so the circuit breaker can
    EXCLUDE it (`exclude=[RateLimitedError]`): a 429 means "you're sending
    too fast", not "the provider is broken". We back off and retry without
    counting it toward the breaker's failure threshold. Sustained 5xx /
    timeout / connection errors are what should trip the circuit.
    """


@dataclass
class BatchTriageConfig:
    batch_size: int = 5          # findings per concurrent batch
    max_concurrent: int = 10     # max parallel API calls
    rate_limit_rpm: int = 60     # max requests per minute
    max_retries: int = 3         # retries per finding
    retry_base_delay: float = 2.0  # exponential backoff base
    request_timeout: float = 120.0  # hard wall-clock timeout per LLM call (asyncio.wait_for)
    # Sprint B-1 — circuit breaker around outbound provider calls. Library-
    # grade (pybreaker) instead of the home-grown adaptive Semaphore swap.
    # The CB opens after N consecutive *non-429* failures and fails fast
    # for `reset_timeout` seconds, then half-opens to probe recovery.
    circuit_breaker_fail_max: int = 5
    circuit_breaker_reset_timeout: float = 60.0


@dataclass
class TriageResult:
    finding_id: str
    success: bool
    result: Optional[dict] = None
    error: Optional[str] = None
    retries: int = 0
    latency_ms: float = 0


class BatchTriageProcessor:
    """
    Processes a batch of findings through the AI triage engine concurrently.

    Resilience design (Sprint B-1):
      - FIXED concurrency via `asyncio.Semaphore(max_concurrent)` — never
        reassigned mid-flight (the old `Semaphore(1)` swap deadlocked).
      - FIXED rate limiting via token bucket — same reason.
      - Per-call `asyncio.wait_for(..., request_timeout)` so any single
        provider call CANNOT hang forever, regardless of upstream behavior.
      - **Circuit breaker (pybreaker)** around every provider call. Opens
        after N consecutive non-429 failures (5xx / timeout / connection)
        and fails subsequent calls fast with `CircuitBreakerError` for
        `reset_timeout` seconds, then half-opens to probe recovery. 429s
        are EXCLUDED from the breaker (they're "slow down", not "broken")
        and follow the existing retry-with-exponential-backoff path.
      - Partial failure tolerance: failed findings return failed
        TriageResult; remaining findings continue.

    What this kills: a stuck call no longer wedges a single shared slot
    forever; sustained provider outage trips the breaker instead of
    burning hours of retries; the batch terminates with honest per-finding
    success/failure counts.
    """

    def __init__(
        self,
        engine: TriageEngine,
        config: Optional[BatchTriageConfig] = None,
    ):
        self.engine = engine
        self.config = config or BatchTriageConfig()
        # FIXED — never reassigned during the run (the deadlock-source).
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent)
        self._rate_limiter = _TokenBucket(self.config.rate_limit_rpm)
        # Sprint B-1 — library-grade async-native circuit breaker.
        # purgatory's factory creates named breakers on demand; we keep the
        # factory here and lazily fetch the named breaker on first
        # process_batch entry (factory.get_breaker is async). 429s
        # (translated to RateLimitedError) are excluded so they back off
        # and retry instead of tripping the CB.
        if _HAS_PURGATORY:
            self._breaker_factory = purgatory.AsyncCircuitBreakerFactory(
                default_threshold=self.config.circuit_breaker_fail_max,
                default_ttl=self.config.circuit_breaker_reset_timeout,
                exclude=[RateLimitedError],
            )
        else:
            self._breaker_factory = None
            logger.warning(
                "ai_triage_circuit_breaker_disabled",
                reason="purgatory not installed — running triage without the CB",
            )
        self._breaker = None  # populated lazily in process_batch

    async def process_batch(
        self,
        findings: list[dict],
        code_contexts: dict[str, dict],
        repo_context: dict,
        on_progress: Optional[Callable[[int, int], Any]] = None,
    ) -> list[TriageResult]:
        """
        Process all findings concurrently with rate limiting.

        Args:
            findings: List of finding data dicts (with 'id' key)
            code_contexts: Mapping of finding_id -> code context dict
            repo_context: Shared repository context
            on_progress: Optional callback(completed, total) for progress tracking

        Returns:
            List of TriageResult for each finding
        """
        total = len(findings)
        completed = 0
        results: list[TriageResult] = []

        # Sprint B-1 — fetch the circuit breaker from the factory once per
        # batch run.  Cached after first call within the same process.
        if self._breaker is None:
            self._breaker = (
                await self._breaker_factory.get_breaker("ai_triage_provider")
                if self._breaker_factory is not None
                else _NullBreaker()
            )

        logger.info("batch_triage_start", total=total, batch_size=self.config.batch_size)

        # Process in batches to control memory and provide progress updates
        for batch_start in range(0, total, self.config.batch_size):
            batch = findings[batch_start:batch_start + self.config.batch_size]

            tasks = [
                self._process_single(
                    finding=f,
                    code_context=code_contexts.get(f.get("id", ""), {}),
                    repo_context=repo_context,
                )
                for f in batch
            ]

            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    finding_id = batch[i].get("id", f"unknown-{batch_start + i}")
                    results.append(TriageResult(
                        finding_id=finding_id,
                        success=False,
                        error=str(result)[:500],
                    ))
                    logger.error("batch_triage_exception", finding_id=finding_id, error=str(result)[:200])
                else:
                    results.append(result)

                completed += 1
                if on_progress:
                    try:
                        await on_progress(completed, total) if asyncio.iscoroutinefunction(on_progress) else on_progress(completed, total)
                    except Exception:
                        pass

        succeeded = sum(1 for r in results if r.success)
        failed = sum(1 for r in results if not r.success)
        avg_latency = sum(r.latency_ms for r in results if r.success) / max(succeeded, 1)

        logger.info(
            "batch_triage_complete",
            total=total,
            succeeded=succeeded,
            failed=failed,
            avg_latency_ms=round(avg_latency),
        )

        return results

    async def _process_single(
        self,
        finding: dict,
        code_context: dict,
        repo_context: dict,
    ) -> TriageResult:
        """Process a single finding through the rate limiter, the FIXED
        concurrency semaphore, and the circuit breaker (Sprint B-1).

        Flow:
          1. Acquire rate-limit token (FIXED rpm).
          2. Acquire a slot in the FIXED max_concurrent semaphore.
          3. Call the provider through the circuit breaker. If the CB is
             OPEN it raises CircuitBreakerError → fail fast, do not retry.
          4. 429 → RateLimitedError → CB-excluded → exponential backoff +
             retry up to max_retries.
          5. 5xx / timeout / connection / other → CB counts it. Retry with
             exponential backoff up to max_retries.
          6. After exhausting retries → return a failed TriageResult.

        `_call_provider` enforces `asyncio.wait_for(request_timeout)` on
        every call so a stuck provider CANNOT wedge a slot forever (the
        previous code's `Semaphore(1)` swap let a single hung call freeze
        the whole batch for the Celery hard time-limit).
        """
        finding_id = finding.get("id", "unknown")
        retries = 0

        while retries <= self.config.max_retries:
            try:
                # 1) rate-limit token
                await self._rate_limiter.acquire()
                # 2) concurrency slot (FIXED — never reassigned)
                async with self._semaphore:
                    start = time.monotonic()
                    # 3) call THROUGH the circuit breaker (async context
                    #    manager).  If the CB is open, entering the context
                    #    raises _CircuitOpen — fail fast, do not retry.
                    async with self._breaker:
                        result = await self._call_provider(
                            finding, code_context, repo_context,
                        )
                    latency = (time.monotonic() - start) * 1000
                    return TriageResult(
                        finding_id=finding_id,
                        success=True,
                        result=result,
                        retries=retries,
                        latency_ms=latency,
                    )

            except _CircuitOpen as _co:
                # CB is OPEN — provider is failing repeatedly. Fail this
                # finding fast instead of burning retries against a
                # dependency that's already known to be broken.
                logger.warning(
                    "triage_circuit_open",
                    finding_id=finding_id,
                    breaker_name=str(_co)[:120],
                )
                return TriageResult(
                    finding_id=finding_id,
                    success=False,
                    error="circuit_breaker_open",
                    retries=retries,
                )

            except RateLimitedError as e:
                # 429 — excluded from CB. Back off + retry.
                retries += 1
                if retries <= self.config.max_retries:
                    delay = min(10.0 * (2 ** (retries - 1)), 60.0)
                    logger.warning(
                        "triage_rate_limited_retry",
                        finding_id=finding_id,
                        retry=retries,
                        delay=delay,
                        error=str(e)[:200],
                    )
                    await asyncio.sleep(delay)
                    continue
                logger.error(
                    "triage_rate_limited_exhausted",
                    finding_id=finding_id,
                    retries=retries,
                )
                return TriageResult(
                    finding_id=finding_id,
                    success=False,
                    error=f"rate_limited_exhausted: {str(e)[:300]}",
                    retries=retries,
                )

            except Exception as e:
                # Non-429 error — CB has counted it. Retry if budget left.
                retries += 1
                error_msg = str(e)
                if retries <= self.config.max_retries:
                    delay = min(self.config.retry_base_delay * (2 ** (retries - 1)), 60.0)
                    logger.warning(
                        "triage_retry",
                        finding_id=finding_id,
                        retry=retries,
                        delay=delay,
                        error=error_msg[:200],
                    )
                    await asyncio.sleep(delay)
                    continue
                logger.error(
                    "triage_exhausted_retries",
                    finding_id=finding_id,
                    retries=retries,
                    error=error_msg[:200],
                )
                return TriageResult(
                    finding_id=finding_id,
                    success=False,
                    error=error_msg[:500],
                    retries=retries,
                )

        # Defensive — loop guard above should always return first.
        return TriageResult(
            finding_id=finding_id, success=False, error="exhausted_retries", retries=retries,
        )

    async def _call_provider(
        self,
        finding: dict,
        code_context: dict,
        repo_context: dict,
    ) -> Any:
        """Provider call wrapped for the circuit breaker (Sprint B-1).

        Two responsibilities:
          * Enforce `asyncio.wait_for(request_timeout)` so the call cannot
            hang regardless of upstream behavior.
          * Translate 429-like responses into ``RateLimitedError`` so the
            CB excludes them — a 429 is "slow down", not "provider broken".
        All other exceptions (timeout, connection error, 5xx) propagate
        unchanged and count toward the CB's failure threshold.
        """
        try:
            return await asyncio.wait_for(
                self.engine.triage_finding(finding, code_context, repo_context),
                timeout=self.config.request_timeout,
            )
        except (asyncio.TimeoutError, TimeoutError):
            raise
        except Exception as e:
            msg = str(e)
            low = msg.lower()
            if "429" in msg or "too many requests" in low or "rate limit" in low:
                raise RateLimitedError(msg) from e
            raise


class _TokenBucket:
    """Simple token bucket rate limiter for API calls."""

    def __init__(self, rate_per_minute: int):
        self.rate = rate_per_minute
        self.interval = 60.0 / max(rate_per_minute, 1)
        self._last_time = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            wait = self.interval - (now - self._last_time)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_time = time.monotonic()
