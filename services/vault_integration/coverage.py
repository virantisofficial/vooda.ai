# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Vault coverage — which leaked credentials are already vault-managed.

This replaces the previous ``drift_detector``, which promised something
it could not deliver.  Drift means "the value in code differs from the
value in the vault", and answering that requires both plaintexts.
Vooda deliberately stores only a SHA-256 hash of a secret, never the
value, so a true drift comparison is impossible by construction — and
making it possible would turn the findings database into a secret
store, which is the opposite of what this product is for.  The old
module acknowledged as much in its own comments and hardcoded
``is_drifted=False`` on every path that found a secret.

What we *can* answer, truthfully and usefully, is coverage:

    You have N leaked credentials.  M of them already exist in your
    vault, so the leak is a stale copy of a managed secret.  The other
    N-M exist nowhere but your source code.

That distinction changes the remediation. A covered secret needs the
code reference removed and the credential rotated. An uncovered one
needs to be put under management first, which is what
``services.vault_integration.migration`` generates the steps for.

Matching is by path, not value. We look for a vault entry whose name
plausibly corresponds to the finding, and report how confident that
match is rather than pretending to certainty we do not have.
"""

import re
import structlog
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional

logger = structlog.get_logger()


class CoverageStatus(str, Enum):
    #: A vault entry matches this credential by name or explicit path.
    COVERED = "covered"
    #: The vault was reachable and holds nothing resembling this credential.
    UNCOVERED = "uncovered"
    #: The vault could not be listed, so coverage is genuinely unknown.
    #: Deliberately distinct from UNCOVERED — reporting a connection
    #: failure as "not in your vault" would be a false all-clear in the
    #: wrong direction.
    UNKNOWN = "unknown"


@dataclass
class CoverageResult:
    incident_id: str
    title: str
    secret_type: Optional[str]
    status: CoverageStatus
    vault_path: Optional[str] = None
    confidence: float = 0.0
    detail: str = ""
    candidates: list[str] = field(default_factory=list)


def _normalize(text: str) -> str:
    """Reduce a name to comparable tokens.

    ``STRIPE_API_KEY``, ``stripe-api-key`` and ``prod/stripe/api_key``
    all normalize to ``stripe api key``.
    """
    return " ".join(t for t in re.split(r"[^a-z0-9]+", text.lower()) if t)


#: Words that appear in almost every secret name and so carry no
#: signal. Leaving them in makes unrelated entries look alike.
_STOPWORDS = {
    "key", "secret", "token", "api", "prod", "production", "value",
    "staging", "dev", "credential", "credentials", "password", "pwd",
}

#: File extensions and path fragments that come from the finding's
#: location rather than the credential's identity.
_PATH_NOISE = {
    "py", "js", "ts", "tsx", "jsx", "go", "rb", "java", "php", "yml",
    "yaml", "json", "env", "cfg", "conf", "ini", "toml", "sh", "tf",
    "src", "lib", "app", "config", "configs", "settings",
}


def _identity_tokens(text: str) -> set[str]:
    """Tokens that identify *which credential* this is.

    A finding title looks like ``src/app.py: STRIPE_API_KEY`` — the part
    before the colon is where it leaked, which says nothing about which
    secret it is. Matching on the whole string let path noise dominate:
    ``src/app.py: STRIPE_API_KEY`` against ``prod/stripe/api_key``
    scored 0.25 and was reported uncovered, when they are plainly the
    same credential.
    """
    if ":" in text:
        text = text.rsplit(":", 1)[-1]
    return set(_normalize(text).split()) - _STOPWORDS - _PATH_NOISE


def _score(finding_name: str, vault_path: str) -> float:
    """Overlap coefficient of the identifying tokens, 0.0–1.0.

    Overlap (``|A∩B| / min(|A|,|B|)``) rather than Jaccard, because the
    two sides are asymmetric by nature: a vault path carries
    organisational structure (``prod/team/stripe/api_key``) that a
    variable name does not. Jaccard punishes that extra context even
    when every token of the shorter name matches.
    """
    a, b = _identity_tokens(finding_name), _identity_tokens(vault_path)
    if not a or not b:
        return 0.0
    return len(a & b) / min(len(a), len(b))


#: Below this, a match is too weak to claim. Reported alongside every
#: result as `confidence`, and near-misses are returned as `candidates`,
#: so a wrong call here is visible rather than silent.
MATCH_THRESHOLD = 0.6


async def check_coverage(
    incidents: Iterable[dict],
    vault_provider,
    explicit_paths: Optional[dict[str, str]] = None,
) -> list[CoverageResult]:
    """Report which incidents correspond to secrets already in the vault.

    Args:
        incidents: dicts with ``id``, ``title`` and optionally
            ``secret_type`` — the shape ``SecretIncident`` rows provide.
        vault_provider: a ``VaultProviderBase`` instance.
        explicit_paths: optional incident-id -> vault-path overrides,
            for credentials a user has already mapped by hand. An
            explicit mapping is authoritative and skips fuzzy matching.

    Returns one result per incident. A vault that cannot be listed
    yields UNKNOWN for every incident rather than a misleading
    UNCOVERED.
    """
    incidents = list(incidents)
    explicit_paths = explicit_paths or {}

    try:
        vault_secrets = await vault_provider.list_secrets()
    except Exception as e:
        logger.error("vault_coverage_list_failed", error=str(e)[:200])
        vault_secrets = None

    if vault_secrets is None:
        return [
            CoverageResult(
                incident_id=str(i.get("id", "")),
                title=i.get("title", ""),
                secret_type=i.get("secret_type"),
                status=CoverageStatus.UNKNOWN,
                detail="Vault could not be listed — coverage is unknown, not clear.",
            )
            for i in incidents
        ]

    paths = [s.path for s in vault_secrets]
    results: list[CoverageResult] = []

    for inc in incidents:
        iid = str(inc.get("id", ""))
        title = inc.get("title", "") or ""

        explicit = explicit_paths.get(iid)
        if explicit:
            present = explicit in paths
            results.append(
                CoverageResult(
                    incident_id=iid,
                    title=title,
                    secret_type=inc.get("secret_type"),
                    status=CoverageStatus.COVERED if present else CoverageStatus.UNCOVERED,
                    vault_path=explicit if present else None,
                    confidence=1.0 if present else 0.0,
                    detail=(
                        f"Mapped to {explicit}."
                        if present
                        else f"Mapped to {explicit}, but no such path exists in the vault."
                    ),
                )
            )
            continue

        scored = sorted(
            ((p, _score(title, p)) for p in paths), key=lambda x: x[1], reverse=True
        )
        best_path, best = scored[0] if scored else (None, 0.0)

        if best >= MATCH_THRESHOLD:
            results.append(
                CoverageResult(
                    incident_id=iid,
                    title=title,
                    secret_type=inc.get("secret_type"),
                    status=CoverageStatus.COVERED,
                    vault_path=best_path,
                    confidence=round(best, 2),
                    detail=(
                        f"Name matches vault entry {best_path}. Rotate the "
                        f"credential and remove the hardcoded copy."
                    ),
                    candidates=[p for p, s in scored[:3] if s > 0],
                )
            )
        else:
            results.append(
                CoverageResult(
                    incident_id=iid,
                    title=title,
                    secret_type=inc.get("secret_type"),
                    status=CoverageStatus.UNCOVERED,
                    confidence=round(best, 2),
                    detail="No matching vault entry — this credential is not under management.",
                    candidates=[p for p, s in scored[:3] if s > 0],
                )
            )

    counts = {s: sum(1 for r in results if r.status is s) for s in CoverageStatus}
    logger.info(
        "vault_coverage_complete",
        total=len(results),
        covered=counts[CoverageStatus.COVERED],
        uncovered=counts[CoverageStatus.UNCOVERED],
        unknown=counts[CoverageStatus.UNKNOWN],
    )
    return results
