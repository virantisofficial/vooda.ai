# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Canonical vocabulary for "is this credential still live?".

This is the answer that separates Vooda from a regex scanner, and until
now it had no enum. Eight different strings were in flight for five
states, produced by two independent engines:

    worker  (services.secret_validation)  active inactive revoked
                                          unknown not_validated
                                          validation_error
    API     (services.secret_verification) active inactive error
                                           unsupported
    notifications dispatcher               unverified
    incidents engine                       not_validated
    database                               NULL

``validation_error`` and ``error`` are the same state spelled twice;
so are ``not_validated``, ``unverified``, ``unknown`` and NULL.

The five canonical values below are chosen so that every incumbent's
vocabulary maps in without loss — a customer migrating from GitHub
Advanced Security or GitGuardian must not lose validity history at the
door:

    GitHub       active -> ACTIVE      inactive -> INACTIVE
    GitGuardian  valid  -> ACTIVE      invalid  -> INACTIVE
                 failed_to_check -> CHECK_FAILED
                 no_checker      -> UNSUPPORTED
                 unknown         -> UNKNOWN
"""

import enum
from typing import Optional


class Validity(str, enum.Enum):
    #: The provider accepted the credential. It works right now.
    ACTIVE = "active"
    #: The provider rejected it — revoked, expired or deleted.
    INACTIVE = "inactive"
    #: Not checked yet, or the check was inconclusive.
    UNKNOWN = "unknown"
    #: No checker exists for this credential type. Distinct from
    #: UNKNOWN: this will not resolve by retrying.
    UNSUPPORTED = "unsupported"
    #: A checker ran and failed — network error, rate limit, egress
    #: block. Distinct from UNSUPPORTED: retrying may succeed.
    CHECK_FAILED = "check_failed"


#: Every legacy spelling, from both engines, the dispatcher and the DB.
#: Kept as data rather than branches so the migration and the runtime
#: normaliser cannot disagree.
_LEGACY: dict[str, Validity] = {
    "active": Validity.ACTIVE,
    "valid": Validity.ACTIVE,
    "inactive": Validity.INACTIVE,
    "invalid": Validity.INACTIVE,
    # A revoked credential is dead. The fact that it was *rotated* is
    # remediation state and lives on the finding, not here.
    "revoked": Validity.INACTIVE,
    "expired": Validity.INACTIVE,
    "unknown": Validity.UNKNOWN,
    "not_validated": Validity.UNKNOWN,
    "unverified": Validity.UNKNOWN,
    "pending": Validity.UNKNOWN,
    "unsupported": Validity.UNSUPPORTED,
    "no_checker": Validity.UNSUPPORTED,
    # The canonical value itself. Missing it meant normalize() sent
    # "check_failed" to UNKNOWN, so filtering the UI's "Check Failed"
    # option silently returned every not-checked finding instead.
    "check_failed": Validity.CHECK_FAILED,
    "error": Validity.CHECK_FAILED,
    "validation_error": Validity.CHECK_FAILED,
    "failed_to_check": Validity.CHECK_FAILED,
    "rate_limited": Validity.CHECK_FAILED,
}


def normalize(value: Optional[str]) -> Validity:
    """Map any legacy spelling (or NULL) onto the canonical vocabulary.

    Unrecognised input becomes UNKNOWN rather than raising: this runs on
    the read path over rows written by older code, and a validity we
    cannot interpret is exactly "we do not know".
    """
    if value is None:
        return Validity.UNKNOWN
    if isinstance(value, Validity):
        return value
    return _LEGACY.get(str(value).strip().lower(), Validity.UNKNOWN)


#: The only states that justify suppressing or de-prioritising a
#: finding on validity grounds. A credential the provider rejected is
#: dead; everything else is an absence of evidence, not evidence of
#: absence — CHECK_FAILED especially must never read as "safe".
PROVABLY_DEAD: tuple[Validity, ...] = (Validity.INACTIVE,)

#: States where we genuinely do not know. Never present these as safe.
INCONCLUSIVE: tuple[Validity, ...] = (
    Validity.UNKNOWN,
    Validity.UNSUPPORTED,
    Validity.CHECK_FAILED,
)


def _assert_total() -> None:
    covered = set(PROVABLY_DEAD) | set(INCONCLUSIVE) | {Validity.ACTIVE}
    missing = set(Validity) - covered
    if missing:
        raise RuntimeError(
            "validity: unplaced value(s): "
            f"{sorted(m.value for m in missing)} — decide whether each is "
            "provably dead, inconclusive, or active."
        )
    for legacy, target in _LEGACY.items():
        if not isinstance(target, Validity):
            raise RuntimeError(f"validity: bad legacy mapping for {legacy!r}")
    # Every canonical value must survive a round trip. Without this the
    # table can quietly omit one of its own values, and normalize()
    # then folds it into UNKNOWN — which is how the "Check Failed"
    # filter came to return every unchecked finding. The severity module
    # has carried this guard since it was written; this one did not.
    for value in Validity:
        if normalize(value.value) is not value:
            raise RuntimeError(
                f"validity: {value.value!r} does not map to itself — add "
                "it to _LEGACY."
            )


_assert_total()
