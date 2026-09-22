# ADR 0001 — One vocabulary per state axis, enforced by the database

- **Status:** accepted
- **Date:** 2026-09-22
- **Supersedes:** the `Classification` enum as the primary triage field

## Context

Vooda tracked four state axes — triage, credential validity, severity,
and scan status. Every one had the same shape of defect: a typed enum
existed, and a parallel unconstrained `String` column sat beside it,
so the database accepted values the enum forbade.

The triage axis was the worst of it. `classification` had grown to
**thirteen** values because it was answering four different questions at
once:

| Question | Belongs in | Was encoded as |
|---|---|---|
| Is this a real exposure? | the status | the value |
| How sure are we? | `ai_confidence` | the `LIKELY_` prefix |
| Who decided? | `classification_provenance` | the `CONFIRMED_` prefix |
| Why did it close? | a resolution reason | more values |

Fusing them meant every new reason *multiplied* the enum instead of
adding a row. Four `RESOLVED_*` values existed that differed only in
what kind of thing had disappeared — a file, an item, a repository, a
source.

Five modules then hand-rolled their own subsets of that enum, and they
disagreed. The clearest contradiction: `LIKELY_FALSE_POSITIVE` counted
as **closed** in the metrics router and as **undecided** in the
occurrence propagator. That value covered roughly 90% of all findings.
The dashboard was reporting them settled while the engine that fans
verdicts out treated them as open work.

Credential validity was in similar shape: eight spellings of five states
(`validation_error` vs `error`; `not_validated` vs `unverified` vs
`unknown` vs NULL), produced by two independent engines, in a column
with no enum and no constraint — and on findings it lived inside a JSONB
blob where nothing could constrain it at all.

## Decision

**One owner per axis, and the database enforces it.**

```
status             open · triaging · resolved · dismissed          (4)
resolution_reason  rotated · revoked · provider_disabled ·         (8)
                   false_positive · test_credential ·
                   acceptable_risk · mitigating_control ·
                   no_longer_present
ai_verdict         likely_tp · likely_fp · unsure   (advisory)     (3)
validity           active · inactive · unknown ·                   (5)
                   unsupported · check_failed
severity           critical · high · medium · low · info           (5)
```

Plus `resolved_by`, `resolved_at`, `resolution_note` for the audit
trail.

Four principles fall out of this:

**1. Only a decision closes a finding.** An AI verdict annotates an open
one. Confidence lives in `ai_confidence`, provenance in
`classification_provenance`; neither belongs in a status name. The UI
labels these as opinions — "Open — AI: likely not a secret", never
"False Positive".

**2. Closing requires a reason, enforced by a CHECK constraint.** Not
by convention. The *why* is the one thing an auditor always asks for.

**3. A reason cannot cross statuses.** A rotated credential is
`resolved`; a false positive is `dismissed`. Crossing them would make
MTTR and compliance reporting meaningless.

**4. Losing visibility is not remediation.** `no_longer_present` is a
*dismissal* reason, never a resolution, and is excluded from MTTR.
Deleting a repository must never read as an instant fix — the
credential survives in every clone and every commit that carried it.

The vocabularies were chosen so every incumbent maps in without loss
(GitHub Advanced Security, GitGuardian, GitLab), because a customer
migrating must not lose triage history at the door.

## Consequences

**The dashboard headline moved from 208 to 1,889 open findings.** That
is the correct number: 1,681 of them are AI verdicts nobody reviewed.
To keep the view usable without lying, the API reports
`open_needs_attention` alongside `open_ai_low_risk` and the UI collapses
the latter by default. Noise reduction became a *view*, not a *state*.

**Two representations are live at once.** `classification` is still
written alongside the new columns so reads could migrate before writes.
Retiring it is deliberately deferred — see *Unresolved* below.

**Structural guards replace vigilance.** Adding a `Classification` value
without placing it in exactly one of `CLOSED`/`OPEN` raises at import
time. Tests fail if any module reintroduces an inline vocabulary, and
each migration's SQL `CASE` is parsed and asserted to agree with the
runtime normaliser, so rows written before and after cannot come to mean
different things.

## What this caught

Consolidation surfaced defects that had been invisible because each
module was self-consistent:

- SLA reports counted **rotated** secrets as overdue forever.
- Compliance reports iterated 6 of 13 classifications, so
  `by_classification` never summed to `total_findings`.
- The verifier donut bucketed on `pending` and `not_validated` — values
  no code path produced, so two segments always read zero.
- A parallel validation engine, 831 lines, was instantiated and never
  called; its validators reached the network outside the egress guard.
- Routing a close through the legacy enum silently rewrote the
  operator's choice (`mitigating_control` stored as `acceptable_risk`)
  and returned 200.

Two lessons generalise. **An ORM-level guard cannot see a Core
`UPDATE`** — that blind spot drifted 26 findings, and later 173
incidents, after the first fix. And **a `CHECK` constraint passes when
its expression evaluates to NULL**, so `reason IN (...)` without an
explicit `IS NOT NULL` guard let `dismissed` with no reason through the
constraint written to forbid exactly that.

## Alternatives considered

**Keep one enum, add values as needed.** Rejected: it is what produced
thirteen values and four near-identical `RESOLVED_*` entries. The growth
is structural, not incidental.

**More statuses, on the assumption enterprises need more granularity.**
Rejected, and it is the opposite of what the market does. GitHub ships
**two** states plus a required resolution; GitGuardian and GitLab ship
four plus a reason enum. Every extra state is a mapping decision when a
customer pipes findings into Jira, ServiceNow or Security Hub — a
liability in a security review, not a feature.

**Drop `classification` immediately.** Rejected: dual-write lets reads
migrate before writes, and the deletion is one-way.

## Unresolved

Retiring `classification`, `review_status`, `rotation_status` and
`remediation_status` (~600 references) is deliberately not done. The
dual-write costs little, and the legacy values cannot be reconstructed
once dropped — `acceptable_risk` and `mitigating_control` are
indistinguishable looking backwards. It should run through at least one
real release first. The deprecated `?classification=` API filter needs
its own deprecation decision.
