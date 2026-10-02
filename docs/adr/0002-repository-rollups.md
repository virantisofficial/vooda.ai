# ADR 0002 — Repository rollups, recomputed not incremented

- **Status:** proposed
- **Date:** 2026-10-02
- **Affects:** `GET /repositories`, the repositories list view, `GET /{id}/stats`

## Context

Painting one page of the repositories list costs **101 HTTP requests**.

The list endpoint returns the repository rows. Everything the table
actually shows about posture — secret count, critical count, last scan,
risk badge, sparkline — is fetched per row, two calls at a time
([page.tsx:701](../../apps/web/src/app/repositories/page.tsx)):

```js
items.forEach((repo) => {
  getRepoStats(repo.id)          // 1 request
  getRepoSeverityTrend(repo.id)  // 1 request
})
```

At the default page size of 50 that is 1 + 100. Each `stats` call runs
its own `COUNT(*)` and `GROUP BY severity` over `normalized_findings`
for a single repository.

Three consequences follow from the same root:

**Sorting is wrong above one page.** Sorting by Secrets, Critical or
Last Scan happens in the browser, over the rows already loaded, because
those values do not exist until the per-row calls land. Below 50
repositories it is correct; above, it orders the page rather than the
list.

**Filtering had the same defect** and was worse, because it hid rows
instead of misordering them. Risk level and scan status now filter
server-side via correlated subqueries. That fixed the correctness
problem and reduced request volume — a filtered list returns fewer rows,
so fewer per-row calls fire — but it computes counts that the `stats`
calls then compute again moments later.

**The counts cannot be used anywhere else.** No report, export or API
consumer can ask "which repositories are critical" without replaying the
same N queries.

The precedent for the fix is already in the codebase.
`SecretIncident.occurrence_count` is a denormalised counter, and
[tasks.py:517](../../apps/worker/tasks.py) states the rule it follows:

> In-loop increments would double-count on the update path, so the count
> is recomputed from the rows — which is idempotent under re-import /
> task redelivery.

## Decision

Add rollup columns to `repositories`, maintained by **authoritative
recompute**, never by increment.

```
total_findings     integer  not null default 0
open_criticals     integer  not null default 0
open_highs         integer  not null default 0
last_scan_at       timestamptz
last_scan_status   varchar(20)
rollups_at         timestamptz   -- when the recompute last ran
```

`rollups_at` is not decoration. It is how a reconciler finds rows that
drifted, and how support answers "is this number stale or wrong?".

### One function, called from the paths that change the population

```python
async def refresh_repository_rollups(db, repository_ids) -> None
```

A single `GROUP BY repository_id` over the findings of those repositories,
written back in one `UPDATE … FROM (VALUES …)`. Idempotent, so a retried
Celery task or a redelivered webhook cannot corrupt it.

Call sites — the complete set, from tracing every write that changes
which findings belong to a repository:

| Path | Where |
|---|---|
| Scan ingest (git) | `tasks.py` ~5007 |
| Scan ingest (source) | `tasks.py` ~2172, ~2804 |
| Scanner import | `tasks.py` ~471 |
| AI triage apply | `tasks.py` ~7464 |
| Scan delete | `repositories.py` `delete_scan` |
| Repository delete | `repositories.py` `delete_repository` |
| Triage / bulk triage | `findings.py` `triage_finding`, `bulk_triage_findings` |
| Orphan sweep on source delete | `scan_sources.py` ~672 |

### The decision that sets the size of this change

**Do the counts include closed findings?**

`GET /{id}/stats` counts every finding regardless of status, and the
Critical column prints that number. So a repository where every critical
has been dismissed as a false positive still reads **Critical**.

The two options are not the same amount of work:

| | Meaning | Write paths |
|---|---|---|
| **Count everything** | "has ever contained" | 2 — ingest and delete |
| **Count open only** | "is exposed now" | 8 — every triage path above |

Counting only open findings is the right number: the column is read as
current exposure, and triage exists to change it. The cost is that
triage becomes a write path for the rollup, which is why the recompute
must be by `COUNT(*)` and not by decrementing on each action — twenty
findings bulk-dismissed in one request is one recompute, not twenty
decrements that must each be correct.

This ADR proposes **open only**, and treats the change in what the
Critical column means as the point of the exercise rather than a
side effect. It is a visible behaviour change and belongs in release
notes.

### Backfill

The migration computes all rollups in one statement. At present scale
(11 repositories, 36 findings) it is instant; it stays a single
aggregate regardless.

### Reconciliation

The rollups are a cache, and a cache that nothing checks is a cache that
is eventually wrong. A nightly beat task recomputes every repository
whose `rollups_at` is older than 24h and logs any row whose stored value
disagreed with the recomputed one. A disagreement is a bug report, not a
routine correction — if the log is never empty, a write path is missing
from the table above.

Drift is a display defect, not a data-loss one: the findings themselves
remain the source of truth, and a recompute restores the number.

## Consequences

**101 requests become 2.** The list payload carries the counts; the
sparkline still needs its own data, because a 30-day daily series is not
a counter and cannot be a column. It becomes one batch call
(`GET /repositories/trends?ids=…`) instead of fifty.

**Server-side sorting becomes free.** `ORDER BY open_criticals DESC` is
a column sort. No join, no aggregate, no extra cost on the unfiltered
default load — which is the reason not to implement server-side sorting
before this lands: without the columns it means aggregating the whole
findings table on every list request, including the one everybody hits.

**The risk filter stops needing correlated subqueries.** It becomes
`WHERE open_criticals > 0`.

**`GET /{id}/stats` stays.** The detail page needs the full severity
breakdown; only the list stops calling it per row.

**A new way to be wrong.** Today the numbers are recomputed on every
read and cannot be stale. After this they can. That is the trade being
made, and the reconciler plus `rollups_at` is the price of making it
safely.

## Alternatives considered

**Database triggers.** Rejected: the codebase maintains
`occurrence_count` in application code, and a trigger would be the only
one in the schema — invisible to anyone reading the Python, and
untestable with the existing suite.

**Increment and decrement on each write.** Rejected for the reason
already written down at `tasks.py:517` — not idempotent, and Celery
redelivers.

**A materialised view.** Rejected: refresh is all-or-nothing and the
staleness window is harder to reason about than a per-row
`rollups_at`.

**Leave it alone.** Defensible until the repository count passes one
page. Below 50 repositories the sort is correct, the filter is now
correct, and 101 requests on a page nobody reloads constantly is
survivable. This ADR is worth executing when repository counts grow, or
when the counts are wanted somewhere other than this one screen.

## Unresolved

Whether `GET /{id}/stats` should also switch to open-only counts. It
feeds the detail page, where the full history may be the more useful
number. Leaving the two endpoints with different definitions is how the
current confusion started, so this needs deciding before the rollups
ship, not after.
