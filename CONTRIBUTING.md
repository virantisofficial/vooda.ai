# Contributing to Vooda

Thanks for being here. Vooda is a secret-scanning platform, and the two things that make it good — **detection coverage** and **false-positive rate** — get better mostly through contributions from people who hit a real gap in their own repos.

If you found a secret Vooda missed, or got an alert it shouldn't have raised, that's the highest-value contribution you can make.

## Before you start

**A quick note on the CLA.** Vooda is source-available under the [Vooda Community Licence, Version 1.0](LICENSE.md), and Virantis also sells a commercial edition. That means we need the right to sublicense contributions — so we ask every contributor to sign a one-time [Contributor License Agreement](CLA.md). A bot will prompt you on your first PR; it takes about thirty seconds. You keep copyright in your work. We explain the reasoning honestly in [CLA.md](CLA.md) — please read it rather than clicking through blind.

**Please open an issue before starting anything substantial.** For a typo or a one-line fix, just send the PR. For a new detector, a refactor, or anything touching the scan engine, open an issue first so we can agree on the approach. We'd rather talk for ten minutes than have you spend a weekend on something we then have to turn down.

## Good first issues

We label approachable work [`good first issue`](../../issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22). These are real gaps, not busywork — each one names the file to change and what "done" looks like.

Also useful: [`help wanted`](../../issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) for things we'd genuinely like a hand with, and [`detector`](../../issues?q=is%3Aissue+is%3Aopen+label%3Adetector) for new or improved detection rules.

## Development setup

You need Docker and Docker Compose. Nothing else.

```bash
git clone https://github.com/virantisofficial/vooda.ai.git
cd vooda.ai
cp .env.example .env      # fill in POSTGRES_PASSWORD and SECRET_KEY
docker compose up -d
```

The API runs migrations on startup. Web UI on `http://localhost:3001`, API docs on `http://localhost:8001/api/docs`.

Running the tests:

```bash
docker compose exec api pytest                       # everything
docker compose exec api pytest tests/secret_scan/    # detector tests only
```

## Contributing a detector

This is the most common contribution, so here's the whole path.

Detectors live in `services/secret_scan/detectors/`. Each rule needs a pattern, a `secret_type`, keywords for pre-filtering, and a confidence score.

1. **Add the rule** in the appropriate module under `services/secret_scan/detectors/`. Group it with related providers rather than starting a new file.
2. **Add tests** in `tests/secret_scan/` — and this is the important part: include **both a true positive and a near-miss that must not match**. A rule without a negative test is a false-positive generator waiting to happen.
3. **Never commit a live credential.** Generate a syntactically valid but non-functional example. If your rule needs realistic entropy, use random characters — not a real key with a few digits changed, which often still verifies.
4. **Check the regex is re2-compatible** if you can. Most of the rule pack compiles under `google-re2`, which is immune to catastrophic backtracking. Lookahead and large repetitions fall back to the `regex` engine with a timeout — that works, but re2 is better.
5. **Say where the format is documented.** A link to the provider's docs in the PR makes review much faster.

### On test fixtures

This repository deliberately contains a corpus of planted, non-functional credentials under `tests/`. That is what a secret scanner's test suite is made of. Your scanner will alert on this repo — that's expected.

If you ever find a credential in here that is genuinely **live**, please don't open a public issue. Report it via [SECURITY.md](SECURITY.md).

## Pull requests

- **Branch from `main`.**
- **New files get the license header.** Every source file starts with the two-line SPDX header (`SPDX-FileCopyrightText: 2026 Virantis` + `SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0`) — copy it from any existing file. On Python it's `#` comments at the very top (after a shebang, if any); on TS/TSX it's `//` comments, placed just after a `"use client"`/`"use server"` directive when present. This keeps the license attached to the code if someone lifts a single file out of the repo.
- **Keep it focused.** One logical change. A PR that fixes a bug and reformats 400 lines is very hard to review, and it'll sit longer.
- **Write a real description.** What changed, why, and how you verified it. If it fixes an issue, say `Fixes #123`.
- **Tests pass**, and new behaviour has new tests.
- **Update docs** if you changed behaviour someone depends on.

We use [Conventional Commits](https://www.conventionalcommits.org/) for PR titles: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `perf:`, `chore:`. For detectors, `feat(detector): add Foo API key rule` is ideal.

## Review

A maintainer will review. We aim for a first response within a few days — if it's been longer than a week, please nudge us on the PR, you won't be bothering anyone.

We may ask for changes. That's normal and it isn't a judgement on your work; the scan engine is performance-sensitive and false positives are expensive for every user downstream, so detector changes get scrutinised more than most code.

## Reporting bugs and asking for features

- **Bugs** — use the bug template. A reproduction is worth more than a description.
- **Missed detection or false positive** — use the detection template. Include a **redacted** sample of the string, the file type, and what you expected.
- **Features** — use the feature template. Tell us the problem you're trying to solve, not just the solution you have in mind.
- **Vulnerabilities** — do not open an issue. See [SECURITY.md](SECURITY.md).
- **Questions** — [GitHub Discussions](../../discussions).

## Community

Everyone here is bound by our [Code of Conduct](CODE_OF_CONDUCT.md). Report concerns to **report@vooda.ai**.

Be decent to each other. Assume good faith. Remember the person on the other end may be doing this on their own time, in their third language, at the end of a long day.
