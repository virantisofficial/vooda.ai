# Vooda in CI/CD — distribution & integration

This directory holds everything needed to run Vooda's secret scanner inside
any CI/CD system at enterprise scale. The model is **fat client, light
platform**: each pipeline scans its own checked-out code with the bundled
engine and pushes only **masked** findings to a (self-hosted) Vooda, which
aggregates, dedupes, applies policy, and stores history. Scan compute
distributes across the CI fleet — so it scales to 100k repos without the
platform cloning anything.

```
  ┌─ dev laptop ──┐   ┌─ PR pipeline ─┐   ┌─ main / nightly ─┐
  │ pre-commit    │   │ vooda monitor │   │ vooda monitor    │
  │ (push-protect)│   │ --diff (gate) │   │ --history (full) │
  └──────┬────────┘   └──────┬────────┘   └──────┬───────────┘
         └───────────── masked findings ─────────┘
                              │  POST /api/v1/imports/scan  (findings:import)
                       ┌──────▼───────────────────────┐
                       │  Vooda platform (self-hosted) │  dedupe · policy ·
                       │  api + worker + worker-scans   │  incidents · history
                       └───────────────────────────────┘
```

## 1. The CLI image

The canonical distribution unit is a Docker image — every CI runner can run
containers, it carries the engine + all 946 rules, and it needs **no server
credentials** (only an import key). Build it from the repo root:

```bash
docker build -f infra/docker/Dockerfile.cli -t vooda/cli:1.0.0 .

# smoke test
docker run --rm vooda/cli:1.0.0 --help
```

Run a scan locally:

```bash
docker run --rm \
  -e VOODA_SERVER=https://vooda.acme.com \
  -e VOODA_API_KEY=$VOODA_API_KEY \      # findings:import scope only
  -v "$PWD:/work" -w /work \
  vooda/cli:1.0.0 monitor --wait --fail-on high
```

### Performance — intra-scan parallelism

On a dedicated CI runner, `vooda scan` / `vooda monitor` automatically use
**all the runner's cores** for a single large scan (a process pool — one
worker per core, each with its own compiled rule pack). Measured ~2–2.9×
faster on multi-core boxes; small repos and unsupported contexts transparently
fall back to a sequential scan with **identical** results.

| Env var | Default | Effect |
|---|---|---|
| `VOODA_SCAN_WORKERS` | `min(8, cpu_count)` (cap 16) | Process-pool size. Set `1` to force sequential. |
| `VOODA_SCAN_PARALLEL_MIN_FILES` | `400` | Repos smaller than this scan sequentially (pool startup isn't worth it). |

This is intra-*scan* parallelism (one big scan, many cores). It's distinct
from cross-*scan* parallelism — thousands of pipelines each scanning their own
repo — which needs no tuning and is the primary enterprise scaling lever.

### Publish + supply-chain hardening

Your secret scanner's own image must be clean. After building:

```bash
# Publish to your registry (GHCR shown; ECR/ACR/GAR/Artifactory all work)
docker tag vooda/cli:1.0.0 ghcr.io/<org>/vooda-cli:1.0.0
docker push           ghcr.io/<org>/vooda-cli:1.0.0

# Sign + attest (recommended)
cosign sign            ghcr.io/<org>/vooda-cli:1.0.0
syft  ghcr.io/<org>/vooda-cli:1.0.0 -o spdx-json > vooda-cli.sbom.json
cosign attest --predicate vooda-cli.sbom.json --type spdxjson ghcr.io/<org>/vooda-cli:1.0.0
```

Pin consumers to a **digest** (`@sha256:…`), not a moving tag.

### Air-gapped / regulated networks (banks, defense, gov)

Mirror the image into your internal registry and point CI at it — no public
egress, no SaaS:

```bash
skopeo copy docker://vooda/cli:1.0.0 docker://registry.internal.acme.com/vooda/cli:1.0.0
```

Then set the GitHub Action `image:` input (or the GitLab `image.name`) to the
internal ref. The CLI refuses to send the API key over plaintext http to a
*public* host, but allows internal/private/loopback hosts over http, so an
on-prem Vooda on a private network works without TLS gymnastics.

## 2. CI integration

| Platform | Asset |
|---|---|
| GitHub Actions | `github-action/action.yml` (reusable) + `github-action/example-workflow.yml` |
| GitLab CI | `gitlab/vooda.gitlab-ci.yml` |
| Jenkins / Azure DevOps / CircleCI | run the image directly (see the local-run command above) |

The recommended topology:

- **Pre-commit** (laptop): the push-protection hook (`cli/install-hook.sh`).
- **PR check**: `vooda monitor --diff origin/main..HEAD --fail-on high` — fast,
  diff-only, blocks the merge.
- **main merge / nightly**: `vooda monitor --history` — full coverage.

Big orgs should standardize via **one golden template** owned by the platform
team and consumed by every repo, not per-repo copy-paste.

## 3. Auth

Provision an API key with **only** the `findings:import` scope (Settings → API
Keys). It is write-only: it can import findings for already-onboarded repos and
read the status of its own imports — it cannot read findings, browse other
repositories, or change configuration. **Never** give a CI key `admin`.

> Roadmap: OIDC federation (GitHub/GitLab ID token → short-lived scoped Vooda
> token) so no long-lived secret sits on the runner — the keyless end-state.

## 4. What the runner sends (WS-6)

Only `masked_value` + a one-way `secret_hash` + provenance leave the machine;
the raw secret is redacted by the same scanner the server uses before it is
ever transmitted. Findings dedupe against server-side scans of the same secret
by a path-relative stability id, so a CLI finding and a platform scan collapse
to one incident.
