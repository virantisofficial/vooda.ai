# Deployment Guide — Coolify (or any docker-compose host)

This document describes how to deploy Vooda AI Security Engine to a
self-hosted environment using Coolify or any other Docker Compose
runner. The target is a clean machine with only Docker installed.

---

## TL;DR

```bash
git clone https://github.com/your-org/vooda-ai.git
cd vooda-ai

# 1. Create the env file (see "Required environment variables" below)
cp .env.example .env
# edit .env to set POSTGRES_PASSWORD, SECRET_KEY, ANTHROPIC_API_KEY,
# and your public hostname-based URLs

# 2. Build + start
docker compose up -d --build

# 3. Seed the default tenant + admin user (admin@vooda.ai).
#    Prints a one-time generated password to the console — copy it to log in,
#    or set SEED_ADMIN_PASSWORD in .env beforehand to choose your own.
docker compose exec api python -m infra.scripts.seed
```

The first run takes ~5 min (image build + Alembic + seed). Subsequent
deploys are ~30 s.

---

## Required environment variables

Set these in `.env` (next to `docker-compose.yml`) or via Coolify's
"Environment Variables" panel. Marked **required** entries cause the
deploy to fail-fast at compose-up time if missing.

| Variable | Required | Example | Notes |
|---|:-:|---|---|
| `POSTGRES_PASSWORD` | ✓ | `$(openssl rand -base64 32)` | Postgres superuser password. Used by db, api, worker, beat. |
| `SECRET_KEY`        | ✓ | `$(openssl rand -hex 32)`    | App-wide signing key for JWTs + OAuth state. ≥32 random bytes. |
| `ANTHROPIC_API_KEY` | (1) | `sk-ant-...`                | Required if `AI_PROVIDER=claude` (the default). |
| `OPENAI_API_KEY`    | (1) | `sk-...`                    | Required if `AI_PROVIDER=openai`. |
| `WEB_BASE_URL`      | recommended | `https://vooda.acme.com` | Used in deep-links inside Jira tickets / Slack notifications. Set to your customer-facing URL. |
| `OAUTH_REDIRECT_BASE` | recommended | `https://vooda.acme.com/api/v1/integrations/oauth` | Atlassian / GitHub OAuth callback base. Must match what's registered in the provider's developer console. |
| `CORS_ORIGINS`      | recommended | `https://vooda.acme.com`     | Comma-separated. Default is `http://localhost:3000` for dev. |
| `POSTGRES_USER`     | optional | `vooda` | Defaults to `vooda`. |
| `POSTGRES_DB`       | optional | `vooda` | Defaults to `vooda`. |
| `AI_PROVIDER`       | optional | `claude` | `claude` or `openai`. Defaults to `claude`. |
| `AI_MODEL`          | optional | `claude-sonnet-4-20250514` | Provider-specific model id. |
| `STORAGE_BACKEND`   | optional | `local` | `local` (default) or `s3`. |
| `LOG_LEVEL`         | optional | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR`. |
| `API_WORKERS`       | optional | `2` | uvicorn worker count for the api service. Defaults to 2. |
| `CELERY_CONCURRENCY`| optional | `4` | Celery worker process count. Defaults to 4. |
| `CELERY_LOG_LEVEL`  | optional | `info` | Celery log verbosity. |
| `SEED_ADMIN_EMAIL`  | optional | `you@acme.com` | Override default seed admin email. |
| `SEED_ADMIN_PASSWORD` | optional | `(strong)` | Override default seed admin password. |

(1) At least one AI provider key is required for AI triage to work.
The scanner runs without AI but findings will be unclassified.

---

## What docker-compose.yml does

```
db (postgres:16)         — internal only, port 5432 exposed on docker network
redis (redis:7)          — internal only, port 6379 exposed on docker network
api (vooda-ai/api)       — public, port 8000 (Coolify maps to 443)
worker (vooda-ai/api)    — internal, runs Celery worker
beat (vooda-ai/api)      — internal, runs Celery beat (periodic tasks)
web (vooda-ai/web)       — public, port 3000 (Coolify maps to 443)
```

Inter-service communication uses Docker DNS — services address each
other by name (`db`, `redis`, `api`). No `localhost` references.

### What runs on every container start

`api` service `command:` chains:

1. `alembic -c apps/api/alembic.ini upgrade heads` — applies any
   pending schema migrations including the initial-schema bootstrap
   on a fresh database. Idempotent — safe on every boot.
2. `uvicorn ... --workers ${API_WORKERS:-2}` — serves the API.

Performance indexes (CONCURRENT) are applied as part of the Alembic
migration `j7k8l9m0n1o2_perf_indexes_concurrent.py`, not as a
separate step.

### Healthchecks

| Service | Probe | Interval |
|---|---|---|
| db      | `pg_isready -U $POSTGRES_USER -d $POSTGRES_DB`            | 10s |
| redis   | `redis-cli ping`                                           | 10s |
| api     | `curl -fsS http://127.0.0.1:8000/healthz`                  | 15s |
| worker  | `celery -A apps.worker.celery_app inspect ping --timeout 5`| 30s |
| beat    | `pgrep -f 'celery.*beat'`                                  | 30s |
| web     | `wget -q http://127.0.0.1:3000/api/healthz`                | 30s |

Coolify uses these to drive its restart logic.

---

## Local development

Drop a `docker-compose.override.yml` next to the production compose
file to layer in dev conveniences (bind mounts, `--reload`, ports
published to localhost):

```bash
cp docker-compose.override.example.yml docker-compose.override.yml
docker compose up
```

Compose auto-merges any `docker-compose.override.yml` next to the
base file. The override file is git-ignored.

With the override file applied:

| Service | localhost port |
|---|---|
| db (psql) | 5433 |
| redis     | 6380 |
| api       | 8001 |
| web       | 3001 |

---

## Database migrations

```bash
# Apply all pending migrations (runs automatically on api container start)
docker compose exec api alembic -c apps/api/alembic.ini upgrade heads

# Show current revision
docker compose exec api alembic -c apps/api/alembic.ini current

# Show all heads
docker compose exec api alembic -c apps/api/alembic.ini heads

# Show migration history
docker compose exec api alembic -c apps/api/alembic.ini history
```

The migration chain is:

```
a0b1c2d3e4f5  initial schema (Base.metadata.create_all)
 └── bc0423892c95  add correlation + suppression
     └── f3bcd877ef7f  add api keys
         └── a1e2f3c4d5e6  add notification rules
             └── b7d9e1f2a3c4  add repository scan mode
                 ├── c2d3e4f5g6h7  add custom detectors      ┐
                 └── d8e9f0a1b2c3  add enterprise indexes    │ branch
                     └── e1f2g3h4i5j6  add scan sources      ┘
                         └── 25907caaf14c  merge heads
                             └── 7a9c4e2b1d8f  add rotation events  ┐
                                                                    │ second branch
                             g4h5i6j7k8l9  ticketing dest           │
                              └── h5i6j7k8l9m0  scope binding       │
                                  └── i6j7k8l9m0n1  widen src type  ┘
                                      └── j7k8l9m0n1o2  perf indexes (merge head)
```

After applying all migrations there is exactly one head:
`j7k8l9m0n1o2`.

All migrations are idempotent — re-applying on an already-migrated
database is a no-op.

---

## Seed data

```bash
docker compose exec api python -m infra.scripts.seed
```

Creates:
- Tenant: `Default Org` (slug: `default`)
- Admin user: `admin@vooda.ai` — the password is **randomly generated and printed once to the console** on first seed (copy it then; it is not stored anywhere). Set `SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD` before seeding to choose your own.
- Developer user: opt-in — only created if you set `SEED_DEV_PASSWORD` (as `dev@vooda.ai`).
- Default Security Policy

There is no hardcoded default password: seeding either uses your
`SEED_ADMIN_PASSWORD` or generates one and prints it. Either way,
**rotate it before exposing the instance to a network.**

---

## Coolify-specific notes

- Coolify expects a single `docker-compose.yml` at the repo root —
  ✓ already there.
- Coolify provides domain + SSL via its built-in Traefik proxy. Map
  the `web` service's port `3000` to your customer-facing domain.
- Map the `api` service's port `8000` to your customer-facing domain
  under `/api` (or a separate subdomain like `api.acme.com`). The
  web service's `next.config.mjs` proxies same-origin `/api/*` to
  `http://api:8000` over the docker network, so the SPA only needs
  one public hostname.
- Set environment variables in the Coolify "Environment Variables"
  panel — they get passed through to the container at compose-up
  time. Use the **build-time** `API_INTERNAL_URL` arg (default
  `http://api:8000`) — it must be available during `next build`.

---

## Production checklist

Before going live:

- [ ] Set `POSTGRES_PASSWORD` to a generated random value (≥32 bytes).
- [ ] Set `SECRET_KEY` to a generated random value (≥32 bytes).
- [ ] Set `ANTHROPIC_API_KEY` (or `OPENAI_API_KEY`) so AI triage works.
- [ ] Set `WEB_BASE_URL` to the public hostname (`https://...`).
- [ ] Set `CORS_ORIGINS` to the public hostname(s) — comma-separated.
- [ ] Set `OAUTH_REDIRECT_BASE` if using Atlassian / GitHub OAuth.
- [ ] Run `docker compose exec api python -m infra.scripts.seed` once.
- [ ] Set `SECRET_KEY` (`openssl rand -hex 32`) — the API and worker refuse to start without it.
- [ ] Copy the admin password the seed prints, or set `SEED_ADMIN_PASSWORD` beforehand.
- [ ] Configure a Postgres backup strategy (Coolify can do daily snapshots).
- [ ] Plan disk hygiene — on a single host, images/cache self-clean (containerd auto-release + BuildKit GC, no cap needed); for deeper cleanup or k8s/fleet sizing see `docs/deployment.md` → **Disk Hygiene & Image Lifecycle (Enterprise)** (`infra/scripts/docker-housekeeping.sh` is the single-host helper).
- [ ] Configure log shipping if compliance requires it (the API uses structlog).
- [ ] Verify `https://your-domain/healthz` returns `200` after deploy.

---

## Optional: scanning Docker images

The `services/source_scanners/adapters/docker_image.py` adapter
shells out to the `docker` CLI to inspect container images.
**`docker` is NOT installed in the production image** because:

1. It would balloon the image by ~80 MB.
2. The adapter requires the host's `/var/run/docker.sock` to be
   mounted into the container — a security-sensitive setup that
   needs to be opt-in.

If you need this scanner, build a custom image that adds:

```dockerfile
# Add to Dockerfile.api runtime stage
RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io && rm -rf /var/lib/apt/lists/*
```

…and add to docker-compose.yml worker service:

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

---

## Troubleshooting

### Migrations fail on a fresh deploy
Should not happen — `a0b1c2d3e4f5_initial_schema.py` creates every
table from the SQLAlchemy models on first run. If it does, check:
- Is `DATABASE_URL_SYNC` set correctly?
- Does the Postgres user have `CREATE TABLE` privilege?
- Run `docker compose logs api | head -100` for the error trace.

### "relation X does not exist" mid-migration
A model was added to the codebase but the SQLAlchemy import in
`apps/api/app/models/__init__.py` doesn't import it, so
`Base.metadata.create_all` skips its table. Add the model to the
package's `__init__.py` then re-run migrations.

### Web build fails: "tsconfig.tsbuildinfo references absolute paths"
The `.dockerignore` should exclude `**/tsconfig.tsbuildinfo`. If a
local `tsconfig.tsbuildinfo` slipped into the build context, run
`docker compose build --no-cache web`.

### Web service starts but `/api/...` returns 502
Likely the `API_INTERNAL_URL` build arg wasn't set during the web
build, so `next.config.mjs` baked in `http://localhost:8000` (which
doesn't resolve inside a container). Rebuild the web image with the
correct arg:

```bash
docker compose build --build-arg API_INTERNAL_URL=http://api:8000 web
docker compose up -d web
```

### Seed script crashes on `Tenant` import
The seed script imports models lazily — if it crashes, the most
likely cause is `DATABASE_URL_SYNC` not being set. Check the env.
