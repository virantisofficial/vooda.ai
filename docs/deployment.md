# Vooda AI -- Deployment Guide

## Docker Compose Setup

Vooda AI runs as five interconnected services orchestrated by Docker Compose.

### Services

| Service | Container | Image | Purpose |
|---------|-----------|-------|---------|
| **db** | vooda-db | postgres:16-alpine | PostgreSQL database (52+ tables) |
| **redis** | vooda-redis | redis:7-alpine | Task queue, cache, and pub/sub |
| **api** | vooda-api | Custom (Python 3.12) | FastAPI backend with 31 routers |
| **worker** | vooda-worker | Custom (Python 3.12) | Celery async task workers |
| **web** | vooda-web | Custom (Node 20) | Next.js 15 frontend |

### Port Mappings

| Service | Host Port | Container Port | Protocol |
|---------|-----------|----------------|----------|
| web | **3001** | 3000 | HTTP |
| api | **8001** | 8000 | HTTP/WS |
| db | 5433 | 5432 | TCP |
| redis | 6380 | 6379 | TCP |

**Note**: Host ports are offset from standard ports to avoid conflicts with local services.

### Service Dependencies

```
db (PostgreSQL 16)  <--+
                       +--> api (FastAPI) --> web (Next.js)
redis (Redis 7)    <--+        |
                       +--> worker (Celery)
```

- `api` and `worker` wait for `db` and `redis` health checks before starting
- `web` waits for `api` to be available
- `api` automatically runs Alembic migrations on startup

## Quick Start

```bash
# 1. Clone the repository
git clone <repo-url>
cd Vooda

# 2. (Optional) Set your AI API key for triage features
export ANTHROPIC_API_KEY=sk-ant-...

# 3. Start all services
docker compose up -d

# 4. Verify all containers are running
docker compose ps

# 5. (Optional) Seed demo data
docker compose exec api python -m infra.scripts.seed

# 6. Access the platform
#    Web UI:    http://localhost:3001
#    API Docs:  http://localhost:8001/api/docs
#    Login:     admin@vooda.ai — the seed prints a generated password once
```

### Checking Health

```bash
# API health endpoint
curl http://localhost:8001/api/health
# Returns: {"status": "healthy", "version": "..."}

# Container status
docker compose ps

# View logs
docker compose logs api
docker compose logs worker
docker compose logs web
```

## Environment Variables

### API & Worker Services

Both the `api` and `worker` containers share the same environment configuration:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | (set in compose) | PostgreSQL async connection string (`postgresql+asyncpg://...`) |
| `DATABASE_URL_SYNC` | Yes | (set in compose) | PostgreSQL sync connection string for Alembic (`postgresql://...`) |
| `REDIS_URL` | Yes | (set in compose) | Redis connection string (`redis://redis:6379/0`) |
| `SECRET_KEY` | Yes | *(none — startup fails without it)* | Signs sessions and encrypts stored integration credentials. The API and worker refuse to start in production unless it is set and at least 32 characters. `openssl rand -hex 32`. |
| `AI_PROVIDER` | No | `claude` | Default AI provider (`claude`, `openai`, `google`) |
| `ANTHROPIC_API_KEY` | No | -- | Anthropic Claude API key for AI triage |
| `OPENAI_API_KEY` | No | -- | OpenAI API key (alternative provider) |
| `STORAGE_BACKEND` | No | `local` | File storage backend (`local`, `s3`) |
| `STORAGE_PATH` | No | `/app/storage` | Local file storage path |
| `LOG_LEVEL` | No | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

### Web Service

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NEXT_PUBLIC_API_URL` | No | `""` (empty) | Public API base URL. Empty string proxies through Next.js. |
| `API_INTERNAL_URL` | No | `http://api:8000` | Internal API URL for server-side requests |

### Database Service

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTGRES_DB` | Yes | `vooda` | Database name |
| `POSTGRES_USER` | Yes | `vooda` | Database user |
| `POSTGRES_PASSWORD` | Yes | `vooda_dev_password` | Database password. **Must change for production.** |

## Database Initialization

### Automatic Setup

The API container runs Alembic migrations automatically on startup:

```
alembic -c apps/api/alembic.ini upgrade head
```

This creates all 52+ tables and applies any pending migrations.

### Initialization Script

An SQL initialization script runs when the PostgreSQL container is first created:

```
infra/scripts/init-db.sql --> /docker-entrypoint-initdb.d/init.sql
```

This handles any database-level setup that must occur before migrations.

### Manual Migration

```bash
# Run migrations manually
docker compose exec api alembic -c apps/api/alembic.ini upgrade head

# Create a new migration after model changes
docker compose exec api alembic -c apps/api/alembic.ini revision --autogenerate -m "description"

# Downgrade one revision
docker compose exec api alembic -c apps/api/alembic.ini downgrade -1
```

### Seeding Demo Data

```bash
docker compose exec api python -m infra.scripts.seed
```

This creates the default tenant and the admin user (`admin@vooda.ai`).
There is no default password: unless you set `SEED_ADMIN_PASSWORD`, the
script generates a strong one and prints it once. Nothing stores it, so
copy it when you see it — if it is lost, reset the account rather than
looking it up.

## Default Credentials

| Resource | Credential | Notes |
|----------|-----------|-------|
| Web UI / API | `admin@vooda.ai` / generated at seed time | No default password. Set `SEED_ADMIN_PASSWORD` to choose your own, or copy the one the seed prints. |
| PostgreSQL | `vooda` / `vooda_dev_password` | Database user. Change via `POSTGRES_PASSWORD` env var. |
| JWT Secret | none — `SECRET_KEY` is required | Signs sessions **and** encrypts stored integration credentials. The API and worker refuse to start in production without a value of 32+ characters. Generate with `openssl rand -hex 32`. |

**Security Warning**: All default credentials are for development only. Every credential listed above must be changed before any production or internet-facing deployment.

## Persistent Volumes

Docker Compose defines two named volumes:

| Volume | Mount Path | Purpose |
|--------|-----------|---------|
| `pgdata` | `/var/lib/postgresql/data` | PostgreSQL data directory |
| `storage_data` | `/app/storage` | Cloned repositories and scan artifacts |

These volumes persist data across container restarts. To fully reset:

```bash
docker compose down -v   # Removes containers AND volumes
docker compose up -d     # Fresh start with empty database
```

## Production Deployment Considerations

### Security Hardening

1. **Change all default credentials** -- database password, JWT secret key, and admin user password
2. **Generate a strong SECRET_KEY** -- use `openssl rand -hex 32` or equivalent
3. **Enable HTTPS** -- place a reverse proxy (nginx, Traefik, or cloud LB) in front of the web and API services
4. **Restrict database access** -- remove the `ports` mapping for `db` and `redis` in production so they are only accessible within the Docker network
5. **Set secure CORS origins** -- configure `CORS_ORIGINS` to allow only your domain
6. **Rotate API keys** -- set key expiration policies in Settings

> **SSO is temporarily disabled.** SAML/OIDC login is off in this release and every SSO endpoint returns `503` until it is re-enabled after a security hardening pass. Do not rely on SSO for authentication in this release; use JWT email/password login behind your reverse proxy.

### Database

- **Connection pooling**: Use PgBouncer or the built-in SQLAlchemy pool with tuned `pool_size` and `max_overflow`
- **Backups**: Schedule `pg_dump` or use managed PostgreSQL (RDS, Cloud SQL, Azure DB)
- **Replication**: Configure read replicas for high-read workloads (metrics, dashboard)
- **Encryption at rest**: Use managed database services with encryption enabled or LUKS volumes

### Redis

- **Persistence**: Enable AOF or RDB snapshotting for queue durability
- **Memory limits**: Set `maxmemory` with an appropriate eviction policy (`allkeys-lru` for cache)
- **Cluster mode**: For high availability, deploy Redis Sentinel or Redis Cluster

### Reverse Proxy Configuration

Example nginx configuration:

```nginx
server {
    listen 443 ssl;
    server_name vooda.example.com;

    ssl_certificate     /etc/ssl/vooda.crt;
    ssl_certificate_key /etc/ssl/vooda.key;

    # Frontend
    location / {
        proxy_pass http://localhost:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # API
    location /api/ {
        proxy_pass http://localhost:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # WebSocket
    location /api/v1/ws/ {
        proxy_pass http://localhost:8001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## Scaling

### Worker Replicas

The Celery worker is the primary scaling target. Increase concurrency or add replicas:

```bash
# Option 1: Increase concurrency per worker
# Edit docker-compose.yml worker command:
celery -A apps.worker.celery_app worker --loglevel=info --concurrency=8

# Option 2: Run multiple worker containers
docker compose up -d --scale worker=3
```

For different task priorities, run specialized workers:

```bash
# Scan workers (CPU-intensive)
celery -A apps.worker.celery_app worker -Q scan --concurrency=4

# AI triage workers (IO-bound, waiting on API calls)
celery -A apps.worker.celery_app worker -Q triage --concurrency=16
```

### API Replicas

Run multiple API instances behind a load balancer:

```yaml
# docker-compose.override.yml
services:
  api:
    deploy:
      replicas: 3
    ports: []  # Remove direct port mapping; use LB instead
```

### Connection Pools

Tune database connection pools based on the number of API and worker replicas:

| Setting | Default | Recommended (Production) |
|---------|---------|------------------------|
| SQLAlchemy `pool_size` | 5 | 10-20 per replica |
| SQLAlchemy `max_overflow` | 10 | 20-40 per replica |
| Redis `max_connections` | 10 | 50-100 per replica |
| Celery `worker_concurrency` | 4 | 4-16 depending on task type |

**Rule of thumb**: Total database connections = `(api_replicas * pool_size) + (worker_replicas * concurrency) + headroom`. Ensure PostgreSQL `max_connections` exceeds this total.

### Monitoring

- **Health endpoint**: `GET /api/health` for load balancer health checks
- **Celery monitoring**: Use Flower (`celery -A apps.worker.celery_app flower`) for worker dashboard
- **Database metrics**: Monitor connection count, query latency, and replication lag
- **Redis metrics**: Monitor memory usage, queue depth, and pub/sub channels

## Disk Hygiene & Image Lifecycle (Enterprise)

At scale, "the disk filled up" is prevented by **architecture, not a cron job**. There are three tiers, each with its own native, event/threshold-driven mechanism — and in all three, **Vooda's data lives off the node** (managed Postgres + object storage), so image/cache reclamation can never touch findings or scan history.

> **Build vs. run.** Runtime nodes *pull* pre-built images and never build, so a BuildKit cache cap (`defaultKeepStorage`) is irrelevant there — it only matters on CI builders. Do not carry a dev-machine cache number into cluster sizing; the mechanisms below are what actually govern disk at scale.

### 1. Runtime nodes — kubelet image garbage collection

The `api` / `worker` / `worker-scans` / `web` pods run on nodes that self-clean via kubelet image GC (threshold-driven, evaluated every ~5 min — no cron). Recommended `KubeletConfiguration`:

```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
# image GC on the image filesystem (containerd/overlayfs)
imageGCHighThresholdPercent: 80   # start reclaiming unused images above 80% (default 85)
imageGCLowThresholdPercent: 60    # reclaim down to 60%                (default 80)
imageMinimumGCAge: "5m"           # protect freshly pulled images
imageMaximumGCAge: "168h"         # evict images unused for 7d regardless of disk (k8s >= 1.30)
# container log rotation (the other big node-disk consumer)
containerLogMaxSize: "50Mi"
containerLogMaxFiles: 5
# last-resort hard eviction backstop (pods evicted + images reclaimed under pressure)
evictionHard:
  imagefs.available: "15%"
  nodefs.available: "10%"
  nodefs.inodesFree: "5%"
```

| Platform | Where to set it |
|---|---|
| Amazon EKS | managed node-group launch template `--kubelet-extra-args`, custom `bootstrap.sh`, or Karpenter `kubelet` block |
| Google GKE | node-system-config `kubeletConfig` (`imageGcHighThresholdPercent`, …) |
| Self-managed k8s | `/var/lib/kubelet/config.yaml` |
| Plain Docker / Swarm host (no kubelet) | `infra/scripts/docker-housekeeping.sh` on a systemd-timer — the single-host equivalent. **Never** pass `--volumes`. |

### 2. Registry retention — where image history actually lives

Image history belongs in the registry under a retention policy, **not** on nodes. Use **immutable tags** (git-SHA and/or semver); never deploy a moving `:latest` in production — deploy by digest (`@sha256:…`).

**Amazon ECR lifecycle policy** (apply per repo: `vooda-api`, `vooda-web`, `vooda-cli`):

```json
{ "rules": [
  { "rulePriority": 1, "description": "Expire untagged after 1 day",
    "selection": { "tagStatus": "untagged", "countType": "sinceImagePushed", "countUnit": "days", "countNumber": 1 },
    "action": { "type": "expire" } },
  { "rulePriority": 2, "description": "Keep last 10 release images",
    "selection": { "tagStatus": "tagged", "tagPrefixList": ["v"], "countType": "imageCountMoreThan", "countNumber": 10 },
    "action": { "type": "expire" } },
  { "rulePriority": 3, "description": "Keep 30 days of SHA-tagged builds",
    "selection": { "tagStatus": "tagged", "tagPrefixList": ["sha-"], "countType": "sinceImagePushed", "countUnit": "days", "countNumber": 30 },
    "action": { "type": "expire" } }
] }
```

| Registry | Mechanism |
|---|---|
| Amazon ECR | Lifecycle policy (above) + **tag immutability enabled** |
| Harbor | Tag-retention rules (keep last N / last Nd) **+ a scheduled GC job** to free the underlying blobs |
| Google Artifact Registry | Cleanup policies (keep-most-recent + delete older-than) |
| JFrog Artifactory | Retention via AQL or the Cleanup plugin |

### 3. CI build cache — remote, not a local cap

Build Vooda's images on **ephemeral runners** with a **remote** cache backend, so cache is shared across runners and bounded by the backend's retention — never by a per-host `defaultKeepStorage` guess.

```bash
# buildx with registry-backed cache (portable across ephemeral runners)
REG=ghcr.io/acme
docker buildx build -f infra/docker/Dockerfile.api \
  -t "$REG/vooda-api:sha-$GIT_SHA" \
  --cache-from type=registry,ref="$REG/vooda-api:buildcache" \
  --cache-to   type=registry,ref="$REG/vooda-api:buildcache",mode=max \
  --push .
```

- **GitHub Actions**: `docker/build-push-action` with `cache-from: type=gha` + `cache-to: type=gha,mode=max` (or the registry cache above).
- **Scale-out**: managed remote builders — **Docker Build Cloud** or **depot.dev** — or **BuildKit-on-Kubernetes** with a sized cache PVC.
- **If a persistent self-hosted builder is unavoidable**: set BuildKit GC `keepBytes` to the *workload* (e.g. 100–200 GB across all services) and monitor it — that is the only place a cache cap belongs, and it is an order of magnitude larger than a developer laptop's.

### 4. Data-safety guardrails (non-negotiable)

- **Production data is off-node**: `DATABASE_URL` → managed Postgres (RDS / Cloud SQL); `STORAGE_BACKEND=s3` → object storage; Redis → managed. Image/cache GC physically cannot reach Vooda data.
- **If self-hosting with volumes** (`pgdata`, `storage_data`): never run `docker system prune --volumes` or `docker volume prune`. Back up `pgdata` (pg_dump + WAL archiving) and `storage_data` (volume snapshots) on a schedule.

### 5. Monitoring & alerting

- node_exporter + Prometheus: alert on `node_filesystem_avail_bytes` below **15 % (warn) / 10 % (critical)** for **both** the image filesystem and the root filesystem — so you are paged *before* a node crosses the eviction threshold.
- Registry: track per-repo storage and retention-policy effectiveness.
- CI: track build-cache hit ratio and builder cache size.

## CI/CD Integration

### API Key Authentication

Create an API key in Settings, then use it in CI pipelines:

```bash
# Gate check -- returns pass/fail based on policies
curl -H "Authorization: Bearer vooda_..." \
     https://vooda.example.com/api/v1/gates/{repo_id}/check

# Trigger a scan
curl -X POST -H "Authorization: Bearer vooda_..." \
     https://vooda.example.com/api/v1/repositories/{repo_id}/scan \
     -d '{"scan_type": "standalone"}'

# Push protection -- check a commit for secrets before merge
curl -X POST -H "Authorization: Bearer vooda_..." \
     https://vooda.example.com/api/v1/push-protection/check \
     -d '{"diff": "..."}'
```

### Scheduled Scans

Configure scan schedules in repository settings:

| Schedule | Behavior |
|----------|----------|
| `on_demand` | Manual trigger only |
| `daily` | Runs at 2:00 AM UTC |
| `weekly` | Runs Monday at 2:00 AM UTC |

Celery Beat checks hourly for due scans.

## Troubleshooting

### Common Issues

**Container fails to start**:
```bash
# Check logs for the failing service
docker compose logs api
docker compose logs worker

# Verify database is healthy
docker compose exec db pg_isready -U vooda
```

**Database migration errors**:
```bash
# Check current migration state
docker compose exec api alembic -c apps/api/alembic.ini current

# Stamp the head if state is inconsistent
docker compose exec api alembic -c apps/api/alembic.ini stamp head
```

**Worker not processing tasks**:
```bash
# Verify Redis connectivity
docker compose exec redis redis-cli ping

# Check Celery worker status
docker compose exec worker celery -A apps.worker.celery_app inspect active
```

**Frontend cannot reach API**:
```bash
# Verify API is responding
curl http://localhost:8001/api/health

# Check Next.js proxy configuration
# API_INTERNAL_URL should be http://api:8000 (Docker internal network)
```
