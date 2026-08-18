#!/bin/bash
#
# docker-housekeeping.sh  —  safe, automatic Docker disk hygiene for Vooda.
# =============================================================================
# WHY THIS EXISTS
#   Every `docker compose build` of the shared vooda-ai/api image creates a NEW
#   image and silently un-tags the previous one, which becomes a dangling
#   <none> image that Docker never deletes on its own. BuildKit also grows its
#   layer/pip cache without bound. On a host that rebuilds all day this climbs
#   to 100GB+ and eventually crashes the build at the "exporting to image" step
#   (the failure that once took Vooda down). This script is the SINGLE-HOST
#   equivalent of Kubernetes' kubelet image garbage collection.
#
# WHAT IT REMOVES  (safe — never touches application data):
#   - stopped containers older than 24h
#   - dangling (<none>) images               -> leftovers from rebuilds
#   - build cache older than 72h             -> BuildKit layer + pip cache
#   - (disk-pressure only) full build cache  -> when the VM disk crosses HIGH%
#   - (--deep, opt-in only) UNUSED TAGGED images older than 7d
#
# WHAT IT NEVER TOUCHES:
#   - docker VOLUMES  (Postgres scan data + cloned-repo storage live here).
#     There is no `docker volume prune` and no `--volumes` anywhere below. Ever.
#   - running containers and the images they use
#   - tagged images that ARE in use
#
# PRODUCTION MAPPING (where you do NOT run this by hand):
#   - Kubernetes: kubelet image GC does this automatically —
#       imageGCHighThresholdPercent=85   (start reclaiming above 85% disk)
#       imageGCLowThresholdPercent=80    (reclaim down to 80%)
#       imageMinimumGCAge=2m             (don't GC images younger than this)
#     containerd/CRI reaps exited containers. Image *history* lives in a
#     registry (ECR / Harbor / GHCR) under a retention policy ("keep last N
#     tags, GC the rest") — never on the nodes. Nodes are replaced each deploy.
#   - Plain Docker / Swarm host: run THIS script on a systemd-timer or cron,
#     off-peak, and never with --volumes.
#
# USAGE:
#   ./docker-housekeeping.sh            # safe default clean
#   ./docker-housekeeping.sh --deep     # also remove unused TAGGED images >7d
#                                       #   (can remove OTHER projects' images)
#   DOCKER_GC_HIGH_PCT=75 ./docker-housekeeping.sh   # custom disk threshold
# =============================================================================
set -euo pipefail

# launchd/cron run with a minimal PATH; make sure the docker CLI is findable.
export PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"

DEEP=0
[ "${1:-}" = "--deep" ] && DEEP=1
DISK_HIGH_PCT="${DOCKER_GC_HIGH_PCT:-80}"

log() { printf '[housekeeping %s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }

# Fail fast (but cleanly) if the Docker daemon isn't up — e.g. Mac asleep.
if ! docker info >/dev/null 2>&1; then
  log "Docker daemon not reachable — skipping this run."
  exit 0
fi

log "===== Vooda Docker housekeeping start ====="
log "BEFORE:"
docker system df || true

# 1) stopped containers older than 24h (keeps recent ones for debugging)
log "pruning stopped containers (>24h) ..."
docker container prune -f --filter "until=24h" >/dev/null 2>&1 || true

# 2) dangling (<none>) images — rebuild leftovers. NEVER tagged images.
log "pruning dangling images ..."
docker image prune -f >/dev/null 2>&1 || true

# 3) build cache older than 72h
log "pruning build cache (>72h) ..."
docker builder prune -f --filter "until=72h" >/dev/null 2>&1 || true

# 4) disk-pressure escalation — the kubelet-style HIGH threshold.
#    Reads the Docker VM root fs from inside a throwaway container.
used_pct="$(docker run --rm alpine:latest sh -c "df -P / | awk 'NR==2{gsub(\"%\",\"\",\$5); print \$5}'" 2>/dev/null || echo 0)"
if [ "${used_pct:-0}" -ge "$DISK_HIGH_PCT" ] 2>/dev/null; then
  log "Docker VM disk at ${used_pct}% (>= ${DISK_HIGH_PCT}% HIGH) — escalating: full build-cache prune"
  docker builder prune -af >/dev/null 2>&1 || true
else
  log "Docker VM disk at ${used_pct}% (below ${DISK_HIGH_PCT}% HIGH) — no escalation"
fi

# 5) OPT-IN deep clean: unused TAGGED images >7d. Can remove images that belong
#    to OTHER projects (kali, trivex, sonarqube, ...). Off by default on purpose.
if [ "$DEEP" -eq 1 ]; then
  log "--deep: pruning UNUSED TAGGED images (>7d) — may remove other projects' images"
  docker image prune -af --filter "until=168h" >/dev/null 2>&1 || true
fi

log "AFTER:"
docker system df || true
log "===== done — volumes were NOT touched ====="
