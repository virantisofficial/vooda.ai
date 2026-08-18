#!/bin/bash
#
# rebuild-api.sh  —  rebuild the shared vooda-ai/api image, land it on the
#                    running containers, and clean up the leftover in one step.
# =============================================================================
# This is the ROOT-CAUSE fix for image accumulation. A bare
# `docker compose build api` leaves the previous image dangling forever; over
# many dev rebuilds that is what filled the disk. This wrapper prunes the
# dangling leftover immediately after every build, so rebuilds never pile up.
#
# It also force-recreates the four app containers onto the freshly built image,
# so the new code/deps are always LIVE (no "image built but containers still on
# the old one" gap).
#
# NEVER touches volumes or application data.
#
# USAGE:  ./infra/scripts/rebuild-api.sh
# =============================================================================
set -euo pipefail
export PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"

# repo root = two levels up from this script (infra/scripts/ -> repo root)
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

log() { printf '[rebuild %s] %s\n' "$(date '+%H:%M:%S')" "$*"; }

log "building vooda-ai/api ..."
docker compose build api

log "recreating app containers onto the new image (db/redis/web untouched) ..."
docker compose up -d --no-build --force-recreate api beat worker worker-scans

log "pruning the dangling leftover + stale build cache from this build ..."
docker image prune -f >/dev/null 2>&1 || true
docker builder prune -f --filter "until=72h" >/dev/null 2>&1 || true

log "verifying the fix is baked into the image (purgatory + triage import) ..."
docker exec vooda-worker python -c "import purgatory; from services.ai_triage.batch import _HAS_PURGATORY; print('  purgatory OK, _HAS_PURGATORY =', _HAS_PURGATORY)"

log "done."
docker system df | head -6
