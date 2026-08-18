#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
#
# Vooda installer / updater for Linux & macOS.
#
#   ./install.sh                 Interactive menu
#   ./install.sh install --prod  Install in production mode  (http://localhost:3000)
#   ./install.sh install --dev   Install in development mode (http://localhost:3001, hot reload)
#   ./install.sh update          Pull latest + rebuild, preserving ALL data
#   ./install.sh check           Check dependencies only (no changes)
#   ./install.sh --help
#
# What it does:
#   - Verifies Docker, Docker Compose v2, git and a running daemon.
#   - Creates .env from .env.example and auto-generates POSTGRES_PASSWORD
#     and SECRET_KEY if they are empty.
#   - Selects the dev or prod run override (docker-compose.override.yml).
#   - Brings the stack up, waits for health, seeds the admin account and
#     shows its one-time password.
#   - `update` pulls the latest code and rebuilds WITHOUT deleting your
#     data volumes; it takes a pg_dump backup first as a safety net.

set -euo pipefail

# ── config ─────────────────────────────────────────────────────────
DEV_OVERRIDE="docker-compose.override.example.yml"
PROD_OVERRIDE="docker-compose.override.prod.example.yml"
ACTIVE_OVERRIDE="docker-compose.override.yml"
ENV_FILE=".env"
ENV_EXAMPLE=".env.example"
BACKUP_DIR="backups"

# ── pretty output ──────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_RED=$'\033[31m'
  C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_CYN=$'\033[36m'
else
  C_RESET=; C_BOLD=; C_RED=; C_GRN=; C_YEL=; C_CYN=
fi
info() { printf "%s %s\n" "${C_CYN}▸${C_RESET}" "$*"; }
ok()   { printf "%s %s\n" "${C_GRN}✓${C_RESET}" "$*"; }
warn() { printf "%s %s\n" "${C_YEL}!${C_RESET}" "$*"; }
err()  { printf "%s%s%s\n" "${C_RED}✗ " "$*" "${C_RESET}" >&2; }
die()  { err "$*"; exit 1; }

# ── run from the repo root ─────────────────────────────────────────
cd "$(dirname "$0")"
[ -f docker-compose.yml ] || die "Run this from the Vooda repo root (docker-compose.yml not found)."

# ── docker compose command detection ───────────────────────────────
COMPOSE=""
detect_compose() {
  if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then COMPOSE="docker-compose"; fi
}
have() { command -v "$1" >/dev/null 2>&1; }

check_deps() {
  info "Checking dependencies…"
  local missing=0
  if have docker; then ok "docker $(docker --version | awk '{print $3}' | tr -d ',')"
  else err "docker not found — install Docker: https://docs.docker.com/get-docker/"; missing=1; fi
  detect_compose
  if [ -n "$COMPOSE" ]; then ok "compose available ($COMPOSE)"
  else err "Docker Compose v2 not found — it ships with modern Docker Desktop/Engine."; missing=1; fi
  if have git; then ok "git $(git --version | awk '{print $3}')"
  else warn "git not found — required for 'update', not for a first install."; fi
  if docker info >/dev/null 2>&1; then ok "docker daemon is running"
  else err "Docker daemon not reachable — start Docker and re-run."; missing=1; fi
  [ "$missing" -eq 0 ] || die "Install the missing dependencies above, then re-run."
}

# ── env helpers ────────────────────────────────────────────────────
gen_secret() { # $1 = hex|b64
  if have openssl; then
    if [ "$1" = hex ]; then openssl rand -hex 32; else openssl rand -base64 32; fi
  elif [ "$1" = hex ]; then head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
  else head -c 32 /dev/urandom | base64 | tr -d '\n'; fi
}

env_get() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- || true; }

# Portable in-place set of KEY=value (no reliance on sed -i flavour).
env_set() { # $1 key  $2 value
  local key="$1" val="$2" esc
  esc="$(printf '%s' "$val" | sed -e 's/[\/&]/\\&/g')"
  if grep -qE "^${key}=" "$ENV_FILE"; then
    sed "s/^${key}=.*/${key}=${esc}/" "$ENV_FILE" > "$ENV_FILE.tmp" && mv "$ENV_FILE.tmp" "$ENV_FILE"
  else
    printf "%s=%s\n" "$key" "$val" >> "$ENV_FILE"
  fi
}

ensure_env() { # $1 = dev|prod
  local mode="$1" web api
  if [ -f "$ENV_FILE" ]; then info "$ENV_FILE exists — keeping your values."
  else cp "$ENV_EXAMPLE" "$ENV_FILE"; ok "Created $ENV_FILE from $ENV_EXAMPLE"; fi
  [ -n "$(env_get POSTGRES_PASSWORD)" ] || { env_set POSTGRES_PASSWORD "$(gen_secret b64)"; ok "Generated a POSTGRES_PASSWORD"; }
  [ -n "$(env_get SECRET_KEY)" ]        || { env_set SECRET_KEY "$(gen_secret hex)"; ok "Generated a SECRET_KEY"; }
  if [ "$mode" = dev ]; then web=3001; api=8001; else web=3000; api=8000; fi
  env_set WEB_BASE_URL        "http://localhost:$web"
  env_set CORS_ORIGINS        "http://localhost:$web"
  env_set OAUTH_REDIRECT_BASE "http://localhost:$api/api/v1/integrations/oauth"
  [ -n "$(env_get ANTHROPIC_API_KEY)" ] || warn "ANTHROPIC_API_KEY is empty in $ENV_FILE — AI triage is off until you set a key (or configure a local model in the UI)."
}

apply_override() { # $1 = dev|prod
  local src ans
  if [ "$1" = dev ]; then src="$DEV_OVERRIDE"; else src="$PROD_OVERRIDE"; fi
  [ -f "$src" ] || die "Override template $src not found."
  if [ -f "$ACTIVE_OVERRIDE" ] && ! cmp -s "$src" "$ACTIVE_OVERRIDE"; then
    warn "$ACTIVE_OVERRIDE already exists and differs from the $1 template."
    printf "  Replace it with the %s template? [y/N] " "$1"; read -r ans
    case "$ans" in y|Y) : ;; *) info "Keeping your existing $ACTIVE_OVERRIDE."; return 0;; esac
  fi
  cp "$src" "$ACTIVE_OVERRIDE"; ok "Selected $1 mode  ($ACTIVE_OVERRIDE ← $src)"
}

wait_healthy() {
  info "Waiting for the API to become healthy…"
  local i=0 cid
  while :; do
    cid="$($COMPOSE ps -q api 2>/dev/null || true)"
    if [ -n "$cid" ] && [ "$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null)" = healthy ]; then
      ok "API healthy"; return 0
    fi
    i=$((i + 1)); [ "$i" -gt 60 ] && { warn "API not healthy after ~3 min — check: $COMPOSE logs api"; return 1; }
    sleep 3
  done
}

run_seed() {
  info "Seeding the default org + admin account…"
  $COMPOSE exec -T api python -m infra.scripts.seed \
    || warn "Seed reported an issue — safe to re-run: $COMPOSE exec api python -m infra.scripts.seed"
}

print_access() { # $1 = dev|prod
  local web api
  if [ "$1" = dev ]; then web=3001; api=8001; else web=3000; api=8000; fi
  printf "\n%sVooda is up (%s mode).%s\n" "$C_BOLD" "$1" "$C_RESET"
  printf "  Web UI   : http://localhost:%s\n" "$web"
  printf "  API docs : http://localhost:%s/api/docs\n" "$api"
  printf "  Health   : http://localhost:%s/api/health\n" "$api"
  printf "  Login    : admin@vooda.ai — password was printed by the seed step above.\n"
  printf "  %sChange the admin password before exposing this to a network.%s\n\n" "$C_YEL" "$C_RESET"
}

current_mode() { # echoes dev|prod based on the active override
  if [ -f "$ACTIVE_OVERRIDE" ] && grep -q '3001:3000' "$ACTIVE_OVERRIDE"; then echo dev; else echo prod; fi
}

do_install() { # $1 = dev|prod
  check_deps
  ensure_env "$1"
  apply_override "$1"
  info "Building and starting the stack (first run can take a few minutes)…"
  $COMPOSE up -d --build
  wait_healthy || true
  run_seed
  print_access "$1"
}

backup_db() {
  detect_compose
  mkdir -p "$BACKUP_DIR"
  local out="$BACKUP_DIR/vooda-db-$(date +%Y%m%d-%H%M%S).sql"
  info "Backing up the database to $out (safety net before update)…"
  if $COMPOSE exec -T db sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB"' > "$out" 2>/dev/null && [ -s "$out" ]; then
    ok "DB backup written: $out"
  else
    warn "Could not take a DB backup (is the db container running?). Continuing — the update never deletes volumes."
    rm -f "$out"
  fi
}

do_update() {
  check_deps
  have git || die "git is required for update."
  [ -d .git ] || die "Not a git checkout — pull manually. Your data is untouched."
  info "Updating the repo to the latest release…"
  info "(your .env and docker-compose.override.yml are git-ignored and stay as-is)"
  git pull --ff-only || die "git pull failed (local changes to tracked files?). Resolve manually and re-run — your data is untouched."
  backup_db
  info "Rebuilding images with the new code…"
  $COMPOSE build
  info "Recreating containers — data volumes are preserved, migrations run on startup…"
  $COMPOSE up -d
  wait_healthy || true
  ok "Update complete. Volumes kept: pgdata, redis_data, storage_data."
  print_access "$(current_mode)"
}

menu() {
  printf "\n%sVooda installer%s\n" "$C_BOLD" "$C_RESET"
  printf "  1) Install — %sproduction%s  (real build, http://localhost:3000)\n" "$C_BOLD" "$C_RESET"
  printf "  2) Install — %sdevelopment%s (next dev + hot reload, http://localhost:3001)\n" "$C_BOLD" "$C_RESET"
  printf "  3) Update  — pull latest + rebuild, keep all data\n"
  printf "  4) Check dependencies only\n"
  printf "  5) Quit\n"
  printf "Choose [1-5]: "; read -r c
  case "$c" in
    1) do_install prod ;;
    2) do_install dev ;;
    3) do_update ;;
    4) check_deps ;;
    *) info "Bye." ;;
  esac
}

usage() {
  cat <<EOF
Vooda installer (Linux/macOS)

Usage:
  ./install.sh                 Interactive menu
  ./install.sh install --prod  Production mode  (http://localhost:3000)
  ./install.sh install --dev   Development mode (http://localhost:3001, hot reload)
  ./install.sh update          Pull latest + rebuild, preserving all data
  ./install.sh check           Check dependencies only
  ./install.sh --help          This help
EOF
}

# ── dispatch ───────────────────────────────────────────────────────
case "${1:-}" in
  ""|menu)        menu ;;
  -h|--help|help) usage ;;
  check)          check_deps ;;
  update)         do_update ;;
  install)
    case "${2:-}" in
      --prod|prod) do_install prod ;;
      --dev|dev)   do_install dev ;;
      "")          printf "prod or dev? [prod/dev]: "; read -r m; [ "$m" = dev ] && do_install dev || do_install prod ;;
      *)           die "Unknown install option: $2 (use --prod or --dev)" ;;
    esac ;;
  *) usage; die "Unknown command: $1" ;;
esac
