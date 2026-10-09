#!/usr/bin/env bash
# Malware Scan guided installer.
#
#   ./scripts/install.sh              # local install: venv + backend deps + frontend build
#   ./scripts/install.sh --docker     # container install with docker compose
#   ./scripts/install.sh --dry-run    # print every step without changing anything
#
# Secrets are generated locally and written only to deploy/.env (git-ignored, mode 0600).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE=local
DRY=0
for arg in "$@"; do
  case "$arg" in
    --docker) MODE=docker ;;
    --dry-run) DRY=1 ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '\033[36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
run() { if [ "$DRY" = 1 ]; then echo "    [dry-run] $*"; else "$@"; fi; }

gen_secret() { python3 -c 'import secrets;print(secrets.token_urlsafe(48))'; }
gen_password() {
  python3 -c 'import secrets,string;a=string.ascii_letters+string.digits+"!#%+-_";print("".join(secrets.choice(a) for _ in range(24)))'
}

ENV_FILE="$ROOT/deploy/.env"

ensure_env() {
  if [ -f "$ENV_FILE" ]; then
    say "keeping existing $ENV_FILE"
    return
  fi
  say "creating $ENV_FILE with generated secrets (mode 0600)"
  if [ "$DRY" = 1 ]; then
    echo "    [dry-run] write $ENV_FILE from deploy/.env.example with generated secrets"
    return
  fi
  local pw key
  pw="$(gen_password)"
  key="$(gen_secret)"
  sed -e "s|^MALWARESCAN_ADMIN_PASSWORD=.*|MALWARESCAN_ADMIN_PASSWORD=${pw}|" \
      -e "s|^MALWARESCAN_SECRET_KEY=.*|MALWARESCAN_SECRET_KEY=${key}|" \
      "$ROOT/deploy/.env.example" > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  printf '\n  Admin user:     admin\n  Admin password: %s\n  (stored in %s — change it after first login)\n\n' "$pw" "$ENV_FILE"
}

if [ "$MODE" = docker ]; then
  command -v docker >/dev/null || die "docker is not installed"
  docker compose version >/dev/null 2>&1 || die "the docker compose plugin is required"
  ensure_env
  say "building and starting containers"
  run docker compose -f "$ROOT/deploy/docker-compose.yml" --env-file "$ENV_FILE" up -d --build
  if [ "$DRY" = 0 ]; then
    say "waiting for the web tier to become healthy"
    for _ in $(seq 1 60); do
      curl -sf "http://127.0.0.1:${MALWARESCAN_WEB_PORT:-3000}/login" >/dev/null && break
      sleep 2
    done
  fi
  say "open http://localhost:${MALWARESCAN_WEB_PORT:-3000}"
  exit 0
fi

# ------------------------------------------------------------------ local install
command -v python3 >/dev/null || die "python3 not found"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || die "Python 3.11 or newer is required"
command -v node >/dev/null || die "Node.js 20+ is required for the web UI"
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
[ "$NODE_MAJOR" -ge 20 ] || die "Node.js 20+ is required (found major version $NODE_MAJOR)"

say "creating the Python virtualenv in backend/.venv"
run python3 -m venv "$ROOT/backend/.venv"
run "$ROOT/backend/.venv/bin/pip" install -q -r "$ROOT/backend/requirements.txt"

say "installing and building the web UI"
run npm --prefix "$ROOT/frontend" ci --no-audit --no-fund
run npm --prefix "$ROOT/frontend" run build

ensure_env

cat <<MSG

Installed. Start the platform (two long-running processes; use systemd or a process manager):

  # 1) API — exactly one worker by design (see docs/OPERATIONS.md)
  cd $ROOT/backend && set -a && . ../deploy/.env && set +a && \
    MALWARESCAN_DATA=\$PWD/data .venv/bin/uvicorn malwarescan.main:app --host 127.0.0.1 --port 8000 --workers 1

  # 2) Web UI (proxies /api/* to the API above)
  cd $ROOT/frontend && MALWARESCAN_API_URL=http://127.0.0.1:8000 npx next start -H 0.0.0.0 -p 3000

Then open http://localhost:3000 and sign in as 'admin' with the password shown above.
Run the backend tests with:  cd backend && .venv/bin/python -m pytest tests
MSG
