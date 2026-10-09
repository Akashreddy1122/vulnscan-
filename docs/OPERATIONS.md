# Operations guide

## Requirements

- Python 3.11+ (backend), Node.js 20+ (web), or Docker with Compose v2.
- 1 vCPU / 1 GB RAM for a small estate; the scan pipeline is CPU-bound on large files.
- Disk: quarantine and uploads are kept until deleted. Plan for the largest sample you accept (`MALWARESCAN_UPLOAD_MAX_BYTES`).

## Install

### Guided (recommended)

```bash
./scripts/install.sh --dry-run      # see every step first
./scripts/install.sh                # local: venv, dependencies, web build, generated secrets
./scripts/install.sh --docker       # containers via docker compose
```

The installer writes `deploy/.env` (mode 0600) with a generated admin password and secret key. It prints the admin password once. Change it after first login (Settings → Change password).

### Manual, local

```bash
cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cd ../frontend && npm ci && npm run build
```

Run two processes (use systemd or supervisord):

```bash
# API — one worker, by design
cd backend && MALWARESCAN_DATA=$PWD/data MALWARESCAN_ADMIN_PASSWORD='…' \
  .venv/bin/uvicorn malwarescan.main:app --host 127.0.0.1 --port 8000 --workers 1
# Web
cd frontend && MALWARESCAN_API_URL=http://127.0.0.1:8000 npx next start -H 0.0.0.0 -p 3000
```

Put the web tier behind an HTTPS reverse proxy (Caddy, nginx, or your load balancer). Do not expose port 8000 publicly.

### Docker Compose

`deploy/docker-compose.yml` builds both images. Only the web tier is published on `MALWARESCAN_WEB_PORT` (default 3000). The API volume is `msdata`. Note: the Dockerfiles have **not been built in the development environment**; build them once in your pipeline before relying on them.

## Configuration

All settings are environment variables. See `deploy/.env.example` for the full list with defaults. Key ones:

| Variable | Default | Why you might change it |
|---|---|---|
| `MALWARESCAN_DATA` | `./data` | Where the database, uploads, quarantine and reports live. Put it on a backed-up volume. |
| `MALWARESCAN_SECRET_KEY` | generated | Signs tokens and encrypts quarantine. Losing it makes quarantined samples unrecoverable. |
| `MALWARESCAN_ADMIN_PASSWORD` | random, printed | Bootstrap admin on first start only. |
| `MALWARESCAN_UPLOAD_MAX_BYTES` | 200 MB | Upper bound for uploads, path scans and agent submissions. |
| `MALWARESCAN_RATE_LIMIT` / `_AUTH` | 600 / 20 per minute | Per-IP limits. |
| `MALWARESCAN_FIM_PATHS` | `/etc,/usr/local/bin` | Watched paths (also editable in the UI). |
| `MALWARESCAN_LOG_FILES` | `/var/log/auth.log,/var/log/syslog` | Local log tails. Unreadable files are reported, not silently skipped. |
| `MALWARESCAN_RESPONSE_ALLOW_DANGEROUS` | `false` | Enables live firewall changes. Requires host privileges. |
| `MALWARESCAN_LOCAL_MONITORING` | `true` | Turn off to run the API as a pure control plane. |

## First-run checklist

1. Sign in as `admin` and change the password.
2. Admin → Runtime settings: decide whether self-registration stays on, and which role it grants.
3. Admin → Detection rules: confirm the integrity badge says *integrity verified*.
4. Dashboard: confirm `local-host` is **online** and the SCA panel has a result (first run at startup).
5. Run the EICAR test sample (File Scanner → Safe test samples). It should come back *malicious / info*. This verifies the whole pipeline without any real malware.
6. Set `MALWARESCAN_FIM_PATHS` to paths you actually want to protect, then Reset baseline.
7. Add analysts with the *analyst* role; keep *admin* to a minimum.

## Health and monitoring

- `GET /api/health` — liveness, database status, disk, worker status. Unauthenticated; safe for load balancers.
- `GET /api/health/ready` — readiness: rules loaded, migrations applied, ML model present.
- `GET /api/health/diagnostics` — admin-only detail (resources, rule integrity, log source readability, worker errors). Also shown in Admin → System health.
- Workers record `status`, `last_run`, `duration_ms` and the last error. A failing worker keeps retrying on its interval and is visible in the UI.

## Backups and restore

Back up `MALWARESCAN_DATA` **and** `MALWARESCAN_SECRET_KEY` together.

```bash
# consistent online backup of the database
sqlite3 "$MALWARESCAN_DATA/malwarescan.db" ".backup '/backups/malwarescan-$(date +%F).db'"
# samples and reports
tar -C "$MALWARESCAN_DATA" -czf /backups/ms-files-$(date +%F).tgz quarantine uploads reports
```

Restore: stop the API, put the database and folders back, start the API. Migrations are applied automatically and idempotently.

## Upgrades

1. Back up (above).
2. Pull the new code; rebuild the images or re-run `install.sh`.
3. Start the API. Pending SQL migrations in `backend/malwarescan/migrations/` are applied in order and recorded in `schema_migrations`.
4. Check `/api/health/ready` and Admin → Detection rules (integrity should be verified after an upgrade; if it is not, regenerate the manifest only after reviewing the rule diff).

## Rule and threat-intelligence updates

- **Detection content** lives in `backend/malwarescan/engine/rules/`. Edit, then `python scripts/rules_manifest.py` to refresh hashes, then Reload in the UI (or restart).
- **Custom YARA-subset rules** can be uploaded in Admin → Detection rules. They are compiled before they are stored; a non-compiling rule is rejected with the reason.
- **Remote rule packs** (optional) use `MALWARESCAN_RULES_URL`. Every file must match the published SHA-256 before anything is replaced.
- **IOCs** are managed in Threat Intel or imported from a feed. Built-in IOCs are documented test indicators, not live intelligence.

## Testing

```bash
# backend unit + API tests (49)
cd backend && .venv/bin/python -m pytest tests

# API end-to-end against a running server (158 checks, creates test data)
cd backend && E2E_ADMIN_PASSWORD='…' .venv/bin/python scripts/e2e_test.py

# frontend type-check and production build
cd frontend && npm run typecheck && npm run build

# browser end-to-end (46 checks). Needs a Chromium binary; see frontend/e2e/README.md
cd frontend/e2e && MS_ADMIN_PASSWORD='…' CHROME_PATH=/path/to/chromium node browser_e2e.mjs
```

Notes:

- The API suite triggers the credential rate limit on purpose. Wait 60 seconds before running the browser suite from the same IP, or the browser login will be rate-limited.
- The API suite is written to be re-runnable against the same data directory (names are suffixed per run).

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `database is locked` in logs | Two API processes on the same SQLite file | Run one API process. Check for an old process still holding the port. |
| Login returns 429 | Credential rate limit (20/min per IP) | Wait a minute. Behind a proxy, make sure `--forwarded-allow-ips` is set so limits apply per client. |
| Dashboard shows *Live refresh issue* | API stopped or unreachable from the web tier | Check `MALWARESCAN_API_URL` and `/api/health`. |
| Quarantine restore says *hash mismatch* | Stored blob changed, or the secret key changed | Restore the original secret key from backup. The file is never written unless its hash matches. |
| Rules integrity *failed* | A rule file was edited without regenerating the manifest | Review the diff; if intended, run `scripts/rules_manifest.py`. |
| Block IP refused | Live mode disabled, or no firewall tool on the host | Expected by default. Dry-run shows the command that would run. |
| Many process alerts on developer machines | Rules are tuned for servers | Add a suppression with a reason (Alerts → mark false positive → suppress). |
