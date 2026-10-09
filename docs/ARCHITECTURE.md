# Malware Scan — architecture

```
                 ┌──────────────────────────────┐
  browser ──────▶│ web (Next.js 14, React 18)   │  same-origin /api/* ──┐
                 │ dark cyber UI, live polling  │                       │ rewrite
                 └──────────────────────────────┘                       ▼
                                              ┌───────────────────────────────────────────┐
  remote agents ─── X-Agent-Token ──────────▶ │ api (FastAPI, single worker)              │
  (malwarescan_agent.py)                      │  routers: auth scans alerts incidents     │
                                              │  logs fim vulns sca network hunt intel    │
                                              │  response reports agents assistant admin  │
                                              │                                           │
                                              │  engine/  yara-lite · static · ML · rules │
                                              │  monitoring/ process · network · logs·FIM │
                                              │  response/ playbooks (precheck→verify)    │
                                              │  workers.py  supervised asyncio loops     │
                                              └───────────────┬───────────────────────────┘
                                                              │ SQLite (WAL) + encrypted quarantine
                                                              ▼
                                                      /data volume
```

## Components

| Layer | Location | Notes |
|---|---|---|
| Web UI | `frontend/` | Next.js App Router. Route group `app/(app)` holds the authenticated shell and an auth guard. Pages poll the API; no WebSocket yet. |
| API | `backend/malwarescan/` | FastAPI. OpenAPI at `/api/openapi.json`, Swagger at `/api/docs`. |
| Storage | `backend/malwarescan/db.py`, `migrations/` | SQLite in WAL mode with a versioned migration runner. Named-column insert helper (`db.insert_row`). |
| Detection engine | `engine/` | `scanner.py` orchestrates IOC → YARA-lite → static heuristics → ML → history, then produces verdict/score/explanation. |
| Rule packs | `engine/rules/` | JSON + `.yrl` files, manifest with SHA-256 per file, hot reload, optional checksum-verified remote update. |
| Monitoring | `monitoring/` | Process, network, log, FIM collectors. Each writes storage rows and raises deduplicated alerts. |
| Correlation | `alerting.py` | Dedup key, counters, thresholds, escalation, suppressions, incident auto-open, auto-response hooks. |
| Response | `response/playbooks.py` | Every playbook records `pending → precheck → executed → verified` (or `rolled_back`) with JSON evidence. |
| Vulnerability & SCA | `vuln/` | Inventory via `importlib.metadata` and tool `--version` output; SCA probes read `/etc`, `/proc/sys`, sockets, Docker. |
| Workers | `workers.py` | Supervised loops with per-job health (last run, duration, error) shown in the UI. |
| Agent | `agent/malwarescan_agent.py` | Stdlib + psutil. Enroll → heartbeat/process push → honours isolation. |

## Data flow for a scan

1. `POST /api/scans/upload` streams the body to `uploads/.tmp_*`, rejects >limit or empty, hashes while streaming, then renames to `uploads/<sha256>` (0600).
2. A `scans` row is inserted (`status=queued`). A daemon thread runs `run_scan_pipeline`.
3. Progress is written at 5 → 15 → 35 → 85 → 100 %. The UI polls `GET /api/scans/{id}`.
4. Results are persisted: verdict, score, factors, detections, static analysis (`static_json`), ML contributions.
5. Malicious/suspicious verdicts create or update a deduplicated alert (dedup key = sha256 + verdict, 24 h window).

## Why SQLite and one worker (and the upgrade path)

SQLite in WAL mode handles this workload on one host: single-writer serialization is enforced by a process-wide lock, and reads never block writes. The cost is that rate limiting, the scan queue and background monitors live in one process. Running several API workers would duplicate monitors and split the rate-limit counters, so the container runs `--workers 1`.

The documented upgrade path when a single node is no longer enough:

1. Move the database to PostgreSQL behind the same repository functions (`db.query`, `db.execute`, `db.insert_row`).
2. Move the rate limiter to Redis and the scan queue to a worker pool (RQ/Celery), leaving one scheduler process for monitors.
3. Add an event search backend (OpenSearch) for log and network volume, fed from the same ingest functions.

These are **not implemented** in this release; the single-node design is what has been tested.

## Failure behaviour

- A broken YARA rule is reported as a factor and skipped; scanning continues.
- A failed worker iteration records `status=error` with the traceback tail; the loop keeps running on its interval.
- A failed write rolls back the transaction, so one bad request cannot lock the database for everyone (regression-tested).
- Remote calls (NVD, feeds, LLM, rule updates) time out and return explicit errors.
