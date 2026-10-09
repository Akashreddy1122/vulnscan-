# Malware Scan — feature status (what is real, what is partial, what is optional)

This page is the source of truth for claims. Status legend:

- **Implemented** — code path exists, is exercised by automated tests (`backend/tests`), the API end-to-end suite (`backend/scripts/e2e_test.py`, 158 checks) and/or the browser suite (`frontend/e2e/browser_e2e.mjs`, 46 checks).
- **Partial** — works, with the limits stated.
- **Optional** — implemented, but only active when you configure an external service. Unconfigured, the UI says "not configured"; nothing is simulated.
- **Not implemented** — listed so nobody mistakes it for a feature.

Nothing here claims perfect detection or zero vulnerabilities. See [SECURITY.md](SECURITY.md) and [DETECTION.md](DETECTION.md) for limits.

| Area | Capability | Status | Notes |
|---|---|---|---|
| Malware scanning | Upload scanning (streamed, size-capped, hashed, never executed) | Implemented | Sanitized filenames, 0600 storage, progress in UI |
| | Path scanning of files on the server host | Implemented | Reads only; optional auto-quarantine (policy setting) |
| | Hash/IOC matching (MD5/SHA1/SHA256, built-in + operator IOCs) | Implemented | Built-in pack = documented test indicators only |
| | YARA-subset rules (text, hex with wildcards, regex, nocase/wide/fullword, set conditions, filesize) | Implemented | Parser **rejects** unsupported syntax. Not libyara — see DETECTION.md |
| | Static analysis (entropy, PE/ELF headers, sections, imports, packers, overlay, suspicious strings) | Implemented | Pure Python, parse failures reported as findings |
| | Explainable ML score (logistic regression, per-feature contributions) | Implemented | Trained on generated benign/malicious-shaped inert samples; validated only on that data |
| | Verdicts, 0–100 risk score, severity, explanation, MITRE mapping | Implemented | Every point of score traces to a listed factor |
| | Safe test samples (EICAR, inert webshell/cradle simulators, packed blob) | Implemented | Simulators contain indicator strings only |
| | Dynamic sandbox / detonation | **Not implemented** | The platform never executes samples |
| Ransomware | Shadow-copy/backup deletion, ransom-note and encryption-claim rules | Implemented (rules) | Detection of *encryption behaviour* (mass file rewrites) is limited to FIM event volume; no kernel-level behavioural engine |
| Quarantine | Encrypt-copy → verify hash → remove original; restore with hash check; delete | Implemented | AES-256-GCM at rest; restore never overwrites |
| Logs | Local tails of configured files, agent-pushed lines, bulk ingest | Implemented | Offsets persisted; rotation handled |
| | Rule matching with thresholds and escalation (brute-force) | Implemented | 40+ rules in `log_rules.json` |
| | Suricata / Zeek EVE-JSON import | Implemented (import) | Alert events become IDS alerts; other event types go through the text pipeline |
| FIM | SHA-256 baseline, add/modify/remove/permission change, path-aware severity | Implemented | Polling-based (default 5 min), not inotify/ETW |
| Vulnerabilities | Python package and system-tool inventory, version-range CVE matching | Implemented | Curated offline KB (~40 CVEs). **Not a full NVD mirror** |
| | Aging out of fixed vulnerabilities | Implemented | Mitigated when the version disappears from inventory |
| | NVD online lookup | Optional | `MALWARESCAN_NVD_ENABLED=true` |
| Configuration (SCA) | 25 read-only probes of real system state (SSH, sysctl, permissions, firewall, auditd, time sync, Docker) | Implemented (Linux) | Remediation is advisory; nothing is changed automatically. Windows/macOS probes are limited |
| Compliance | Control-family compliance percentages and trends | Implemented | Not a certification; control families are original wording |
| Process / EDR | Process rules (miners, reverse shells, credential dumping, security tampering, temp-dir execution, deleted binaries, fan-out) | Implemented | psutil; works on Linux, macOS, Windows (rule set is Linux-oriented) |
| Network / IDS | Connection-table monitoring, port/direction signatures, fan-out rule, IOC IP matches | Implemented | Connection metadata only — **no packet capture or payload inspection** |
| Threat hunting | Hash pivot, process history search, directory YARA sweep, rule workbench | Implemented | Sweeps are read-only and capped |
| Threat intel | IOC management with per-type validation; feed pull (JSON) | Implemented / Optional | Remote feeds require `MALWARESCAN_THREAT_FEED_URLS` |
| Rule updates | Manifest with SHA-256 per file; reload; custom rule upload; checksum-verified remote update | Implemented (local) / Optional (remote) | Local manifest, reload and custom upload are tested. The remote download path (`MALWARESCAN_RULES_URL`) is not covered by automated tests |
| Incidents & correlation | Auto-open on critical alerts or ≥2 high alerts per endpoint in 30 min; timeline; risk | Implemented | Correlation is per-endpoint, time-window based |
| Alert tuning | Dedup with counters, thresholds, false-positive workflow, reversible suppressions | Implemented | Suppressions are audited and expire optionally |
| Response | Playbooks with precheck → act → verify → rollback; dry-run default; confirmation for dangerous actions | Implemented | Auto-response rules are opt-in and dry-run by default |
| | Quarantine file, kill process (protected list), isolate/release endpoint | Implemented | Kill is irreversible; PID 1 and the platform's own processes are refused |
| | Block IP via host firewall (iptables / nft / pfctl) | Implemented, **gated** | Live mode needs `MALWARESCAN_RESPONSE_ALLOW_DANGEROUS=true` and host privileges. Dry-run shows the exact command |
| Endpoints | Local host monitoring; remote enrollment (one-time token → hashed long-lived credential); heartbeat, logs, processes, file samples | Implemented | The server agent API is covered by the E2E suite. The reference agent (`agent/malwarescan_agent.py`) was verified manually against a live server (enroll, heartbeat, process push, file upload); it is not part of the automated suites |
| | Agent isolation enforced by the agent on check-in | Implemented (cooperative) | A compromised endpoint may ignore its own isolation flag; pair with network controls |
| Cloud & containers | Docker socket permission and privileged-container SCA checks (local daemon) | Partial | No cloud-provider (AWS/Azure/GCP) posture, no registry or Kubernetes scanning |
| Assistant | Local analyst engine: intents over the live database, cited records, next steps | Implemented | Answers only from DB rows; it is not a general-purpose LLM |
| | External LLM (OpenAI-compatible) | Optional | `MALWARESCAN_LLM_URL`; grounded on a context bundle; UI labels the engine used |
| Reports | HTML, JSON, CSV reports from live data, with a limitations statement | Implemented | Downloads require authentication |
| Auth & RBAC | Registration (policy-controlled), login with lockout, JWT, roles admin/analyst/responder/viewer | Implemented | Role matrix visible in Admin → Users |
| | Audit trail for security-relevant actions and denials | Implemented | Stored in SQLite; no external SIEM forwarder yet |
| | Rate limiting (per IP, strict on credential endpoints) | Implemented | In-process; see OPERATIONS.md for multi-instance caveat |
| Monitoring | Background worker health, liveness, readiness, diagnostics | Implemented | `/api/health`, `/api/health/ready`, Admin → System health |
| Deployment | Docker Compose (API + web), guided installer, env-based configuration | Written, **not container-tested** | Docker was not available in the build environment. The installer's dry-run and the local (non-Docker) path are checked; the Dockerfiles and compose file have not been built |
| Email / Slack / SIEM forwarding | SMTP alerts | **Not implemented** | Config key is reserved and not reported as an integration |
| Sandbox detonation | External sandbox submission | **Not implemented** | Config key is reserved and not reported as an integration |
| Scale | Horizontal API scaling | **Not implemented** | Single-writer SQLite and in-process workers; see ARCHITECTURE.md for the upgrade path |
