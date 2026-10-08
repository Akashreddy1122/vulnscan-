# ShadowScan

**ShadowScan is a scope-controlled, modular security assessment tool for authorized testing.** It provides bounded reconnaissance, read-only configuration checks, conservative web probes, offline CVE correlation, persistent scan history, and local reports. It is not an exploit framework, and a clean report does **not** mean a target is secure.

> **Authorization required.** Scan only assets you own or are explicitly permitted to assess. Network scans may trigger alerts or affect fragile services. The CLI requires `--authorized` or interactive confirmation; API requests require an explicit authorization assertion.

## Quick start

Python **3.10 or later** is required. Create a virtual environment:

```bash
python -m venv .venv
. .venv/bin/activate                 # Windows: .venv\Scripts\activate
python -m pip install -e .
shadowscan --list-modules
shadowscan -t https://owned.example --authorized --profile quick --output report.html
```

Optional features: `pip install -e '.[pdf,socks,test,audit]'` (`audit` installs Ruff and pip-audit). Runtime and optional dependencies are pinned in `pyproject.toml`; `requirements.txt` contains only required runtime packages. Unused heavyweight libraries are not installed.

## Common commands

```bash
# A few explicitly selected web checks on a supplied URL and its query parameters
shadowscan -t 'https://owned.example/search?q=test' --authorized --modules headers,cors,xss,sqli

# TCP connect inventory of an authorized CIDR; UDP inventory is a separate explicit option
shadowscan -t 192.0.2.0/28 --authorized --port-scan --ports 22,80,443 --format json
shadowscan -t 192.0.2.10 --authorized --udp-ports 53,161

# Explicit full TCP port inventory for ONE target; can take many hours at the default rate
shadowscan -t 192.0.2.10 --authorized --port-scan --all-ports

# DNS-only subdomain guesses: no newly discovered host is automatically scanned
shadowscan -t owned.example --authorized --recon-only --include-subdomains

# Inspect locally supplied JWT metadata without contacting a target
shadowscan -t owned.example --authorized --passive --modules jwt --jwt-env MY_JWT

# Resume and compare saved scans
shadowscan --resume SCAN_ID --authorized --db shadowscan.db
shadowscan -t owned.example --authorized --compare PREVIOUS_SCAN_ID --db shadowscan.db
```

`-t` accepts an IP address, bounded IPv4 range, CIDR, domain, HTTP(S) URL, target-list file, or `-` for stdin. Query strings and target URLs are stored in scan history and reports—**do not put secrets in them**. `--profile quick` is the default; `standard` enables common checks, and `full` selects all *implemented* modules, **not** all ports or every vulnerability class. Use `--list-modules` for the current registry.

### Configuration, pace, and scope

Pass `--config path.yaml` or a JSON file to override keys in [`shadowscan/config/default_config.yaml`](shadowscan/config/default_config.yaml). Bounds apply to targets, concurrency, rate, timeout, response size, crawl depth, TCP/UDP port lists, and user-agent lists. `--delay` adds pacing; `--stealth` slows and jitters requests but does **not** provide IDS evasion.

HTTP requests stay on the **exact scheme, hostname, and effective port** selected for that target. Redirects are never followed; response bodies are capped; per-target DNS answers are cached for the HTTP session. The crawler reads `robots.txt`, safely parses the same-host sitemap, and does not submit forms or execute JavaScript. Direct TCP/UDP plugins touch only configured ports. Proxy routing is trusted infrastructure and may resolve names differently from the local scanner.

### Authentication and proxies

Prefer HTTPS. Credentials in environment variables are less exposed than command-line arguments:

```bash
export SCAN_BASIC='user:password'
shadowscan -t https://owned.example --authorized --auth-basic-env SCAN_BASIC
```

Supported: `--auth-basic-env`, `--auth-digest-env` (`user:password`), `--auth-bearer-env`, and `--auth-cookie`. **Credentials over plain HTTP are refused by default**; the unsafe `--allow-insecure-auth --authorized` override is available for explicitly approved test environments. Command-line cookies remain visible in shell history/process listings. Credentials are not saved in results, but authenticated **target URLs and response observations may be**.

`--proxy` accepts a single HTTP(S), SOCKS4, or SOCKS5 URL (SOCKS requires the `socks` extra); `--proxy-list` rotates at most 50 HTTP(S) proxies. A proxy operator can observe traffic. Custom headers cannot override request authority or framing headers.

## Implemented checks and interpretation

| Group | Representative checks | Important boundary |
| --- | --- | --- |
| Recon | TCP reachability/connect inventory, bounded UDP replies, A/AAAA DNS, opt-in DNS subdomains, technology and edge-provider hints | Silent UDP ports are **inconclusive**; discovered hosts are not automatically scanned. |
| Web | Headers, cookies, CORS, static CSRF/form/parameter/upload inventory, same-host crawler, API docs, GraphQL shallow introspection, WebSocket Origin handshake, short file-exposure and public-file traversal checks | No form submissions, file uploads, account testing, or browser execution. |
| Query probes | SQL error differential, inert HTML reflection, arithmetic template expressions, redirect Location | These are **leads**, not proof of SQL injection, executable XSS, or exploitability. |
| Network | TLS certificate/negotiated cipher; TLS 1.0/1.1 handshake probes in aggressive mode; SSH/FTP/SMTP greetings and RDP transport negotiation | No credential guessing, mail relay, BlueKeep, or other exploit probes. |
| CMS/CVE | Read-only WordPress/Joomla/Drupal/Magento signals; exact-CPE HTTP banner matches from local NVD data | A reported version or CVE match is not verified software inventory. |

Findings carry severity, confidence, evidence, and remediation. Configuration finding CVSS values are indicative; NVD scores come from imported data. The HTML report is self-contained, sortable, and filterable. JSON, XML, CSV (spreadsheet-formula protected), and optional compact PDF are also supported. Reports and SQLite/log files are created with private permissions where the operating system supports them. Treat all outputs as sensitive.

**Not implemented:** raw-packet SYN/FIN/ACK scans, OS fingerprinting, CT/search-engine feeds, JavaScript rendering, stored/DOM XSS confirmation, time-based SQL extraction, authenticated IDOR/BOLA workflows, XXE/SSRF/OOB command probes, default-credential attacks, Heartbleed/EternalBlue/BlueKeep exploit checks, PostgreSQL, online NVD auto-download, Chart.js, and full HTML/PDF feature parity. There are no empty registered plugins pretending to provide these features.

## CVE data, history, and scheduling

Import a **local NVD 2.0 JSON file** obtained through a trusted channel:

```bash
shadowscan --update-db nvd-export.json --db shadowscan.db
shadowscan -t owned.example --authorized --modules cve --db shadowscan.db
```

Import size is limited to 32 MiB. Only explicitly vulnerable **exact CPE versions** are indexed; wildcard/range and multi-product AND clauses are skipped to avoid false matches. Nothing is fetched from external CVE or exploit services.

For future or recurring scans:

```bash
shadowscan -t owned.example --authorized --schedule-at '2026-10-10T09:00:00+05:30' --repeat-hours 24
shadowscan --run-due --authorized --db shadowscan.db --format json
```

`--run-due` runs eligible jobs **once**. Call it from cron/Task Scheduler for unattended repetition. Jobs persist targets/profile, **not** authentication material. Recurring scans write a delta JSON report; consistent config and authentication are needed for meaningful comparison.

## Optional local REST API

```bash
export SHADOWSCAN_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(36))')"
shadowscan --serve --db shadowscan.db  # loopback 127.0.0.1:8787 only
curl -H "Authorization: Bearer $SHADOWSCAN_API_TOKEN" http://127.0.0.1:8787/modules
curl -H "Authorization: Bearer $SHADOWSCAN_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"authorized":true,"targets":["https://owned.example"],"profile":"quick"}' \
  http://127.0.0.1:8787/scans
```

All routes require the bearer token; POST `/scans` additionally requires `authorized: true`. GET `/scans/{id}` returns the last checkpoint; DELETE `/scans/{id}` cancels the active scan. The API runs one scan at a time and accepts individual URLs/hosts/IPs, not local files, stdin, or CIDRs. It **refuses non-loopback binding** because it has no built-in TLS. For remote access, put an authenticated TLS-terminating reverse proxy in front of the loopback listener and apply network controls.

## Architecture and development

- [`core/`](shadowscan/core) — input validation, exact request scope, rate limiter, HTTP transport, orchestrator, plugin selection.
- [`modules/`](shadowscan/modules) — independently registered async checks, grouped by recon/web/network/CMS/CVE.
- [`database/`](shadowscan/database) — SQLite scan checkpoints, scheduled jobs, offline exact-CPE cache.
- [`reporting/`](shadowscan/reporting) — local exports and new/resolved finding comparison.
- [`tests/`](tests) — in-process HTTP, protocol, API, scheduling, and hardening regression tests.

Create a plugin by subclassing `modules.base.Plugin`, defining `name`, `group`, `active`, and `async scan(context) -> list[Finding]`. Use `context.http` for scoped requests and the shared limiter for raw sockets. See [`examples/plugin_template.py`](examples/plugin_template.py). Installed third-party entry points are loaded **only** with `--enable-third-party`; they execute arbitrary Python and are **not sandboxed**. Install only trusted packages.

Run `pytest -q -W error` and `ruff check shadowscan --select S,E4,E7,E9,F` after installing the `test` and `audit` extras. GitHub Actions runs these checks on Python 3.10–3.12. Dependency advisories should be rechecked regularly with `pip-audit -r requirements.txt --vulnerability-service pypi`; an audit is a point-in-time check, **not** a guarantee of no vulnerabilities. Security boundaries and reporting guidance are also described in [SECURITY.md](SECURITY.md).
