# Malware Scan — security model

> This document covers the **Malware Scan** platform (`backend/`, `frontend/`, `agent/`). The repository's root `SECURITY.md` and the `shadowscan/` tool are a separate, earlier project.

## Threat model in one paragraph

Malware Scan receives untrusted files, process and network telemetry from endpoints, and analyst commands that can change systems (quarantine, process termination, firewall rules). The design goals are: never execute submitted content; never let a low-privilege user change state; make every state change reversible or explicitly irreversible-and-confirmed; keep an audit trail; and avoid leaking secrets or sample content.

## Controls implemented

### Authentication
- Passwords: PBKDF2-HMAC-SHA256, 210 000 iterations (configurable), per-user 128-bit salt, constant-time comparison.
- Minimum length 8, maximum 256. Usernames and emails validated.
- Account lockout after `MALWARESCAN_LOGIN_MAX_FAILURES` failures for `MALWARESCAN_LOGIN_LOCKOUT_MINUTES`.
- Disabled accounts cannot log in; existing tokens are rejected on the next request because every request reloads the user.
- Tokens: JWT (HS256) with `exp`. Session length is `MALWARESCAN_TOKEN_MINUTES` (default 12 h). Logout is client-side plus an audit record; JWTs are stateless, so a stolen token remains valid until expiry. Shorten the lifetime or add server-side revocation if that is unacceptable.
- Self-registration is controllable: after the first account, `allow_registration` can be turned off and new accounts receive a configurable non-admin role.
- The first account becomes admin. If `MALWARESCAN_ADMIN_PASSWORD` is unset, a random password is printed once at first boot.

### Authorization (RBAC)
Four roles: `admin`, `analyst`, `responder`, `viewer`. Permissions are enforced by FastAPI dependencies on every route. Role changes apply on the next request. The full matrix is in `backend/malwarescan/security.py` and is shown in Admin → Users. Automated tests cover the matrix (`backend/tests/test_security.py`) and representative routes (`backend/tests/test_api.py`).

| Action | viewer | analyst | responder | admin |
|---|---|---|---|---|
| Read alerts, scans, logs, reports | ✔ | ✔ | ✔ | ✔ |
| Upload / path-scan files | ✘ | ✔ | ✘ | ✔ |
| Quarantine / restore | ✘ | ✘ | ✔ | ✔ |
| Dry-run response | ✘ | ✔ | ✔ | ✔ |
| Live response (execute) | ✘ | ✘ | ✔ | ✔ |
| Users, settings, rules, audit | ✘ | ✘ | ✘ | ✔ |

### Secure file handling
- Uploads are streamed to a temporary file with a size cap (`MALWARESCAN_UPLOAD_MAX_BYTES`, default 200 MB), hashed as they arrive, and never executed. Empty uploads are rejected.
- Filenames are reduced to a basename and sanitized before storage or display. Directory traversal in filenames is tested.
- Stored samples are written 0600 under `data/uploads/<sha256>`.
- Quarantined samples are encrypted with AES-256-GCM. The key is derived from the app secret, so **losing the secret makes quarantined samples unrecoverable**; back up the secret with the data volume.
- Quarantine writes an encrypted copy, verifies it decrypts to the original hash, and only then removes the original. Restore decrypts, verifies the hash, and refuses to overwrite an existing file.
- The path-scan and YARA-sweep endpoints read files only; they never change them.

### Response safety
- Every playbook: precheck → act → verify, recorded in `response_actions` with JSON evidence.
- Dry-run is the default in the UI and in auto-response rules.
- Dangerous actions (`kill_process`, `block_ip`, `delete_quarantine`) require `confirm=true` when live.
- `quarantine_file` refuses system-critical prefixes (`/bin`, `/etc`, `/usr/bin`, `C:\Windows`, …).
- `kill_process` refuses PID 1, the platform's own process tree, and a protected-name list.
- `block_ip` refuses loopback and addresses bound on the host, and is disabled for live use unless `MALWARESCAN_RESPONSE_ALLOW_DANGEROUS=true`.
- Rollback exists for quarantine (restore), block (remove rule) and isolation (release). Kill and delete are irreversible and labelled as such.

### Input validation and abuse controls
- All request bodies are Pydantic models with length and pattern limits. Regexes submitted for hunting are compiled with error handling.
- IOC values are type-validated (hash length/hex, IP parse, domain pattern, http(s) URL).
- Rate limits: 600 requests/min per IP by default; 20/min per IP on credential-checking POSTs (login, register, password change). Session checks are not counted, which was a bug found during testing and is now regression-tested.
- Agent endpoints require a credential issued at enrollment. Enrollment tokens are single-use. Only SHA-256 hashes of tokens and credentials are stored.

### Transport and headers
- Responses include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` and a restrictive CSP for the API.
- CORS is restricted to `MALWARESCAN_CORS_ORIGINS`. In the recommended deployment the browser talks only to the web tier, which proxies `/api/*`.
- **TLS is not terminated by the application.** Put the web tier behind an HTTPS reverse proxy. The reference agent verifies TLS by default.

### Containers
- The API and web images run as non-root (uid 10001), with `no-new-privileges`, all capabilities dropped and a read-only root filesystem for the API (state lives in the `/data` volume).
- Only the web tier is published. The API is reachable only inside the compose network.

### Audit
- Security-relevant actions (logins, failed logins, denials, user and role changes, uploads, scans, response actions, rule changes, setting changes, exports) are written to `audit_log` with user, IP and result. Admin → Audit trail shows them.
- The audit log is in the same SQLite database as the data. It is not tamper-evident and is not forwarded anywhere yet.

## Known limitations (read before deploying)

1. **JWT in `localStorage`.** The web UI keeps the token in `localStorage`, so an XSS bug in the UI would expose it. The UI has no `dangerouslySetInnerHTML`, CSP for the web tier is not yet set, and the token lifetime is limited. The hardening path is httpOnly cookies with a CSRF token.
2. **No revocation.** See the token note above.
3. **Single-node.** Rate limits and worker state are per process (see ARCHITECTURE.md).
4. **Secrets in `.env`.** The Docker path reads `deploy/.env`. Use your secret manager in production.
5. **Local host monitoring needs privileges** for full process and socket attribution, and for live firewall changes. Run with the least privilege that the features you need require; the containerized API is intentionally unprivileged and therefore cannot change the host firewall.
6. **Not reviewed by a third party.** No penetration test or external audit has been performed on this release.

## Reporting a vulnerability

Open a private security advisory on the repository, or contact the maintainers directly. Do not post exploit details in public issues.
