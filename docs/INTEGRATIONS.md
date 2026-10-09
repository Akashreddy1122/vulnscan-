# Integrations

Malware Scan works standalone. The integrations below are optional. When one is not configured, the platform reports it as **not configured** (Admin → Integrations) and no feature pretends to use it.

| Integration | Config | What happens when enabled | Tested |
|---|---|---|---|
| NVD CVE lookup | `MALWARESCAN_NVD_ENABLED=true`, `MALWARESCAN_NVD_API_KEY` (optional) | Vulnerability detail view fetches the CVE from the NVD 2.0 API and shows CVSS and publication date. Failures are shown as errors. | The disabled state is tested (honest "not configured" response). The enabled path needs outbound access to NVD and was **not** exercised. |
| Threat feeds | `MALWARESCAN_THREAT_FEED_URLS` (comma-separated) | Intelligence → "Pull now" downloads a JSON array of `{type,value,source,confidence,tags}`, validates each item, and stores valid indicators. | Per-item validation is covered by the IOC API tests. The feed pull itself is **not** exercised by the automated suites. |
| Remote rule packs | `MALWARESCAN_RULES_URL` | `POST /api/admin/rules/update-remote` fetches `manifest.json` and each file; every file's SHA-256 must match before anything is written, and unsafe paths are rejected. | The not-configured state is tested. The download, checksum and swap paths are **not** exercised by automated tests. Review before enabling. |
| External LLM | `MALWARESCAN_LLM_URL` (OpenAI-compatible base URL), `MALWARESCAN_LLM_KEY` | The assistant sends the question and a context bundle built from the database to `…/chat/completions`. If the call fails, it falls back to the local engine and says so. | The local engine (default) is tested. The external path and its fallback are **not** exercised by automated tests. |

## Not implemented

These keys are reserved in the configuration and are **not** reported as integrations, because there is no code path:

- `MALWARESCAN_SANDBOX_URL` / `MALWARESCAN_SANDBOX_KEY` — dynamic sandbox submission.
- `MALWARESCAN_SMTP_ENABLED` — email notifications.

Adding them means writing the client, the failure handling and tests. Do not configure them expecting behaviour.

## Optional: external sensors

- **Suricata / Zeek EVE-JSON.** Post events to `POST /api/logs/ingest/eve`. Alert events become IDS alerts (signature id and severity mapped); other event types are matched against the log rules. This is an import path, not an inline sensor.
- **Syslog or application logs.** Use `POST /api/logs/ingest` with batches of up to 2 000 lines, or configure `MALWARESCAN_LOG_FILES` for local tails.

## Optional: the reference endpoint agent

`agent/malwarescan_agent.py` (Python 3.9+, `psutil`) enrolls with a one-time token, sends heartbeats and process snapshots, and uploads files for scanning. Usage:

```bash
pip install psutil
python agent/malwarescan_agent.py enroll --server https://ms.example --token msa_... --state ~/.msagent.json
python agent/malwarescan_agent.py run --state ~/.msagent.json --interval 60
python agent/malwarescan_agent.py scan --state ~/.msagent.json --file suspicious.bin
```

The agent is intentionally small. It does not run continuously as a system service out of the box, does not collect file-system events, and does not enforce isolation locally. Packaging as a signed service is future work.
