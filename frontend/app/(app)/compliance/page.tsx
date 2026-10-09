"use client";

import { useEffect, useState, useCallback } from "react";
import { api, fmtTime } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Alert, Badge, Empty, Panel, useToast } from "@/components/ui";

export default function CompliancePage() {
  const { can } = useAuth();
  const toast = useToast();
  const [overview, setOverview] = useState<any | null>(null);
  const [results, setResults] = useState<any | null>(null);
  const [status, setStatus] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api("/api/compliance").then(setOverview).catch((e) => setErr(e.message));
    api(`/api/sca${status ? `?status=${status}` : ""}`).then(setResults).catch((e) => setErr(e.message));
  }, [status]);
  useEffect(() => { load(); }, [load]);

  const run = async () => {
    setBusy(true);
    try { const r = await api("/api/sca/run", { method: "POST", json: { agent_id: 1 } }); toast("ok", `Assessment: ${r.pass} pass · ${r.fail} fail · ${r.warn} warn · score ${r.score}`); load(); }
    catch (e: any) { toast("error", e.message); } finally { setBusy(false); }
  };

  return (
    <>
      <div className="page-head"><div><h1>Compliance & configuration (SCA)</h1>
        <div className="sub">Read-only probes of real system state: SSH, kernel parameters, permissions, firewall, patching, auditing, Docker. Each failure has evidence and a remediation step you apply yourself.</div></div>
        <div className="actions">{can("sca:read") && <button className="btn" disabled={busy} onClick={run}>{busy ? "Assessing…" : "Run assessment"}</button>}</div></div>
      {err && <Alert>{err}</Alert>}
      {overview && (
        <div className="grid g-main" style={{ marginBottom: 16 }}>
          <Panel tilt title="Overall compliance">
            <div className="row"><b style={{ fontSize: 40 }}>{overview.overall_pct}%</b><span className="faint">of checks passing (latest run)</span></div>
            <div className={`bar ${overview.overall_pct < 60 ? "danger" : overview.overall_pct < 85 ? "warn" : ""}`} style={{ marginTop: 10 }}><span style={{ width: `${overview.overall_pct}%` }} /></div>
            <p className="faint" style={{ fontSize: 12, marginTop: 10 }}>{overview.framework_note}</p>
          </Panel>
          <Panel title="By control family">
            {overview.families.length === 0 ? <Empty title="No assessment yet" /> : (
              <div className="stack" style={{ gap: 8 }}>{overview.families.map((f: any) => (
                <div key={f.family}><div className="row" style={{ fontSize: 13 }}><span>{f.family}</span><span className="right faint">{f.passed}/{f.total} pass · {f.failed} fail</span></div>
                  <div className="bar" style={{ height: 6 }}><span style={{ width: `${f.compliance_pct}%` }} /></div></div>))}</div>)}
          </Panel>
        </div>)}
      <Panel actions={<select aria-label="Filter status" value={status} onChange={(e) => setStatus(e.target.value)}>
        <option value="">All results</option><option value="fail">Fail</option><option value="warn">Warn</option><option value="pass">Pass</option><option value="error">Error</option></select>}>
        {!results ? null : results.results.length === 0 ? <Empty title="No results" hint="Run an assessment to populate this table." /> : (
          <>
            <div className="faint" style={{ fontSize: 12, marginBottom: 8 }}>Last run {fmtTime(results.last_run)} · {Object.entries(results.counts).map(([k, v]) => `${k}: ${v}`).join(" · ")}</div>
            <div className="table-wrap"><table>
              <thead><tr><th>Status</th><th>Check</th><th>Severity</th><th>Evidence</th><th>Remediation</th></tr></thead>
              <tbody>{results.results.map((r: any) => (
                <tr key={r.id}><td><Badge value={r.status} /></td>
                  <td className="wrap"><b>{r.title}</b><div className="faint mono" style={{ fontSize: 11 }}>{r.check_id} · {r.framework}</div><div className="faint" style={{ fontSize: 12, marginTop: 3 }}>{r.rationale}</div></td>
                  <td><Badge value={r.severity} /></td><td className="wrap mono" style={{ fontSize: 12, maxWidth: 360 }}>{r.evidence}</td>
                  <td className="wrap" style={{ fontSize: 12.5, maxWidth: 320 }}>{r.status === "pass" ? <span className="faint">—</span> : r.remediation}</td></tr>))}</tbody></table></div>
          </>)}
      </Panel>
    </>
  );
}
