"use client";

import { useEffect, useState, useCallback } from "react";
import { ShieldCheck, Undo2, Play } from "lucide-react";
import { api, fmtTime } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Alert, Badge, Empty, Panel, useToast } from "@/components/ui";

const TARGET_EXAMPLE: Record<string, string> = {
  quarantine_file: "/absolute/path/to/suspicious.bin",
  kill_process: "1234 (process id)",
  block_ip: "203.0.113.66",
  isolate_agent: "agent id (number)",
  release_agent: "agent id (number)",
};

export default function ResponsePage() {
  const { can } = useAuth();
  const toast = useToast();
  const [pbs, setPbs] = useState<any[] | null>(null);
  const [actions, setActions] = useState<any[] | null>(null);
  const [pb, setPb] = useState("quarantine_file");
  const [target, setTarget] = useState("");
  const [reason, setReason] = useState("");
  const [dry, setDry] = useState(true);
  const [confirm, setConfirm] = useState(false);
  const [result, setResult] = useState<any | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api("/api/response/playbooks").then((r) => setPbs(r.playbooks)).catch(() => setPbs([]));
    api("/api/response/actions?limit=60").then((r) => setActions(r.actions)).catch(() => setActions([]));
  }, []);
  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [load]);

  const current = pbs?.find((p) => p.name === pb);
  const needsConfirm = !!current?.dangerous && !dry;

  const run = async () => {
    setBusy(true); setResult(null);
    try {
      const r = await api("/api/response/execute", { method: "POST", json: {
        playbook: pb, target: target.trim(), dry_run: dry, confirm, params: reason ? { reason } : {} } });
      setResult(r);
      if (r.ok) toast("ok", dry ? "Dry run passed — no changes made" : `Action ${r.action_id} verified`);
      else toast("error", r.error || (r.problems || []).join("; ") || "Action refused by safety checks");
      load();
    } catch (e: any) { setResult({ ok: false, error: e.message }); toast("error", e.message); }
    finally { setBusy(false); }
  };

  const rollback = async (id: number) => {
    try { const r = await api(`/api/response/actions/${id}/rollback`, { method: "POST", json: {} }); toast("ok", `Rolled back (${r.ok ? "ok" : "check details"})`); load(); }
    catch (e: any) { toast("error", e.message); }
  };

  return (
    <>
      <div className="page-head"><div><h1>Automated response</h1>
        <div className="sub">Playbooks run prechecks, perform the action, verify the outcome and record everything. Dry-run is the default. Dangerous actions need explicit confirmation and policy opt-in.</div></div></div>

      <div className="grid g-main" style={{ marginBottom: 16 }}>
        <Panel title="Run a playbook" actions={<ShieldCheck size={16} color="#22d3ee" />}>
          {!can("response:dry_run") ? <Alert kind="warn">Your role cannot run response playbooks.</Alert> : (
            <div className="stack">
              <div className="grid g-2">
                <label className="field">Playbook
                  <select value={pb} onChange={(e) => { setPb(e.target.value); setResult(null); }}>
                    {(pbs || []).filter((p) => p.executable).map((p) => <option key={p.name} value={p.name}>{p.name}{p.dangerous ? " (dangerous)" : ""}</option>)}
                  </select></label>
                <label className="field">Target <span className="faint">e.g. {TARGET_EXAMPLE[pb]}</span>
                  <input value={target} onChange={(e) => setTarget(e.target.value)} aria-label="Target" /></label>
              </div>
              <label className="field">Reason (recorded in audit)
                <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why are you running this?" /></label>
              {current && <p className="muted" style={{ fontSize: 13 }}>{current.description} {current.reversible ? <Badge value="reversible" /> : <Badge value="irreversible" />}</p>}
              <div className="row">
                <label className="check"><input type="checkbox" checked={dry} onChange={(e) => setDry(e.target.checked)} /> Dry run (preview only)</label>
                {!dry && current?.dangerous && <label className="check"><input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} /> I confirm this live action</label>}
              </div>
              {!dry && <Alert kind="warn">Live mode will change the system. Prechecks still apply and refusals are recorded.</Alert>}
              <div><button className={`btn ${dry ? "" : "danger"}`} disabled={busy || !target.trim() || (needsConfirm && !confirm)} onClick={run}>
                <Play size={14} /> {busy ? "Running…" : dry ? "Run dry-run" : "Execute live"}</button></div>
              {result && (
                <div className={`alert-box ${result.ok ? "ok" : "error"}`}>
                  <b>{result.ok ? "Completed" : "Refused / failed"}</b>
                  {result.action_id && <> · action #{result.action_id}</>}
                  {result.problems && <ul style={{ margin: "6px 0 0 16px" }}>{result.problems.map((p: string, i: number) => <li key={i}>{p}</li>)}</ul>}
                  {result.error && <div style={{ marginTop: 6 }}>{result.error}</div>}
                  {result.command && <div className="mono" style={{ marginTop: 6 }}>{result.command}</div>}
                  {result.verification && <pre className="code-block" style={{ marginTop: 6 }}>{JSON.stringify(result.verification, null, 2)}</pre>}
                </div>)}
            </div>)}
        </Panel>

        <Panel title="Playbook catalog">
          <div className="stack" style={{ gap: 8 }}>
            {(pbs || []).map((p) => (
              <div key={p.name} style={{ border: "1px solid var(--border)", borderRadius: 10, padding: "8px 10px" }}>
                <div className="row"><b className="mono">{p.name}</b>{p.dangerous && <Badge value="dangerous" />}{!p.executable && <span className="badge">direct API only</span>}
                  <span className="right">{p.reversible ? <Badge value="reversible" /> : <Badge value="irreversible" />}</span></div>
                <div className="faint" style={{ fontSize: 12.5, marginTop: 3 }}>{p.description}</div>
              </div>))}
            <div className="faint" style={{ fontSize: 12 }}>Live firewall blocking requires <span className="mono">MALWARESCAN_RESPONSE_ALLOW_DANGEROUS=true</span> on the server.</div>
          </div>
        </Panel>
      </div>

      <Panel title="Action trail" actions={<span className="faint" style={{ fontSize: 12 }}>every precheck, execution and verification is stored</span>}>
        {!actions ? null : actions.length === 0 ? <Empty title="No response actions yet" /> : (
          <div className="table-wrap"><table>
            <thead><tr><th>#</th><th>When</th><th>Playbook</th><th>Target</th><th>Mode</th><th>Status</th><th>By</th><th>Verification</th><th></th></tr></thead>
            <tbody>{actions.map((a) => (
              <tr key={a.id}>
                <td className="faint">{a.id}</td><td className="faint">{fmtTime(a.ts)}</td>
                <td className="mono">{a.playbook}</td><td className="wrap mono" style={{ fontSize: 11.5 }}>{a.target}</td>
                <td>{a.dry_run ? <Badge value="dry" /> : <Badge value="live" />}</td>
                <td><Badge value={a.status} /></td>
                <td className="faint">{a.requested_by}</td>
                <td className="wrap" style={{ maxWidth: 260 }}>{a.verification ? <span className="mono" style={{ fontSize: 11 }}>{JSON.stringify(a.verification).slice(0, 140)}</span> : <span className="faint">—</span>}</td>
                <td>{a.reversible && a.status !== "rolled_back" && a.playbook !== "delete_quarantine" && can("response:execute") && !a.dry_run && (
                  <button className="btn ghost sm" onClick={() => rollback(a.id)}><Undo2 size={12} /> Roll back</button>)}</td>
              </tr>))}</tbody></table></div>)}
      </Panel>
    </>
  );
}
