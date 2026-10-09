"use client";

import { useEffect, useState, useCallback } from "react";
import { Server, KeyRound, Copy } from "lucide-react";
import { api, timeAgo, fmtTime } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Badge, Empty, Panel, Alert, useToast } from "@/components/ui";

export default function AgentsPage() {
  const { user, can } = useAuth();
  const toast = useToast();
  const [agents, setAgents] = useState<any[] | null>(null);
  const [name, setName] = useState("");
  const [token, setToken] = useState<{ name: string; token: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => api("/api/agents").then((r) => setAgents(r.agents)).catch((e) => setErr(e.message)), []);
  useEffect(() => { load(); const t = setInterval(load, 10000); return () => clearInterval(t); }, [load]);

  const issue = async () => {
    try { const r = await api("/api/agents", { method: "POST", json: { name } }); setToken({ name, token: r.enroll_token }); setName(""); toast("ok", "Enrollment token issued — shown once"); load(); }
    catch (e: any) { toast("error", e.message); }
  };

  return (
    <>
      <div className="page-head"><div><h1>Endpoints</h1>
        <div className="sub">The server monitors its own host as <b>local-host</b>. Remote endpoints enroll with a one-time token, then push heartbeats, logs, process snapshots and file samples. Isolation is enforced by the agent on check-in.</div></div></div>
      {err && <Alert>{err}</Alert>}

      <Panel title={`Fleet (${agents?.length ?? 0})`}>
        {!agents ? null : agents.length === 0 ? <Empty title="No endpoints yet" /> : (
          <div className="table-wrap"><table>
            <thead><tr><th>Endpoint</th><th>Status</th><th>OS</th><th>Risk</th><th>Open alerts</th><th>Metrics</th><th>Last heartbeat</th></tr></thead>
            <tbody>{agents.map((a) => (
              <tr key={a.id}>
                <td><div className="row"><Server size={14} color="#22d3ee" /><b>{a.name}</b></div><div className="faint" style={{ fontSize: 11.5 }}>{a.hostname} · {a.ip}</div></td>
                <td><span className={`dot ${a.status === "online" ? "on" : a.status === "isolated" ? "warn" : "off"}`} /> <Badge value={a.status} /></td>
                <td>{a.os}<div className="faint" style={{ fontSize: 11.5 }}>{a.os_version}</div></td>
                <td>{a.risk ? <div className="row" style={{ gap: 8 }}><div className={`bar ${a.risk.score >= 60 ? "danger" : ""}`} style={{ width: 70 }}><span style={{ width: `${a.risk.score}%` }} /></div>{a.risk.score}</div> : <span className="faint">—</span>}</td>
                <td>{a.open_alerts}</td>
                <td className="mono faint" style={{ fontSize: 11.5 }}>{a.metrics?.cpu_percent !== undefined ? `cpu ${Math.round(a.metrics.cpu_percent)}% · mem ${Math.round(a.metrics.mem_percent ?? 0)}%` : "—"}</td>
                <td className="faint">{timeAgo(a.last_seen)}<div style={{ fontSize: 11 }}>{fmtTime(a.last_seen)}</div></td>
              </tr>))}</tbody></table></div>)}
      </Panel>

      {can("agents:read") && user?.role === "admin" && (
        <div className="grid g-2" style={{ marginTop: 16 }}>
          <Panel title="Enroll a new endpoint" actions={<KeyRound size={15} color="#22d3ee" />}>
            <div className="stack">
              <label className="field">Endpoint name<input value={name} onChange={(e) => setName(e.target.value)} placeholder="web-01" /></label>
              <div><button className="btn primary" disabled={name.trim().length < 2} onClick={issue}>Issue enrollment token</button></div>
              {token && (
                <div className="stack">
                  <Alert kind="warn">Copy this token now. It is shown once, works once, and expires on use.</Alert>
                  <div className="code-block mono" style={{ fontSize: 12 }}>{token.token}</div>
                  <button className="btn ghost sm" onClick={() => { navigator.clipboard?.writeText(token.token); toast("ok", "Copied to clipboard"); }}><Copy size={12} /> Copy</button>
                  <p className="faint" style={{ fontSize: 12 }}>The agent calls <span className="mono">POST /api/agent/enroll</span> with this token and receives a long-lived credential, which is stored only as a hash on the server.</p>
                </div>)}
            </div>
          </Panel>
          <Panel title="Agent API">
            <ul className="muted" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.8, fontSize: 13 }}>
              <li><span className="mono">POST /api/agent/heartbeat</span> metrics + liveness</li>
              <li><span className="mono">POST /api/agent/logs</span> batched log lines (rule-matched)</li>
              <li><span className="mono">POST /api/agent/processes</span> process snapshots (EDR rules)</li>
              <li><span className="mono">POST /api/agent/scan</span> base64 file sample → full scan</li>
            </ul>
            <p className="faint" style={{ fontSize: 12, marginTop: 10 }}>Interactive API docs: <a href="/api/docs" target="_blank" rel="noreferrer">/api/docs</a></p>
          </Panel>
        </div>)}
    </>
  );
}
