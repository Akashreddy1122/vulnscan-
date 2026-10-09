"use client";

import { useEffect, useState, useCallback } from "react";
import { api, fmtTime, timeAgo } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Badge, Empty, Panel, Alert, useToast, Drawer } from "@/components/ui";

export default function IncidentsPage() {
  const { can } = useAuth();
  const toast = useToast();
  const [status, setStatus] = useState("");
  const [items, setItems] = useState<any[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [openId, setOpenId] = useState<number | null>(null);
  const [detail, setDetail] = useState<any | null>(null);
  const [note, setNote] = useState("");

  const load = useCallback(() => {
    api(`/api/incidents?limit=100${status ? `&status=${status}` : ""}`).then((r) => setItems(r.incidents)).catch((e) => setErr(e.message));
  }, [status]);
  useEffect(() => { load(); const t = setInterval(load, 12000); return () => clearInterval(t); }, [load]);

  const openDetail = (id: number) => {
    setOpenId(id);
    api(`/api/incidents/${id}`).then(setDetail).catch((e) => toast("error", e.message));
  };

  const update = async (body: any) => {
    if (!openId) return;
    try {
      const d = await api(`/api/incidents/${openId}`, { method: "POST", json: body });
      setDetail(d); setNote(""); load();
      toast("ok", "Incident updated");
    } catch (e: any) { toast("error", e.message); }
  };

  return (
    <>
      <div className="page-head"><div><h1>Incidents</h1>
        <div className="sub">Auto-opened when a critical alert appears or several high-severity alerts correlate on one endpoint within 30 minutes. Every change is on the timeline.</div></div>
        <div className="actions"><select aria-label="Status filter" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All</option><option value="open">Open</option><option value="investigating">Investigating</option><option value="contained">Contained</option><option value="resolved">Resolved</option></select></div></div>
      {err && <Alert>{err}</Alert>}
      <Panel>
        {!items ? null : items.length === 0 ? <Empty title="No incidents" hint="Nothing has correlated into an incident yet." /> : (
          <div className="table-wrap"><table>
            <thead><tr><th>#</th><th>Title</th><th>Severity</th><th>Status</th><th>Risk</th><th>Alerts</th><th>Updated</th></tr></thead>
            <tbody>{items.map((i) => (
              <tr key={i.id} className="clickable" onClick={() => openDetail(i.id)}>
                <td className="faint">{i.id}</td><td className="wrap"><b>{i.title}</b><div className="faint" style={{ fontSize: 11.5 }}>{i.summary}</div></td>
                <td><Badge value={i.severity} /></td><td><Badge value={i.status} /></td>
                <td><div className="row" style={{ gap: 8 }}><div className={`bar ${i.risk_score >= 60 ? "danger" : ""}`} style={{ width: 70 }}><span style={{ width: `${i.risk_score}%` }} /></div>{i.risk_score}</div></td>
                <td>{i.alert_count}</td><td className="faint">{timeAgo(i.updated_at)}</td>
              </tr>))}</tbody></table></div>)}
      </Panel>

      <Drawer open={openId !== null} onClose={() => { setOpenId(null); setDetail(null); }} title={detail ? `Incident #${detail.id}` : "Incident"}>
        {!detail ? <div className="muted">Loading…</div> : (
          <div className="stack">
            <div className="row"><Badge value={detail.severity} /> <Badge value={detail.status} /> <span className="faint">risk {detail.risk_score}/100 · opened {fmtTime(detail.created_at)}</span></div>
            <h2 style={{ fontSize: 18 }}>{detail.title}</h2>
            <p className="muted">{detail.summary}</p>
            <Panel title={`Alerts (${detail.alerts.length})`}>
              {detail.alerts.map((a: any) => a && (<div key={a.id} className="row" style={{ padding: "6px 0", borderBottom: "1px solid var(--border)" }}>
                <Badge value={a.severity} /><span className="wrap">{a.title}</span><Badge value={a.status} /></div>))}
            </Panel>
            <Panel title="Timeline">
              <div className="timeline">
                {[...detail.timeline].reverse().map((t: any, i: number) => (
                  <div key={i} className={`tl-item sev-${t.event === "response" ? "info" : "low"}`}>
                    <div className="when">{fmtTime(t.ts)} · {t.event}</div><div style={{ fontSize: 13.5 }}>{t.detail}</div></div>))}
              </div>
            </Panel>
            {detail.actions?.length > 0 && <Panel title="Response actions">{detail.actions.map((a: any) => <div key={a.id} className="row"><span className="mono">{a.playbook}</span><span className="faint">{a.target}</span><Badge value={a.status} /></div>)}</Panel>}
            {can("incidents:write") && (
              <Panel title="Work the incident">
                <div className="stack">
                  <textarea aria-label="Investigation note" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a timeline note…" />
                  <div className="row">
                    <button className="btn" disabled={!note.trim()} onClick={() => update({ note })}>Add note</button>
                    <button className="btn" onClick={() => update({ status: "investigating" })}>Investigating</button>
                    <button className="btn" onClick={() => update({ status: "contained" })}>Contained</button>
                    <button className="btn primary" onClick={() => update({ status: "resolved", note: note || undefined })}>Resolve</button>
                  </div>
                </div>
              </Panel>)}
          </div>)}
      </Drawer>
    </>
  );
}
