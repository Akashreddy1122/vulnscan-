"use client";

import { useEffect, useState, useCallback } from "react";
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from "recharts";
import { api, fmtTime } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Badge, Empty, Panel, useToast, Pager } from "@/components/ui";

export default function NetworkPage() {
  const { can } = useAuth();
  const toast = useToast();
  const [summary, setSummary] = useState<any | null>(null);
  const [events, setEvents] = useState<any | null>(null);
  const [verdict, setVerdict] = useState("");
  const [q, setQ] = useState("");
  const [off, setOff] = useState(0);

  const load = useCallback(() => {
    api("/api/network/summary").then(setSummary).catch(() => {});
    const p = new URLSearchParams({ limit: "50", offset: String(off) });
    if (verdict) p.set("verdict", verdict);
    if (q) p.set("q", q);
    api(`/api/network/events?${p}`).then(setEvents).catch(() => {});
  }, [verdict, q, off]);
  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [load]);

  const tick = async () => {
    try { const r = await api("/api/network/scan-now", { method: "POST" }); toast("ok", `${r.connections} connection(s) evaluated · ${r.alerts_raised} alert(s)`); load(); }
    catch (e: any) { toast("error", e.message); }
  };

  const tl = (summary?.timeline || []).map((t: any) => ({ hour: t.hour.slice(11) + ":00", total: t.c, flagged: t.flagged }));

  return (
    <>
      <div className="page-head"><div><h1>Network & intrusion detection</h1>
        <div className="sub">Live connection table evaluated against port/direction signatures, process fan-out rules and threat-intel IP indicators. Suricata/Zeek EVE import is available for packet-level sensors.</div></div>
        <div className="actions">{can("network:read") && <button className="btn" onClick={tick}>Sample now</button>}</div></div>

      <div className="grid g-main" style={{ marginBottom: 16 }}>
        <Panel title="Connection activity">
          {tl.length === 0 ? <Empty title="No network samples yet" hint="Press “Sample now” or wait for the 20s monitor tick." /> : (
            <div style={{ width: "100%", height: 220 }}><ResponsiveContainer><AreaChart data={tl}>
              <CartesianGrid stroke="rgba(34,211,238,0.07)" vertical={false} /><XAxis dataKey="hour" stroke="#4d5f85" fontSize={11} /><YAxis stroke="#4d5f85" fontSize={11} />
              <Tooltip contentStyle={{ background: "#0b1430", border: "1px solid rgba(34,211,238,.3)", borderRadius: 10 }} />
              <Area type="monotone" dataKey="total" stroke="#22d3ee" fill="rgba(34,211,238,.12)" /><Area type="monotone" dataKey="flagged" stroke="#ff4d6d" fill="rgba(255,77,109,.22)" /></AreaChart></ResponsiveContainer></div>)}
        </Panel>
        <Panel title="Listening services">
          {!summary ? null : summary.listeners.length === 0 ? <Empty title="No listeners visible" hint="Some listeners need elevated privileges for process attribution." /> : (
            <div className="table-wrap" style={{ maxHeight: 240 }}><table><thead><tr><th>Port</th><th>Process</th><th>Bind</th></tr></thead>
              <tbody>{summary.listeners.map((l: any, i: number) => <tr key={i}><td className="mono">{l.port}</td><td>{l.process || "?"}</td><td className="mono faint">{l.src}</td></tr>)}</tbody></table></div>)}
        </Panel>
      </div>

      <Panel actions={<div className="row">
        <input aria-label="Search connections" className="search" placeholder="IP or process" value={q} onChange={(e) => { setQ(e.target.value); setOff(0); }} />
        <select aria-label="Verdict" value={verdict} onChange={(e) => { setVerdict(e.target.value); setOff(0); }}>
          <option value="">All verdicts</option><option value="malicious">Malicious (IOC)</option><option value="suspicious">Suspicious</option><option value="attention">Attention</option><option value="benign">Benign</option></select></div>} title="Connection events">
        {!events ? null : events.events.length === 0 ? <Empty title="No events match" /> : (
          <>
            <div className="table-wrap"><table>
              <thead><tr><th>When</th><th>Verdict</th><th>Direction</th><th>Process</th><th>Local → Remote</th><th>Reason</th></tr></thead>
              <tbody>{events.events.map((e: any) => (
                <tr key={e.id}><td className="faint mono" style={{ fontSize: 11.5 }}>{fmtTime(e.ts)}</td><td><Badge value={e.verdict} /></td><td><span className="badge">{e.direction}</span></td>
                  <td>{e.process || "?"} <span className="faint">pid {e.pid ?? "?"}</span></td>
                  <td className="mono" style={{ fontSize: 12 }}>{e.src}:{e.sport} → {e.dst || "—"}:{e.dport ?? ""}</td>
                  <td className="wrap" style={{ fontSize: 12.5 }}>{e.reason || "—"}</td></tr>))}</tbody></table></div>
            <Pager offset={off} limit={50} total={events.total} onChange={setOff} />
          </>)}
      </Panel>
    </>
  );
}
