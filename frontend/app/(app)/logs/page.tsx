"use client";

import { useEffect, useState, useCallback } from "react";
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from "recharts";
import { api, fmtTime } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Alert, Badge, Empty, Panel, Pager, useToast } from "@/components/ui";

const LIMIT = 50;

export default function LogsPage() {
  const { can } = useAuth();
  const toast = useToast();
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("");
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<any | null>(null);
  const [stats, setStats] = useState<any | null>(null);
  const [sources, setSources] = useState<any | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [testLine, setTestLine] = useState("Failed password for root from 203.0.113.9 port 22 ssh2");
  const [testRes, setTestRes] = useState<any | null>(null);
  const [ingest, setIngest] = useState("");

  const load = useCallback(() => {
    const p = new URLSearchParams({ limit: String(LIMIT), offset: String(offset) });
    if (q) p.set("q", q);
    if (sev) p.set("severity", sev);
    api(`/api/logs?${p}`).then(setData).catch((e) => setErr(e.message));
  }, [q, sev, offset]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const f = () => { api("/api/logs/stats").then(setStats).catch(() => {}); api("/api/logs/sources").then(setSources).catch(() => {}); };
    f(); const t = setInterval(f, 20000); return () => clearInterval(t);
  }, []);

  const test = async () => {
    try { setTestRes(await api("/api/logs/test-match", { method: "POST", json: { line: testLine } })); }
    catch (e: any) { toast("error", e.message); }
  };
  const doIngest = async () => {
    const lines = ingest.split("\n").map((l) => l.trim()).filter(Boolean);
    if (!lines.length) return;
    try {
      const r = await api("/api/logs/ingest", { method: "POST", json: { lines, source: "manual-paste" } });
      toast("ok", `${r.accepted} line(s) ingested · ${r.matched} matched · ${r.alert_ids.length} alert(s)`);
      setIngest(""); load();
    } catch (e: any) { toast("error", e.message); }
  };

  return (
    <>
      <div className="page-head"><div><h1>Log analysis</h1>
        <div className="sub">Local log tails, pushed agent logs and Suricata/Zeek EVE events are matched against {"detection rules"}. Repeated auth failures escalate automatically.</div></div></div>
      {err && <Alert>{err}</Alert>}

      <div className="grid g-4" style={{ marginBottom: 16 }}>
        <Panel><div className="faint" style={{ fontSize: 12 }}>Stored lines</div><b style={{ fontSize: 26 }}>{stats?.total ?? "—"}</b><div className="faint" style={{ fontSize: 12 }}>retention {stats?.retention_days ?? "?"} days</div></Panel>
        <Panel><div className="faint" style={{ fontSize: 12 }}>High / critical</div><b style={{ fontSize: 26, color: "#ff8fa3" }}>{(stats?.by_severity?.high || 0) + (stats?.by_severity?.critical || 0)}</b></Panel>
        <Panel><div className="faint" style={{ fontSize: 12 }}>Rule matches</div><b style={{ fontSize: 26 }}>{(stats?.by_rule || []).reduce((a: number, r: any) => a + r.c, 0)}</b></Panel>
        <Panel title="Sources">{(sources?.sources || []).map((s: any) => <div key={s.path} className="row" style={{ fontSize: 12 }}><Badge value={s.status === "tailing" ? "online" : s.status} /><span className="mono wrap">{s.path}</span></div>)}
          {sources && sources.sources.length === 0 && <span className="faint">none configured</span>}</Panel>
      </div>

      <div className="grid g-main" style={{ marginBottom: 16 }}>
        <Panel title="Activity by rule" actions={<span className="faint" style={{ fontSize: 12 }}>top matches</span>}>
          {!stats || stats.by_rule.length === 0 ? <Empty title="No rule matches yet" hint="Paste lines below or wait for local tails." /> : (
            <div style={{ width: "100%", height: 260 }}><ResponsiveContainer><BarChart data={stats.by_rule.slice(0, 10)} layout="vertical" margin={{ left: 20 }}>
              <XAxis type="number" stroke="#4d5f85" fontSize={11} allowDecimals={false} /><YAxis type="category" dataKey="matched_rule" width={190} stroke="#7e91b5" fontSize={11} />
              <Tooltip contentStyle={{ background: "#0b1430", border: "1px solid rgba(34,211,238,.3)", borderRadius: 10 }} />
              <Bar dataKey="c" fill="#22d3ee" radius={[0, 6, 6, 0]} /></BarChart></ResponsiveContainer></div>)}
        </Panel>
        <Panel title="Rule tester (dry run, nothing stored)">
          <div className="stack">
            <textarea aria-label="Log line to test" value={testLine} onChange={(e) => setTestLine(e.target.value)} />
            <div><button className="btn" onClick={test}>Test against rules</button></div>
            {testRes && <div className={`alert-box ${testRes.result?.matched_rule ? "error" : "ok"}`}>{testRes.result?.matched_rule ? <>Matched <b className="mono">{testRes.result.matched_rule}</b> · {testRes.result.severity}</> : "No rule matched this line."}</div>}
            {can("logs:read") && (<div className="stack" style={{ borderTop: "1px solid var(--border)", paddingTop: 10 }}>
              <label className="field">Ingest lines (one per line, max 2000)<textarea aria-label="Lines to ingest" value={ingest} onChange={(e) => setIngest(e.target.value)} /></label>
              <div><button className="btn ghost" disabled={!ingest.trim()} onClick={doIngest}>Ingest & analyze</button></div></div>)}
          </div>
        </Panel>
      </div>

      <Panel actions={<div className="row">
        <input aria-label="Search logs" className="search" placeholder="Search raw log text" value={q} onChange={(e) => { setQ(e.target.value); setOffset(0); }} />
        <select aria-label="Severity" value={sev} onChange={(e) => { setSev(e.target.value); setOffset(0); }}>
          <option value="">All severities</option>{["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}</select></div>} title="Log search">
        {!data ? null : data.logs.length === 0 ? <Empty title="No log lines match" /> : (
          <>
            <div className="table-wrap"><table>
              <thead><tr><th>Time</th><th>Source</th><th>Severity</th><th>Rule</th><th>Line</th><th>Alert</th></tr></thead>
              <tbody>{data.logs.map((l: any) => (
                <tr key={l.id}><td className="faint mono" style={{ fontSize: 11.5 }}>{fmtTime(l.ts)}</td><td className="faint" style={{ fontSize: 12 }}>{l.source}</td>
                  <td><Badge value={l.severity} /></td><td className="mono" style={{ fontSize: 11.5 }}>{l.matched_rule || "—"}</td>
                  <td className="wrap mono" style={{ fontSize: 11.5, maxWidth: 560 }}>{l.raw}</td><td>{l.alert_id ? <a href={`/alerts?focus=${l.alert_id}`}>#{l.alert_id}</a> : ""}</td></tr>))}</tbody></table></div>
            <Pager offset={offset} limit={LIMIT} total={data.total} onChange={setOffset} />
          </>)}
      </Panel>
    </>
  );
}
