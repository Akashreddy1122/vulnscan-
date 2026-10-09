"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid, BarChart, Bar, Cell } from "recharts";
import { Activity, ShieldAlert, Bug, Archive, FileWarning, Server, Cpu, HardDrive, MemoryStick } from "lucide-react";
import { api, fmtTime, timeAgo } from "@/lib/api";
import { Badge, Empty, Panel, Stat, Alert, Spinner } from "@/components/ui";

type Overview = any;

const SEV_COLORS: Record<string, string> = { critical: "#ff4d6d", high: "#fb923c", medium: "#fbbf24", low: "#22d3ee", info: "#64748b" };

export default function DashboardPage() {
  const [o, setO] = useState<Overview | null>(null);
  const [tl, setTl] = useState<any | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [updated, setUpdated] = useState<string>("");

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [ov, t] = await Promise.all([api("/api/dashboard/overview"), api("/api/dashboard/timeline?hours=24")]);
        if (!alive) return;
        setO(ov);
        setTl(t);
        setErr(null);
        setUpdated(new Date().toLocaleTimeString());
      } catch (e: any) {
        if (alive) setErr(e.message);
      }
    };
    load();
    const id = setInterval(load, 8000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  if (err && !o) return <Alert>{err}</Alert>;
  if (!o || !tl) return <Spinner label="Loading live dashboard…" />;

  const openAlerts = Object.values(o.alerts_by_severity || {}).reduce<number>((a, b) => a + Number(b), 0);
  const critical = o.alerts_by_severity?.critical || 0;
  const agentRisks = o.agents.filter((a: any) => a.risk !== null && a.risk !== undefined).map((a: any) => a.risk);
  const avgRisk = agentRisks.length ? Math.round(agentRisks.reduce((a: number, b: number) => a + b, 0) / agentRisks.length) : null;

  // merge timelines for one chart
  const hours = new Map<string, any>();
  const add = (arr: any[], key: string, field: string) => arr.forEach((r) => {
    const h = hours.get(r.hour) || { hour: r.hour.slice(11) + ":00" };
    h[key] = (h[key] || 0) + (r[field] ?? r.c ?? 0);
    hours.set(r.hour, h);
  });
  add(tl.alerts, "alerts", "c");
  add(tl.alerts, "severe", "severe");
  add(tl.network, "network", "flagged");
  const series = Array.from(hours.values());

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Security overview</h1>
          <div className="sub">Live view · refreshes every 8s · last update {updated} · server time {o.server_time}</div>
        </div>
        <div className="actions">
          <Link className="btn" href="/scan">Scan a file</Link>
          <Link className="btn ghost" href="/alerts">Triage alerts</Link>
        </div>
      </div>
      {err && <div style={{ marginBottom: 12 }}><Alert kind="warn">Live refresh issue: {err}</Alert></div>}

      <div className="grid g-4" style={{ marginBottom: 16 }}>
        <Stat label="Open alerts" value={openAlerts} tone={critical ? "alert" : "default"}
          hint={<>{critical} critical · {o.alerts.last24h} in last 24h</>} icon={<Bug size={15} />} />
        <Stat label="Malicious verdicts" value={o.scans.malicious ?? 0}
          hint={<>{o.scans.suspicious ?? 0} suspicious · {o.scans.total ?? 0} total scans</>} tone={(o.scans.malicious ?? 0) > 0 ? "alert" : "default"} icon={<FileWarning size={15} />} />
        <Stat label="Open incidents" value={o.incidents.open ?? 0} hint={<>{o.incidents.total ?? 0} recorded</>} icon={<Activity size={15} />} />
        <Stat label="Quarantined" value={o.quarantined} hint={<>{o.fim_events_24h} FIM changes (24h)</>} icon={<Archive size={15} />} />
      </div>

      <div className="grid g-main" style={{ marginBottom: 16 }}>
        <Panel title="Activity · last 24 hours" actions={<span className="faint" style={{ fontSize: 12 }}>alerts · severe · flagged network</span>}>
          {series.length === 0 ? (
            <Empty title="No activity in the last 24h" hint="Scans, alerts and monitoring events will appear here as they happen." />
          ) : (
            <div style={{ width: "100%", height: 240 }}>
              <ResponsiveContainer>
                <AreaChart data={series} margin={{ left: -10, right: 10, top: 10 }}>
                  <defs>
                    <linearGradient id="gA" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#22d3ee" stopOpacity={0.5} /><stop offset="95%" stopColor="#22d3ee" stopOpacity={0} /></linearGradient>
                    <linearGradient id="gS" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#ff4d6d" stopOpacity={0.5} /><stop offset="95%" stopColor="#ff4d6d" stopOpacity={0} /></linearGradient>
                  </defs>
                  <CartesianGrid stroke="rgba(34,211,238,0.07)" vertical={false} />
                  <XAxis dataKey="hour" stroke="#4d5f85" fontSize={11} />
                  <YAxis stroke="#4d5f85" fontSize={11} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: "#0b1430", border: "1px solid rgba(34,211,238,.3)", borderRadius: 10 }} />
                  <Area type="monotone" dataKey="alerts" stroke="#22d3ee" fill="url(#gA)" strokeWidth={2} />
                  <Area type="monotone" dataKey="severe" stroke="#ff4d6d" fill="url(#gS)" strokeWidth={2} />
                  <Area type="monotone" dataKey="network" stroke="#a78bfa" fill="none" strokeWidth={1.5} strokeDasharray="4 3" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>

        <Panel title="Endpoint status" tilt>
          <div className="row" style={{ marginBottom: 10 }}>
            <div className="ring-wrap" style={{ width: 170, height: 170, flex: "0 0 170px" }}>
              <div className="ring" aria-hidden />
              <div className="ring-core" style={{ position: "absolute", inset: 0 }}>
                <div><b>{avgRisk ?? "—"}</b><div className="faint" style={{ fontSize: 11 }}>avg risk</div></div>
              </div>
            </div>
            <div className="stack" style={{ flex: 1, minWidth: 180 }}>
              <div className="faint" style={{ fontSize: 12 }}>Risk = weighted open findings (vulns, alerts, FIM, config). A prioritization aid, not a guarantee.</div>
              <div className="row"><span className="dot on" /> <span>{o.agents.filter((a: any) => a.status === "online").length} online</span>
                <span className="dot off" style={{ marginLeft: 8 }} /> <span>{o.agents.filter((a: any) => a.status !== "online").length} other</span></div>
            </div>
          </div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Host</th><th>Status</th><th>Risk</th><th>Last seen</th></tr></thead>
              <tbody>
                {o.agents.map((a: any) => (
                  <tr key={a.id}>
                    <td><Link href={`/agents`}>{a.name}</Link><div className="faint" style={{ fontSize: 11 }}>{a.os} · {a.ip}</div></td>
                    <td><span className={`dot ${a.status === "online" ? "on" : a.status === "isolated" ? "warn" : "off"}`} /> <Badge value={a.status} /></td>
                    <td>{a.risk ?? "—"}</td>
                    <td className="faint">{timeAgo(a.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>

      <div className="grid g-4" style={{ marginBottom: 16 }}>
        {[
          { label: "CPU", v: o.host_metrics.cpu_percent, icon: <Cpu size={14} /> },
          { label: "Memory", v: o.host_metrics.mem_percent, icon: <MemoryStick size={14} /> },
          { label: "Disk", v: o.host_metrics.disk_percent, icon: <HardDrive size={14} /> },
          { label: "Processes", v: null, text: o.host_metrics.processes, icon: <Server size={14} /> },
        ].map((m) => (
          <Panel key={m.label} tilt className="" title={<span className="row" style={{ gap: 6, fontSize: 13 }}>{m.icon} {m.label}</span>}>
            {m.v === null || m.v === undefined ? (
              <div className="value" style={{ fontSize: 24, fontWeight: 700 }}>{m.text ?? "—"}</div>
            ) : (
              <>
                <div className="row" style={{ justifyContent: "space-between" }}><b style={{ fontSize: 22 }}>{Math.round(m.v)}%</b></div>
                <div className={`bar ${m.v > 85 ? "danger" : m.v > 70 ? "warn" : ""}`} style={{ marginTop: 8 }}><span style={{ width: `${Math.min(100, m.v)}%` }} /></div>
              </>
            )}
          </Panel>
        ))}
      </div>

      <div className="grid g-2" style={{ marginBottom: 16 }}>
        <Panel title="Top unresolved alerts" actions={<Link href="/alerts" className="btn ghost sm">All alerts</Link>}>
          {o.top_alerts.length === 0 ? <Empty title="No open alerts" hint="Quiet is good — but absence of alerts is not proof of absence of compromise." /> : (
            <div className="table-wrap"><table>
              <thead><tr><th>Severity</th><th>Alert</th><th>Seen</th></tr></thead>
              <tbody>{o.top_alerts.map((a: any) => (
                <tr key={a.id} className="clickable" onClick={() => (window.location.href = `/alerts?focus=${a.id}`)}>
                  <td><Badge value={a.severity} /></td>
                  <td className="wrap">{a.title}<div className="faint" style={{ fontSize: 11 }}>{a.category} · #{a.id}</div></td>
                  <td className="faint">{a.count}× · {timeAgo(a.ts)}</td>
                </tr>))}
              </tbody></table></div>
          )}
        </Panel>

        <Panel title="Alerts by category">
          {o.alerts_by_category.length === 0 ? <Empty title="No open alerts by category" /> : (
            <div style={{ width: "100%", height: 260 }}>
              <ResponsiveContainer>
                <BarChart data={o.alerts_by_category} layout="vertical" margin={{ left: 10, right: 20 }}>
                  <XAxis type="number" stroke="#4d5f85" fontSize={11} allowDecimals={false} />
                  <YAxis type="category" dataKey="category" stroke="#7e91b5" fontSize={12} width={120} />
                  <Tooltip contentStyle={{ background: "#0b1430", border: "1px solid rgba(34,211,238,.3)", borderRadius: 10 }} />
                  <Bar dataKey="c" radius={[0, 6, 6, 0]}>
                    {o.alerts_by_category.map((_: any, i: number) => <Cell key={i} fill={["#22d3ee", "#67e8f9", "#38bdf8", "#818cf8", "#a78bfa", "#fb923c", "#fbbf24", "#f472b6"][i % 8]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>
      </div>

      <div className="grid g-3" style={{ marginBottom: 16 }}>
        <Panel title="Suspicious processes" actions={<Link href="/hunt" className="btn ghost sm">Hunt</Link>}>
          {o.suspicious_processes.length === 0 ? <Empty title="No suspicious processes" hint="Process rules run every 15s on the local host and on enrolled agents." /> : (
            <div className="stack" style={{ gap: 8 }}>
              {o.suspicious_processes.map((p: any) => (
                <div key={p.ts + p.pid + p.name} className="alert-box error" style={{ padding: 9 }}>
                  <b>{p.name}</b> <span className="faint">pid {p.pid} · {p.username}</span>
                  <div className="mono" style={{ marginTop: 4, wordBreak: "break-all" }}>{(p.cmdline || "").slice(0, 140)}</div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Incident timeline" actions={<Link href="/incidents" className="btn ghost sm">Incidents</Link>}>
          <IncidentFeed />
        </Panel>

        <Panel title="Recent scans" actions={<Link href="/scan" className="btn ghost sm">Scanner</Link>}>
          {o.recent_scans.length === 0 ? <Empty title="No scans yet" hint="Upload a file or generate a safe EICAR test sample from the File Scanner." /> : (
            <div className="stack" style={{ gap: 8 }}>
              {o.recent_scans.map((s: any) => (
                <Link key={s.id} href={`/scan/${s.id}`} className="row" style={{ justifyContent: "space-between", padding: "6px 8px", borderRadius: 10, border: "1px solid var(--border)" }}>
                  <span className="wrap" style={{ maxWidth: "60%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.filename}</span>
                  <span className="row" style={{ gap: 6 }}>
                    {s.status !== "done" ? <Badge value={s.status} /> : <><Badge value={s.verdict} /><span className="faint">{s.score}</span></>}
                  </span>
                </Link>
              ))}
            </div>
          )}
        </Panel>
      </div>

      <div className="grid g-2">
        <Panel title="Network activity (flagged, last 24h)" actions={<Link href="/network" className="btn ghost sm">Network</Link>}>
          {tl.network.length === 0 ? <Empty title="No flagged network events" hint="Outbound connections are evaluated against rules and threat-intel IOCs." /> : (
            <div style={{ width: "100%", height: 180 }}>
              <ResponsiveContainer>
                <AreaChart data={tl.network.map((n: any) => ({ hour: n.hour.slice(11) + ":00", flagged: n.flagged, total: n.c }))}>
                  <CartesianGrid stroke="rgba(34,211,238,0.07)" vertical={false} />
                  <XAxis dataKey="hour" stroke="#4d5f85" fontSize={11} /><YAxis stroke="#4d5f85" fontSize={11} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: "#0b1430", border: "1px solid rgba(34,211,238,.3)", borderRadius: 10 }} />
                  <Area type="monotone" dataKey="total" stroke="#22d3ee" fill="rgba(34,211,238,0.12)" />
                  <Area type="monotone" dataKey="flagged" stroke="#ff4d6d" fill="rgba(255,77,109,0.2)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>
        <Panel title="Configuration posture (latest SCA)" actions={<Link href="/compliance" className="btn ghost sm">Compliance</Link>}>
          {!o.sca ? <Empty title="No SCA run yet" hint="The configuration assessment runs at startup and hourly." /> : (
            <div className="stack">
              <div className="row"><b style={{ fontSize: 22 }}>{o.sca.passed}</b><span className="muted">passing</span>
                <b style={{ fontSize: 22, marginLeft: 16, color: "#ff8fa3" }}>{o.sca.failed}</b><span className="muted">failing</span>
                <span className="faint right">of {o.sca.total} checks · {timeAgo(o.sca.ts)}</span></div>
              <div className="bar"><span style={{ width: `${Math.round((o.sca.passed / Math.max(1, o.sca.total)) * 100)}%` }} /></div>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}

function IncidentFeed() {
  const [items, setItems] = useState<any[] | null>(null);
  useEffect(() => {
    let alive = true;
    const load = () => api("/api/dashboard/incident-feed?limit=12").then((r: any) => alive && setItems(r.events)).catch(() => alive && setItems([]));
    load();
    const id = setInterval(load, 10000);
    return () => { alive = false; clearInterval(id); };
  }, []);
  if (items === null) return <Spinner />;
  if (!items.length) return <Empty title="No events yet" />;
  return (
    <div className="timeline" style={{ maxHeight: 360, overflowY: "auto" }}>
      {items.map((e) => (
        <div key={e.kind + e.id + e.ts} className={`tl-item sev-${e.severity}`}>
          <div className="when">{fmtTime(e.ts)} · <span className="badge" style={{ padding: "0 6px" }}>{e.kind}</span></div>
          <div style={{ fontSize: 13 }}>{e.title} <Badge value={e.status} /></div>
        </div>
      ))}
    </div>
  );
}
