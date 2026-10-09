"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { Search } from "lucide-react";
import { api, fmtTime, timeAgo } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Alert, Badge, Drawer, Empty, Panel, Pager, useToast } from "@/components/ui";

const LIMIT = 25;

function AlertsInner() {
  const { can } = useAuth();
  const toast = useToast();
  const router = useRouter();
  const sp = useSearchParams();
  const focus = sp.get("focus");
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<any | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [openId, setOpenId] = useState<number | null>(focus ? Number(focus) : null);
  const [detail, setDetail] = useState<any | null>(null);
  const [fpReason, setFpReason] = useState("");
  const [suppress, setSuppress] = useState(false);
  const [note, setNote] = useState("");

  const load = useCallback(async () => {
    try {
      const p = new URLSearchParams({ limit: String(LIMIT), offset: String(offset) });
      if (status) p.set("status", status);
      if (severity) p.set("severity", severity);
      if (category) p.set("category", category);
      if (q) p.set("search", q);
      setData(await api(`/api/alerts?${p}`));
      setErr(null);
    } catch (e: any) { setErr(e.message); }
  }, [status, severity, category, q, offset]);

  useEffect(() => { load(); const t = setInterval(load, 10000); return () => clearInterval(t); }, [load]);

  useEffect(() => {
    if (openId === null) { setDetail(null); return; }
    api(`/api/alerts/${openId}`).then(setDetail).catch((e) => toast("error", e.message));
  }, [openId, toast]);

  const setStat = async (st: string) => {
    if (!openId) return;
    try {
      await api(`/api/alerts/${openId}/status`, { method: "POST", json: {
        status: st, note, fp_reason: st === "false_positive" ? fpReason || note : undefined,
        create_suppression: st === "false_positive" && suppress } });
      toast("ok", `Alert #${openId} → ${st.replace("_", " ")}`);
      setNote(""); setFpReason(""); setSuppress(false);
      load();
      setDetail(await api(`/api/alerts/${openId}`));
    } catch (e: any) { toast("error", e.message); }
  };

  const close = () => { setOpenId(null); router.replace("/alerts"); };

  return (
    <>
      <div className="page-head">
        <div><h1>Alert triage</h1>
          <div className="sub">Deduplicated, explainable alerts with weighted factors and ATT&CK mapping. Repeats increment a counter instead of flooding the queue.</div></div>
      </div>
      {err && <div style={{ marginBottom: 12 }}><Alert>{err}</Alert></div>}

      {data && (
        <div className="row" style={{ marginBottom: 14, gap: 8 }}>
          {(["critical", "high", "medium", "low"] as const).map((s) => (
            <button key={s} className="btn ghost sm" onClick={() => { setSeverity(severity === s ? "" : s); setOffset(0); }} aria-pressed={severity === s}>
              <Badge value={s} /> <span className="mono">{data.open_by_severity?.[s] ?? 0}</span> open
            </button>))}
        </div>
      )}

      <Panel actions={
        <div className="row">
          <div style={{ position: "relative" }}>
            <Search size={14} style={{ position: "absolute", left: 10, top: 11, color: "#4d5f85" }} />
            <input aria-label="Search alerts" className="search" style={{ paddingLeft: 30 }} placeholder="Search title, description, key…" value={q} onChange={(e) => { setQ(e.target.value); setOffset(0); }} />
          </div>
          <select aria-label="Status" value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0); }}>
            <option value="">Open & closed</option><option value="new">New</option><option value="ack">Acknowledged</option>
            <option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option>
          </select>
          <select aria-label="Category" value={category} onChange={(e) => { setCategory(e.target.value); setOffset(0); }}>
            <option value="">All categories</option>
            {["malware", "auth", "fim", "process", "process-behavior", "network", "vulnerability", "configuration", "log", "ids", "web-attack", "persistence", "defense-evasion"].map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>}>
        {!data ? null : data.alerts.length === 0 ? <Empty title="No alerts match these filters" hint="Try clearing filters, or run a test sample from the File Scanner." /> : (
          <>
            <div className="table-wrap"><table>
              <thead><tr><th>Severity</th><th>Alert</th><th>Category</th><th>Count</th><th>Status</th><th>Last seen</th></tr></thead>
              <tbody>
                {data.alerts.map((a: any) => (
                  <tr key={a.id} className="clickable" onClick={() => setOpenId(a.id)} aria-selected={openId === a.id}>
                    <td><Badge value={a.severity} /></td>
                    <td className="wrap"><b>{a.title}</b><div className="faint" style={{ fontSize: 11.5 }}>#{a.id} · {a.source}</div></td>
                    <td><span className="badge">{a.category}</span></td>
                    <td className="mono">{a.count}</td>
                    <td><Badge value={a.status} /></td>
                    <td className="faint">{timeAgo(a.last_seen)}</td>
                  </tr>))}
              </tbody>
            </table></div>
            <Pager offset={offset} limit={LIMIT} total={data.total} onChange={setOffset} />
          </>
        )}
      </Panel>

      <Drawer open={openId !== null} onClose={close} title={detail ? `Alert #${detail.id}` : "Alert"}>
        {!detail ? <div className="muted">Loading…</div> : (
          <div className="stack">
            <div className="row"><Badge value={detail.severity} /> <Badge value={detail.status} /> <span className="badge">{detail.category}</span> <span className="faint right">seen {detail.count}× · first {fmtTime(detail.first_seen)}</span></div>
            <h2 style={{ fontSize: 18 }}>{detail.title}</h2>
            <p className="muted">{detail.description}</p>
            <Panel title="Explanation"><p style={{ lineHeight: 1.65, fontSize: 13.5 }}>{detail.explanation}</p></Panel>
            <Panel title="Why it fired (weighted factors)">
              {(detail.factors || []).length === 0 ? <span className="faint">No weighted factors recorded.</span> : (
                <div className="stack" style={{ gap: 8 }}>
                  {[...detail.factors].sort((a: any, b: any) => (b.weight || 0) - (a.weight || 0)).map((f: any, i: number) => (
                    <div key={i} className="row" style={{ fontSize: 13, alignItems: "flex-start" }}>
                      <span className="mono" style={{ color: "var(--cyan)", minWidth: 46 }}>+{f.weight ?? "?"}</span>
                      <span>{f.description}</span></div>))}
                </div>)}
            </Panel>
            <Panel title="Evidence"><pre className="code-block">{JSON.stringify(detail.evidence, null, 2)}</pre></Panel>
            {detail.mitre?.length > 0 && <Panel title="MITRE ATT&CK"><div className="row">{detail.mitre.map((m: any) => <span key={m.id} className="badge">{m.id} {m.name || ""}</span>)}</div></Panel>}
            <div className="row" style={{ gap: 12 }}>
              {detail.scan && <Link href={`/scan/${detail.scan.id}`}>Open scan #{detail.scan.id} →</Link>}
              {detail.incident && <Link href="/incidents">Incident #{detail.incident.id} →</Link>}
            </div>
            {detail.related_actions?.length > 0 && <Panel title="Response actions">{detail.related_actions.map((r: any) => <div key={r.id} className="row"><span className="mono">{r.playbook}</span><Badge value={r.status} /><span className="faint">{fmtTime(r.ts)}</span></div>)}</Panel>}
            {can("alerts:write") && (
              <Panel title="Triage">
                <div className="stack">
                  <label className="field">Analyst note
                    <textarea value={note} onChange={(e) => setNote(e.target.value)} placeholder="What did you find? Recorded in the audit trail and incident timeline." /></label>
                  <div className="row">
                    <button className="btn" onClick={() => setStat("ack")}>Acknowledge</button>
                    <button className="btn" onClick={() => setStat("investigating")}>Investigating</button>
                    <button className="btn primary" onClick={() => setStat("resolved")}>Resolve</button>
                  </div>
                  <div className="stack" style={{ borderTop: "1px solid var(--border)", paddingTop: 12 }}>
                    <label className="field">False-positive reason <span className="faint">(required to mark FP)</span>
                      <input value={fpReason} onChange={(e) => setFpReason(e.target.value)} placeholder="e.g. internal backup tool with matching strings" /></label>
                    <label className="check"><input type="checkbox" checked={suppress} onChange={(e) => setSuppress(e.target.checked)} /> Also suppress this alert key going forward (audited, reversible)</label>
                    <div><button className="btn ghost" disabled={!fpReason.trim()} onClick={() => setStat("false_positive")}>Mark false positive</button></div>
                  </div>
                </div>
              </Panel>)}
          </div>
        )}
      </Drawer>
    </>
  );
}

export default function AlertsPage() {
  return <Suspense fallback={null}><AlertsInner /></Suspense>;
}
