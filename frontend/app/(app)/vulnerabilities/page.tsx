"use client";

import { useEffect, useState, useCallback } from "react";
import { api, fmtTime } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Alert, Badge, Empty, Panel, useToast, Pager } from "@/components/ui";

export default function VulnsPage() {
  const { can } = useAuth();
  const toast = useToast();
  const [status, setStatus] = useState("open");
  const [sev, setSev] = useState("");
  const [q, setQ] = useState("");
  const [off, setOff] = useState(0);
  const [data, setData] = useState<any | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [nvd, setNvd] = useState<Record<number, any>>({});

  const load = useCallback(() => {
    const p = new URLSearchParams({ status, limit: "50", offset: String(off) });
    if (sev) p.set("severity", sev);
    if (q) p.set("q", q);
    api(`/api/vulnerabilities?${p}`).then(setData).catch((e) => setErr(e.message));
  }, [status, sev, q, off]);
  useEffect(() => { load(); }, [load]);

  const setVs = async (id: number, st: string, note = "") => {
    try { await api(`/api/vulnerabilities/${id}/status`, { method: "POST", json: { status: st, note } }); toast("ok", `Marked ${st.replace("_", " ")}`); load(); }
    catch (e: any) { toast("error", e.message); }
  };
  const rescan = async () => {
    try { const r = await api("/api/vulnerabilities/rescan", { method: "POST", json: { agent_id: 1 } }); toast("ok", `Inventory: ${r.packages_scanned} packages, ${r.tools_scanned} tools, ${r.new} new finding(s)`); load(); }
    catch (e: any) { toast("error", e.message); }
  };
  const lookup = async (id: number) => {
    try { setNvd({ ...nvd, [id]: await api(`/api/vulnerabilities/${id}/nvd`) }); }
    catch (e: any) { toast("error", e.message); }
  };

  return (
    <>
      <div className="page-head"><div><h1>Vulnerability management</h1>
        <div className="sub">Installed Python packages and system tools are matched against a curated, versioned CVE knowledge base. Findings age out automatically when a package is upgraded. Matching is version-based and may miss vulnerabilities.</div></div>
        <div className="actions">{can("vulns:write") && <button className="btn" onClick={rescan}>Re-run inventory</button>}</div></div>
      {err && <Alert>{err}</Alert>}
      {data && (
        <div className="grid g-4" style={{ marginBottom: 16 }}>
          {["critical", "high", "medium", "low"].map((s) => (
            <Panel key={s} tilt><div className="faint" style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: 1 }}>{s}</div>
              <b style={{ fontSize: 26, color: s === "critical" ? "#ff8fa3" : undefined }}>{data.open_by_severity?.[s] ?? 0}</b> <span className="faint">open</span></Panel>))}
        </div>)}
      <Panel actions={<div className="row">
        <input aria-label="Search package or CVE" className="search" placeholder="Package or CVE id" value={q} onChange={(e) => { setQ(e.target.value); setOff(0); }} />
        <select aria-label="Status" value={status} onChange={(e) => { setStatus(e.target.value); setOff(0); }}>
          <option value="open">Open</option><option value="mitigated">Mitigated</option><option value="risk_accepted">Risk accepted</option><option value="all">All</option></select>
        <select aria-label="Severity" value={sev} onChange={(e) => { setSev(e.target.value); setOff(0); }}>
          <option value="">Any severity</option>{["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}</select></div>}>
        {!data ? null : data.vulnerabilities.length === 0 ? <Empty title="No matching findings" hint="Run the inventory to correlate the current host." /> : (
          <>
            <div className="table-wrap"><table>
              <thead><tr><th>CVE</th><th>Severity</th><th>Package / tool</th><th>Installed → fixed</th><th>Status</th><th>First seen</th><th>Actions</th></tr></thead>
              <tbody>{data.vulnerabilities.map((v: any) => (
                <tr key={v.id}>
                  <td><b className="mono">{v.cve_id}</b><div className="faint" style={{ fontSize: 11.5, maxWidth: 380 }}>{v.description}</div>
                    {nvd[v.id] && <div className="alert-box" style={{ marginTop: 6, fontSize: 12 }}>{nvd[v.id].ok ? <>NVD: CVSS {nvd[v.id].cvss ?? "n/a"} · published {nvd[v.id].published}</> : <>NVD: {nvd[v.id].error}</>}</div>}</td>
                  <td><Badge value={v.severity} /> <span className="faint mono" style={{ fontSize: 11 }}>CVSS {v.cvss ?? "—"}</span></td>
                  <td>{v.name}<div className="faint" style={{ fontSize: 11.5 }}>{v.source}</div></td>
                  <td className="mono" style={{ fontSize: 12 }}>{v.version} → <span style={{ color: "#a7f3d0" }}>{v.fixed_version}</span></td>
                  <td><Badge value={v.status === "risk_accepted" ? "pending" : v.status === "mitigated" ? "resolved" : "open"}>{v.status.replace("_", " ")}</Badge></td>
                  <td className="faint">{fmtTime(v.first_seen)}</td>
                  <td><div className="stack" style={{ gap: 6 }}>
                    {can("vulns:write") && v.status === "open" && <div className="row" style={{ gap: 6 }}>
                      <button className="btn ghost sm" onClick={() => setVs(v.id, "risk_accepted", "accepted by analyst")}>Accept risk</button>
                      <button className="btn ghost sm" onClick={() => setVs(v.id, "mitigated", "marked mitigated")}>Mitigated</button></div>}
                    <button className="btn ghost sm" onClick={() => lookup(v.id)}>NVD lookup</button>
                  </div></td>
                </tr>))}</tbody></table></div>
            <Pager offset={off} limit={50} total={data.total} onChange={setOff} />
          </>)}
      </Panel>
    </>
  );
}
