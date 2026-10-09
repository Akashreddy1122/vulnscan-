"use client";

import { useEffect, useState, useCallback } from "react";
import { FileText, Download } from "lucide-react";
import { api, downloadAuthed, fmtBytes, fmtTime } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Alert, Empty, Panel, useToast } from "@/components/ui";

export default function ReportsPage() {
  const { can } = useAuth();
  const toast = useToast();
  const [reports, setReports] = useState<any[] | null>(null);
  const [format, setFormat] = useState("html");
  const [days, setDays] = useState(7);
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => api("/api/reports").then((r) => setReports(r.reports)).catch(() => setReports([])), []);
  useEffect(() => { load(); }, [load]);

  const generate = async () => {
    setBusy(true);
    try { const r = await api("/api/reports/generate", { method: "POST", json: { format, days } }); toast("ok", `Report #${r.id} generated (${fmtBytes(r.size)})`); load(); }
    catch (e: any) { toast("error", e.message); } finally { setBusy(false); }
  };
  const download = async (r: any) => {
    try { await downloadAuthed(`/api/reports/${r.id}/download`, `malwarescan-report-${r.id}.${r.format}`); }
    catch (e: any) { toast("error", e.message); }
  };

  return (
    <>
      <div className="page-head"><div><h1>Reports</h1>
        <div className="sub">Executive summary, risk posture, detections, vulnerabilities, configuration findings and response history — generated from live data, with a limitations statement.</div></div></div>
      <div className="grid g-main">
        <Panel title="Generate a report" actions={<FileText size={15} color="#22d3ee" />}>
          {!can("reports:write") ? <Alert kind="warn">Your role can view and download reports but not generate them.</Alert> : (
            <div className="stack">
              <div className="grid g-2">
                <label className="field">Format<select value={format} onChange={(e) => setFormat(e.target.value)}><option value="html">HTML (printable)</option><option value="json">JSON (machine-readable)</option><option value="csv">CSV (spreadsheet)</option></select></label>
                <label className="field">Window (days)<input type="number" min={1} max={365} value={days} onChange={(e) => setDays(Number(e.target.value))} /></label>
              </div>
              <div><button className="btn primary" disabled={busy} onClick={generate}>{busy ? "Generating…" : "Generate report"}</button></div>
            </div>)}
        </Panel>
        <Panel title="Report history">
          {!reports ? null : reports.length === 0 ? <Empty title="No reports yet" hint="Generate one to see it here." /> : (
            <div className="table-wrap" style={{ maxHeight: 440 }}><table>
              <thead><tr><th>#</th><th>Generated</th><th>Format</th><th>Window</th><th>Size</th><th></th></tr></thead>
              <tbody>{reports.map((r) => (
                <tr key={r.id}><td className="faint">{r.id}</td><td>{fmtTime(r.ts)}<div className="faint" style={{ fontSize: 11.5 }}>by {r.generated_by}</div></td>
                  <td><span className="badge">{r.format}</span></td><td>{r.scope}</td><td>{fmtBytes(r.size)}</td>
                  <td><button className="btn ghost sm" onClick={() => download(r)}><Download size={12} /> Download</button></td></tr>))}</tbody></table></div>)}
        </Panel>
      </div>
    </>
  );
}
