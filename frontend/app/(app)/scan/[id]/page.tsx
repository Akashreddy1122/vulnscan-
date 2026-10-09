"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { ShieldAlert, Fingerprint, Archive, RotateCcw } from "lucide-react";
import { api, fmtBytes, fmtTime } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Alert, Badge, Empty, Panel, Spinner, useToast } from "@/components/ui";

export default function ScanDetail() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const { can } = useAuth();
  const toast = useToast();
  const [s, setS] = useState<any | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = () => api(`/api/scans/${id}`).then(setS).catch((e) => setErr(e.message));
  useEffect(() => {
    load();
    const t = setInterval(() => { if (s?.status !== "done" && s?.status !== "error") load(); }, 1200);
    return () => clearInterval(t);
  }, [id]); // eslint-disable-line react-hooks/exhaustive-deps

  if (err) return <Alert>{err}</Alert>;
  if (!s) return <Spinner label="Loading scan report…" />;

  const quarantine = async () => {
    setBusy(true);
    try {
      const r = await api("/api/response/execute", { method: "POST", json: {
        playbook: "quarantine_file", target: s.stored_path, dry_run: false, confirm: true,
        params: { scan_id: s.id, reason: `manual quarantine of scan #${s.id} (${s.verdict})`, severity: s.severity, original_name: s.filename } } });
      if (r.ok) { toast("ok", "Sample quarantined (encrypted) and verified."); load(); }
      else toast("error", r.error || (r.problems || []).join("; ") || "Quarantine failed");
    } catch (e: any) { toast("error", e.message); }
    finally { setBusy(false); }
  };
  const rescan = async () => {
    const r = await api(`/api/scans/${s.id}/rescan`, { method: "POST" });
    toast("ok", `Rescan #${r.scan_id} queued`);
  };

  const factors = [...(s.factors || [])].sort((a: any, b: any) => (b.weight || 0) - (a.weight || 0));
  const st = s.static_analysis || {};
  const ml = s.ml || {};

  return (
    <>
      <div className="page-head">
        <div>
          <div className="faint" style={{ fontSize: 12 }}><Link href="/scan">File scanner</Link> / scan #{s.id}</div>
          <h1 className="wrap" style={{ wordBreak: "break-all" }}>{s.filename}</h1>
          <div className="sub">{s.file_type} · {fmtBytes(s.size)} · submitted {fmtTime(s.created_at)} via {s.source}</div>
        </div>
        <div className="actions">
          {s.verdict === "malicious" && s.stored_path && can("response:execute") && (
            <button className="btn danger" onClick={quarantine} disabled={busy || s.quarantine?.status === "quarantined"}>
              <Archive size={14} /> {s.quarantine ? "Quarantined" : "Quarantine sample"}
            </button>
          )}
          {can("scan:write") && <button className="btn ghost" onClick={rescan}><RotateCcw size={14} /> Rescan</button>}
          {s.alert && <Link className="btn ghost" href={`/alerts?focus=${s.alert.id}`}>Alert #{s.alert.id}</Link>}
        </div>
      </div>

      {s.status !== "done" && s.status !== "error" && <Alert kind="info">Scan in progress… {s.progress}%</Alert>}
      {s.status === "error" && <Alert>Scan error: {s.error}</Alert>}

      {s.status === "done" && (
        <>
          <div className="grid g-4" style={{ marginBottom: 16 }}>
            <Panel tilt title="Verdict"><div style={{ fontSize: 26, fontWeight: 750 }}><Badge value={s.verdict}>{s.verdict}</Badge></div><div className="faint" style={{ marginTop: 8 }}>severity <Badge value={s.severity} /></div></Panel>
            <Panel tilt title="Risk score"><div className="row"><b style={{ fontSize: 30 }}>{s.score}</b><span className="faint">/ 100</span></div>
              <div className={`bar ${s.score >= 65 ? "danger" : s.score >= 40 ? "warn" : ""}`} style={{ marginTop: 10 }}><span style={{ width: `${s.score}%` }} /></div></Panel>
            <Panel tilt title="ML risk probability"><b style={{ fontSize: 30 }}>{ml.probability != null ? `${(ml.probability * 100).toFixed(1)}%` : "—"}</b>
              <div className="faint" style={{ fontSize: 12, marginTop: 6 }}>Logistic model over {ml.model_meta ? "22 static features" : "features"} — one signal, never decisive alone.</div></Panel>
            <Panel tilt title="Hashes"><div className="mono" style={{ fontSize: 11, wordBreak: "break-all" }}>
              <div>SHA256 {s.sha256}</div><div className="faint">MD5 {s.md5}</div><div className="faint">SHA1 {s.sha1}</div></div></Panel>
          </div>

          <Panel title="Explanation" actions={<ShieldAlert size={15} color="#22d3ee" />} className="" >
            <p style={{ lineHeight: 1.65 }}>{s.explanation}</p>
          </Panel>

          <div className="grid g-main" style={{ marginTop: 16 }}>
            <Panel title={`Risk factors (${factors.length})`}>
              {factors.length === 0 ? <Empty title="No risk factors" hint="No engine raised a factor for this file." /> : (
                <div className="table-wrap"><table>
                  <thead><tr><th>Engine</th><th>Why</th><th>Weight</th></tr></thead>
                  <tbody>{factors.map((f: any, i: number) => (
                    <tr key={i}><td><span className="badge">{f.engine}</span></td>
                      <td className="wrap">{f.description}{f.evidence && <div className="mono faint" style={{ marginTop: 3, wordBreak: "break-all" }}>{String(f.evidence).slice(0, 180)}</div>}</td>
                      <td className="mono">+{f.weight}</td></tr>))}
                  </tbody></table></div>)}
            </Panel>

            <div className="stack">
              <Panel title="Detections">
                {(s.detections || []).length === 0 ? <Empty title="No signature or rule matched" /> : (
                  <div className="stack" style={{ gap: 8 }}>
                    {s.detections.map((d: any, i: number) => (
                      <div key={i} className="row" style={{ border: "1px solid var(--border)", borderRadius: 10, padding: "8px 10px", alignItems: "flex-start" }}>
                        <div className="stack" style={{ gap: 2, flex: 1 }}>
                          <b>{d.rule || d.indicator}</b>
                          <span className="faint" style={{ fontSize: 12 }}>{d.description || d.note || d.source}</span>
                          {d.matched_strings && <span className="mono faint">matched: {d.matched_strings.join(", ")}</span>}
                        </div>
                        <span className="badge">{d.engine}</span>
                        {d.severity && <Badge value={d.severity} />}
                      </div>))}
                  </div>)}
              </Panel>
              <Panel title="ATT&CK techniques">
                {(s.mitre || []).length === 0 ? <span className="faint">No technique mapped.</span> : (
                  <div className="row">{s.mitre.map((t: any) => <span key={t.id} className="badge" title={t.tactic}>{t.id} · {t.name}</span>)}</div>)}
              </Panel>
              <Panel title="Static analysis">
                <dl className="kv">
                  <dt>Type</dt><dd>{s.file_type}</dd>
                  <dt>Detail</dt><dd>{st.type_detail || "—"}</dd>
                  <dt>Entropy</dt><dd>{st.entropy} <span className="faint">({st.entropy_label})</span></dd>
                  <dt>Printable ratio</dt><dd>{st.printable_ratio}</dd>
                  <dt>PE</dt><dd>{st.is_pe ? `${st.pe_info?.valid ? "valid" : "malformed"} · sections ${st.pe_info?.sections_count ?? "?"} · imports ${(st.pe_info?.imports || []).length}` : "no"}</dd>
                  <dt>ELF</dt><dd>{st.is_elf ? `${st.elf_info?.class ?? ""} ${st.elf_info?.type ?? ""} ${st.elf_info?.machine ?? ""}` : "no"}</dd>
                </dl>
              </Panel>
              <Panel title="Model contributions (explainable)">
                {(ml.contributions || []).length === 0 ? <span className="faint">No per-feature contributions recorded.</span> : (
                  <div className="stack" style={{ gap: 6 }}>
                    {ml.contributions.slice(0, 8).map((c: any) => (
                      <div key={c.feature} className="row" style={{ fontSize: 12.5 }}>
                        <span style={{ width: 170 }} className="mono">{c.feature}</span>
                        <span className="faint">value {c.value}</span>
                        <span className="right" style={{ color: c.contribution > 0 ? "#ffb3c0" : "#a7f3d0" }}>{c.contribution > 0 ? "+" : ""}{c.contribution}</span>
                      </div>))}
                  </div>)}
              </Panel>
            </div>
          </div>

          {(st.suspicious_strings || []).length > 0 && (
            <Panel title="Suspicious strings observed" className="" >
              <div className="table-wrap"><table><thead><tr><th>Indicator</th><th>Weight</th><th>Match</th></tr></thead>
                <tbody>{st.suspicious_strings.map((x: any, i: number) => (
                  <tr key={i}><td className="wrap">{x.label}</td><td>{x.weight}</td><td className="mono wrap">{x.match}</td></tr>))}</tbody></table></div>
            </Panel>
          )}
          {s.quarantine && (
            <div style={{ marginTop: 16 }}><Alert kind="info">Quarantine record #{s.quarantine.id}: <b>{s.quarantine.status}</b> · {fmtTime(s.quarantine.quarantined_at)} · original {s.quarantine.original_path}. <Link href="/quarantine">Manage quarantine →</Link></Alert></div>
          )}
        </>
      )}
      <div className="faint" style={{ marginTop: 18, fontSize: 12 }}>{fmtTime(s.finished_at)}</div>
    </>
  );
}
