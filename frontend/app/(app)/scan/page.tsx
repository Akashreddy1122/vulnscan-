"use client";

import Link from "next/link";
import { useEffect, useRef, useState, DragEvent } from "react";
import { UploadCloud, FlaskConical, FolderSearch, RefreshCw } from "lucide-react";
import { api, uploadFile, fmtBytes, timeAgo, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Alert, Badge, Empty, Panel, useToast, Pager } from "@/components/ui";

const STEPS = [
  { key: "upload", label: "Received & hashed", min: 5 },
  { key: "static", label: "Static analysis", min: 35 },
  { key: "rules", label: "Rules, IOCs & ML", min: 85 },
  { key: "verdict", label: "Verdict", min: 100 },
];

const SAMPLES: { kind: string; label: string; note: string }[] = [
  { kind: "eicar", label: "EICAR test file", note: "Industry-standard inert antivirus test string" },
  { kind: "php_webshell_sim", label: "Webshell (inert)", note: "Webshell-shaped PHP; executes nothing" },
  { kind: "ps_cradle_sim", label: "PowerShell cradle (inert)", note: "Indicator strings only; contacts nothing" },
  { kind: "high_entropy", label: "Packed blob", note: "Random bytes — exercises entropy analysis" },
  { kind: "double_ext", label: "Double extension", note: "report.pdf.exe masquerading pattern" },
  { kind: "benign_text", label: "Benign text", note: "Should come back clean" },
];

export default function ScanPage() {
  const { can } = useAuth();
  const toast = useToast();
  const [file, setFile] = useState<File | null>(null);
  const [over, setOver] = useState(false);
  const [progress, setProgress] = useState(0);
  const [uploading, setUploading] = useState(false);
  const [activeId, setActiveId] = useState<number | null>(null);
  const [active, setActive] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [path, setPath] = useState("");
  const [autoQ, setAutoQ] = useState(false);
  const [list, setList] = useState<any | null>(null);
  const [verdict, setVerdict] = useState("");
  const [offset, setOffset] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const LIMIT = 15;

  const loadList = async () => {
    try {
      const q = new URLSearchParams({ limit: String(LIMIT), offset: String(offset) });
      if (verdict) q.set("verdict", verdict);
      setList(await api(`/api/scans?${q}`));
    } catch (e: any) { setError(e.message); }
  };
  useEffect(() => { loadList(); }, [offset, verdict]); // eslint-disable-line react-hooks/exhaustive-deps

  // poll the active scan until done/error
  useEffect(() => {
    if (!activeId) return;
    let alive = true;
    const tick = async () => {
      try {
        const s = await api(`/api/scans/${activeId}`);
        if (!alive) return;
        setActive(s);
        if (s.status === "done" || s.status === "error") {
          loadList();
          if (s.status === "done") toast("ok", `Scan #${s.id} complete: ${s.verdict} (${s.score}/100)`);
          return;
        }
      } catch (e: any) {
        if (alive) setError(e.message);
        return;
      }
      if (alive) setTimeout(tick, 700);
    };
    tick();
    return () => { alive = false; };
  }, [activeId]); // eslint-disable-line react-hooks/exhaustive-deps

  const startUpload = async (f: File) => {
    setError(null);
    setUploading(true);
    setProgress(0);
    setActive(null);
    try {
      const r = await uploadFile<{ scan_id: number }>("/api/scans/upload", f, setProgress);
      setActiveId(r.scan_id);
      setFile(null);
      if (inputRef.current) inputRef.current.value = "";
    } catch (e: any) {
      setError(e instanceof ApiError ? e.message : "Upload failed");
    } finally {
      setUploading(false);
    }
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setOver(false);
    const f = e.dataTransfer.files?.[0];
    if (f) { setFile(f); startUpload(f); }
  };

  const sample = async (kind: string) => {
    setError(null);
    try {
      const r = await api<{ scan_id: number; filename: string }>("/api/scans/test-samples", { method: "POST", json: { kind } });
      setActive(null);
      setActiveId(r.scan_id);
    } catch (e: any) { setError(e.message); }
  };

  const scanPath = async () => {
    setError(null);
    try {
      const r = await api<{ scan_id: number }>("/api/scans/path", { method: "POST", json: { path, auto_quarantine: autoQ } });
      setActive(null);
      setActiveId(r.scan_id);
      setPath("");
    } catch (e: any) { setError(e.message); }
  };

  const stepIndex = (() => {
    if (!active) return -1;
    if (active.status === "done") return 4;
    const p = active.progress || 0;
    return STEPS.filter((s) => p >= s.min).length - 1;
  })();

  return (
    <>
      <div className="page-head">
        <div><h1>File scanner</h1>
          <div className="sub">Signatures, YARA-subset rules, IOC/hash intel, static analysis and an explainable ML score. Every verdict lists the factors behind it.</div></div>
      </div>
      {error && <div style={{ marginBottom: 14 }}><Alert>{error}</Alert></div>}

      <div className="grid g-main" style={{ marginBottom: 16 }}>
        <Panel title="Upload a file" actions={<span className="faint" style={{ fontSize: 12 }}>max 200 MB · stored encrypted-at-rest in quarantine if acted on</span>}>
          {can("scan:write") ? (
            <>
              <div
                className={`dropzone ${over ? "over" : ""}`}
                onDragOver={(e) => { e.preventDefault(); setOver(true); }}
                onDragLeave={() => setOver(false)}
                onDrop={onDrop}
                onClick={() => inputRef.current?.click()}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") inputRef.current?.click(); }}
                aria-label="Drop a file here or press Enter to choose one"
              >
                <UploadCloud size={36} color="#22d3ee" />
                <div style={{ fontWeight: 650, marginTop: 8 }}>Drop a file here, or click to choose</div>
                <div className="faint" style={{ fontSize: 12, marginTop: 4 }}>Files are hashed while streaming and never executed.</div>
                <input ref={inputRef} type="file" className="sr-only" aria-label="Choose file to scan"
                  onChange={(e) => { const f = e.target.files?.[0]; if (f) { setFile(f); startUpload(f); } }} />
              </div>
              {file && !uploading && <div className="faint" style={{ marginTop: 8 }}>{file.name} · {fmtBytes(file.size)}</div>}
              {uploading && (
                <div className="stack" style={{ marginTop: 12 }}>
                  <div className="row"><span>Uploading…</span><span className="right mono">{Math.round(progress * 100)}%</span></div>
                  <div className="progress" role="progressbar" aria-valuenow={Math.round(progress * 100)} aria-valuemin={0} aria-valuemax={100}><span style={{ width: `${progress * 100}%` }} /></div>
                </div>
              )}
            </>
          ) : <Alert kind="warn">Your role (<b>viewer</b>) can read scan results but cannot submit files. Ask an analyst or admin.</Alert>}

          {active && (
            <div className="stack" style={{ marginTop: 16 }} aria-live="polite">
              <div className="row"><b>{active.filename}</b> <Badge value={active.status} />
                {active.status === "done" && <Badge value={active.verdict} />}
                <Link className="right btn ghost sm" href={`/scan/${active.id}`}>Open full report →</Link></div>
              <div className="steps">
                {STEPS.map((s, i) => (
                  <div key={s.key} className={`step ${stepIndex > i || active.status === "done" ? "done" : stepIndex === i ? "active" : ""}`}>{s.label}</div>
                ))}
              </div>
              <div className="progress" role="progressbar" aria-valuenow={active.progress} aria-valuemin={0} aria-valuemax={100}><span style={{ width: `${active.progress}%` }} /></div>
              {active.status === "done" && (
                <Alert kind={active.verdict === "clean" ? "ok" : active.verdict === "suspicious" ? "warn" : "error"}>
                  <b>{active.verdict.toUpperCase()}</b> · severity {active.severity} · risk score {active.score}/100. {active.explanation?.slice(0, 260)}…
                </Alert>
              )}
              {active.status === "error" && <Alert>Scan failed: {active.error}</Alert>}
            </div>
          )}
        </Panel>

        <div className="stack">
          <Panel title="Safe test samples" actions={<FlaskConical size={15} color="#22d3ee" />}>
            <p className="muted" style={{ fontSize: 12.5, marginBottom: 10 }}>Inert files that exercise each detection path end to end. None of them can cause harm.</p>
            <div className="stack" style={{ gap: 8 }}>
              {SAMPLES.map((s) => (
                <div key={s.kind} className="row" style={{ justifyContent: "space-between", border: "1px solid var(--border)", borderRadius: 10, padding: "7px 10px" }}>
                  <div><div style={{ fontWeight: 600 }}>{s.label}</div><div className="faint" style={{ fontSize: 11.5 }}>{s.note}</div></div>
                  <button className="btn sm" disabled={!can("scan:write")} onClick={() => sample(s.kind)}>Run</button>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="Scan a file already on this server" actions={<FolderSearch size={15} color="#22d3ee" />}>
            <div className="stack">
              <label className="field">Absolute path (must be readable by the backend)
                <input value={path} onChange={(e) => setPath(e.target.value)} placeholder="/home/user/Downloads/invoice.pdf.exe" disabled={!can("scan:write")} />
              </label>
              <label className="check"><input type="checkbox" checked={autoQ} onChange={(e) => setAutoQ(e.target.checked)} disabled={!can("scan:write")} />
                Auto-quarantine if the verdict is malicious (reversible)</label>
              <button className="btn" onClick={scanPath} disabled={!path.trim() || !can("scan:write")}>Scan path</button>
            </div>
          </Panel>
        </div>
      </div>

      <Panel title="Recent scans" actions={
        <div className="row">
          <select aria-label="Filter by verdict" value={verdict} onChange={(e) => { setOffset(0); setVerdict(e.target.value); }}>
            <option value="">All verdicts</option><option value="malicious">Malicious</option><option value="suspicious">Suspicious</option><option value="clean">Clean</option>
          </select>
          <button className="btn ghost sm" onClick={loadList} aria-label="Refresh"><RefreshCw size={13} /></button>
        </div>}>
        {!list ? null : list.scans.length === 0 ? <Empty title="No scans yet" hint="Run a test sample or upload a file." /> : (
          <>
            <div className="table-wrap"><table>
              <thead><tr><th>#</th><th>File</th><th>Verdict</th><th>Severity</th><th>Score</th><th>Status</th><th>SHA-256</th><th>When</th></tr></thead>
              <tbody>
                {list.scans.map((s: any) => (
                  <tr key={s.id} className="clickable" onClick={() => (window.location.href = `/scan/${s.id}`)}>
                    <td className="faint">{s.id}</td>
                    <td className="wrap">{s.filename}<div className="faint" style={{ fontSize: 11 }}>{s.source} · {fmtBytes(s.size)}</div></td>
                    <td><Badge value={s.verdict || s.status} /></td>
                    <td><Badge value={s.severity} /></td>
                    <td>{s.status === "done" ? <div className="row" style={{ gap: 8 }}><div className={`bar ${s.score >= 65 ? "danger" : ""}`} style={{ width: 70 }}><span style={{ width: `${s.score}%` }} /></div>{s.score}</div> : <span className="faint">{s.progress}%</span>}</td>
                    <td><Badge value={s.status} /></td>
                    <td className="mono faint">{(s.sha256 || "").slice(0, 16)}…</td>
                    <td className="faint">{timeAgo(s.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
            <Pager offset={offset} limit={LIMIT} total={list.total} onChange={setOffset} />
          </>
        )}
      </Panel>
    </>
  );
}
