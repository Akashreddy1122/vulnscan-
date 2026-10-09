"use client";

import { useEffect, useState, useCallback } from "react";
import { api, fmtTime } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Alert, Badge, Empty, Panel, useToast, Pager } from "@/components/ui";

export default function FimPage() {
  const { can } = useAuth();
  const toast = useToast();
  const [events, setEvents] = useState<any | null>(null);
  const [files, setFiles] = useState<any | null>(null);
  const [watch, setWatch] = useState<any | null>(null);
  const [paths, setPaths] = useState("");
  const [tab, setTab] = useState<"events" | "inventory" | "config">("events");
  const [off, setOff] = useState(0);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api(`/api/fim/events?limit=50&offset=${off}`).then(setEvents).catch((e) => setErr(e.message));
    api("/api/fim/inventory?limit=100").then(setFiles).catch(() => {});
    api("/api/fim/watch-paths").then((w) => { setWatch(w); setPaths(w.paths.join("\n")); }).catch(() => {});
  }, [off]);
  useEffect(() => { load(); const t = setInterval(load, 20000); return () => clearInterval(t); }, [load]);

  const act = async (fn: () => Promise<any>, ok: (r: any) => string) => {
    setBusy(true);
    try { const r = await fn(); toast("ok", ok(r)); load(); }
    catch (e: any) { toast("error", e.message); }
    finally { setBusy(false); }
  };

  return (
    <>
      <div className="page-head"><div><h1>File integrity monitoring</h1>
        <div className="sub">SHA-256 baselines of watched paths. Adds, modifications, deletions and permission changes are recorded with before/after hashes and path-aware severity. Scheduled every {watch?.interval_seconds ?? "?"}s.</div></div>
        <div className="actions">{can("fim:write") && <>
          <button className="btn" disabled={busy} onClick={() => act(() => api("/api/fim/scan-now", { method: "POST", json: { agent_id: 1 } }), (r) => `Scan: ${r.added} added, ${r.modified} modified, ${r.removed} removed, ${r.permissions} permission change(s)`)}>Scan now</button>
          <button className="btn ghost" disabled={busy} onClick={() => act(() => api("/api/fim/baseline-reset", { method: "POST", json: { agent_id: 1 } }), (r) => `Baseline reset: ${r.baselined_files} file(s) recorded`)}>Reset baseline</button></>}</div></div>
      {err && <Alert>{err}</Alert>}
      <div className="tabs" role="tablist">
        {(["events", "inventory", "config"] as const).map((t) => <button key={t} role="tab" aria-selected={tab === t} className={`tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>{t === "events" ? "Change events" : t === "inventory" ? "Baseline inventory" : "Watch paths"}</button>)}
      </div>

      {tab === "events" && (
        <Panel>
          {!events ? null : events.events.length === 0 ? <Empty title="No integrity changes recorded" hint="The first scan establishes the baseline; later changes appear here." /> : (
            <>
              <div className="table-wrap"><table>
                <thead><tr><th>When</th><th>Change</th><th>Severity</th><th>Path</th><th>Before → after</th></tr></thead>
                <tbody>{events.events.map((e: any) => (
                  <tr key={e.id}><td className="faint">{fmtTime(e.ts)}</td><td><span className="badge">{e.change_type}</span></td><td><Badge value={e.severity} /></td>
                    <td className="wrap mono" style={{ fontSize: 12 }}>{e.path}</td>
                    <td className="mono faint" style={{ fontSize: 11 }}>{e.before_hash ? e.before_hash.slice(0, 12) : "—"} → {e.after_hash ? e.after_hash.slice(0, 12) : "—"}
                      {e.before_mode && e.after_mode && e.before_mode !== e.after_mode && <div>mode {e.before_mode} → {e.after_mode}</div>}</td></tr>))}</tbody></table></div>
              <Pager offset={off} limit={50} total={events.total} onChange={setOff} />
            </>)}
        </Panel>)}

      {tab === "inventory" && (
        <Panel title={`Baseline (${files?.total ?? 0} files)`}>
          {!files ? null : files.files.length === 0 ? <Empty title="No baseline yet" hint="Run a scan or reset the baseline." /> : (
            <div className="table-wrap" style={{ maxHeight: 520 }}><table>
              <thead><tr><th>Path</th><th>SHA-256</th><th>Size</th><th>Mode</th><th>Last seen</th></tr></thead>
              <tbody>{files.files.map((f: any) => (<tr key={f.id}><td className="wrap mono" style={{ fontSize: 12 }}>{f.path}</td><td className="mono faint" style={{ fontSize: 11 }}>{f.sha256.slice(0, 16)}…</td><td>{f.size}</td><td className="mono">{f.mode}</td><td className="faint">{fmtTime(f.seen_at)}</td></tr>))}</tbody></table></div>)}
        </Panel>)}

      {tab === "config" && (
        <Panel title="Watched paths">
          <div className="stack">
            <p className="faint" style={{ fontSize: 13 }}>Absolute paths, one per line (max 20). Walks skip hidden dirs, node_modules, .git, and files over 50 MB. Defaults are read-only to the platform.</p>
            <textarea aria-label="Watch paths" rows={6} value={paths} onChange={(e) => setPaths(e.target.value)} disabled={!can("fim:write")} />
            {can("fim:write") && <div><button className="btn" onClick={() => act(() => api("/api/fim/watch-paths", { method: "POST", json: { paths: paths.split("\n").map((p) => p.trim()).filter(Boolean) } }), () => "Watch paths saved — baseline on next scan")}>Save watch paths</button></div>}
          </div>
        </Panel>)}
    </>
  );
}
