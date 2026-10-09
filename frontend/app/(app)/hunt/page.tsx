"use client";

import { useState } from "react";
import { api, fmtTime } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Alert, Badge, Empty, Panel, useToast } from "@/components/ui";

type Tab = "hash" | "process" | "yara" | "rule";

export default function HuntPage() {
  const { can } = useAuth();
  const toast = useToast();
  const [tab, setTab] = useState<Tab>("hash");
  const [err, setErr] = useState<string | null>(null);
  const [hash, setHash] = useState("");
  const [hashRes, setHashRes] = useState<any | null>(null);
  const [pattern, setPattern] = useState("");
  const [fields, setFields] = useState<string[]>(["name", "cmdline"]);
  const [procRes, setProcRes] = useState<any | null>(null);
  const [sweepPath, setSweepPath] = useState("");
  const [sweepRes, setSweepRes] = useState<any | null>(null);
  const [busy, setBusy] = useState(false);
  const [rule, setRule] = useState(`rule Demo_Marker : demo {
    meta:
        severity = "low"
        description = "Matches a demo marker string"
    strings:
        $m = "HUNT-DEMO-MARKER"
    condition:
        any of them
}`);
  const [sample, setSample] = useState("contains HUNT-DEMO-MARKER here");
  const [ruleRes, setRuleRes] = useState<any | null>(null);

  const wrap = async (fn: () => Promise<void>) => {
    setErr(null); setBusy(true);
    try { await fn(); } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };

  return (
    <>
      <div className="page-head"><div><h1>Threat hunting</h1>
        <div className="sub">Pivot on hashes across scans, quarantine, IOCs, FIM and alerts. Search process history. Run rules over real directories. Validate custom detection logic before deploying it.</div></div></div>
      <div className="tabs" role="tablist">
        {([["hash", "Hash pivot"], ["process", "Process history"], ["yara", "YARA sweep"], ["rule", "Rule workbench"]] as [Tab, string][]).map(([k, l]) => (
          <button key={k} role="tab" aria-selected={tab === k} className={`tab ${tab === k ? "active" : ""}`} onClick={() => setTab(k)}>{l}</button>))}
      </div>
      {err && <div style={{ marginBottom: 12 }}><Alert>{err}</Alert></div>}

      {tab === "hash" && (
        <Panel title="Pivot on a hash">
          <div className="row">
            <input aria-label="MD5, SHA1 or SHA256" className="search" style={{ maxWidth: 640 }} placeholder="MD5 / SHA1 / SHA256 hex" value={hash} onChange={(e) => setHash(e.target.value)} />
            <button className="btn" disabled={busy || !hash.trim()} onClick={() => wrap(async () => setHashRes(await api(`/api/hunt/hash/${hash.trim()}`)))}>Hunt</button>
          </div>
          {hashRes && (
            <div className="stack" style={{ marginTop: 16 }}>
              <Alert kind={hashRes.seen_anywhere ? "warn" : "ok"}>{hashRes.seen_anywhere ? "This hash appears in the platform's records." : "No records of this hash on this platform."}</Alert>
              <div className="grid g-2">
                {Object.entries(hashRes.summary).map(([k, v]) => <div key={k} className="panel" style={{ padding: 12 }}><div className="faint" style={{ fontSize: 12 }}>{k}</div><b style={{ fontSize: 20 }}>{v as any}</b></div>)}
              </div>
              {hashRes.scans.map((s: any) => <div key={s.id} className="row"><span>scan #{s.id}</span><span>{s.filename}</span><Badge value={s.verdict} /><span className="faint">{fmtTime(s.created_at)}</span></div>)}
              {hashRes.alerts.map((a: any) => <div key={a.id} className="row"><span>alert #{a.id}</span><span>{a.title}</span><Badge value={a.severity} /></div>)}
              {hashRes.ioc_matches.map((i: any, k: number) => <div key={k} className="row"><span className="badge">IOC</span><span>{i.source} · confidence {i.confidence}</span></div>)}
            </div>)}
        </Panel>)}

      {tab === "process" && (
        <Panel title="Search process snapshots">
          <div className="row">
            <input aria-label="Regex pattern" className="search" style={{ maxWidth: 480 }} placeholder="Regex, e.g. xmrig|nc -e|/tmp/" value={pattern} onChange={(e) => setPattern(e.target.value)} />
            {["name", "cmdline", "exe", "username"].map((f) => (
              <label key={f} className="check"><input type="checkbox" checked={fields.includes(f)} onChange={(e) => setFields(e.target.checked ? [...fields, f] : fields.filter((x) => x !== f))} /> {f}</label>))}
            <button className="btn" disabled={busy || !pattern.trim()} onClick={() => wrap(async () => setProcRes(await api("/api/hunt/processes", { method: "POST", json: { pattern, fields } })))}>Search</button>
          </div>
          {procRes && (procRes.hits.length === 0 ? <div style={{ marginTop: 14 }}><Empty title="No matches in stored snapshots" hint="Snapshots keep suspicious processes and top resource users to bound storage." /></div> : (
            <div className="table-wrap" style={{ marginTop: 14 }}><table>
              <thead><tr><th>When</th><th>PID</th><th>Name</th><th>User</th><th>Matched</th><th>Command line</th></tr></thead>
              <tbody>{procRes.hits.map((h: any, i: number) => (
                <tr key={i}><td className="faint">{fmtTime(h.ts)}</td><td>{h.pid}</td><td>{h.name}{h.suspicious ? <Badge value="flagged" /> : null}</td>
                  <td>{h.username}</td><td><span className="badge">{h.matched_field}</span></td><td className="wrap mono" style={{ fontSize: 11.5 }}>{(h.cmdline || "").slice(0, 200)}</td></tr>))}</tbody></table></div>))}
        </Panel>)}

      {tab === "yara" && (
        <Panel title="Sweep a directory with the rule set" actions={<span className="faint" style={{ fontSize: 12 }}>read-only · max 5,000 files · files over 20 MB skipped</span>}>
          {!can("hunt:write") ? <Alert kind="warn">Your role cannot run sweeps (analyst or admin required).</Alert> : (
            <div className="row">
              <input aria-label="Directory path" className="search" style={{ maxWidth: 560 }} placeholder="/path/to/directory" value={sweepPath} onChange={(e) => setSweepPath(e.target.value)} />
              <button className="btn" disabled={busy || !sweepPath.trim()} onClick={() => wrap(async () => setSweepRes(await api("/api/hunt/yara-sweep", { method: "POST", json: { path: sweepPath } })))}>Run sweep</button>
            </div>)}
          {sweepRes && (
            <div className="stack" style={{ marginTop: 14 }}>
              <div className="faint">{sweepRes.files_scanned} files · {sweepRes.rules_used} rules · {sweepRes.matches.length} match(es) · {sweepRes.note}</div>
              {sweepRes.matches.length === 0 ? <Empty title="No rule matches" /> : (
                <div className="table-wrap"><table><thead><tr><th>Severity</th><th>Rule</th><th>File</th><th>Strings</th></tr></thead>
                  <tbody>{sweepRes.matches.map((m: any, i: number) => (
                    <tr key={i}><td><Badge value={m.severity} /></td><td className="wrap"><b>{m.rule}</b><div className="faint" style={{ fontSize: 11.5 }}>{m.description}</div></td>
                      <td className="mono wrap" style={{ fontSize: 11.5 }}>{m.file}</td><td className="mono">{m.strings.join(", ")}</td></tr>))}</tbody></table></div>)}
            </div>)}
        </Panel>)}

      {tab === "rule" && (
        <Panel title="Rule workbench (yara-lite)" actions={<span className="faint" style={{ fontSize: 12 }}>compile-check, then test against sample text</span>}>
          {!can("hunt:write") ? <Alert kind="warn">Analyst or admin role required.</Alert> : (
            <div className="grid g-2">
              <div className="stack">
                <label className="field">Rule source<textarea aria-label="Rule source" rows={12} value={rule} onChange={(e) => setRule(e.target.value)} style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }} /></label>
                <label className="field">Sample text to test against<textarea aria-label="Sample text" value={sample} onChange={(e) => setSample(e.target.value)} /></label>
                <div><button className="btn primary" disabled={busy} onClick={() => wrap(async () => setRuleRes(await api("/api/hunt/yara-validate", { method: "POST", json: { source: rule, test_against: sample } })))}>Validate & test</button></div>
              </div>
              <div className="stack">
                {ruleRes && !ruleRes.ok && <Alert>Rule rejected: {ruleRes.error}</Alert>}
                {ruleRes?.ok && (<>
                  <Alert kind="ok">Compiles. {ruleRes.rules.length} rule(s) parsed.</Alert>
                  {ruleRes.rules.map((r: any) => <div key={r.name} className="panel" style={{ padding: 12 }}><b>{r.name}</b> <span className="faint">{r.strings} string(s)</span>
                    <div className="faint" style={{ fontSize: 12 }}>{r.meta?.description}</div></div>)}
                  <div className="faint">Test result: {Object.entries(ruleRes.test_matches || {}).map(([k, v]) => <div key={k}>{k}: {(v as string[]).length ? `matched ${(v as string[]).join(", ")}` : "no match"}</div>)}</div>
                </>)}
                <p className="faint" style={{ fontSize: 12 }}>Syntax subset: text / hex (with ?? wildcards) / regex strings, modifiers nocase/wide/fullword, conditions with any/all/N of, and/or/not, filesize comparisons. Unsupported constructs are rejected explicitly rather than silently ignored. Upload a validated file under Admin → Rules to deploy it.</p>
              </div>
            </div>)}
        </Panel>)}
    </>
  );
}
