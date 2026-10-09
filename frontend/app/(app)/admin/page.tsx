"use client";

import { useEffect, useState, useCallback } from "react";
import { api, fmtTime, timeAgo } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Alert, Badge, Empty, Panel, useToast, ConfirmButton, Pager } from "@/components/ui";

type Tab = "users" | "audit" | "settings" | "rules" | "integrations" | "health";
const TABS: [Tab, string][] = [["users", "Users & roles"], ["audit", "Audit trail"], ["settings", "Runtime settings"], ["rules", "Detection rules"], ["integrations", "Integrations"], ["health", "System health"]];

export default function AdminPage() {
  const { user } = useAuth();
  const [tab, setTab] = useState<Tab>("users");
  if (user?.role !== "admin") return <Alert>The administrator role is required for this console.</Alert>;
  return (
    <>
      <div className="page-head"><div><h1>Administration</h1><div className="sub">Access control, audit, runtime configuration, detection content and platform health.</div></div></div>
      <div className="tabs" role="tablist">{TABS.map(([k, l]) => <button key={k} role="tab" aria-selected={tab === k} className={`tab ${tab === k ? "active" : ""}`} onClick={() => setTab(k)}>{l}</button>)}</div>
      {tab === "users" && <UsersTab />}
      {tab === "audit" && <AuditTab />}
      {tab === "settings" && <SettingsTab />}
      {tab === "rules" && <RulesTab />}
      {tab === "integrations" && <IntegrationsTab />}
      {tab === "health" && <HealthTab />}
    </>
  );
}

function UsersTab() {
  const { user } = useAuth();
  const toast = useToast();
  const [data, setData] = useState<any | null>(null);
  const [form, setForm] = useState({ username: "", email: "", password: "", role: "viewer" });
  const load = useCallback(() => api("/api/admin/users").then(setData).catch((e) => toast("error", e.message)), [toast]);
  useEffect(() => { load(); }, [load]);
  const create = async () => {
    try { await api("/api/admin/users", { method: "POST", json: form }); toast("ok", `User ${form.username} created`); setForm({ username: "", email: "", password: "", role: "viewer" }); load(); }
    catch (e: any) { toast("error", e.message); }
  };
  const update = async (id: number, body: any) => {
    try { await api(`/api/admin/users/${id}`, { method: "POST", json: body }); toast("ok", "User updated"); load(); }
    catch (e: any) { toast("error", e.message); }
  };
  if (!data) return null;
  return (
    <div className="grid g-main">
      <Panel title="Accounts">
        <div className="table-wrap"><table>
          <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last sign-in</th><th>Change</th></tr></thead>
          <tbody>{data.users.map((u: any) => (
            <tr key={u.id}><td><b>{u.username}</b><div className="faint" style={{ fontSize: 11.5 }}>{u.email}</div></td>
              <td><select aria-label={`Role for ${u.username}`} value={u.role} onChange={(e) => update(u.id, { role: e.target.value })}>{data.roles.map((r: string) => <option key={r}>{r}</option>)}</select></td>
              <td><Badge value={u.is_active ? "online" : "offline"}>{u.is_active ? "active" : "disabled"}</Badge>{u.locked_until && <div className="faint" style={{ fontSize: 11 }}>locked until {fmtTime(u.locked_until)}</div>}</td>
              <td className="faint">{timeAgo(u.last_login)}</td>
              <td>{u.id !== user?.id && <ConfirmButton onConfirm={() => update(u.id, { is_active: !u.is_active })} label={u.is_active ? "Disable" : "Enable"} confirmLabel={u.is_active ? "Disable now" : "Enable now"} className={u.is_active ? "btn danger sm" : "btn sm"} />}</td></tr>))}</tbody></table></div>
        <details style={{ marginTop: 14 }}><summary className="muted" style={{ cursor: "pointer" }}>Role permission matrix</summary>
          <div className="stack" style={{ gap: 8, marginTop: 10 }}>{data.roles.filter((r: string) => r !== "admin").map((r: string) => (
            <div key={r}><b>{r}</b><div className="row" style={{ gap: 4, marginTop: 4 }}>{data.permissions[r].map((p: string) => <span key={p} className="badge" style={{ fontSize: 10 }}>{p}</span>)}</div></div>))}
            <div><b>admin</b> <span className="faint">all permissions (*)</span></div></div></details>
      </Panel>
      <Panel title="Create account">
        <div className="stack">
          <label className="field">Username<input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></label>
          <label className="field">Email<input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
          <label className="field">Temporary password (min. 8)<input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
          <label className="field">Role<select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{data.roles.map((r: string) => <option key={r}>{r}</option>)}</select></label>
          <div><button className="btn primary" disabled={!form.username || !form.email || form.password.length < 8} onClick={create}>Create account</button></div>
        </div>
      </Panel>
    </div>
  );
}

function AuditTab() {
  const [data, setData] = useState<any | null>(null);
  const [q, setQ] = useState("");
  const [result, setResult] = useState("");
  const [off, setOff] = useState(0);
  const toast = useToast();
  useEffect(() => {
    const p = new URLSearchParams({ limit: "50", offset: String(off) });
    if (q) p.set("q", q);
    if (result) p.set("result", result);
    api(`/api/admin/audit?${p}`).then(setData).catch((e) => toast("error", e.message));
  }, [q, result, off, toast]);
  return (
    <Panel actions={<div className="row">
      <input aria-label="Search audit" className="search" placeholder="Action, resource or detail" value={q} onChange={(e) => { setQ(e.target.value); setOff(0); }} />
      <select aria-label="Result" value={result} onChange={(e) => { setResult(e.target.value); setOff(0); }}><option value="">All results</option><option value="success">Success</option><option value="failure">Failure</option><option value="denied">Denied</option><option value="error">Error</option></select></div>}
      title={`Audit trail (${data?.total ?? 0})`}>
      {!data ? null : data.entries.length === 0 ? <Empty title="No entries" /> : (<>
        <div className="table-wrap"><table>
          <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Resource</th><th>Result</th><th>IP</th></tr></thead>
          <tbody>{data.entries.map((e: any) => (<tr key={e.id}><td className="faint mono" style={{ fontSize: 11.5 }}>{fmtTime(e.ts)}</td><td>{e.username || "—"}</td><td className="mono" style={{ fontSize: 12 }}>{e.action}</td>
            <td className="wrap" style={{ maxWidth: 380, fontSize: 12 }}>{e.resource}<div className="faint mono" style={{ fontSize: 11 }}>{(e.detail || "").slice(0, 160)}</div></td>
            <td><Badge value={e.result === "success" ? "ok" : e.result === "failure" || e.result === "denied" || e.result === "error" ? "failed" : "info"}>{e.result}</Badge></td><td className="faint mono">{e.ip}</td></tr>))}</tbody></table></div>
        <Pager offset={off} limit={50} total={data.total} onChange={setOff} />
      </>)}
    </Panel>
  );
}

function SettingsTab() {
  const toast = useToast();
  const [data, setData] = useState<any | null>(null);
  const [autoRules, setAutoRules] = useState("");
  const [fimPaths, setFimPaths] = useState("");
  const load = useCallback(() => api("/api/admin/settings").then((r) => {
    setData(r); setAutoRules(r.values.auto_response_rules || "[]"); setFimPaths(r.values.fim_watch_paths || "");
  }).catch((e) => toast("error", e.message)), [toast]);
  useEffect(() => { load(); }, [load]);
  const save = async (key: string, value: string) => {
    try { await api("/api/admin/settings", { method: "POST", json: { key, value } }); toast("ok", `${key} saved`); load(); }
    catch (e: any) { toast("error", e.message); }
  };
  if (!data) return null;
  const v = data.values;
  return (
    <div className="grid g-2">
      <Panel title="Access & automation">
        <div className="stack">
          <label className="check"><input type="checkbox" checked={v.allow_registration !== "false"} onChange={(e) => save("allow_registration", e.target.checked ? "true" : "false")} /> Allow self-registration</label>
          <label className="field">Role for self-registered accounts<select value={v.default_registration_role || "viewer"} onChange={(e) => save("default_registration_role", e.target.value)}>
            <option value="viewer">viewer</option><option value="analyst">analyst</option><option value="responder">responder</option></select></label>
          <label className="check"><input type="checkbox" checked={v.auto_quarantine !== "false"} onChange={(e) => save("auto_quarantine", e.target.checked ? "true" : "false")} /> Auto-quarantine malicious verdicts from on-disk scans</label>
          <dl className="kv" style={{ fontSize: 12.5 }}>
            <dt>Live dangerous actions</dt><dd>{data.static.response_allow_dangerous ? "enabled by policy" : "disabled (set MALWARESCAN_RESPONSE_ALLOW_DANGEROUS)"}</dd>
            <dt>Confirmation required</dt><dd>{String(data.static.response_require_confirmation)}</dd>
            <dt>Upload limit</dt><dd>{data.static.upload_max_mb} MB</dd>
            <dt>Rate limit</dt><dd>{data.static.rate_limit_requests_per_min}/min per IP · auth {data.static.rate_limit_auth_per_min}/min</dd>
            <dt>Session lifetime</dt><dd>{data.static.token_minutes} min</dd>
          </dl>
        </div>
      </Panel>
      <Panel title="Watch paths & auto-response">
        <div className="stack">
          <label className="field">FIM watch paths (JSON list)<textarea rows={3} value={fimPaths} onChange={(e) => setFimPaths(e.target.value)} /></label>
          <div><button className="btn sm" onClick={() => save("fim_watch_paths", fimPaths)}>Save FIM paths</button></div>
          <label className="field">Auto-response rules (JSON list; dry-run unless dry_run=false)<textarea rows={6} value={autoRules} onChange={(e) => setAutoRules(e.target.value)} className="mono" style={{ fontSize: 12 }} /></label>
          <div className="row"><button className="btn sm" onClick={() => save("auto_response_rules", autoRules)}>Save auto-response</button>
            <span className="faint" style={{ fontSize: 12 }}>e.g. {`[{"name":"quarantine malicious uploads","source_pattern":"scan:malicious","min_severity":"critical","playbook":"quarantine_file","target_from":"path","dry_run":true}]`}</span></div>
        </div>
      </Panel>
    </div>
  );
}

function RulesTab() {
  const toast = useToast();
  const [data, setData] = useState<any | null>(null);
  const [name, setName] = useState("custom_rules.yrl");
  const [src, setSrc] = useState("");
  const load = useCallback(() => api("/api/admin/rules").then(setData).catch((e) => toast("error", e.message)), [toast]);
  useEffect(() => { load(); }, [load]);
  const act = async (fn: () => Promise<any>, ok: string) => { try { const r = await fn(); toast("ok", typeof ok === "string" ? ok : ok); load(); return r; } catch (e: any) { toast("error", e.message); } };
  if (!data) return null;
  const s = data.status;
  return (
    <div className="grid g-2">
      <Panel title="Rule packs" actions={<span className={`badge ${data.integrity.ok ? "ok" : "failed"}`}>{data.integrity.ok ? "integrity verified" : "integrity check failed"}</span>}>
        <dl className="kv">
          <dt>Loaded at</dt><dd>{fmtTime(s.loaded_at)}</dd>
          <dt>YARA-subset rules</dt><dd>{s.yara_rules}</dd>
          <dt>Log / process / network rules</dt><dd>{s.log_rules} / {s.process_rules} / {s.network_rules}</dd>
          <dt>ATT&amp;CK techniques</dt><dd>{s.mitre_techniques}</dd>
          <dt>IOCs (stored)</dt><dd>{s.iocs}</dd>
          <dt>SCA checks</dt><dd>{s.sca_checks}</dd>
          <dt>CVE KB</dt><dd>{s.cve_packages} package entries · {s.cve_tools} tool entries</dd>
          <dt>Manifest version</dt><dd className="mono">{data.integrity.version || "—"}</dd>
        </dl>
        {s.yara_errors?.length > 0 && <div style={{ marginTop: 10 }}><Alert>{s.yara_errors.map((e: any) => `${e.file}: ${e.error}`).join(" · ")}</Alert></div>}
        {!data.integrity.ok && <div style={{ marginTop: 10 }}><Alert kind="warn">{(data.integrity.problems || []).map((p: any) => `${p.file}: ${p.error}`).join(" · ") || data.integrity.error}. Re-generate the manifest after an intentional rule change.</Alert></div>}
        <div className="row" style={{ marginTop: 14 }}>
          <button className="btn" onClick={() => act(() => api("/api/admin/rules/reload", { method: "POST" }), "Rules reloaded from disk")}>Reload</button>
          <button className="btn ghost" onClick={() => act(() => api("/api/admin/rules/manifest", { method: "POST" }), "Manifest regenerated")}>Regenerate manifest</button>
          <button className="btn ghost" onClick={() => act(() => api("/api/admin/rules/update-remote", { method: "POST" }), "Remote rule update applied")}>Pull remote update</button>
        </div>
        <p className="faint" style={{ fontSize: 12, marginTop: 10 }}>Remote updates are optional (MALWARESCAN_RULES_URL). Every file is checksum-verified before anything is replaced.</p>
      </Panel>
      <Panel title="Add a custom YARA-subset rule">
        <div className="stack">
          <label className="field">File name (.yrl)<input value={name} onChange={(e) => setName(e.target.value)} /></label>
          <label className="field">Rule source<textarea rows={10} value={src} onChange={(e) => setSrc(e.target.value)} className="mono" style={{ fontSize: 12 }} placeholder={'rule Acme_Internal_Marker : custom {\n  meta:\n    severity = "medium"\n    description = "..."\n  strings:\n    $a = "marker"\n  condition:\n    any of them\n}'} /></label>
          <div><button className="btn primary" disabled={!src.trim()} onClick={() => act(() => api("/api/admin/rules/custom", { method: "POST", json: { filename: name, source: src } }), "Rule compiled, stored and loaded")}>Validate & deploy</button></div>
        </div>
      </Panel>
    </div>
  );
}

function IntegrationsTab() {
  const [data, setData] = useState<any | null>(null);
  useEffect(() => { api("/api/admin/settings").then(setData).catch(() => {}); }, []);
  if (!data) return null;
  const rows = Object.entries(data.integrations) as [string, any][];
  return (
    <Panel title="Optional integrations" actions={<span className="faint" style={{ fontSize: 12 }}>nothing is simulated — unconfigured means off</span>}>
      <div className="table-wrap"><table><thead><tr><th>Integration</th><th>Purpose</th><th>Status</th></tr></thead>
        <tbody>{rows.map(([k, v]) => (<tr key={k}><td className="mono">{k}</td><td>{v.description}</td><td>{v.configured ? <Badge value="online">configured</Badge> : <span className="badge">not configured</span>}</td></tr>))}</tbody></table></div>
      <p className="faint" style={{ fontSize: 12, marginTop: 12 }}>Configure via environment variables (see <span className="mono">deploy/.env.example</span> and docs/INTEGRATIONS.md). Restart the backend after changing them.</p>
    </Panel>
  );
}

function HealthTab() {
  const [d, setD] = useState<any | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const load = useCallback(() => api("/api/health/diagnostics").then(setD).catch((e) => setErr(e.message)), []);
  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [load]);
  if (err) return <Alert>{err}</Alert>;
  if (!d) return null;
  return (
    <div className="grid g-2">
      <Panel title="Platform & resources">
        <dl className="kv">
          <dt>OS</dt><dd>{d.platform.system} {d.platform.release}</dd><dt>Python</dt><dd>{d.platform.python}</dd><dt>CPUs</dt><dd>{d.platform.cpus}</dd>
          <dt>CPU / memory</dt><dd>{Math.round(d.resources.cpu_percent)}% / {Math.round(d.resources.mem_percent)}%</dd>
          <dt>Database</dt><dd>{d.resources.db_size_mb} MB</dd><dt>Quarantine store</dt><dd>{d.resources.quarantine_size_mb} MB</dd><dt>Uploads</dt><dd>{d.resources.uploads_size_mb} MB</dd>
          <dt>ML model</dt><dd>{d.ml_model.loaded ? `loaded · ${d.ml_model.meta?.algorithm}` : "missing"}</dd>
        </dl>
      </Panel>
      <Panel title="Background workers" actions={<button className="btn ghost sm" onClick={load}>Refresh</button>}>
        <div className="table-wrap"><table><thead><tr><th>Worker</th><th>Status</th><th>Last run</th><th>Duration</th></tr></thead>
          <tbody>{Object.entries(d.workers).map(([k, w]: any) => (
            <tr key={k}><td className="mono">{k}</td><td><Badge value={w.status === "ok" ? "online" : "error"}>{w.status}</Badge>{w.error && <div className="faint" style={{ fontSize: 11 }}>{w.error}</div>}</td>
              <td className="faint">{timeAgo(w.last_run)}</td><td className="faint">{w.duration_ms} ms</td></tr>))}
            {Object.keys(d.workers).length === 0 && <tr><td colSpan={4} className="faint">No worker has run yet.</td></tr>}</tbody></table></div>
      </Panel>
      <Panel title="Log sources">
        <div className="stack" style={{ gap: 6 }}>{Object.entries(d.log_sources).map(([p, s]: any) => (
          <div key={p} className="row"><Badge value={s.readable ? "online" : s.exists ? "failed" : "offline"}>{s.readable ? "readable" : s.exists ? "no permission" : "missing"}</Badge><span className="mono">{p}</span></div>))}
          {Object.keys(d.log_sources).length === 0 && <span className="faint">none configured</span>}</div>
      </Panel>
      <Panel title="Rule integrity">
        <Alert kind={d.rules_integrity.ok ? "ok" : "warn"}>{d.rules_integrity.ok ? `All ${Object.keys(d.rules_integrity.files || {}).length || "tracked"} rule files match the manifest.` : (d.rules_integrity.error || "One or more rule files differ from the manifest.")}</Alert>
      </Panel>
    </div>
  );
}
