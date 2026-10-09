"use client";

import { useState, FormEvent } from "react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Alert, Badge, Panel, useToast } from "@/components/ui";

export default function SettingsPage() {
  const { user, permissions } = useAuth();
  const toast = useToast();
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const change = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      await api("/api/auth/change-password", { method: "POST", json: { current_password: cur, new_password: next } });
      setCur(""); setNext("");
      toast("ok", "Password changed. Other sessions remain valid until their token expires.");
    } catch (e: any) { setErr(e.message); }
    finally { setBusy(false); }
  };

  return (
    <>
      <div className="page-head"><div><h1>My account</h1><div className="sub">Profile, role and password.</div></div></div>
      <div className="grid g-2">
        <Panel title="Profile">
          <dl className="kv">
            <dt>Username</dt><dd>{user?.username}</dd>
            <dt>Email</dt><dd>{user?.email}</dd>
            <dt>Role</dt><dd><Badge value={user?.role}>{user?.role}</Badge></dd>
            <dt>Last sign-in</dt><dd>{user?.last_login || "—"}</dd>
          </dl>
          <h3 style={{ marginTop: 18, marginBottom: 8 }}>Effective permissions</h3>
          <div className="row" style={{ gap: 6 }}>
            {permissions.includes("*") ? <span className="badge">all permissions</span> : permissions.map((p) => <span key={p} className="badge" style={{ fontSize: 10.5 }}>{p}</span>)}
          </div>
        </Panel>
        <Panel title="Change password">
          <form className="stack" onSubmit={change}>
            {err && <Alert>{err}</Alert>}
            <label className="field">Current password<input type="password" required autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} /></label>
            <label className="field">New password <span className="faint">(min. 8 characters)</span><input type="password" required minLength={8} autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} /></label>
            <div><button className="btn primary" disabled={busy}>{busy ? "Saving…" : "Update password"}</button></div>
          </form>
        </Panel>
      </div>
      <div style={{ marginTop: 16 }}>
        <Alert kind="info">API documentation (Swagger UI) is available at <a href="/api/docs" target="_blank" rel="noreferrer">/api/docs</a> and the OpenAPI schema at <a href="/api/openapi.json" target="_blank" rel="noreferrer">/api/openapi.json</a>.</Alert>
      </div>
    </>
  );
}
