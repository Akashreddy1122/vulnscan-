"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Alert, Empty, Panel, Spinner } from "@/components/ui";

const ORDER = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"];
const SEV: Record<string, string> = { critical: "#ff4d6d", high: "#fb923c", medium: "#fbbf24", low: "#22d3ee", info: "#64748b" };

export default function MitrePage() {
  const [data, setData] = useState<any | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [sel, setSel] = useState<any | null>(null);
  useEffect(() => { api("/api/mitre").then(setData).catch((e) => setErr(e.message)); }, []);
  if (err) return <Alert>{err}</Alert>;
  if (!data) return <Spinner />;
  const tactics = ORDER.filter((t) => data.tactics.includes(t));
  return (
    <>
      <div className="page-head"><div><h1>MITRE ATT&CK coverage</h1>
        <div className="sub">Curated technique subset (ATT&CK {data.version}). Cells light up when this platform has actually raised alerts mapped to that technique. Covered: {data.covered} of {data.total} techniques in the catalog.</div></div></div>
      <Panel>
        <div style={{ overflowX: "auto" }}>
          <div style={{ display: "grid", gridTemplateColumns: `repeat(${tactics.length}, minmax(130px,1fr))`, gap: 8, minWidth: tactics.length * 140 }}>
            {tactics.map((t) => (
              <div key={t}>
                <div style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: 1, color: "var(--text-dim)", marginBottom: 8, minHeight: 30 }}>{t.replace(/-/g, " ")}</div>
                <div className="stack" style={{ gap: 6 }}>
                  {data.techniques.filter((x: any) => x.tactic === t).map((x: any) => (
                    <button key={x.id} onClick={() => setSel(x)} aria-label={`${x.id} ${x.name}, ${x.alert_count} alerts`}
                      style={{ textAlign: "left", font: "inherit", color: "var(--text)", cursor: "pointer", padding: "7px 8px", borderRadius: 8,
                        border: `1px solid ${x.alert_count ? SEV[x.max_severity] || "#22d3ee" : "var(--border)"}`,
                        background: x.alert_count ? "rgba(34,211,238,0.08)" : "rgba(255,255,255,0.015)",
                        boxShadow: x.alert_count ? `0 0 16px -6px ${SEV[x.max_severity] || "#22d3ee"}` : "none" }}>
                      <div className="mono" style={{ fontSize: 11, color: "var(--cyan)" }}>{x.id}</div>
                      <div style={{ fontSize: 12 }}>{x.name}</div>
                      {x.alert_count > 0 && <div style={{ fontSize: 11, marginTop: 3, color: SEV[x.max_severity] }}>{x.alert_count} alert(s)</div>}
                    </button>))}
                </div>
              </div>))}
          </div>
        </div>
      </Panel>
      {sel && (
        <div style={{ marginTop: 16 }}><Panel title={`${sel.id} · ${sel.name}`} actions={<button className="btn ghost sm" onClick={() => setSel(null)}>Close</button>}>
          <p className="muted">{sel.description}</p>
          <p style={{ marginTop: 8, fontSize: 13 }}><b>Detection in this platform:</b> {sel.hint}</p>
          <p style={{ marginTop: 6, fontSize: 13 }}>Observed alerts: <b>{sel.alert_count}</b>{sel.max_severity ? <> · highest severity {sel.max_severity}</> : null}</p>
        </Panel></div>
      )}
      {data.techniques.length === 0 && <Empty title="No techniques loaded" />}
    </>
  );
}
