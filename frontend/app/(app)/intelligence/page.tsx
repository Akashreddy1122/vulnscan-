"use client";

import { useEffect, useState, useCallback } from "react";
import { api, fmtTime } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Alert, Badge, ConfirmButton, Empty, Panel, useToast, Pager } from "@/components/ui";

const LIMIT = 25;

export default function IntelPage() {
  const { can } = useAuth();
  const toast = useToast();
  const [data, setData] = useState<any | null>(null);
  const [feeds, setFeeds] = useState<any | null>(null);
  const [offset, setOffset] = useState(0);
  const [q, setQ] = useState("");
  const [form, setForm] = useState({ type: "ip", value: "", source: "analyst", confidence: 80, tags: "" });
  const [err, setErr] = useState<string | null>(null);
  const [feedUrl, setFeedUrl] = useState("");

  const load = useCallback(() => {
    api(`/api/intelligence/iocs?limit=${LIMIT}&offset=${offset}${q ? `&q=${encodeURIComponent(q)}` : ""}`).then(setData).catch((e) => setErr(e.message));
  }, [offset, q]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { api("/api/intelligence/feeds").then(setFeeds).catch(() => {}); }, []);

  const add = async () => {
    try {
      await api("/api/intelligence/iocs", { method: "POST", json: { ...form, confidence: Number(form.confidence) } });
      toast("ok", "Indicator added — applies to the next scan"); setForm({ ...form, value: "" }); load();
    } catch (e: any) { toast("error", e.message); }
  };
  const del = async (id: number) => {
    try { await api(`/api/intelligence/iocs/${id}`, { method: "DELETE" }); toast("ok", "Indicator removed"); load(); }
    catch (e: any) { toast("error", e.message); }
  };
  const pull = async () => {
    try { const r = await api("/api/intelligence/feeds/pull", { method: "POST", json: { url: feedUrl || undefined } }); toast("ok", `Feed imported: ${r.added} added, ${r.skipped} skipped`); load(); }
    catch (e: any) { toast("error", e.message); }
  };

  return (
    <>
      <div className="page-head"><div><h1>Threat intelligence</h1>
        <div className="sub">Indicators are validated per type, matched during scans, network monitoring and hunts. Built-in items are documented test indicators — live intelligence needs a configured feed.</div></div></div>
      {err && <Alert>{err}</Alert>}
      <div className="grid g-main" style={{ marginBottom: 16 }}>
        <Panel title="Indicators" actions={<input aria-label="Search indicators" className="search" placeholder="Search value or tag" value={q} onChange={(e) => { setQ(e.target.value); setOffset(0); }} />}>
          {!data ? null : data.iocs.length === 0 ? <Empty title="No operator indicators yet" hint={`${data.builtin_pack.count} built-in indicators are active.`} /> : (
            <>
              <div className="table-wrap"><table>
                <thead><tr><th>Type</th><th>Value</th><th>Source</th><th>Conf.</th><th>Last match</th><th></th></tr></thead>
                <tbody>{data.iocs.map((i: any) => (
                  <tr key={i.id}><td><span className="badge">{i.type}</span></td><td className="wrap mono" style={{ fontSize: 12 }}>{i.value}</td>
                    <td>{i.source}<div className="faint" style={{ fontSize: 11 }}>{i.tags}</div></td><td>{i.confidence}</td>
                    <td className="faint">{fmtTime(i.last_matched)}</td>
                    <td>{can("intelligence:write") && <ConfirmButton onConfirm={() => del(i.id)} label="Remove" confirmLabel="Remove?" />}</td></tr>))}</tbody></table></div>
              <Pager offset={offset} limit={LIMIT} total={data.total} onChange={setOffset} />
            </>)}
        </Panel>
        <div className="stack">
          <Panel title="Add an indicator">
            {!can("intelligence:write") ? <span className="faint">Analyst or admin role required.</span> : (
              <div className="stack">
                <div className="grid g-2">
                  <label className="field">Type<select value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>
                    {["hash", "ip", "domain", "url", "regex"].map((t) => <option key={t}>{t}</option>)}</select></label>
                  <label className="field">Confidence (0–100)<input type="number" min={0} max={100} value={form.confidence} onChange={(e) => setForm({ ...form, confidence: Number(e.target.value) })} /></label>
                </div>
                <label className="field">Value<input aria-label="Indicator value" value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} placeholder={form.type === "hash" ? "32/40/64 hex chars" : form.type === "ip" ? "203.0.113.10" : form.type === "domain" ? "evil.example" : ""} /></label>
                <label className="field">Tags<input value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} /></label>
                <button className="btn" disabled={!form.value.trim()} onClick={add}>Add indicator</button>
              </div>)}
          </Panel>
          <Panel title="Remote feeds (optional integration)">
            {feeds && (<div className="stack">
              <div className="row"><span>Status</span><Badge value={feeds.status} /></div>
              <p className="faint" style={{ fontSize: 12.5 }}>{feeds.note}</p>
              {can("intelligence:write") && <div className="row">
                <input aria-label="Feed URL" className="search" placeholder={feeds.configured_feeds[0] || "https://feed.example/iocs.json"} value={feedUrl} onChange={(e) => setFeedUrl(e.target.value)} />
                <button className="btn sm" onClick={pull} disabled={!feeds.configured_feeds.length && !feedUrl}>Pull now</button></div>}
            </div>)}
          </Panel>
        </div>
      </div>
    </>
  );
}
