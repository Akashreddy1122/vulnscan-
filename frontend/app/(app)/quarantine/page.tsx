"use client";

import { useEffect, useState, useCallback } from "react";
import { api, fmtTime } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Badge, ConfirmButton, Empty, Panel, Alert, useToast, Pager } from "@/components/ui";

const LIMIT = 25;

export default function QuarantinePage() {
  const { can } = useAuth();
  const toast = useToast();
  const [status, setStatus] = useState("quarantined");
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<any | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [dest, setDest] = useState<Record<number, string>>({});

  const load = useCallback(() => {
    const p = new URLSearchParams({ limit: String(LIMIT), offset: String(offset) });
    if (status) p.set("status", status);
    api(`/api/quarantine?${p}`).then(setData).catch((e) => setErr(e.message));
  }, [status, offset]);
  useEffect(() => { load(); }, [load]);

  const restore = async (id: number, dry: boolean) => {
    try {
      const r = await api(`/api/quarantine/${id}/restore`, { method: "POST", json: { destination: dest[id] || null, dry_run: dry } });
      if (dry) toast("ok", `Dry run OK — would restore to ${r.dry_run ? "original location (see action trail)" : ""}`);
      else toast("ok", `Restored to ${r.restored_to}. Hash verified before writing.`);
      load();
    } catch (e: any) { toast("error", e.message); }
  };

  const remove = async (id: number) => {
    try { await api(`/api/quarantine/${id}`, { method: "DELETE" }); toast("ok", "Sample permanently deleted"); load(); }
    catch (e: any) { toast("error", e.message); }
  };

  return (
    <>
      <div className="page-head"><div><h1>Quarantine</h1>
        <div className="sub">Samples are AES-256-GCM encrypted at rest. Restore decrypts into memory, verifies the SHA-256, and refuses to overwrite existing files.</div></div>
        <div className="actions">
          <select aria-label="Status" value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0); }}>
            <option value="quarantined">Quarantined</option><option value="restored">Restored</option><option value="deleted">Deleted</option><option value="">All</option></select>
        </div></div>
      {err && <Alert>{err}</Alert>}
      <Panel>
        {!data ? null : data.items.length === 0 ? <Empty title="Quarantine is empty" hint="Malicious samples acted on from a scan or alert appear here." /> : (
          <>
            <div className="table-wrap"><table>
              <thead><tr><th>#</th><th>Original file</th><th>Reason</th><th>Status</th><th>Quarantined</th><th>Actions</th></tr></thead>
              <tbody>{data.items.map((q: any) => (
                <tr key={q.id}>
                  <td className="faint">{q.id}</td>
                  <td className="wrap"><b>{q.original_name}</b><div className="mono faint" style={{ fontSize: 11, wordBreak: "break-all" }}>{q.original_path}</div>
                    <div className="mono faint" style={{ fontSize: 11 }}>sha256 {q.sha256.slice(0, 20)}…</div></td>
                  <td className="wrap">{q.reason}{q.auto_action ? <div className="faint" style={{ fontSize: 11 }}>automatic</div> : null}</td>
                  <td><Badge value={q.status} /></td>
                  <td className="faint">{fmtTime(q.quarantined_at)}<div style={{ fontSize: 11 }}>by {q.quarantined_by}</div></td>
                  <td>
                    {q.status === "quarantined" && can("quarantine:restore") && (
                      <div className="stack" style={{ gap: 6, minWidth: 220 }}>
                        <input aria-label={`Restore destination for #${q.id}`} placeholder={`Destination (default: ${q.original_path})`} value={dest[q.id] || ""}
                          onChange={(e) => setDest({ ...dest, [q.id]: e.target.value })} style={{ fontSize: 12 }} />
                        <div className="row" style={{ gap: 6 }}>
                          <button className="btn ghost sm" onClick={() => restore(q.id, true)}>Dry run</button>
                          <button className="btn sm" onClick={() => restore(q.id, false)}>Restore</button>
                          {can("quarantine:write") && <ConfirmButton onConfirm={() => remove(q.id)} label="Delete" confirmLabel="Really delete?" />}
                        </div>
                      </div>)}
                    {q.restored_to && <div className="faint" style={{ fontSize: 12 }}>restored to {q.restored_to}</div>}
                  </td>
                </tr>))}</tbody></table></div>
            <Pager offset={offset} limit={LIMIT} total={data.total} onChange={setOffset} />
          </>)}
      </Panel>
    </>
  );
}
