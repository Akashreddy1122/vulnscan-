"use client";

import Link from "next/link";
import { useEffect, useRef, useState, FormEvent } from "react";
import { Bot, Send } from "lucide-react";
import { api } from "@/lib/api";
import { Badge, Panel } from "@/components/ui";

type Msg = { role: "user" | "bot"; text: string; actions?: any[]; mode?: string; intent?: string };

const SUGGESTIONS = [
  "Top threats right now",
  "Explain alert 1",
  "Summarize the latest incident",
  "Which vulnerabilities are open?",
  "Show file integrity changes",
  "What network connections look suspicious?",
  "Compliance posture",
  "Which MITRE techniques have we seen?",
  "help",
];

export default function AssistantPage() {
  const [msgs, setMsgs] = useState<Msg[]>([{ role: "bot", text: "I answer from the live Malware Scan database and cite the records I use. Ask about alerts, scans, incidents, vulnerabilities, FIM, network events, compliance or ATT&CK coverage." }]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [session, setSession] = useState<string | undefined>(undefined);
  const [status, setStatus] = useState<any | null>(null);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => { api("/api/assistant/status").then(setStatus).catch(() => {}); }, []);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" }); }, [msgs]);

  const ask = async (q: string) => {
    if (!q.trim() || busy) return;
    setMsgs((m) => [...m, { role: "user", text: q }]);
    setInput("");
    setBusy(true);
    try {
      const r = await api("/api/assistant/ask", { method: "POST", json: { question: q, session_id: session } });
      setSession(r.session_id);
      setMsgs((m) => [...m, { role: "bot", text: r.answer, actions: r.actions, mode: r.mode, intent: r.intent }]);
    } catch (e: any) {
      setMsgs((m) => [...m, { role: "bot", text: `Sorry — the assistant could not answer: ${e.message}` }]);
    } finally { setBusy(false); }
  };

  const submit = (e: FormEvent) => { e.preventDefault(); ask(input); };

  return (
    <>
      <div className="page-head"><div><h1>AI investigation assistant</h1>
        <div className="sub">Grounded answers with citations, factor walkthroughs and next steps you can run from the console.</div></div>
        <div className="actions">{status && <Badge value={status.external_llm_configured ? "external LLM" : "local analyst"}>{status.external_llm_configured ? "External LLM" : "Local analyst engine"}</Badge>}</div></div>
      <div className="grid g-main">
        <Panel title="Conversation" className="" actions={<Bot size={16} color="#22d3ee" />}>
          <div className="stack" style={{ minHeight: 420, maxHeight: 560, overflowY: "auto", paddingRight: 4 }} aria-live="polite">
            {msgs.map((m, i) => (
              <div key={i} className={`assist-msg ${m.role === "user" ? "user" : "bot"}`}>
                <div style={{ whiteSpace: "pre-wrap" }}>{m.text.replace(/\*\*(.*?)\*\*/g, "$1")}</div>
                {m.mode && <div className="faint" style={{ fontSize: 11, marginTop: 6 }}>engine: {m.mode}{m.intent ? ` · intent: ${m.intent}` : ""}</div>}
                {m.actions && m.actions.length > 0 && (
                  <div className="row" style={{ marginTop: 8, gap: 6 }}>
                    {m.actions.map((a, k) => a.ui ? <Link key={k} className="btn ghost sm" href={a.ui}>{a.label}</Link> : <span key={k} className="badge">{a.label} (use Response console)</span>)}
                  </div>)}
              </div>))}
            {busy && <div className="faint">Analyzing records…</div>}
            <div ref={endRef} />
          </div>
          <form onSubmit={submit} className="row" style={{ marginTop: 12 }}>
            <input aria-label="Ask the assistant" className="search" style={{ maxWidth: "none" }} value={input} onChange={(e) => setInput(e.target.value)} placeholder="Ask about alerts, scans, incidents, a hash…" maxLength={2000} />
            <button className="btn primary" type="submit" disabled={busy || !input.trim()}><Send size={14} /> Ask</button>
          </form>
        </Panel>
        <Panel title="Try asking">
          <div className="stack" style={{ gap: 8 }}>
            {SUGGESTIONS.map((s) => <button key={s} className="btn ghost" style={{ justifyContent: "flex-start" }} onClick={() => ask(s)}>{s}</button>)}
          </div>
          <p className="faint" style={{ fontSize: 12, marginTop: 14 }}>
            {status?.external_llm_configured
              ? "An external LLM endpoint is configured; its answers are grounded in a context bundle built from the database."
              : "No external LLM is configured (optional integration). The local engine answers from database records only and does not invent findings."}
          </p>
        </Panel>
      </div>
    </>
  );
}
