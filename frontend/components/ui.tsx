"use client";

import { ReactNode, useEffect, useState, useRef, createContext, useContext, useCallback } from "react";
import { X, Inbox } from "lucide-react";

export function Badge({ value, children }: { value?: string | null; children?: ReactNode }) {
  const v = (value || "").toLowerCase().replace(/\s+/g, "-");
  return <span className={`badge ${v}`}>{children ?? value ?? "—"}</span>;
}

export function Panel({
  title, actions, children, className = "", tilt = false, id,
}: {
  title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; tilt?: boolean; id?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const onMove = (e: React.MouseEvent) => {
    if (!tilt || !ref.current) return;
    const r = ref.current.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width - 0.5;
    const y = (e.clientY - r.top) / r.height - 0.5;
    ref.current.style.transform = `perspective(900px) rotateY(${x * 4}deg) rotateX(${-y * 4}deg)`;
  };
  const onLeave = () => {
    if (ref.current) ref.current.style.transform = "";
  };
  return (
    <section
      id={id}
      ref={ref}
      className={`panel ${tilt ? "tilt" : ""} ${className}`}
      onMouseMove={onMove}
      onMouseLeave={onLeave}
    >
      {(title || actions) && (
        <div className="panel-head">
          {title && <h2>{title}</h2>}
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

export function Stat({
  label, value, hint, tone, icon,
}: { label: string; value: ReactNode; hint?: ReactNode; tone?: "alert" | "default"; icon?: ReactNode }) {
  return (
    <div className={`panel stat tilt glow ${tone === "alert" ? "alert" : ""}`}>
      <div className="row" style={{ marginBottom: 6 }}>
        <span className="label">{label}</span>
        <span className="right muted">{icon}</span>
      </div>
      <div className="value">{value}</div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

export function Empty({ title = "Nothing here yet", hint }: { title?: string; hint?: ReactNode }) {
  return (
    <div className="empty">
      <div className="icon"><Inbox size={28} /></div>
      <div style={{ color: "var(--text)", fontWeight: 600 }}>{title}</div>
      {hint && <div className="faint" style={{ marginTop: 4 }}>{hint}</div>}
    </div>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="row muted" style={{ padding: 16 }}>
      <span className="dot on" /> {label}
    </div>
  );
}

export function Alert({ kind = "error", children }: { kind?: "error" | "warn" | "ok" | "info"; children: ReactNode }) {
  return <div className={`alert-box ${kind === "info" ? "" : kind}`} role={kind === "error" ? "alert" : "status"}>{children}</div>;
}

export function Drawer({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} aria-hidden />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={typeof title === "string" ? title : "details"}>
        <div className="row" style={{ marginBottom: 14 }}>
          <h2 style={{ flex: 1 }}>{title}</h2>
          <button className="btn ghost sm" onClick={onClose} aria-label="Close"><X size={14} /></button>
        </div>
        {children}
      </aside>
    </>
  );
}

export function Modal({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: string; children: ReactNode }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} aria-hidden />
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <div className="row" style={{ marginBottom: 12 }}>
          <h2 style={{ flex: 1 }}>{title}</h2>
          <button className="btn ghost sm" onClick={onClose} aria-label="Close"><X size={14} /></button>
        </div>
        {children}
      </div>
    </>
  );
}

export function Pager({ offset, limit, total, onChange }: { offset: number; limit: number; total: number; onChange: (o: number) => void }) {
  if (total <= limit) return <span className="faint">{total} item(s)</span>;
  return (
    <div className="row" style={{ marginTop: 10 }}>
      <span className="faint">{offset + 1}–{Math.min(total, offset + limit)} of {total}</span>
      <div className="right row">
        <button className="btn ghost sm" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>Previous</button>
        <button className="btn ghost sm" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>Next</button>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ toasts
type Toast = { id: number; kind: "ok" | "error" | "info"; text: string };
const ToastCtx = createContext<(kind: Toast["kind"], text: string) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  const push = useCallback((kind: Toast["kind"], text: string) => {
    const id = Date.now() + Math.random();
    setItems((xs) => [...xs, { id, kind, text }]);
    setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), 4800);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className={`toast ${t.kind}`}>{t.text}</div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export function useToast() {
  return useContext(ToastCtx);
}

export function ConfirmButton({
  onConfirm, label, confirmLabel = "Confirm", className = "btn danger sm", disabled, children,
}: {
  onConfirm: () => void; label?: string; confirmLabel?: string; className?: string; disabled?: boolean; children?: ReactNode;
}) {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const t = setTimeout(() => setArmed(false), 4000);
    return () => clearTimeout(t);
  }, [armed]);
  return armed ? (
    <button className="btn danger sm" onClick={() => { setArmed(false); onConfirm(); }}>{confirmLabel}</button>
  ) : (
    <button className={className} disabled={disabled} onClick={() => setArmed(true)}>{children ?? label}</button>
  );
}

export function sevRank(s?: string) {
  return ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 } as Record<string, number>)[s || "info"] ?? 0;
}
