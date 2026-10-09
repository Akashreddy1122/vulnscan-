"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState, ReactNode } from "react";
import {
  LayoutDashboard, Bell, ScanSearch, Archive, Crosshair, Globe2, Target,
  ScrollText, FileDigit, Network, Server, ShieldAlert, ClipboardCheck, Workflow, FileText,
  Bot, Settings as SettingsIcon, Shield, LogOut, Menu, Flame, Gauge,
} from "lucide-react";
import { useAuth } from "@/lib/auth";
import Scene3D from "@/components/Scene3D";
import { api } from "@/lib/api";

type NavItem = { href: string; label: string; icon: ReactNode; perm?: string; badge?: "alerts" };

const GROUPS: { title: string; items: NavItem[] }[] = [
  { title: "Overview", items: [
    { href: "/dashboard", label: "Dashboard", icon: <LayoutDashboard size={16} />, perm: "scan:read" },
    { href: "/alerts", label: "Alerts", icon: <Bell size={16} />, perm: "alerts:read", badge: "alerts" },
    { href: "/incidents", label: "Incidents", icon: <Flame size={16} />, perm: "incidents:read" },
  ]},
  { title: "Detection", items: [
    { href: "/scan", label: "File Scanner", icon: <ScanSearch size={16} />, perm: "scan:read" },
    { href: "/quarantine", label: "Quarantine", icon: <Archive size={16} />, perm: "quarantine:read" },
    { href: "/hunt", label: "Threat Hunting", icon: <Crosshair size={16} />, perm: "hunt:read" },
    { href: "/intelligence", label: "Threat Intel", icon: <Globe2 size={16} />, perm: "intelligence:read" },
    { href: "/mitre", label: "ATT&CK Matrix", icon: <Target size={16} />, perm: "hunt:read" },
  ]},
  { title: "Monitoring", items: [
    { href: "/agents", label: "Endpoints", icon: <Server size={16} />, perm: "agents:read" },
    { href: "/logs", label: "Log Analysis", icon: <ScrollText size={16} />, perm: "logs:read" },
    { href: "/fim", label: "File Integrity", icon: <FileDigit size={16} />, perm: "fim:read" },
    { href: "/network", label: "Network & IDS", icon: <Network size={16} />, perm: "network:read" },
  ]},
  { title: "Posture", items: [
    { href: "/vulnerabilities", label: "Vulnerabilities", icon: <ShieldAlert size={16} />, perm: "vulns:read" },
    { href: "/compliance", label: "Compliance (SCA)", icon: <ClipboardCheck size={16} />, perm: "sca:read" },
  ]},
  { title: "Response", items: [
    { href: "/response", label: "Automated Response", icon: <Workflow size={16} />, perm: "response:read" },
    { href: "/reports", label: "Reports", icon: <FileText size={16} />, perm: "reports:read" },
    { href: "/assistant", label: "AI Assistant", icon: <Bot size={16} />, perm: "assistant:use" },
  ]},
  { title: "Administration", items: [
    { href: "/admin", label: "Admin Console", icon: <Gauge size={16} />, perm: "settings:read" },
    { href: "/settings", label: "My Account", icon: <SettingsIcon size={16} /> },
  ]},
];

export default function AppLayout({ children }: { children: ReactNode }) {
  const { user, loading, can, logout } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [openAlerts, setOpenAlerts] = useState<number | null>(null);

  useEffect(() => {
    if (!loading && !user) router.replace("/login");
  }, [loading, user, router]);

  useEffect(() => { setOpen(false); }, [pathname]);

  // live badge: open alert count, refreshed every 15s
  useEffect(() => {
    if (!user || !can("alerts:read")) return;
    let alive = true;
    const load = async () => {
      try {
        const r = await api<{ total: number; open_by_severity: Record<string, number> }>("/api/alerts?limit=1");
        const open = Object.values(r.open_by_severity || {}).reduce((a, b) => a + b, 0);
        if (alive) setOpenAlerts(open);
      } catch { /* badge is best-effort */ }
    };
    load();
    const t = setInterval(load, 15000);
    return () => { alive = false; clearInterval(t); };
  }, [user, can]);

  if (loading || !user) {
    return (
      <div className="auth-wrap">
        <Scene3D />
        <div className="muted">Loading secure session…</div>
      </div>
    );
  }

  return (
    <div className="shell">
      <Scene3D />
      <nav className={`sidebar ${open ? "open" : ""}`} aria-label="Primary">
        <div className="brand">
          <div className="brand-mark"><Shield size={18} /></div>
          <div>
            <div className="brand-name">Malware Scan</div>
            <div className="brand-sub">Security operations</div>
          </div>
        </div>
        {GROUPS.map((g) => {
          const items = g.items.filter((i) => !i.perm || can(i.perm));
          if (!items.length) return null;
          return (
            <div key={g.title}>
              <div className="nav-group">{g.title}</div>
              {items.map((i) => {
                const active = pathname === i.href || pathname.startsWith(i.href + "/");
                return (
                  <Link key={i.href} href={i.href} className={`nav-link ${active ? "active" : ""}`} aria-current={active ? "page" : undefined}>
                    {i.icon}
                    <span>{i.label}</span>
                    {i.badge === "alerts" && openAlerts !== null && openAlerts > 0 && (
                      <span className="nav-badge" aria-label={`${openAlerts} open alerts`}>{openAlerts}</span>
                    )}
                  </Link>
                );
              })}
            </div>
          );
        })}
        <div className="grow" style={{ flex: 1 }} />
        <div className="faint" style={{ fontSize: 11, padding: "10px 8px" }}>
          Detection is probabilistic. No platform guarantees zero vulnerabilities.
        </div>
      </nav>
      <div className="main">
        <header className="topbar">
          <button className="btn ghost sm menu-btn" onClick={() => setOpen((o) => !o)} aria-label="Toggle navigation">
            <Menu size={16} />
          </button>
          <div className="grow" />
          <span className="badge">{user.role}</span>
          <span className="muted" style={{ fontSize: 13 }}>{user.username}</span>
          <button className="btn ghost sm" onClick={logout} aria-label="Sign out"><LogOut size={14} /> Sign out</button>
        </header>
        <main id="main" className="content" tabIndex={-1}>{children}</main>
      </div>
    </div>
  );
}
