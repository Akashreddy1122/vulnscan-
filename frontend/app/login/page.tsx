"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { FormEvent, Suspense, useState } from "react";
import { Shield, LogIn } from "lucide-react";
import { useAuth } from "@/lib/auth";
import { Alert } from "@/components/ui";
import Scene3D from "@/components/Scene3D";

function LoginForm() {
  const { login } = useAuth();
  const router = useRouter();
  const params = useSearchParams();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(params.get("expired") ? "Your session expired. Please sign in again." : null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username.trim(), password);
      router.replace("/dashboard");
    } catch (err: any) {
      setError(err?.message || "Sign-in failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="panel tilt stack" onSubmit={submit} aria-describedby={error ? "login-error" : undefined} style={{ gap: 14 }}>
      <div className="row" style={{ marginBottom: 4 }}>
        <div className="brand-mark"><Shield size={18} /></div>
        <div><div className="brand-name">Sign in to Malware Scan</div><div className="brand-sub">Role-based access · audited sessions</div></div>
      </div>
      {error && <div id="login-error"><Alert>{error}</Alert></div>}
      <label className="field">Username or email
        <input required autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
      </label>
      <label className="field">Password
        <input required type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </label>
      <button className="btn primary" type="submit" disabled={busy}><LogIn size={15} /> {busy ? "Signing in…" : "Sign in"}</button>
      <p className="muted" style={{ fontSize: 13 }}>
        New here? <Link href="/register">Create an account</Link>. Accounts are subject to the platform’s registration policy.
      </p>
    </form>
  );
}

export default function LoginPage() {
  return (
    <div className="auth-wrap">
      <Scene3D />
      <div className="auth-card">
        <Suspense fallback={null}><LoginForm /></Suspense>
      </div>
    </div>
  );
}
