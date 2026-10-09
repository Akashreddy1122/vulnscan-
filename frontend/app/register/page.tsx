"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";
import { Shield, UserPlus } from "lucide-react";
import { useAuth } from "@/lib/auth";
import { Alert } from "@/components/ui";
import Scene3D from "@/components/Scene3D";

export default function RegisterPage() {
  const { register } = useAuth();
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password !== confirm) return setError("Passwords do not match.");
    if (password.length < 8) return setError("Password must be at least 8 characters.");
    setBusy(true);
    try {
      const msg = await register(username.trim(), email.trim(), password);
      setNotice(msg);
      router.replace("/dashboard");
    } catch (err: any) {
      setError(err?.message || "Registration failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-wrap">
      <Scene3D />
      <div className="auth-card">
        <form className="panel tilt stack" onSubmit={submit} style={{ gap: 14 }}>
          <div className="row">
            <div className="brand-mark"><Shield size={18} /></div>
            <div><div className="brand-name">Create your account</div><div className="brand-sub">The first account becomes the administrator</div></div>
          </div>
          {error && <Alert>{error}</Alert>}
          {notice && <Alert kind="ok">{notice}</Alert>}
          <label className="field">Username <span className="faint">(3–32 chars: letters, digits, _ . -)</span>
            <input required minLength={3} maxLength={32} pattern="[A-Za-z0-9_.\-]{3,32}" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
          </label>
          <label className="field">Email
            <input required type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
          <label className="field">Password <span className="faint">(min. 8 characters)</span>
            <input required minLength={8} type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </label>
          <label className="field">Confirm password
            <input required minLength={8} type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          </label>
          <button className="btn primary" type="submit" disabled={busy}><UserPlus size={15} /> {busy ? "Creating…" : "Create account"}</button>
          <p className="muted" style={{ fontSize: 13 }}>Already registered? <Link href="/login">Sign in</Link></p>
        </form>
      </div>
    </div>
  );
}
