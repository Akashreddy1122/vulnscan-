"use client";

import { createContext, useCallback, useContext, useEffect, useState, ReactNode } from "react";
import { api, getToken, setToken } from "./api";

export interface User {
  id: number;
  username: string;
  email: string;
  role: string;
  created_at?: string;
  last_login?: string;
}

interface AuthState {
  user: User | null;
  permissions: string[];
  loading: boolean;
  can: (perm: string) => boolean;
  login: (username: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string) => Promise<string>;
  logout: () => void;
  refresh: () => Promise<void>;
}

const AuthCtx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [permissions, setPermissions] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    if (!getToken()) {
      setUser(null);
      setPermissions([]);
      setLoading(false);
      return;
    }
    try {
      const me = await api<{ user: User; permissions: string[] }>("/api/auth/me");
      setUser(me.user);
      setPermissions(me.permissions);
    } catch {
      setUser(null);
      setPermissions([]);
      setToken(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const login = async (username: string, password: string) => {
    const r = await api<{ token: string; user: User }>("/api/auth/login", {
      method: "POST",
      json: { username, password },
    });
    setToken(r.token);
    await refresh();
  };

  const register = async (username: string, email: string, password: string) => {
    const r = await api<{ token: string; user: User; message: string }>("/api/auth/register", {
      method: "POST",
      json: { username, email, password },
    });
    setToken(r.token);
    await refresh();
    return r.message;
  };

  // Clearing state is enough: the authenticated layout's guard performs the single
  // client-side redirect to /login. A second, hard navigation here would race it.
  const logout = () => {
    setToken(null);
    setUser(null);
    setPermissions([]);
  };

  const can = (perm: string) => permissions.includes("*") || permissions.includes(perm);

  return (
    <AuthCtx.Provider value={{ user, permissions, loading, can, login, register, logout, refresh }}>
      {children}
    </AuthCtx.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthCtx);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
