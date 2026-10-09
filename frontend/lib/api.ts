/**
 * Thin API client. All requests are same-origin (/api/*); Next.js rewrites them
 * to the backend (see next.config.mjs). The JWT lives in localStorage — see
 * docs/SECURITY.md for the trade-off and the recommended hardening path.
 */

export const TOKEN_KEY = "ms_token";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null): void {
  if (typeof window === "undefined") return;
  if (token) window.localStorage.setItem(TOKEN_KEY, token);
  else window.localStorage.removeItem(TOKEN_KEY);
}

function messageFrom(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const d = (body as { detail: unknown }).detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d)) {
      return d.map((x: any) => (x?.msg ? `${x.loc?.slice(-1)[0] ?? "field"}: ${x.msg}` : String(x))).join("; ");
    }
  }
  return fallback;
}

function handleUnauthorized(status: number) {
  if (status === 401 && typeof window !== "undefined" && !window.location.pathname.startsWith("/login")
      && !window.location.pathname.startsWith("/register")) {
    setToken(null);
    window.location.href = "/login?expired=1";
  }
}

export async function api<T = any>(path: string, opts: RequestInit & { json?: unknown } = {}): Promise<T> {
  const headers = new Headers(opts.headers || {});
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let body = opts.body;
  if (opts.json !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(opts.json);
  }
  let res: Response;
  try {
    res = await fetch(path, { ...opts, headers, body });
  } catch {
    throw new ApiError(0, "Network error — the Malware Scan API is unreachable. Check that the backend is running.");
  }
  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) {
    handleUnauthorized(res.status);
    throw new ApiError(res.status, messageFrom(data, `Request failed (${res.status})`));
  }
  return data as T;
}

/** Multipart upload with real byte-level progress (XMLHttpRequest upload events). */
export function uploadFile<T = any>(
  path: string,
  file: File,
  onProgress?: (fraction: number) => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", path);
    const token = getToken();
    if (token) xhr.setRequestHeader("Authorization", `Bearer ${token}`);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total);
    };
    xhr.onload = () => {
      let data: any = null;
      try {
        data = JSON.parse(xhr.responseText);
      } catch {
        data = xhr.responseText;
      }
      if (xhr.status >= 200 && xhr.status < 300) resolve(data as T);
      else {
        handleUnauthorized(xhr.status);
        reject(new ApiError(xhr.status, messageFrom(data, `Upload failed (${xhr.status})`)));
      }
    };
    xhr.onerror = () => reject(new ApiError(0, "Network error during upload"));
    const form = new FormData();
    form.append("file", file, file.name);
    xhr.send(form);
  });
}

/** Authenticated file download (for reports) — returns a Blob and triggers save. */
export async function downloadAuthed(path: string, filename: string): Promise<void> {
  const token = getToken();
  const res = await fetch(path, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  if (!res.ok) {
    handleUnauthorized(res.status);
    throw new ApiError(res.status, `Download failed (${res.status})`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function fmtTime(ts?: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts.endsWith("Z") || ts.includes("+") ? ts : ts.replace(" ", "T") + "Z");
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

export function timeAgo(ts?: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts.endsWith("Z") || ts.includes("+") ? ts : ts.replace(" ", "T") + "Z");
  const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}
