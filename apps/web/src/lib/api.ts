// API client: same-origin, session cookie + CSRF header on unsafe methods (docs/11 §1).
export class ApiError extends Error {
  constructor(public status: number, public detail: string, public body?: any) {
    super(detail);
  }
}

function csrf(): string {
  const m = document.cookie.match(/(?:^|; )saw_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

async function req<T>(method: string, url: string, body?: unknown, raw?: BodyInit, responseType: "auto" | "text" = "auto"): Promise<T> {
  const headers: Record<string, string> = {};
  if (method !== "GET") headers["x-csrf-token"] = csrf();
  if (body !== undefined) headers["content-type"] = "application/json";
  if (raw !== undefined) headers["content-type"] = "application/octet-stream";
  const r = await fetch("/api/v1" + url, {
    method,
    headers,
    credentials: "same-origin",
    body: raw ?? (body !== undefined ? JSON.stringify(body) : undefined),
  });
  if (r.status === 401 && !url.startsWith("/auth/")) {
    window.dispatchEvent(new CustomEvent("saw:unauthorized"));
  }
  const ct = r.headers.get("content-type") || "";
  const data = r.ok && responseType === "text" ? await r.text() : ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new ApiError(r.status, typeof data === "string" ? data : data.detail || data.title || r.statusText, data);
  return data as T;
}

export const api = {
  get: <T = any>(url: string) => req<T>("GET", url),
  post: <T = any>(url: string, body?: unknown) => req<T>("POST", url, body ?? {}),
  put: <T = any>(url: string, body: unknown) => req<T>("PUT", url, body),
  patch: <T = any>(url: string, body: unknown) => req<T>("PATCH", url, body),
  del: <T = any>(url: string) => req<T>("DELETE", url),
  putRaw: <T = any>(url: string, data: BodyInit) => req<T>("PUT", url, undefined, data),
  text: (url: string) => req<string>("GET", url, undefined, undefined, "text"),
  /** POST a request whose response is a file (e.g. a server-side export) and hand it to the browser. */
  downloadPost: async (url: string, body: unknown, fallbackName: string): Promise<Response> => {
    const r = await fetch("/api/v1" + url, { method: "POST", credentials: "same-origin", body: JSON.stringify(body),
      headers: { "content-type": "application/json", "x-csrf-token": csrf() } });
    if (r.status === 401) window.dispatchEvent(new CustomEvent("saw:unauthorized"));
    if (!r.ok) {
      const ct = r.headers.get("content-type") || "";
      const d = ct.includes("json") ? await r.json() : { detail: await r.text() };
      throw new ApiError(r.status, d.detail || r.statusText);
    }
    const name = /filename="?([^";]+)"?/.exec(r.headers.get("content-disposition") || "")?.[1] || fallbackName;
    const href = URL.createObjectURL(await r.clone().blob());
    const a = document.createElement("a");
    a.href = href;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(href), 5000);
    return r;
  },
  /** GET a binary response and hand it to the browser as a file download. */
  download: async (url: string, fallbackName: string): Promise<Response> => {
    const r = await fetch("/api/v1" + url, { credentials: "same-origin" });
    if (r.status === 401) window.dispatchEvent(new CustomEvent("saw:unauthorized"));
    if (!r.ok) {
      const ct = r.headers.get("content-type") || "";
      const d = ct.includes("json") ? await r.json() : { detail: await r.text() };
      throw new ApiError(r.status, d.detail || r.statusText);
    }
    const name = /filename="?([^";]+)"?/.exec(r.headers.get("content-disposition") || "")?.[1] || fallbackName;
    const href = URL.createObjectURL(await r.clone().blob());
    const a = document.createElement("a");
    a.href = href;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(href), 5000);
    return r;
  },
};
