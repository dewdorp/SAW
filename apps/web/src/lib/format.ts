// Formatting + safe-render helpers. All analysis data is untrusted: never build HTML from it except via escapeHtml.
export function escapeHtml(v: unknown): string {
  return String(v ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const KST = "Asia/Seoul";
let tzMode: "KST" | "UTC" = (localStorage.getItem("saw.tz") as "KST" | "UTC") || "KST";
const tzListeners = new Set<() => void>();
export function setTz(m: "KST" | "UTC") {
  tzMode = m;
  try { localStorage.setItem("saw.tz", m); } catch { /* ignore */ }
  tzListeners.forEach((listener) => listener());
}
export function getTz() { return tzMode; }
export function subscribeTz(listener: () => void) {
  tzListeners.add(listener);
  return () => { tzListeners.delete(listener); };
}

export function fmtTime(ts?: string | number | null, withDate = true): string {
  if (ts === null || ts === undefined || ts === "") return "–";
  // API datetimes are stored in UTC; SQLite may return them without an offset.
  const value = typeof ts === "string" && /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(ts)
    ? ts.replace(" ", "T") + "Z"
    : ts;
  const d = typeof value === "number" ? new Date(value * 1000) : new Date(value);
  if (isNaN(d.getTime())) return String(ts);
  const opts: Intl.DateTimeFormatOptions = {
    timeZone: tzMode === "KST" ? KST : "UTC", hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit",
    ...(withDate ? { month: "2-digit", day: "2-digit" } : {}),
  };
  return new Intl.DateTimeFormat("ko-KR", opts).format(d).replace(/\. /g, "-").replace(/\.$/, "");
}

export function fmtNum(n?: number | null, approx = false): string {
  if (n === null || n === undefined || isNaN(Number(n))) return "–";
  return (approx ? "≈" : "") + Number(n).toLocaleString("en-US", { maximumFractionDigits: 2 });
}

export function fmtBytes(n?: number | null): string {
  if (n === null || n === undefined) return "–";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${u[i]}`;
}

export function pct(v?: number | null): string {
  return v === null || v === undefined ? "–" : `${(v * 100).toFixed(1)}%`;
}

export function defang(v: string): string {
  return v.replace(/^http/i, "hxxp").replace(/\./g, "[.]");
}

export function dur(sec?: number | null): string {
  if (sec === null || sec === undefined) return "";
  const a = Math.abs(sec);
  if (a < 1) return `${sec >= 0 ? "+" : "-"}${a.toFixed(2)}s`;
  if (a < 60) return `${sec >= 0 ? "+" : "-"}${a.toFixed(1)}s`;
  if (a < 3600) return `${sec >= 0 ? "+" : "-"}${Math.floor(a / 60)}m${Math.round(a % 60)}s`;
  return `${sec >= 0 ? "+" : "-"}${Math.floor(a / 3600)}h${Math.round((a % 3600) / 60)}m`;
}
