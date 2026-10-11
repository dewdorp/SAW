import { ReactNode } from "react";

const SEV_ICON: Record<string, string> = { critical: "◆", high: "▲", medium: "■", low: "●", info: "○", normal: "○" };

export function Sev({ level, score }: { level?: string | null; score?: number | null }) {
  const l = (level || "info").toLowerCase();
  return (
    <span className={`sev ${l}`} title={score !== undefined && score !== null ? `risk score ${score}` : undefined}>
      <span aria-hidden>{SEV_ICON[l] || "○"}</span>
      {l.toUpperCase()}
      {score !== undefined && score !== null ? <span className="muted"> {Math.round(score)}</span> : null}
    </span>
  );
}

export function Panel({ title, right, children, className, bodyClass }: { title?: ReactNode; right?: ReactNode; children: ReactNode; className?: string; bodyClass?: string }) {
  return (
    <section className={`panel ${className || ""}`}>
      {title !== undefined && (
        <div className="ph">
          <span className="grow ellipsis">{title}</span>
          {right}
        </div>
      )}
      <div className={`pb ${bodyClass || ""}`}>{children}</div>
    </section>
  );
}

export function Loading({ label }: { label?: string }) {
  return (
    <div className="empty">
      <span className="spinner" /> {label || "불러오는 중…"}
    </div>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  const msg = error instanceof Error ? error.message : String(error);
  return <div className="error small" role="alert">⚠ {msg}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function AiLabel() {
  return <span className="tag ai" title="AI 생성 — 검증 필요">✦ AI 생성 · 검증 필요</span>;
}

export function Check({ c }: { c: { label: string; passed: boolean | null; value: unknown; detail?: string } }) {
  const cls = c.passed === true ? "pass" : c.passed === false ? "fail" : "na";
  const mark = c.passed === true ? "✓" : c.passed === false ? "✗" : "·";
  return (
    <div className={`check ${cls}`}>
      <span className="m" aria-label={cls}>{mark}</span>
      <span>{c.label}</span>
      <span className="mono muted ellipsis" title={c.detail || ""}>{String(c.value ?? "")}</span>
    </div>
  );
}

export function KV({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <div className="kv">
      {rows.map(([k, v]) => [<div key={k + "k"}>{k}</div>, <div key={k + "v"} className="mono ellipsis">{v}</div>])}
    </div>
  );
}

export function Bar({ value, max }: { value: number; max: number }) {
  return (
    <div className="progress" aria-valuenow={value} aria-valuemax={max} role="progressbar">
      <div style={{ width: `${max ? Math.min(100, (100 * value) / max) : 0}%` }} />
    </div>
  );
}
