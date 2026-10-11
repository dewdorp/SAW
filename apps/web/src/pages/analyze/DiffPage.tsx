import { useMutation } from "@tanstack/react-query";
import { PageHeader } from "../../components/ui";
import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { api } from "../../lib/api";
import { AnalyzeNav } from "./UniversalPage";

const SAMPLE = `GET /api/user?id=100 HTTP/1.1
Host: service.example.com

HTTP/1.1 403 Forbidden

denied
###
GET /api/user?userId=100 HTTP/1.1
Host: service.example.com

HTTP/1.1 403 Forbidden

denied
###
POST /api/user HTTP/1.1
Host: service.example.com
Content-Type: application/json

{"id":100}

HTTP/1.1 200 OK

{"name":"…","phone":"…","account":"…"}`;

const SIGN: Record<string, [string, string]> = {
  PARAM_ADDED: ["+", "d-add"], HEADER_ADDED: ["+", "d-add"], PARAM_REMOVED: ["−", "d-rem"], HEADER_REMOVED: ["−", "d-rem"],
};

export function RequestEvolution({ r }: { r: any }) {
  const [sel, setSel] = useState(r.requests.length - 1);
  const t = sel > 0 ? r.transitions[sel - 1] : null;
  const req = r.requests[sel];
  return (
    <div className="col">
      <Panel title="REQUEST EVOLUTION" right={r.strategy ? <span className="small">Strategy: {r.strategy}</span> : null}>
        <div className="evo">
          {r.requests.map((q: any, i: number) => {
            const tr = i > 0 ? r.transitions[i - 1] : null;
            const changedFields = new Set((tr?.changes || []).map((c: any) => c.field));
            const ok = q.status >= 200 && q.status < 300;
            return (
              <div key={i} className="row" style={{ alignItems: "stretch" }}>
                {tr && (
                  <div className="arrow">
                    <span>⟶</span>
                    {tr.changes.slice(0, 3).map((c: any, j: number) => <span key={j} className="d-chg">{c.type}</span>)}
                    {tr.bypass && <span className="bypass">⚑ BYPASS {tr.bypass_reason}</span>}
                  </div>
                )}
                <div className={`req ${sel === i ? "sel" : ""}`} onClick={() => setSel(i)} role="button" tabIndex={0}>
                  <div className="small muted">#{i + 1}{q.partial ? " (partial)" : ""}</div>
                  <div className={`mono ${changedFields.has("method") ? "d-chg" : ""}`}><b>{q.method}</b></div>
                  <div className={`mono ellipsis ${changedFields.has("path") ? "d-chg" : ""}`}>{q.path}</div>
                  {q.params.slice(0, 4).map((p: any, k: number) => (
                    <div key={k} className="mono small ellipsis">{p.name}={p.value} <span className="muted">{p.location}</span></div>
                  ))}
                  <div className={ok ? "bypass" : "sev high"}>{q.status ? (ok ? "✓ " : "▲ ") + q.status : "—"} <span className="muted small">{q.response_size ?? ""}B</span></div>
                </div>
              </div>
            );
          })}
        </div>
      </Panel>
      {t && (
        <Panel title={`#${sel} → #${sel + 1} changes`}>
          <table className="t"><thead><tr><th>Field</th><th>Before</th><th>After</th><th>Change</th></tr></thead>
            <tbody>{t.changes.map((c: any, i: number) => {
              const [s, cls] = SIGN[c.type] || ["~", "d-chg"];
              return <tr key={i}><td className="mono">{c.field}</td><td className="mono d-rem">{c.before ?? ""}</td><td className="mono d-add">{c.after ?? ""}</td><td className={cls}>{s} {c.type} {c.detail}</td></tr>;
            })}</tbody></table>
        </Panel>
      )}
      <Panel title={`Request #${sel + 1}`}><div className="mono pre small">{JSON.stringify(req, null, 2)}</div></Panel>
    </div>
  );
}

export function DiffPage() {
  const loc = useLocation() as { state?: { input?: string } };
  const [text, setText] = useState(loc.state?.input || "");
  const m = useMutation({ mutationFn: () => api.post("/analyze/diff", { requests: [text] }) });
  useEffect(() => { if (loc.state?.input) m.mutate(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <div className="page">
      <PageHeader eyebrow="빠른 분석" title="요청 비교" desc="여러 HTTP 요청 사이의 변화(파라미터·인증 헤더·우회 헤더)를 비교합니다." />
      <AnalyzeNav />
      <textarea className="input" rows={8} value={text} onChange={(e) => setText(e.target.value)} placeholder="여러 HTTP Request(+Response)를 ### 로 구분해 붙여넣기 (2~200개)" />
      <div className="row" style={{ margin: "8px 0" }}>
        <button className="btn primary" disabled={!text.trim()} onClick={() => m.mutate()}>Compare</button>
        <button className="btn ghost sm" onClick={() => setText(SAMPLE)}>예시 넣기</button>
      </div>
      {m.isPending && <Loading />}
      <ErrorBox error={m.error} />
      {m.data && <RequestEvolution r={m.data} />}
    </div>
  );
}
