import { useMutation } from "@tanstack/react-query";
import { PageHeader } from "../../components/ui";
import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { HighlightedInput, HttpResult, IocCard, LogSummary, PayloadResult } from "../../components/analysis";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { api } from "../../lib/api";

export const ANALYZE_LINKS: [string, string][] = [["/analyze", "붙여넣기"], ["/analyze/ioc", "IOC"], ["/analyze/http", "HTTP 요청"], ["/analyze/payload", "페이로드 디코딩"], ["/analyze/log", "로그"], ["/analyze/diff", "요청 비교"]];

export function AnalyzeNav() {
  const loc = useLocation();
  return (
    <div className="tabs" style={{ marginBottom: 8 }}>
      {ANALYZE_LINKS.map(([to, l]) => <Link key={to} to={to}><button className={loc.pathname === to ? "active" : ""}>{l}</button></Link>)}
    </div>
  );
}

export function UniversalPage() {
  const loc = useLocation() as { state?: { input?: string; investigation?: string } };
  const nav = useNavigate();
  const [text, setText] = useState(loc.state?.input || "");
  const [hover, setHover] = useState<number | null>(null);
  const [tab, setTab] = useState<string>("");
  const m = useMutation({ mutationFn: (input: string) => api.post("/analyze/universal", { input }) });
  const add = useMutation({ mutationFn: (inv: string) => api.post(`/investigations/${inv}/paste`, { text }) });
  useEffect(() => { if (loc.state?.input) m.mutate(loc.state.input); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const r = m.data;
  useEffect(() => { if (r) setTab(Object.keys(r.results)[0] || ""); }, [r]);
  return (
    <div className="page">
      <PageHeader eyebrow="빠른 분석" title="붙여넣기 분석" desc="입력 종류를 자동으로 판별해 맞는 분석기로 연결합니다. 결과는 저장하지 않습니다." />
      <AnalyzeNav />
      {!r && (
        <div className="col">
          <textarea className="input" rows={10} value={text} onChange={(e) => setText(e.target.value)} placeholder="분석할 데이터를 붙여넣으세요" />
          <div className="row"><button className="btn primary" disabled={!text.trim() || m.isPending} onClick={() => m.mutate(text)}>Analyze</button></div>
        </div>
      )}
      {m.isPending && <Loading label="분석 중…" />}
      <ErrorBox error={m.error} />
      {r && (
        <div className="col">
          <div className="row">
            <b>UNIVERSAL ANALYSIS</b><span className="muted small">input {text.length} chars · {loc.state?.investigation ? "Investigation에 추가 가능" : "저장되지 않음"}</span>
            {r.input_masked?.length > 0 && <span className="tag warn">민감정보 감지: {r.input_masked.join(", ")}</span>}
            <div className="grow" />
            <button className="btn sm" onClick={() => { m.reset(); }}>새 입력</button>
            {loc.state?.investigation && <button className="btn sm primary" disabled={add.isPending || add.isSuccess} onClick={() => add.mutate(loc.state!.investigation!)}>{add.isSuccess ? "추가됨 ✓" : "Add to Investigation"}</button>}
            {add.isSuccess && <a onClick={() => nav(`/inv/${loc.state!.investigation}`)}>열기 →</a>}
          </div>
          <ErrorBox error={add.error} />
          <div className="grid2">
            <Panel title="Input"><HighlightedInput text={text} spans={r.detections} active={hover} onHover={setHover} /></Panel>
            <Panel title={`Detected (${r.detections.length})`}>
              <table className="t"><tbody>{r.detections.map((d: any, i: number) => (
                <tr key={i} className={hover === i ? "hl" : ""} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}>
                  <td>✓ {d.type}</td><td className="mono ellipsis" style={{ maxWidth: 260 }}>{d.value || ""}{d.context ? <span className="muted"> ({d.context})</span> : null}</td><td className="num">{d.confidence}</td>
                </tr>))}</tbody></table>
            </Panel>
          </div>
          <div className="row wrap"><span className="muted small">RECOMMENDED:</span>
            {r.recommended.map((x: any) => {
              const done = !!r.results[x.analysis];
              const to: Record<string, string> = { http: "/analyze/http", payload: "/analyze/payload", ioc: "/analyze/ioc", diff: "/analyze/diff", log: "/analyze/log" };
              return <button key={x.analysis} className={`btn sm ${done ? "" : "ghost"}`} onClick={() => (done ? setTab(x.analysis) : to[x.analysis] ? nav(to[x.analysis], { state: { input: text } }) : undefined)}
                title={x.analysis === "similar_case" ? "Phase 9" : undefined}>{done ? "✓ " : ""}{x.analysis}</button>;
            })}
          </div>
          <div className="tabs">{Object.keys(r.results).map((k) => <button key={k} className={tab === k ? "active" : ""} onClick={() => setTab(k)}>{k.toUpperCase()}</button>)}</div>
          {tab === "http" && <HttpResult r={r.results.http} />}
          {tab === "ioc" && <div className="grid-auto">{r.results.ioc.map((x: any, i: number) => <IocCard key={i} r={x} />)}</div>}
          {tab === "payload" && (r.results.payload.error ? <div className="error">{r.results.payload.error}</div> : <PayloadResult r={r.results.payload} />)}
          {tab === "log" && <LogSummary r={r.results.log} />}
        </div>
      )}
    </div>
  );
}
