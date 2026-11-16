import { useMutation, useQuery } from "@tanstack/react-query";
import { PageHeader } from "../../components/ui";
import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { LogSummary } from "../../components/analysis";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { CaseCard, WebLogResult } from "../../components/WebLogResult";
import { api } from "../../lib/api";
import { AnalyzeNav } from "./UniversalPage";

const SERVERS = "Apache·Nginx·IIS·Tomcat·WebtoB·JEUS·HAProxy·Caddy, JSON 접근 로그, Apache·Nginx 오류 로그";

export function LogPage() {
  const loc = useLocation() as { state?: { input?: string } };
  const [text, setText] = useState(loc.state?.input || "");
  const [parser, setParser] = useState("");
  const [caseId, setCaseId] = useState("");
  const parsers = useQuery({ queryKey: ["parsers"], queryFn: () => api.get("/parsers") });
  const cases = useQuery({ queryKey: ["web-log-cases"], queryFn: () => api.get("/analyze/log/web-cases") });
  const m = useMutation({ mutationFn: (input: string) => api.post("/analyze/log", { text: input, parser_id: parser || null }) });
  const load = useMutation({
    mutationFn: (id: string) => api.get(`/analyze/log/web-cases/${id}`),
    onSuccess: (d: any) => { setText(d.text); setCaseId(d.id); m.mutate(d.text); },
  });
  useEffect(() => { if (loc.state?.input) m.mutate(loc.state.input); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const chosen = (cases.data?.items || []).find((c: any) => c.id === caseId);
  return (
    <div className="page">
      <PageHeader eyebrow="빠른 분석" title="로그 분석"
        desc={`웹 서버 로그를 붙여넣으면 형식을 알아보고, 조사와 같은 웹 탐지 기준으로 판단합니다(${SERVERS}). 붙여넣은 내용은 저장하지 않습니다.`} />
      <AnalyzeNav />
      <textarea className="input mono" rows={8} value={text} aria-label="로그 붙여넣기"
        onChange={(e) => { setText(e.target.value); setCaseId(""); }} placeholder="로그 줄을 붙여넣으세요 (5MB까지). 더 큰 파일은 헌팅의 자료 올리기를 쓰세요." />
      <div className="row wrap" style={{ margin: "8px 0" }}>
        <select className="input" value={parser} onChange={(e) => setParser(e.target.value)} aria-label="형식">
          <option value="">형식 자동 감지</option>{(parsers.data || []).map((p: any) => <option key={p.id} value={p.id}>{p.id}</option>)}
        </select>
        <button className="btn primary" disabled={!text.trim() || m.isPending} onClick={() => m.mutate(text)}>분석</button>
        {text && <button className="btn" onClick={() => { setText(""); setCaseId(""); m.reset(); }}>지우기</button>}
      </div>
      <Panel title={`웹 서버 로그 사례로 해 보기 (${cases.data?.items?.length ?? "…"})`}>
        <div className="col" style={{ gap: 2 }} data-testid="web-cases">
          {(cases.data?.items || []).map((c: any) => (
            <div key={c.id} className="row small">
              <span className="mono muted">{c.id}</span><span style={{ minWidth: 150 }}>{c.server}</span>
              <span className="grow ellipsis" title={c.scenario}>{c.title}</span>
              <span className="muted">{c.lines}줄</span>
              <button className="btn sm" disabled={load.isPending} onClick={() => load.mutate(c.id)}>이 사례 넣기</button>
            </div>
          ))}
          <ErrorBox error={cases.error || load.error} />
        </div>
      </Panel>
      {chosen && <CaseCard c={chosen} r={m.data} />}
      {(m.isPending || load.isPending) && <Loading label="분석 중…" />}
      <ErrorBox error={m.error} />
      {m.data && <WebLogResult r={m.data} text={text} />}
      {m.data && <details><summary className="muted small">기본 요약(상위 값·반복 패턴·해석 실패)</summary><LogSummary r={m.data} /></details>}
    </div>
  );
}
