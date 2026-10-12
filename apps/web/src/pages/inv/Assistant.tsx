import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Panel } from "../../components/common";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { aiError } from "../../lib/aiErrors";

const ACTIONS: [string, string][] = [["explain_finding", "왜 이상한가?"], ["next_steps", "추가 확인사항"], ["compare_cases", "과거 사례 비교"],
  ["ioc_summary", "관련 IOC 정리"], ["hunting_query", "헌팅 조건"], ["timeline_summary", "시간순 요약"], ["detection_idea", "탐지조건 제안"], ["report_draft", "보고서 작성"]];

/** Contextual SOC Assistant (docs/29 §3). Output is data: rendered as text, citations verified server-side. */
export function Assistant({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const [q, setQ] = useState("");
  const st = useQuery({ queryKey: ["ai-status"], queryFn: () => api.get("/ai/status") });
  const m = useMutation({ mutationFn: (x: { action: string; question?: string }) => api.post("/ai/actions", { investigation_id: inv, finding_id: ctx.findingId, ...x }) });
  const fb = useMutation({ mutationFn: (f: string) => api.post(`/ai/${m.data.id}/feedback`, { feedback: f }) });
  const r = m.data;
  const rejected = r?.output_status === "rejected";
  const template = r?.output_status === "template" || r?.is_llm === false;
  const label = rejected ? "AI 출력 검증 실패 · 답변 미채택" : template ? "오프라인 템플릿 (LLM 아님)" : "AI 생성 초안 · 사실 검토 필요";
  return (
    <Panel title="✦ SOC Assistant" right={st.data ? <span className={`tag ${st.data.is_llm ? "ai" : "warn"}`}>{st.data.is_llm ? `${st.data.provider} · ${st.data.model}` : "오프라인 템플릿 (LLM 아님, ENV-08)"}</span> : null}>
      <ErrorBox error={aiError(st.error)} />
      {st.data?.synthetic_only && <div className="small muted">합성 데이터 전용 · 운영 품질 미채택</div>}
      {!st.data?.available ? <span className="muted small">SOC Assistant 비활성 ({st.data?.detail || "실행 환경 미설정"})</span> : (
        <div className="col">
          {st.data.detail && <span className="small muted">{st.data.detail}</span>}
          <div className="row wrap">{ACTIONS.map(([a, l]) => <button key={a} className="btn sm" disabled={m.isPending} onClick={() => m.mutate({ action: a })}>{l}</button>)}</div>
          <div className="row"><input className="input grow" placeholder="SOC Assistant에 질문…" value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && q.trim() && !m.isPending) m.mutate({ action: "ask", question: q }); }} />
            <button className="btn sm" disabled={!q.trim() || m.isPending} onClick={() => m.mutate({ action: "ask", question: q })}>질문</button></div>
          <div className="small muted">기준: {ctx.findingId ? "선택한 탐지" : "조사 상위 탐지"} · 원시 로그 전체는 전달하지 않음(마스킹 샘플 ≤20)</div>
          {m.isPending && <span className="small"><span className="spinner" /> 생성 중…</span>}
          <ErrorBox error={aiError(m.error)} />
          {r && (
            <div className="ai-block col small">
              <div className="row"><span className={`tag ${rejected ? "bad" : template ? "warn" : "ai"}`}>{label}</span><span className="muted">{r.provider} · {r.latency_ms}ms · 탐지 {r.context_size.findings} · 샘플 {r.context_size.samples}</span></div>
              <span className="muted">{template ? "템플릿 생성 · LLM 추론 없음" : r.execution_status === "executed" ? "실제 모델 추론 실행됨" : "추론 실행 상태 확인 필요"}</span>
              {r.injection_signals.length > 0 && <div className="tag bad">⚠ 근거 데이터에 지시문 의심 문자열: {r.injection_signals.join(" | ")} — 명령으로 처리하지 않음</div>}
              {rejected ? <div className="error">{r.output_reason === "invalid_citations" ? "인용 근거 확인에 실패했습니다." : "응답 형식 확인에 실패했습니다."} 답변을 표시하거나 저장하지 않습니다.</div> : <>
                {!template && <span className="muted">문장별 사실 근거는 검증되지 않았습니다. 인용 ID 확인만으로 내용이 사실임을 보장하지 않습니다.</span>}
                <div className="pre">{r.answer_md}</div>
                {r.query && <div className="mono pre">{JSON.stringify(r.query, null, 1)}</div>}
                <div className="row wrap">근거: {r.citations.map((c: any) => <span key={c.id} className={`tag ${c.valid ? "ok" : "bad"}`} style={c.valid ? undefined : { textDecoration: "line-through" }} title={c.valid ? "전달된 근거에 존재" : "검증 실패 — 전달된 근거에 없음"}>{c.id}</span>)}{!r.citations.length && <span className="muted">없음</span>}</div>
                {!r.citation_valid && <div className="error">일부 인용이 검증되지 않았습니다. 해당 문장을 신뢰하지 마세요.</div>}
              </>}
              <div className="row"><button className="btn sm ghost" onClick={() => fb.mutate("helpful")}>👍</button><button className="btn sm ghost" onClick={() => fb.mutate("wrong")}>👎 틀림</button><button className="btn sm ghost" onClick={() => fb.mutate("unsafe")}>⚠ 부적절</button>
                <button className="btn sm ghost" disabled={rejected} onClick={() => { if (!rejected) api.post(`/investigations/${inv}/notes`, { body_md: `[${label}]\n${r.answer_md}`, links: r.citations.map((c: any) => c.id) }); }}>노트로 저장</button></div>
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}
