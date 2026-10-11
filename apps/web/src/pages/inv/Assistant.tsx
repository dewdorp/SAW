import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Panel } from "../../components/common";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";

const ACTIONS: [string, string][] = [["explain_finding", "왜 이상한가?"], ["next_steps", "추가 확인사항"], ["compare_cases", "과거 사례 비교"],
  ["ioc_summary", "관련 IOC 정리"], ["hunting_query", "Hunting Query"], ["timeline_summary", "Timeline 요약"], ["detection_idea", "탐지조건 제안"], ["report_draft", "보고서 작성"]];

/** Contextual SOC Assistant (docs/29 §3). Output is data: rendered as text, citations verified server-side. */
export function Assistant({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const [q, setQ] = useState("");
  const st = useQuery({ queryKey: ["ai-status"], queryFn: () => api.get("/ai/status") });
  const m = useMutation({ mutationFn: (x: { action: string; question?: string }) => api.post("/ai/actions", { investigation_id: inv, finding_id: ctx.findingId, ...x }) });
  const fb = useMutation({ mutationFn: (f: string) => api.post(`/ai/${m.data.id}/feedback`, { feedback: f }) });
  const r = m.data;
  return (
    <Panel title="✦ SOC Assistant" right={st.data ? <span className={`tag ${st.data.is_llm ? "ai" : "warn"}`}>{st.data.is_llm ? `${st.data.provider} · ${st.data.model}` : "오프라인 템플릿 (LLM 아님, ENV-08)"}</span> : null}>
      {!st.data?.available ? <span className="muted small">SOC Assistant 비활성 ({st.data?.detail || "provider none"})</span> : (
        <div className="col">
          <div className="row wrap">{ACTIONS.map(([a, l]) => <button key={a} className="btn sm" disabled={m.isPending} onClick={() => m.mutate({ action: a })}>{l}</button>)}</div>
          <div className="row"><input className="input grow" placeholder="Ask SOC Assistant…" value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && q.trim()) m.mutate({ action: "ask", question: q }); }} />
            <button className="btn sm" disabled={!q.trim() || m.isPending} onClick={() => m.mutate({ action: "ask", question: q })}>Ask</button></div>
          <div className="small muted">기준: {ctx.findingId ? "선택한 Finding" : "Investigation 상위 Finding"} · 원시 로그 전체는 전달하지 않음(마스킹 샘플 ≤20)</div>
          {m.isPending && <span className="small"><span className="spinner" /> 생성 중…</span>}
          <ErrorBox error={m.error} />
          {r && (
            <div className="ai-block col small">
              <div className="row"><span className="tag ai">✦ {r.label}</span><span className="muted">{r.provider} · {r.latency_ms}ms · findings {r.context_size.findings} · samples {r.context_size.samples}</span></div>
              {r.injection_signals.length > 0 && <div className="tag bad">⚠ 근거 데이터에 지시문 의심 문자열: {r.injection_signals.join(" | ")} — 명령으로 처리하지 않음</div>}
              <div className="pre">{r.answer_md}</div>
              {r.query && <div className="mono pre">{JSON.stringify(r.query, null, 1)}</div>}
              <div className="row wrap">근거: {r.citations.map((c: any) => <span key={c.id} className={`tag ${c.valid ? "ok" : "bad"}`} style={c.valid ? undefined : { textDecoration: "line-through" }} title={c.valid ? "context에 존재" : "검증 실패 — context에 없음"}>{c.id}</span>)}{!r.citations.length && <span className="muted">없음</span>}</div>
              {!r.citation_valid && <div className="error">일부 인용이 검증되지 않았습니다. 해당 문장을 신뢰하지 마세요.</div>}
              <div className="row"><button className="btn sm ghost" onClick={() => fb.mutate("helpful")}>👍</button><button className="btn sm ghost" onClick={() => fb.mutate("wrong")}>👎 틀림</button><button className="btn sm ghost" onClick={() => fb.mutate("unsafe")}>⚠ 부적절</button>
                <button className="btn sm ghost" onClick={() => api.post(`/investigations/${inv}/notes`, { body_md: `[AI ${r.label}]\n${r.answer_md}`, links: r.citations.map((c: any) => c.id) })}>Note로 저장</button></div>
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}
