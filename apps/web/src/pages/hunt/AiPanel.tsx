import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox } from "../../components/common";
import { api } from "../../lib/api";
import { fmtTime } from "../../lib/format";

const STATE_TONE: Record<string, string> = { not_connected: "", connected_unverified: "warn", ready: "ok", failed: "bad" };
const KIND_KO: Record<string, string> = { confirmed: "확인", inferred: "추정", unknown: "미확인" };

/** AI investigation of this hunt, kept apart from the built-in analysis: what the model asked, what the engine answered. */
export function AiPanel({ inv }: { inv: string }) {
  const qc = useQueryClient();
  const [question, setQuestion] = useState("");
  const q = useQuery({ queryKey: ["ai-investigations", inv], queryFn: () => api.get(`/investigations/${inv}/ai-investigations`) });
  const refresh = () => qc.invalidateQueries({ queryKey: ["ai-investigations", inv] });
  const probe = useMutation({ mutationFn: () => api.post("/ai/investigator/probe", {}), onSuccess: refresh });
  const start = useMutation({ mutationFn: () => api.post(`/investigations/${inv}/ai-investigations`, { question }), onSettled: refresh });
  const cancel = useMutation({ mutationFn: (id: string) => api.post(`/investigations/${inv}/ai-investigations/${id}/cancel`, {}), onSuccess: refresh });
  const st = probe.data || q.data?.status;
  if (!st) return null;
  const runs: any[] = q.data?.runs || [];
  return <details className="ha-methods ha-ai"><summary>AI 조사 — <span className={`tag ${STATE_TONE[st.state] || ""}`}>{st.label}</span>{st.model ? ` ${st.model}` : ""}{runs.length ? ` · 실행 ${runs.length}회` : ""}</summary>
    <p className="small">{st.text}</p>
    {st.state === "not_connected" ? <p className="small muted">위의 활동 목록은 모델 없이 계산한 기본 분석입니다. 모델은 관리자가 "도구·설정 &gt; 로컬 모델"에서 연결합니다.</p> : <>
      <div className="row wrap"><button className="btn sm" disabled={probe.isPending} onClick={() => probe.mutate()}>{probe.isPending ? "확인 중…" : "모델 추론 확인"}</button>
        <input className="input grow" aria-label="AI에게 줄 질문" placeholder="질문(선택) — 비워 두면 자료 개요에서 스스로 확인할 것을 찾습니다" value={question} onChange={e => setQuestion(e.target.value)} />
        <button className="btn sm primary" disabled={start.isPending || st.state === "failed"} onClick={() => start.mutate()}>{start.isPending ? "조사 중…" : "AI 조사 시작"}</button></div>
      <p className="small muted">모델은 이 헌팅의 관계사·기간 안에서 읽기 조회만 요청할 수 있고, 숫자는 모두 엔진이 계산합니다. 차단·설정 변경·코드 실행 도구는 없습니다.</p>
      <ErrorBox error={probe.error} /><ErrorBox error={start.error} /></>}
    {runs.map(r => <div key={r.id} className="ha-airun">
      <p className="small"><b>{r.mode_label}</b> · {fmtTime(r.created_at)} · {r.by} · <span className={`tag ${r.status === "complete" ? "ok" : r.status === "failed" ? "bad" : "warn"}`}>{r.stop_text}</span> · {(r.elapsed_ms / 1000).toFixed(1)}초
        {r.status === "running" && <button className="btn ghost sm" onClick={() => cancel.mutate(r.id)}>취소</button>}</p>
      {r.question && <p className="small">질문: {r.question}</p>}
      <ol className="small">{r.steps.map((s: any) => <li key={s.id}>{s.kind === "tool" ? <><b>{s.id}</b> {s.thought && <span className="muted">{s.thought} → </span>}<span className="mono">{s.tool}({JSON.stringify(s.args).slice(0, 160)})</span>
        {s.error ? <span className="tag bad">거부·오류: {s.error}</span> : <span className="muted"> → {JSON.stringify(s.result).slice(0, 220)}</span>}</> : <span className="tag bad">{s.kind === "model_error" ? `모델 호출 실패 ${s.error}` : "해석할 수 없는 응답"}</span>}</li>)}</ol>
      {r.verification?.claims?.length > 0 && <><h5>모델의 주장과 자동 확인 ({r.verification.verified}/{r.verification.total} 통과)</h5>
        <ul className="small">{r.verification.claims.map((c: any, i: number) => <li key={i}><span className={`tag ${c.verified ? "ok" : "bad"}`}>{c.verified ? "근거 일치" : "확인 실패"}</span> <span className="tag">{KIND_KO[c.kind] || c.kind}</span> {c.text}
          <span className="muted"> [{c.evidence.join(", ") || "근거 없음"}]</span>{c.problems.map((p: string) => <div key={p} className="muted">· {p}</div>)}</li>)}</ul>
        <p className="small muted">{r.verification.note}</p></>}
      {r.final?.normal_possibilities?.length > 0 && <p className="small">정상 가능성: {r.final.normal_possibilities.join(" / ")}</p>}
      {r.final?.open_questions?.length > 0 && <p className="small">남은 의문: {r.final.open_questions.join(" / ")}</p>}
    </div>)}
  </details>;
}
