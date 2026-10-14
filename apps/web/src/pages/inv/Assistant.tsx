import { useIsMutating, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Panel } from "../../components/common";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { aiError } from "../../lib/aiErrors";

const PRIMARY: [string, string][] = [["explain_finding", "근거 설명"], ["next_steps", "추가 확인 추천"], ["report_draft", "보고서 초안"]];
const OTHER: [string, string][] = [["compare_cases", "과거 사례 비교"], ["ioc_summary", "관련 IOC 정리"], ["hunting_query", "헌팅 조건"], ["timeline_summary", "시간순 요약"], ["detection_idea", "탐지조건 제안"]];
type Citation = { id: string; type: "finding" | "event"; finding_id?: string; event_id?: string };
type EvidenceContext = {
  scope: { investigation_id: string; finding_id: string; finding_display_id: string; time: { start?: string; end?: string } | null; query_available: boolean; matched_events: number | null; sampled_events: number; sample_limit: number; truncated: boolean };
  finding: { display_id: string; title: string; risk_level: string; metrics: { name: string; label?: string; observed: unknown; baseline: unknown; unit?: string }[]; checks: { label: string; passed: boolean | null; value: unknown }[]; attack: string[] };
  observations: string[]; alternatives: string[]; next_checks: string[]; limitations: string[]; citations: Citation[];
};
const valueText = (value: unknown) => value == null ? "자료 없음" : typeof value === "object" ? JSON.stringify(value) : String(value);
function baselineText(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) return valueText(value);
  const base = value as Record<string, unknown>;
  const parts = [];
  if (base.min != null || base.max != null) parts.push(`${valueText(base.min)} ~ ${valueText(base.max)}`);
  if (base.median != null) parts.push(`중앙값 ${valueText(base.median)}`);
  if (base.source) parts.push(valueText(base.source));
  return parts.length ? parts.join(" · ") : "상세 탐지에서 확인";
}

/** Remount on scope changes so late responses and save state cannot cross investigations or findings. */
export function Assistant({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  return <ScopedAssistant key={JSON.stringify([inv, ctx.findingId])} inv={inv} findingId={ctx.findingId} />;
}

/** Output is data: render text and resolve citations only through server-provided mappings. */
function ScopedAssistant({ inv, findingId }: { inv: string; findingId: string | null }) {
  const ctx = useInv(inv);
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const st = useQuery({ queryKey: ["ai-status"], queryFn: () => api.get("/ai/status") });
  const preview = useQuery({ queryKey: ["ai-context", inv, findingId], enabled: !!findingId,
    queryFn: () => api.get<EvidenceContext>(`/ai/context?investigation_id=${encodeURIComponent(inv)}&finding_id=${encodeURIComponent(findingId!)}`) });
  const facts = preview.data?.scope.investigation_id === inv && preview.data.scope.finding_id === findingId ? preview.data : undefined;
  const busy = useIsMutating({ mutationKey: ["ai-generation"] }) > 0;
  const m = useMutation({ mutationKey: ["ai-generation"], mutationFn: (x: { action: string; question?: string }) => api.post("/ai/actions", { investigation_id: inv, finding_id: findingId, ...x }) });
  const r = m.isPending ? undefined : m.data;
  const wrongScope = !!r && (r.context_scope !== "selected_finding" || !r.scope || r.scope.investigation_id !== inv || r.scope.finding_id !== findingId);
  const rejected = r?.output_status === "rejected" || !!wrongScope;
  const template = r?.output_status === "template" || r?.is_llm === false;
  const label = rejected ? "AI 출력 검증 실패 · 답변 미채택" : template ? "오프라인 템플릿 (LLM 아님)" : "AI 생성 초안 · 사실 검토 필요";
  const save = useMutation({ mutationFn: (output: any) => api.post(`/investigations/${inv}/notes`, {
    body_md: `[${label}]\n선택 탐지: ${facts?.finding.display_id || findingId}\n${output.answer_md}`, links: output.citations.filter((c: any) => c.valid).map((c: any) => c.id),
  }), onSuccess: () => { qc.invalidateQueries({ queryKey: ["notes", inv] }); qc.invalidateQueries({ queryKey: ["timeline", inv] }); } });
  const fb = useMutation({ mutationFn: (feedback: string) => api.post(`/ai/${r.id}/feedback`, { feedback }) });
  const canGenerate = !!findingId && !!facts && !preview.error && !!st.data?.available && !st.error && !busy && !save.isPending;
  const generate = (action: string, question?: string) => { if (canGenerate) { save.reset(); fb.reset(); m.mutate({ action, ...(question ? { question } : {}) }); } };
  const openCitation = (c: Citation) => {
    if (c.type === "finding" && c.finding_id) ctx.set({ findingId: c.finding_id, tab: "findings" });
    if (c.type === "event" && c.event_id) ctx.set({ eventId: c.event_id });
  };
  const citationButton = (c: Citation) => <button key={c.id} className="btn sm ghost" aria-label={`근거 ${c.id} 열기`} onClick={() => openCitation(c)}>{c.id} ↗</button>;
  const statusLabel = st.error ? "실행 상태 확인 실패" : !st.data ? "실행 상태 확인 중" : st.data.is_llm ? `${st.data.provider} · ${st.data.model}` : st.data.provider === "template" ? "템플릿 모드 · 모델 추론 없음" : "모델 추론 비활성";
  return <Panel title="✦ SOC Assistant" right={<span className={`tag ${st.data?.is_llm && !st.error ? "ai" : "warn"}`}>{statusLabel}</span>}>
    <div className="col small">
      <p>선택한 탐지의 근거를 확인하고 설명·조사 계획·보고서 초안을 작성합니다. 최종 판단과 조치는 분석가가 결정하며, 자동 종결·차단·룰 배포는 하지 않습니다.</p>
      {!findingId && <div className="muted">탐지 목록에서 분석할 탐지를 선택하세요. 선택한 탐지의 근거만 사용합니다.</div>}
      <ErrorBox error={aiError(preview.error)} />
      {findingId && preview.isPending && <span className="muted">선택한 탐지의 근거를 불러오는 중…</span>}
      {facts && <div className="ai-block col small">
        <strong>근거 요약 · 모델 추론 없음</strong>
        <div>{facts.finding.display_id} · {facts.finding.title}</div>
        {facts.scope.query_available ? <>
          <div className="muted">일치 {facts.scope.matched_events}건 · 원문 바로가기 표본 {facts.scope.sampled_events}건 (최대 {facts.scope.sample_limit}건)</div>
          <div className="muted">시간 범위: {facts.scope.time ? `${facts.scope.time.start || "시작 미지정"} ~ ${facts.scope.time.end || "종료 미지정"}` : "탐지 근거의 전체 시간 범위"}</div>
        </> : <div className="muted">근거 조회 범위 없음 · 조회하지 않음</div>}
        {facts.scope.truncated && <div className="tag warn">전체 일치 자료 중 일부 표본의 바로가기만 표시합니다. 전체 원문을 읽은 결과가 아닙니다.</div>}
        <div className="muted">미리보기는 표본 참조만 표시합니다. 주요 3개 생성은 저장된 탐지 지표를 사용하며 이벤트 원문을 전달하지 않습니다.</div>
        {facts.observations.map((text, i) => <div key={i}>{text}</div>)}
        <strong>정상 가능성과 다른 설명</strong>
        {facts.alternatives.map((text, i) => <div key={i}>{text}</div>)}
        <strong>추가로 확인할 사항</strong>
        <ol style={{ margin: 0, paddingLeft: "1.5em" }}>{facts.next_checks.map((text, i) => <li key={i}>{text}</li>)}</ol>
        {facts.limitations.map((text, i) => <div key={i} className="muted">{text}</div>)}
        <details><summary>측정값·확인 결과·근거 열기</summary><div className="col">
          {facts.finding.metrics.map((metric, i) => <div key={i}>{metric.label || metric.name}: 관측 {valueText(metric.observed)} · 기준 {baselineText(metric.baseline)} {metric.unit || ""}</div>)}
          {facts.finding.checks.map((check, i) => <div key={i}>{check.label}: {check.passed === true ? "조건 충족" : check.passed === false ? "조건 미충족" : "미확인"} · {valueText(check.value)}</div>)}
          {!!facts.finding.attack.length && <div>ATT&amp;CK 제안: {facts.finding.attack.join(", ")} · 검토 필요</div>}
          <div className="row wrap">{facts.citations.map(citationButton)}</div>
        </div></details>
      </div>}
      <ErrorBox error={aiError(st.error)} />
      {st.data?.detail && !st.error && <div className="muted">{st.data.detail}</div>}
      {st.data?.synthetic_only && <div className="muted">합성 데이터 전용 · 운영 품질 미채택</div>}
      {st.data && !st.data.available && !st.error && <div className="muted">모델 생성은 사용할 수 없습니다. 위 근거 요약과 확인 목록은 모델 없이 사용할 수 있습니다.</div>}
      <div className="row wrap">{PRIMARY.map(([action, text]) => <button key={action} className="btn sm" disabled={!canGenerate} onClick={() => generate(action)}>{text}</button>)}</div>
      <details><summary>기타 분석 지원</summary><div className="col">
        <div className="row wrap">{OTHER.map(([action, text]) => <button key={action} className="btn sm" disabled={!canGenerate} onClick={() => generate(action)}>{text}</button>)}</div>
        <div className="row"><input className="input grow" aria-label="선택한 탐지에 대한 질문" placeholder="선택한 탐지에 대해 질문…" value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && q.trim()) generate("ask", q.trim()); }} />
          <button className="btn sm" disabled={!q.trim() || !canGenerate} onClick={() => generate("ask", q.trim())}>질문</button></div>
      </div></details>
      {busy && <span role="status"><span className="spinner" /> 생성 중… CPU에서는 시간이 걸릴 수 있습니다. 중복 요청은 잠시 기다려 주세요.</span>}
      <ErrorBox error={aiError(m.error)} />
      {r && <div className="ai-block col small">
        <div className="row wrap"><span className={`tag ${rejected ? "bad" : template ? "warn" : "ai"}`}>{label}</span><span className="muted">{r.provider} · {r.model} · {r.latency_ms}ms · 탐지 {r.context_size.findings} · 표본 {r.context_size.samples}</span></div>
        <span className="muted">{template ? "템플릿 생성 · LLM 추론 없음" : r.execution_status === "executed" ? "실제 모델 추론 실행됨" : "추론 실행 상태 확인 필요"}</span>
        {!!r.injection_signals.length && <div className="tag bad">⚠ 근거 데이터에 지시문 의심 문자열: {r.injection_signals.join(" | ")} — 명령으로 처리하지 않음</div>}
        {rejected ? <div className="error">{wrongScope ? "선택한 탐지와 응답 범위가 다릅니다." : r.output_reason === "invalid_citations" ? "인용 근거 확인에 실패했습니다." : "응답 형식 확인에 실패했습니다."} 답변을 표시하거나 저장하지 않습니다.</div> : <>
          {!template && <span className="muted">문장별 사실 근거는 검증되지 않았습니다. 인용 ID 확인만으로 내용이 사실임을 보장하지 않습니다.</span>}
          <div className="pre">{r.answer_md}</div>
          {r.query && <div className="mono pre">{JSON.stringify(r.query, null, 1)}</div>}
          <div className="row wrap">근거: {r.citations.map((c: any) => {
            const mapped = c.valid && facts?.citations.find((item) => item.id === c.id);
            return mapped ? citationButton(mapped) : <span key={c.id} className={`tag ${c.valid ? "ok" : "bad"}`} title={c.valid ? "전달된 근거에 존재 · 직접 이동 정보 없음" : "검증 실패 — 전달된 근거에 없음"}>{c.id}</span>;
          })}{!r.citations.length && <span className="muted">없음</span>}</div>
          {!r.citation_valid && <div className="error">일부 인용이 검증되지 않았습니다. 해당 문장을 신뢰하지 마세요.</div>}
        </>}
        <div className="row wrap"><button className="btn sm ghost" disabled={fb.isPending} onClick={() => fb.mutate("helpful")}>👍 도움 됨</button><button className="btn sm ghost" disabled={fb.isPending} onClick={() => fb.mutate("wrong")}>👎 틀림</button><button className="btn sm ghost" disabled={fb.isPending} onClick={() => fb.mutate("unsafe")}>⚠ 부적절</button>
          <button className="btn sm ghost" disabled={rejected || !r.citation_valid || save.isPending || save.isSuccess || busy} onClick={() => { if (!rejected && r.citation_valid) save.mutate(r); }}>노트로 저장</button></div>
        <ErrorBox error={aiError(save.error)} /><ErrorBox error={aiError(fb.error)} />
        {save.isPending && <span role="status">노트 저장 중…</span>}{save.isSuccess && <span role="status">노트에 저장했습니다.</span>}
        {fb.isSuccess && <span role="status">의견을 기록했습니다. 자동 학습이나 판단 변경은 하지 않습니다.</span>}
      </div>}
    </div>
  </Panel>;
}
