import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { CheckDialog, type Target } from "../../components/Checks";
import { DATA_STATES, SOURCE_LABELS, type GuidanceResponse, type GuidanceScope } from "../../components/GuidanceResponse";
import { ErrorBox, Panel } from "../../components/common";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtTime } from "../../lib/format";

const METHOD = "soc-guidance/1.0";
const SOURCES = SOURCE_LABELS;
const STATUS: Record<string, string> = { open: "확인 필요", answered: "답변 기록됨", follow_up: "후속확인 등록됨", not_applicable: "이번 범위에 해당 없음" };
type Question = { rule_id: string; question_id: string; title: string; purpose: string; status: string; allowed_actions: string[]; needed_sources: string[]; resolution_conditions: string[]; forbidden_claims: string[]; answer_check_ids: string[] };
type Preview = { methodology: { id: string; version: string; digest: string }; scope: { scope_key: string; effective_time: GuidanceScope["time"]; evidence_manifest: unknown[] }; facts: { id: string; label: string; value: unknown; data_state: string; query_ref: string; evidence_refs: string[] }[]; unknowns: { source: string; state: string; reason: string; source_kind?: string; author?: string }[]; questions: Question[]; queries: { id: string; query: { filters?: GuidanceScope["filters"]; branches?: GuidanceScope["filters"][]; time?: GuidanceScope["time"] }; executed_at: string; data_state: string; matched_count: number | null; sampled_count: number; limit: number; truncated: boolean; missing_count: number | null; error_code?: string; evidence_refs?: string[] }[]; limits: string[] };

/** Scope changes discard response forms so answers never migrate to another IP or time range. */
export function GuidancePanel({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const targetType = ctx.findingId ? "finding" : ctx.selection?.type === "ip" ? "entity" : "investigation";
  const targetKey = ctx.findingId || (ctx.selection?.type === "ip" ? `ip:${ctx.selection.value}` : inv);
  const scope = { target_type: targetType, target_key: targetKey, filters: ctx.filters, time: ctx.time };
  return <ScopedGuidance key={JSON.stringify([inv, scope])} inv={inv} base={scope} />;
}

function ScopedGuidance({ inv, base }: { inv: string; base: Pick<GuidanceScope, "target_type" | "target_key" | "filters" | "time"> }) {
  const ctx = useInv(inv);
  const [ipInput, setIpInput] = useState(base.target_type === "entity" ? base.target_key.slice(3) : "");
  const [receiptsOpen, setReceiptsOpen] = useState(false);
  const [role, setRole] = useState("either");
  const [asOf, setAsOf] = useState<string | null>(null);
  const [dateInput, setDateInput] = useState("");
  const [answer, setAnswer] = useState<GuidanceResponse | null>(null);
  const request: GuidanceScope = { ...base, role, as_of: asOf, methodology_version: METHOD };
  const q = useQuery<Preview>({ queryKey: ["guidance", inv, request], queryFn: () => api.post(`/investigations/${inv}/guidance/preview`, request), retry: false });
  const me = useQuery({ queryKey: ["me"], queryFn: () => api.get("/auth/me"), retry: false, staleTime: 60_000 });
  const d = q.data;
  const canWrite = me.data?.permissions?.includes("investigation.write");
  const target: Target = { type: base.target_type === "investigation" ? "set" : base.target_type as "entity" | "finding", key: base.target_key, label: base.target_type === "investigation" ? "현재 조사 범위" : base.target_key, time: [base.time?.start, base.time?.end] };
  const openQuery = (ref: string, branch = 0) => {
    const query = d?.queries.find(x => x.id === ref)?.query;
    if (query) ctx.set({ filters: query.branches?.[branch] || query.filters || [], time: query.time || null, tab: "raw" });
  };
  const respond = (item: Question) => setAnswer({ methodology_version: METHOD, rule_id: item.rule_id, scope: request, title: item.title, answer_status: "follow_up", data_states: (d?.unknowns || []).map(({ source, state, reason }) => ({ source, state, reason })) });
  return <Panel title="조사 안내" right={<span className="tag">AI 없이 동작</span>}>
    <div className="col small" style={{ gap: 10 }}>
      <div className="col" style={{ gap: 5 }}>
        <input className="input" aria-label="조사할 IP" placeholder="같은 조사에서 확인할 IP (로그가 없어도 가능)" maxLength={64} value={ipInput} onChange={e => setIpInput(e.target.value)} />
        <button className="btn sm" disabled={!ipInput.trim()} onClick={() => ctx.set({ selection: { type: "ip", value: ipInput.trim() }, findingId: null })}>이 조사에서 IP 확인</button>
      </div>
      <div className="row wrap"><span className="mono" style={{ overflowWrap: "anywhere" }}>{base.target_type === "investigation" ? "현재 조사" : base.target_key}</span>
        {base.target_type === "entity" && <label className="row">IP 역할<select className="input" aria-label="IP 역할" value={role} onChange={e => { setAnswer(null); setRole(e.target.value); }}><option value="either">출발지 또는 목적지</option><option value="src">출발지</option><option value="dst">목적지</option></select></label>}
      </div>
      <div className="muted">현재 필터 {base.filters.length}개 · {base.time ? `${base.time.start || "시작 미지정"} ~ ${base.time.end || "종료 미지정"}` : "선택 범위의 전체 관측 시간"}</div>
      <details open={receiptsOpen} onToggle={e => setReceiptsOpen(e.currentTarget.open)}><summary>범위·조회 기록</summary>
        <div className="col" style={{ gap: 5 }}>
          <div>판단 기준시점: {asOf || "이번 조회 시점"}. 과거 스냅샷이 없으면 과거 자료를 재현한 것으로 사용하지 않습니다.</div>
          <input className="input" aria-label="판단 기준시점" placeholder="선택: ISO 시각 (예: 2026-10-15T01:00:00Z)" value={dateInput} onChange={e => setDateInput(e.target.value)} />
          <button className="btn sm" disabled={!!dateInput && !Number.isFinite(Date.parse(dateInput))} onClick={() => { setAnswer(null); setAsOf(dateInput ? new Date(dateInput).toISOString() : null); }}>기준시점 적용</button>
          <div className="mono">{METHOD}</div>
          {d?.queries.map(query => <div key={query.id} style={{ borderTop: "1px solid var(--line)", paddingTop: 5 }}>
            <b>{query.id}</b> · {DATA_STATES[query.data_state] || query.data_state}<br />
            일치 {query.matched_count == null ? "미확인" : `${query.matched_count}건`} · 표시 표본 {query.sampled_count}건 / 상한 {query.limit}건<br />
            {fmtTime(query.executed_at)}{query.truncated && " · 전체 원문을 읽지 않음"}{query.error_code && ` · ${query.error_code}`}
            {(query.query.branches || [query.query.filters || []]).map((_, i, branches) => <button key={i} className="btn sm ghost" disabled={query.data_state === "query_failed" || query.data_state === "forbidden"} onClick={() => openQuery(query.id, i)}>{branches.length > 1 ? (i === 0 ? "출발지 일치 원문" : "목적지 일치 원문 (출발지 중복 제외)") : "이 조회의 원문"}</button>)}
            {!!query.evidence_refs?.length && <div className="row wrap">{query.evidence_refs.slice(0, 20).map(id => <button key={id} className="btn sm ghost mono" onClick={() => ctx.set({ eventId: id })}>원문 {id.slice(0, 12)} ↗</button>)}</div>}
          </div>)}
        </div>
      </details>
      {q.isPending && <span className="muted">현재 범위의 자료를 조회하고 있습니다…</span>}
      <ErrorBox error={q.error} />
      {q.error && <span className="tag warn">조회 실패 · 결과 0건으로 판단하지 마세요.</span>}
      {d && <>
        <div className="col" style={{ gap: 5 }}><strong>현재 확인된 내용</strong>
          {d.facts.map(f => <div key={f.id} className="row wrap" style={{ borderBottom: "1px solid var(--line)", paddingBottom: 4 }}>
            <span className="grow">{f.label}</span><b>{f.value == null ? "건수 미확인" : typeof f.value === "object" ? JSON.stringify(f.value) : String(f.value)}</b>
            <span className="tag">{DATA_STATES[f.data_state] || f.data_state}</span>
            {f.query_ref && <button className="btn ghost sm" onClick={() => setReceiptsOpen(true)} aria-label={`${f.label} 근거 조회`}>근거 ↗</button>}
          </div>)}
          {!d.facts.length && <span className="muted">확인된 사실이 없습니다.</span>}
        </div>
        <div className="col" style={{ gap: 5 }}><strong>아직 확인하지 못한 내용</strong>
          {d.unknowns.map((u, i) => <div key={`${u.source}-${i}`}><span className="tag warn">{DATA_STATES[u.state] || u.state}</span> {SOURCES[u.source] || u.source} · {u.reason}{u.source_kind === "analyst_statement" && <span className="muted"> · 분석가 기록{u.author ? ` (${u.author})` : ""}</span>}</div>)}
          {d.limits.map((text, i) => <div key={i} className="muted">· {text}</div>)}
        </div>
        <div className="col" style={{ gap: 8 }}><strong>다음에 확인할 사항</strong>
          {d.questions.map(item => <div key={item.question_id} className="ck-item col" style={{ gap: 5 }}>
            <div className="row wrap"><b>{item.title}</b><span className="tag">{STATUS[item.status] || item.status}</span></div>
            <div>{item.purpose}</div>
            <div className="muted">필요 자료: {item.needed_sources.join(" · ")}</div>
            <details><summary>판단 근거·금지할 단정</summary>{item.resolution_conditions.map(x => <div key={x}>확인: {x}</div>)}{item.forbidden_claims.map(x => <div key={x} className="d-chg">단정 금지: {x}</div>)}</details>
            {item.status === "open" && canWrite && <button className="btn sm primary" onClick={() => respond(item)}>답변·근거 남기기</button>}
            {item.status !== "open" && <button className="btn sm" onClick={() => ctx.set({ tab: "checks" })}>저장한 확인 기록 보기</button>}
          </div>)}
          {!d.questions.length && <span className="muted">현재 규칙에서 추가 안내할 항목이 없습니다. 정상 판정을 뜻하지 않습니다.</span>}
        </div>
      </>}
      {answer && <CheckDialog inv={inv} target={target} guidance={answer} evidenceOptions={[...new Set((d?.queries || []).flatMap(x => x.evidence_refs || []))]} onClose={() => setAnswer(null)} />}
    </div>
  </Panel>;
}
