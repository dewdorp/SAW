import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox } from "../../../components/common";
import { api, ApiError } from "../../../lib/api";
import "./flows.css";

export const ROLE_KO: Record<string, string> = { auth_page: "인증 화면 접근", auth_attempt: "인증 시도", lookup: "조회 요청",
  change: "변경 요청", logout: "로그아웃", other: "기타" };
const MATCH_KO: Record<string, string> = { exact: "이 경로만", prefix: "이 경로로 시작", pattern: "패턴({변수}·*)" };
const OPS: [string, string][] = [["eq", "같음"], ["ne", "다름"], ["in", "중 하나(쉼표)"], ["contains", "포함"], ["prefix", "시작"], ["ge", "이상"], ["le", "이하"]];

export type Seed = { host?: string; method?: string; path?: string; eventIds?: string[]; source?: string; meaning?: string; role?: string; kind?: "activity" | "link" };
type Draft = { kind: "activity" | "link"; content: any; include: boolean; from?: string };

const blankActivity = (seed: Seed): Draft => ({ kind: "activity", include: true, content: { host: seed.host || "", method: seed.method || "", path: seed.path || "/",
  match: "exact", params: [], meaning: seed.meaning || "", role: seed.role || "other", object_param: "", outcomes: [], note: "" } });
const blankLink = (seed: Seed): Draft => ({ kind: "link", include: true, content: { host: seed.host || "", session_cookie: "", request_id_confirmed: false, note: "" } });

function Preview({ inv, draft }: { inv: string; draft: Draft }) {
  const ready = draft.kind === "activity" && !!draft.content.host && !!draft.content.meaning && String(draft.content.path).startsWith("/");
  const q = useQuery({ queryKey: ["flow-preview", inv, draft.content], enabled: ready, retry: false,
    queryFn: () => api.post(`/investigations/${inv}/flow-knowledge/preview`, { kind: "activity", content: draft.content }) });
  if (draft.kind !== "activity") return null;
  if (!ready) return <p className="small muted">서비스·경로·의미를 채우면 이 조사에서 적용될 기록을 미리 보여 줍니다.</p>;
  if (q.isLoading) return <p className="small muted" role="status">적용될 기록을 세는 중…</p>;
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data;
  return <div className="small" role="status">
    <b>이 조사에서 적용될 기록 {d.matches.toLocaleString()}건</b> <span className="muted">(같은 서비스의 요청 {d.host_records.toLocaleString()}건 중{d.partial ? ", 일부만 확인" : ""})</span>
    {d.samples.slice(0, 3).map((s: any) => <div key={s.event_id} className="mono muted">{s.method} {s.path} → {s.status_code ?? "응답 없음"}</div>)}
    {d.matches === 0 && d.not_matched_examples.length > 0 && <div className="muted">맞지 않은 요청 예: {d.not_matched_examples.map((n: any) => `${n.method || ""} ${n.path}`).join(", ")}</div>}
  </div>;
}

function ActivityEditor({ inv, draft, onChange }: { inv: string; draft: Draft; onChange: (content: any) => void }) {
  const c = draft.content;
  const set = (patch: any) => onChange({ ...c, ...patch });
  const setOutcome = (i: number, patch: any) => set({ outcomes: c.outcomes.map((o: any, k: number) => k === i ? { ...o, ...patch } : o) });
  return <div className="fk-editor">
    <div className="fk-grid">
      <label>서비스(host)<input className="input" value={c.host} onChange={e => set({ host: e.target.value })} placeholder="portal.example.test" /></label>
      <label>메서드<select className="input" value={c.method} onChange={e => set({ method: e.target.value })}>
        <option value="">모든 메서드</option>{["GET", "POST", "PUT", "DELETE", "PATCH"].map(m => <option key={m}>{m}</option>)}</select></label>
      <label>경로<input className="input mono" value={c.path} onChange={e => set({ path: e.target.value })} /></label>
      <label>적용 방식<select className="input" value={c.match} onChange={e => set({ match: e.target.value })}>{Object.entries(MATCH_KO).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
      <label className="wide">업무 의미<input className="input" value={c.meaning} onChange={e => set({ meaning: e.target.value })} placeholder="예: 회원정보 조회" /></label>
      <label>역할<select className="input" value={c.role} onChange={e => set({ role: e.target.value })}>{Object.entries(ROLE_KO).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
      {(c.role === "lookup" || c.role === "change") && <label>대상 파라미터<input className="input mono" value={c.object_param} onChange={e => set({ object_param: e.target.value })} placeholder="예: id" /></label>}
    </div>
    <details open={c.outcomes.length > 0}><summary>결과 확인 기준 {c.outcomes.length ? `${c.outcomes.length}개` : "(없으면 결과는 '미확인'으로 표시)"}</summary>
      <p className="small muted">HTTP 200이나 쿠키만으로는 성공을 정하지 않습니다. 이 서비스에서 결과를 알려 주는 기록과 값을 적어 주세요.</p>
      {c.outcomes.map((o: any, i: number) => <div key={i} className="row wrap small fk-outcome">
        <select className="input" aria-label="기록 종류" value={o.source} onChange={e => setOutcome(i, { source: e.target.value })}><option value="app">애플리케이션 기록</option><option value="http">이 요청의 필드</option></select>
        {o.source === "app" && <input className="input" aria-label="이벤트 이름" placeholder="이벤트(예: login)" value={o.event} onChange={e => setOutcome(i, { event: e.target.value })} style={{ width: 120 }} />}
        <input className="input mono" aria-label="필드" placeholder={o.source === "app" ? "result" : "status_code"} value={o.field} onChange={e => setOutcome(i, { field: e.target.value })} style={{ width: 120 }} />
        <select className="input" aria-label="비교" value={o.op} onChange={e => setOutcome(i, { op: e.target.value })}>{OPS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
        <input className="input mono" aria-label="값" value={o.value} onChange={e => setOutcome(i, { value: e.target.value })} style={{ width: 110 }} />
        <span>이면</span>
        <select className="input" aria-label="결과" value={o.result} onChange={e => setOutcome(i, { result: e.target.value })}><option value="success">성공</option><option value="failure">실패</option></select>
        <button type="button" className="btn ghost sm" onClick={() => set({ outcomes: c.outcomes.filter((_: any, k: number) => k !== i) })}>빼기</button>
      </div>)}
      <button type="button" className="btn sm" onClick={() => set({ outcomes: [...c.outcomes, { source: "app", event: "", field: "result", op: "eq", value: "", result: "success" }] })}>기준 추가</button>
    </details>
    <Preview inv={inv} draft={draft} />
  </div>;
}

function LinkEditor({ draft, onChange }: { draft: Draft; onChange: (content: any) => void }) {
  const c = draft.content;
  return <div className="fk-editor"><div className="fk-grid">
    <label>서비스(host)<input className="input" value={c.host} onChange={e => onChange({ ...c, host: e.target.value })} /></label>
    <label>세션 식별 쿠키 이름<input className="input mono" value={c.session_cookie} onChange={e => onChange({ ...c, session_cookie: e.target.value })} placeholder="예: JSESSIONID" /></label>
    <label className="wide row"><input type="checkbox" checked={c.request_id_confirmed} onChange={e => onChange({ ...c, request_id_confirmed: e.target.checked })} />
      uuid가 다른 장비·애플리케이션 기록과 공유되는 요청 ID임을 확인했습니다</label>
  </div><p className="small muted">확인하지 않은 항목은 연결에 쓰지 않습니다. 쿠키 값은 저장하지 않고 연결용 참조로만 비교합니다.</p></div>;
}

/** Save what the analyst just learned: reusable meaning as knowledge, this incident's judgement with this incident. */
export function RememberDialog({ inv, seed, flow, onClose, onSaved }: { inv: string; seed: Seed; flow?: { runId: string; key: string; eventIds: string[] };
  onClose: () => void; onSaved: (result: any) => void }) {
  const [memo, setMemo] = useState("");
  const [drafts, setDrafts] = useState<Draft[]>([seed.kind === "link" ? blankLink(seed) : blankActivity(seed)]);
  const [verdict, setVerdict] = useState("");
  const [note, setNote] = useState("");
  const [conflict, setConflict] = useState<any[] | null>(null);
  const extract = useMutation({ mutationFn: () => api.post("/knowledge/flow-items/extract", { text: memo, host: seed.host || drafts[0]?.content.host || "" }),
    onSuccess: (d: any) => {
      if (d.drafts.length) setDrafts(d.drafts.map((x: any) => ({ kind: x.kind, content: { ...x.content, host: x.content.host || seed.host || "" }, include: true, from: x.from_text })));
      if (d.judgement) { setVerdict(d.judgement.verdict); setNote(memo); }
    } });
  const save = useMutation({ mutationFn: (allow: boolean) => api.post(`/investigations/${inv}/flows/remember`, {
      items: drafts.filter(d => d.include).map(d => ({ kind: d.kind, content: d.content, allow_conflict: allow,
        evidence: { investigation_id: inv, event_ids: (seed.eventIds || []).slice(0, 50), source: seed.source || "event" } })),
      judgement: verdict && flow ? { run_id: flow.runId, flow_key: flow.key, verdict, note, event_ids: flow.eventIds.slice(0, 200) }
        : verdict ? { verdict, note, event_ids: (seed.eventIds || []).slice(0, 200) } : null }),
    onSuccess: (d) => onSaved(d),
    onError: (e) => { if (e instanceof ApiError && e.status === 409) setConflict(e.body?.conflicts || []); } });
  const update = (i: number, patch: Partial<Draft>) => setDrafts(drafts.map((d, k) => k === i ? { ...d, ...patch } : d));
  const chosen = drafts.filter(d => d.include);
  const valid = chosen.every(d => d.content.host && (d.kind === "link" || (d.content.meaning && String(d.content.path).startsWith("/"))));
  return <>
    <div className="overlay" onClick={onClose} />
    <div className="modal xl panel" role="dialog" aria-label="메모하고 기억하기">
      <div className="ph"><span className="grow">메모하고 기억하기</span><button className="btn ghost sm" onClick={onClose}>닫기</button></div>
      <div className="pb col">
        <p className="small muted">확인한 의미를 저장하면 다음 자료부터 자동으로 적용됩니다. 재사용할 지식과 이번 사건의 판단은 따로 저장합니다.</p>
        <label className="col small">메모(선택) — 문장으로 적고 "문장에서 뽑기"를 누르면 아래 항목을 채워 줍니다
          <textarea className="input" rows={2} value={memo} onChange={e => setMemo(e.target.value)} placeholder="예: auth.html은 인증 관련 기능이고 /memberinfo는 사용자정보 조회 기능이다. 이번 요청은 정상" /></label>
        <div className="row wrap"><button className="btn sm" disabled={!memo.trim() || extract.isPending} onClick={() => extract.mutate()}>문장에서 뽑기</button>
          {extract.data && <span className="small muted" role="status">{extract.data.drafts.length ? `항목 ${extract.data.drafts.length}개를 뽑았습니다. 틀린 곳만 고쳐 주세요.` : "경로를 찾지 못했습니다. 아래에 직접 적어 주세요."}</span>}</div>
        <ErrorBox error={extract.error} />
        <h4 className="fk-h">다음 분석에 재사용할 지식</h4>
        {drafts.map((d, i) => <div key={i} className="fk-draft">
          <div className="row wrap small"><label className="row"><input type="checkbox" checked={d.include} onChange={e => update(i, { include: e.target.checked })} /><b>{d.kind === "activity" ? "업무 의미" : "연결 기준"}</b></label>
            {d.from && <span className="muted">"{d.from}"에서</span>}<div className="grow" />
            {drafts.length > 1 && <button className="btn ghost sm" onClick={() => setDrafts(drafts.filter((_, k) => k !== i))}>이 항목 빼기</button>}</div>
          {d.include && (d.kind === "activity" ? <ActivityEditor inv={inv} draft={d} onChange={content => update(i, { content })} /> : <LinkEditor draft={d} onChange={content => update(i, { content })} />)}
        </div>)}
        <div className="row wrap"><button className="btn sm" onClick={() => setDrafts([...drafts, blankActivity({ host: seed.host || drafts[0]?.content.host })])}>업무 의미 추가</button>
          <button className="btn sm" onClick={() => setDrafts([...drafts, blankLink({ host: seed.host || drafts[0]?.content.host })])}>연결 기준 추가</button></div>
        <h4 className="fk-h">이번 사건의 판단 (선택)</h4>
        <div className="row wrap small"><select className="input" aria-label="이번 사건의 판단" value={verdict} onChange={e => setVerdict(e.target.value)}>
          <option value="">판단 남기지 않음</option><option value="normal">정상으로 확인</option><option value="suspicious">의심</option><option value="undetermined">미확정</option></select>
          <input className="input grow" aria-label="판단 근거" placeholder="판단 근거" value={note} onChange={e => setNote(e.target.value)} /></div>
        <p className="small muted">판단은 이 사건에만 남습니다. 같은 주소·IP의 다른 요청을 계속 정상으로 처리하지 않습니다.</p>
        {conflict && <div className="error small" role="alert">같은 범위에 다른 내용이 이미 등록되어 있습니다:
          {conflict.map((c: any) => <div key={c.id}>· {c.title} (v{c.version})</div>)}
          둘 다 남기면 어느 쪽도 자동 적용되지 않고 '상충'으로 표시됩니다.
          <div className="row"><button className="btn sm" onClick={() => { setConflict(null); save.mutate(true); }}>상충 상태로 저장</button><button className="btn sm ghost" onClick={() => setConflict(null)}>돌아가서 고치기</button></div></div>}
        {!conflict && <ErrorBox error={save.error} />}
        <div className="row"><div className="grow" /><button className="btn" onClick={onClose}>취소</button>
          <button className="btn primary" disabled={!valid || (!chosen.length && !verdict) || save.isPending} onClick={() => save.mutate(false)}>{save.isPending ? "저장하고 다시 분석하는 중…" : chosen.length ? "기억하고 다시 분석" : "판단만 저장"}</button></div>
      </div>
    </div>
  </>;
}
