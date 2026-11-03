import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../lib/api";
import { fmtNum, fmtTime } from "../lib/format";
import { ErrorBox } from "./common";
import { ANSWER_STATES, GuidanceResponseFields, type GuidanceResponse } from "./GuidanceResponse";

/** Confirmation records: what was checked (the question), how it was judged, how far (one / sample / all). */
export const QUESTIONS: [string, string, string][] = [
  ["nature", "요청 성격", "공격·비정상 요청인가"], ["success", "성공 여부", "실제로 실행·성공했는가"],
  ["impact", "피해 여부", "피해·유출이 있었는가"], ["business", "정상 업무 여부", "정상 업무로 설명되는가"],
];
export const JUDGEMENTS: [string, string][] = [["normal", "정상"], ["suspicious", "의심"], ["malicious", "악성"], ["undetermined", "판단 불가"]];
const Q_KO = Object.fromEntries(QUESTIONS.map(([k, l]) => [k, l]));
const J_KO = Object.fromEntries(JUDGEMENTS);
const COVER_KO: Record<string, string> = { one: "", selected: "고른 기록", sample: "표본", all: "전체" };

export type Target = {
  type: "event" | "entity" | "finding" | "set"; key: string; label: string;
  time?: [string | null | undefined, string | null | undefined]; evidence?: string[];
  /** search-result targets: the query, how many records match and the ids of the first loaded rows */
  set?: { query: unknown; total: number | null; loaded: string[] };
};
export type BehaviorResponse = {
  result_id: string; result_sha256: string; metric_ids: string[];
  answer_status: "answered" | "follow_up" | "not_applicable";
  follow_up?: { target: string; due_at?: string | null; needed_data: string[]; items: string[]; priority: string };
};
export type Mark = { id: string; questions: string[]; judgement: string | null; author: string; kind: string; coverage: string; shared: boolean; source_state: string; guidance_status?: string };
export type Marks = { events: Record<string, Mark[]>; entities: Record<string, Mark[]>; findings: Record<string, Mark[]> };

export function useMarks(inv: string) {
  return useQuery<Marks>({ queryKey: ["checks", inv, "marks"], queryFn: () => api.get(`/investigations/${inv}/checks/marks`), staleTime: 15_000 });
}

/** Compact marks for a table cell. `parent` marks belong to an address/name the row carries, not to the row itself. */
export function MarkBadges({ own, parent }: { own?: Mark[]; parent?: Mark[] }) {
  const one = (m: Mark, i: number, up: boolean) => (
    <span key={(up ? "p" : "o") + m.id + i} className={`ck ${m.judgement || "none"} ${up ? "up" : ""} ${m.kind === "cited" ? "cited" : ""}`}
      title={`${up ? "상위 대상(주소·이름)에 대한 확인 — 이 기록을 직접 판단한 것은 아님\n" : ""}${m.kind === "cited" ? "다른 조사의 확인을 참고\n" : ""}확인: ${m.questions.map((q) => Q_KO[q]).join(", ")}${m.judgement ? `\n판단: ${J_KO[m.judgement]}` : "\n판단 없음"}${COVER_KO[m.coverage] ? `\n범위: ${COVER_KO[m.coverage]}` : ""}\n${m.author}`}>
      {m.guidance_status && m.guidance_status !== "answered" ? ANSWER_STATES[m.guidance_status] : <>{up ? "↑" : "✓"}{m.judgement ? J_KO[m.judgement] : "확인"}</>}{m.coverage === "sample" ? "·표본" : ""}
    </span>);
  if (!own?.length && !parent?.length) return null;
  return <span className="ck-row">{(own || []).slice(0, 2).map((m, i) => one(m, i, false))}{(parent || []).slice(0, 1).map((m, i) => one(m, i, true))}
    {(own?.length || 0) + (parent?.length || 0) > 3 && <span className="muted small">+{(own?.length || 0) + (parent?.length || 0) - 3}</span>}</span>;
}

/** "확인 기록" window: the question(s), an optional judgement with a one-line reason, the range, optional sharing. */
export function CheckDialog({ inv, target, edit, guidance: initialGuidance, behavior: initialBehavior, evidenceOptions = [], onClose }: { inv: string; target: Target; edit?: any; guidance?: GuidanceResponse; behavior?: BehaviorResponse; evidenceOptions?: string[]; onClose: () => void }) {
  const qc = useQueryClient();
  const [selectedEvidence, setSelectedEvidence] = useState<string[]>(edit?.evidence || target.evidence || []);
  const [behavior, setBehavior] = useState<BehaviorResponse | undefined>(edit?.behavior || initialBehavior);
  const [guidance, setGuidance] = useState<GuidanceResponse | undefined>(edit?.guidance || initialGuidance);
  const editEvidence = useQuery<{ queries: { evidence_refs?: string[] }[] }>({
    queryKey: ["guidance-edit-evidence", inv, edit?.id, guidance?.scope],
    queryFn: () => api.post(`/investigations/${inv}/guidance/preview`, guidance!.scope),
    enabled: !!edit && !!guidance, retry: false,
  });
  const availableEvidence = [...new Set([...evidenceOptions, ...(editEvidence.data?.queries || []).flatMap(q => q.evidence_refs || [])])];
  const [questions, setQuestions] = useState<string[]>(edit?.questions || (behavior ? ["nature"] : []));
  const [judgement, setJudgement] = useState<string>(edit?.judgement || (guidance || behavior ? "undetermined" : ""));
  const [note, setNote] = useState<string>(edit?.note || "");
  const [coverage, setCoverage] = useState<string>(edit?.coverage || (target.type === "set" ? "sample" : "one"));
  const [sample, setSample] = useState<number>(Math.min(30, target.set?.loaded.length || 30));
  const [shared, setShared] = useState<boolean>(!!edit?.shared);
  const [share, setShare] = useState<Record<string, string>>(edit?.share || { fact: "", confirmed_scope: "", unconfirmed_scope: "" });
  const save = useMutation({
    mutationFn: () => {
      const body: any = { questions, judgement: judgement || null, note, shared, share };
      if (behavior) {
        body.evidence = selectedEvidence;
        body.scope = { ...(edit?.scope || {}), coverage: "selected", event_ids: selectedEvidence, checked: selectedEvidence.length };
        const f = behavior.follow_up;
        body.behavior = { result_id: behavior.result_id, result_sha256: behavior.result_sha256,
          metric_ids: behavior.metric_ids, answer_status: behavior.answer_status,
          follow_up: f ? { ...f, needed_data: f.needed_data.map(x => x.trim()).filter(Boolean), items: f.items.map(x => x.trim()).filter(Boolean) } : undefined };
      }
      if (guidance) {
        body.evidence = selectedEvidence;
        const f = guidance.follow_up;
        body.guidance = { methodology_version: guidance.methodology_version, rule_id: guidance.rule_id, scope: guidance.scope,
          answer_status: guidance.answer_status || "follow_up", data_states: (guidance.data_states || []).map(({ source, state, reason }) => ({ source, state, reason })), answer: note,
          follow_up: f ? { ...f, needed_data: f.needed_data.map(x => x.trim()).filter(Boolean), items: f.items.map(x => x.trim()).filter(Boolean) } : undefined };
      }
      if (!edit) {
        Object.assign(body, { target_type: target.type, target_key: target.key, target_label: target.label,
          time_start: target.time?.[0] || null, time_end: target.time?.[1] || null, evidence: guidance || behavior ? selectedEvidence : target.evidence || [] });
        if (target.set && !behavior) body.scope = coverage === "sample"
          ? { coverage, query: target.set.query, total: target.set.total, checked: sample, loaded: target.set.loaded.length, event_ids: target.set.loaded.slice(0, sample) }
          : { coverage: "all", query: target.set.query, total: target.set.total, checked: target.set.total, loaded: target.set.loaded.length };
      }
      return edit ? api.put(`/investigations/${inv}/checks/${edit.id}`, body) : api.post(`/investigations/${inv}/checks`, body);
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["checks", inv] }); qc.invalidateQueries({ queryKey: ["briefing", inv] }); qc.invalidateQueries({ queryKey: ["guidance", inv] }); qc.invalidateQueries({ queryKey: ["closure-draft", inv] }); onClose(); },
  });
  const toggle = (k: string) => setQuestions(questions.includes(k) ? questions.filter((x) => x !== k) : [...questions, k]);
  const needNote = judgement === "normal" || judgement === "malicious";
  const followOk = !guidance || (guidance.answer_status || "follow_up") !== "follow_up" || (!!guidance.follow_up?.target.trim() && guidance.follow_up.items.some(x => x.trim()) && guidance.follow_up.needed_data.some(x => x.trim()));
  const behaviorFollowOk = !behavior || behavior.answer_status !== "follow_up" || (!!behavior.follow_up?.target.trim() && behavior.follow_up.items.some(x => x.trim()) && behavior.follow_up.needed_data.some(x => x.trim()));
  const behaviorOk = !behavior || (selectedEvidence.length <= 20 && !!note.trim() && behaviorFollowOk && (behavior.answer_status !== "answered" || selectedEvidence.length > 0));
  const ok = behaviorOk && (guidance ? !!note.trim() && followOk && (guidance.answer_status !== "answered" || selectedEvidence.length > 0) : questions.length > 0) && (!needNote || note.trim()) && (!shared || (share.fact?.trim() && share.confirmed_scope?.trim()));
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="modal panel" role="dialog" aria-label="확인 기록" style={{ width: 580 }}>
        <div className="ph"><span className="grow">{edit ? "판단 변경" : "확인 기록"}</span><button className="btn ghost sm" onClick={onClose}>닫기</button></div>
        <div className="pb col" style={{ gap: 12 }}>
        {behavior && <div className="col" style={{ gap: 7 }}>
          <b>행위 결과 확인 · {behavior.result_id}</b>
          <div className="small muted">해석은 확인 기록에 저장하며 계산된 관측값을 변경하지 않습니다.</div>
          <label className="col small">답변 상태<select className="input" aria-label="행위 답변 상태" value={behavior.answer_status}
            onChange={e => setBehavior({ ...behavior, answer_status: e.target.value as BehaviorResponse["answer_status"] })}>
            {Object.entries(ANSWER_STATES).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select></label>
          {behavior.answer_status === "follow_up" && <GuidanceResponseFields value={{ methodology_version: "", rule_id: "", scope: {} as any,
            title: "행위 후속확인", answer_status: "follow_up", data_states: [], follow_up: behavior.follow_up }}
            onChange={v => setBehavior({ ...behavior, answer_status: (v.answer_status || "follow_up") as BehaviorResponse["answer_status"], follow_up: v.follow_up })} />}
        </div>}
        {(guidance || behavior) && <>
          {guidance && <GuidanceResponseFields value={guidance} onChange={setGuidance} />}
          <details open={(guidance || behavior)?.answer_status === "answered"}><summary className="small">선택 근거 {selectedEvidence.length}건</summary>
            <div className="small muted">조회 표본 중 실제로 확인한 기록만 선택하세요. 답변 기록 상태는 근거 선택이 필요합니다.{behavior && " 행위 근거는 최대 20건입니다."}</div>
            {[...new Set([...selectedEvidence, ...availableEvidence])].map(id => <label key={id} className="row small" style={{ overflowWrap: "anywhere" }}><input type="checkbox" aria-label={`근거 선택 ${id}`} checked={selectedEvidence.includes(id)} onChange={e => setSelectedEvidence(e.target.checked ? [...selectedEvidence, id] : selectedEvidence.filter(x => x !== id))} />{id}</label>)}
            <ErrorBox error={editEvidence.error} />
            {editEvidence.isFetching && <div className="small muted">기존 범위에서 새 근거를 조회합니다…</div>}
            {!availableEvidence.length && !selectedEvidence.length && <div className="small muted">선택 가능한 원문이 없습니다. 자료 부족과 후속확인으로 기록할 수 있습니다.</div>}
          </details>
        </>}
        <div className="small"><span className="muted">대상</span> <span className="mono">{target.label}</span></div>
        <div className="col" style={{ gap: 4 }}>
          <div className="small muted">{guidance ? "기존 확인 분류 (선택하지 않으면 안내 항목에서 자동 분류)" : "무엇을 확인했나요? (하나 이상)"}</div>
          <div className="row wrap">{QUESTIONS.map(([k, l, hint]) => (
            <label key={k} className={`chip-check ${questions.includes(k) ? "on" : ""}`} title={hint}><input type="checkbox" checked={questions.includes(k)} onChange={() => toggle(k)} />{l}</label>))}</div>
        </div>
        <div className="col" style={{ gap: 4 }}>
          <div className="small muted">판단 (아직 판단할 수 없으면 비워 두세요 — 확인한 사실만 남습니다)</div>
          <div className="row wrap">
            <label className={`chip-check ${judgement === "" ? "on" : ""}`}><input type="radio" name="ck-j" checked={judgement === ""} onChange={() => setJudgement("")} />판단 없음</label>
            {JUDGEMENTS.map(([k, l]) => <label key={k} className={`chip-check ck ${k} ${judgement === k ? "on" : ""}`}><input type="radio" name="ck-j" checked={judgement === k} onChange={() => setJudgement(k)} />{l}</label>)}
          </div>
        </div>
        <input className="input" aria-label="근거" placeholder={guidance || behavior ? "현재 확인한 내용과 판단 근거 (필수)" : needNote ? "근거 한 줄 (필수) 예) DB팀 확인: 02시 정산 배치" : "근거·메모 한 줄 (선택)"} value={note} onChange={(e) => setNote(e.target.value)} />
        {target.set && !edit && !behavior && (
          <div className="col" style={{ gap: 4 }}>
            <div className="small muted">어디까지 봤나요? (검색 결과 {target.set.total != null ? `${fmtNum(target.set.total)}건` : "건수 미확인"})</div>
            <label className="row small"><input type="radio" name="ck-c" checked={coverage === "sample"} onChange={() => setCoverage("sample")} /> 일부만 봤음(표본)
              <input className="input" type="number" min={1} max={Math.max(1, target.set.loaded.length)} aria-label="표본 건수" style={{ width: 80 }} value={sample} onChange={(e) => setSample(Math.min(Math.max(1, target.set!.loaded.length), Math.max(1, Number(e.target.value) || 1)))} />건
              <span className="muted">(화면에 불러온 {fmtNum(target.set.loaded.length)}건 안에서)</span></label>
            {(() => {
              const partial = target.set.total == null || target.set.loaded.length < target.set.total;
              return <label className="row small" title={partial ? "불러온 기록이 검색 결과 전체보다 적습니다" : undefined}>
                <input type="radio" name="ck-c" disabled={partial} checked={coverage === "all"} onChange={() => setCoverage("all")} /> 전체를 모두 확인했음
                {partial && <span className="muted">(불러온 {fmtNum(target.set.loaded.length)}건 &lt; 전체 {target.set.total != null ? fmtNum(target.set.total) : "미확인"}건 — 표본으로만 기록 가능)</span>}
              </label>;
            })()}
            <div className="small muted">표본 확인은 전체 확인으로 세지 않으며, 보고용 요약의 유의할 점에 표시됩니다.</div>
          </div>
        )}
        {target.type === "entity" && !guidance && !behavior && (
          <div className="col" style={{ gap: 4 }}>
            <label className="row small"><input type="checkbox" checked={shared} onChange={(e) => setShared(e.target.checked)} /> 다른 조사에도 공유 (같은 대상이 나오면 참고로 표시됩니다. 그 조사의 판정을 바꾸지 않습니다)</label>
            {shared && (<>
              <input className="input" aria-label="확인한 사실" placeholder="확인한 사실 예) 정산 배치 서버로 사용됨" value={share.fact || ""} onChange={(e) => setShare({ ...share, fact: e.target.value })} />
              <input className="input" aria-label="확인한 범위" placeholder="확인한 범위 예) 02~03시, 고객 조회 API 호출" value={share.confirmed_scope || ""} onChange={(e) => setShare({ ...share, confirmed_scope: e.target.value })} />
              <input className="input" aria-label="확인하지 않은 범위" placeholder="확인하지 않은 범위 (선택) 예) 그 밖의 시간·목적지" value={share.unconfirmed_scope || ""} onChange={(e) => setShare({ ...share, unconfirmed_scope: e.target.value })} />
              <div className="small muted">"이 IP는 정상"처럼 쓰지 말고, 무엇이 사실이고 어디까지 확인했는지를 나눠 적어 주세요. 정상 확인은 90일, 악성 확인은 180일 뒤 "오래된 확인"으로 표시됩니다.</div>
            </>)}
          </div>
        )}
        <ErrorBox error={save.error} />
        <div className="row"><div className="grow" /><button className="btn primary" disabled={!ok || save.isPending} onClick={() => save.mutate()}>{edit ? "변경 저장" : "확인 기록 저장"}</button></div>
        </div>
      </div>
    </>
  );
}

function CheckRow({ inv, c, me, canEdit, target }: { inv: string; c: any; me: string; canEdit: boolean; target: Target }) {
  const qc = useQueryClient();
  const [edit, setEdit] = useState(false);
  const cancel = useMutation({
    mutationFn: (note: string) => api.post(`/investigations/${inv}/checks/${c.id}/cancel`, { note }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["checks", inv] }),
  });
  const old = c.state !== "active";
  return (
    <div className="ck-item" style={old ? { opacity: 0.55 } : undefined}>
      <div className="row wrap small">
        {c.kind === "cited" ? <span className="tag">다른 조사 참고</span> : c.behavior ? <span className="tag">행위 · {ANSWER_STATES[c.behavior.answer_status] || "확인 기록"}</span> : c.guidance ? <span className="tag">{ANSWER_STATES[c.guidance.answer_status] || "답변 기록"}</span> : c.coverage === "observation" ? <span className="tag">자동 관측 근거</span> : <span className="tag ok">직접 확인</span>}
        <b>{c.question_labels.join(" · ")}</b>
        {c.judgement ? <span className={`ck ${c.judgement}`}>{c.judgement_ko}</span> : <span className="muted">판단 없음</span>}
        {c.coverage === "sample" && <span className="tag warn">표본 {fmtNum(c.checked)} / {fmtNum(c.total)}건</span>}
        {c.coverage === "all" && c.total != null && <span className="tag">전체 {fmtNum(c.total)}건</span>}
        {c.shared && <span className="tag accent">공유됨{c.expired ? " · 오래됨" : ""}{c.share_status === "recheck" ? " · 재확인 요청 받음" : ""}</span>}
        {c.source_state === "changed" && <span className="tag bad">참고한 확인이 바뀜 — 다시 확인 필요</span>}
        {c.source_state === "retracted" && <span className="tag bad">참고한 확인이 철회됨</span>}
        {old && <span className="tag">{c.state === "cancelled" ? `취소됨${c.state_note ? `: ${c.state_note}` : ""}` : "이전 기록"}</span>}
        <span className="grow" /><span className="muted">{c.author} · {fmtTime(c.created_at)}</span>
      </div>
      {c.note && <div className="small">{c.note}</div>}
      {c.share_status === "recheck" && c.state_note && <div className="small d-chg">재확인 요청({c.state_by}): {c.state_note}</div>}
      {!old && canEdit && (
        <div className="row small">
          {c.author_id === me && c.kind === "direct" && <a onClick={() => setEdit(true)}>판단 변경</a>}
          <a onClick={() => { const r = window.prompt("취소하는 이유 (기록은 지워지지 않고 '취소됨'으로 남습니다)", ""); if (r !== null) cancel.mutate(r); }}>{c.author_id === me ? "내 표시 취소" : "취소(매니저)"}</a>
        </div>
      )}
      <ErrorBox error={cancel.error} />
      {edit && <CheckDialog inv={inv} target={target} edit={c} onClose={() => setEdit(false)} />}
    </div>
  );
}

/** Records of one target with history, plus what other investigations shared about it. */
export function TargetChecks({ inv, target, canEdit = true, compact = false }: { inv: string; target: Target; canEdit?: boolean; compact?: boolean }) {
  const [open, setOpen] = useState(false);
  const [history, setHistory] = useState(false);
  const q = useQuery({ queryKey: ["checks", inv, "target", target.key, history], queryFn: () => api.get(`/investigations/${inv}/checks?target_key=${encodeURIComponent(target.key)}&history=${history}`) });
  const rows = q.data?.checks || [];
  return (
    <div className="col" style={{ gap: 6 }}>
      <div className="row small">
        <b className="mono ellipsis" style={{ maxWidth: 380 }} title={target.label}>{target.label}</b>
        <span className="muted">확인 기록 {rows.filter((c: any) => c.state === "active").length}건</span>
        <span className="grow" />
        <label className="row muted"><input type="checkbox" checked={history} onChange={(e) => setHistory(e.target.checked)} /> 변경 이력</label>
        {canEdit && <button className="btn sm primary" onClick={() => setOpen(true)}>✓ 확인 기록</button>}
      </div>
      {rows.map((c: any) => <CheckRow key={c.id} inv={inv} c={c} me={q.data.me} canEdit={canEdit} target={target} />)}
      {!rows.length && !compact && <span className="muted small">아직 확인 기록이 없습니다. 열어 본 것만으로는 "확인함"이 되지 않습니다.</span>}
      {target.type === "entity" && <TeamChecks inv={inv} keys={[target.key]} canEdit={canEdit} />}
      {open && <CheckDialog inv={inv} target={target} onClose={() => setOpen(false)} />}
    </div>
  );
}

const CMP: Record<string, [string, string]> = { match: ["같음", "ok"], differ: ["다름", "bad"], unknown: ["비교 불가", ""] };

/** What other investigations confirmed about the same targets: a reference with its conditions, never a verdict. */
export function TeamChecks({ inv, keys, canEdit = true }: { inv: string; keys: string[]; canEdit?: boolean }) {
  const qc = useQueryClient();
  const [evidence, setEvidence] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["checks", inv, "team", keys], enabled: keys.length > 0, queryFn: () => api.post(`/investigations/${inv}/checks/team`, { keys }) });
  const ev = useQuery({ queryKey: ["team-evidence", evidence], enabled: !!evidence, queryFn: () => api.get(`/team-checks/${evidence}/evidence`) });
  const done = () => qc.invalidateQueries({ queryKey: ["checks", inv] });
  const cite = useMutation({ mutationFn: (id: string) => api.post(`/investigations/${inv}/checks/cite`, { source_id: id }), onSuccess: done });
  const recheck = useMutation({ mutationFn: ({ id, note }: { id: string; note: string }) => api.post(`/team-checks/${id}/recheck`, { note }), onSuccess: done });
  const items = q.data?.items || [];
  if (!items.length) return null;
  return (
    <div className="team-checks col" style={{ gap: 6 }}>
      <div className="small"><b>팀 확인 정보 {items.length}건</b> <span className="muted">다른 조사에서 확인한 내용입니다. 참고용이며 이 조사의 판정을 바꾸지 않습니다.</span></div>
      {items.map((t: any) => (
        <div key={t.id} className="ck-item">
          <div className="row wrap small">
            <span className="mono">{t.target_label}</span>
            {t.judgement ? <span className={`ck ${t.judgement}`}>{t.judgement_ko}</span> : <span className="muted">판단 없음</span>}
            <span className="tag">{t.share_status_ko}</span>
            {t.expired && <span className="tag warn">오래된 확인 — 다시 확인 필요</span>}
            {t.citations > 0 && <span className="muted" title="같은 확인을 여러 조사가 인용해도 독립된 확인 여러 건으로 세지 않습니다">확인 1건 · 인용 {t.citations}회</span>}
            <span className="grow" /><span className="muted">{t.author} · {fmtTime(t.created_at)} · {t.source.display_id}</span>
          </div>
          <table className="t ck-share"><tbody>
            <tr><td className="muted">확인한 사실</td><td>{t.share.fact}</td></tr>
            <tr><td className="muted">확인한 범위</td><td>{t.share.confirmed_scope}</td></tr>
            <tr><td className="muted">확인하지 않은 범위</td><td>{t.share.unconfirmed_scope || <span className="muted">적지 않음</span>}</td></tr>
            <tr><td className="muted">확인한 질문</td><td>{t.question_labels.join(" · ")}{t.note ? ` — ${t.note}` : ""}</td></tr>
            <tr><td className="muted">이번 조사와 다른 점</td><td>{t.comparison.map((c: any) => (
              <div key={c.label} className="row small"><span style={{ width: 70 }}>{c.label}</span><span className={`tag ${CMP[c.result][1]}`}>{CMP[c.result][0]}</span><span>{c.text}</span></div>))}</td></tr>
          </tbody></table>
          <div className="row small wrap">
            {t.evidence_count > 0 && <a onClick={() => setEvidence(evidence === t.id ? null : t.id)}>현재 기록과 비교 (근거 {t.evidence_count}건 보기)</a>}
            {canEdit && !t.cited_here && !t.expired && t.share_status !== "recheck" && <a onClick={() => cite.mutate(t.id)}>내 조사에 근거로 연결</a>}
            {t.cited_here && <span className="muted">내 조사에 연결됨</span>}
            {canEdit && t.share_status !== "recheck" && <a onClick={() => { const n = window.prompt("왜 다시 확인이 필요한가요? (작성자에게 전달됩니다)", ""); if (n) recheck.mutate({ id: t.id, note: n }); }}>재확인 요청</a>}
            {t.source.can_open && <a href={`/inv/${t.source.id}`}>원래 조사 열기</a>}
          </div>
          {evidence === t.id && ev.data && (
            <div className="col small" style={{ gap: 2 }}>
              <div className="muted">공유된 근거 기록만 가린 상태로 보여 줍니다(열람은 감사 기록에 남습니다).</div>
              {ev.data.events.map((e: any) => <div key={e.event_id} className="mono ellipsis" title={JSON.stringify(e)}>{fmtTime(e.timestamp)} {e.src_ip} → {e.dst_ip}{e.dst_port != null ? `:${e.dst_port}` : ""} {[e.method, e.uri, e.status_code].filter((v: unknown) => v != null).join(" ")}</div>)}
              {!ev.data.events.length && <span className="muted">근거 기록을 찾을 수 없습니다(원래 조사에서 증거가 다시 처리되었을 수 있음).</span>}
            </div>
          )}
        </div>
      ))}
      <ErrorBox error={cite.error || recheck.error || ev.error} />
    </div>
  );
}
