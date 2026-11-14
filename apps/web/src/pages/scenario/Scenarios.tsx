import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { PageHeader } from "../../components/ui";
import { api, ApiError } from "../../lib/api";
import { fmtTime } from "../../lib/format";
import "../hunt/hunt.css";
import "../inv/flows/flows.css";

const WINDOWS: [number, string][] = [[10, "10초"], [30, "30초"], [60, "1분"], [300, "5분"], [600, "10분"], [900, "15분"], [1800, "30분"], [3600, "1시간"], [7200, "2시간"],
  [21600, "6시간"], [43200, "12시간"], [86400, "1일"], [604800, "7일"]];
const KIND_WORD: Record<string, string> = { then_variation: "앞 단계 뒤 대상이 바뀌는 조회", sequence: "요청 순서", periodic_external: "반복 통신", spread_internal: "여러 대상 접촉",
  alert_then_traffic: "경보 뒤 통신", ddos_window_access: "DDoS 구간의 접속", threshold: "기준을 넘는 통신·기록" };
const STATUS_TONE: Record<string, string> = { found: "warn", no_match: "ok", insufficient_data: "", partial: "warn", failed: "bad" };
const flowKinds = new Set(["then_variation", "sequence"]);

/** Starting values of a "threshold" scenario: which records, grouped by what, measured how, against what value. */
const THRESHOLD = { sources: [] as string[], conditions: [] as any[], condition_groups: [] as any[], groups_mode: "all", group_by: "src_ip", measure: "records", threshold: 0, byte_unit: "MB" };

function blank(t: any): any {
  return { name: t.name, purpose: t.purpose, kind: t.kind, host: "", entity: "src_ip", window_seconds: 600, steps: [], count_unit: "distinct_param", count_param: "",
    min_count: 5, state: "draft", normal_note: t.normal_note || "", template: t.id, ...THRESHOLD, ...(t.defaults || {}) };
}

/** A scenario written from scratch: nothing filled in but safe starting values. */
const EMPTY = { ...THRESHOLD, sources: ["fw"], threshold: 10, name: "", purpose: "", kind: "threshold", host: "", entity: "src_ip", window_seconds: 600, count_unit: "distinct_param", count_param: "", min_count: 1,
  state: "draft", normal_note: "", template: "",
  steps: [{ label: "1단계", method: "", path: "/", match: "exact", contains: "" }, { label: "2단계", method: "", path: "/", match: "exact", contains: "" }] };

/** Steps typed as lines, one per step: "이름: GET /path*?포함글자". Only the path is required. */
export function stepsFromText(text: string): { steps: any[]; skipped: string[] } {
  const steps: any[] = [], skipped: string[] = [];
  for (const raw of text.split(/\r?\n|→|->/).map(l => l.trim()).filter(Boolean)) {
    const m = raw.match(/^(?:(.*?)\s*[:：]\s*)?(?:(GET|POST|PUT|DELETE|PATCH|HEAD)\s+)?(\/\S*)$/i);
    if (!m) { skipped.push(raw); continue; }
    const [whole, contains = ""] = m[3].split(/\?(.*)/s);
    const prefix = whole.endsWith("*");
    const path = prefix ? whole.slice(0, -1) || "/" : whole;
    steps.push({ label: (m[1] || path).slice(0, 100), method: (m[2] || "").toUpperCase(), path, match: prefix ? "prefix" : "exact", contains: contains.slice(0, 200) });
  }
  return { steps: steps.slice(0, 6), skipped };
}

/** Four steps, no code: what to find, what the flow is, try it on real data, save. */
function Wizard({ start, existing, kinds, options, onDone }: { start: any; existing?: any; kinds: any[]; options?: any; onDone: () => void }) {
  const [typed, setTyped] = useState("");
  const [skipped, setSkipped] = useState<string[]>([]);
  const qc = useQueryClient();
  // Conditions saved as one plain list (older definitions, shipped examples) open as the first "all" group.
  const [c, setC] = useState<any>(() => { const v = { ...THRESHOLD, ...start };
    return v.conditions?.length ? { ...v, conditions: [], condition_groups: [{ mode: "all", conditions: v.conditions }, ...(v.condition_groups || [])] } : v; });
  const [step, setStep] = useState(1);
  const [inv, setInv] = useState("");
  const [org, setOrg] = useState<string>(existing?.org_unit_id || "");
  const hunts = useQuery({ queryKey: ["hunts"], queryFn: () => api.get("/hunts") });
  const orgs = useQuery({ queryKey: ["org-units"], queryFn: () => api.get("/source-context/org-units") });
  const said = useQuery({ queryKey: ["scenario-describe", c], queryFn: () => api.post("/scenarios/describe", { content: c }), retry: false });
  const preview = useMutation({ mutationFn: () => api.post(`/investigations/${inv}/scenarios/preview`, { content: c }) });
  const save = useMutation({ mutationFn: (state: string) => existing
      ? api.put(`/knowledge/flow-items/${existing.id}`, { expected_version: existing.version, content: { ...c, state }, change_note: "시나리오 수정" })
      : api.post("/knowledge/flow-items", { kind: "scenario", org_unit_id: org || null, content: { ...c, state } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["scenarios"] }); onDone(); } });
  const set = (patch: any) => { setC({ ...c, ...patch }); preview.reset(); };
  const setStepAt = (i: number, patch: any) => set({ steps: c.steps.map((s: any, k: number) => k === i ? { ...s, ...patch } : s) });
  const p = preview.data;
  const flow = flowKinds.has(c.kind);
  const th = c.kind === "threshold";
  const o = options || { sources: [], fields: [], ops: [], group_by: [], measures: [], byte_units: ["KB", "MB", "GB"] };
  const bytes = String(c.measure).startsWith("bytes");
  const newCond = () => ({ field: "enforcement_action", op: "is", value: "" });
  const setGroup = (gi: number, patch: any) => set({ condition_groups: c.condition_groups.map((g: any, k: number) => k === gi ? { ...g, ...patch } : g)
    .filter((g: any) => g.conditions.length > 0) });
  const setCond = (gi: number, i: number, patch: any) => setGroup(gi, { conditions: c.condition_groups[gi].conditions.map((x: any, k: number) => k === i ? { ...x, ...patch } : x) });
  const named = !!String(c.name || "").trim();
  const kind = kinds.find(k => k.kind === c.kind);
  const newStep = (n: number) => ({ label: `${n}단계`, method: "", path: "/", match: "exact", contains: "" });
  // Changing how the scenario looks at data keeps what was typed and only fixes the number of steps.
  const setKind = (k: string) => {
    let steps = c.steps || [];
    if (flowKinds.has(k)) while (steps.length < 2) steps = [...steps, newStep(steps.length + 1)];
    if (k === "then_variation") steps = steps.slice(0, 2);
    set({ kind: k, steps, min_count: k === "then_variation" && c.min_count < 2 ? 5 : c.min_count });
  };
  const useTyped = () => {
    const out = stepsFromText(typed);
    setSkipped(out.skipped);
    if (out.steps.length >= 2) set({ steps: c.kind === "then_variation" ? out.steps.slice(0, 2) : out.steps });
  };
  return <Panel title={existing ? `시나리오 수정 — ${existing.title} (v${existing.version})` : "새 시나리오"} right={<button className="btn ghost sm" onClick={onDone}>닫기</button>}>
    <ol className="sc-steps" aria-label="작성 단계">{["무엇을 찾을까요?", "조건 정하기", "현재 자료로 확인", "저장"].map((l, i) =>
      <li key={l} className={step === i + 1 ? "on" : ""}><button className="btn sm ghost" aria-current={step === i + 1} onClick={() => setStep(i + 1)}>{i + 1}. {l}</button></li>)}</ol>

    {step === 1 && <div className="col">
      <label className="col small">이름<input className="input" value={c.name} onChange={e => set({ name: e.target.value })} /></label>
      <label className="col small">무엇을 찾는 시나리오인가요?<textarea className="input" rows={2} value={c.purpose} onChange={e => set({ purpose: e.target.value })} /></label>
      <label className="col small">찾는 방식
        <select className="input" aria-label="찾는 방식" value={c.kind} onChange={e => setKind(e.target.value)}>
          {kinds.map(k => <option key={k.kind} value={k.kind}>{k.name}</option>)}</select></label>
      <p className="small muted">{kind?.hint || KIND_WORD[c.kind]} 필요한 자료: {(kind?.needs || []).join(", ")}. 방식은 언제든 바꿀 수 있고, 다음 단계에서 대상·시간·기준을 정합니다.</p>
      {!named && <p className="small muted">이름을 적으면 다음으로 갈 수 있습니다.</p>}
      <div className="row"><div className="grow" /><button className="btn primary" disabled={!named} onClick={() => setStep(2)}>다음: 조건 정하기</button></div></div>}

    {step === 2 && <div className="col">
      {th && <>
        <fieldset className="sc-th"><legend>1. 어떤 자료에서 찾을까요? (하나 이상)</legend>
          <div className="row wrap">{o.sources.map((s: any) => <label key={s.id} className="row small"><input type="checkbox" aria-label={`${s.name} 자료`} checked={c.sources.includes(s.id)}
            onChange={() => set({ sources: c.sources.includes(s.id) ? c.sources.filter((x: string) => x !== s.id) : [...c.sources, s.id] })} />{s.name}</label>)}</div></fieldset>
        <fieldset className="sc-th"><legend>2. 어떤 기록만 볼까요? (선택 — 비우면 고른 자료 전체)</legend>
          {c.condition_groups.length > 1 && <label className="row wrap small">묶음이 여러 개일 때
            <select className="input" aria-label="묶음 사이" value={c.groups_mode} onChange={e => set({ groups_mode: e.target.value })}>
              <option value="all">모든 묶음을 만족 (그리고)</option><option value="any">묶음 중 하나라도 만족 (또는)</option></select></label>}
          {c.condition_groups.map((g: any, gi: number) => <div key={gi} className="sc-group">
            {gi > 0 && <div className="sc-join">{c.groups_mode === "all" ? "그리고" : "또는"}</div>}
            <div className="row wrap small"><b>묶음 {gi + 1}</b> 이 안의 조건을
              <select className="input" aria-label={`묶음 ${gi + 1} 방식`} value={g.mode} onChange={e => setGroup(gi, { mode: e.target.value })}>
                <option value="all">모두 만족 (그리고)</option><option value="any">하나라도 만족 (또는)</option></select>
              <div className="grow" /><button className="btn ghost sm" onClick={() => set({ condition_groups: c.condition_groups.filter((_: any, k: number) => k !== gi) })}>묶음 빼기</button></div>
            {g.conditions.map((x: any, i: number) => <div key={i} className="row wrap small">
              {i > 0 && <span className="sc-word">{g.mode === "all" ? "그리고" : "또는"}</span>}
              <select className="input" aria-label={`묶음 ${gi + 1} 조건 ${i + 1} 항목`} value={x.field} onChange={e => setCond(gi, i, { field: e.target.value })}>{o.fields.map((f: any) => <option key={f.id} value={f.id}>{f.name}</option>)}</select>
              <select className="input" aria-label={`묶음 ${gi + 1} 조건 ${i + 1} 비교`} value={x.op} onChange={e => setCond(gi, i, { op: e.target.value })}>{o.ops.map((f: any) => <option key={f.id} value={f.id}>{f.name}</option>)}</select>
              <input className="input mono" aria-label={`묶음 ${gi + 1} 조건 ${i + 1} 값`} placeholder={x.field === "enforcement_action" ? "허용 또는 차단" : x.field.endsWith("_ip") ? "예: 10.0.0.0/8" : "값"} value={x.value}
                onChange={e => setCond(gi, i, { value: e.target.value })} style={{ width: 200 }} />
              <button className="btn ghost sm" aria-label={`묶음 ${gi + 1} 조건 ${i + 1} 빼기`} onClick={() => setGroup(gi, { conditions: g.conditions.filter((_: any, k: number) => k !== i) })}>빼기</button></div>)}
            {g.conditions.length < 8 && <div><button className="btn sm" aria-label={`묶음 ${gi + 1}에 조건 추가`} onClick={() => setGroup(gi, { conditions: [...g.conditions, newCond()] })}>이 묶음에 조건 추가</button></div>}
          </div>)}
          {c.condition_groups.length < 6 && <div><button className="btn sm" onClick={() => set({ condition_groups: [...c.condition_groups, { mode: "all", conditions: [newCond()] }] })}>
            {c.condition_groups.length ? "조건 묶음 추가" : "조건 추가"}</button></div>}
          <p className="small muted">묶음 안은 "모두(그리고)" 또는 "하나라도(또는)", 묶음끼리도 "그리고" 또는 "또는"으로 잇습니다.
            예: (조치 = 차단 그리고 목적지 포트 = 22,3389) 또는 (응답 코드 ≥ 500). "같음"은 한 칸에 쉼표로 여러 값을 적으면 그중 하나와 같으면 되고, IP는 대역(10.0.0.0/8)도 됩니다. "이상·이하"는 숫자입니다.</p></fieldset>
        <fieldset className="sc-th"><legend>3. 무엇끼리 묶어, 얼마 동안, 무엇이 얼마 이상일 때?</legend>
          <div className="row wrap small">
            <select className="input" aria-label="묶는 기준" value={c.group_by} onChange={e => set({ group_by: e.target.value })}>{o.group_by.map((f: any) => <option key={f.id} value={f.id}>{f.name}</option>)}</select>끼리 묶어
            <select className="input" aria-label="시간 범위" value={c.window_seconds} onChange={e => set({ window_seconds: Number(e.target.value) })}>{WINDOWS.map(([v, l]) => <option key={v} value={v}>{l} 안에</option>)}</select>
            <select className="input" aria-label="세는 값" value={c.measure} onChange={e => set({ measure: e.target.value })}>{o.measures.map((f: any) => <option key={f.id} value={f.id}>{f.name}</option>)}</select>이(가)
            <input className="input" type="number" min={0} step={bytes ? 0.1 : 1} aria-label="기준 값" value={c.threshold} onChange={e => set({ threshold: Number(e.target.value) || 0 })} style={{ width: 110 }} />
            {bytes && <select className="input" aria-label="전송량 단위" value={c.byte_unit} onChange={e => set({ byte_unit: e.target.value })}>{o.byte_units.map((u: string) => <option key={u}>{u}</option>)}</select>}
            이상</div>
          <label className="col small">특정 서비스(호스트)만 볼 때 (선택)<input className="input" value={c.host} onChange={e => set({ host: e.target.value })} placeholder="예: portal.example.test" /></label></fieldset>
      </>}
      {flow && <>
        <label className="col small">어느 서비스에서 찾을까요? (비우면 모든 서비스)<input className="input" value={c.host} onChange={e => set({ host: e.target.value })} placeholder="예: portal.example.test" /></label>
        <details className="sc-typed"><summary>단계를 글로 한꺼번에 적기</summary>
          <p className="small muted">한 줄에 한 단계씩 적습니다. 경로만 적어도 됩니다. 끝의 *는 "이 경로로 시작", ? 뒤는 "이 글자 포함"입니다.</p>
          <textarea className="input mono" rows={4} aria-label="단계를 글로 적기" value={typed} onChange={e => setTyped(e.target.value)}
            placeholder={"로그인: POST /login\n내려받기 화면: /report/*\n전체 내려받기: GET /report/export?mode=all"} />
          <div className="row wrap"><button className="btn sm" disabled={!typed.trim()} onClick={useTyped}>아래 단계 카드로 바꾸기</button>
            {skipped.length > 0 && <span className="small" role="alert">읽지 못한 줄 {skipped.length}개(경로가 /로 시작해야 합니다): {skipped.slice(0, 3).join(" | ")}</span>}
            {typed.trim() && !skipped.length && stepsFromText(typed).steps.length < 2 && <span className="small muted">단계가 2개 이상 필요합니다.</span>}</div></details>
        <div className="sc-cards">{c.steps.map((s: any, i: number) => <div key={i} className="sc-card">
          <b>{i + 1}단계</b>
          <label className="col small">이 단계의 이름<input className="input" value={s.label} onChange={e => setStepAt(i, { label: e.target.value })} /></label>
          <label className="col small">요청 경로<input className="input mono" value={s.path} onChange={e => setStepAt(i, { path: e.target.value })} /></label>
          <div className="row wrap small"><select className="input" aria-label={`${i + 1}단계 메서드`} value={s.method} onChange={e => setStepAt(i, { method: e.target.value })}><option value="">모든 메서드</option>{["GET", "POST", "PUT", "DELETE"].map(m => <option key={m}>{m}</option>)}</select>
            <select className="input" aria-label={`${i + 1}단계 경로 방식`} value={s.match} onChange={e => setStepAt(i, { match: e.target.value })}><option value="exact">이 경로만</option><option value="prefix">이 경로로 시작</option><option value="pattern">패턴</option></select>
            {c.kind === "sequence" && c.steps.length > 2 && <button className="btn ghost sm" onClick={() => set({ steps: c.steps.filter((_: any, k: number) => k !== i) })}>단계 빼기</button>}</div>
          <label className="col small">요청에 이 글자가 있을 때만 (선택)<input className="input mono" aria-label={`${i + 1}단계 포함 글자`} placeholder="예: mode=export" value={s.contains || ""} onChange={e => setStepAt(i, { contains: e.target.value })} /></label>
        </div>)}
          {c.kind === "sequence" && c.steps.length < 6 && <button className="btn sm" onClick={() => set({ steps: [...c.steps, newStep(c.steps.length + 1)] })}>단계 추가</button>}</div>
        <label className="row wrap small">같은 대상으로 묶는 기준
          <select className="input" aria-label="같은 대상 기준" value={c.entity} onChange={e => set({ entity: e.target.value })}><option value="src_ip">같은 출발지 IP (후보 — 같은 사용자라는 근거는 아님)</option><option value="session">같은 세션 (세션 쿠키가 연결 기준으로 등록된 서비스)</option></select></label>
      </>}
      {!th && <label className="row wrap small">시간 범위
        <select className="input" aria-label="시간 범위" value={c.window_seconds} onChange={e => set({ window_seconds: Number(e.target.value) })}>{WINDOWS.map(([v, l]) => <option key={v} value={v}>{l} 안에</option>)}</select></label>}
      {c.kind === "then_variation" && <div className="row wrap small">무엇을 셀까요?
        <select className="input" aria-label="세는 단위" value={c.count_unit} onChange={e => set({ count_unit: e.target.value })}><option value="distinct_param">서로 다른 값(파라미터)</option><option value="requests">요청 수(중복 전달 제외)</option></select>
        {c.count_unit === "distinct_param" && <input className="input mono" aria-label="값이 바뀌는 파라미터" placeholder="파라미터 이름(예: id)" value={c.count_param} onChange={e => set({ count_param: e.target.value })} style={{ width: 160 }} />}</div>}
      {c.kind !== "ddos_window_access" && !th && <label className="row wrap small">기준 <input className="input" type="number" min={1} aria-label="기준 값" value={c.min_count} onChange={e => set({ min_count: Math.max(1, Number(e.target.value) || 1) })} style={{ width: 90 }} /> 이상</label>}
      <label className="col small">정상 업무로 설명될 수 있는 경우<textarea className="input" rows={2} value={c.normal_note} onChange={e => set({ normal_note: e.target.value })} /></label>
      <div className="sc-said" role="status">{said.error ? <ErrorBox error={said.error} /> : <><b>이 시나리오가 찾는 것</b><p>{said.data?.description || "…"}</p><p className="small muted">세는 단위: {said.data?.unit}</p></>}</div>
      <div className="row"><button className="btn" onClick={() => setStep(1)}>이전</button><div className="grow" /><button className="btn primary" disabled={!!said.error} onClick={() => setStep(3)}>다음: 현재 자료로 확인</button></div></div>}

    {step === 3 && <div className="col">
      <div className="row wrap small">시험할 헌팅
        <select className="input" aria-label="시험할 헌팅" value={inv} onChange={e => { setInv(e.target.value); preview.reset(); }}><option value="">헌팅을 고르세요</option>
          {(hunts.data?.items || []).map((h: any) => <option key={h.id} value={h.id}>{h.display_id} {h.title} ({h.run?.records ?? 0}건)</option>)}</select>
        <button className="btn primary sm" disabled={!inv || preview.isPending} onClick={() => preview.mutate()}>{preview.isPending ? "시험 중…" : "한 번 시험하기"}</button></div>
      <p className="small muted">저장하지 않고 고른 헌팅의 전체 자료에서 실행합니다. 결과는 이 화면에만 보입니다.</p>
      <ErrorBox error={preview.error} />
      {p && <div className="col" role="status">
        <p><span className={`tag ${STATUS_TONE[p.status] || ""}`}>{p.status_label}</span> {p.description} <span className="small muted">— {p.scope.range} {p.scope.selected_records.toLocaleString()}건, 읽은 기록 {p.examined.records_read ?? p.examined.records ?? "—"}건{p.examined.records_matching_conditions != null ? `, 조건에 맞은 기록 ${p.examined.records_matching_conditions.toLocaleString()}건` : ""}</span></p>
        {p.missing?.length > 0 && <p role="alert">필요한 자료가 없습니다: {p.missing.join(", ")}. 빈 결과가 아니라 확인하지 못한 것입니다.</p>}
        {p.matches.length > 0 && <div className="fk-table"><table className="t"><caption>조건을 만족한 흐름 {p.matches.length}개{p.examined.limit && p.matches.length >= p.examined.limit ? ` (표시 한도 ${p.examined.limit})` : ""}</caption>
          <thead><tr><th>대상</th><th>서비스</th><th>시작 ~ 끝</th><th>{p.unit}</th><th>내용</th></tr></thead>
          <tbody>{p.matches.slice(0, 20).map((m: any, i: number) => <tr key={i}><td className="mono small">{m.entity}</td><td className="small">{m.host}</td><td className="small nowrap">{m.start ? fmtTime(m.start) : ""} ~ {m.end ? fmtTime(m.end) : ""}</td><td className="num">{m.count}</td>
            <td className="small">{m.title || (m.steps || []).map((s: any) => s.label).join(" → ")}</td></tr>)}</tbody></table></div>}
        {p.near.length > 0 && <div className="fk-lines"><h5>조건에 가까웠지만 해당하지 않은 예</h5><ul>{p.near.map((n: any, i: number) => <li key={i}>
          <span className="tag">{({ below: "기준 미달", reversed: "순서가 반대", outside_window: "시간 범위 밖" } as any)[n.kind]}</span> {n.text}</li>)}</ul></div>}
        {p.notes.filter(Boolean).length > 0 && <ul className="small muted">{p.notes.filter(Boolean).map((n: string, i: number) => <li key={i}>{n}</li>)}</ul>}
      </div>}
      <div className="row"><button className="btn" onClick={() => setStep(2)}>이전</button><div className="grow" /><button className="btn primary" onClick={() => setStep(4)}>다음: 저장</button></div></div>}

    {step === 4 && <div className="col">
      <p><b>{c.name}</b> — {said.data?.description}</p>
      {!existing && <label className="row wrap small">적용 범위
        <select className="input" aria-label="적용 범위" value={org} onChange={e => setOrg(e.target.value)}><option value="">모든 관계사 공통</option>{(orgs.data || []).map((o: any) => <option key={o.id} value={o.id}>{o.display_name}만</option>)}</select></label>}
      {!p && <p className="small" role="note">아직 시험하지 않았습니다. 시험 없이도 초안으로 저장할 수 있습니다.</p>}
      {!named && <p role="alert">이름이 비어 있습니다. <button className="btn sm" onClick={() => setStep(1)}>1단계에서 이름 적기</button></p>}
      {said.error && <p role="alert">조건에 고칠 곳이 있습니다. <button className="btn sm" onClick={() => setStep(2)}>2단계에서 확인</button></p>}
      {save.error instanceof ApiError && save.error.status === 409 ? <p role="alert">{save.error.detail}</p> : <ErrorBox error={save.error} />}
      <div className="row wrap"><button className="btn" onClick={() => setStep(3)}>이전</button><div className="grow" />
        <button className="btn" disabled={save.isPending || !named || !!said.error} onClick={() => save.mutate("draft")}>초안으로 저장(시험만)</button>
        <button className="btn primary" disabled={save.isPending || !named || !!said.error} onClick={() => save.mutate("active")}>다음 헌팅부터 사용</button></div>
      <p className="small muted">저장은 새 버전을 만듭니다. 이미 끝난 헌팅은 당시 버전을 그대로 갖습니다.</p></div>}
  </Panel>;
}

/** My scenarios, the shipped templates and the worked analysis examples, in one place. */
export function Scenarios() {
  const qc = useQueryClient();
  const [params] = useSearchParams();
  const q = useQuery({ queryKey: ["scenarios"], queryFn: () => api.get("/scenarios") });
  const [editing, setEditing] = useState<{ start: any; existing?: any } | null>(null);
  const state = useMutation({ mutationFn: ({ item, action }: any) => api.post(`/knowledge/flow-items/${item.id}/${action}`, { expected_version: item.version }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scenarios"] }) });
  if (q.isLoading) return <div className="page"><Loading /></div>;
  if (q.error) return <div className="page"><ErrorBox error={q.error} /></div>;
  const { scenarios, templates, kinds = [], threshold_options } = q.data;
  const fresh = () => setEditing({ start: { ...EMPTY, steps: EMPTY.steps.map(s => ({ ...s })) } });
  const fromHunt = params.get("from");
  return <div className="page col">
    <PageHeader eyebrow="시나리오" title="시나리오" desc="'무엇을 어떤 자료에서 어떤 기준으로 찾을지'를 저장해 다음 헌팅에서 다시 씁니다. 방화벽·웹·WAF·IPS·DDoS 기록에 쓸 수 있고 코드나 조건식을 쓰지 않습니다."
      actions={!editing && <button className="btn primary" onClick={fresh}>직접 만들기</button>} />
    {editing ? <Wizard key={editing.existing?.id || editing.start.template || "new"} start={editing.start} existing={editing.existing} kinds={kinds} options={threshold_options} onDone={() => setEditing(null)} /> : <>
      <Panel title={`내 시나리오 ${scenarios.length}개`} right={<button className="btn sm primary" onClick={fresh}>빈 양식에서 새로 만들기</button>}>
        {!scenarios.length && <p>아직 만든 시나리오가 없습니다. 위의 "직접 만들기"로 빈 양식에서 시작하거나 아래 예제에서 시작하세요.{fromHunt ? " 헌팅 결과에서 왔다면, 가장 가까운 예제를 골라 경로와 기준을 그 결과에 맞추면 됩니다." : ""}</p>}
        <ul className="fk-flows">{scenarios.map((s: any) => <li key={s.id} className="fk-item">
          <div className="row wrap"><b>{s.title}</b><span className={`tag ${s.run_state === "다음 헌팅부터 사용" ? "ok" : ""}`}>{s.run_state}</span>
            <span className="small muted">v{s.version} · {s.org_unit_id ? "관계사 지정" : "공통"} · 고친 날 {fmtTime(s.updated_at)}</span><div className="grow" />
            <button className="btn sm" onClick={() => setEditing({ start: s.content, existing: s })}>고치기·시험</button>
            {s.status === "active" ? <button className="btn sm ghost" disabled={state.isPending} onClick={() => state.mutate({ item: s, action: "stop" })}>사용 중지</button>
              : <button className="btn sm ghost" disabled={state.isPending} onClick={() => state.mutate({ item: s, action: "restore" })}>다시 사용</button>}</div>
          <div className="small">{s.description}</div>
          <div className="small muted">목적: {s.content.purpose || "—"} · 필요한 자료: {s.needs.join(", ")}</div></li>)}</ul>
        <ErrorBox error={state.error} />
      </Panel>
      <Panel title="제공 예제에서 만들기">
        <div className="sc-cards">{templates.map((t: any) => <div key={t.id} className="sc-card">
          <b>{t.name}</b> <span className={`tag ${t.executable ? "ok" : ""}`}>{t.executable ? "실행 가능" : "설명 자료(실행기 없음)"}</span>
          <p className="small">{t.purpose}</p><p className="small muted">필요한 자료: {t.needs.join(", ")}</p>
          {t.caution && <p className="small">{t.caution}</p>}
          {t.executable ? <button className="btn sm primary" onClick={() => setEditing({ start: blank(t) })}>이 예제로 만들기</button> : <p className="small muted">{t.reason}</p>}</div>)}</div>
      </Panel>
      <Panel title="분석 예시">
        <p className="small">실제 화면에서 분석을 끝낸 사례입니다. 사례는 읽는 자료이며, 사례가 있다고 해서 그 수만큼 자동 분석기가 있는 것은 아닙니다.</p>
        <div className="row wrap"><Link className="btn sm" to="/casebook">분석 사례집 열기 (업무 흐름 F01~F07 · 플랫폼 분석 W01~W60 · 로그 예제 C001~C100)</Link></div>
      </Panel></>}
  </div>;
}
