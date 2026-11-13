import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { PageHeader } from "../../components/ui";
import { api, ApiError } from "../../lib/api";
import { fmtTime } from "../../lib/format";
import "../hunt/hunt.css";
import "../inv/flows/flows.css";

const WINDOWS: [number, string][] = [[60, "1분"], [300, "5분"], [600, "10분"], [1800, "30분"], [3600, "1시간"], [21600, "6시간"], [86400, "1일"], [604800, "7일"]];
const KIND_WORD: Record<string, string> = { then_variation: "앞 단계 뒤 대상이 바뀌는 조회", sequence: "요청 순서", periodic_external: "반복 통신", spread_internal: "여러 대상 접촉",
  alert_then_traffic: "경보 뒤 통신", ddos_window_access: "DDoS 구간의 접속" };
const STATUS_TONE: Record<string, string> = { found: "warn", no_match: "ok", insufficient_data: "", partial: "warn", failed: "bad" };
const flowKinds = new Set(["then_variation", "sequence"]);

function blank(t: any): any {
  return { name: t.name, purpose: t.purpose, kind: t.kind, host: "", entity: "src_ip", window_seconds: 600, steps: [], count_unit: "distinct_param", count_param: "",
    min_count: 5, state: "draft", normal_note: t.normal_note || "", template: t.id, ...(t.defaults || {}) };
}

/** Four steps, no code: what to find, what the flow is, try it on real data, save. */
function Wizard({ start, existing, onDone }: { start: any; existing?: any; onDone: () => void }) {
  const qc = useQueryClient();
  const [c, setC] = useState<any>(start);
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
  return <Panel title={existing ? `시나리오 수정 — ${existing.title} (v${existing.version})` : "새 시나리오"} right={<button className="btn ghost sm" onClick={onDone}>닫기</button>}>
    <ol className="sc-steps" aria-label="작성 단계">{["무엇을 찾을까요?", "어떤 흐름인가요?", "현재 자료로 확인", "저장"].map((l, i) =>
      <li key={l} className={step === i + 1 ? "on" : ""}><button className="btn sm ghost" aria-current={step === i + 1} onClick={() => setStep(i + 1)}>{i + 1}. {l}</button></li>)}</ol>

    {step === 1 && <div className="col">
      <label className="col small">이름<input className="input" value={c.name} onChange={e => set({ name: e.target.value })} /></label>
      <label className="col small">무엇을 찾는 시나리오인가요?<textarea className="input" rows={2} value={c.purpose} onChange={e => set({ purpose: e.target.value })} /></label>
      <p className="small muted">찾는 방식: <b>{KIND_WORD[c.kind]}</b>. 방식은 예제에서 정해지며, 다음 단계에서 대상·시간·기준을 고칩니다.</p>
      <div className="row"><div className="grow" /><button className="btn primary" disabled={!c.name.trim()} onClick={() => setStep(2)}>다음: 흐름 확인</button></div></div>}

    {step === 2 && <div className="col">
      {flow && <>
        <label className="col small">어느 서비스에서 찾을까요? (비우면 모든 서비스)<input className="input" value={c.host} onChange={e => set({ host: e.target.value })} placeholder="예: portal.example.test" /></label>
        <div className="sc-cards">{c.steps.map((s: any, i: number) => <div key={i} className="sc-card">
          <b>{i + 1}단계</b>
          <label className="col small">이 단계의 이름<input className="input" value={s.label} onChange={e => setStepAt(i, { label: e.target.value })} /></label>
          <label className="col small">요청 경로<input className="input mono" value={s.path} onChange={e => setStepAt(i, { path: e.target.value })} /></label>
          <div className="row wrap small"><select className="input" aria-label={`${i + 1}단계 메서드`} value={s.method} onChange={e => setStepAt(i, { method: e.target.value })}><option value="">모든 메서드</option>{["GET", "POST", "PUT", "DELETE"].map(m => <option key={m}>{m}</option>)}</select>
            <select className="input" aria-label={`${i + 1}단계 경로 방식`} value={s.match} onChange={e => setStepAt(i, { match: e.target.value })}><option value="exact">이 경로만</option><option value="prefix">이 경로로 시작</option><option value="pattern">패턴</option></select>
            {c.kind === "sequence" && c.steps.length > 2 && <button className="btn ghost sm" onClick={() => set({ steps: c.steps.filter((_: any, k: number) => k !== i) })}>단계 빼기</button>}</div>
        </div>)}
          {c.kind === "sequence" && c.steps.length < 6 && <button className="btn sm" onClick={() => set({ steps: [...c.steps, { label: `${c.steps.length + 1}단계`, method: "", path: "/", match: "exact" }] })}>단계 추가</button>}</div>
        <label className="row wrap small">같은 대상으로 묶는 기준
          <select className="input" aria-label="같은 대상 기준" value={c.entity} onChange={e => set({ entity: e.target.value })}><option value="src_ip">같은 출발지 IP (후보 — 같은 사용자라는 근거는 아님)</option><option value="session">같은 세션 (세션 쿠키가 연결 기준으로 등록된 서비스)</option></select></label>
      </>}
      <label className="row wrap small">시간 범위
        <select className="input" aria-label="시간 범위" value={c.window_seconds} onChange={e => set({ window_seconds: Number(e.target.value) })}>{WINDOWS.map(([v, l]) => <option key={v} value={v}>{l} 안에</option>)}</select></label>
      {c.kind === "then_variation" && <div className="row wrap small">무엇을 셀까요?
        <select className="input" aria-label="세는 단위" value={c.count_unit} onChange={e => set({ count_unit: e.target.value })}><option value="distinct_param">서로 다른 값(파라미터)</option><option value="requests">요청 수(중복 전달 제외)</option></select>
        {c.count_unit === "distinct_param" && <input className="input mono" aria-label="값이 바뀌는 파라미터" placeholder="파라미터 이름(예: id)" value={c.count_param} onChange={e => set({ count_param: e.target.value })} style={{ width: 160 }} />}</div>}
      {c.kind !== "ddos_window_access" && <label className="row wrap small">기준 <input className="input" type="number" min={1} aria-label="기준 값" value={c.min_count} onChange={e => set({ min_count: Math.max(1, Number(e.target.value) || 1) })} style={{ width: 90 }} /> 이상</label>}
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
        <p><span className={`tag ${STATUS_TONE[p.status] || ""}`}>{p.status_label}</span> {p.description} <span className="small muted">— {p.scope.range} {p.scope.selected_records.toLocaleString()}건, 읽은 기록 {p.examined.records_read ?? p.examined.records ?? "—"}건</span></p>
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
      {save.error instanceof ApiError && save.error.status === 409 ? <p role="alert">{save.error.detail}</p> : <ErrorBox error={save.error} />}
      <div className="row wrap"><button className="btn" onClick={() => setStep(3)}>이전</button><div className="grow" />
        <button className="btn" disabled={save.isPending} onClick={() => save.mutate("draft")}>초안으로 저장(시험만)</button>
        <button className="btn primary" disabled={save.isPending} onClick={() => save.mutate("active")}>다음 헌팅부터 사용</button></div>
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
  const { scenarios, templates } = q.data;
  const fromHunt = params.get("from");
  return <div className="page col">
    <PageHeader eyebrow="시나리오" title="시나리오" desc="'이런 흐름을 어떤 자료로 확인할지'를 저장해 다음 헌팅에서 다시 씁니다. 코드나 조건식을 쓰지 않습니다." />
    {editing ? <Wizard key={editing.existing?.id || editing.start.template} start={editing.start} existing={editing.existing} onDone={() => setEditing(null)} /> : <>
      <Panel title={`내 시나리오 ${scenarios.length}개`}>
        {!scenarios.length && <p>아직 만든 시나리오가 없습니다. 아래 예제에서 시작하세요.{fromHunt ? " 헌팅 결과에서 왔다면, 가장 가까운 예제를 골라 경로와 기준을 그 결과에 맞추면 됩니다." : ""}</p>}
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
