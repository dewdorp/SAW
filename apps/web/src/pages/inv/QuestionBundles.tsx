import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment, useEffect, useId, useRef, useState } from "react";
import "./question-worklist.css";
import { Link } from "react-router-dom";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { blankQuestionView, scopeKeyOf, useInv, useInvStore, type QuestionView } from "../../context/invContext";
import { ActivityCaseComparison } from "./ActivityCaseComparison";
import { isCaseEvidenceInScope } from "../practice/caseApplicability";
import { LongWindowComparison } from "./LongWindowComparison";
import { WorkedCasePanel } from "./WorkedCasePanel";
import { CLAIM_COLUMNS } from "./evidenceView";
import { ApiError, api } from "../../lib/api";
import { fmtNum, fmtPeriod, getTz } from "../../lib/format";

const STATUS: Record<string, [string, string]> = {
  found: ["확인할 근거 있음", "warn"], looked_none: ["이 기준에서는 보이지 않음 (정상 판정 아님)", ""],
  no_match: ["조건에 맞는 기록 없음 (정상 판정 아님)", ""],
  insufficient_data: ["자료 부족 — 판단 불가", "warn"], failed: ["계산 실패", "warn"], not_connected: ["아직 계산 연결 안 됨", ""],
};
const SCOPES: Record<string, string> = { investigation: "이번 조사", affiliate: "같은 관계사의 조사", common: "공통 템플릿" };

type Param = { name: string; label: string; type: string; default: any; help?: string; min?: number; max?: number; unit?: string; choices?: [string, string][] };

/** One input per condition, typed by the server's definition (the same definition that runs and is saved). */
export function ParamInput({ p, value, onChange }: { p: Param; value: any; onChange: (v: any) => void }) {
  const label = <span className="small"><b>{p.label}</b>{p.help ? <span className="muted"> — {p.help}</span> : null}</span>;
  if (p.type === "int" || p.type === "float") {
    return <label className="col" style={{ gap: 2 }}>{label}<span className="row" style={{ gap: 4 }}>
      <input className="input" type="number" aria-label={p.label} style={{ width: 120 }} min={p.min} max={p.max} step={p.type === "float" ? 0.01 : 1}
        value={value ?? ""} onChange={(e) => onChange(e.target.value === "" ? "" : Number(e.target.value))} />{p.unit && <span className="small muted">{p.unit}</span>}</span></label>;
  }
  if (p.type === "bool") return <label className="row small"><input type="checkbox" aria-label={p.label} checked={!!value} onChange={(e) => onChange(e.target.checked)} />{label}</label>;
  if (p.type === "choice") {
    return <label className="col" style={{ gap: 2 }}>{label}<select className="input" aria-label={p.label} value={value} onChange={(e) => onChange(e.target.value)}>
      {(p.choices || []).map(([v, t]) => <option key={v} value={v}>{t}</option>)}</select></label>;
  }
  if (p.type === "choice_list") {
    return <fieldset className="col" style={{ gap: 2, border: "none", padding: 0 }}><legend>{label}</legend><span className="row wrap" style={{ gap: 8 }}>
      {(p.choices || []).map(([v, t]) => <label key={v} className="row small"><input type="checkbox" aria-label={`${p.label}: ${t}`} checked={(value || []).includes(v)}
        onChange={(e) => onChange(e.target.checked ? [...(value || []), v] : (value || []).filter((x: string) => x !== v))} />{t}</label>)}</span></fieldset>;
  }
  // ip_list / port_list: one value per comma or line; the server checks each value and says which is wrong.
  const text = (value || []).join(", ");
  return <label className="col" style={{ gap: 2 }}>{label}<input className="input" aria-label={p.label} placeholder={p.type === "port_list" ? "예: 22, 445, 3389" : "예: 10.20.5.7, 10.20.5.8"}
    defaultValue={text} key={text} onBlur={(e) => onChange(e.target.value.split(/[\s,]+/).filter(Boolean).map((x) => (p.type === "port_list" ? Number(x) : x)))} /></label>;
}

/** Edit a question's condition, run it on the current logs, and save it with a clear reach and version. */
function ConditionEditor({ inv, bundle, def, sensitivity, initial, onValues, onResult, onClose }: { inv: string; bundle: string; def: any; sensitivity: string;
  initial?: Record<string, any>; onValues?: (v: Record<string, any>) => void; onResult: (r: any | null) => void; onClose: () => void }) {
  const qc = useQueryClient();
  const [values, setValuesState] = useState<Record<string, any>>(initial || def.defaults);
  const setValues = (v: Record<string, any>) => { setValuesState(v); onValues?.(v); };
  const [ran, setRan] = useState<string>("");
  const [loaded, setLoaded] = useState<any>(null);
  const [name, setName] = useState("");
  const [reach, setReach] = useState("investigation");
  const [note, setNote] = useState("");
  const dirty = JSON.stringify(values) !== (loaded ? JSON.stringify(loaded.parameters) : JSON.stringify(def.defaults));
  const presets = useQuery<any>({ queryKey: ["question-presets", inv, bundle], queryFn: () => api.get(`/investigations/${inv}/question-presets?bundle=${bundle}`) });
  useEffect(() => {
    if (!dirty) return;
    const warn = (e: BeforeUnloadEvent) => { e.preventDefault(); e.returnValue = ""; };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);
  const preview = useMutation({
    mutationFn: (body: any) => api.post(`/investigations/${inv}/question-bundles/${bundle}/preview`, { sensitivity, ...body }),
    onSuccess: (r: any) => { setRan(JSON.stringify(r.parameters)); onResult(r); },
  });
  const save = useMutation({
    mutationFn: () => {
      const body = { bundle, scope_kind: loaded ? loaded.scope_kind : reach, name: name || loaded?.name, description: "", parameters: values, change_note: note };
      return loaded ? api.put(`/investigations/${inv}/question-presets/${loaded.id}`, { ...body, expected_version: loaded.version })
        : api.post(`/investigations/${inv}/question-presets`, body);
    },
    onSuccess: (row: any) => { setLoaded(row); setValues(row.parameters); setNote(""); qc.invalidateQueries({ queryKey: ["question-presets", inv, bundle] }); },
  });
  const load = async (id: string) => {
    if (!id) { setLoaded(null); setValues(def.defaults); return; }
    if (dirty && !window.confirm("저장하지 않은 조건 변경이 있습니다. 버리고 저장된 조건을 불러올까요?")) return;
    const row = await api.get(`/investigations/${inv}/question-presets/${id}`);
    setLoaded(row); setValues(row.parameters); setName(row.name);
    preview.mutate({ preset_id: row.id });
  };
  const close = () => { if (!dirty || window.confirm("저장하지 않은 조건 변경이 있습니다. 닫을까요?")) { onResult(null); onClose(); } };
  const conflict = save.error instanceof ApiError && save.error.status === 409;
  return (
    <section aria-label="조건 수정" tabIndex={-1} className="panel pb col" style={{ gap: 8, marginTop: 6 }}>
      <div className="row wrap" style={{ gap: 8 }}>
        <b>조건 수정</b>
        <label className="small">저장된 조건 <select className="input" aria-label="저장된 조건" value={loaded?.id || ""} onChange={(e) => load(e.target.value)}>
          <option value="">기본값(민감도 {sensitivity === "low" ? "낮음" : sensitivity === "high" ? "높음" : "보통"})</option>
          {(presets.data?.items || []).map((p: any) => <option key={p.id} value={p.id}>{p.name} · {p.scope_ko} · v{p.version}</option>)}</select></label>
        {dirty && <span className="tag warn" role="status">저장하지 않은 변경</span>}
        {ran && ran !== JSON.stringify(values) && <span className="tag warn">미리 보기 후 조건이 바뀜 — 다시 실행하세요</span>}
        <button className="btn sm ghost" onClick={close}>닫기</button>
      </div>
      <div className="row wrap" style={{ gap: 14, alignItems: "flex-start" }}>
        {def.params.map((p: Param) => <ParamInput key={p.name} p={p} value={values[p.name]} onChange={(v) => setValues({ ...values, [p.name]: v })} />)}
      </div>
      <div className="row wrap" style={{ gap: 6 }}>
        <button className="btn primary sm" disabled={preview.isPending} onClick={() => preview.mutate({ parameters: values })}>현재 로그로 미리 보기</button>
        <button className="btn sm" onClick={() => setValues(loaded ? loaded.parameters : def.defaults)}>변경 취소</button>
      </div>
      <ErrorBox error={preview.error} />
      <div className="row wrap small" style={{ gap: 8, borderTop: "1px solid var(--line)", paddingTop: 6 }}>
        {loaded ? <span>저장된 조건 <b>{loaded.name}</b> · {loaded.scope_ko} · v{loaded.version} 수정 저장(새 버전)</span> : <>
          <label>이름 <input className="input" aria-label="조건 이름" maxLength={128} value={name} onChange={(e) => setName(e.target.value)} /></label>
          <label>적용 범위 <select className="input" aria-label="적용 범위" value={reach} onChange={(e) => setReach(e.target.value)}>
            {Object.entries(SCOPES).map(([k, t]) => <option key={k} value={k}>{t}</option>)}</select></label></>}
        <label>바꾼 이유 <input className="input" aria-label="바꾼 이유" maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} /></label>
        <button className="btn sm" disabled={save.isPending || (!loaded && !name.trim())} onClick={() => save.mutate()}>{loaded ? "새 버전으로 저장" : "조건 저장"}</button>
      </div>
      <p className="small muted">저장한 조건은 검색 조건입니다. 자동 분석이나 탐지 정책을 켜거나 바꾸지 않습니다.</p>
      {conflict ? <div className="error small" role="alert">{(save.error as Error).message} <button className="btn sm" onClick={() => loaded && load(loaded.id)}>최신 버전 불러오기</button></div> : <ErrorBox error={save.error} />}
      {save.isSuccess && <p role="status" className="small">v{(save.data as any).version}으로 저장했습니다. 이 조건은 {(save.data as any).scope_ko}에서 다시 열 수 있습니다.</p>}
      <details className="small"><summary>고급: 조건 원본(JSON) 보기</summary><pre className="mono">{JSON.stringify(values, null, 1)}</pre></details>
    </section>
  );
}

function Coverage({ b, limits }: { b: any; limits: any }) {
  if (!b.examined) return null;
  const ex = b.examined;
  return (
    <div className="small muted">
      조건 범위 기록 {fmtNum(b.records || 0)}건 · 계산한 그룹 {fmtNum(ex.groups || 0)}개{ex.groups_total != null ? ` / 전체 ${fmtNum(ex.groups_total)}개` : ""}(한도 {fmtNum(ex.group_limit || limits?.groups || 0)})
      {ex.timelines ? ` · 시간순 계산 ${fmtNum(ex.timelines)}개(각 ${fmtNum(ex.timeline_limit)}건까지)` : ""} · 후보 {fmtNum(b.found || 0)}개 중 {fmtNum(b.shown || 0)}개 표시
      {b.completeness === "partial" && <div className="error" role="status">일부만 계산: {(b.partial_reasons || []).join(" · ")}. 이 결과를 전체 결과로 보지 마세요.</div>}
      {(b.unconfirmed || []).map((u: string) => <div key={u}>원천 의미 미확인: {u}</div>)}
    </div>
  );
}

/** The 120 example specifications: searchable knowledge with three separate states, never shown as installed rules. */
function ExampleSearch({ inv, editing, onOpen }: { inv: string; editing: string | null; onOpen: (bundle: string) => void }) {
  const [q, setQ] = useState("");
  const [opened, setOpened] = useState(false);
  const [kind, setKind] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const list = useQuery<any>({ queryKey: ["question-examples", inv, q, kind], enabled: opened, queryFn: () => api.get(`/investigations/${inv}/question-examples?q=${encodeURIComponent(q)}&kind=${kind}`) });
  return (
    <details className="small" style={{ marginTop: 8 }} onToggle={e => setOpened(e.currentTarget.open)}>
      <summary><b>더 많은 예제 찾기</b> — 명세 {list.data?.catalog_total ?? 120}개(탐지·헌팅·시나리오), 실행 룰이 아님</summary>
      {opened && <><p><Link to={`/casebook?investigation=${encodeURIComponent(inv)}`}>분석 사례집</Link>에서 가상 NDR·FW 로그와 분석가의 해석을 읽을 수 있습니다.</p>
      <p className="muted">{list.data?.note}</p>
      <div className="row wrap" style={{ gap: 6 }}>
        <input className="input" aria-label="예제 검색" placeholder="예: 포트, 반복, Q06, D027" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="input" aria-label="예제 종류" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="">전체</option><option value="detection">탐지 조건 명세</option><option value="hunt">헌팅 질문</option><option value="scenario">조사 시나리오</option></select>
        <span className="muted">{fmtNum(list.data?.total || 0)}개</span>
      </div>
      <ErrorBox error={list.error} />
      <table className="t small"><thead><tr><th>예제</th><th>실행 연결</th><th>자료 준비</th><th>계산</th></tr></thead><tbody>
        {(list.data?.items || []).map((x: any) => (<Fragment key={x.id}>
          <tr><td><button className="btn ghost sm" aria-expanded={open === x.id} onClick={() => setOpen(open === x.id ? null : x.id)}>{x.id}</button> {x.kind_ko} · {x.title}</td>
            <td>{x.execution.label}</td><td>{x.data_readiness.label}</td><td>{x.calculation.label}</td></tr>
          {open === x.id && <tr><td colSpan={4}><div className="col" style={{ gap: 3 }}>
            <div><b>질문</b> {x.question}</div>{x.logic && <div><b>조건 설명</b> {x.logic}</div>}
            <div><b>결론 낼 수 없는 것</b> {(x.cannot_conclude || []).join(" · ")}</div>
            <div><b>정상 설명</b> {(x.normal_explanations || []).join(" · ")}</div>
            <div><b>다음 확인</b> {(x.followup_questions || []).map((f: any) => `${f.question} (${(f.needed_data || []).join(", ")})`).join(" / ")}</div>
            <div className="muted">시작값(현장 보정 전): {(x.parameters || []).map((p: any) => `${p.label_ko} ${Array.isArray(p.default) ? p.default.join(",") : p.default}${p.unit ? ` ${p.unit}` : ""}`).join(" · ")}</div>
            {x.execution.bundle && <div><button className="btn sm" disabled={!!editing && editing !== x.execution.bundle} onClick={() => onOpen(x.execution.bundle)}>가까운 질문 {x.execution.question}의 조건 열기</button>
              <span className="muted"> 이 명세의 조건이 그대로 실행되는 것은 아닙니다. 연결된 질문의 조건을 고쳐 현재 로그로 확인하세요.</span></div>}
          </div></td></tr>}</Fragment>))}</tbody></table></>}
    </details>
  );
}

const NAMES: Record<string, string> = { web_attack: "웹 요청", transfer: "대량 전송", periodic: "반복 통신", spread: "다수 대상·포트 접촉" };
// What an automatic candidate of each kind establishes from these logs, said once and plainly.
const ESTABLISHED: Record<string, string> = {
  spread: "여러 대상·포트에 대한 접촉 기록", periodic: "일정한 간격으로 반복된 기록",
  transfer: "기준을 넘은 바이트 기록", web_attack: "여러 경로 요청 또는 공격 패턴이 든 요청",
};
const SOURCE: Record<string, string> = { web: "HTTP 요청(NDR·웹)", firewall: "방화벽", connection: "연결 기록",
  zeek_conn: "Zeek 연결", waf: "웹 방화벽", ips: "IPS", ddos: "DDoS" };
const PAGE = 5;

function sourceScope(filters: any[] = []) {
  const bySource = filters.filter(f => f.field === "data_source");
  const named = (v: string) => SOURCE[v] || v;
  const exact = bySource.find(f => f.op === "is")?.value;
  const included = bySource.find(f => f.op === "in")?.value;
  return { observed: typeof exact === "string" ? named(exact) : "",
    included: Array.isArray(included) ? included.map(named).join(" · ") : "" };
}
function DetailsList({ label, items }: { label: string; items?: string[] }) {
  if (!items?.length) return null;
  return <div><dt>{label}</dt><dd><ul>{items.map((s, i) => <li key={i}>{s}</li>)}</ul></dd></div>;
}

/** Automatic candidates and their evidence. A request does not attest that anyone read the raw rows. */
export function QuestionBundles({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const qc = useQueryClient();
  // Everything the analyst set here lives with this investigation: a trip to the raw view and back keeps it,
  // and another investigation (another affiliate) starts from its own.
  const view: QuestionView = ctx.questionView || blankQuestionView();
  // Always patch the latest stored view: two updates in one event (or one after an await) must not undo each other.
  const setView = (patch: Partial<QuestionView> | ((v: QuestionView) => Partial<QuestionView>)) => {
    const latest = useInvStore.getState().get(inv).questionView || blankQuestionView();
    ctx.set({ questionView: { ...latest, ...(typeof patch === "function" ? patch(latest) : patch) } });
  };
  const { sensitivity, previews, editing } = view;
  const settings = useRef<HTMLDetailsElement>(null);
  const focusEditor = () => {
    const el = settings.current?.querySelector<HTMLElement>('[aria-label="조건 수정"]');
    el?.focus({ preventScroll: true });
    el?.scrollIntoView?.({ block: "nearest" });
  };
  useEffect(() => { if (editing) { if (settings.current) settings.current.open = true; focusEditor(); } }, [editing]); // eslint-disable-line react-hooks/exhaustive-deps
  const prefix = useId();
  const q = useQuery<any>({ queryKey: ["question-bundles", inv, sensitivity],
    queryFn: () => api.get(`/investigations/${inv}/question-bundles?sensitivity=${sensitivity}`) });
  const me = useQuery<any>({ queryKey: ["me"], queryFn: () => api.get("/auth/me"), retry: false, staleTime: 60_000 });
  const scopeTime = (b: any, item: any) => item.evidence_time ?? (b.scope || q.data?.scope)?.time ?? null;
  const openEvidence = (b: any, item: any, judge = false) => {
    const time = scopeTime(b, item);
    const claim = CLAIM_COLUMNS[b.id];
    ctx.set({ tab: "raw", filters: item.filters, time, selection: null, eventId: null, findingId: null,
      evidenceColumns: claim ? { key: scopeKeyOf(item.filters, time), ...claim } : null,
      ...(judge ? { judgeScope: scopeKeyOf(item.filters, time) } : {}) });
  };
  const record = useMutation({
    mutationFn: async ({ b, item }: { b: any; item: any }) => {
      const time = scopeTime(b, item);
      const query = { filters: item.filters, time };
      const page = await api.post<any>(`/investigations/${inv}/query/events`, { ...query, limit: 20 });
      const ids = (page.events || []).map((e: any) => e.event_id).slice(0, 20);
      const origin = { kind: "question", bundle: b.id, title: b.title, description: b.description, parameters: b.parameters,
        preset: b.preset || null, scope: b.scope || q.data?.scope, completeness: b.completeness, partial_reasons: b.partial_reasons, item };
      const check = await api.post<any>(`/investigations/${inv}/checks`, { target_type: "set", target_label: item.title.slice(0, 500), questions: ["nature"],
        note: `자동 관측과 추가로 확인할 사항을 기록합니다. ${item.observed} 확인 필요: ${(item.next_questions || []).join(" / ")}`.slice(0, 2000),
        evidence: ids, scope: { coverage: "observation", checked: 0, event_ids: [], query, origin } });
      if (!check.id) throw new Error("확인 기록의 번호를 받지 못했습니다. 확인 기록 목록을 확인하세요.");
      return { id: check.id, target_label: check.target_label || item.title };
    },
    onSuccess: (check) => { qc.invalidateQueries({ queryKey: ["checks", inv] }); ctx.set({ tab: "checks", followUpCheck: check }); },
  });
  // Back from the raw view: the activity the analyst was reading is where they left it.
  const list = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!ctx.questionActivity || !q.data) return;
    const el = list.current?.querySelector<HTMLElement>(`[data-activity="${CSS.escape(ctx.questionActivity)}"]`);
    el?.scrollIntoView?.({ block: "nearest" });
  }, [q.data]); // eslint-disable-line react-hooks/exhaustive-deps
  if (q.isLoading) return <Panel title="검토할 활동" className="question-worklist"><Loading label="로그에서 검토할 활동을 찾고 있습니다" />
    <WorkedCasePanel inv={inv} status="loading" /><LongWindowComparison key={inv} inv={inv} /></Panel>;
  if (!Array.isArray(q.data?.bundles)) return <Panel title="검토할 활동"><ErrorBox error={q.error || new Error("활동 결과를 불러오지 못했습니다.")} />
    <button className="btn sm" onClick={() => q.refetch()}>다시 불러오기</button><WorkedCasePanel inv={inv} status="error" /><LongWindowComparison key={inv} inv={inv} /></Panel>;
  const defs = q.data.definitions || {};
  const bundles: any[] = (q.data.bundles || []).map((base: any) => previews[base.id] || base);
  const groups = bundles.filter(b => (b.items || []).length).map(b => ({ b, items: b.items as any[] }));
  const keyOf = (b: any, item: any) => JSON.stringify([b.id, item.filters, item.title, scopeTime(b, item)]);
  const period = q.data.scope?.time;
  const partial = bundles.filter(b => b.completeness === "partial").length;
  const missing = bundles.filter(b => b.status === "insufficient_data").length;
  const failed = bundles.filter(b => b.status === "failed").length;
  const incomplete = !!(partial || missing || failed || !bundles.length);
  const found = groups.reduce((n, g) => n + (g.b.found ?? g.items.length), 0);
  // The first type opens by itself; the rest show their one-line summary until the analyst opens them.
  const openTypes = view.openTypes ?? groups.slice(0, 1).map(g => g.b.id);
  const toggleType = (id: string) => setView({ openTypes: openTypes.includes(id) ? openTypes.filter(x => x !== id) : [...openTypes, id] });
  const adjust = (id: string) => {
    if (editing && editing !== id) return;
    if (settings.current) settings.current.open = true;
    if (editing === id) focusEditor(); else setView({ editing: id });
  };
  const canWrite = me.data?.permissions?.includes("investigation.write");
  return <Panel title="검토할 활동" className="question-worklist">
    <div id="review-activities" tabIndex={-1} />
    <ErrorBox error={q.error || record.error} />
    <div className="queue-intro"><strong>{groups.length ? `자동 계산 후보 ${fmtNum(found)}개` : incomplete ? "확인하지 못한 범위가 있습니다" : "표시할 후보가 없습니다"}</strong>
      <span>{groups.length ? "저장된 탐지 결과와 별개로, 로그에서 바로 계산한 후보입니다. 활동을 열어 근거와 다음 확인을 보세요." : incomplete ? "계산 결과에서 자료와 범위를 확인하세요." : "조건에 맞는 후보가 없어도 정상으로 판정할 수는 없습니다."}</span></div>
    <p className="queue-scope">민감도 {({ low: "낮음", normal: "보통", high: "높음" } as Record<string,string>)[sensitivity]} · {period?.start || period?.end ? `조사 기간 ${fmtPeriod(period.start, period.end)} ${getTz()}${period.end_exclusive ? " (끝 시각 제외)" : ""}` : "기간 미지정 · 저장된 자료 기준"}{Object.keys(previews).length ? " · 조건 미리 보기 적용 중" : ""}</p>
    {(ctx.filters.length > 0 || !!ctx.time) && <p className="queue-scope">자료 통계는 현재 검색 조건을 따르며, 이 활동 목록은 위 계산 범위를 따릅니다.</p>}
    {(partial > 0 || missing > 0 || failed > 0) && <div className="queue-notice" role="status"><b>계산 한계</b>
      {partial > 0 && <span>일부만 계산 {partial}개 유형</span>}{missing > 0 && <span>자료 부족 {missing}개 유형</span>}{failed > 0 && <span>계산 실패 {failed}개 유형</span>}
      <button className="btn sm ghost" onClick={() => { if (settings.current) { settings.current.open = true; settings.current.scrollIntoView?.({ block: "nearest" }); } }}>한계 확인</button></div>}
    <WorkedCasePanel inv={inv} scope={q.data.scope} bundles={bundles} onEvidence={openEvidence} />
    <LongWindowComparison key={inv} inv={inv} />
    <div className="activity-list" ref={list}>{groups.map(({ b, items }) => {
      const open = openTypes.includes(b.id);
      const shown = Math.min(items.length, view.pages[b.id] || PAGE);
      const computed = b.found ?? items.length;
      return <section key={b.id} className="activity-type" aria-label={`${NAMES[b.id] || b.title} 후보`}>
        <button type="button" className="activity-type-head" aria-expanded={open} onClick={() => toggleType(b.id)}>
          <b>{NAMES[b.id] || b.title}</b>
          <span>계산된 {fmtNum(computed)}개{open ? ` · 현재 표시 ${fmtNum(shown)}개` : ""}{b.completeness === "partial" ? " · 일부만 계산(전체 결과 아님)" : ""}{previews[b.id] ? (b.preset ? " · 저장된 검색 조건" : " · 조건 미리 보기") : ""}</span>
          <span aria-hidden="true" className="activity-chevron">{open ? "−" : "+"}</span>
        </button>
        {open && <>{items.slice(0, shown).map((item: any, i: number) => {
          const key = keyOf(b, item), expanded = ctx.questionActivity === key, source = sourceScope(item.filters);
          const id = `${prefix}-${b.id}-${i}`;
          return <article key={key} data-activity={key} className={expanded ? "activity-entry is-open" : "activity-entry"}>
            <button className="activity-row" type="button" aria-expanded={expanded} aria-controls={id}
              onClick={() => ctx.set({ questionActivity: expanded ? null : key })}>
              <strong>{item.title}</strong>
              <span className="activity-meta">근거 {fmtNum(item.records)}건{source.observed && ` · ${source.observed}`}{item.time?.start && ` · ${fmtPeriod(item.time.start, item.time.end)}`}</span>
              <span aria-hidden="true" className="activity-chevron">{expanded ? "−" : "+"}</span>
            </button>
            {expanded && <div className="activity-detail" id={id}>
              <dl>
                <div><dt>관측 사실</dt><dd>{item.observed} <button className="btn sm" onClick={() => openEvidence(b, item)}>근거 {fmtNum(item.records)}건 보기</button>
                  {item.time?.start && <div className="queue-scope">근거 구간 {fmtPeriod(item.time.start, item.time.end)} {getTz()} · 조사 기간과 별개</div>}</dd></div>
                <div><dt>판단 범위</dt><dd>{ESTABLISHED[b.id] || "관측 기록"}은 확인됐습니다.{item.unknown?.length ? ` ${item.unknown.join(" · ")}은(는) 이 로그로 미확인입니다.` : ""}</dd></div>
                {item.next_questions?.[0] && <div><dt>다음 확인</dt><dd>{item.next_questions[0]}</dd></div>}
              </dl>
              {canWrite && <div className="row wrap">
                <button className="btn sm" onClick={() => openEvidence(b, item, true)}>판단 남기기</button>
                <button className="btn primary sm" disabled={record.isPending} onClick={() => record.mutate({ b, item })}>추가 확인 요청</button>
              </div>}
              {isCaseEvidenceInScope(q.data.scope, b, item, inv) && <ActivityCaseComparison
                inv={inv} observed={item.observed} title={item.title} onEvidence={() => openEvidence(b, item)} />}
              <details className="activity-more"><summary>선정 이유·정상 가능성·조건 펼치기</summary>
                <dl><div><dt>선정 이유</dt><dd>{b.description || item.basis?.metric || b.title}</dd></div>
                  {!source.observed && source.included && <div><dt>조회에 포함한 원천</dt><dd>{source.included}</dd></div>}
                  <DetailsList label="가능한 정상 업무" items={item.normal_possibilities} />
                  <DetailsList label="그 밖의 확인 사항" items={(item.next_questions || []).slice(1)} />
                  <DetailsList label="장비 의미 확인 필요" items={b.unconfirmed} />
                </dl>
                {defs[b.id] && <button className="queue-adjust" disabled={!!editing && editing !== b.id} onClick={() => adjust(b.id)}>이 유형의 검색 조건 조정</button>}
                {canWrite && <p className="queue-scope">"추가 확인 요청"은 초안만 엽니다. 직접 저장할 때까지 등록·발송되지 않으며, 자동으로 붙인 원문은 분석가가 읽은 기록으로 세지 않습니다.</p>}
              </details>
            </div>}
          </article>;
        })}
        {items.length > shown && <button className="btn sm" onClick={() => setView(v => ({ pages: { ...v.pages, [b.id]: shown + PAGE } }))}>
          {NAMES[b.id] || b.title} 더 보기 ({fmtNum(shown)}/{fmtNum(items.length)})</button>}
        {computed > items.length && <p className="queue-scope">계산된 {fmtNum(computed)}개 중 {fmtNum(items.length)}개만 받아 왔습니다. 조건을 좁혀 나머지를 보세요.</p>}
        </>}
      </section>;
    })}</div>
    <details className="queue-tools" ref={settings}><summary><b>계산 결과와 조건</b> · {bundles.length}개 유형 · 민감도</summary>
      <label className="queue-filter">질문 민감도 <select className="input" aria-label="질문 민감도" disabled={!!editing} value={sensitivity} onChange={e => { setView({ sensitivity: e.target.value, previews: {}, pages: {}, openTypes: null }); ctx.set({ questionActivity: null }); }}>
        <option value="low">낮음</option><option value="normal">보통</option><option value="high">높음</option></select></label>
      {bundles.map(b => { const [label, cls] = STATUS[b.status] || [b.status, ""];
        return <section className="queue-calculation" key={b.id} aria-label={b.title}><div className="row wrap">
          <b>{b.title}</b><span className={`tag ${cls}`}>{label}</span>
          {previews[b.id] && <span className="tag">{b.preset ? `저장된 조건 v${b.preset.version}` : "미리 보기 · 저장 안 됨"}</span>}
          {defs[b.id] && editing !== b.id && <button className="btn sm" disabled={!!editing} onClick={() => adjust(b.id)}>조건 수정</button>}</div>
          {b.description && <div>조건: {b.description}</div>}
          {b.note && <div>{b.note}</div>}
          {b.missing && <div>필요한 자료: {b.missing.join(", ")}</div>}
          <Coverage b={b} limits={q.data.limits} />
          {editing === b.id && defs[b.id] && <ConditionEditor inv={inv} bundle={b.id} def={defs[b.id]} sensitivity={sensitivity}
            initial={view.editorValues[b.id]} onValues={v => setView(cur => ({ editorValues: { ...cur.editorValues, [b.id]: v } }))}
            onResult={r => setView(cur => { const next = { ...cur.previews }; if (r) next[b.id] = r; else delete next[b.id];
              // A previewed condition opens its type, so the changed candidates are in view.
              const opened = cur.openTypes ?? openTypes;
              return { previews: next, openTypes: r && !opened.includes(b.id) ? [...opened, b.id] : opened }; })}
            onClose={() => setView(cur => { const values = { ...cur.editorValues }; delete values[b.id]; return { editing: null, editorValues: values }; })} />}
        </section>;
      })}
      {q.data.note && <p className="queue-scope">{q.data.note} · {q.data.version}</p>}
    </details>
    {q.data.questions && <details className="queue-tools"><summary><b>기본 질문 {q.data.questions.length}개</b> · 실행 여부와 필요한 자료</summary>
      <div className="queue-table-wrap"><table className="t small"><thead><tr><th>질문</th><th>실행 연결</th><th>자료·계산 상태</th><th>필요한 자료</th></tr></thead><tbody>
        {q.data.questions.map((x: any) => <tr key={x.id}><td>{x.id} {x.question}</td><td>{x.bundle ? "자동 계산" : x.view === "overview" ? "전체 현황에서 확인" : "아직 연결 안 됨"}</td>
          <td>{x.bundle ? `${(STATUS[x.status] || [x.status])[0]}${x.completeness === "partial" ? " · 일부만 계산" : ""}` : "실행 안 함"}</td><td>{x.needs || x.inputs?.join("·")}</td></tr>)}</tbody></table></div>
    </details>}
    <ExampleSearch inv={inv} editing={editing} onOpen={adjust} />
  </Panel>;
}
