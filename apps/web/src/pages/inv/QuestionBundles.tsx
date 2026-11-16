import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment, useEffect, useState } from "react";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { useInv } from "../../context/invContext";
import { ApiError, api } from "../../lib/api";
import { fmtNum, fmtTime } from "../../lib/format";

const STATUS: Record<string, [string, string]> = {
  found: ["확인할 근거 있음", "warn"], looked_none: ["이 기준에서는 보이지 않음 (정상 판정 아님)", ""],
  no_match: ["조건에 맞는 기록 없음 (정상 판정 아님)", ""],
  insufficient_data: ["자료 부족 — 판단 불가", "warn"], failed: ["계산 실패", "warn"], not_connected: ["아직 계산 연결 안 됨", ""],
};
const SCOPES: Record<string, string> = { investigation: "이번 조사", affiliate: "같은 관계사의 조사", common: "공통 템플릿" };

type Param = { name: string; label: string; type: string; default: any; help?: string; min?: number; max?: number; unit?: string; choices?: [string, string][] };

/** One input per condition, typed by the server's definition (the same definition that runs and is saved). */
function ParamInput({ p, value, onChange }: { p: Param; value: any; onChange: (v: any) => void }) {
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
function ConditionEditor({ inv, bundle, def, sensitivity, onResult, onClose }: { inv: string; bundle: string; def: any; sensitivity: string;
  onResult: (r: any | null) => void; onClose: () => void }) {
  const qc = useQueryClient();
  const [values, setValues] = useState<Record<string, any>>(def.defaults);
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
    <section aria-label="조건 수정" className="panel pb col" style={{ gap: 8, marginTop: 6 }}>
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
function ExampleSearch({ inv, onOpen }: { inv: string; onOpen: (bundle: string) => void }) {
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const list = useQuery<any>({ queryKey: ["question-examples", inv, q, kind], queryFn: () => api.get(`/investigations/${inv}/question-examples?q=${encodeURIComponent(q)}&kind=${kind}`) });
  return (
    <details className="small" style={{ marginTop: 8 }}>
      <summary><b>더 많은 예제 찾기</b> — 명세 {list.data?.catalog_total ?? 120}개(탐지·헌팅·시나리오), 실행 룰이 아님</summary>
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
            {x.execution.bundle && <div><button className="btn sm" onClick={() => onOpen(x.execution.bundle)}>가까운 질문 {x.execution.question}의 조건 열기</button>
              <span className="muted"> 이 명세의 조건이 그대로 실행되는 것은 아닙니다. 연결된 질문의 조건을 고쳐 현재 로그로 확인하세요.</span></div>}
          </div></td></tr>}</Fragment>))}</tbody></table>
    </details>
  );
}

/** The investigation questions, computed from the logs; each item leads to its logs and to a check, in one scope. */
export function QuestionBundles({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const qc = useQueryClient();
  const [sensitivity, setSensitivity] = useState("normal");
  const [editing, setEditing] = useState<string | null>(null);
  const [previews, setPreviews] = useState<Record<string, any>>({});
  const q = useQuery<any>({ queryKey: ["question-bundles", inv, sensitivity],
    queryFn: () => api.get(`/investigations/${inv}/question-bundles?sensitivity=${sensitivity}`) });
  const scopeTime = (b: any) => (b.scope || q.data?.scope)?.time ?? null;
  const record = useMutation({
    // A check on the item's own records, in the question's scope, carrying the whole question and its condition.
    mutationFn: async ({ b, item }: { b: any; item: any }) => {
      const time = scopeTime(b);
      const page = await api.post<any>(`/investigations/${inv}/query/events`, { filters: item.filters, time, limit: 500 });
      const ids = (page.events || []).map((e: any) => e.event_id);
      const origin = { kind: "question", bundle: b.id, title: b.title, description: b.description, parameters: b.parameters,
        preset: b.preset || null, scope: b.scope || q.data?.scope, completeness: b.completeness, partial_reasons: b.partial_reasons, item };
      const query = { filters: item.filters, time };
      return api.post(`/investigations/${inv}/checks`, { target_type: "set", target_label: item.title.slice(0, 500), questions: ["nature"],
        note: `${item.observed} 확인 필요: ${(item.next_questions || []).join(" / ")}`.slice(0, 2000),
        evidence: ids.slice(0, 20),
        // Everything loaded is "all"; otherwise the 20 kept records are a sample of what was loaded.
        scope: ids.length >= item.records
          ? { coverage: "all", query, loaded: ids.length, event_ids: ids.slice(0, 20), origin }
          : { coverage: "sample", query, checked: Math.min(20, ids.length), loaded: ids.length, event_ids: ids.slice(0, 20), origin } });
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["checks", inv] }); ctx.set({ tab: "checks" }); },
  });
  if (q.isLoading) return <Loading label="확인할 질문 계산 중" />;
  const defs = q.data?.definitions || {};
  return (
    <Panel title="확인할 질문 — 로그에서 바로 계산 (정책·규칙 작성 없이)"
      right={<label className="small row" style={{ gap: 4 }}>민감도<select className="input" aria-label="질문 민감도" value={sensitivity} onChange={(e) => { setSensitivity(e.target.value); setPreviews({}); }}>
        <option value="low">낮음</option><option value="normal">보통</option><option value="high">높음</option></select></label>}>
      <ErrorBox error={q.error || record.error} />
      {q.data?.note && <p className="small muted">{q.data.note} 계산 범위: 조사 기간 {fmtTime(q.data.scope?.time?.start)} ~ {fmtTime(q.data.scope?.time?.end)}{q.data.scope?.time?.end_exclusive ? " 전" : ""} · {q.data.version}</p>}
      {q.data?.questions && (
        <details className="small"><summary><b>기본 질문 10개</b> — 실행 연결·자료 준비·계산 상태</summary>
          <table className="t small"><thead><tr><th>질문</th><th>실행 연결</th><th>자료·계산 상태</th><th>필요한 것</th></tr></thead><tbody>
            {q.data.questions.map((x: any) => (
              <tr key={x.id}><td>{x.id} {x.question}</td><td>{x.bundle ? "엔진 연결됨" : x.view === "overview" ? "전체 현황에서 확인" : "아직 연결 안 됨"}</td>
                <td>{x.bundle ? `${(STATUS[x.status] || [x.status])[0]}${x.completeness === "partial" ? " · 일부만 계산" : ""}` : "실행 안 함"}</td>
                <td>{x.needs || x.inputs.join("·")}</td></tr>))}</tbody></table>
        </details>)}
      <ExampleSearch inv={inv} onOpen={(bundle) => setEditing(bundle)} />
      {(q.data?.bundles || []).map((base: any) => {
        const b = previews[base.id] || base;
        const [label, cls] = STATUS[b.status] || [b.status, ""];
        return (
          <section key={base.id} aria-label={base.title} className="col" style={{ gap: 6, marginTop: 10 }}>
            <div className="row wrap" style={{ gap: 6 }}>
              <b>{base.title}</b><span className={`tag ${cls}`}>{label}</span>
              {b.completeness === "partial" && <span className="tag warn">일부만 계산</span>}
              {previews[base.id] && <span className="tag">{previews[base.id].preset ? `저장된 조건 v${previews[base.id].preset.version}` : "미리 보기 · 저장 안 됨"}</span>}
              {defs[base.id] && editing !== base.id && <button className="btn sm" onClick={() => setEditing(base.id)}>조건 수정</button>}
            </div>
            {b.description && <div className="small">조건: {b.description}</div>}
            {b.note && <div className="small muted">{b.note}</div>}
            {b.missing && <div className="small muted">필요한 자료: {b.missing.join(", ")}. 이 질문 말고 다른 분석은 계속됩니다.</div>}
            <Coverage b={b} limits={q.data?.limits} />
            {editing === base.id && <ConditionEditor inv={inv} bundle={base.id} def={defs[base.id]} sensitivity={sensitivity}
              onResult={(r) => setPreviews((cur) => { const next = { ...cur }; if (r) next[base.id] = r; else delete next[base.id]; return next; })}
              onClose={() => setEditing(null)} />}
            {(b.items || []).map((it: any, i: number) => (
              <article key={i} className="panel pb col" style={{ gap: 4 }}>
                <b>{it.title}</b>
                <div className="small"><b>관측된 근거</b> {it.observed} (관련 기록 {fmtNum(it.records)}건{it.time?.start ? ` · ${fmtTime(it.time.start)} ~ ${fmtTime(it.time.end)}` : ""})</div>
                <div className="small"><b>아직 알 수 없는 것</b> {(it.unknown || []).join(" · ")}</div>
                <div className="small"><b>정상 가능성</b> {(it.normal_possibilities || []).join(" · ")}</div>
                <div className="small"><b>다음 확인</b> {(it.next_questions || []).join(" / ")}</div>
                <div className="row wrap" style={{ gap: 6 }}>
                  <button className="btn sm" onClick={() => ctx.set({ tab: "raw", filters: it.filters, time: scopeTime(b), selection: null })}>같은 범위 전체 로그 보기</button>
                  <button className="btn sm" disabled={record.isPending} onClick={() => record.mutate({ b, item: it })}>확인 기록으로 남기고 확인 요청 작성</button>
                </div>
              </article>
            ))}
          </section>
        );
      })}
    </Panel>
  );
}
