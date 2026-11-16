import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ErrorBox, Loading } from "../../components/common";
import { PageHeader } from "../../components/ui";
import { api, ApiError } from "../../lib/api";
import { fmtTime } from "../../lib/format";
import { ParamInput } from "../inv/QuestionBundles";
import "./hunt.css";

const WHERE: Record<string, [string, string, string]> = {
  knowledge: ["/knowledge/flows", "업무 의미·흐름 열기", "업무 의미는 헌팅의 기록 상세에서 \"메모하고 기억하기\"로 더합니다."],
  scenarios: ["/scenarios", "시나리오 열기", "시나리오를 만들거나 고치고 \"다음 헌팅부터 사용\"으로 저장합니다."],
  detections: ["/detections", "탐지 룰 열기", "직접 만든 탐지 룰을 관리합니다. 기본 내장 탐지의 기준은 여기서 바꿀 수 없습니다."],
};
const same = (a: any, b: any) => JSON.stringify(a) === JSON.stringify(b);

/** What a hunt looks for and with what thresholds: switches and numbers, for every affiliate or for one. */
export function Criteria() {
  const qc = useQueryClient();
  const [params, setParams] = useSearchParams();
  const org = params.get("org") || "";
  const focus = params.get("method") || "";
  const orgs = useQuery({ queryKey: ["org-units"], queryFn: () => api.get("/source-context/org-units") });
  const q = useQuery({ queryKey: ["hunt-criteria", org], queryFn: () => api.get(`/hunt-criteria${org ? `?org_unit_id=${org}` : ""}`) });
  const [form, setForm] = useState<any>(null);
  const [saved, setSaved] = useState("");
  const item = q.data ? (org ? q.data.own : q.data.common) : null;
  // The form starts from what is saved for this scope; an affiliate without its own criteria starts from what it follows now.
  useEffect(() => {
    if (!q.data) return;
    const base = item?.content || (org && q.data.common?.content) || q.data.defaults;
    setForm({ off: [...(base.off || [])], questions: JSON.parse(JSON.stringify(base.questions || {})), target_variation: { ...base.target_variation } });
  }, [q.data, org]); // eslint-disable-line react-hooks/exhaustive-deps
  const done = (text: string) => { setSaved(text); qc.invalidateQueries({ queryKey: ["hunt-criteria"] }); qc.invalidateQueries({ queryKey: ["hunt"] }); };
  const save = useMutation({ mutationFn: () => item
      ? api.put(`/knowledge/flow-items/${item.id}`, { expected_version: item.version, content: form, change_note: "분석 기준 수정" })
      : api.post("/knowledge/flow-items", { kind: "criteria", org_unit_id: org || null, content: form }),
    onSuccess: () => done("저장했습니다. 다음 분석부터 적용됩니다.") });
  const reset = useMutation({ mutationFn: () => api.post(`/knowledge/flow-items/${item.id}/stop`, { expected_version: item.version, change_note: "분석 기준 사용 중지" }),
    onSuccess: () => done(org ? "이 관계사만의 기준을 중지했습니다. 공통 기준(없으면 기본 기준)을 따릅니다." : "공통 기준을 중지했습니다. 기본 기준을 따릅니다.") });
  if (q.isLoading || !form) return <div className="page"><Loading /></div>;
  if (q.error) return <div className="page"><ErrorBox error={q.error} /></div>;
  const d = q.data;
  const eff = d.effective;
  const orgName = (orgs.data || []).find((o: any) => o.id === org)?.display_name || "";
  const set = (patch: any) => { setForm({ ...form, ...patch }); setSaved(""); };
  const on = (id: string) => !form.off.includes(id);
  const toggle = (id: string) => set({ off: on(id) ? [...form.off, id] : form.off.filter((x: string) => x !== id) });
  const setQ = (bundle: string, name: string, value: any, def: any) => {
    const next = { ...(form.questions[bundle] || {}) };
    if (same(value, def)) delete next[name]; else next[name] = value;
    const questions = { ...form.questions, [bundle]: next };
    if (!Object.keys(next).length) delete questions[bundle];
    set({ questions });
  };
  const following = eff.source === "affiliate" ? `${orgName || "이 관계사"}의 기준 v${eff.version}` : eff.source === "common" ? `공통 기준 v${eff.version}` : "기본 기준(저장된 기준 없음)";
  return <div className="page col">
    <PageHeader eyebrow="헌팅" title="분석 기준" desc="헌팅이 자료에서 무엇을 찾고 어떤 기준으로 '확인할 활동'을 만드는지 정합니다. 코드나 조건식을 쓰지 않습니다."
      actions={<Link className="btn" to="/">헌팅 목록</Link>} />
    <div className="row wrap cr-scope">
      <label className="row small">적용 범위
        <select className="input" aria-label="적용 범위" value={org} onChange={e => { setParams(e.target.value ? { org: e.target.value } : {}); setSaved(""); }}>
          <option value="">모든 관계사 공통</option>{(orgs.data || []).map((o: any) => <option key={o.id} value={o.id}>{o.display_name}만</option>)}</select></label>
      <span className="small" role="status">지금 {org ? `${orgName || "이 관계사"}의 헌팅` : "관계사 기준이 없는 헌팅"}에 적용되는 것: <b>{following}</b>
        {item ? ` · 고친 날 ${fmtTime(item.updated_at)}` : ""}</span>
    </div>
    {eff.conflict && <p role="alert">같은 범위에 사용 중인 기준이 둘 이상이라 어느 쪽도 적용하지 않고 기본 기준으로 분석합니다. 도구·설정 &gt; 업무 의미·흐름 이력에서 하나를 중지하세요.</p>}
    {org && !d.own && <p className="small" role="note">이 관계사만의 기준은 아직 없습니다. 아래 값은 지금 따르는 기준에서 시작하며, 저장하면 이 관계사에만 적용됩니다.</p>}
    <div className="cr-list">{d.methods.map((m: any) => {
      const isQ = m.id.startsWith("q.");
      const bundle = m.id.slice(2);
      const changed = isQ ? Object.keys(form.questions[bundle] || {}) : [];
      const tv = form.target_variation;
      const tvChanged = m.id === "target_variation" && !same(tv, d.defaults.target_variation);
      return <section key={m.id} id={`m-${m.id}`} className={`panel cr-card ${focus === m.id ? "focus" : ""} ${on(m.id) ? "" : "offed"}`}>
        <div className="row wrap">
          <label className="row"><input type="checkbox" aria-label={`${m.name} 사용`} checked={on(m.id)} disabled={!d.can_write} onChange={() => toggle(m.id)} /><b>{m.name}</b></label>
          <span className={`tag ${on(m.id) ? "ok" : ""}`}>{on(m.id) ? "사용" : "사용 안 함"}</span>
          {(changed.length > 0 || tvChanged) && <span className="tag warn">기본값에서 바꿈 {changed.length || ""}</span>}
        </div>
        <p className="small">{m.what}</p>
        {!on(m.id) && <p className="small muted">끄면 이 방법은 계산하지 않고, 헌팅에는 "사용 안 함"으로 표시됩니다("조건 일치 없음"과 다릅니다).</p>}
        {isQ && on(m.id) && <details open={focus === m.id || changed.length > 0}><summary>기준 값 보기·고치기</summary>
          <div className="cr-params">{m.params.map((p: any) => {
            const value = (form.questions[bundle] || {})[p.name] ?? m.defaults[p.name];
            return <div key={p.name} className={changed.includes(p.name) ? "cr-changed" : ""}>
              <ParamInput p={p} value={value} onChange={v => setQ(bundle, p.name, v, m.defaults[p.name])} />
              {changed.includes(p.name) && <button className="btn ghost sm" onClick={() => setQ(bundle, p.name, m.defaults[p.name], m.defaults[p.name])}>기본값으로</button>}</div>;
          })}</div></details>}
        {m.id === "target_variation" && on(m.id) && <div className="cr-params">
          <label className="row wrap small"><b>서로 다른 대상 수</b>
            <input className="input" type="number" min={2} max={5000} aria-label="서로 다른 대상 수" style={{ width: 100 }} value={tv.min_targets}
              onChange={e => set({ target_variation: { ...tv, min_targets: Number(e.target.value) } })} /> 개 이상이고</label>
          <label className="row wrap small"><b>같은 기능 이용자 중앙값의</b>
            <input className="input" type="number" min={1} max={100} step={0.5} aria-label="중앙값 배수" style={{ width: 100 }} value={tv.ratio}
              onChange={e => set({ target_variation: { ...tv, ratio: Number(e.target.value) } })} /> 배 이상일 때 활동으로</label>
          {tvChanged && <button className="btn ghost sm" onClick={() => set({ target_variation: { ...d.defaults.target_variation } })}>기본값으로 (8개 · 4배)</button>}</div>}
        {WHERE[m.edit] && <p className="small">{WHERE[m.edit][2]} <Link to={WHERE[m.edit][0]}>{WHERE[m.edit][1]}</Link></p>}
      </section>;
    })}</div>
    <div className="cr-save">
      {save.error instanceof ApiError && save.error.status === 409 ? <p role="alert">{save.error.detail}</p> : <ErrorBox error={save.error} />}
      <ErrorBox error={reset.error} />
      {saved && <p role="status"><b>{saved}</b> 이미 끝난 헌팅은 그 헌팅에서 "다시 분석"을 눌러야 바뀝니다.</p>}
      {!d.can_write && <p className="small muted">기준을 고칠 권한이 없어 보기만 할 수 있습니다.</p>}
      <div className="row wrap">
        <button className="btn primary" disabled={!d.can_write || save.isPending} onClick={() => save.mutate()}>
          {save.isPending ? "저장 중…" : org ? `${orgName || "이 관계사"}에만 저장` : "모든 관계사 공통으로 저장"}</button>
        {item && <button className="btn" disabled={!d.can_write || reset.isPending} onClick={() => reset.mutate()}>{org ? "이 관계사만의 기준 중지" : "공통 기준 중지(기본 기준으로)"}</button>}
        <span className="small muted">{d.note}</span></div>
    </div>
  </div>;
}
