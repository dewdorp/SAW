import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { PageHeader } from "../../components/ui";
import { api } from "../../lib/api";
import { fmtTime } from "../../lib/format";
import "../hunt/hunt.css";
import "../inv/flows/flows.css";

const CRIT_KO: Record<string, string> = { critical: "매우 높음", high: "높음", medium: "보통", low: "낮음" };
const ACTION_KO: Record<string, string> = { new: "신규", changed: "변경", unchanged: "변경 없음", conflict: "충돌", error: "오류" };
const FIELD_KO: Record<string, string> = { name: "이름", service: "서비스", business: "업무", hostname: "호스트", owner: "담당자", department: "부서", network: "망", notes: "비고",
  info_source: "출처", last_confirmed: "마지막 확인일", next_review: "다음 확인일", state: "상태", operating_hours: "운영 시간", criticality: "중요도", external_id: "외부 관리 ID" };

function Import({ org, onDone }: { org: string; onDone: () => void }) {
  const [text, setText] = useState("");
  const [clear, setClear] = useState(false);
  const body = { text, org_unit_id: org || null, clear_blank: clear };
  const preview = useMutation({ mutationFn: () => api.post("/asset-book/import/preview", body) });
  const apply = useMutation({ mutationFn: () => api.post("/asset-book/import/apply", body), onSuccess: onDone });
  const read = async (file?: File) => { if (file) { setText(await file.text()); preview.reset(); } };
  const p = preview.data;
  return <Panel title="파일로 갱신 (CSV)">
    <p className="small muted">1. 파일 선택 → 2. 열 연결 확인 → 3. 신규·변경·충돌 미리 보기 → 4. 적용. Excel 파일은 "CSV(쉼표로 분리)"로 저장해 올리세요. 엑셀에서 복사해 붙여 넣어도 됩니다.</p>
    <div className="row wrap"><input type="file" accept=".csv,.txt,.tsv" aria-label="자산 파일 선택" onChange={e => read(e.target.files?.[0])} />
      <label className="row small"><input type="checkbox" checked={clear} onChange={e => { setClear(e.target.checked); preview.reset(); }} />빈 칸은 기존 값 비우기 (기본: 기존 값 유지)</label></div>
    <textarea className="input mono" rows={4} aria-label="자산 표 붙여넣기" placeholder={"자산 ID,이름,IP 주소,담당자,업무,중요도\nCRM-001,고객관리 웹,10.50.9.77,김담당,고객 상담 조회,높음"} value={text} onChange={e => { setText(e.target.value); preview.reset(); }} />
    <div className="row"><button className="btn primary sm" disabled={!text.trim() || preview.isPending} onClick={() => preview.mutate()}>미리 보기</button></div>
    <ErrorBox error={preview.error} />
    {p && <div className="col" role="status">
      <p className="small">연결한 열: {p.columns.map((c: string) => FIELD_KO[c] || ({ asset_id: "자산 ID", ip: "IP 주소", domain: "도메인", cidr: "대역", valid_from: "유효 시작", valid_to: "유효 종료" } as any)[c] || c).join(", ")}
        {p.unknown_columns.length > 0 && <span className="tag warn">연결하지 못한 열: {p.unknown_columns.join(", ")}</span>}</p>
      <p><b>신규 {p.counts.new} · 변경 {p.counts.changed} · 변경 없음 {p.counts.unchanged} · 충돌 {p.counts.conflict} · 오류 {p.counts.error}</b></p>
      <div className="fk-table"><table className="t"><thead><tr><th>행</th><th>자산</th><th>처리</th><th>내용</th></tr></thead>
        <tbody>{p.rows.filter((r: any) => r.action !== "unchanged").slice(0, 200).map((r: any) => <tr key={r.line}><td className="num">{r.line}</td><td className="small">{r.asset_id || "(새 ID)"} {r.name}</td>
          <td><span className={`tag ${r.action === "conflict" || r.action === "error" ? "bad" : r.action === "changed" ? "warn" : "ok"}`}>{ACTION_KO[r.action]}</span></td>
          <td className="small">{r.reason || r.changes.map((c: any) => `${FIELD_KO[c.field] || c.field}: ${c.from || "(없음)"} → ${c.to || "(비움)"}`).join(" / ") || "새로 등록"}</td></tr>)}</tbody></table></div>
      <ul className="small muted">{p.notes.map((n: string) => <li key={n}>{n}</li>)}</ul>
      <div className="row"><button className="btn primary" disabled={apply.isPending || !(p.counts.new + p.counts.changed)} onClick={() => apply.mutate()}>신규 {p.counts.new}건·변경 {p.counts.changed}건 적용</button>
        <span className="small muted">충돌·오류 행은 적용하지 않습니다.</span></div>
      <ErrorBox error={apply.error} /></div>}
  </Panel>;
}

function Detail({ a, onSaved }: { a: any; onSaved: () => void }) {
  const [tab, setTab] = useState("basic");
  const [form, setForm] = useState<any>({ name: a.name, owner: a.owner || "", department: a.department || "", business: a.business || "", operating_hours: a.operating_hours || "",
    info_source: a.info_source || "", last_confirmed: a.last_confirmed || "", next_review: a.next_review || "", state: a.state || "active", notes: a.notes || "" });
  const [crit, setCrit] = useState(a.criticality);
  const [addrs, setAddrs] = useState<any[]>(a.addresses);
  const save = useMutation({ mutationFn: (extra: any = {}) => api.put(`/asset-book/${a.id}`, { expected_rev: a.rev, criticality: crit, data: { ...form, addresses: addrs.filter(x => x.value.trim()), ...extra } }), onSuccess: onSaved });
  const meanings = useQuery({ queryKey: ["flow-items-host", a.hostname, a.domain], enabled: tab === "work",
    queryFn: async () => { const hosts = [a.hostname, ...(a.domain || [])].filter(Boolean); const all = await Promise.all(hosts.map((h: string) => api.get(`/knowledge/flow-items?host=${encodeURIComponent(h)}`))); return all.flatMap((x: any) => x.items); } });
  const history = useQuery({ queryKey: ["asset-history", a.id, a.rev], enabled: tab === "history", queryFn: () => api.get(`/asset-book/${a.id}/history`) });
  const field = (k: string, label: string, type = "text") => <label className="col small">{label}<input className="input" type={type} value={form[k]} onChange={e => setForm({ ...form, [k]: e.target.value })} /></label>;
  return <div className="fk-detail">
    <div className="tabs" role="tablist">{[["basic", "기본 정보"], ["work", "서비스 기능·정상 업무"], ["history", "변경 이력·확인할 내용"]].map(([k, l]) =>
      <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? "active" : ""} onClick={() => setTab(k)}>{l}</button>)}</div>
    {tab === "basic" && <div className="col">
      <div className="fk-grid">{field("name", "이름")}{field("owner", "담당자")}{field("department", "부서")}
        <label className="col small">중요도<select className="input" value={crit} onChange={e => setCrit(e.target.value)}>{Object.entries(CRIT_KO).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
        <label className="col small">상태<select className="input" value={form.state} onChange={e => setForm({ ...form, state: e.target.value })}><option value="active">사용 중</option><option value="retired">폐기</option></select></label>
        {field("info_source", "정보 출처")}{field("last_confirmed", "마지막 확인일", "date")}{field("next_review", "다음 확인일", "date")}</div>
      <h5 className="fk-h">주소·식별 정보 (언제부터 언제까지 이 자산의 것이었는지)</h5>
      {addrs.map((x, i) => <div key={i} className="row wrap small">
        <input className="input mono" aria-label="주소 또는 호스트" value={x.value} onChange={e => setAddrs(addrs.map((y, k) => k === i ? { ...y, value: e.target.value } : y))} style={{ width: 180 }} />
        <label>시작 <input className="input" type="date" value={(x.valid_from || "").slice(0, 10)} onChange={e => setAddrs(addrs.map((y, k) => k === i ? { ...y, valid_from: e.target.value } : y))} /></label>
        <label>종료 <input className="input" type="date" value={(x.valid_to || "").slice(0, 10)} onChange={e => setAddrs(addrs.map((y, k) => k === i ? { ...y, valid_to: e.target.value } : y))} /></label>
        <span className="muted">{x.source || ""}</span><button className="btn ghost sm" onClick={() => setAddrs(addrs.filter((_, k) => k !== i))}>빼기</button></div>)}
      <div><button className="btn sm" onClick={() => setAddrs([...addrs, { value: "", kind: "ip", valid_from: "", valid_to: "", source: "수동 등록" }])}>주소 추가</button></div>
      <p className="small muted">주소를 다른 자산으로 옮길 때는 지우지 말고 종료일을 적으세요. 과거 기록은 그때 유효했던 자산으로 연결됩니다.</p>
      <ErrorBox error={save.error} />
      <div className="row"><button className="btn primary" disabled={save.isPending} onClick={() => save.mutate({})}>저장</button>
        <button className="btn" disabled={save.isPending} title="오늘 날짜로 확인했다고 남깁니다" onClick={() => save.mutate({ last_confirmed: new Date().toISOString().slice(0, 10) })}>오늘 확인함</button></div></div>}
    {tab === "work" && <div className="col">
      <label className="col small">이 자산의 업무 (담당자가 확인한 설명)<textarea className="input" rows={2} value={form.business} onChange={e => setForm({ ...form, business: e.target.value })} /></label>
      {field("operating_hours", "운영 시간·정기 작업 (예: 평일 09~18시, 매일 02시 정산 배치)")}
      <div className="row"><button className="btn primary sm" disabled={save.isPending} onClick={() => save.mutate({})}>저장</button></div><ErrorBox error={save.error} />
      <h5 className="fk-h">서비스 기능 설명 (경로의 업무 의미)</h5>
      {!a.hostname && !(a.domain || []).length ? <p className="small">이 자산에 호스트명이나 도메인이 없어 연결된 기능 설명을 찾을 수 없습니다. 기본 정보에 도메인을 추가하세요.</p>
        : meanings.isLoading ? <Loading /> : <ul className="small">{(meanings.data || []).filter((k: any) => k.kind !== "scenario").map((k: any) => <li key={k.id}>{k.title} <span className="muted">v{k.version}{k.status === "stopped" ? " · 적용 중지" : ""}</span></li>)}
          {!(meanings.data || []).length && <li className="muted">등록된 기능 설명이 없습니다.</li>}</ul>}
      <p className="small muted">기능 설명은 헌팅의 기록 상세에서 "메모하고 기억하기"로 추가하고, <Link to="/knowledge/flows">업무 의미·흐름 이력</Link>에서 고칩니다. 확인한 것만 등록하세요. 등록된 설명은 활동을 숨기지 않고 "정상 가능성" 옆에 표시됩니다.</p></div>}
    {tab === "history" && <div className="col">
      {a.review.length > 0 ? <ul>{a.review.map((r: string) => <li key={r}><span className="tag warn">확인 필요</span> {r}</li>)}</ul> : <p className="small">확인할 내용이 없습니다.</p>}
      {history.isLoading ? <Loading /> : <div className="small">{(history.data?.revisions || []).map((r: any) => <div key={r.rev} className="fk-version"><span>rev {r.rev}</span><span className="muted">{r.actor}{r.at ? ` · ${fmtTime(r.at)}` : ""}</span>
        <span>{r.data?.owner ? `담당 ${r.data.owner}` : "담당 없음"} · 주소 {(r.data?.addresses || r.data?.ip || []).length}개</span></div>)}</div>}</div>}
  </div>;
}

/** Assets and business context: start with a name and one identifier, keep it current, and see what needs a check. */
export function Assets() {
  const qc = useQueryClient();
  const [org, setOrg] = useState("");
  const [text, setText] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [mode, setMode] = useState<"list" | "import">("list");
  const [quick, setQuick] = useState({ name: "", identifier: "" });
  const orgs = useQuery({ queryKey: ["org-units"], queryFn: () => api.get("/source-context/org-units") });
  const q = useQuery({ queryKey: ["asset-book", org, text], queryFn: () => api.get(`/asset-book?q=${encodeURIComponent(text)}${org ? `&org_unit_id=${org}` : ""}`) });
  const refresh = () => qc.invalidateQueries({ queryKey: ["asset-book"] });
  const create = useMutation({ mutationFn: () => api.post("/asset-book", { ...quick, org_unit_id: org || null }), onSuccess: (a: any) => { setQuick({ name: "", identifier: "" }); refresh(); setOpen(a.id); } });
  const items: any[] = q.data?.items || [];
  return <div className="page col">
    <PageHeader eyebrow="자산·업무" title="자산·업무" desc="자산과 서비스 기능, 정상 업무를 등록해 두면 다음 헌팅에서 활동 옆에 함께 보여 줍니다. 등록하지 않아도 헌팅은 됩니다." />
    <div className="row wrap">
      <select className="input" aria-label="관계사" value={org} onChange={e => setOrg(e.target.value)}><option value="">모든 관계사</option>{(orgs.data || []).map((o: any) => <option key={o.id} value={o.id}>{o.display_name}</option>)}</select>
      <input className="input" type="search" aria-label="자산 찾기" placeholder="이름·주소·ID" value={text} onChange={e => setText(e.target.value)} />
      <button className={`btn sm ${mode === "import" ? "primary" : ""}`} onClick={() => setMode(mode === "import" ? "list" : "import")}>{mode === "import" ? "목록으로" : "파일로 갱신"}</button></div>
    {mode === "import" ? <Import org={org} onDone={() => { refresh(); setMode("list"); }} /> : <>
      <Panel title="자산 등록">
        <form className="row wrap" onSubmit={e => { e.preventDefault(); create.mutate(); }}>
          <input className="input" aria-label="자산 이름" placeholder="이름 (예: 회원 포털)" value={quick.name} onChange={e => setQuick({ ...quick, name: e.target.value })} />
          <input className="input mono" aria-label="식별 정보" placeholder="IP·도메인·호스트 중 하나" value={quick.identifier} onChange={e => setQuick({ ...quick, identifier: e.target.value })} />
          <button className="btn primary" disabled={!quick.name.trim() || !quick.identifier.trim() || create.isPending}>등록</button>
          <span className="small muted">{org ? "선택한 관계사로 등록합니다." : "관계사를 고르지 않으면 공통 자산으로 등록합니다."} 담당자·업무는 나중에 채워도 됩니다.</span></form>
        <ErrorBox error={create.error} /></Panel>
      {q.data?.to_review?.length > 0 && <Panel title={`확인할 변경 ${q.data.to_review.length}건`}>
        <ul className="small">{q.data.to_review.slice(0, 30).map((t: any, i: number) => <li key={i}><span className={`tag ${t.kind === "address_conflict" ? "bad" : "warn"}`}>{t.kind === "address_conflict" ? "주소 충돌" : "확인 필요"}</span> {t.text}
          <button className="btn ghost sm" onClick={() => setOpen(t.asset_ids[t.asset_ids.length - 1])}>열기</button></li>)}</ul></Panel>}
      <Panel title={`자산 ${items.length}개`}>
        {q.isLoading && <Loading />}<ErrorBox error={q.error} />
        {!q.isLoading && !items.length && <p>등록된 자산이 없습니다. 위에서 이름과 주소 하나로 등록하거나, 파일로 한꺼번에 올리세요.</p>}
        <ul className="fk-flows">{items.map(a => <li key={a.id} className={open === a.id ? "open" : ""}>
          <button className="fk-flow" aria-expanded={open === a.id} onClick={() => setOpen(open === a.id ? null : a.id)}>
            <span className="fk-flow-main"><b>{a.name}</b><span className="small muted">{a.asset_id} · {a.addresses.filter((x: any) => !x.valid_to || x.valid_to >= new Date().toISOString().slice(0, 10)).map((x: any) => x.value).join(", ") || "주소 없음"} · 담당 {a.owner_masked || "미확인"} · 중요도 {CRIT_KO[a.criticality]}</span></span>
            <span className="fk-flow-tags">{a.state === "retired" && <span className="tag">폐기</span>}{a.review.map((r: string) => <span key={r} className="tag warn">{r}</span>)}</span></button>
          {open === a.id && <Detail key={`${a.id}:${a.rev}`} a={a} onSaved={refresh} />}</li>)}</ul></Panel></>}
  </div>;
}
