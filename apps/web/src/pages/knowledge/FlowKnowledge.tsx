import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { api, ApiError } from "../../lib/api";
import { fmtTime } from "../../lib/format";
import { ROLE_KO } from "../inv/flows/RememberDialog";
import "../inv/flows/flows.css";

const KIND_KO: Record<string, string> = { activity: "업무 의미", link: "연결 기준", flow: "흐름" };

function describe(item: any, names: Record<string, string>): string {
  const c = item.content;
  if (item.kind === "activity") return `${c.method || "모든 메서드"} ${c.path}${c.match !== "exact" ? ` (${c.match === "prefix" ? "시작 일치" : "패턴"})` : ""} → ${c.meaning} · ${ROLE_KO[c.role] || c.role}`
    + (c.object_param ? ` · 대상 ${c.object_param}` : "") + (c.outcomes?.length ? ` · 결과 기준 ${c.outcomes.length}개` : " · 결과 기준 없음");
  if (item.kind === "link") return `${c.session_cookie ? `세션 쿠키 ${c.session_cookie}` : "세션 식별자 미확인"} · uuid ${c.request_id_confirmed ? "요청 ID로 확인" : "의미 미확정"}`;
  return (c.steps || []).map((s: any) => `${names[s.activity] || "?"}${s.state ? `(${s.state === "success" ? "성공" : "실패"})` : ""}${s.optional ? "?" : ""}${s.repeat ? "+" : ""}`).join(" → ")
    + ` · ${({ normal: "정상 업무 흐름", suspicious: "의심 흐름", undetermined: "분류 미확정" } as any)[c.classification]}`;
}

function Item({ item, names, orgs }: { item: any; names: Record<string, string>; orgs: Record<string, string> }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState("");
  const [note, setNote] = useState("");
  const refresh = () => { qc.invalidateQueries({ queryKey: ["flow-items"] }); qc.invalidateQueries({ queryKey: ["flow-item-history", item.id] }); qc.invalidateQueries({ queryKey: ["flows"] }); };
  const history = useQuery({ queryKey: ["flow-item-history", item.id], enabled: open, queryFn: () => api.get(`/knowledge/flow-items/${item.id}/history`) });
  const affected = useQuery({ queryKey: ["flow-item-affected", item.id, item.version], enabled: open, queryFn: () => api.get(`/knowledge/flow-items/${item.id}/affected`) });
  const state = useMutation({ mutationFn: (action: string) => api.post(`/knowledge/flow-items/${item.id}/${action}`, { expected_version: item.version, change_note: note }), onSuccess: () => { setNote(""); refresh(); } });
  const restore = useMutation({ mutationFn: (v: number) => api.post(`/knowledge/flow-items/${item.id}/versions/${v}/restore`, { expected_version: item.version, change_note: note }), onSuccess: refresh });
  const save = useMutation({ mutationFn: (allow: boolean) => api.put(`/knowledge/flow-items/${item.id}`, { expected_version: item.version, change_note: note, content: JSON.parse(text), allow_conflict: allow }),
    onSuccess: () => { setEditing(false); setNote(""); refresh(); } });
  const conflict = save.error instanceof ApiError && save.error.status === 409;
  return <li className={`fk-item ${item.status === "stopped" ? "stopped" : ""}`}>
    <div className="row wrap"><span className="tag">{KIND_KO[item.kind]}</span><b>{item.title}</b>
      <span className="small muted">{item.host} · {item.org_unit_id ? orgs[item.org_unit_id] || "관계사 지정" : "공통"} · v{item.version}</span>
      {item.status === "stopped" && <span className="tag">적용 중지</span>}
      {item.conflicts_with.length > 0 && <span className="tag bad" title="같은 범위에 다른 내용이 있어 어느 쪽도 적용하지 않습니다">상충 {item.conflicts_with.length}</span>}
      <div className="grow" /><button className="btn sm ghost" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? "접기" : "이력·수정"}</button></div>
    <div className="small mono">{describe(item, names)}</div>
    {open && <div className="col" style={{ gap: 8, marginTop: 6 }}>
      <input className="input" aria-label="변경 이유" placeholder="변경 이유(이력에 남습니다)" value={note} onChange={e => setNote(e.target.value)} />
      <div className="row wrap">
        {item.status === "active" ? <button className="btn sm" disabled={state.isPending} onClick={() => state.mutate("stop")}>적용 중지</button>
          : <button className="btn sm" disabled={state.isPending} onClick={() => state.mutate("restore")}>다시 적용</button>}
        <button className="btn sm" onClick={() => { setEditing(!editing); setText(JSON.stringify(item.content, null, 2)); }}>{editing ? "수정 닫기" : "내용 수정"}</button></div>
      <ErrorBox error={state.error} /><ErrorBox error={restore.error} />
      {editing && <div className="col" style={{ gap: 6 }}>
        <textarea className="input mono" aria-label="지식 내용" rows={Math.min(18, text.split("\n").length + 1)} value={text} onChange={e => setText(e.target.value)} />
        <p className="small muted">조사 화면의 "기억하기"로 만든 내용을 여기서 직접 고칠 수 있습니다. 저장하면 새 버전이 되고 이전 버전은 이력에 남습니다.</p>
        {conflict ? <div className="error small" role="alert">{(save.error as ApiError).detail}
          <div className="row"><button className="btn sm" onClick={() => save.mutate(true)}>상충 상태로 저장</button></div></div> : <ErrorBox error={save.error} />}
        <div className="row"><button className="btn sm primary" disabled={save.isPending} onClick={() => { try { JSON.parse(text); save.mutate(false); } catch { alert("내용 형식(JSON)이 올바르지 않습니다."); } }}>새 버전으로 저장</button></div></div>}
      {affected.data?.investigations.length > 0 && <div className="small"><b>이 지식의 영향을 받는 진행 중 조사 {affected.data.investigations.length}건</b>
        {affected.data.investigations.slice(0, 10).map((i: any) => <div key={i.investigation_id}><Link to={`/inv/${i.investigation_id}?tab=flows`}>{i.display_id} {i.title}</Link>
          {i.applied_version !== i.current_version ? <span className="tag warn">v{i.applied_version ?? "미적용"} 적용 중 → 다시 분석 필요</span> : <span className="muted"> 최신 버전 적용</span>}</div>)}</div>}
      {history.isLoading ? <Loading /> : <div className="small"><b>변경 이력</b>{(history.data?.versions || []).map((v: any) => <div key={v.version} className="fk-version">
        <span>v{v.version}</span><span className="muted">{fmtTime(v.created_at)} · {v.changed_by}</span><span>{v.status === "stopped" ? "적용 중지" : v.change_note || (v.version === 1 ? "처음 등록" : "수정")}</span>
        {v.evidence?.investigation_id && <Link to={`/inv/${v.evidence.investigation_id}?tab=flows`}>근거 조사</Link>}
        {v.version !== item.version && <button className="btn ghost sm" disabled={restore.isPending} onClick={() => restore.mutate(v.version)}>이 버전 내용으로 복원</button>}</div>)}</div>}
    </div>}
  </li>;
}

/** The knowledge analysts saved from the logs: meanings, link criteria and flows, with every version kept. */
export function FlowKnowledge() {
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("");
  const list = useQuery({ queryKey: ["flow-items", kind, q], queryFn: () => api.get(`/knowledge/flow-items?${kind ? `kind=${kind}&` : ""}q=${encodeURIComponent(q)}`) });
  const orgList = useQuery({ queryKey: ["org-units"], queryFn: () => api.get("/source-context/org-units"), retry: false });
  const items: any[] = list.data?.items || [];
  const names = Object.fromEntries(items.filter(i => i.kind === "activity").map(i => [i.id, i.content.meaning]));
  const orgs = Object.fromEntries(((orgList.data?.items || orgList.data || []) as any[]).map((o: any) => [o.id, o.display_name]));
  const hosts = [...new Set(items.map(i => i.host))];
  return <div className="col">
    <Panel title="업무 의미·흐름">
      <p className="small muted">분석가가 로그를 보며 저장한 지식입니다. 다음 자료부터 자동으로 적용되고, 고치거나 중지해도 이전 버전과 이미 끝난 분석 결과는 그대로 남습니다. 새로 등록하려면 조사 화면의 "업무 흐름" 또는 기록 상세에서 "메모하고 기억하기"를 누르세요.</p>
      <div className="row wrap"><input className="input" type="search" aria-label="지식 찾기" placeholder="서비스·경로·의미" value={q} onChange={e => setQ(e.target.value)} />
        <select className="input" aria-label="종류" value={kind} onChange={e => setKind(e.target.value)}><option value="">전체 종류</option>{Object.entries(KIND_KO).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
        <span className="small muted" role="status">{items.length}건 · 서비스 {hosts.length}개</span></div>
      {list.isLoading && <Loading />}<ErrorBox error={list.error} />
      {!list.isLoading && !items.length && <p>등록된 지식이 없습니다.</p>}
    </Panel>
    {hosts.map(host => <Panel key={host} title={host}><ul className="fk-flows">{items.filter(i => i.host === host).map(i => <Item key={i.id} item={i} names={names} orgs={orgs} />)}</ul></Panel>)}
  </div>;
}
