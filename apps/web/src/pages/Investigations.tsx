import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMe } from "../App";
import { ErrorBox, Loading, Sev } from "../components/common";
import { Badge, EmptyState, PageHeader } from "../components/ui";
import { api } from "../lib/api";
import { fmtBytes, fmtTime } from "../lib/format";

const STATUS_KO: Record<string, string> = { new: "신규", in_progress: "분석 중", closed: "종결", open: "진행 중" };
const VERDICT_KO: Record<string, string> = { attack: "공격", normal: "정상", false_positive: "오탐", unknown: "판단 불가" };
const KIND_KO: Record<string, string> = { web_log: "웹 로그", waf_log: "WAF", pcap: "PCAP", ioc_list: "IOC", sec_log: "보안 로그", fw_log: "방화벽", db_audit: "DB 감사", paste: "붙여넣기", auto: "자동" };

export function Investigations() {
  const q = useQuery({ queryKey: ["investigations"], queryFn: () => api.get("/investigations") });
  const orgs = useQuery({ queryKey: ["org-units"], queryFn: () => api.get("/source-context/org-units") });
  const me = useMe();
  const [title, setTitle] = useState("");
  const [org, setOrg] = useState("");
  const [filter, setFilter] = useState("");
  const [orgName, setOrgName] = useState("");
  const nav = useNavigate();
  const qc = useQueryClient();
  const create = useMutation({ mutationFn: () => api.post("/investigations", { title, ...(org ? { org_unit_id: org } : {}) }), onSuccess: i => { qc.invalidateQueries({ queryKey: ["investigations"] }); nav(`/inv/${i.id}`); } });
  const createOrg = useMutation({ mutationFn: () => api.post("/source-context/org-units", { display_name: orgName.trim() }), onSuccess: o => { qc.setQueryData(["org-units"], (old: any) => [...(old || []), o]); setOrg(o.id); setOrgName(""); } });
  const rows = (q.data || []).filter((i: any) => !filter || (filter === "unassigned" ? !i.org_unit_id : i.org_unit_id === filter));
  return <div className="page col">
    <PageHeader eyebrow="조사" title="조사 목록" desc="관계사와 장비 로그만으로 시작할 수 있습니다. 서비스명과 의심 IP는 나중에 확인해도 됩니다." />
    <div className="panel">
      <div className="ph row wrap"><span className="grow">조사 {rows.length}건</span>
        <label>관계사 필터 <select className="input" value={filter} onChange={e => setFilter(e.target.value)}><option value="">전체</option><option value="unassigned">미분류</option>{(orgs.data || []).map((o: any) => <option key={o.id} value={o.id}>{o.display_name}</option>)}</select></label>
      </div>
      <div className="pb col">
        <div className="row wrap"><input className="input grow" placeholder="새 조사 제목 (예: 고객 API 대량 조회 의심)" value={title} onChange={e => setTitle(e.target.value)} />
          <label>새 조사 관계사 <select className="input" value={org} onChange={e => setOrg(e.target.value)}><option value="">미지정</option>{(orgs.data || []).map((o: any) => <option key={o.id} value={o.id}>{o.display_name}</option>)}</select></label>
          <button className="btn primary sm" disabled={!title.trim() || create.isPending} onClick={() => create.mutate()}>새 조사 만들기</button></div>
        {me.data?.permissions.includes("asset.write") && <div className="row wrap"><label>새 관계사 이름 <input className="input" maxLength={64} value={orgName} onChange={e => setOrgName(e.target.value)} /></label><button className="btn sm" disabled={!orgName.trim() || createOrg.isPending} onClick={() => createOrg.mutate()}>관계사 등록</button></div>}
        <p className="small muted">조사 관계사는 업무 분류입니다. 실제 관측 대상의 귀속은 업로드할 때 별도 근거로 확인합니다.</p>
      </div>
      <ErrorBox error={create.error || createOrg.error || q.error || orgs.error} />
      {q.isLoading ? <Loading /> : <div style={{ overflowX: "auto" }}><table className="t"><thead><tr><th>위험도</th><th>ID</th><th>제목</th><th>관계사</th><th>상태</th><th>증거</th><th>관측 기간</th><th>생성</th><th></th></tr></thead>
        <tbody>{rows.map((i: any) => <tr key={i.id}><td><Sev level={i.risk_level} score={i.risk_score} /></td><td className="mono"><Link to={`/inv/${i.id}`}>{i.display_id}</Link></td>
          <td><Link to={`/inv/${i.id}`} style={{ color: "var(--fg)", fontWeight: 600 }}>{i.title}</Link></td><td>{i.org_unit || "미분류"}</td>
          <td><Badge tone={i.status === "closed" ? undefined : "accent"}>{STATUS_KO[i.status] || i.status}{i.verdict ? ` · ${VERDICT_KO[i.verdict] || i.verdict}` : ""}</Badge></td>
          <td className="small">{i.evidence.map((e: any) => `${KIND_KO[e.kind] || e.kind} ${fmtBytes(e.size)}`).join(", ")}</td>
          <td className="small">{fmtTime(i.time_start)} ~ {fmtTime(i.time_end)}</td><td className="small">{fmtTime(i.created_at)}</td><td><Link className="btn sm" to={`/inv/${i.id}/report`}>보고용 요약</Link></td></tr>)}</tbody></table></div>}
      {!q.isLoading && !rows.length && <EmptyState title="표시할 조사가 없습니다">위에서 새 조사를 만들거나 관계사 필터를 바꾸세요.</EmptyState>}
    </div>
  </div>;
}
