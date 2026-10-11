import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, EmptyState, PageHeader } from "../components/ui";

const STATUS_KO: Record<string, string> = { new: "신규", in_progress: "분석 중", closed: "종결", open: "진행 중" };
const VERDICT_KO: Record<string, string> = { attack: "공격", normal: "정상", false_positive: "오탐", unknown: "판단 불가" };
const KIND_KO: Record<string, string> = { web_log: "웹 로그", waf_log: "WAF", pcap: "PCAP", ioc_list: "IOC", sec_log: "보안 로그", fw_log: "방화벽",
  db_audit: "DB 감사", paste: "붙여넣기", auto: "자동" };
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ErrorBox, Loading, Sev } from "../components/common";
import { api } from "../lib/api";
import { fmtBytes, fmtTime } from "../lib/format";

export function Investigations() {
  const q = useQuery({ queryKey: ["investigations"], queryFn: () => api.get("/investigations") });
  const [title, setTitle] = useState("");
  const nav = useNavigate();
  const qc = useQueryClient();
  const create = useMutation({ mutationFn: () => api.post("/investigations", { title }), onSuccess: (i) => { qc.invalidateQueries({ queryKey: ["investigations"] }); nav(`/inv/${i.id}`); } });
  return (
    <div className="page col">
      <PageHeader eyebrow="조사" title="조사 목록" desc="증거를 묶어 분석하는 단위입니다. 위험도와 상태를 확인하고 작업대로 이동하세요." />
      <div className="panel">
        <div className="ph"><span className="grow">조사 {(q.data || []).length}건</span>
          <input className="input" style={{ width: 300 }} placeholder="새 조사 제목 (예: 고객 API 대량 조회 의심)" value={title} onChange={(e) => setTitle(e.target.value)} />
          <button className="btn primary sm" disabled={!title.trim()} onClick={() => create.mutate()}>새 조사 만들기</button></div>
        <ErrorBox error={create.error || q.error} />
        {q.isLoading ? <Loading /> : (
          <table className="t"><thead><tr><th>위험도</th><th>ID</th><th>제목</th><th>상태</th><th>증거</th><th>관측 기간</th><th>생성</th><th></th></tr></thead>
            <tbody>{(q.data || []).map((i: any) => (
              <tr key={i.id}><td><Sev level={i.risk_level} score={i.risk_score} /></td><td className="mono"><Link to={`/inv/${i.id}`}>{i.display_id}</Link></td>
                <td><Link to={`/inv/${i.id}`} style={{ color: "var(--fg)", fontWeight: 600 }}>{i.title}</Link></td>
                <td><Badge tone={i.status === "closed" ? undefined : "accent"}>{STATUS_KO[i.status] || i.status}{i.verdict ? ` · ${VERDICT_KO[i.verdict] || i.verdict}` : ""}</Badge></td>
                <td className="small">{i.evidence.map((e: any) => `${KIND_KO[e.kind] || e.kind} ${fmtBytes(e.size)}`).join(", ")}</td>
                <td className="small">{fmtTime(i.time_start)} ~ {fmtTime(i.time_end)}</td><td className="small">{fmtTime(i.created_at)}</td><td><Link className="btn sm" to={`/inv/${i.id}/report`}>보고용 요약</Link></td></tr>))}</tbody></table>
        )}
        {q.data?.length === 0 && <EmptyState title="아직 조사가 없습니다">홈에서 파일을 올리거나 위에서 새 조사를 만드세요.</EmptyState>}
      </div>
    </div>
  );
}
