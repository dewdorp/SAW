import { useMe } from "../App";
import { principalKey } from "./golden/types";
import { GoldenExportJob } from "./golden/GoldenExportJob";
import {ReportExportJob} from "../components/reports/ReportExportJob";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PageHeader } from "../components/ui";
import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Bar, ErrorBox, Loading, Panel } from "../components/common";
import { api, ApiError } from "../lib/api";
import { fmtBytes, fmtNum, fmtTime } from "../lib/format";

export function Jobs() {
  const me=useMe();
  const q = useQuery({ queryKey: ["jobs",principalKey(me.data)], enabled:!!me.data, queryFn: () => api.get("/jobs"), refetchInterval: 5000 });
  if(me.isLoading||q.isLoading)return <Loading/>;if(me.error||q.error)return <ErrorBox error={me.error||q.error}/>;
  return (
    <div className="page col">
      <PageHeader eyebrow="처리" title="작업 상태" desc="업로드한 증거의 압축 해제 → 파싱 → 색인 → 분석 진행 상황입니다." />
      <b>JOBS</b>
      {q.isLoading ? <Loading /> : (
        <table className="t"><thead><tr><th>Job</th><th>Kind</th><th>State</th><th>Events</th><th>Current</th><th>Created</th><th>Finished</th></tr></thead>
          <tbody>{(q.data || []).map((j: any) => (
            <tr key={j.id}><td className="mono"><Link to={`/jobs/${j.id}`}>#{j.id.slice(0, 8)}</Link></td><td>{j.kind}</td><td><span className="tag">{j.state}</span></td>
              <td className="num">{fmtNum(j.events_done)}</td><td className="ellipsis small" style={{ maxWidth: 260 }}>{j.current_item}</td><td className="small">{fmtTime(j.created_at)}</td><td className="small">{fmtTime(j.finished_at)}</td></tr>))}</tbody></table>
      )}
    </div>
  );
}

const STAGES = ["upload", "extract", "parse", "index", "analyze"];
const STAGE_LABEL: Record<string, string> = { upload: "업로드", extract: "압축 해제", parse: "파싱", index: "색인", analyze: "분석" };
const STATE_LABEL: Record<string, string> = { QUEUED: "대기", PARSING: "파싱 중", INDEXING: "색인 중", ANALYZING: "분석 중",
  WAITING_INPUT: "확인 필요", COMPLETED: "완료", FAILED: "실패", CANCELLED: "취소됨" };

export function fmtEta(sec?: number | null): string {
  if (sec === undefined || sec === null || sec < 0) return "";
  if (sec < 60) return "1분 이내";
  const m = Math.round(sec / 60);
  return m < 60 ? `약 ${m}분 남음` : `약 ${Math.floor(m / 60)}시간 ${m % 60}분 남음`;
}

/** Job progress with SSE (docs/10 §6, wireframe 15). */
export function JobDetail() {
  const me=useMe();const {id=""}=useParams();
  if(me.isLoading)return <Loading/>;if(me.error)return <ErrorBox error={me.error}/>;
  const principal=principalKey(me.data);
  return <JobDetailContent key={principal+":"+id} principal={principal}/>;
}
function JobDetailContent({principal}:{principal:string}) {
  const { id = "" } = useParams();
  const navigate=useNavigate();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["job", id,principal], queryFn: () => api.get(`/jobs/${id}`), refetchInterval: (qq) => (["COMPLETED", "FAILED", "CANCELLED"].includes((qq.state.data as any)?.state) ? false : 2000) });
  useEffect(()=>{if(q.error instanceof ApiError&&[403,404].includes(q.error.status)){setLive(null);qc.removeQueries({queryKey:["job",id,principal],exact:true});}},[q.error,id,principal,qc]);
  const [live, setLive] = useState<any | null>(null);
  const parsers = useQuery({ queryKey: ["parsers"], enabled: !!q.data && !["report_export", "golden_export"].includes(q.data.kind), queryFn: () => api.get("/parsers") });
  useEffect(() => {
    const es = new EventSource(`/api/v1/jobs/${id}/events`);
    es.addEventListener("progress", (e) => setLive(JSON.parse((e as MessageEvent).data)));
    es.addEventListener("end", () => { es.close(); qc.invalidateQueries({ queryKey: ["job", id,principal] }); });
    es.onerror = () => es.close();
    return () => es.close();
  }, [id, principal, qc]);
  const cancel = useMutation({ mutationFn: () => api.post(`/jobs/${id}/cancel`), onSuccess: () => qc.invalidateQueries({ queryKey: ["job", id,principal] }) });
  const retry = useMutation({ mutationFn: () => api.post(`/jobs/${id}/retry`), onSuccess: () => qc.invalidateQueries({ queryKey: ["job", id,principal] }) });
  const setParser = useMutation({ mutationFn: ({ fid, pid }: { fid: string; pid: string }) => api.post(`/evidence/${q.data.evidence_id}/files/${fid}/parser`, { parser_id: pid }), onSuccess: (result) => { qc.invalidateQueries({ queryKey: ["job", id,principal] }); qc.invalidateQueries({ queryKey: ["jobs"] }); if (result.job_id) navigate("/jobs/" + encodeURIComponent(result.job_id)); } });
  if (q.isLoading) return <Loading />;
  if (q.error) return <div className="page"><ErrorBox error={q.error} /></div>;
  if(q.data.kind === "report_export") return <div className="page col"><ReportExportJob id={id} initial={q.data} onRetry={job=>navigate(`/jobs/${job.id}`)}/></div>;
  if(q.data.kind === "golden_export") return <div className="page col"><GoldenExportJob key={id} id={id} initial={q.data} initialPrincipal={principal} onRetry={job=>navigate(`/jobs/${job.id}`)}/></div>;
  const j = { ...q.data, ...(live || {}) };
  const files = q.data.files || [];
  const leaves = files.filter((f: any) => !files.some((c: any) => c.parent_file_id === f.id));
  const waiting = leaves.filter((f: any) => f.status === "waiting_input");
  const total = files.filter((f: any) => !f.parent_file_id).reduce((a: number, f: any) => a + f.size, 0);
  return (
    <div className="page col" style={{ maxWidth: 1100 }}>
      <div className="row wrap"><b>처리 작업 #{id.slice(0, 8)}</b><span className="tag">● {STATE_LABEL[j.state] || j.state}</span><span className="muted small">{fmtTime(j.started_at || j.created_at)}</span>
        <Link to={`/inv/${j.investigation_id}`}>조사 열기 →</Link><div className="grow" />
        {!["COMPLETED", "FAILED", "CANCELLED"].includes(j.state) && <button className="btn sm" onClick={() => cancel.mutate()}>취소</button>}
        {["FAILED", "COMPLETED"].includes(j.state) && files.some((f: any) => f.status === "failed") && <button className="btn sm" onClick={() => retry.mutate()}>실패한 파일 다시 처리</button>}
      </div>
      <div className="row small wrap"><span>파일 {files.filter((f: any) => !f.parent_file_id).length}개 · {fmtBytes(total)}</span>
        <span>이벤트 {fmtNum(j.events_done)}{j.events_total_est ? ` / 약 ${fmtNum(j.events_total_est)}` : ""}</span>
        {j.stages?.parse?.eps && <span>초당 {fmtNum(j.stages.parse.eps)}건</span>}
        {!j.stages?.parse?.done && j.stages?.parse?.eta_sec != null && <b>{fmtEta(j.stages.parse.eta_sec)}</b>}
        <span className="muted">현재: {j.current_item || "–"}</span></div>
      {j.state === "ANALYZING" && <div className="notice small">색인이 끝나 조사 화면에서 검색·원본 보기를 바로 할 수 있습니다. 탐지 분석은 뒤에서 계속 진행됩니다.</div>}
      <Panel title="단계">
        {j.kind === "reprocess" && <p className="muted small">보관된 원본으로 다시 처리합니다. 업로드와 압축 해제는 반복하지 않습니다.</p>}
        {(j.kind === "reprocess" ? STAGES.slice(2) : STAGES).map((s) => {
          const st = j.stages?.[s] || {};
          const p = st.done ? 100 : st.pct ?? 0;
          return <div key={s} className="row small"><span style={{ width: 70 }}>{STAGE_LABEL[s]}</span><div className="grow"><Bar value={p} max={100} /></div><span style={{ width: 70 }}>{st.done ? "✓" : st.pct !== undefined && st.pct !== null ? `${p}%` : "대기"}</span></div>;
        })}
      </Panel>
      {j.error?.message && <div className="error">⚠ {j.error.message}</div>}
      {waiting.length > 0 && (
        <Panel title="⚠ 확인 필요 — 이 파일의 형식을 골라 주세요">
          {waiting.map((f: any) => {
            const cands = f.error_samples?.[0]?.candidates || [];
            return (
              <div key={f.id} className="row wrap small"><span className="mono">{f.name}</span><span className="muted">자동 판별 확신도 {f.parser_confidence}</span>
                {cands.map((c: any) => <button key={c.parser_id} className="btn sm" onClick={() => setParser.mutate({ fid: f.id, pid: c.parser_id })}>{c.parser_id} {c.confidence}</button>)}
                <ParserSelect parsers={parsers.data} label="다른 파서…" onPick={(pid) => setParser.mutate({ fid: f.id, pid })} />
                <Link className="btn sm primary" to={`/parsers/new?ev=${q.data.evidence_id}&file=${f.id}&job=${id}`}>새 파서 만들기</Link>
              </div>
            );
          })}
          <ErrorBox error={setParser.error} />
        </Panel>
      )}
      {j.state === "COMPLETED" && leaves.some((f: any) => f.type === "text" && f.parser_id && f.parser_id !== "ioc_list") && (
        <Panel title="다른 파서로 다시 처리">
          <div className="muted small">형식이 제대로 해석되지 않았다면 다른 파서를 고르거나 새로 만들어 이 증거를 다시 처리하세요. 기존 결과와 분석 이력은 보존합니다. 새 결과 저장을 확인하면 최신 결과로 전환합니다. 전환 전 실패하거나 취소되면 기존 결과를 유지합니다. 전환 후 탐지 분석만 실패하거나 취소될 수 있으며, 이때 저장된 새 결과는 유지됩니다.</div>
          {leaves.filter((f: any) => f.type === "text" && f.parser_id && f.parser_id !== "ioc_list").map((f: any) => (
            <div key={f.id} className="row wrap small"><span className="mono">{f.name}</span><span className="muted">현재: {f.parser_id}</span>
              <ParserSelect parsers={parsers.data} label="다시 처리할 파서…" onPick={(pid) => setParser.mutate({ fid: f.id, pid })} />
              <Link className="btn sm" to={`/parsers/new?ev=${q.data.evidence_id}&file=${f.id}&job=${id}`}>새 파서 만들기</Link>
            </div>))}
          <ErrorBox error={setParser.error} />
        </Panel>
      )}
      <Panel title="파일">
        <table className="t"><thead><tr><th>파일</th><th>크기</th><th>형식</th><th>파서</th><th>상태</th><th className="num">이벤트</th><th className="num">실패</th><th>메시지</th></tr></thead>
          <tbody>{files.map((f: any) => (
            <tr key={f.id}><td className="mono ellipsis" style={{ maxWidth: 300 }}>{f.parent_file_id ? "  └ " : ""}{f.name}</td><td>{fmtBytes(f.size)}</td><td>{f.type}</td><td>{f.parser_id || "?"}</td>
              <td>{f.status === "done" ? "✓ 완료" : f.status === "failed" ? "✗ 실패" : f.status === "degraded" ? "⚠ 일부 실패" : f.status}</td><td className="num">{fmtNum(f.events_parsed)}</td><td className="num">{fmtNum(f.events_failed)}</td><td className="small ellipsis" style={{ maxWidth: 280 }}>{f.message}</td></tr>))}</tbody></table>
      </Panel>
      {leaves.some((f: any) => f.coverage) && (
        <Panel title="처리 범위 — 파일의 모든 줄이 어디로 갔는지">
          <table className="t"><thead><tr><th>파일</th><th className="num">전체 줄</th><th className="num">이벤트</th><th className="num">이어진 줄</th><th className="num">머리글·합쳐진 줄</th><th className="num">빈 줄</th><th className="num">실패</th><th className="num">저장 거부</th><th className="num">분석 비율</th></tr></thead>
            <tbody>{leaves.filter((f: any) => f.coverage).map((f: any) => {
              const c = f.coverage;
              const used = c.lines ? (c.events + c.continuation_lines + c.skipped_lines) / Math.max(1, c.lines - c.blank_lines) : 0;
              return <tr key={f.id}><td className="mono ellipsis" style={{ maxWidth: 260 }}>{f.name}</td><td className="num">{fmtNum(c.lines)}</td><td className="num">{fmtNum(c.events)}</td>
                <td className="num">{fmtNum(c.continuation_lines || 0)}</td><td className="num">{fmtNum(c.skipped_lines)}</td><td className="num">{fmtNum(c.blank_lines)}</td>
                <td className="num">{c.failed_lines ? <b style={{ color: "var(--bad)" }}>{fmtNum(c.failed_lines)}</b> : 0}</td>
                <td className="num">{c.rejected_events ? <b style={{ color: "var(--bad)" }}>{fmtNum(c.rejected_events)}</b> : 0}</td><td className="num">{(used * 100).toFixed(used < 1 ? 2 : 0)}%</td></tr>;
            })}</tbody></table>
          <div className="muted small">머리글·합쳐진 줄: CSV 머리글, 요청 이벤트에 합쳐진 응답 행(NDR) 등. 실패한 줄은 아래 표본에서 원인을 확인하세요. 저장 거부: 읽기는 했지만 검색엔진이 받지 않아 검색·탐지에 포함되지 않은 이벤트입니다.</div>
        </Panel>
      )}
      {leaves.some((f: any) => f.events_failed > 0) && (
        <Panel title="실패한 줄 표본 (민감정보 가림)">
          {leaves.flatMap((f: any) => (f.events_failed ? (f.error_samples || []).filter((x: any) => x.line_no).slice(0, 10).map((x: any) => <div key={f.id + x.line_no} className="mono small">{f.name}:{x.line_no} {x.reason} — {x.raw}</div>) : []))}
        </Panel>
      )}
    </div>
  );
}

function ParserSelect({ parsers, label, onPick }: { parsers?: any[]; label: string; onPick: (pid: string) => void }) {
  return (
    <select className="input" value="" onChange={(e) => e.target.value && onPick(e.target.value)}>
      <option value="">{label}</option>
      {(parsers || []).map((p: any) => <option key={p.id} value={p.id}>{p.user ? `${p.name} (${p.id} v${p.version})${p.status === "active" ? "" : p.status === "pending" ? " · 승인 대기" : " · 내 초안"}` : p.id}</option>)}
    </select>
  );
}
