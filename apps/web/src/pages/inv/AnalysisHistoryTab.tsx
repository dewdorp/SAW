import {ReportExportDialog} from "../../components/reports/ReportExportDialog";
import {ReportVersionsPanel} from "../../components/reports/ReportVersionsPanel";
import {eligibleRun} from "../../components/reports/types";
import { DeviceObservationResults } from "./DeviceObservationResults";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ErrorBox, Loading } from "../../components/common";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtNum, fmtTime } from "../../lib/format";

const STATUS: Record<string, string> = { complete: "완료", limited: "한도 도달", completed: "완료", completed_match: "완료·후보 있음", completed_no_match: "완료·조건 적중 없음", running: "실행 중", failed: "실패", cancelled: "취소", not_applicable: "적용 불가", insufficient_data: "자료 부족", partial: "일부 처리", skipped: "미실행" };
const COUNT_LABELS: Record<string, string> = { records: "기록", sessions: "세션", new_connections: "시작 기록이 있는 접속", deny_attempts: "거부 시도", unresolved_records: "의미 미확정 기록", omitted_sessions: "표시 생략 세션", omitted_candidates: "표시 생략 후보", candidates: "SAW 후보" };
const TERMINAL = ["COMPLETED", "FAILED", "CANCELLED"];
const CANDIDATE_LABELS: Record<string, string> = { scan: "탐색", beacon: "접속 시작 기록의 주기성", transfer_asymmetry: "전송 비대칭", long_flow: "장기 연결", asymmetric_transfer: "전송 비대칭", long_connection: "장기 연결", deny_to_allow: "거부 후 허용" };
const METRIC_LABELS: Record<string, string> = { src_to_dst_bytes: "출발지 → 목적지 (바이트)", dst_to_src_bytes: "목적지 → 출발지 (바이트)", duration_seconds: "지속시간 (초)", unique_destinations: "서로 다른 목적지", unique_ports: "서로 다른 포트", src_ip: "출발지 IP", dst_ip: "목적지 IP", ratio: "방향별 전송량 비율", window_seconds: "시간창 (초)", new_connections: "시작 기록이 있는 접속", mean_interval_seconds: "평균 간격 (초)", cv: "간격 변동계수" };
const hasCounts = (status: string) => ["complete", "completed", "completed_match", "completed_no_match", "partial", "limited"].includes(status);
const count = (v: any) => typeof v === "number" ? fmtNum(v) : "미확인";
const eventIds = (refs: any[]) => [...new Set((refs || []).map(r => typeof r === "string" ? r : r.event_id).filter((x): x is string => typeof x === "string" && !!x))];

export function AnalysisHistoryTab({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const qc = useQueryClient();
  const [analysisOrg, setAnalysisOrg] = useState("");
  const [analysisDevice, setAnalysisDevice] = useState("");
  const [useFilters, setUseFilters] = useState(true);
  const [jobId, setJobId] = useState("");
  const orgs = useQuery({ queryKey: ["org-units"], queryFn: () => api.get("/source-context/org-units") });
  const devices = useQuery({ queryKey: ["source-devices", inv], queryFn: () => api.get(`/source-context/investigations/${inv}/devices`) });
  const launch = useMutation({ mutationFn: () => api.post(`/investigations/${inv}/analysis-runs`, { ...(analysisOrg ? { org_unit_id: analysisOrg } : {}), ...(analysisDevice ? { device_id: analysisDevice } : {}), filters: useFilters ? ctx.filters : [], time: useFilters ? ctx.time : null }), onSuccess: job => setJobId(job.id) });
  const job = useQuery({ queryKey: ["job", jobId], queryFn: () => api.get(`/jobs/${jobId}`), enabled: !!jobId, refetchInterval: q => TERMINAL.includes(q.state.data?.state) ? false : 2000 });
  useEffect(() => {
    if (TERMINAL.includes(job.data?.state)) { qc.invalidateQueries({ queryKey: ["analysis-runs", inv] }); qc.invalidateQueries({ queryKey: ["analysis-run", inv] }); qc.invalidateQueries({ queryKey: ["inv", inv] }); }
  }, [job.data?.state, inv, qc]);
  const [selected, setSelected] = useState("");
  const [before, setBefore] = useState<number | null>(null);
  const [older, setOlder] = useState<any[]>([]);
  const [pageError, setPageError] = useState<unknown>(null);
  const [paging, setPaging] = useState(false);
  const [exporting,setExporting]=useState(false);
  const [saved, setSaved] = useState<any>(null);
  const [showNotApplicable, setShowNotApplicable] = useState(false);
  const list = useQuery({ queryKey: ["analysis-runs", inv], queryFn: () => api.get(`/investigations/${inv}/analysis-runs`), refetchInterval: 10000 });
  const runs = [...(list.data?.runs || []), ...older].filter((r, index, all) => all.findIndex(x => x.id === r.id) === index);
  const runId = selected || runs[0]?.id;
  const detail = useQuery({ queryKey: ["analysis-run", inv, runId], queryFn: () => api.get(`/investigations/${inv}/analysis-runs/${runId}`), enabled: !!runId, refetchInterval: q => q.state.data?.status === "running" ? 2000 : false });
  const report = useMutation({ mutationFn: () => api.post(`/investigations/${inv}/report-versions`, { analysis_run_id: runId }), onSuccess: r => { setSaved(r); qc.invalidateQueries({ queryKey: ["report-versions", inv] }); } });
  const next = before === null ? list.data?.next_before_version : before;
  const more = async () => {
    setPaging(true); setPageError(null);
    try { const page = await api.get(`/investigations/${inv}/analysis-runs?before_version=${next}`); setOlder(old => [...old, ...page.runs]); setBefore(page.next_before_version ?? 0); }
    catch (e) { setPageError(e); } finally { setPaging(false); }
  };
  const raw = (refs: any[]) => { const ids = eventIds(refs); if (ids.length) ctx.set({ tab: "raw", time: null, selection: null, eventId: null, filters: [{ field: "event_id", op: "in", value: ids }] }); };
  const run = detail.data;
  const executions = run?.executions || [];
  const notApplicable = executions.filter((item: any) => item.status === "not_applicable").length;
  const visibleExecutions = executions.filter((item: any) => showNotApplicable || item.status !== "not_applicable");
  return <div className="col" style={{ gap: 16 }}><div><h3>분석 실행 이력</h3><p className="muted">저장된 실행 범위와 근거를 봅니다. 현재 화면 필터는 과거 실행을 다시 계산하지 않습니다. 관측 후보와 분석가 판단·확인 기록은 별도로 유지합니다.</p></div>
    <ErrorBox error={list.error || detail.error || report.error || pageError || orgs.error || devices.error || launch.error || job.error} />
    <section className="panel pb col"><h4>새 장비 분석 실행</h4><p className="small muted">서버에서 새 실행을 만듭니다. 서비스명·의심 IP 없이 관계사와 장비를 선택할 수 있습니다. 미확인 귀속 기록은 자동으로 선택 관계사에 합치지 않습니다.</p>
      <div className="row wrap"><label>분석 관계사 <select className="input" value={analysisOrg} onChange={e => setAnalysisOrg(e.target.value)}><option value="">조사 전체</option>{(orgs.data || []).map((o: any) => <option key={o.id} value={o.id}>{o.display_name}</option>)}</select></label><label>분석 장비 <select className="input" value={analysisDevice} onChange={e => setAnalysisDevice(e.target.value)}><option value="">장비 전체</option>{(devices.data || []).map((d: any) => <option key={d.id} value={d.id}>{d.display_name}</option>)}</select></label></div>
      <label><input type="checkbox" checked={useFilters} onChange={e => setUseFilters(e.target.checked)} />현재 화면 필터·기간을 서버 실행 범위에 적용</label><div className="small muted">적용할 화면 필터 {useFilters ? ctx.filters.length : 0}개 · 기간 {useFilters && ctx.time ? `${fmtTime(ctx.time.start)} ~ ${fmtTime(ctx.time.end)}` : "전체"}</div>
      <button className="btn primary" disabled={launch.isPending || (!!jobId && !!job.data && !TERMINAL.includes(job.data.state))} onClick={() => launch.mutate()}>선택 범위로 장비 분석 실행</button>
      {jobId && <div role="status"><Link className="btn sm" to={`/jobs/${jobId}`}>분석 작업 보기</Link> · {({ COMPLETED: "완료", FAILED: "실패", CANCELLED: "취소", ANALYZING: "분석 중", QUEUED: "대기" } as Record<string, string>)[job.data?.state] || "진행 상태 확인 중"}{typeof job.data?.events_done === "number" && ` · 처리 ${count(job.data.events_done)}건`}</div>}
    </section>
    {list.isLoading ? <Loading /> : !runs.length ? <p>저장된 분석 실행이 없습니다. 작업대에서 분석을 실행하세요. 과거 결과는 만들어 채우지 않습니다.</p> : <>
      <div className="row wrap"><label>분석 실행 선택 <select className="input" value={runId} onChange={e => { setSelected(e.target.value); setSaved(null); }}>{runs.map((r: any) => <option key={r.id} value={r.id}>v{r.version} · {STATUS[r.status] || r.status} · {fmtTime(r.created_at)}</option>)}</select></label>{!!next && <button className="btn" disabled={paging} onClick={more}>이전 분석 더 보기</button>}</div>
      {detail.isLoading ? <Loading /> : run && <>
        <div className="small">실행 v{run.version} · {STATUS[run.status] || run.status} · 입력 SHA256 <span className="mono">{run.input_sha256 || "미기록"}</span></div>
        <details><summary>고정된 분석 범위·요약</summary><pre style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify({ scope: run.scope, summary: run.summary }, null, 2)}</pre></details>
        {executions.filter((item: any) => item.detector_id === "fw.observation").map((execution: any) => <section key={execution.detector_id} className="panel pb col" style={{ gap: 12 }}><h4>FW 관측 결과 · {STATUS[execution.status] || execution.status}</h4>
          {execution.detail && <>
            <table className="t"><caption>FW 관측 단위별 집계</caption><thead><tr><th>구분</th><th>건수</th></tr></thead><tbody>{Object.entries(COUNT_LABELS).map(([key, label]) => <tr key={key}><th>{label}</th><td>{hasCounts(execution.status) ? count(execution.detail.counts?.[key]) : "미확인"}</td></tr>)}</tbody></table>
            <p className="small muted">시작 기록이 있는 접속은 성공한 연결·핸드셰이크를 뜻하지 않습니다. 기록 수와 세션 수를 구분하며, 원천 방향은 내부/외부 방향이나 침해를 확정하지 않습니다.</p>
            <div className="row wrap small"><span>계산 범위: {execution.detail.limits?.coverage_complete === true ? "설정 범위 처리 완료" : execution.detail.limits?.coverage_complete === false ? "일부 처리·한도 확인 필요" : "미확인"}</span><span>기록 상한 {count(execution.detail.limits?.max_records)}</span><span>결과 표시 상한 {count(execution.detail.limits?.max_results)}</span><span>품질 확인 항목 {execution.detail.quality != null && typeof execution.detail.quality === "object" && !Array.isArray(execution.detail.quality) ? `${Object.keys(execution.detail.quality).length}개` : "미확인"}</span></div>
            <h4>우선 확인 후보</h4>{!(execution.detail.candidates || []).length && <p className="small">저장된 후보가 없습니다. 적용 상태·자료 품질·한계를 함께 확인하세요.</p>}
            {(execution.detail.candidates || []).map((candidate: any, index: number) => <article key={index} className="panel pb col" style={{ gap: 8 }}><b>{CANDIDATE_LABELS[candidate.kind] || candidate.kind} 후보</b><div className="small muted">관측 조건에 해당하는 확인 후보입니다. 연결 성공이나 피해를 확정하지 않습니다.</div>
              <dl className="row wrap" style={{ margin: 0, gap: 20 }}>{Object.entries(candidate.metrics || {}).filter(([key]) => METRIC_LABELS[key]).map(([key, value]) => <div key={key}><dt className="small muted">{METRIC_LABELS[key]}</dt><dd style={{ margin: 0, fontWeight: 600 }}>{typeof value === "number" ? count(value) : String(value ?? "미확인")}</dd></div>)}</dl>
              <div className="row wrap"><span className="small">선택 근거 {eventIds(candidate.event_refs).length}건</span><button className="btn sm" disabled={!eventIds(candidate.event_refs).length} onClick={() => raw(candidate.event_refs)}>후보 {index + 1} 근거 원문</button></div>
              <details><summary>후보 구조 상세</summary><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{JSON.stringify(candidate, null, 2)}</pre></details>
            </article>)}
            <table className="t"><caption>세션별 방향 카운터</caption><thead><tr><th>세션</th><th>src→dst 바이트</th><th>dst→src 바이트</th><th>지속시간(초)</th><th>근거</th></tr></thead><tbody>{(execution.detail.sessions || []).map((session: any, index: number) => <tr key={index}><td>{session.session_id || index + 1}</td><td>{count(session.src_to_dst_bytes)}</td><td>{count(session.dst_to_src_bytes)}</td><td>{count(session.duration_seconds)}</td><td><button className="btn sm" disabled={!eventIds(session.event_refs).length} onClick={() => raw(session.event_refs)}>세션 {index + 1} 근거 원문</button>{session.omitted_event_refs > 0 && <span> 참조 {count(session.omitted_event_refs)}건 생략</span>}</td></tr>)}</tbody></table>
          </>}
          <details><summary>품질·계산 한도·적용 기준·미실행 사유</summary><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{JSON.stringify({ detail: execution.detail, effective_config: execution.effective_config }, null, 2)}</pre></details>
        </section>)}
        {executions.filter((item:any)=>["waf.observation","ips.observation","ddos.observation","ndr.observation"].includes(item.detector_id)).map((execution:any)=><DeviceObservationResults key={execution.detector_id} execution={execution} status={STATUS[execution.status]||execution.status} onRaw={raw}/>)}
        {!!notApplicable && <button className="btn sm" aria-expanded={showNotApplicable} onClick={() => setShowNotApplicable(!showNotApplicable)}>{showNotApplicable ? `적용 불가 탐지기 ${notApplicable}개 숨기기` : `적용 불가 탐지기 ${notApplicable}개 보기`}</button>}
        <table className="t"><caption>탐지기 실행 상태 — 미실행·실패·자료 부족은 0건으로 해석하지 않습니다</caption><thead><tr><th>탐지기</th><th>버전</th><th>상태</th><th>입력</th><th>후보</th></tr></thead><tbody>{visibleExecutions.map((execution: any) => <tr key={execution.detector_id}><td>{execution.detector_id}</td><td>{execution.detector_version || "미기록"}</td><td>{STATUS[execution.status] || execution.status}</td><td>{hasCounts(execution.status) ? count(execution.input_count) : "미확인"}</td><td>{hasCounts(execution.status) ? count(execution.match_count) : "미확인"}</td></tr>)}</tbody></table>
        {visibleExecutions.filter((item: any) => !["fw.observation","waf.observation","ips.observation","ddos.observation","ndr.observation"].includes(item.detector_id)).map((execution: any) => <details key={execution.detector_id} className="panel pb"><summary>{execution.detector_id} · {STATUS[execution.status] || execution.status} · 실행 근거</summary><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{JSON.stringify({ detail: execution.detail, effective_config: execution.effective_config }, null, 2)}</pre></details>)}        {!!run.findings?.length && <details><summary>이 실행에 고정된 탐지 스냅샷 {run.findings.length}건</summary>{run.findings.map((f: any) => <pre key={f.id} style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(f, null, 2)}</pre>)}</details>}
        <div className="row wrap"><button className="btn primary" disabled={report.isPending || !eligibleRun(run)} onClick={() => report.mutate()}>선택 실행 HTML 보고서 저장</button><button className="btn" disabled={!eligibleRun(run)} onClick={()=>setExporting(true)}>선택 실행 HTML·Excel 내보내기</button><button className="btn" onClick={() => ctx.set({ tab: "checks" })}>분석가 확인·판단 기록</button></div>
      </>}
    </>}
    <ReportVersionsPanel inv={inv} extra={saved}/>
    {exporting&&<ReportExportDialog scope={{kind:"investigation",selections:[{investigation_id:inv,analysis_run_id:runId,followup_version_ids:null}]}} onClose={()=>setExporting(false)}/>}
  </div>;
}
