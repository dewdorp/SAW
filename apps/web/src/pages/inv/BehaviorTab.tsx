import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { CheckDialog, TargetChecks, type BehaviorResponse, type Target } from "../../components/Checks";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { useInv, type Filter, type TimeRange } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtNum, fmtTime } from "../../lib/format";
import { EChart, axisStyle, safeTooltip } from "../../viz/EChart";
import { RequestEvolution } from "../analyze/DiffPage";

type Scope = { filters: Filter[]; time: TimeRange; ips: string[]; role: "src" | "dst" | "either" };
type Window = { start: string; end_exclusive: string; src_ip?: string; service?: string };
type Metric = { id: string; label: string; window_seconds: number; value: number | null; data_state: string; result: string; window: Window | null;
  qualifying_window?: Window & { value: number; status404: number; evidence_ids: string[] }; status404_in_window?: number | null; required_status404?: number;
  reference_threshold: number; applied_threshold: number; excluded_count: number; eligible_count: number; partial_window: boolean; evidence_ids: string[] };
export type BehaviorResult = { id: string; version: number; job_id: string; created_at: string; created_by: string; result_sha256: string;
  result: { schema: string; scope: Scope; methodology: any; profile: any; source_manifest: any;
    observations: { summary: any; quality: any; metrics: Metric[]; timeline: any; indicators: any[]; followups: any[]; limits: any[]; execution: any };
    selected_evidence: { event_id: string; event: any; sha256: string; raw_sha256?: string }[] } };
const METRICS = [
  ["requests_10s", "요청 수", 30], ["paths_60s", "서로 다른 경로", 30], ["status404_60s", "404 응답", 15],
  ["repeats_60s", "반복 요청", 20], ["ua_600s", "서로 다른 UA", 2],
] as const;
const STATES: Record<string, string> = { conditional_code_derived: "코드에서 확인한 조건부 문자열", code_defined_unreachable: "설명된 버전에서 도달할 수 없는 코드 경로", existing_normalized_tags: "기존 정규화 태그 일치", available: "자료 있음", partial: "일부 자료", not_collected: "미수집", unknown: "알 수 없음",
  threshold_met: "기준 도달", below_threshold: "기준 미만", unavailable: "판단 자료 없음", insufficient_data: "자료 부족",
  observed: "관측", not_observed: "이번 자료에서 미관측", QUEUED: "대기", ANALYZING: "분석 중", COMPLETED: "완료", FAILED: "실패", CANCELLED: "취소됨", done: "완료", degraded: "일부 실패", failed: "실패", skipped: "건너뜀", pending: "대기", parsing: "처리 중" };
const QUALITY: Record<string, string> = { user_agent: "UA 필드", present: "값 기록됨", recorded_empty: "빈 값 기록됨", not_collected: "미수집", unknown: "알 수 없음",
  timestamp_precision: "원본 시각 정밀도", seconds: "초 단위", subseconds: "초 미만", source_counts: "자료 출처별 건수", duplicate_risk: "다중 센서 중복 가능성",
  coverage_label: "관측 기준", data_sources: "자료 출처", missing_timestamp: "시각 없음", missing_src_ip: "출발지 없음", timestamp_ties: "시각이 같은 기록", missing_service: "목적 서비스 없음", field_coverage: "필드별 기록 건수", categorical_unique_counts: "범주별 고유 값 수", multi_source_duplicate_risk: "다중 출처 중복 가능성", collection_continuity: "수집 연속성", field_denominator: "필드 관측 분모", producer_observation_denominator: "수집 당시 품질 분모", method: "메서드", uri: "원본 URI", status_code: "상태 코드", enforcement_action: "조치" };
const TERMINAL = ["COMPLETED", "FAILED", "CANCELLED"];
const display = (v: any): string => v == null ? "미수집 / 알 수 없음" : typeof v === "object" ? Array.isArray(v)
  ? v.map(display).join(" · ") : Object.entries(v).map(([key, value]) => `${QUALITY[key] || key}: ${display(value)}`).join(" · ") : typeof v === "boolean" ? (v ? "있음" : "없음") : STATES[String(v)] || String(v);

/** Keep the calculator's microsecond precision when selecting frozen chart samples. */
function isoMicros(value?: string): bigint | null {
  if (!value) return null;
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) return null;
  const fraction = /[T ]\d{2}:\d{2}:\d{2}[.,](\d+)/.exec(value)?.[1] || "";
  return BigInt(milliseconds) * 1000n + BigInt(fraction.padEnd(6, "0").slice(3, 6));
}

/** Saved observations remain independent of the current investigation query. */
export function BehaviorTab({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const qc = useQueryClient();
  const base = `/investigations/${inv}/behavior`;
  const [ipsText, setIpsText] = useState(ctx.selection?.type === "ip" ? ctx.selection.value : "");
  const [role, setRole] = useState<Scope["role"]>("src");
  const [thresholds, setThresholds] = useState<Record<string, number>>(() => Object.fromEntries(METRICS.map(([id, , value]) => [id, value])));
  const [excludeOptions, setExcludeOptions] = useState(true);
  const [suffixes, setSuffixes] = useState(".css,.js,.map,.png,.jpg,.jpeg,.gif,.svg,.ico,.woff,.woff2,.ttf,.eot");
  const [uaMin404, setUaMin404] = useState(2);
  const [deduplicate, setDeduplicate] = useState(false);
  const [selectedId, setSelectedId] = useState("");
  const [compareId, setCompareId] = useState("");
  const [jobId, setJobId] = useState("");
  const [selectedEvents, setSelectedEvents] = useState<string[]>([]);
  const [checkOpen, setCheckOpen] = useState(false);
  const [zoom, setZoom] = useState<[number, number] | null>(null);
  const [focus, setFocus] = useState<(Window & { evidence_ids?: string[] }) | null>(null);
  const ips = [...new Set(ipsText.split(/[\s,;]+/).filter(Boolean))];
  const validProfile = Object.values(thresholds).every(n => Number.isInteger(n) && n > 0 && n <= 100000) && Number.isInteger(uaMin404) && uaMin404 >= 1 && uaMin404 <= 100000;
  const versions = useQuery<{ results: any[] }>({ queryKey: ["behavior", inv], queryFn: () => api.get(base) });
  const results = versions.data?.results || [];
  const id = selectedId || results[0]?.id || "";
  const saved = useQuery<BehaviorResult>({ queryKey: ["behavior-result", inv, id], queryFn: () => api.get(`${base}/${id}`), enabled: !!id });
  const comparison = useQuery<BehaviorResult>({ queryKey: ["behavior-result", inv, compareId], queryFn: () => api.get(`${base}/${compareId}`), enabled: !!compareId && compareId !== id });
  const job = useQuery<any>({ queryKey: ["job", jobId], queryFn: () => api.get(`/jobs/${jobId}`), enabled: !!jobId,
    refetchInterval: q => TERMINAL.includes(q.state.data?.state) ? false : 2000 });
  const run = useMutation({ mutationFn: () => api.post(base, { filters: ctx.filters, time: ctx.time, ips, role,
    profile: { thresholds, ua_min_404: uaMin404, exclude_methods: excludeOptions ? ["OPTIONS"] : [],
      static_suffixes: suffixes.split(/[\s,;]+/).filter(Boolean), deduplicate_request_id: deduplicate } }),
    onSuccess: j => { setJobId(j.id); qc.setQueryData(["job", j.id], j); } });
  // A job is cancelled only from the investigation it belongs to.
  const cancel = useMutation({ mutationFn: async () => {
    if (job.data && job.data.investigation_id && job.data.investigation_id !== inv) throw new Error("이 작업은 현재 조사의 작업이 아닙니다.");
    return api.post(`/jobs/${jobId}/cancel`);
  }, onSuccess: () => qc.invalidateQueries({ queryKey: ["job", jobId] }) });
  useEffect(() => { setJobId(""); setSelectedId(""); setCompareId(""); }, [inv]);
  useEffect(() => {
    if (job.data?.state === "COMPLETED") {
      qc.invalidateQueries({ queryKey: ["behavior", inv] });
      setSelectedId(""); setCompareId("");
    }
  }, [job.data?.state, inv, qc]);
  useEffect(() => { setSelectedEvents([]); setZoom(null); setFocus(null); diff.reset(); }, [id]);
  const r = saved.data;
  const o = r?.result.observations;
  const evidence = r?.result.selected_evidence || [];
  const files = (r?.result.source_manifest?.evidence || []).flatMap((entry: any) =>
    (entry.files || []).map((file: any) => ({ ...file, evidence_id: entry.evidence_id, tz_assumed: entry.tz_assumed })));
  const evidenceIds = evidence.map(x => x.event_id);
  const buckets = o?.timeline?.buckets || [];
  const metrics = o?.metrics || [];
  const active = !!jobId && !TERMINAL.includes(job.data?.state || "QUEUED");
  const diff = useMutation({ mutationFn: () => api.post(`/investigations/${inv}/diff`, { ...r!.result.scope, event_ids: selectedEvents, behavior_result_id: r!.id, result_sha256: r!.result_sha256 }) });
  const raw = (ids: string[]) => {
    const savedIds = [...new Set(ids.filter(value => evidenceIds.includes(value)))];
    if (!r || !savedIds.length) return;
    // Saved scope fields may be masked. IDs already belong to that immutable scope.
    ctx.set({ tab: "raw", filters: [{ field: "event_id", op: "in", value: savedIds }], time: null, selection: null });
  };
  const focusStart = isoMicros(focus?.start);
  const focusEnd = isoMicros(focus?.end_exclusive);
  const focusedEvidenceIds = focus?.evidence_ids ?? evidence.filter(item => {
    const timestamp = isoMicros(item.event?.timestamp);
    return focusStart != null && focusEnd != null && timestamp != null && timestamp >= focusStart && timestamp < focusEnd;
  }).map(item => item.event_id);
  const peak = (window: Window, ids: string[]) => {
    const indices = buckets.flatMap((b: any, i: number) => Date.parse(b.start) < Date.parse(window.end_exclusive) && Date.parse(b.end_exclusive) > Date.parse(window.start) ? [i] : []);
    setZoom(indices.length ? [indices[0], indices[indices.length - 1]] : null); setFocus({ ...window, evidence_ids: ids });
  };
  const target: Target = { type: "set", key: `behavior:${id}`, label: `행위 분석 v${r?.version || ""}`,
    evidence: evidenceIds.slice(0, 20), time: [r?.result.scope.time?.start, r?.result.scope.time?.end] };
  const behavior: BehaviorResponse | undefined = r ? { result_id: r.id, result_sha256: r.result_sha256,
    metric_ids: metrics.map(m => m.id), answer_status: "follow_up" } : undefined;
  const option = useMemo(() => ({
    aria: { enabled: true, label: { description: `저장된 행위 관측 시계열, UTC, 총 ${buckets.length}구간. ${buckets.length > 12 ? "처음 12구간 안내. " : ""}${buckets.slice(0, 12).map((b: any) => `${b.start}: 관측 ${b.count ?? "미수집"}, 404 ${b.status404 ?? "미수집"}, 차단 ${b.blocked ?? "미수집"}, 허용 ${b.allowed ?? "미수집"}`).join(". ")}. 빈 구간의 수집 연속성은 확인할 수 없습니다.` } },
    grid: { left: 48, right: 22, top: 35, bottom: 64 }, legend: { data: ["관측", "404", "차단", "허용"] },
    tooltip: { trigger: "axis" as const, formatter: safeTooltip(p => [["UTC", buckets[p.dataIndex]?.start || ""], [p.seriesName, p.value ?? "미수집"]]) },
    xAxis: { type: "category" as const, data: buckets.map((b: any) => b.start), ...axisStyle },
    yAxis: { type: "value" as const, min: 0, ...axisStyle },
    dataZoom: [{ type: "slider" as const, startValue: zoom?.[0] ?? 0, endValue: zoom?.[1] ?? Math.max(0, buckets.length - 1) }, { type: "inside" as const }],
    series: [["관측", "count", "#4c8dff"], ["404", "status404", "#e3ad53"], ["차단", "blocked", "#d77979"], ["허용", "allowed", "#65ba9e"]].map(([name, field, color]) =>
      ({ name, type: "bar" as const, data: buckets.map((b: any) => b[field]), itemStyle: { color }, barMaxWidth: 22 })),
  }), [buckets, zoom]);

  return <div className="col" style={{ gap: 12 }}>
    <Panel title="행위 분석 범위">
      <p className="small muted">현재 필터와 시간 범위로 계산하고 결과를 새 버전으로 저장합니다. 관측한 요청 특성과 기준 비교를 확인할 수 있습니다.</p>
      <div className="row wrap" style={{ gap: 10 }}>
        <label className="col small grow">분석 IP (쉼표 구분, 최대 16개)<input className="input" aria-label="분석 IP" value={ipsText} onChange={e => setIpsText(e.target.value)} placeholder="비우면 현재 범위의 모든 IP" /></label>
        <label className="col small">IP 역할<select className="input" aria-label="IP 역할" value={role} onChange={e => setRole(e.target.value as Scope["role"])}><option value="src">출발지</option><option value="dst">목적지</option><option value="either">어느 쪽이든</option></select></label>
        {ctx.selection?.type === "ip" && <button className="btn sm" onClick={() => setIpsText(ctx.selection!.value)}>선택 IP 사용</button>}
        <button className="btn primary" disabled={run.isPending || active || ips.length > 16 || !validProfile} onClick={() => run.mutate()}>행위 분석 실행</button>
      </div>
      {ips.length > 16 && <div role="alert">IP는 최대 16개입니다.</div>}
      <div className="small muted">현재 필터 {ctx.filters.length}개 · 시간: {ctx.time?.start || "시작 제한 없음"} ~ {ctx.time?.end || "끝 제한 없음"}</div>
      <details style={{ marginTop: 10 }}><summary>SAW 로컬 분석 기준 · 제외 조건</summary>
        <p className="small muted">참고 기준을 조정하여 이 결과에만 저장합니다. 운영 탐지 규칙의 변경이 아닙니다.</p>
        <div className="row wrap">{METRICS.map(([key, label]) => <label key={key} className="col small">{label}<input type="number" min={1} step={1} className="input" style={{ width: 100 }} aria-label={`${label} 기준`} value={thresholds[key]} onChange={e => setThresholds({ ...thresholds, [key]: Number(e.target.value) })} /></label>)}
          <label className="col small">UA 조건 404 최소<input className="input" type="number" min={1} max={100000} aria-label="UA 조건 404 최소" value={uaMin404} onChange={e => setUaMin404(Number(e.target.value))} /></label></div>
        <label className="row small"><input type="checkbox" checked={excludeOptions} onChange={e => setExcludeOptions(e.target.checked)} />OPTIONS 제외 (요청·경로·반복만)</label>
        <label className="col small">정적 파일 제외 확장자<input className="input" aria-label="정적 파일 제외 확장자" value={suffixes} onChange={e => setSuffixes(e.target.value)} /></label>
        <label className="row small"><input type="checkbox" checked={deduplicate} onChange={e => setDeduplicate(e.target.checked)} />명시적 요청 ID와 동일 요청·시각이 일치하는 다중 센서 기록만 중복 제거</label>
      </details><ErrorBox error={run.error} />
      {jobId && <div aria-live="polite" className="notice small" style={{ marginTop: 8 }}>
        작업: {STATES[job.data?.state] || job.data?.state || "대기"}{job.data?.stages?.behavior_result?.coverage === "partial" ? " (일부만 분석)" : ""} · 처리 {fmtNum(job.data?.events_done ?? 0)}건 {job.data?.current_item || ""}
        {active && <button className="btn sm" disabled={cancel.isPending} onClick={() => cancel.mutate()}>분석 취소</button>}
        {job.data?.error?.message && <div role="alert">{job.data.error.message}</div>}<ErrorBox error={job.error || cancel.error} />
      </div>}
    </Panel>
    <div className="row wrap">
      <label className="row small">저장 버전<select className="input" aria-label="저장 버전" value={id} onChange={e => { setSelectedId(e.target.value); diff.reset(); }}>
        {!results.length && <option value="">없음</option>}{results.map(v => <option key={v.id} value={v.id}>v{v.version} · {v.created_at ? fmtTime(v.created_at) : v.id}</option>)}
      </select></label>
      <label className="row small">비교 대상<select className="input" aria-label="비교 대상" value={compareId === id ? "" : compareId} onChange={e => setCompareId(e.target.value)}>
        <option value="">선택 안 함</option>{results.filter(v => v.id !== id).map(v => <option key={v.id} value={v.id}>v{v.version}</option>)}
      </select></label>
      <span className="grow" />{r && <a className="btn sm" href={`/api/v1${base}/${r.id}/report`} target="_blank" rel="noopener noreferrer">저장 결과 보고서</a>}
    </div>
    <ErrorBox error={versions.error || saved.error || comparison.error} />
    {(versions.isLoading || saved.isLoading) && <Loading />}
    {!versions.isLoading && !versions.error && !results.length && <div className="empty">저장된 분석 결과가 없습니다. 범위를 고르고 분석을 실행하세요.</div>}
    {r && o && <>
      <Panel title="수집 범위와 자료 품질" right={<span className="row"><span className="tag">v{r.version}</span><span className="tag">{r.result.profile?.id === "theori-reference-v1" ? "WhitepaperReference" : "SAW 로컬 프로필"}</span></span>}>
        <b>{r.result.methodology?.source_basis || o.timeline?.coverage_label || "관측 자료 범위 미확인"}</b>
        <p className="small">저장된 IP: {r.result.scope.ips.join(", ") || "전체"} · 역할: {{ src: "출발지", dst: "목적지", either: "어느 쪽이든" }[r.result.scope.role]} · {r.created_at}</p>
        <div style={{ overflowX: "auto" }}><table className="t"><caption className="small">입력 파일별 처리 범위 · 파일 전체 건수이며 선택 범위의 관측 건수와 다를 수 있습니다.</caption>
          <thead><tr><th>파일</th><th>파서</th><th>처리 상태</th><th>파싱 건수</th><th>실패 건수</th><th>해석 시간대 (가정)</th></tr></thead>
          <tbody>{files.slice(0, 100).map((file: any) => <tr key={file.id}><td style={{ overflowWrap: "anywhere" }}>{file.display_name || file.id}</td>
            <td>{file.parser_id || "미기록"}{file.parser_version ? ` · ${file.parser_version}` : ""}</td><td>{STATES[file.parse_status] || file.parse_status || "미기록"}</td>
            <td>{file.events_parsed == null ? "미기록" : fmtNum(file.events_parsed)}</td><td>{file.events_failed == null ? "미기록" : fmtNum(file.events_failed)}</td><td>{file.tz_assumed || "미기록"}</td></tr>)}</tbody></table></div>
        {!files.length && <p className="small muted">파일별 출처 명세가 저장되지 않았습니다.</p>}
        {files.length > 100 && <p className="small muted">파일 {files.length}개 중 100개를 표시합니다. 나머지 지문은 저장된 출처 명세에서 확인할 수 있습니다.</p>}
        <table className="t"><tbody>{Object.entries(o.quality || {}).map(([key, value]) => <tr key={key}><th>{QUALITY[key] || key}</th><td>{value && typeof value === "object" ? <div className="row wrap" style={{ gap: 8 }}>{Object.entries(value).map(([field, count]) => <span key={field} className="tag">{QUALITY[field] || field}: {display(count)}</span>)}</div> : display(value)}</td></tr>)}</tbody></table>
        <p className="small muted">빈 UA 기록은 헤더 부재의 증거가 아닙니다. 비어 있는 시간 구간은 수집 연속성 미확인으로 해석합니다. 다중 센서에는 같은 요청이 중복 기록될 수 있습니다.</p>
        {(o.execution?.truncated || o.execution?.coverage === "partial") && <div className="notice warn" role="alert">
          일부만 분석: 대상 {o.execution.target_total != null ? fmtNum(o.execution.target_total) : "미확인"}건 중 {fmtNum(o.execution.processed ?? 0)}건 처리
          {o.execution.reason ? ` · 중단 이유 ${o.execution.reason}` : ""}. 아래 값은 처리한 부분의 관측값입니다.</div>}
        {o.execution?.coverage === "complete" && <div className="small muted">대상 {fmtNum(o.execution.target_total)}건 전체를 분석했습니다.</div>}
        <details><summary>저장된 범위·방법·출처 지문</summary><pre className="small mono" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{JSON.stringify({ scope: r.result.scope, methodology: r.result.methodology, profile: r.result.profile, source_manifest: r.result.source_manifest, execution: o.execution, result_sha256: r.result_sha256 }, null, 2)}</pre></details>
      </Panel>
      <Panel title="계산된 관측값">
        <div className="row wrap"><b>관측 {fmtNum(o.summary?.count)}건</b><span>서로 다른 경로 {o.summary?.unique_paths == null ? "미수집" : fmtNum(o.summary.unique_paths)}</span><span className="small">{o.summary?.first || "시각 미수집"} ~ {o.summary?.last || "시각 미수집"}</span></div>
        <table className="t"><tbody>{[["메서드", "methods"], ["상태 코드", "status_codes"], ["조치", "actions"], ["서비스", "services"], ["UA", "user_agents"]].map(([label, field]) => <tr key={field}><th>{label}</th><td>{display(o.summary?.[field])}</td></tr>)}</tbody></table>
      </Panel>
      <Panel title="시간 변화 · UTC">
        {buckets.length ? <EChart ariaLabel="행위 관측 시계열" height={280} option={option} onClick={p => { const b = buckets[p.dataIndex]; if (b) setFocus(b); }} /> : <div className="muted">시각이 있는 관측값이 없습니다.</div>}
        <p className="small muted">고정 {o.timeline?.interval_seconds ?? "—"}초 막대는 관측 건수입니다. 아래 지표는 출발지와 목적 서비스별 이동 시간창의 최대값입니다. 막대 아래 조절부나 마우스 휠로 확대할 수 있습니다.</p>
        <div className="row wrap"><button className="btn sm" onClick={() => { setZoom(null); setFocus(null); }}>전체 구간</button>
          {metrics.filter(m => m.window).map(m => <button key={m.id} className="btn sm" onClick={() => peak(m.window!, m.evidence_ids)}>{m.label} 최대 구간</button>)}
          {metrics.filter(m => m.qualifying_window).map(m => <button key={`qualify:${m.id}`} className="btn sm" onClick={() => peak(m.qualifying_window!, m.qualifying_window!.evidence_ids)}>{m.label} 동반 조건 구간</button>)}
          {focus && <button className="btn sm" disabled={!focusedEvidenceIds.some(value => evidenceIds.includes(value))} onClick={() => raw(focusedEvidenceIds)}>선택 구간 표본 원문</button>}</div>
        {focus && <div className="small mono">[{focus.start}, {focus.end_exclusive}) · {focus.src_ip || ""} {focus.service || ""}</div>}
      </Panel>
      <Panel title="이동 시간창 지표">
        <p className="small muted">WhitepaperReference 참고 기준과 저장된 적용 기준을 비교합니다. 기준 도달 자체는 도구·행위 주체·침해 여부를 뜻하지 않습니다.</p>
        <div style={{ overflowX: "auto" }}><table className="t"><thead><tr><th>지표 / 시간창</th><th>관측값</th><th>자료 상태 / 기준 비교</th><th>참고 / 적용 기준</th><th>대상 / 제외</th><th>최대 구간 [시작, 끝)</th><th>근거</th></tr></thead>
          <tbody>{metrics.map(m => <tr key={m.id}><th>{m.label}<div className="small muted">{m.window_seconds}초</div></th><td className="num">{m.value == null ? "—" : fmtNum(m.value)}</td>
            <td>{STATES[m.data_state] || m.data_state}<div className="small">{STATES[m.result] || m.result}</div>{m.partial_window && <span className="tag warn">부분 시간창</span>}</td>
            <td>{m.reference_threshold} / {m.applied_threshold}{m.required_status404 != null && <div className="small">같은 창 404 ≥ {m.required_status404}</div>}</td><td>{m.eligible_count} / {m.excluded_count}</td>
            <td className="small">{m.window ? <>{m.window.start}<br />~ {m.window.end_exclusive}<br />{m.window.src_ip} · {m.window.service}{m.status404_in_window != null && <div>최대 구간 404: {m.status404_in_window}</div>}</> : "시간창 없음"}
              {m.qualifying_window && <div style={{ marginTop: 6 }}><b>동반 조건 충족 구간</b><div>UA {m.qualifying_window.value} / 404 {m.qualifying_window.status404}</div>
                <div>{m.qualifying_window.start} ~ {m.qualifying_window.end_exclusive}</div><div>{m.qualifying_window.src_ip} · {m.qualifying_window.service}</div></div>}</td>
            <td><button className="btn sm" disabled={!m.evidence_ids?.length} aria-label={`${m.label} 표본 원문`} onClick={() => raw(m.evidence_ids)}>표본 원문</button>{m.qualifying_window && <button className="btn sm" disabled={!m.qualifying_window.evidence_ids?.length}
              onClick={() => raw(m.qualifying_window!.evidence_ids)}>동반 조건 근거</button>}</td></tr>)}</tbody></table></div>
        <p className="small muted">부분 시간창은 관측 기간이 해당 창보다 짧음을 뜻합니다. 같은 시각 기록의 순서는 확정하지 않으며, 반복 요청의 쿼리는 유지합니다.</p>
      </Panel>
      {comparison.data && compareId !== id && <Panel title={`비교 대상 v${comparison.data.version}`}>
        <p className="small muted">서로 다른 범위·자료 품질·적용 기준은 결과 차이에 영향을 줍니다.</p>
        <div className="small">{display(comparison.data.result.scope)}</div>
        <table className="t"><thead><tr><th>지표</th><th>현재 저장 결과</th><th>비교 대상</th></tr></thead><tbody>{metrics.map(m => { const other = comparison.data.result.observations.metrics.find(x => x.id === m.id); return <tr key={m.id}><td>{m.label}</td><td>{m.value ?? "미수집"} · {m.applied_threshold}</td><td>{other?.value ?? "미수집"} · {other?.applied_threshold ?? "—"} · {STATES[other?.data_state || ""] || ""}</td></tr>; })}</tbody></table>
      </Panel>}
      <Panel title="조건부 신호 · 근거와 한계">
        {(o.indicators || []).map(x => <div key={x.id} style={{ borderBottom: "1px solid var(--line)", padding: "8px 0" }}>
          <div className="row wrap"><b>{x.label}</b><span className="tag">{STATES[x.state] || x.state}</span><span>{x.count ?? "—"}건</span>
            <button className="btn sm" disabled={!x.evidence_ids?.length} onClick={() => raw(x.evidence_ids.filter((e: string) => evidenceIds.includes(e)))}>근거 표본</button></div>
          <div className="small">자료: {display(x.source)} · 확인 방법: {display(x.verification)}</div>{x.rule_ids?.length > 0 && <div className="small">규칙: {x.rule_ids.join(", ")}</div>}
          <div className="small">조건: {display(x.conditions ?? x.condition)}</div><div className="small muted">한계: {display(x.limits)}</div>
        </div>)}
        <ul className="small muted">{(o.limits || []).map((x, i) => <li key={i}>{display(x)}</li>)}</ul>
      </Panel>
      <Panel title="조건에 따른 후속확인">
        {(o.followups || []).map((x, i) => <div key={x.id || i} className="small" style={{ padding: "8px 0" }}>
          <div className="row wrap"><b>{x.label || x.target || "추가 확인"}</b><span className="muted">{x.question_version ? <>질문 버전: <span>{x.question_version}</span></> : "질문 버전: 미기록"}</span></div>
          <table className="t"><tbody>{[
            ["적용 조건", x.condition ?? x.conditions], ["질문", x.question], ["필요 자료", x.needed_data],
            ["허용된 확인 행동", x.allowed_actions], ["해결 조건", x.resolution_criteria],
            ["미해결 시 처리", x.if_unresolved], ["금지 단정", x.forbidden_claims], ["확인 내용", x.items],
          ].map(([label, value]) => <tr key={label}><th style={{ width: 145 }}>{label}</th><td>{value == null ? "이 저장 결과에는 미기록" : Array.isArray(value) && !value.length ? "기록된 항목 없음" : display(value)}</td></tr>)}</tbody></table>
        </div>)}
      </Panel>
      <Panel title="저장된 대표 근거 · 원문과 요청 비교">
        <p className="small muted">아래 기록은 저장된 범위의 제한된 표본입니다. 원문 이동은 이 저장 결과의 근거 표본만 보여 줍니다. 요청 비교에서 쿼리 변화는 유지하며 헤더·본문 미수집으로 확인할 수 없는 내용은 별도 확인이 필요합니다.</p>
        <div className="row wrap"><button className="btn sm" disabled={!evidence.length} onClick={() => raw(evidenceIds)}>저장된 근거 표본 원문</button>
          <button className="btn sm" disabled={selectedEvents.length < 2 || diff.isPending} onClick={() => diff.mutate()}>선택 요청 비교</button><span className="small">{selectedEvents.length}건 선택</span></div>
        <table className="t"><thead><tr><th>비교</th><th>시각</th><th>요청</th><th>원문</th></tr></thead><tbody>{evidence.map(e => <tr key={e.event_id}>
          <td><input type="checkbox" aria-label={`요청 비교 선택 ${e.event_id}`} checked={selectedEvents.includes(e.event_id)} onChange={x => { diff.reset(); setSelectedEvents(x.target.checked ? [...selectedEvents, e.event_id] : selectedEvents.filter(id => id !== e.event_id)); }} /></td>
          <td className="small">{e.event?.timestamp || "시각 없음"}</td><td className="mono small" style={{ overflowWrap: "anywhere" }}>{e.event?.method || ""} {e.event?.uri || e.event?.url_path || e.event_id}</td>
          <td><button className="btn sm" onClick={() => ctx.set({ eventId: e.event_id })}>기록 상세</button></td></tr>)}</tbody></table>
        <ErrorBox error={diff.error} />{diff.data?.requests?.length > 0 && <RequestEvolution key={`${id}:${selectedEvents.join(",")}`} r={diff.data} />}
        {diff.data && !diff.data.requests?.length && <div className="muted small">비교 가능한 요청이 없습니다.</div>}
      </Panel>
      <Panel title="분석가 해석 · 확인 기록" right={<button className="btn primary sm" onClick={() => setCheckOpen(true)}>분석가 확인 기록</button>}>
        <p className="small muted">승인된 점검·배치 등 설명은 확인한 근거와 범위를 기록하세요. 해석은 계산된 관측값과 별도로 저장합니다.</p>
        <TargetChecks inv={inv} target={target} canEdit={false} />
      </Panel>
      {checkOpen && behavior && <CheckDialog inv={inv} target={target} behavior={behavior} evidenceOptions={evidenceIds} onClose={() => setCheckOpen(false)} />}
    </>}
  </div>;
}
