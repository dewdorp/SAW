import { useMutation, useQuery } from "@tanstack/react-query";
import { useRef, useState, type ReactNode } from "react";
import { ScopeSnapshot, SOURCE_NAMES } from "./ScopeSnapshot";
import "./readable-workbench.css";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { FieldMeanings } from "./FieldMeanings";
import { QuestionBundles } from "./QuestionBundles";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtNum, fmtTime } from "../../lib/format";
import { axisStyle, EChart, safeTooltip } from "../../viz/EChart";

const REGISTRY_KO: Record<string, string> = { confirmed: "의미 확인됨(같은 장비·유효기간)", name_only: "이름만 일치 — 장비 미지정 등록",
  ambiguous: "적용 가능한 등록 여러 개 — 확인 필요", needs_confirmation: "의미 확인 필요" };
// The tooltip explains the meaning that actually applies, or why no registered meaning applies — never just the first entry.
const alertTitle = (a: any) => a.applied ? `${a.applied.meaning} (v${a.applied.version} · ${a.applied.basis})`
  : (a.entries || []).map((e: any) => e.not_applied_reason).filter(Boolean).join(" / ") || "등록된 의미가 없습니다.";
const RUN_KO: Record<string, string> = { queued: "대기 중", running: "진행 중", complete: "완료", partial: "일부만 처리", failed: "실패", cancelled: "취소" };
const PICKABLE = new Set(["data_source", "enforcement_action", "alert_name", "src_ip", "dst_ip", "dst_port", "protocol"]);

/** Inline editor for the declared investigation period (shown while it is missing). */
export function ScopePeriodEditor({ inv, onSaved }: { inv: any; onSaved: () => void }) {
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const save = useMutation({
    mutationFn: () => api.patch(`/investigations/${inv.id}`, { period_start: `${start}:00+09:00`, period_end: `${end}:59+09:00` }),
    onSuccess: onSaved,
  });
  return (
    <span className="row wrap" style={{ gap: 4, display: "inline-flex" }}>
      <input className="input" type="datetime-local" aria-label="조사 시작" value={start} onChange={(e) => setStart(e.target.value)} />
      ~ <input className="input" type="datetime-local" aria-label="조사 끝" value={end} onChange={(e) => setEnd(e.target.value)} />
      <button className="btn sm" disabled={!start || !end || save.isPending} onClick={() => save.mutate()}>조사 기간 저장(KST)</button>
      <ErrorBox error={save.error} />
    </span>
  );
}

function Breakdown({ name, data, onPick }: { name: string; data: any; onPick?: (value: any) => void }) {
  if (!data) return null;
  const rows = data.buckets || [];
  return (
    <Panel title={`${data.label} (기록된 ${fmtNum(data.recorded)}건 · 값 없음 ${fmtNum(data.not_recorded)}건)`}>
      {!rows.length && <div className="small muted">이 범위에 값이 기록된 로그가 없습니다. 값이 없다는 것과 '이상 없음'은 다릅니다.</div>}
      <table className="t"><tbody>
        {rows.map((b: any) => (
          <tr key={String(b.key)}>
            <td className="mono ellipsis" style={{ maxWidth: 260 }}>{name === "data_source" ? (SOURCE_NAMES[b.key] || b.key) : (b.label || String(b.key))}</td>
            <td className="num">{fmtNum(b.count)}</td>
            {onPick && PICKABLE.has(name) && <td><button className="btn ghost sm" onClick={() => onPick(b.key)} title="이 값으로 좁혀 보기 (전체 기준은 그대로 표시됩니다)">좁혀 보기</button></td>}
          </tr>
        ))}
        {data.other > 0 && <tr><td className="muted">그 외</td><td className="num">{fmtNum(data.other)}</td></tr>}
      </tbody></table>
    </Panel>
  );
}

export function ScopeSummary({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const [weekly, setWeekly] = useState(false);
  const [timeExpanded, setTimeExpanded] = useState(false);
  const qualityRef = useRef<HTMLDetailsElement>(null);
  const timeRef = useRef<HTMLDetailsElement>(null);
  const openDetail = (key: "quality" | "time") => {
    const node = (key === "quality" ? qualityRef : timeRef).current;
    if (!node) return;
    node.open = true;
    node.querySelector("summary")?.focus({ preventScroll: true });
    node.scrollIntoView?.({ block: "start" });
  };
  // The summary is keyed by everything that changes it: investigation, period, data and analysis versions, filter.
  const meta = useQuery<any>({ queryKey: ["inv", inv], queryFn: () => api.get(`/investigations/${inv}`) });
  const version = [meta.data?.period_start, meta.data?.period_end, (meta.data?.evidence || []).map((e: any) => `${e.id}:${e.status}`).join(","),
    JSON.stringify(meta.data?.finding_counts ?? null), meta.data?.time_start, meta.data?.time_end];
  const q = useQuery({ queryKey: ["scope-summary", inv, version, ctx.filters, ctx.time],
    queryFn: () => api.post(`/investigations/${inv}/scope-summary`, { filters: ctx.filters, time: ctx.time }),
    refetchInterval: (query: any) => ["running", "queued"].includes(query.state.data?.analysis?.status) ? 5000 : false });
  const alerts = useQuery({ queryKey: ["alert-names", inv], queryFn: () => api.get(`/investigations/${inv}/alert-names`) });
  const openAll = (tab: "raw" | "statistics") =>
    ctx.set({ tab, filters: [], time: null, selection: null, findingId: null, eventId: null });
  // Each result loads independently. A slow or failed aggregation must not block the basic investigation.
  const frame = (details: ReactNode) => <div className="scope-reading">
    <ScopeSnapshot data={q.data} error={q.error} openAll={() => openAll("raw")} openStats={() => openAll("statistics")} openDetail={openDetail} />
    <QuestionBundles inv={inv} />
    {details}
  </div>;
  if (!q.data) return frame(null);
  const d = q.data;
  const t = d.time;
  const inputs = d.inputs;
  const series = weekly ? t.weekly.map((w: any) => ({ key: w.week, count: w.count })) : t.daily.map((x: any) => ({ key: x.date, count: x.count }));
  const pick = (field: string) => (value: any) => ctx.addFilter({ field, op: "is", value });
  const option = {
    grid: { left: 44, right: 10, top: 16, bottom: 40 },
    xAxis: { type: "category", data: series.map((s: any) => s.key), ...axisStyle },
    yAxis: { type: "value", ...axisStyle },
    dataZoom: [{ type: "slider", height: 14, bottom: 4 }],
    tooltip: { trigger: "axis", formatter: safeTooltip((p) => [[p.axisValue, p.value]]) },
    series: [{ type: "bar", data: series.map((s: any) => ({ value: s.count, itemStyle: { color: s.count ? "#4c8dff" : "#f5b324" } })) }],
  };
  const openDay = (index: number) => {
    const day = t.daily[index]?.date;
    // [day 00:00, next day 00:00): the whole day, with no millisecond trimmed off either end.
    const next = day && new Date(Date.parse(`${day}T00:00:00Z`) + 86400000).toISOString().slice(0, 10);
    if (!weekly && day) ctx.set({ time: { start: `${day}T00:00:00+09:00`, end: `${next}T00:00:00+09:00`, end_exclusive: true } });
  };
  return frame(
    <section className="scope-extras" aria-label="자료 상세">
      <h3>자료 상세</h3>
      <details ref={qualityRef} className="scope-fold">
        <summary>수집·파싱과 조사 범위</summary>
        <div className="scope-fold-content">
      <section aria-label="조사 범위와 기준" className="panel pb col" style={{ gap: 6 }}>
        <div className="row wrap" style={{ gap: 16 }}>
          <span><span className="muted">관계사</span> <b>{d.scope.org_unit || "미지정"}</b></span>
          <span><span className="muted">조사 기간</span> <b>{d.scope.period_declared ? `${fmtTime(d.scope.period_start)} ~ ${fmtTime(d.scope.period_end)}` : "미지정"}</b></span>
          <span><span className="muted">로그 관측 기간</span> {fmtTime(d.scope.observed_start)} ~ {fmtTime(d.scope.observed_end)}</span>
        </div>
        <div role="status" aria-label="집계 기준">
          {d.basis.kind === "all"
            ? <b>집계 기준: 조사 전체 {fmtNum(d.basis.all_events)}건</b>
            : <b>집계 기준: 현재 필터 {fmtNum(d.basis.events)}건 (조사 전체 {fmtNum(d.basis.all_events)}건 중)</b>}
          <span className="small muted"> · 조사 후보를 열어도 이 분모는 바뀌지 않습니다. 필터를 지우면 전체 기준으로 돌아갑니다.</span>
        </div>
        <div className="small">
          시간 정보 있음 {fmtNum(t.with_timestamp)}건 · <b style={{ color: t.without_timestamp ? "var(--warn)" : undefined }}>시간 없음·해석 불가 {fmtNum(t.without_timestamp)}건</b>
          {t.outside_period && <> · 조사 기간 밖 기록: 이전 {fmtNum(t.outside_period.before)}건, 이후 {fmtNum(t.outside_period.after)}건</>}
        </div>
        <div className="small muted">{d.method_note}</div>
      </section>

      <Panel title="입력과 파싱 상태 — 몇 건이 들어왔고 몇 건을 분석에 쓸 수 있는가">
        <div className="row wrap small" style={{ gap: 16 }}>
          <span>파일 {fmtNum(inputs.files)}개</span><span>입력 줄 {fmtNum(inputs.lines)}</span>
          <span>분석에 쓰이는 기록 <b>{fmtNum(inputs.events)}</b></span>
          <span style={{ color: inputs.failed_lines ? "var(--bad)" : undefined }}>읽지 못한 줄 {fmtNum(inputs.failed_lines)}</span>
          <span>저장 거부 {fmtNum(inputs.rejected_events)}</span>
          <span>시간 없음 {fmtNum(inputs.timestamp_missing)} · 시간 해석 불가 {fmtNum(inputs.timestamp_invalid)}</span>
          <span style={{ color: inputs.unsupported_files ? "var(--warn)" : undefined }}>미지원·처리 실패 파일 {fmtNum(inputs.unsupported_files)}</span>
          <span style={{ color: inputs.files_with_notes ? "var(--warn)" : undefined }}>확인할 점이 있는 파일 {fmtNum(inputs.files_with_notes)}</span>
        </div>
        <table className="t" style={{ marginTop: 8 }}><thead><tr><th>파일</th><th>파서</th><th>상태</th><th className="num">기록</th><th className="num">실패</th><th>확인할 점</th></tr></thead>
          <tbody>{inputs.by_file.map((f: any, i: number) => (
            <tr key={i}><td className="mono ellipsis" style={{ maxWidth: 220 }}>{f.name}</td><td>{f.parser_id || <span className="tag warn">파서 없음</span>}</td>
              <td>{f.status}</td><td className="num">{fmtNum(f.events)}</td><td className="num">{fmtNum(f.failed)}</td>
              <td className="small" style={{ whiteSpace: "pre-wrap" }}>{f.message ? f.message.split(" · ").map((m: string, k: number) => <div key={k}>⚠ {m}</div>) : <span className="muted">없음</span>}</td></tr>
          ))}</tbody></table>
        {inputs.files_truncated && <div className="small muted">파일이 많아 처음 200개만 표시했습니다.</div>}
      </Panel>

      {t.empty_days.length > 0 && <p className="small">기록 없는 날짜: {t.empty_days.slice(0,20).join(", ")}{t.empty_days.length > 20 ? " …" : ""}. 수집 중단 여부는 별도 확인이 필요합니다.</p>}
      </div></details>
      <details ref={timeRef} className="scope-fold" onToggle={e => setTimeExpanded(e.currentTarget.open)}>
      <summary>기간별 추이와 자료 분포</summary><div className="scope-fold-content">
      <Panel title={weekly ? "주별 기록 수" : "일별 기록 수 (빈 날은 주황 · 날짜를 누르면 그 날로 좁혀 봅니다)"}
        right={<span className="row small" style={{ gap: 6 }}><button className={`btn sm ${weekly ? "" : "primary"}`} onClick={() => setWeekly(false)}>일별</button><button className={`btn sm ${weekly ? "primary" : ""}`} onClick={() => setWeekly(true)}>주별</button></span>}>
        {timeExpanded && <EChart ariaLabel="기간별 기록 수" height={200} option={option as any} onClick={(p: any) => openDay(p.dataIndex)} />}
        {t.empty_days.length > 0 && <div className="small" style={{ color: "var(--warn)" }}>
          조사 전체에 기록이 하나도 없는 날 {t.empty_days.length}일: {t.empty_days.slice(0, 20).join(", ")}{t.empty_days.length > 20 ? " …" : ""}. 수집 공백인지, 실제로 통신이 없었는지는 수집 담당자에게 확인해야 합니다.
        </div>}
        {(t.no_result_days || []).length > 0 && <div className="small muted">
          현재 검색 조건에서 결과가 없는 날 {t.no_result_days.length}일 — 이 날들에도 다른 기록은 있으므로 수집 공백이 아닙니다.
        </div>}
      </Panel>

      <div className="grid3">
        <Breakdown name="enforcement_action" data={d.breakdown.enforcement_action} onPick={pick("enforcement_action")} />
        <Breakdown name="data_source" data={d.breakdown.data_source} onPick={pick("data_source")} />
        <Panel title={`장비 공격명 (장비의 주장 · 의미 등록 상태)${d.basis.kind === "filter" ? " — 현재 필터 기준 건수" : ""}`}>
          {alerts.isLoading && <Loading />}
          {/* Counts follow the same basis as every other card; the registry state comes from the whole investigation. */}
          {(d.breakdown.alert_name?.buckets || []).slice(0, 10).map((b: any) => {
            const rows = (alerts.data?.items || []).filter((a: any) => a.alert_name === String(b.key));
            const states = [...new Set(rows.map((a: any) => a.registry))];
            const a = rows.length === 1 ? rows[0] : null;
            return (
              <div key={String(b.key)} className="row small" style={{ gap: 6 }}>
                <span className="grow ellipsis mono" title={String(b.key)}>{String(b.key)}</span>
                <span className="num">{fmtNum(b.count)}</span>
                {a ? <span className={`tag ${a.registry === "confirmed" ? "" : "warn"}`} title={alertTitle(a)}>{REGISTRY_KO[a.registry] || a.registry}</span>
                  : <span className="tag warn" title="같은 이름이 장비마다 다르게 해석될 수 있습니다. 원문의 장비를 확인하세요.">{states.length > 1 ? "장비별로 다름 — 확인 필요" : REGISTRY_KO[String(states[0] || "needs_confirmation")]}</span>}
                <button className="btn ghost sm" onClick={() => pick("alert_name")(b.key)}>좁혀 보기</button>
              </div>
            );
          })}
          {!(d.breakdown.alert_name?.buckets || []).length && <div className="small muted">{d.basis.kind === "filter" ? "현재 필터에 해당하는 기록에는 공격명이 없습니다." : "공격명이 기록된 로그가 없습니다."}</div>}
          {alerts.data && <div className="small muted">{alerts.data.note}</div>}
        </Panel>
        <Breakdown name="src_ip" data={d.breakdown.src_ip} onPick={pick("src_ip")} />
        <Breakdown name="dst_ip" data={d.breakdown.dst_ip} onPick={pick("dst_ip")} />
        <Breakdown name="dst_port" data={d.breakdown.dst_port} onPick={pick("dst_port")} />
        <Breakdown name="protocol" data={d.breakdown.protocol} onPick={pick("protocol")} />
      </div>

      </div></details>
      <FieldMeanings inv={inv} />
      <details className="scope-fold"><summary>최근 탐지 실행 상세</summary><div className="scope-fold-content">
      {d.analysis?.status && <Panel title={`최근 분석 실행 v${d.analysis.version} — ${RUN_KO[d.analysis.status] || d.analysis.status}`}>
        {d.analysis.incomplete.length > 0 && <ul className="small">{d.analysis.incomplete.map((x: any) => <li key={x.detector_id}>{x.detector_id}: {x.label}{x.reason_label ? ` — ${x.reason_label}` : ""}</li>)}</ul>}
        {/* "Everything finished" is said only for a finished run; a running or failed run is never reported as complete. */}
        {d.analysis.status === "complete" && !d.analysis.incomplete.length && <div className="small muted">모든 분석이 설정된 범위에서 끝났습니다. 수집의 완전성은 별도로 확인해야 합니다.</div>}
        {["running", "queued"].includes(d.analysis.status) && <div className="small" role="status">분석이 아직 진행 중입니다. 지금 보이는 후보와 미완료 목록은 바뀔 수 있습니다.</div>}
        {["failed", "cancelled"].includes(d.analysis.status) && <div className="small" role="alert">이 분석 실행은 {RUN_KO[d.analysis.status]}되었습니다. 결과가 일부이거나 없을 수 있습니다. 분석 실행 이력 탭에서 이유를 확인하세요.</div>}
        <div className="small muted">'자료 부족'·'일부만 처리'는 정상 판정이 아닙니다. 분석 실행 이력 탭에서 범위와 이유를 확인하세요.</div>
      </Panel>}
      {!d.analysis?.status && <div className="small muted">아직 분석이 실행되지 않았습니다. 분석하지 못한 상태는 '이상 없음'과 다릅니다.</div>}
      </div></details>
    </section>
  );
}
