import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtNum, fmtTime } from "../../lib/format";
import { axisStyle, EChart, safeTooltip } from "../../viz/EChart";

const SOURCE_KO: Record<string, string> = { connection: "연결(방화벽·NDR 세션)", web: "HTTP 요청(NDR·웹)", waf: "웹 방화벽", zeek_conn: "네트워크 연결", zeek_http: "패킷 속 HTTP", suricata: "IDS 경보" };
const REGISTRY_KO: Record<string, string> = { confirmed: "의미 확인됨(같은 장비·유효기간)", name_only: "이름만 일치 — 장비 미지정 등록",
  ambiguous: "적용 가능한 등록 여러 개 — 확인 필요", needs_confirmation: "의미 확인 필요" };
// The tooltip explains the meaning that actually applies, or why no registered meaning applies — never just the first entry.
const alertTitle = (a: any) => a.applied ? `${a.applied.meaning} (v${a.applied.version} · ${a.applied.basis})`
  : (a.entries || []).map((e: any) => e.not_applied_reason).filter(Boolean).join(" / ") || "등록된 의미가 없습니다.";
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
            <td className="mono ellipsis" style={{ maxWidth: 260 }}>{name === "data_source" ? (SOURCE_KO[b.key] || b.key) : (b.label || String(b.key))}</td>
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
  const q = useQuery({ queryKey: ["scope-summary", inv, ctx.filters, ctx.time],
    queryFn: () => api.post(`/investigations/${inv}/scope-summary`, { filters: ctx.filters, time: ctx.time }) });
  const alerts = useQuery({ queryKey: ["alert-names", inv], queryFn: () => api.get(`/investigations/${inv}/alert-names`) });
  if (q.isLoading) return <Loading label="전체 현황 집계 중" />;
  if (q.error) return <ErrorBox error={q.error} />;
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
    if (!weekly && day) ctx.set({ time: { start: `${day}T00:00:00+09:00`, end: `${day}T23:59:59.999+09:00` } });
  };
  return (
    <div className="col" style={{ gap: 12 }}>
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

      <Panel title={weekly ? "주별 기록 수" : "일별 기록 수 (빈 날은 주황 · 날짜를 누르면 그 날로 좁혀 봅니다)"}
        right={<span className="row small" style={{ gap: 6 }}><button className={`btn sm ${weekly ? "" : "primary"}`} onClick={() => setWeekly(false)}>일별</button><button className={`btn sm ${weekly ? "primary" : ""}`} onClick={() => setWeekly(true)}>주별</button></span>}>
        <EChart ariaLabel="기간별 기록 수" height={200} option={option as any} onClick={(p: any) => openDay(p.dataIndex)} />
        {t.empty_days.length > 0 && <div className="small" style={{ color: "var(--warn)" }}>
          기록이 하나도 없는 날 {t.empty_days.length}일: {t.empty_days.slice(0, 20).join(", ")}{t.empty_days.length > 20 ? " …" : ""}. 수집 공백인지, 실제로 통신이 없었는지는 수집 담당자에게 확인해야 합니다.
        </div>}
      </Panel>

      <div className="grid3">
        <Breakdown name="enforcement_action" data={d.breakdown.enforcement_action} onPick={pick("enforcement_action")} />
        <Breakdown name="data_source" data={d.breakdown.data_source} onPick={pick("data_source")} />
        <Panel title="장비 공격명 (장비의 주장 · 의미 등록 상태)">
          {alerts.isLoading && <Loading />}
          {(alerts.data?.items || []).slice(0, 10).map((a: any, i: number) => (
            <div key={`${a.alert_name}-${i}`} className="row small" style={{ gap: 6 }}>
              <span className="grow ellipsis mono" title={a.alert_name}>{a.alert_name}</span>
              <span className="num">{fmtNum(a.count)}</span>
              <span className={`tag ${a.registry === "confirmed" ? "" : "warn"}`} title={alertTitle(a)}>{REGISTRY_KO[a.registry] || a.registry}</span>
              <button className="btn ghost sm" onClick={() => pick("alert_name")(a.alert_name)}>좁혀 보기</button>
            </div>
          ))}
          {alerts.data && !alerts.data.items.length && <div className="small muted">공격명이 기록된 로그가 없습니다.</div>}
          {alerts.data && <div className="small muted">{alerts.data.note}</div>}
        </Panel>
        <Breakdown name="src_ip" data={d.breakdown.src_ip} onPick={pick("src_ip")} />
        <Breakdown name="dst_ip" data={d.breakdown.dst_ip} onPick={pick("dst_ip")} />
        <Breakdown name="dst_port" data={d.breakdown.dst_port} onPick={pick("dst_port")} />
        <Breakdown name="protocol" data={d.breakdown.protocol} onPick={pick("protocol")} />
      </div>

      {d.analysis && <Panel title={`최근 분석 실행 v${d.analysis.version} — 일부만 처리·자료 부족인 분석`}>
        {d.analysis.incomplete.length ? <ul className="small">{d.analysis.incomplete.map((x: any) => <li key={x.detector_id}>{x.detector_id}: {x.label}{x.reason_label ? ` — ${x.reason_label}` : ""}</li>)}</ul>
          : <div className="small muted">모든 분석이 설정된 범위에서 끝났습니다. 수집의 완전성은 별도로 확인해야 합니다.</div>}
        <div className="small muted">'자료 부족'·'일부만 처리'는 정상 판정이 아닙니다. 분석 실행 이력 탭에서 범위와 이유를 확인하세요.</div>
      </Panel>}
      {!d.analysis && <div className="small muted">아직 분석이 실행되지 않았습니다. 분석하지 못한 상태는 '이상 없음'과 다릅니다.</div>}
    </div>
  );
}
