import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { Filter, useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtBytes, fmtNum, fmtTime } from "../../lib/format";
import { axisStyle, EChart, safeTooltip } from "../../viz/EChart";

const GROUPS: Record<string, string> = { data_source: "로그 종류", source_file: "파일", src_ip: "출발지 IP", dst_ip: "목적지 IP", dst_port: "목적지 포트" };

export function StatisticsTab({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const [group, setGroup] = useState("data_source");
  const [size, setSize] = useState(20);
  const q = useQuery({ queryKey: ["statistics", inv, ctx.filters, ctx.time, group, size],
    queryFn: () => api.post(`/investigations/${inv}/statistics`, { filters: ctx.filters, time: ctx.time, group_by: group, size }) });
  const d = q.data;
  const buckets = d?.timeline?.buckets || [];
  const raw = (filters: Filter[]) => {
    for (const filter of filters) ctx.addFilter(filter);
    ctx.set({ tab: "raw", eventId: null });
  };
  const label = (key: Record<string, string | number>) => key.source_file !== undefined
    ? `${key.source_file} · 증거 ${String(key.evidence_id).slice(0, 8)}` : String(Object.values(key)[0]);
  const option = {
    grid: { left: 50, right: 15, top: 20, bottom: 40 },
    xAxis: { type: "category", data: buckets.map((b: any) => fmtTime(b.key)), ...axisStyle },
    yAxis: { type: "value", ...axisStyle },
    tooltip: { trigger: "axis", formatter: safeTooltip((p) => [["기록 수", p.value]]) },
    dataZoom: [{ type: "slider", height: 14, bottom: 4 }],
    series: [{ name: "기록 수", type: "bar", data: buckets.map((b: any) => b.count) }],
  };
  return <div className="col">
    <div className="row wrap">
      <h3>로그 통계</h3>
      <label>통계 기준 <select aria-label="통계 기준" value={group} onChange={e => setGroup(e.target.value)}>
        {Object.entries(GROUPS).map(([value, text]) => <option key={value} value={value}>{text}</option>)}
      </select></label>
      <label>표시 개수 <select aria-label="표시 개수" value={size} onChange={e => setSize(Number(e.target.value))}>
        {[10, 20, 50].map(n => <option key={n} value={n}>상위 {n}개</option>)}
      </select></label>
    </div>
    <p className="muted small">현재 조사와 위쪽 필터·시간 범위에 해당하는 색인 기록을 집계합니다. 정상·악성 여부를 확정하는 통계가 아닙니다.</p>
    {group === "source_file" && <p className="notice">증거 ID와 파일명을 함께 구분합니다. 같은 증거 안의 동명 파일은 합산될 수 있습니다.</p>}
    {q.isLoading && <Loading />}
    {q.error && <ErrorBox error={q.error} />}
    {d && !q.error && <>
      <div className="row wrap panel pb" aria-label="통계 범위">
        <b>선택 범위 {fmtNum(d.summary.matched_events)}건</b>
        <span>관측 {fmtTime(d.summary.time_start)} ~ {fmtTime(d.summary.time_end)}</span>
        <span>시각 없음 {fmtNum(d.summary.timestamp_missing)}건</span>
        <span>필터 {ctx.filters.length}개{ctx.time ? " · 시간 범위 적용" : " · 전체 관측 기간"}</span>
      </div>
      <Panel title={`기록 수 시간 추이 · ${d.timeline.interval_sec}초 간격 (드래그하여 범위 선택)`}>
        {buckets.length ? <EChart ariaLabel="기록 수 시간 추이" height={190} option={option as any}
          onBrush={([a, b]) => {
            if (!buckets[a] || !buckets[b]) return;
            const start = Math.max(buckets[a].key * 1000, ctx.time?.start ? Date.parse(ctx.time.start) : -Infinity);
            const end = Math.min((buckets[b].key + d.timeline.interval_sec) * 1000 - 1,
              ctx.time?.end ? Date.parse(ctx.time.end) : Infinity);
            if (start <= end) ctx.set({ time: { start: new Date(start).toISOString(), end: new Date(end).toISOString() } });
          }} /> : <p className="muted">표시할 시각이 있는 기록이 없습니다.</p>}
      </Panel>
      <div className="row wrap small">
        <span>표시 합계 {fmtNum(d.table.shown_events)}건</span>
        <span>기타 {fmtNum(d.table.other_events)}건</span>
        <span>분류 값 없음 {fmtNum(d.table.missing_events)}건</span>
        <span>최대 {d.table.limit}개 그룹</span>
      </div>
      {d.table.approximate && <p className="notice">상위 집계는 근삿값입니다. 분산 색인의 상위 그룹·건수에는 오차가 있을 수 있습니다. 원본 로그에서 범위를 확인하세요.</p>}
      <p className="muted small">bytes_out은 로그에 기록된 값의 합계입니다. 수집 중복·로그 종류별 방향 차이로 실제 전송량과 다를 수 있습니다. 로그 종류를 먼저 좁혀 비교하세요.</p>
      <div style={{ overflowX: "auto" }}>
        <table className="t" aria-label="로그별 통계">
          <thead><tr><th>분류 값</th><th>건수</th><th>선택 전체 대비</th><th>bytes_out 합계</th><th>최초 ~ 최종</th><th>근거</th></tr></thead>
          <tbody>{d.table.rows.map((row: any) => {
            const name = label(row.key);
            return <tr key={JSON.stringify(row.key)}>
              <td style={{ maxWidth: 300, overflowWrap: "anywhere" }}>{name}</td><td>{fmtNum(row.count)}</td>
              <td>{d.summary.matched_events ? (row.count * 100 / d.summary.matched_events).toFixed(1) : "0.0"}%</td>
              <td>{row.bytes_out_sum === null ? "값 없음" : fmtBytes(row.bytes_out_sum)}
                <div className="small muted">값이 있는 기록 {fmtNum(row.bytes_out_known_events)}건</div></td>
              <td>{fmtTime(row.first_ts)} ~ {fmtTime(row.last_ts)}</td>
              <td><button className="btn sm" aria-label={`${name} 원본 로그`} onClick={() => raw(row.filter)}>원본 로그</button>
                <button className="btn sm ghost" onClick={() => row.filter.forEach((f: Filter) => ctx.addFilter(f))}>이 조건으로 좁히기</button></td>
            </tr>;
          })}</tbody>
        </table>
      </div>
      {!d.table.rows.length && <p className="muted">현재 조건에서 분류할 기록이 없습니다. 분류 값 누락과 필터 범위를 확인하세요.</p>}
      <p className="small muted">정상 로그 사이의 후보는 탐지 결과에서 ‘동일 서비스 대비 행동 차이 가능성’을 확인하세요. 비교 조건·표본 부족 안내와 정상 업무 가능성을 함께 검토합니다.</p>
    </>}
  </div>;
}
