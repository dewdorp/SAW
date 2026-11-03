import { ErrorBox } from "../../components/common";
import { fmtNum } from "../../lib/format";

export const SOURCE_NAMES: Record<string, string> = {
  firewall: "방화벽", connection: "연결 기록", web: "HTTP 요청(NDR·웹)", waf: "웹 방화벽", ips: "IPS", ddos: "DDoS",
  zeek_conn: "패킷 연결", zeek_dns: "패킷 DNS", zeek_http: "패킷 HTTP", zeek_ssl: "패킷 TLS", suricata: "IDS 경보",
};
const RUN: Record<string, string> = { running: "진행 중", queued: "대기 중", failed: "실패", cancelled: "취소", partial: "일부만 처리", complete: "완료" };
const PARSER_NAMES: Record<string, string> = { ko_fw_csv: "방화벽(FW)", en_fw_csv:"방화벽(FW)", ko_ndr_csv:"NDR", en_ndr_http_csv:"NDR HTTP" };
// Different appliances can normalize to the same event type. Only name equipment from actual parser metadata
// when the complete file list accounts for the whole denominator. Under a filter use its real source buckets.
function sourceCounts(d: any): { label: string; count: number }[] {
  const f = d.inputs, rows = f.by_file;
  if (d.basis.kind === "all" && !f.files_truncated && rows.length > 0 && rows.length === f.files &&
      rows.every((x: any) => PARSER_NAMES[x.parser_id] && Number.isFinite(x.events)) &&
      rows.reduce((n: number, x: any) => n + x.events,0) === d.basis.all_events) {
    const counts = new Map<string,number>();
    for (const row of rows) { const label = PARSER_NAMES[row.parser_id]; counts.set(label,(counts.get(label) || 0) + row.events); }
    return [...counts].map(([label,count]) => ({label,count})).sort((a,b) => b.count-a.count);
  }
  return (d.breakdown.data_source?.buckets || []).map((b:any) => ({label:SOURCE_NAMES[b.key] || String(b.key),count:b.count}));
}

/** "2026년 9월 5일 ~ 10월 10일" in the investigation's zone; an exclusive midnight end names the last included day. */
export function dayRange(start?: string | null, end?: string | null, zone = "Asia/Seoul"): string {
  const day = (s: string, back = false) => {
    let t = new Date(/[zZ]|[+-]\d{2}:\d{2}$/.test(s) ? s : s.replace(" ", "T") + "Z").getTime();
    if (!Number.isFinite(t)) return null;
    const hm = new Intl.DateTimeFormat("en-GB", { timeZone: zone, hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" }).format(t);
    if (back && hm === "00:00:00") t -= 1000;
    const v = Object.fromEntries(new Intl.DateTimeFormat("en-GB", { timeZone: zone, year: "numeric", month: "numeric", day: "numeric" })
      .formatToParts(t).map(x => [x.type, x.value]));
    return { y: v.year, text: `${Number(v.month)}월 ${Number(v.day)}일` };
  };
  const a = start ? day(start) : null, b = end ? day(end, true) : null;
  if (!a && !b) return "기간 미확인";
  if (!a || !b) return `${(a || b)!.y}년 ${(a || b)!.text}`;
  return `${a.y}년 ${a.text} ~ ${b.y === a.y ? "" : b.y + "년 "}${b.text}`;
}

type Day = { date: string; count: number };
// Adjacent days are summed for long periods; no busy day is discarded by downsampling.
function DailyStrip({ days, filtered, zone, onOpen }: { days: Day[]; filtered: boolean; zone: string; onOpen: () => void }) {
  if (!days.length) return <div className="scope-trend"><span>기간별 기록</span><b>표시할 시각 자료 없음</b></div>;
  const stride = Math.max(1, Math.ceil(days.length / 60));
  const groups = Array.from({ length: Math.ceil(days.length / stride) }, (_, i) => {
    const part = days.slice(i * stride, (i + 1) * stride);
    return { label: part.length > 1 ? part[0].date + " ~ " + part[part.length - 1].date : part[0].date,
      count: part.reduce((n, d) => n + d.count, 0) };
  });
  const max = Math.max(1, ...groups.map(v => v.count));
  return <button type="button" className="scope-trend" onClick={onOpen} aria-label="기간별 추이 자세히 보기">
    <span>{filtered ? "현재 조건 · " : ""}{stride === 1 ? "일별" : stride + "일 합계"} 기록 <span aria-hidden="true">↗</span></span>
    <svg role="img" aria-label={`기간별 기록 수, ${zone}. ${groups[0].label}부터 ${groups[groups.length - 1].label}까지.`}
      viewBox={`0 0 ${groups.length * 5} 26`} preserveAspectRatio="none">
      {groups.map((g, i) => <rect key={g.label} x={5*i} y={26 - (g.count ? Math.max(1, 25*g.count/max) : 1)} width={4}
        height={g.count ? Math.max(1,25*g.count/max) : 1} fill={g.count ? "var(--accent)" : "var(--fg-2)"}>
        <title>{g.label} · {fmtNum(g.count)}건</title></rect>)}
    </svg>
    <small>{days[0].date} ~ {days[days.length - 1].date} · {zone === "Asia/Seoul" ? "KST" : zone}</small>
  </button>;
}

export function ScopeSnapshot({ data: d, error, openAll, openStats, openDetail }: {
  data?: any; error: unknown; openAll: () => void; openStats: () => void; openDetail: (key: "quality" | "time") => void;
}) {
  const filtered = d?.basis.kind === "filter";
  const files = d?.inputs;
  const issues: string[] = [];
  if (d) {
    if (files.failed_lines) issues.push(`읽지 못한 줄 ${fmtNum(files.failed_lines)}줄`);
    if (files.rejected_events) issues.push(`저장 거부 ${fmtNum(files.rejected_events)}건`);
    if (files.unsupported_files) issues.push(`미지원·처리 실패 파일 ${fmtNum(files.unsupported_files)}개`);
    if (d.time.without_timestamp) issues.push(`시각 미확인 ${fmtNum(d.time.without_timestamp)}건`);
    if (d.time.empty_days.length) issues.push(`기록 없는 날 ${fmtNum(d.time.empty_days.length)}일`);
    if (files.files_with_notes && !issues.length) issues.push(`확인할 파일 ${fmtNum(files.files_with_notes)}개`);
  }
  const sources = d ? sourceCounts(d) : [];
  const incomplete = d?.analysis?.incomplete?.length ?? 0;
  const status = d?.analysis?.status;
  const declared = d?.scope.period_declared;
  const line: string[] | null = !d ? null : [d.scope.org_unit || "관계사 미지정",
    `${dayRange(declared ? d.scope.period_start : d.scope.observed_start, declared ? d.scope.period_end : d.scope.observed_end, d.scope.timezone)}${declared ? "" : " (기록 기준)"}`,
    sources.length ? sources.slice(0, 4).map(b => `${b.label} ${fmtNum(b.count)}건`).join(" · ") : null,
    `전체 ${fmtNum(d.basis.all_events)}건`].filter((x): x is string => !!x);
  const toActivities = () => {
    const target = document.getElementById("review-activities");
    target?.scrollIntoView?.({ block: "start" });
    target?.focus({ preventScroll: true });
  };
  return <section className="scope-snapshot" aria-label="자료 현황">
    {line && <p className="scope-line" aria-label="자료 요약">{line.map((part, i) => <span key={i}>{part}</span>)}</p>}
    <header><h2>자료 현황</h2><div className="row wrap">
      <button type="button" className="btn sm skip-activities" onClick={toActivities}>검토할 활동으로 이동</button>
      <button type="button" className="btn sm" onClick={openAll}>전체 로그 보기</button>
      <button type="button" className="btn sm ghost" onClick={openStats}>전체 로그 통계</button>
    </div></header>
    {d && !!error && <p role="status">최신 집계에 실패해 마지막 조회 결과를 표시합니다.</p>}
    {!d ? (error ? <ErrorBox error={error} /> : <p role="status">자료 범위와 건수를 집계하고 있습니다…</p>) : <>
      <div className="scope-metrics">
        <div className="scope-count"><span>조사 전체 로그</span><strong>{fmtNum(d.basis.all_events)}</strong><small>건</small></div>
        <div className="scope-count"><span>입력 파일</span><strong>{fmtNum(files.files)}</strong><small>개</small></div>
        <div className="scope-count scope-run"><span>최근 탐지 실행</span><b>{!status ? "실행 기록 없음" : status === "complete" && incomplete ? "일부만 처리" : RUN[status] || status}</b>
          {incomplete > 0 && <small>미완료 분석 {fmtNum(incomplete)}개</small>}</div>
        <DailyStrip days={d.time.daily} zone={d.scope.timezone} filtered={filtered} onOpen={() => openDetail("time")} />
      </div>
      {filtered && <p className="scope-filter-note">현재 검색 조건: {fmtNum(d.basis.events)}건. 위의 전체 로그·통계 버튼은 검색 조건을 해제합니다.</p>}
      {sources.length > 0 && <div className="scope-sources"><b>{filtered ? "현재 조건의 원천" : "로그 원천"}</b>
        {sources.slice(0, 4).map(b => <span key={b.label}>{b.label} <strong>{fmtNum(b.count)}건</strong></span>)}
        {(sources.length > 4 || d.breakdown.data_source?.other > 0) && <span>그 외 원천 있음</span>}
      </div>}
      {issues.length > 0 && <button type="button" className="scope-issues" onClick={() => openDetail("quality")}>
        <b>자료 확인</b><span>{issues.join(" · ")}</span><span className="scope-more">상세 보기 ↗</span></button>}
    </>}
  </section>;
}
