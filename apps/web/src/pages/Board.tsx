import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ErrorBox, Loading, Panel } from "../components/common";
import { Badge, EmptyState, PageHeader, Stat } from "../components/ui";
import { api } from "../lib/api";

const PERIODS: [number, string][] = [[7, "최근 7일"], [30, "최근 30일"], [90, "최근 90일"]];

function Bar({ rows, total }: { rows: { key: string; label: string; count: number }[]; total: number }) {
  if (!total) return <span className="muted small">해당 없음</span>;
  return (
    <div className="col" style={{ gap: 6 }}>
      {rows.filter((r) => r.count).map((r) => (
        <div key={r.key} className="row small" style={{ gap: 8 }}>
          <span style={{ width: 130 }}>{r.label}</span>
          <div className="bd-bar"><div className={`bd-fill ${r.key}`} style={{ width: `${Math.max(4, (r.count / total) * 100)}%` }} /></div>
          <b style={{ width: 28, textAlign: "right" }}>{r.count}</b>
        </div>))}
    </div>
  );
}

/** Where every investigation stands, what needs attention first, and the way into each report summary. */
export function Board() {
  const [days, setDays] = useState(30);
  const [only, setOnly] = useState<"all" | "open" | "urgent" | "stale" | "review">("open");
  const q = useQuery({ queryKey: ["board", days], queryFn: () => api.get(`/board?days=${days}`), refetchInterval: 60000 });
  const d = q.data;
  const day = (v?: string | null) => (v ? new Date(v).toLocaleDateString("ko-KR", { month: "2-digit", day: "2-digit" }) : "—");
  const rows = (d?.rows || []).filter((r: any) => only === "all" || (only === "open" && r.status !== "closed") || (only === "urgent" && r.urgent) || (only === "stale" && r.stale) || (only === "review" && r.reviews_open > 0));
  const maxWeek = Math.max(1, ...(d?.weeks || []).map((w: any) => Math.max(w.opened, w.closed)));
  return (
    <div className="page col">
      <PageHeader eyebrow="보고" title="현황판"
        desc={d?.scope === "all" ? "모든 조사의 진행 상황입니다. 먼저 봐야 할 조사가 위에 오고, 각 조사에서 보고용 요약으로 바로 갈 수 있습니다." : "내가 참여한 조사의 진행 상황입니다."}
        actions={<div className="row">{PERIODS.map(([n, l]) => <button key={n} className={`btn sm ${days === n ? "primary" : ""}`} onClick={() => setDays(n)}>{l}</button>)}</div>} />
      <ErrorBox error={q.error} />
      {q.isLoading && <Loading />}
      {d && (
        <>
          <div className="stats">
            <Stat label="진행 중인 조사" value={d.tiles.open} onClick={() => setOnly("open")} />
            <Stat label="높은 위험 · 미종결" value={d.tiles.urgent} tone={d.tiles.urgent ? "high" : undefined} onClick={() => setOnly("urgent")} />
            <Stat label={`${d.stale_days}일 넘게 멈춘 조사`} value={d.tiles.stale} tone={d.tiles.stale ? "high" : undefined} onClick={() => setOnly("stale")} />
            <Stat label="검토가 끝나지 않은 조사" value={d.tiles.review_wait} tone={d.tiles.review_wait ? "high" : undefined} onClick={() => setOnly("review")} />
            <Stat label={`${days}일간 새로 접수`} value={d.tiles.opened} />
            <Stat label={`${days}일간 종결`} value={d.tiles.closed} sub={d.tiles.median_days_to_close != null ? `종결까지 보통 ${d.tiles.median_days_to_close}일` : undefined} />
          </div>
          <div className="grid3">
            <Panel title="진행 중 조사의 위험도"><Bar rows={d.by_risk_open} total={d.tiles.open} /></Panel>
            <Panel title={`${days}일간 종결한 조사의 판정`}><Bar rows={d.by_verdict} total={d.tiles.closed} /></Panel>
            <Panel title="주별 접수·종결">
              <div className="bd-weeks" role="img" aria-label="주별 접수와 종결 건수">
                {d.weeks.map((w: any) => (
                  <div key={w.week} className="bd-week" title={`${w.week} 주: 접수 ${w.opened}, 종결 ${w.closed}`}>
                    <div className="bd-cols"><i className="opened" style={{ height: `${(w.opened / maxWeek) * 100}%` }} /><i className="closed" style={{ height: `${(w.closed / maxWeek) * 100}%` }} /></div>
                    <span>{w.week}</span>
                  </div>))}
              </div>
              <div className="small muted"><i className="bd-dot opened" /> 접수 <i className="bd-dot closed" /> 종결</div>
            </Panel>
          </div>
          {d.by_owner.length > 0 && (
            <Panel title="담당자별 진행 중 조사">
              <table className="t"><thead><tr><th>담당</th><th className="num">진행 중</th><th className="num">높은 위험</th><th className="num">멈춘 조사</th></tr></thead>
                <tbody>{d.by_owner.map((o: any) => <tr key={o.owner}><td>{o.owner}</td><td className="num">{o.open}</td>
                  <td className="num">{o.urgent ? <b className="sev high">{o.urgent}</b> : 0}</td><td className="num">{o.stale ? <b className="sev medium">{o.stale}</b> : 0}</td></tr>)}</tbody></table>
            </Panel>
          )}
          <div className="panel">
            <div className="ph"><span className="grow">조사 {rows.length}건</span>
              {([["open", "진행 중"], ["urgent", "높은 위험"], ["stale", "멈춘 조사"], ["review", "검토 대기"], ["all", "전체"]] as [typeof only, string][]).map(([k, l]) =>
                <button key={k} className={`btn sm ${only === k ? "primary" : "ghost"}`} onClick={() => setOnly(k)}>{l}</button>)}</div>
            {rows.length ? (
              <table className="t"><thead><tr><th>위험도</th><th>조사</th><th>상태</th><th>담당</th><th>접수</th><th className="num">경과</th><th>마지막 작업</th><th className="num">높은 위험 탐지</th><th>검토·지원</th><th></th></tr></thead>
                <tbody>{rows.map((r: any) => (
                  <tr key={r.id}>
                    <td className={`sev ${r.risk_level}`}>{r.risk_ko}</td>
                    <td><Link to={`/inv/${r.id}`} style={{ color: "var(--fg)", fontWeight: 600 }}>{r.title}</Link><div className="mono small muted">{r.display_id}</div></td>
                    <td><Badge tone={r.status === "closed" ? undefined : "accent"}>{r.status_ko}</Badge>{r.verdict_ko && <div className="small muted">{r.verdict_ko}</div>}</td>
                    <td>{r.owner || "—"}</td><td className="small">{day(r.created_at)}</td><td className="num">{r.age_days}일</td>
                    <td className="small">{day(r.last_activity)}{r.stale && <div><Badge tone="warn">{r.idle_days}일째 멈춤</Badge></div>}</td>
                    <td className="num">{r.high_findings ? <b className="sev high">{r.high_findings}</b> : 0}</td>
                    <td>{r.reviews_open ? <Badge tone="warn">검토 대기 {r.reviews_open}</Badge> : null}{r.support_open ? <Badge tone="accent">지원 진행 {r.support_open}</Badge> : null}
                      {!r.reviews_open && !r.support_open && <span className="muted small">—</span>}</td>
                    <td><Link className="btn sm" to={`/inv/${r.id}/report`}>보고용 요약</Link></td>
                  </tr>))}</tbody></table>
            ) : <EmptyState title="해당하는 조사가 없습니다">위의 단추로 다른 조건을 골라 보세요.</EmptyState>}
          </div>
        </>
      )}
    </div>
  );
}
