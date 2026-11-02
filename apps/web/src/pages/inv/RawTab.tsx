import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useMemo, useRef, useState } from "react";
import { CheckDialog, MarkBadges, useMarks } from "../../components/Checks";
import { ErrorBox, Loading } from "../../components/common";
import { entityKey, useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtNum, fmtTime } from "../../lib/format";

const ALL_COLS = ["timestamp", "data_source", "src_ip", "src_cloud", "method", "hostname", "uri", "uri_template", "status_code", "bytes_out", "bytes_in", "user_agent", "ua_class", "domain", "dst_ip", "dst_port", "protocol", "enforcement_action", "user", "tags", "source_file"];
const DEFAULT = ["timestamp", "data_source", "src_ip", "method", "uri", "status_code", "bytes_out", "user_agent"];

// The table keeps one section of the result in memory. Past it the analyst moves to the next section (the
// previous one is released) or exports the whole result on the server; the browser never holds everything.
export const MAX_LOADED = 20_000;

function loadCols(): string[] {
  try { return JSON.parse(localStorage.getItem("saw.rawcols") || "null") || DEFAULT; } catch { return DEFAULT; }
}

/** Analyst table (docs/14 §5, docs/02 §50): virtualized, column show/hide/resize, header top-values with Include/Exclude/Pivot. */
export function RawTab({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const [cols, setCols] = useState<string[]>(loadCols);
  const [widths, setWidths] = useState<Record<string, number>>({});
  const [head, setHead] = useState<string | null>(null);
  const [sort, setSort] = useState<"asc" | "desc">("asc");
  const parent = useRef<HTMLDivElement>(null);
  useEffect(() => { try { localStorage.setItem("saw.rawcols", JSON.stringify(cols)); } catch { /* ignore */ } }, [cols]);
  const body = { filters: ctx.filters, time: ctx.time, sort };
  // Sections: each starts at a cursor; moving on keeps only the cursors of earlier sections, not their rows.
  const [sections, setSections] = useState<(string | null)[]>([null]);
  const start = sections[sections.length - 1];
  useEffect(() => { setSections([null]); }, [JSON.stringify(body)]); // eslint-disable-line react-hooks/exhaustive-deps
  const q = useInfiniteQuery({
    queryKey: ["raw", inv, body, start],
    queryFn: ({ pageParam }) => api.post(`/investigations/${inv}/query/events`, { ...body, limit: 500, cursor: pageParam }),
    initialPageParam: start, getNextPageParam: (l: any) => l.next_cursor,
  });
  const all = useQuery({ queryKey: ["rawcount", inv, body.filters, body.time], queryFn: () => api.post(`/investigations/${inv}/query/aggregate`, { filters: ctx.filters, time: ctx.time, agg: { type: "count" } }) });
  const totalCount: number | null = all.data?.value ?? all.data?.count ?? null;
  // The time column has no "top values": it shows records per day (Asia/Seoul) and narrows by a day range,
  // so no filter ever compares the timestamp with another column's value.
  const isTime = head === "timestamp";
  const top = useQuery({ queryKey: ["top", inv, head, body], enabled: !!head, queryFn: () => api.post(`/investigations/${inv}/query/aggregate`, { filters: ctx.filters, time: ctx.time,
    agg: isTime ? { type: "date_histogram", field: "timestamp", interval_sec: 3600 } : { type: "terms", field: head, size: 10 } }) });
  const perDay = isTime ? Object.entries((top.data?.buckets || []).reduce((acc: Record<string, number>, b: any) => {
    const day = new Date((Number(b.key) + 9 * 3600) * 1000).toISOString().slice(0, 10);
    acc[day] = (acc[day] || 0) + b.count; return acc; }, {})).filter(([, n]) => n) : [];
  const nextDay = (day: string) => new Date(Date.parse(`${day}T00:00:00Z`) + 86400000).toISOString().slice(0, 10);
  const rows = useMemo(() => (q.data?.pages || []).flatMap((p: any) => p.events), [q.data]);
  const v = useVirtualizer({ count: rows.length, getScrollElement: () => parent.current, estimateSize: () => 24, overscan: 30 });
  const vi = v.getVirtualItems();
  const lastIdx = vi.length ? vi[vi.length - 1].index : -1;
  const capped = rows.length >= MAX_LOADED && !!q.hasNextPage;
  useEffect(() => { if (lastIdx >= rows.length - 20 && q.hasNextPage && !q.isFetchingNextPage && rows.length < MAX_LOADED) q.fetchNextPage(); }, [lastIdx, rows.length, q.hasNextPage, q.isFetchingNextPage]); // eslint-disable-line
  const sel = entityKey(ctx.selection);
  const marks = useMarks(inv);
  const [checking, setChecking] = useState(false);
  const total = all;
  const before = (sections.length - 1) * MAX_LOADED;
  const nextSection = () => { const last = (q.data?.pages || []).slice(-1)[0]?.next_cursor; if (last) setSections([...sections, last]); };
  const [exporting, setExporting] = useState<string | null>(null);
  const exportAll = async () => {
    setExporting("서버에서 전체 결과를 만드는 중…");
    try {
      const r = await api.downloadPost(`/investigations/${inv}/query/events/export`, { filters: ctx.filters, time: ctx.time, columns: cols }, `saw_events_${inv.slice(0, 8)}_all.csv`);
      setExporting(r.headers.get("x-saw-truncated") === "true"
        ? `전체 ${fmtNum(Number(r.headers.get("x-saw-total")))}건 중 ${fmtNum(Number(r.headers.get("x-saw-rows")))}건까지만 내보냈습니다(서버 한도). 조건을 나눠 내보내세요.`
        : `조건에 맞는 전체 ${fmtNum(Number(r.headers.get("x-saw-rows")))}건을 내보냈습니다.`);
    } catch (e) { setExporting(`내보내기 실패: ${(e as Error).message}`); }
  };
  const parentMarks = (e: any) => [e.src_ip && marks.data?.entities[`ip:${e.src_ip}`], e.dst_ip && marks.data?.entities[`ip:${e.dst_ip}`], e.domain && marks.data?.entities[`domain:${String(e.domain).toLowerCase()}`]].flatMap((x) => x || []);
  const exportCsv = () => {
    const esc = (x: unknown) => { let s = String(x ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; }; // CSV injection guard
    const csv = [cols.join(","), ...rows.map((r: any) => cols.map((c) => esc(Array.isArray(r[c]) ? r[c].join("|") : r[c])).join(","))].join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    a.download = `saw_events_${inv.slice(0, 8)}.csv`;
    a.click();
  };
  const w = (c: string) => widths[c] || (c === "uri" || c === "user_agent" ? 320 : c === "timestamp" ? 130 : 110);
  return (
    <div className="col" style={{ height: "100%" }}>
      <div className="row wrap small">
        <b>원본 로그</b><span className="muted" role="status">조건에 맞는 전체 {totalCount == null ? "…" : fmtNum(totalCount)}건 · 화면 {fmtNum(before + (rows.length ? 1 : 0))}~{fmtNum(before + rows.length)}번째{q.hasNextPage ? " · 다음 기록 있음" : ""} · 민감값 가림 · 열 제목을 누르면 상위 값</span>
        <button className="btn sm" onClick={() => setSort(sort === "asc" ? "desc" : "asc")}>시간 {sort === "asc" ? "↑" : "↓"}</button>
        {/* Default columns per export kind; every original column stays reachable in the record detail. */}
        <button className="btn sm" onClick={() => setCols(["timestamp", "src_ip", "dst_ip", "hostname", "method", "uri", "status_code", "bytes_out", "bytes_in"])}>NDR 기본 열</button>
        <button className="btn sm" onClick={() => setCols(["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "enforcement_action", "bytes_out", "bytes_in"])}>FW 기본 열</button>
        <details><summary className="btn sm">표시할 열</summary><div className="panel pb" style={{ position: "absolute", zIndex: 5 }}>{ALL_COLS.map((c) => <label key={c} className="row small"><input type="checkbox" checked={cols.includes(c)} onChange={(e) => setCols(e.target.checked ? [...cols, c] : cols.filter((x) => x !== c))} />{c}</label>)}</div></details>
        <button className="btn sm" onClick={exportCsv} title="화면에 불러온 행만 내보냅니다">화면의 행만 CSV (가림)</button>
        <button className="btn sm" onClick={exportAll} disabled={!!exporting && exporting.endsWith("…")} title="조건에 맞는 모든 기록을 서버에서 CSV로 만듭니다">조건 전체 결과 CSV (서버, 가림)</button>
        <button className="btn sm" disabled={!rows.length} onClick={() => setChecking(true)} title="지금 검색 결과에 대해 무엇을 확인했는지 남깁니다 (일부만 봤다면 표본으로)">✓ 검색 결과 확인 기록</button>
      </div>
      {exporting && <div className="small" role="status">{exporting}</div>}
      {(capped || sections.length > 1) && (
        <div className="row wrap small" role="status" style={{ gap: 6 }}>
          <span className="error">한 번에 {fmtNum(MAX_LOADED)}건씩 봅니다(브라우저 메모리 보호). 다른 구간으로 넘어가면 지금 구간은 화면에서 내려갑니다.</span>
          <button className="btn sm" disabled={sections.length < 2} onClick={() => setSections(sections.slice(0, -1))}>← 이전 {fmtNum(MAX_LOADED)}건</button>
          <button className="btn sm" disabled={!capped} onClick={nextSection}>다음 {fmtNum(MAX_LOADED)}건 →</button>
        </div>)}
      {head && (
        <div className="panel"><div className="ph"><span className="grow">{isTime ? "날짜별 기록 수 · 시간" : `상위 값 · ${head}`}</span><button className="btn ghost sm" onClick={() => setHead(null)}>✕</button></div>
          {isTime && <div className="pb">{perDay.map(([day, n]) => (
            <div key={day} className="row small"><span className="mono grow">{day}</span><span className="num">{fmtNum(n as number)}</span>
              <button className="btn sm" onClick={() => ctx.set({ time: { start: `${day}T00:00:00+09:00`, end: `${nextDay(day)}T00:00:00+09:00`, end_exclusive: true } })}>이 날로 좁히기</button>
            </div>))}</div>}
          {!isTime && <div className="pb">{(top.data?.buckets || []).map((b: any) => (
            <div key={String(b.key)} className="row small"><span className="mono grow ellipsis">{String(b.key)}</span><span className="num">{fmtNum(b.count)}</span>
              <button className="btn sm" onClick={() => ctx.addFilter({ field: head, op: "is", value: b.key })}>포함</button>
              <button className="btn sm" onClick={() => ctx.addFilter({ field: head, op: "is_not", value: b.key })}>제외</button>
              {head === "src_ip" && <button className="btn sm" onClick={() => ctx.set({ tab: "entity", selection: { type: "ip", value: String(b.key) } })}>출발지 상세</button>}
            </div>))}</div>}</div>
      )}
      {q.isLoading && <Loading />}
      <ErrorBox error={q.error} />
      {checking && (total.data || total.error) && (
        <CheckDialog inv={inv} onClose={() => setChecking(false)} target={{ type: "set", key: "", label: `검색 결과 (${ctx.filters.length ? ctx.filters.map((f: any) => `${f.field} ${f.op} ${f.value}`).join(", ") : "조건 없음"})`,
          time: [ctx.time?.start, ctx.time?.end], set: { query: { filters: ctx.filters, time: ctx.time }, total: total.data?.value ?? total.data?.count ?? null, loaded: rows.map((r: any) => r.event_id) } }} />
      )}
      <div ref={parent} className="scroll" style={{ flex: 1, minHeight: 300 }}>
        <div style={{ display: "flex", position: "sticky", top: 0, zIndex: 2, background: "var(--bg-2)", borderBottom: "1px solid var(--line-2)" }}>
          <div className="small" style={{ width: 96, flex: "none", padding: "3px 6px", fontWeight: 600 }} title="✓ 이 기록을 직접 확인 · ↑ 이 기록의 주소·이름에 대한 확인(참고)">확인</div>
          {cols.map((c) => (
            <div key={c} className="small" style={{ width: w(c), flex: "none", padding: "3px 6px", fontWeight: 600, position: "relative", cursor: "pointer" }} onClick={() => setHead(c)}>
              {c}
              <span style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 5, cursor: "col-resize" }} onMouseDown={(e) => {
                e.stopPropagation(); const x0 = e.clientX; const w0 = w(c);
                const mv = (ev: MouseEvent) => setWidths((s) => ({ ...s, [c]: Math.max(50, w0 + ev.clientX - x0) }));
                const up = () => { window.removeEventListener("mousemove", mv); window.removeEventListener("mouseup", up); };
                window.addEventListener("mousemove", mv); window.addEventListener("mouseup", up);
              }} />
            </div>
          ))}
        </div>
        <div style={{ height: v.getTotalSize(), position: "relative" }}>
          {vi.map((r) => {
            const e = rows[r.index];
            const hl = sel && (sel === `ip:${e.src_ip}` || sel === `uri:${e.uri_template}`);
            return (
              <div key={r.key} onClick={() => ctx.set({ eventId: e.event_id })} style={{ position: "absolute", top: 0, transform: `translateY(${r.start}px)`, display: "flex", height: 24, alignItems: "center", cursor: "pointer", borderBottom: "1px solid var(--line)", background: ctx.eventId === e.event_id ? "var(--accent-weak)" : hl ? "var(--hl-bg)" : undefined }}>
                <div style={{ width: 96, flex: "none", padding: "0 6px", overflow: "hidden" }}><MarkBadges own={marks.data?.events[e.event_id]} parent={parentMarks(e)} /></div>
                {cols.map((c) => <div key={c} className="mono ellipsis small" style={{ width: w(c), flex: "none", padding: "0 6px" }} title={String(e[c] ?? "")}>{c === "timestamp" ? fmtTime(e[c]) : Array.isArray(e[c]) ? e[c].join(" ") : String(e[c] ?? "")}</div>)}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
