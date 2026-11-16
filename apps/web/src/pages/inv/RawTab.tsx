import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useMemo, useRef, useState } from "react";
import { CheckDialog, MarkBadges, useMarks } from "../../components/Checks";
import { ErrorBox, Loading } from "../../components/common";
import { entityKey, useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtNum, fmtPeriod, getTz } from "../../lib/format";
import { scopeKeyOf } from "../../context/invContext";
import { ALL_COLS, columnLabel, type ColumnMode, displayField, PRESETS, PROFILE_NAMES, profileForScope, readColumnPref, valueOf } from "./evidenceView";
import "./evidenceView.css";

// The table keeps one section of the result in memory. Past it the analyst moves to the next section (the
// previous one is released) or exports the whole result on the server; the browser never holds everything.
export const MAX_LOADED = 20_000;

/** Analyst table (docs/14 §5, docs/02 §50): virtualized, column show/hide/resize, header top-values with Include/Exclude/Pivot. */
export function RawTab({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const [pref, setPref] = useState(readColumnPref);
  const scoped = !!ctx.filters.length || !!ctx.time;
  const sources = useQuery({ queryKey: ["agg", inv, "data_source"], staleTime: 30_000,
    queryFn: () => api.post(`/investigations/${inv}/query/aggregate`, {filters:[],agg:{type:"terms",field:"data_source",size:20}}) });
  const profile = profileForScope(ctx.filters, sources.data);
  // An activity's evidence opens with the columns that check its claim (e.g. allowed/blocked for a FW sweep),
  // for exactly the scope it opened; the analyst's own column choice always wins.
  const claim = ctx.evidenceColumns && ctx.evidenceColumns.key === scopeKeyOf(ctx.filters, ctx.time) ? ctx.evidenceColumns : null;
  const cols = pref.mode === "custom" ? pref.custom : pref.mode === "auto" && claim ? claim.cols : PRESETS[pref.mode === "auto" ? profile : pref.mode];
  const setCols = (custom: string[]) => { if(custom.length) setPref({mode:"custom",custom}); };
  const label = (field: string) => columnLabel(field, profile);
  const [widths, setWidths] = useState<Record<string, number>>({});
  const [head, setHead] = useState<string | null>(null);
  const [sort, setSort] = useState<"asc" | "desc">("asc");
  const parent = useRef<HTMLDivElement>(null);
  useEffect(() => { try { localStorage.setItem("saw.rawview.v1", JSON.stringify(pref)); } catch { /* private browsing */ } }, [pref]);
  const body = { filters: ctx.filters, time: ctx.time, sort };
  // Sections: each starts at a cursor; moving on keeps only the cursors of earlier sections, not their rows.
  const scopeKey = JSON.stringify([inv, body]);
  const [paging, setPaging] = useState<{scope: string; cursors: (string|null)[]}>({scope:scopeKey, cursors:[null]});
  // Discard the previous scope's cursor before querying, not in a later render.
  const sections = paging.scope === scopeKey ? paging.cursors : [null];
  const setSections = (cursors: (string|null)[]) => setPaging({scope:scopeKey,cursors});
  const start = sections[sections.length - 1];
  useEffect(() => { if(parent.current) parent.current.scrollTop = 0; }, [scopeKey,start]);
  const q = useInfiniteQuery({
    queryKey: ["raw", inv, body, start],
    queryFn: ({ pageParam }) => api.post(`/investigations/${inv}/query/events`, { ...body, limit: 500, cursor: pageParam }),
    initialPageParam: start, getNextPageParam: (l: any) => l.next_cursor, gcTime: 0,
  });
  const all = useQuery({ queryKey: ["rawcount", inv, body.filters, body.time], queryFn: () => api.post(`/investigations/${inv}/query/aggregate`, { filters: ctx.filters, time: ctx.time, agg: { type: "count" } }) });
  const totalCount: number | null = all.data?.value ?? all.data?.count ?? null;
  const whole = useQuery({queryKey:["rawcount",inv,[],null], enabled:scoped, staleTime:30_000,
    queryFn:() => api.post(`/investigations/${inv}/query/aggregate`,{filters:[],time:null,agg:{type:"count"}})});
  const wholeCount = scoped ? whole.data?.value ?? whole.data?.count ?? null : totalCount;
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
  const v = useVirtualizer({ count: rows.length, getScrollElement: () => parent.current, estimateSize: () => 32, overscan: 24 });
  const vi = v.getVirtualItems();
  const lastIdx = vi.length ? vi[vi.length - 1].index : -1;
  const capped = rows.length >= MAX_LOADED && !!q.hasNextPage;
  useEffect(() => { if (lastIdx >= rows.length - 20 && q.hasNextPage && !q.isFetchingNextPage && rows.length < MAX_LOADED) q.fetchNextPage(); }, [lastIdx, rows.length, q.hasNextPage, q.isFetchingNextPage]); // eslint-disable-line
  const sel = entityKey(ctx.selection);
  const marks = useMarks(inv);
  const [checking, setChecking] = useState(false);
  // "판단 남기기" from an activity: once its records are loaded, open the dialog for exactly that scope, so the
  // judgement states how many records were actually loaded and read.
  useEffect(() => {
    if (ctx.judgeScope && ctx.judgeScope === scopeKeyOf(ctx.filters, ctx.time) && rows.length && !q.isFetching) {
      setChecking(true); ctx.set({ judgeScope: null });
    }
  }, [ctx.judgeScope, rows.length, q.isFetching]); // eslint-disable-line react-hooks/exhaustive-deps
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
  const parentMarks = (e: any) => [e.src_ip && marks.data?.entities?.[`ip:${e.src_ip}`], e.dst_ip && marks.data?.entities?.[`ip:${e.dst_ip}`], e.domain && marks.data?.entities?.[`domain:${String(e.domain).toLowerCase()}`]].flatMap((x) => x || []);
  const exportCsv = () => {
    const esc = (x: unknown) => { let s = String(x ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; }; // CSV injection guard
    const csv = [cols.join(","), ...rows.map((r: any) => cols.map((c) => { const x = valueOf(r, c); return esc(Array.isArray(x) ? x.join("|") : x); }).join(","))].join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    a.download = `saw_events_${inv.slice(0, 8)}.csv`;
    a.click();
  };
  const w = (c: string) => widths[c] || (c === "uri" || c === "user_agent" ? 200 : c === "hostname" ? 150 : c === "timestamp" ? 176 : ["src_ip","dst_ip"].includes(c) ? 128 : 96);
  const changeMode = (mode: ColumnMode) => { setPref({mode, custom:pref.custom.length ? pref.custom : [...cols]}); setHead(null); };
  return (
    <div className="col evidence-table">
      <section className="evidence-scope" aria-label="로그 조회 범위">
        <div className="row wrap"><h3>로그 기록</h3><span className="tag">{scoped ? "현재 검색 범위" : "조사 전체"}</span>{scoped && <span className="muted">조사 전체 {wholeCount == null ? "건수 미확인" : `${fmtNum(wholeCount)}건`}</span>}</div>
        <div role="status">조건에 맞는 전체 {totalCount == null ? (all.isError ? "건수 미확인" : "집계 중") : `${fmtNum(totalCount)}건`}{rows.length ? ` · 화면 ${fmtNum(before + 1)}~${fmtNum(before + rows.length)}번째` : ""}{q.hasNextPage ? " · 다음 기록 있음" : ""}</div>
        <div className="muted small">{ctx.time ? `검색 기간 ${fmtPeriod(ctx.time.start, ctx.time.end)} ${getTz()}${ctx.time.end_exclusive ? " (끝 시각 제외)" : ""}` : "전체 저장 기간"} · {ctx.filters.length ? `검색 조건 ${ctx.filters.length}개` : "검색 조건 없음"} · 민감값 가림</div>
      </section>
      <div className="row wrap evidence-tools">
        <select className="input" aria-label="로그 표 구성" value={pref.mode} onChange={e=>changeMode(e.target.value as ColumnMode)}>
          <option value="auto">자동 · {claim ? claim.label : PROFILE_NAMES[profile]}</option><option value="http">NDR·HTTP 열</option><option value="network">FW·연결 열</option>
          <option value="common">공통 열</option><option value="custom">내가 선택한 열</option>
        </select>
        <button className="btn sm" onClick={() => setSort(sort === "asc" ? "desc" : "asc")}>{sort === "asc" ? "시간순 ↑" : "최신순 ↓"}</button>
        <details className="evidence-options"><summary className="btn sm">열 편집</summary>
          <div className="panel pb evidence-columns">{ALL_COLS.map((c) => <label key={c} className="row small"><input type="checkbox" checked={cols.includes(c)} disabled={cols.length === 1 && cols[0] === c} onChange={(e) => setCols(e.target.checked ? [...cols, c] : cols.filter((x) => x !== c))} />{label(c)}</label>)}</div></details>
        <details className="evidence-options"><summary className="btn sm">CSV 내보내기</summary><div className="panel pb evidence-export">
          <button className="btn sm" onClick={exportAll} disabled={!!exporting && exporting.endsWith("…")}>조건 전체 결과 CSV (서버, 가림)</button>
          <button className="btn sm" onClick={exportCsv} disabled={!rows.length}>화면의 행만 CSV (가림)</button></div></details>
        <button className="btn sm" disabled={!rows.length} onClick={() => setChecking(true)} title="지금 검색 결과에 대해 무엇을 확인했는지 남깁니다 (일부만 봤다면 표본으로)">✓ 검색 결과 확인 기록</button>
      </div>
      {exporting && <div className="small" role="status">{exporting}</div>}
      {(capped || sections.length > 1) && (
        <div className="row wrap small" role="status" style={{ gap: 6 }}>
          <span className="muted">한 번에 {fmtNum(MAX_LOADED)}건씩 봅니다. 전체 결과는 CSV로 내보낼 수 있습니다.</span>
          <button className="btn sm" disabled={sections.length < 2} onClick={() => setSections(sections.slice(0, -1))}>← 이전 {fmtNum(MAX_LOADED)}건</button>
          <button className="btn sm" disabled={!capped} onClick={nextSection}>다음 {fmtNum(MAX_LOADED)}건 →</button>
        </div>)}
      {head && (
        <div className="panel"><div className="ph"><span className="grow">{isTime ? "날짜별 기록 수 · KST" : `상위 값 · ${label(head)}`}</span><button className="btn ghost sm" aria-label="상위 값 닫기" onClick={() => setHead(null)}>✕</button></div>
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
      {!q.isLoading && !q.isError && !rows.length && <p className="muted">{scoped ? "현재 검색 범위에 일치하는 로그가 없습니다. 기간과 검색 조건을 확인하세요." : "이 조사에 저장된 로그가 없습니다."}</p>}
      {checking && (total.data || total.error) && (
        <CheckDialog inv={inv} onClose={() => setChecking(false)} target={{ type: "set", key: "", label: `검색 결과 (${ctx.filters.length ? ctx.filters.map((f: any) => `${f.field} ${f.op} ${f.value}`).join(", ") : "조건 없음"})`,
          time: [ctx.time?.start, ctx.time?.end], set: { query: { filters: ctx.filters, time: ctx.time }, total: total.data?.value ?? total.data?.count ?? null, loaded: rows.map((r: any) => r.event_id) } }} />
      )}
      <div ref={parent} className="scroll evidence-scroll" role="table" aria-label="조회한 로그 기록">
        <div role="row" className="evidence-head">
          <div role="columnheader" className="evidence-open" title="기록 상세와 확인 상태">기록 상세</div>
          {cols.map((c) => (
            <div key={c} role="columnheader" className="evidence-column" style={{ width: w(c) }}>
              <button className="evidence-name" title={c} aria-label={`${label(c)} ${c === "timestamp" ? "날짜별 기록 보기" : "상위 값 보기"}`} onClick={() => setHead(c)}>{label(c)}</button>
              <span style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 5, cursor: "col-resize" }} onMouseDown={(e) => {
                e.stopPropagation(); const x0 = e.clientX; const w0 = w(c);
                const mv = (ev: MouseEvent) => setWidths((s) => ({ ...s, [c]: Math.max(50, w0 + ev.clientX - x0) }));
                const up = () => { window.removeEventListener("mousemove", mv); window.removeEventListener("mouseup", up); };
                window.addEventListener("mousemove", mv); window.addEventListener("mouseup", up);
              }} />
            </div>
          ))}
        </div>
        <div role="rowgroup" style={{ height: v.getTotalSize(), position: "relative" }}>
          {vi.map((r) => {
            const e = rows[r.index];
            const hl = sel && (sel === `ip:${e.src_ip}` || sel === `uri:${e.uri_template}`);
            return (
              <div key={r.key} role="row" className="evidence-row" onClick={() => ctx.set({ eventId: e.event_id })} style={{ transform: `translateY(${r.start}px)`, background: ctx.eventId === e.event_id ? "var(--accent-weak)" : hl ? "var(--hl-bg)" : undefined }}>
                <div role="cell" className="evidence-open"><button className="btn sm" aria-label={`${before+r.index+1}번째 기록 상세 보기`} onClick={evt=>{evt.stopPropagation();ctx.set({eventId:e.event_id});}}>보기</button><MarkBadges own={marks.data?.events?.[e.event_id]} parent={parentMarks(e)} /></div>
                {cols.map((c) => <div key={c} role="cell" className="mono ellipsis evidence-cell" style={{ width: w(c) }} title={String(valueOf(e, c) ?? "")}>{displayField(c, valueOf(e, c))}</div>)}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
