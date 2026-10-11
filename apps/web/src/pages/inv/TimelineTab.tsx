import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useMemo, useRef } from "react";
import { ErrorBox, Loading, Sev } from "../../components/common";
import { entityKey, useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { dur, fmtNum, fmtTime } from "../../lib/format";
import { axisStyle, EChart, safeTooltip } from "../../viz/EChart";
import { MAX_LOADED } from "./RawTab";

const SRC_COLOR: Record<string, string> = { web: "#4c8dff", waf: "#f5b324", zeek_conn: "#3ccf91", zeek_dns: "#2dd4bf", zeek_ssl: "#a78bfa", zeek_http: "#60a5fa", suricata: "#ff6b3d", linux: "#94a3b8", db_audit: "#f472b6" };

export function TimelineTab({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const parent = useRef<HTMLDivElement>(null);
  const body = { filters: ctx.filters, time: ctx.time };
  const dens = useQuery({ queryKey: ["density", inv, body], queryFn: () => api.post(`/investigations/${inv}/timeline/density`, body) });
  const q = useInfiniteQuery({
    queryKey: ["timeline", inv, body],
    queryFn: ({ pageParam }) => api.post(`/investigations/${inv}/timeline`, { ...body, limit: 500, cursor: pageParam }),
    initialPageParam: null as string | null,
    getNextPageParam: (last: any) => last.next_cursor,
  });
  const items = useMemo(() => {
    const out: any[] = [];
    const pages = q.data?.pages || [];
    const notes = pages[0]?.notes || [];
    const marks = pages[0]?.finding_marks || [];
    pages.forEach((p: any) => out.push(...p.items));
    // interleave finding marks and notes by time (Story/Finding anchors)
    const extra = [...marks.map((m: any) => ({ kind: "finding", ts: m.ts, m })), ...notes.map((n: any) => ({ kind: "note", ts: n.ts, n }))];
    const all = [...out.map((x) => ({ ...x, ts: x.kind === "event" ? x.event.timestamp : x.first })), ...extra];
    all.sort((a, b) => String(a.ts || "").localeCompare(String(b.ts || "")));
    return all;
  }, [q.data]);
  const v = useVirtualizer({ count: items.length + (q.hasNextPage ? 1 : 0), getScrollElement: () => parent.current, estimateSize: () => 28, overscan: 20 });
  const sel = entityKey(ctx.selection);
  const skew: Record<string, number> = q.data?.pages?.[0]?.clock_skew || {};
  const shown = (e: any) => (skew[e.data_source] ? new Date(new Date(e.timestamp).getTime() + skew[e.data_source] * 1000).toISOString() : e.timestamp);
  const db = (dens.data?.buckets || []) as any[];
  const xs = [...new Set(db.map((b) => b.key))].sort((a, b) => a - b);
  const series = [...new Set(db.map((b) => b.series))];
  const vItems = v.getVirtualItems();
  const lastIdx = vItems.length ? vItems[vItems.length - 1].index : -1;
  const capped = items.length >= MAX_LOADED && !!q.hasNextPage;  // same memory bound as the raw table
  useEffect(() => {
    if (lastIdx >= items.length - 1 && q.hasNextPage && !q.isFetchingNextPage && items.length < MAX_LOADED) q.fetchNextPage();
  }, [lastIdx, items.length, q.hasNextPage, q.isFetchingNextPage]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <div className="col" style={{ height: "100%" }}>
      {capped && <div className="error small" role="status">화면에는 {fmtNum(MAX_LOADED)}건까지만 불러옵니다(브라우저 메모리 보호). 시간 범위·필터로 좁혀서 보세요.</div>}
      {dens.data && (
        <EChart ariaLabel="timeline density" height={90} option={{
          grid: { left: 40, right: 10, top: 6, bottom: 34 }, legend: { show: false },
          xAxis: { type: "category", data: xs.map((x) => fmtTime(x)), ...axisStyle }, yAxis: { type: "value", ...axisStyle, splitNumber: 2 },
          dataZoom: [{ type: "slider", height: 12, bottom: 2 }], tooltip: { trigger: "axis", formatter: safeTooltip((p) => [[p.seriesName, p.value]]) },
          series: series.map((sn) => ({ name: String(sn), type: "bar", stack: "d", barCategoryGap: 0, itemStyle: { color: SRC_COLOR[sn] || "#8a93a6" }, data: xs.map((x) => db.find((b) => b.key === x && b.series === sn)?.count || 0) })),
        } as any} onBrush={([a, b]) => xs[a] !== undefined && ctx.set({ time: { start: new Date(xs[a] * 1000).toISOString(), end: new Date((xs[b] + dens.data.interval_sec) * 1000).toISOString() } })} />
      )}
      <div className="row small"><b>TIMELINE</b>{Object.keys(skew).length > 0 && <span className="tag warn">Clock skew 보정: {Object.entries(skew).map(([k, v]) => `${k} ${v}s`).join(", ")} (표시만, 원본 불변)</span>}<span className="muted">반복 이벤트(≥5)는 접힘 · Δt 표시 · 클릭 시 상세 · 범례:</span>
        {series.map((s) => <span key={String(s)} className="tag" style={{ borderColor: SRC_COLOR[s] }}>{String(s)}</span>)}</div>
      {q.isLoading && <Loading />}
      <ErrorBox error={q.error} />
      <div ref={parent} className="scroll" style={{ flex: 1, minHeight: 300 }}>
        <div style={{ height: v.getTotalSize(), position: "relative" }}>
          {vItems.map((vi) => {
            const it = items[vi.index];
            const style = { position: "absolute" as const, top: 0, left: 0, right: 0, transform: `translateY(${vi.start}px)` };
            if (!it) return <div key={vi.key} style={style} className="muted small">불러오는 중…</div>;
            if (it.kind === "group") return (
              <div key={vi.key} ref={v.measureElement} data-index={vi.index} style={style}>
                <div className="tl-row"><span className="mono small muted">{fmtTime(it.first, false)}</span><span className="tl-dot">⋯</span>
                  <div className="tl-group small">⋯ {fmtNum(it.count)} similar events collapsed ({it.key.filter(Boolean).join(" · ")}) · {it.src_count} src · Δt median {it.dt_median?.toFixed?.(2)}s · CV {it.dt_cv ?? "–"} <span className="muted">→ {fmtTime(it.last, false)}</span></div></div>
              </div>);
            if (it.kind === "finding") return (
              <div key={vi.key} ref={v.measureElement} data-index={vi.index} style={style}>
                <div className="tl-row"><span className="mono small">{fmtTime(it.ts, false)}</span><span className="tl-dot">◆</span><a className="small" onClick={() => ctx.set({ tab: "findings", findingId: it.m.id })}><Sev level={it.m.risk_level} /> {it.m.display_id} {it.m.title} <span className="muted">({it.m.stage})</span></a></div>
              </div>);
            if (it.kind === "note") return (
              <div key={vi.key} ref={v.measureElement} data-index={vi.index} style={style}>
                <div className="tl-row"><span className="mono small">{fmtTime(it.ts, false)}</span><span className="tl-dot">✎</span><span className="small">"{it.n.body_md}" — {it.n.author}</span></div>
              </div>);
            const e = it.event;
            const hl = sel && (sel === `ip:${e.src_ip}` || sel === `uri:${e.uri_template}`);
            return (
              <div key={vi.key} ref={v.measureElement} data-index={vi.index} style={style}>
                {it.delta_sec !== null && it.delta_sec !== undefined && Math.abs(it.delta_sec) >= 0.001 && <div className="tl-gap">│ {dur(it.delta_sec)}</div>}
                <div className="tl-row" style={{ background: hl ? "var(--hl-bg)" : ctx.eventId === e.event_id ? "var(--accent-weak)" : undefined, cursor: "pointer" }} onClick={() => ctx.set({ eventId: e.event_id })}>
                  <span className="mono small" title={skew[e.data_source] ? `원본 ${e.timestamp} · 보정 ${skew[e.data_source]}s` : e.timestamp}>{fmtTime(shown(e), false)}{skew[e.data_source] ? "≈" : ""}{e.timestamp_quality && e.timestamp_quality !== "exact" ? " ⏱?" : ""}</span>
                  <span className="tl-dot" style={{ color: SRC_COLOR[e.data_source] }}>●</span>
                  <span className="mono small ellipsis"><b style={{ color: SRC_COLOR[e.data_source] }}>{(e.data_source || "").toUpperCase()}</b> {e.src_ip} {e.method} {e.uri || e.domain || e.raw_event?.slice(0, 120)} <b>{e.status_code ?? ""}</b>{(e.tags || []).filter((t: string) => t.startsWith("pattern:")).map((t: string) => <span key={t} className="tag warn">{t}</span>)}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
