import { useQuery } from "@tanstack/react-query";
import { ErrorBox, Loading, Panel, Sev } from "../../components/common";
import { entityKey, useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtNum, fmtTime, pct } from "../../lib/format";
import { axisStyle, EChart, safeTooltip, TopBar } from "../../viz/EChart";
import { CorrelationPanel } from "./CorrelationPanel";
import { NetworkOverview } from "./NetworkOverview";

const STATUS_COLORS: Record<string, string> = { "2xx": "#3ccf91", "3xx": "#4c8dff", "4xx": "#f5b324", "5xx": "#ff5a5f", null: "#8a93a6" };

export function OverviewTab({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const q = useQuery({ queryKey: ["overview", inv, ctx.filters, ctx.time], queryFn: () => api.post(`/investigations/${inv}/overview`, { filters: ctx.filters, time: ctx.time }) });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data;
  const s = d.summary;
  const pick = (field: string) => (key: any, exclude: boolean) => ctx.addFilter({ field, op: exclude ? "is_not" : "is", value: key });
  // volume stacked by status_class
  const vb = d.charts.volume.buckets as any[];
  const xs = [...new Set(vb.map((b) => b.key))].sort((a, b) => a - b);
  const series = [...new Set(vb.map((b) => String(b.series)))];
  const volOpt = {
    grid: { left: 40, right: 10, top: 20, bottom: 40 },
    legend: { top: 0, right: 0, textStyle: { color: "#8a93a6", fontSize: 10 }, itemHeight: 8 },
    xAxis: { type: "category", data: xs.map((x) => fmtTime(x)), ...axisStyle },
    yAxis: { type: "value", ...axisStyle },
    dataZoom: [{ type: "slider", height: 14, bottom: 4 }],
    tooltip: { trigger: "axis", formatter: safeTooltip((p) => [[`${p.axisValue} ${p.seriesName}`, p.value]]) },
    series: series.map((sname) => ({ name: sname === "null" ? "n/a" : sname, type: "bar", stack: "v", barCategoryGap: 0, itemStyle: { color: STATUS_COLORS[sname] || "#8a93a6" },
      data: xs.map((x) => vb.find((b) => b.key === x && String(b.series) === sname)?.count || 0) })),
  };
  const sb = d.charts.size_trend.buckets as any[];
  const sizeOpt = {
    grid: { left: 50, right: 10, top: 10, bottom: 20 }, xAxis: { type: "category", data: sb.map((b) => fmtTime(b.key)), ...axisStyle },
    yAxis: { type: "value", ...axisStyle }, tooltip: { trigger: "axis", formatter: safeTooltip((p) => [[p.seriesName, Math.round(p.value)]]) },
    series: [{ name: "avg bytes", type: "line", showSymbol: false, data: sb.map((b) => b.avg) }, { name: "max bytes", type: "line", showSymbol: false, data: sb.map((b) => b.max), lineStyle: { type: "dashed" } }],
  };
  const ub = d.charts.unique_ip_trend.buckets as any[];
  const uipOpt = { grid: { left: 40, right: 10, top: 10, bottom: 20 }, xAxis: { type: "category", data: ub.map((b) => fmtTime(b.key)), ...axisStyle }, yAxis: { type: "value", ...axisStyle },
    tooltip: { trigger: "axis", formatter: safeTooltip((p) => [["unique IP", p.value]]) }, series: [{ type: "line", areaStyle: { opacity: 0.15 }, showSymbol: false, data: ub.map((b) => b.unique_ip) }] };
  const st = d.charts.status.buckets as any[];
  const selKey = entityKey(ctx.selection);
  const labelSel = (field: string) => (k: any) => (selKey === `${field}:${k}` ? `▶ ${k}` : String(k));
  return (
    <div className="col">
      <div className="row wrap" style={{ gap: 16 }}>
        <b>ANALYSIS OVERVIEW</b>
        <span>{fmtNum(s.files)} Files</span><span>{fmtNum(s.events)} Events</span>
        <span className="muted">{fmtTime(s.time_range[0])} ~ {fmtTime(s.time_range[1])}</span>
        <span>Unique IP <b>{fmtNum(s.unique_ip, s.approximate)}</b></span><span>Unique URI <b>{fmtNum(s.unique_uri, s.approximate)}</b></span>
        <span>Findings <b>{Object.values(s.findings).reduce((a: number, b: any) => a + b, 0) as number}</b></span>
        <span className="muted">Parse errors {pct(s.parse_error_rate)}</span>
        <span className="muted small">{s.data_sources.map((x: any) => `${x.key} ${fmtNum(x.count)}`).join(" · ")}</span>
      </div>
      <CorrelationPanel inv={inv} />
      <NetworkOverview inv={inv} />
      {d.top_findings.length > 0 && (
        <div className="grid3">
          {d.top_findings.map((f: any) => (
            <div key={f.id} className="panel" style={{ cursor: "pointer" }} onClick={() => ctx.set({ tab: "findings", findingId: f.id })}>
              <div className="pb col" style={{ gap: 2 }}>
                <div className="row"><Sev level={f.risk_level} score={f.risk_score} /><b className="ellipsis">{f.title}</b></div>
                <div className="small muted ellipsis">{f.metrics.slice(0, 3).map((m: any) => `${m.label} ${typeof m.observed === "number" && m.observed < 1 && m.observed > 0 ? pct(m.observed) : fmtNum(m.observed)}`).join(" · ")}</div>
              </div>
            </div>
          ))}
        </div>
      )}
      <Panel title="Event Volume Timeline (status, 드래그로 기간 필터)">
        <EChart ariaLabel="event volume" height={190} option={volOpt as any}
          onBrush={([a, b]) => { if (xs[a] !== undefined && xs[b] !== undefined) ctx.set({ time: { start: new Date(xs[a] * 1000).toISOString(), end: new Date((xs[b] + d.charts.volume.interval_sec) * 1000).toISOString() } }); }} />
      </Panel>
      <div className="grid3">
        <Panel title="HTTP Status Distribution"><TopBar title="status" buckets={st} onPick={pick("status_code")} /></Panel>
        <Panel title="Response Size Trend"><EChart ariaLabel="response size" option={sizeOpt as any} /></Panel>
        <Panel title="Unique IP Trend"><EChart ariaLabel="unique ip trend" option={uipOpt as any} /></Panel>
        <Panel title="Top Source (Alt+클릭 = 제외)"><TopBar title="top source" buckets={d.charts.top_src.buckets} onPick={pick("src_ip")} labelFmt={labelSel("ip")} /></Panel>
        <Panel title="Top URI (template)"><TopBar title="top uri" buckets={d.charts.top_uri.buckets} onPick={pick("uri_template")} labelFmt={labelSel("uri")} /></Panel>
        <Panel title="Top User-Agent"><TopBar title="top ua" buckets={d.charts.top_ua.buckets} onPick={pick("user_agent")} /></Panel>
        <Panel title="Top ASN"><TopBar title="top asn" buckets={d.charts.top_asn.buckets} onPick={pick("src_as_org")} /></Panel>
        <Panel title="Top Country (지도 미사용)"><TopBar title="top country" buckets={d.charts.top_country.buckets} onPick={pick("src_geo_country")} /></Panel>
        <Panel title="Cloud / VPS"><TopBar title="cloud" buckets={d.charts.top_cloud.buckets} onPick={pick("src_cloud")} /></Panel>
      </div>
    </div>
  );
}
