import * as echarts from "echarts";
import { useEffect, useRef } from "react";
import { escapeHtml } from "../lib/format";

/** ECharts wrapper. Tooltip formatters MUST go through safeTooltip (ECharts renders tooltip HTML; docs/04 §5.1). */
export function EChart({ option, height = 180, onClick, onBrush, ariaLabel }: {
  option: echarts.EChartsOption; height?: number; ariaLabel: string;
  onClick?: (p: echarts.ECElementEvent) => void; onBrush?: (range: [number, number]) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.ECharts | null>(null);
  useEffect(() => {
    if (!ref.current) return;
    const theme = document.documentElement.dataset.theme === "light" ? undefined : "dark";
    chart.current = echarts.init(ref.current, theme, { renderer: "canvas" });
    const ro = new ResizeObserver(() => chart.current?.resize());
    ro.observe(ref.current);
    return () => { ro.disconnect(); chart.current?.dispose(); };
  }, []);
  useEffect(() => {
    const c = chart.current;
    if (!c) return;
    c.setOption({ backgroundColor: "transparent", aria: { enabled: true, decal: { show: false } }, animation: false, textStyle: { fontFamily: "inherit" }, ...option }, true);
    c.off("click");
    if (onClick) c.on("click", (p) => onClick(p as echarts.ECElementEvent));
    c.off("datazoom");
    if (onBrush) {
      c.on("datazoom", () => {
        const o = c.getOption() as any;
        const dz = o.dataZoom?.[0];
        if (dz && dz.startValue !== undefined) onBrush([dz.startValue, dz.endValue]);
      });
    }
  }, [option, onClick, onBrush]);
  return <div ref={ref} style={{ height, width: "100%" }} role="img" aria-label={ariaLabel} />;
}

/** Safe tooltip: every value escaped. */
export function safeTooltip(fmt: (p: any) => [string, string | number][]) {
  return (params: any) => {
    const p = Array.isArray(params) ? params : [params];
    return p.flatMap((x) => fmt(x)).map(([k, v]) => `${escapeHtml(k)}: <b>${escapeHtml(v)}</b>`).join("<br/>");
  };
}

export const axisStyle = { axisLine: { lineStyle: { color: "#3a4256" } }, splitLine: { lineStyle: { color: "#232838" } }, axisLabel: { color: "#8a93a6", fontSize: 10 } };

/** Horizontal Top-N bar chart (clickable). */
export function TopBar({ buckets, title, onPick, height, labelFmt, valueFmt }: { buckets: { key: any; count: number }[]; title: string; onPick?: (key: any, exclude: boolean) => void; height?: number; labelFmt?: (k: any) => string; valueFmt?: (v: number) => string }) {
  const data = [...buckets].reverse();
  const lf = labelFmt || ((k: any) => String(k));
  return (
    <EChart
      ariaLabel={title}
      height={height || Math.max(120, data.length * 18 + 20)}
      option={{
        grid: { left: 8, right: 40, top: 4, bottom: 4, containLabel: true },
        xAxis: { type: "value", ...axisStyle, splitLine: { show: false }, axisLabel: { show: false } },
        yAxis: { type: "category", data: data.map((b) => { const s = lf(b.key); return s.length > 34 ? s.slice(0, 33) + "…" : s; }), ...axisStyle, axisLabel: { color: "#aab1c0", fontSize: 10, fontFamily: "monospace" } },
        tooltip: { trigger: "item", formatter: safeTooltip((p) => [[lf(data[p.dataIndex].key), valueFmt ? valueFmt(data[p.dataIndex].count) : data[p.dataIndex].count]]) },
        series: [{ type: "bar", data: data.map((b) => b.count), itemStyle: { color: "#4c8dff" }, barMaxWidth: 12,
          label: { show: true, position: "right", color: "#8a93a6", fontSize: 10, formatter: (p: any) => (valueFmt ? valueFmt(p.value) : String(p.value)) } }],
      }}
      onClick={onPick ? (p) => onPick(data[p.dataIndex as number].key, (p.event?.event as MouseEvent)?.altKey) : undefined}
    />
  );
}
