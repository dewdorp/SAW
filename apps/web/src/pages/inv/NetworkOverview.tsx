import { useQuery } from "@tanstack/react-query";
import cytoscape from "cytoscape";
import { useEffect, useRef } from "react";
import { Panel, Sev } from "../../components/common";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtBytes, fmtNum, fmtTime } from "../../lib/format";
import { TopBar } from "../../viz/EChart";

/** PCAP overview + Visual Network Story (docs/20 §3-4, wireframe 05). */
export function NetworkOverview({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const q = useQuery({ queryKey: ["netov", inv], queryFn: () => api.get(`/investigations/${inv}/network/overview`) });
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!ref.current || !q.data?.available) return;
    const st = q.data.story as any[];
    const nodes = new Map<string, any>();
    st.forEach((e) => {
      const internal = /^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\./.test(e.src);
      nodes.set(e.src, { id: e.src, kind: internal ? "internal" : "external" });
      nodes.set(e.dst, { id: e.dst, kind: e.protocol === "dns" ? "domain" : /^10\.|^192\.168\./.test(e.dst) ? "internal" : "external" });
    });
    const maxB = Math.max(1, ...st.map((e) => e.bytes_out + e.bytes_in));
    const cy = cytoscape({
      container: ref.current,
      elements: [
        ...[...nodes.values()].map((n) => ({ data: { id: n.id, label: n.id, kind: n.kind } })),
        ...st.map((e, i) => ({ data: { id: `e${i}`, source: e.src, target: e.dst, flagged: e.flags.length > 0 ? 1 : 0,
          label: `${e.protocol || "?"} · ${e.protocol === "dns" ? `${e.conns} q` : fmtBytes(e.bytes_out + e.bytes_in)}${e.flags.length ? " ⚠ " + e.flags[0] : ""}`,
          w: 1 + (5 * Math.log(1 + e.bytes_out + e.bytes_in)) / Math.log(1 + maxB), dashed: e.flags.some((f: string) => /Periodic/.test(f)) ? 1 : 0 } })),
      ],
      style: [
        { selector: "node", style: { label: "data(label)", color: "#d6dae3", "font-size": 9, "text-valign": "bottom", width: 16, height: 16,
          "background-color": (el: any) => (el.data("kind") === "internal" ? "#4c8dff" : el.data("kind") === "domain" ? "#2dd4bf" : "#ff6b3d") } },
        { selector: "edge", style: { width: "data(w)", "curve-style": "bezier", "target-arrow-shape": "triangle", label: "data(label)", "font-size": 8,
          color: "#aab1c0", "line-color": (el: any) => (el.data("flagged") ? "#ff6b3d" : "#3a4256"), "target-arrow-color": (el: any) => (el.data("flagged") ? "#ff6b3d" : "#3a4256"),
          "line-style": (el: any) => (el.data("dashed") ? "dashed" : "solid"), "text-background-color": "#0f1115", "text-background-opacity": 0.7, "text-background-padding": "1px" } },
      ],
      layout: { name: "concentric", concentric: (n: any) => (n.data("kind") === "internal" ? 2 : 1), levelWidth: () => 1, minNodeSpacing: 40, animate: false } as any,
    });
    cy.on("tap", "node", (ev) => ctx.set({ selection: { type: /^[\d.:]+$/.test(ev.target.id()) ? "ip" : "domain", value: ev.target.id() } }));
    return () => cy.destroy();
  }, [q.data]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!q.data?.available) return null;
  const d = q.data;
  return (
    <div className="col">
      <div className="row wrap" style={{ gap: 16 }}>
        <b>NETWORK (PCAP-derived)</b>
        <span className="muted">{fmtTime(d.summary.time_range[0])} ~ {fmtTime(d.summary.time_range[1])}</span>
        <span>Connections <b>{fmtNum(d.summary.connections)}</b></span><span>Hosts <b>{fmtNum(d.summary.hosts)}</b></span><span>Domains <b>{fmtNum(d.summary.domains)}</b></span>
        <span className="tag" title="PCAP 분석 엔진">{d.tools.zeek ? "Zeek" : "SAW 내장 PCAP 분석기"}{d.tools.suricata ? " + Suricata" : ""}</span>
        {!d.tools.suricata && <span className="tag warn" title="IDS 시그니처 경보는 Suricata 설치 시 추가됩니다">IDS 경보: Suricata 미설치</span>}
      </div>
      <div className="row" style={{ alignItems: "stretch" }}>
        <Panel title="Visual Network Story (빨강=Finding 연관, 점선=주기적)" className="grow">
          <div ref={ref} style={{ height: 360 }} role="img" aria-label="network story graph" />
        </Panel>
        <div className="col" style={{ width: 360 }}>
          <Panel title="Important Findings">{d.findings.slice(0, 8).map((f: any) => <div key={f.id} className="row small"><Sev level={f.risk_level} /><a className="ellipsis" onClick={() => ctx.set({ tab: "findings", findingId: f.id })}>{f.title}</a></div>)}</Panel>
          <Panel title="Interesting Connections">{d.story.filter((e: any) => e.flags.length).slice(0, 6).map((e: any, i: number) => (
            <div key={i} className="small mono ellipsis">{e.src} → {e.dst} {e.protocol} {e.protocol === "dns" ? `${e.conns}q` : fmtBytes(e.bytes_out + e.bytes_in)} · {e.flags[0]}</div>))}</Panel>
        </div>
      </div>
      <div className="grid-auto">
        <Panel title="Protocol Distribution (bytes)"><TopBar title="protocols" valueFmt={fmtBytes} buckets={d.protocols.map((p: any) => ({ key: p.protocol, count: p.bytes }))} labelFmt={(k) => String(k)} onPick={(k) => ctx.addFilter({ field: "protocol", op: "is", value: k })} /></Panel>
        <Panel title="Top Talkers (bytes)"><TopBar title="talkers" valueFmt={fmtBytes} buckets={d.top_talkers.map((p: any) => ({ key: p.ip, count: p.bytes }))} onPick={(k) => ctx.addFilter({ field: "src_ip", op: "is", value: k })} /></Panel>
        <Panel title="Top Destinations (bytes out)"><TopBar title="destinations" valueFmt={fmtBytes} buckets={d.top_destinations.map((p: any) => ({ key: p.ip, count: p.bytes }))} onPick={(k) => ctx.addFilter({ field: "dst_ip", op: "is", value: k })} /></Panel>
        <Panel title="Top Domains (queries)"><TopBar title="domains" buckets={d.top_domains} onPick={(k) => ctx.addFilter({ field: "domain", op: "is", value: k })} /></Panel>
      </div>
    </div>
  );
}
