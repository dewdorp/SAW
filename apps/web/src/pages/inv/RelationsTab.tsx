import { useQuery } from "@tanstack/react-query";
import cytoscape, { Core } from "cytoscape";
import { useEffect, useRef, useState } from "react";
import { ErrorBox, Loading } from "../../components/common";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtNum } from "../../lib/format";

const COLORS: Record<string, string> = { ip: "#4c8dff", group: "#ff6b3d", uri: "#3ccf91", ja4: "#a78bfa", user_agent: "#94a3b8", user: "#f472b6", session: "#f5b324", asset: "#ffd166", domain: "#2dd4bf" };
const TYPES = ["ip", "uri", "ja4", "user_agent", "user", "session", "asset", "domain"];

/** Relation graph with structural grouping, filters, focus (docs/22). Canvas -> table view for accessibility. */
export function RelationsTab({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const ref = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const [types, setTypes] = useState<string[]>(["ip", "uri", "ja4", "user_agent", "user", "asset", "domain"]);
  const [minCount, setMinCount] = useState(1);
  const [focus, setFocus] = useState<string | null>(null);
  const [table, setTable] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [groupBy, setGroupBy] = useState("cloud");
  const qs = new URLSearchParams({ types: types.join(","), min_count: String(minCount), max_nodes: "300", group_by: groupBy });
  if (focus) qs.set("focus", focus);
  const q = useQuery({ queryKey: ["graph", inv, qs.toString()], queryFn: () => api.get(`/investigations/${inv}/graph?${qs}`) });
  useEffect(() => {
    if (!ref.current || !q.data || table) return;
    const d = q.data;
    const maxC = Math.max(1, ...d.edges.map((e: any) => e.count));
    cy.current?.destroy();
    cy.current = cytoscape({
      container: ref.current,
      elements: [
        ...d.nodes.map((n: any) => ({ data: { id: n.id, label: n.type === "group" ? `${n.label}` : n.label.length > 40 ? n.label.slice(0, 38) + "…" : n.label, type: n.type, count: n.count } })),
        ...d.edges.map((e: any, i: number) => ({ data: { id: `e${i}`, source: e.source, target: e.target, label: e.type, w: 1 + (4 * Math.log(1 + e.count)) / Math.log(1 + maxC) } })),
      ],
      style: [
        { selector: "node", style: { "background-color": (el: any) => COLORS[el.data("type")] || "#8a93a6", label: "data(label)", color: "#d6dae3", "font-size": 9, "text-valign": "bottom", "text-margin-y": 3, width: (el: any) => (el.data("type") === "group" ? 34 : 18), height: (el: any) => (el.data("type") === "group" ? 34 : 18), shape: (el: any) => (el.data("type") === "group" ? "round-rectangle" : el.data("type") === "uri" ? "diamond" : "ellipse") } },
        { selector: "edge", style: { width: "data(w)", "line-color": "#3a4256", "target-arrow-color": "#3a4256", "target-arrow-shape": "triangle", "curve-style": "bezier", label: "data(label)", "font-size": 7, color: "#7c8496" } },
        { selector: "node.hl", style: { "border-width": 3, "border-color": "#ffd166" } },
        { selector: "node.dim", style: { opacity: 0.25 } },
      ],
      layout: { name: "cose", animate: false, nodeDimensionsIncludeLabels: true, idealEdgeLength: 90, nodeRepulsion: 9000 } as any,
      wheelSensitivity: 0.3,
    });
    cy.current.on("tap", "node", (ev) => {
      const n = d.nodes.find((x: any) => x.id === ev.target.id());
      if (!n) return;
      if (n.type === "group") { setExpanded(n.id); return; }
      ctx.set({ selection: { type: n.type, value: n.value } });
    });
    cy.current.on("dbltap", "node", (ev) => {
      const n = d.nodes.find((x: any) => x.id === ev.target.id());
      if (n && n.type !== "group") setFocus(`${n.type}:${n.value}`);
    });
    return () => { cy.current?.destroy(); cy.current = null; };
  }, [q.data, table]); // eslint-disable-line react-hooks/exhaustive-deps
  // cross-highlight on selection changes (no refetch)
  useEffect(() => {
    const c = cy.current;
    if (!c || !q.data) return;
    c.nodes().removeClass("hl dim");
    if (!ctx.selection) return;
    const n = q.data.nodes.find((x: any) => x.type === ctx.selection!.type && x.value === ctx.selection!.value) ||
      q.data.nodes.find((x: any) => x.type === "group" && x.member_values?.includes(ctx.selection!.value));
    if (!n) return;
    const el = c.getElementById(n.id);
    c.nodes().addClass("dim");
    el.removeClass("dim").addClass("hl");
    el.neighborhood("node").removeClass("dim");
    c.animate({ center: { eles: el }, duration: 0 } as any);
  }, [ctx.selection, q.data]);
  const grp = q.data?.nodes.find((n: any) => n.id === expanded);
  return (
    <div className="col" style={{ height: "100%" }}>
      <div className="row wrap small">
        <b>RELATIONS</b>
        <label className="row">Group by <select className="input" value={groupBy} onChange={(e) => setGroupBy(e.target.value)}>
          {[["cloud", "Cloud/VPS"], ["asn", "ASN"], ["country", "Country"], ["structure", "Same neighbours"], ["none", "None"]].map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
        {TYPES.map((t) => <label key={t} className="row"><input type="checkbox" checked={types.includes(t)} onChange={(e) => setTypes(e.target.checked ? [...types, t] : types.filter((x) => x !== t))} /><span style={{ color: COLORS[t] }}>●</span>{t}</label>)}
        <label className="row">Min edges <input className="input" style={{ width: 60 }} type="number" min={1} value={minCount} onChange={(e) => setMinCount(Number(e.target.value) || 1)} /></label>
        {focus && <span className="tag">Focus 2-hop: {focus} <a onClick={() => setFocus(null)}>×</a></span>}
        <div className="grow" />
        {q.data?.truncated?.hidden_nodes > 0 && <span className="tag warn">+{q.data.truncated.hidden_nodes} more (filter/focus로 축소)</span>}
        <button className="btn sm" onClick={() => setTable(!table)}>{table ? "Graph view" : "Table view"}</button>
      </div>
      <div className="muted small">IP는 선택한 기준으로 그룹 노드(▣)로 묶입니다. URI·UA 등은 유형별 상위 노드만 표시(나머지는 +N). 클릭=선택(전체 화면 강조), 더블클릭=포커스, 그룹 클릭=구성원.</div>
      {q.isLoading && <Loading />}
      <ErrorBox error={q.error} />
      {table ? (
        <div className="scroll grow">
          <table className="t"><thead><tr><th>source</th><th>edge</th><th>target</th><th>count</th></tr></thead>
            <tbody>{(q.data?.edges || []).map((e: any, i: number) => {
              const s = q.data.nodes.find((n: any) => n.id === e.source); const t = q.data.nodes.find((n: any) => n.id === e.target);
              return <tr key={i}><td className="mono">{s?.label}</td><td>{e.type}</td><td className="mono">{t?.label}</td><td className="num">{fmtNum(e.count)}</td></tr>;
            })}</tbody></table>
        </div>
      ) : (
        <div className="row" style={{ flex: 1, minHeight: 440, alignItems: "stretch" }}>
          <div ref={ref} className="panel grow" style={{ minHeight: 440 }} role="img" aria-label="relation graph (use Table view for accessible list)" />
          {grp && (
            <div className="panel scroll" style={{ width: 260 }}>
              <div className="ph"><span className="grow">{grp.label}</span><button className="btn ghost sm" onClick={() => setExpanded(null)}>✕</button></div>
              <div className="pb col small">{grp.member_values.map((v: string) => <a key={v} className="mono" onClick={() => ctx.set({ selection: { type: "ip", value: v } })}>{v}</a>)}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
