import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Background, Controls, Edge, Handle, MiniMap, Node, Position, ReactFlow } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import ELK from "elkjs/lib/elk.bundled.js";
import { useEffect, useMemo, useState } from "react";
import { ErrorBox, Loading, Panel, Sev } from "../../components/common";
import { EntityChip, parseEntity } from "../../components/EntityChip";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtNum, fmtTime } from "../../lib/format";
import { EventTable } from "./FindingsTab";

const elk = new ELK();
const STAGE_TACTIC: Record<string, string> = { INFRASTRUCTURE: "resource-development", RECON: "reconnaissance", DISCOVERY: "discovery", AUTHENTICATION: "credential-access", EXPLOITATION: "initial-access", DATA_ACCESS: "collection", EXECUTION: "execution", PERSISTENCE: "persistence", LATERAL: "lateral-movement", OUTBOUND: "exfiltration", UNCLASSIFIED: "—" };

function StoryNode({ data }: { data: any }) {
  const n = data.n;
  return (
    <div className={`snode ${data.sel ? "sel" : ""} ${n.attack?.length ? "" : "unmapped"}`}>
      <Handle type="target" position={Position.Left} />
      <div className="st"><span>{data.lens ? (n.attack?.[0]?.tactic || STAGE_TACTIC[n.stage] || n.stage) : n.stage}</span><Sev level={n.risk} /></div>
      <div className="sb">
        <div style={{ fontWeight: 600 }}>{n.title}{n.origin === "analyst" ? " ✎" : ""}{n.new_since_edit ? " 🆕" : ""}</div>
        {(n.metrics || []).map((m: any) => <div key={m.name} className="small mono">{m.label} {typeof m.value === "number" && m.value < 1 && m.value > 0 ? `${(m.value * 100).toFixed(1)}%` : fmtNum(m.value)}</div>)}
        <div className="small muted">{fmtTime(n.time?.start, true)}</div>
        <div className="small attack">{n.attack?.length ? n.attack.map((a: any) => `${a.technique_id}${a.confidence === "candidate" ? "?" : ""}`).join(" ") : (data.lens ? "unmapped" : "")}</div>
      </div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
const nodeTypes = { story: StoryNode };

export function StoryTab({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const qc = useQueryClient();
  const [version, setVersion] = useState<number | null>(null);
  const [sel, setSel] = useState<string | null>(null);
  const [lens, setLens] = useState(false);
  const [weak, setWeak] = useState(false);
  const [edit, setEdit] = useState(false);
  const [draft, setDraft] = useState<any | null>(null);
  const [pos, setPos] = useState<Record<string, { x: number; y: number }>>({});
  const q = useQuery({ queryKey: ["story", inv, version], queryFn: () => api.get(`/investigations/${inv}/story${version ? `?version=${version}` : ""}`) });
  const save = useMutation({ mutationFn: (graph: any) => api.put(`/investigations/${inv}/story`, { graph }), onSuccess: () => { setEdit(false); setDraft(null); setVersion(null); qc.invalidateQueries({ queryKey: ["story", inv] }); } });
  const graph = draft || q.data?.story?.graph;
  const nodesRaw: any[] = (graph?.nodes || []).filter((n: any) => !n.hidden);
  const edgesRaw: any[] = (graph?.edges || []).filter((e: any) => weak || e.confidence !== "low");
  useEffect(() => {
    if (!nodesRaw.length) return;
    if (lens) {
      const tactics = [...new Set(nodesRaw.map((n) => n.attack?.[0]?.tactic || "unmapped"))];
      const p: Record<string, any> = {};
      const counts: Record<string, number> = {};
      nodesRaw.forEach((n) => { const t = n.attack?.[0]?.tactic || "unmapped"; const c = (counts[t] = (counts[t] || 0) + 1); p[n.id] = { x: tactics.indexOf(t) * 250, y: (c - 1) * 170 }; });
      setPos(p);
      return;
    }
    elk.layout({ id: "root", layoutOptions: { "elk.algorithm": "layered", "elk.direction": "RIGHT", "elk.spacing.nodeNode": "40", "elk.layered.spacing.nodeNodeBetweenLayers": "70" },
      children: nodesRaw.map((n) => ({ id: n.id, width: 210, height: 130 })), edges: edgesRaw.map((e, i) => ({ id: `e${i}`, sources: [e.from], targets: [e.to] })) })
      .then((g) => setPos(Object.fromEntries((g.children || []).map((c) => [c.id, { x: c.x || 0, y: c.y || 0 }]))));
  }, [JSON.stringify(nodesRaw.map((n) => n.id)), JSON.stringify(edgesRaw), lens]); // eslint-disable-line
  const laidOut = nodesRaw.length > 0 && nodesRaw.every((n) => pos[n.id]);
  const layoutKey = `${lens}-${nodesRaw.map((n) => n.id).join(",")}-${Object.keys(pos).length}`;
  const nodes: Node[] = useMemo(() => nodesRaw.map((n) => ({ id: n.id, type: "story", position: pos[n.id] || { x: 0, y: 0 }, data: { n, sel: sel === n.id, lens } })), [nodesRaw, pos, sel, lens]);
  const edges: Edge[] = edgesRaw.map((e, i) => ({ id: `e${i}`, source: e.from, target: e.to, animated: false, label: e.confidence === "low" ? "weak" : undefined,
    style: { strokeDasharray: e.confidence === "low" ? "5 4" : undefined, strokeWidth: e.confidence === "high" ? 2 : 1 }, data: e }));
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  if (!graph?.nodes?.length) return <div className="empty">Attack Story는 Finding이 생성되면 자동으로 구성됩니다.</div>;
  const node = nodesRaw.find((n) => n.id === sel);
  const startEdit = () => { setDraft(JSON.parse(JSON.stringify(graph))); setEdit(true); };
  const upd = (id: string, patch: any) => setDraft({ ...draft, nodes: draft.nodes.map((n: any) => (n.id === id ? { ...n, ...patch, origin: "analyst" } : n)) });
  return (
    <div className="col" style={{ height: "100%" }}>
      <div className="row wrap small">
        <b>ATTACK STORY</b>
        <select className="input" value={version || ""} onChange={(e) => setVersion(e.target.value ? Number(e.target.value) : null)}>
          <option value="">latest (v{q.data.story.version} {q.data.story.origin})</option>
          {q.data.versions.map((v: any) => <option key={v.version} value={v.version}>v{v.version} {v.origin} {fmtTime(v.created_at)}</option>)}
        </select>
        <label className="row"><input type="checkbox" checked={lens} onChange={(e) => setLens(e.target.checked)} />ATT&CK lens</label>
        <label className="row"><input type="checkbox" checked={weak} onChange={(e) => setWeak(e.target.checked)} />weak links</label>
        <span className="muted">실선=공통 Entity · 점선=시간 근접(약한 연결) · 숫자는 Finding 지표와 동일 출처</span>
        <div className="grow" />
        {!edit ? <button className="btn sm" onClick={startEdit}>✎ Edit</button> : <>
          <button className="btn sm" onClick={() => setDraft({ ...draft, nodes: [...draft.nodes, { id: `m${Date.now()}`, stage: "UNCLASSIFIED", title: "분석가 노드", risk: "info", finding_ids: [], metrics: [], time: {}, origin: "analyst", attack: [], entities: [] }] })}>＋ 수동 노드</button>
          <button className="btn sm primary" onClick={() => save.mutate(draft)}>저장 (새 버전)</button><button className="btn sm ghost" onClick={() => { setEdit(false); setDraft(null); }}>취소</button></>}
      </div>
      <ErrorBox error={save.error} />
      <div className="row" style={{ alignItems: "stretch", flex: 1, minHeight: 420 }}>
        <div className="grow panel" style={{ minHeight: 420 }}>
          {!laidOut ? <Loading label="레이아웃 계산 중…" /> : (
          <ReactFlow key={layoutKey} nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.15 }} minZoom={0.2} maxZoom={1.5}
            colorMode={document.documentElement.dataset.theme === "light" ? "light" : "dark"} onNodeClick={(_, n) => setSel(n.id)} nodesConnectable={false} proOptions={{ hideAttribution: true }}>
            <Background gap={24} color="#232838" />
            <MiniMap pannable zoomable position="top-right" style={{ background: "var(--bg-1)", width: 140, height: 90 }} />
            <Controls showInteractive={false} />
          </ReactFlow>)}
        </div>
        {node && (
          <div className="panel scroll" style={{ width: 380 }}>
            <div className="ph"><span className="grow">{node.stage} · {node.title}</span><button className="btn ghost sm" onClick={() => setSel(null)}>✕</button></div>
            <div className="pb col">
              {edit && (
                <div className="col">
                  <input className="input" value={draft.nodes.find((n: any) => n.id === node.id).title} onChange={(e) => upd(node.id, { title: e.target.value })} />
                  <select className="input" value={draft.nodes.find((n: any) => n.id === node.id).stage} onChange={(e) => upd(node.id, { stage: e.target.value })}>{Object.keys(STAGE_TACTIC).map((s) => <option key={s}>{s}</option>)}</select>
                  <div className="row"><button className="btn sm" onClick={() => upd(node.id, { pinned: true })}>📌 고정</button><button className="btn sm" onClick={() => upd(node.id, { hidden: true })}>숨김</button></div>
                </div>
              )}
              <StoryNodeEvidence inv={inv} node={node} onFinding={(id) => ctx.set({ tab: "findings", findingId: id })} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function StoryNodeEvidence({ inv, node, onFinding }: { inv: string; node: any; onFinding: (id: string) => void }) {
  const fid = node.finding_ids?.[0];
  const evs = useQuery({ queryKey: ["finding-events", inv, fid, "story"], queryFn: () => api.post(`/investigations/${inv}/findings/${fid}/events`, { limit: 10 }), enabled: !!fid });
  return (
    <>
      <Panel title="관련 Finding">{node.finding_ids.map((id: string) => <div key={id}><a onClick={() => onFinding(id)}>{id.slice(0, 8)}…</a></div>)}{!node.finding_ids.length && <span className="muted small">분석가 수동 노드</span>}</Panel>
      <Panel title="Related IOC"><div className="row wrap">{(node.entities || []).map((e: string) => { const p = parseEntity(e); return <EntityChip key={e} inv={inv} type={p.type} value={p.value} />; })}</div></Panel>
      {fid && <Panel title={`Supporting Events (${fmtNum(evs.data?.total)})`}><EventTable inv={inv} events={evs.data?.events || []} cols={["timestamp", "src_ip", "method", "uri", "status_code"]} /></Panel>}
    </>
  );
}
