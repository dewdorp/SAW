import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PageHeader } from "../components/ui";
import { Background, Controls, Edge, Handle, Node, Position, ReactFlow } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useState } from "react";
import { Link, Route, Routes, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ErrorBox, Loading, Panel } from "../components/common";
import { api } from "../lib/api";
import { fmtNum, fmtTime } from "../lib/format";
import { TopBar } from "../viz/EChart";

export function Hunting() {
  return (
    <div className="page col">
      <PageHeader eyebrow="헌팅" title="위협 헌팅" desc="가설 → 질의 → 결과 → Pivot 순서로 탐지되지 않은 위협을 찾습니다. 모든 질의는 읽기 전용입니다." />
      <Routes>
        <Route index element={<HuntList />} />
        <Route path=":id" element={<HuntSession />} />
      </Routes>
    </div>
  );
}

function HuntList() {
  const [sp] = useSearchParams();
  const nav = useNavigate();
  const invs = useQuery({ queryKey: ["investigations"], queryFn: () => api.get("/investigations") });
  const list = useQuery({ queryKey: ["hunts"], queryFn: () => api.get("/hunts") });
  const tech = sp.get("tech");
  const [hyp, setHyp] = useState(tech ? `${tech}${sp.get("name") ? ` (${sp.get("name")})` : ""} 관련 흔적이 이 사건에 존재하는가?` : "");
  const [inv, setInv] = useState(sp.get("inv") || "");
  const [scope, setScope] = useState("investigation");
  const create = useMutation({ mutationFn: () => api.post("/hunts", { hypothesis: hyp, investigation_id: scope === "investigation" ? inv : null, scope, seed: tech ? { technique_id: tech, name: sp.get("name") } : null }), onSuccess: (h) => nav(`/hunting/${h.id}`) });
  return (
    <>
      <b>THREAT HUNTING</b>
      <div className="muted small">가설 → 질의 → 결과 → Pivot → 다음 질의. 모든 질의는 읽기 전용이며, 각 단계의 “왜”를 기록합니다. 전역 범위는 Senior 이상.</div>
      <Panel title="새 Hunt">
        <div className="col">
          <input className="input" placeholder="Hypothesis — 예) 동일 JA4를 사용하는 다른 Cloud IP가 존재하는가" value={hyp} onChange={(e) => setHyp(e.target.value)} />
          <div className="row">
            <select className="input" value={scope} onChange={(e) => setScope(e.target.value)}><option value="investigation">Investigation 범위</option><option value="global">전역 (Senior+)</option></select>
            {scope === "investigation" && <select className="input grow" value={inv} onChange={(e) => setInv(e.target.value)}><option value="">Investigation…</option>{(invs.data || []).map((i: any) => <option key={i.id} value={i.id}>{i.display_id} {i.title}</option>)}</select>}
            {tech && <span className="tag ai">seed: {tech} (inferred)</span>}
            <button className="btn primary" disabled={!hyp.trim() || (scope === "investigation" && !inv)} onClick={() => create.mutate()}>시작</button>
          </div>
          <ErrorBox error={create.error} />
        </div>
      </Panel>
      <table className="t"><thead><tr><th>ID</th><th>Hypothesis</th><th>Scope</th><th>Steps</th><th>Status</th><th>Owner</th><th>Created</th></tr></thead>
        <tbody>{(list.data || []).map((h: any) => <tr key={h.id}><td className="mono"><Link to={`/hunting/${h.id}`}>{h.display_id}</Link></td><td>{h.hypothesis}</td><td>{h.scope}</td><td>{h.budget.steps_used}</td><td>{h.status}{h.outcome ? ` · ${h.outcome}` : ""}</td><td>{h.owner}</td><td className="small">{fmtTime(h.created_at)}</td></tr>)}</tbody></table>
    </>
  );
}

type Row = { field: string; op: string; value: string };

function HNode({ data }: { data: any }) {
  return (
    <div className="snode" style={{ width: 200 }}>
      <Handle type="target" position={Position.Left} />
      <div className="st"><span>{data.kind}</span><span>{data.actor || ""}</span></div>
      <div className="sb small">{data.label}</div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
const nodeTypes = { h: HNode };

function HuntSession() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["hunt", id], queryFn: () => api.get(`/hunts/${id}`) });
  const [rows, setRows] = useState<Row[]>([{ field: "user_agent", op: "is", value: "" }]);
  const [aggs, setAggs] = useState("src_ip,src_as_org");
  const [why, setWhy] = useState("");
  const [actor, setActor] = useState("analyst");
  const [parent, setParent] = useState<number | null>(null);
  const [sel, setSel] = useState<number | null>(null);
  const [concl, setConcl] = useState({ outcome: "inconclusive", summary: "" });
  const inval = () => qc.invalidateQueries({ queryKey: ["hunt", id] });
  const run = useMutation({ mutationFn: () => api.post(`/hunts/${id}/steps`, { rationale: why, actor, parent_seq: parent, query: { filters: rows.filter((r) => r.value).map((r) => ({ field: r.field, op: r.op, value: r.op === "range" ? JSON.parse(r.value) : r.value })), aggs: aggs.split(",").map((f) => f.trim()).filter(Boolean).map((f) => ({ type: "terms", field: f, size: 10 })) } }), onSuccess: () => { setWhy(""); setActor("analyst"); inval(); } });
  const suggest = useMutation({ mutationFn: () => api.post("/ai/actions", { investigation_id: q.data.investigation_id, action: "hunting_query", question: q.data.hypothesis }) });
  const conclude = useMutation({ mutationFn: () => api.post(`/hunts/${id}/conclude`, concl), onSuccess: inval });
  const mkFinding = useMutation({ mutationFn: (seq: number) => api.post(`/hunts/${id}/finding`, { seq, title: q.data.hypothesis.slice(0, 120) }) });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const h = q.data;
  const steps = h.steps as any[];
  const st = steps.find((x) => x.seq === sel) || steps[steps.length - 1];
  const nodes: Node[] = [{ id: "h", type: "h", position: { x: 0, y: 0 }, data: { kind: "HYPOTHESIS", label: h.hypothesis } },
    ...steps.map((x, i) => ({ id: `s${x.seq}`, type: "h", position: { x: 260 * (i + 1), y: (i % 2) * 90 }, data: { kind: `#${x.seq} ${fmtNum(x.result.total)} events`, actor: x.actor === "ai" ? "✦ai→👤" : "👤", label: x.rationale } }))];
  const edges: Edge[] = steps.map((x) => ({ id: `e${x.seq}`, source: x.parent_seq ? `s${x.parent_seq}` : x.seq === 1 ? "h" : `s${x.seq - 1}`, target: `s${x.seq}`, label: x.parent_seq ? "pivot" : "" }));
  const usePivot = (p: any) => { setRows([...(st?.query.filters || []).map((f: any) => ({ field: f.field, op: f.op, value: typeof f.value === "object" ? JSON.stringify(f.value) : String(f.value) })), { field: p.field, op: "is", value: String(p.value) }]); setWhy(p.reason); setParent(st?.seq || null); };
  return (
    <>
      <div className="row wrap"><b>HUNT {h.display_id}</b><span>{h.hypothesis}</span><span className="tag">{h.scope}</span><span className="tag">{h.status}{h.outcome ? ` · ${h.outcome}` : ""}</span>
        <span className="muted small">steps {h.budget.steps_used}/{h.budget.max_steps} · ≤{h.budget.max_days}d · owner {h.owner}</span>
        {h.investigation_id && <Link to={`/inv/${h.investigation_id}`}>Investigation →</Link>}</div>
      <div className="row" style={{ alignItems: "stretch" }}>
        <div className="panel grow" style={{ height: 260 }}>
          <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ maxZoom: 1 }} maxZoom={1.2} colorMode="dark" onNodeClick={(_, n) => n.id.startsWith("s") && setSel(Number(n.id.slice(1)))} proOptions={{ hideAttribution: true }} nodesConnectable={false}>
            <Background gap={24} color="#232838" /><Controls showInteractive={false} />
          </ReactFlow>
        </div>
        <Panel title="Query History" className="" bodyClass="scroll">
          <div style={{ width: 380, maxHeight: 220, overflow: "auto" }}>
            {steps.map((x) => (
              <div key={x.seq} className="small" style={{ borderBottom: "1px solid var(--line)", padding: "3px 0", cursor: "pointer", background: st?.seq === x.seq ? "var(--accent-weak)" : undefined }} onClick={() => setSel(x.seq)}>
                <b>#{x.seq}</b> {x.actor === "ai" ? "✦ai(수락: " + x.accepted_by + ")" : "👤"} <span className="mono">{x.query.filters.map((f: any) => `${f.field} ${f.op} ${JSON.stringify(f.value)}`).join(" AND ") || "*"}</span> → {fmtNum(x.result.total)}
                <div className="muted">why: {x.rationale}</div>
              </div>
            ))}
            {!steps.length && <span className="muted">아직 질의 없음</span>}
          </div>
        </Panel>
      </div>
      {h.status === "active" && (
        <Panel title="Next Query (구조화 — SAW Query Model)">
          {rows.map((r, i) => (
            <div key={i} className="row">
              <input className="input" value={r.field} onChange={(e) => setRows(rows.map((x, j) => (j === i ? { ...x, field: e.target.value } : x)))} />
              <select className="input" value={r.op} onChange={(e) => setRows(rows.map((x, j) => (j === i ? { ...x, op: e.target.value } : x)))}>{["is", "is_not", "prefix", "contains", "exists", "range"].map((o) => <option key={o}>{o}</option>)}</select>
              <input className="input grow" value={r.value} onChange={(e) => setRows(rows.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))} />
              <button className="btn ghost sm" onClick={() => setRows(rows.filter((_, j) => j !== i))}>✕</button>
            </div>
          ))}
          <div className="row wrap"><button className="btn ghost sm" onClick={() => setRows([...rows, { field: "src_ip", op: "is", value: "" }])}>＋ 조건</button>
            <label className="row small">aggs <input className="input" value={aggs} onChange={(e) => setAggs(e.target.value)} /></label>
            <input className="input grow" placeholder="Why (필수) — 이 질의를 하는 이유" value={why} onChange={(e) => setWhy(e.target.value)} />
            <button className="btn primary" disabled={!why.trim() || run.isPending} onClick={() => run.mutate()}>Run</button>
            {h.investigation_id && <button className="btn" onClick={() => suggest.mutate()}>✦ AI 질의 제안</button>}</div>
          {suggest.data?.query?.filters && (
            <div className="ai-block small row wrap"><span className="tag ai">✦ {suggest.data.label}</span><span className="mono">{JSON.stringify(suggest.data.query.filters)}</span>
              <button className="btn sm" onClick={() => { setRows(suggest.data.query.filters.map((f: any) => ({ field: f.field, op: f.op, value: String(f.value) }))); setWhy(suggest.data.answer_md.split("\n")[0]); setActor("ai"); }}>제안 수락(검토 후 실행)</button></div>
          )}
          <ErrorBox error={run.error || suggest.error} />
        </Panel>
      )}
      {st && (
        <div className="row" style={{ alignItems: "flex-start" }}>
          <Panel title={`Results #${st.seq} · ${fmtNum(st.result.total)} events`} className="grow">
            <div className="grid2">{st.result.aggs.map((a: any) => <div key={a.field}><div className="small muted">{a.field}</div><TopBar title={a.field} buckets={a.buckets || []} /></div>)}</div>
            <table className="t"><thead><tr><th>time</th><th>src_ip</th><th>method</th><th>uri</th><th>status</th><th>UA</th></tr></thead>
              <tbody>{st.result.samples.map((e: any) => <tr key={e.event_id}><td className="small">{fmtTime(e.timestamp)}</td><td className="mono">{e.src_ip}</td><td>{e.method}</td><td className="mono ellipsis" style={{ maxWidth: 280 }}>{e.uri}</td><td>{e.status_code}</td><td className="ellipsis" style={{ maxWidth: 160 }}>{e.user_agent}</td></tr>)}</tbody></table>
          </Panel>
          <Panel title="Pivot Candidates">
            <div style={{ width: 300 }} className="col">
              {st.pivots.map((p: any, i: number) => <div key={i} className="small"><b className="mono">{p.field}={String(p.value)}</b><div className="muted">— {p.reason}</div>{h.status === "active" && <button className="btn sm" onClick={() => usePivot(p)}>Use as next query</button>}</div>)}
              {!st.pivots.length && <span className="muted small">결정적 Pivot 후보 없음</span>}
              {h.investigation_id && <button className="btn sm" onClick={() => mkFinding.mutate(st.seq)}>Create Finding from #{st.seq}</button>}
              {mkFinding.data && <Link to={`/inv/${h.investigation_id}?finding=${mkFinding.data.finding_id}`}>Finding 열기 →</Link>}
            </div>
          </Panel>
        </div>
      )}
      {h.status === "active" && (
        <Panel title="Conclude">
          <div className="row"><select className="input" value={concl.outcome} onChange={(e) => setConcl({ ...concl, outcome: e.target.value })}>{["confirmed", "refuted", "inconclusive"].map((o) => <option key={o}>{o}</option>)}</select>
            <input className="input grow" placeholder="결론 요약" value={concl.summary} onChange={(e) => setConcl({ ...concl, summary: e.target.value })} />
            <button className="btn" onClick={() => conclude.mutate()}>Conclude</button></div>
        </Panel>
      )}
      {h.outcome_md && <Panel title="Outcome"><div className="pre">{h.outcome_md}</div></Panel>}
    </>
  );
}
