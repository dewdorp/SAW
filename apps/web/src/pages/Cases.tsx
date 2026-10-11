import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PageHeader } from "../components/ui";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { FindingChecks } from "../components/analysis";
import { ErrorBox, Loading, Panel, Sev } from "../components/common";
import { api } from "../lib/api";
import { fmtTime } from "../lib/format";

export function Cases() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["cases"], queryFn: () => api.get("/cases") });
  const [title, setTitle] = useState("");
  const create = useMutation({ mutationFn: () => api.post("/cases", { title }), onSuccess: () => { setTitle(""); qc.invalidateQueries({ queryKey: ["cases"] }); } });
  return (
    <div className="page col">
      <PageHeader eyebrow="보고·인계" title="케이스" desc="조사 결과를 보고·인계용으로 정리합니다. 대응 기록에는 사람이 수행한 조치만 적습니다." />
      <div className="row"><b>CASES</b><div className="grow" /><input className="input" placeholder="새 Case 제목" value={title} onChange={(e) => setTitle(e.target.value)} /><button className="btn primary" disabled={!title.trim()} onClick={() => create.mutate()}>생성</button></div>
      <ErrorBox error={create.error} />
      {q.isLoading ? <Loading /> : (
        <table className="t"><thead><tr><th>Severity</th><th>ID</th><th>Title</th><th>Status</th><th>Verdict</th><th>Created</th></tr></thead>
          <tbody>{(q.data || []).map((c: any) => <tr key={c.id}><td><Sev level={c.severity} /></td><td className="mono"><Link to={`/cases/${c.id}`}>{c.display_id}</Link></td><td>{c.title}</td><td>{c.status}</td><td>{c.verdict || "–"}</td><td className="small">{fmtTime(c.created_at)}</td></tr>)}</tbody></table>
      )}
    </div>
  );
}

export function CaseDetail() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["case", id], queryFn: () => api.get(`/cases/${id}`) });
  const hist = useQuery({ queryKey: ["case-hist", id], queryFn: () => api.get(`/cases/${id}/history`) });
  const [edit, setEdit] = useState<any>(null);
  const save = useMutation({ mutationFn: (p: any) => api.patch(`/cases/${id}`, p), onSuccess: () => { setEdit(null); qc.invalidateQueries({ queryKey: ["case", id] }); qc.invalidateQueries({ queryKey: ["case-hist", id] }); } });
  const exp = async () => {
    const md = await api.text(`/cases/${id}/export`);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([md], { type: "text/markdown" }));
    a.download = `${q.data.display_id}.md`;
    a.click();
  };
  if (q.isLoading) return <Loading />;
  if (q.error) return <div className="page"><ErrorBox error={q.error} /></div>;
  const c = q.data;
  const e = edit || c;
  return (
    <div className="page col" style={{ maxWidth: 1200 }}>
      <div className="row wrap"><b>{c.display_id}</b><span>{c.title}</span><Sev level={c.severity} />
        <select className="input" value={e.status} onChange={(x) => save.mutate({ status: x.target.value })}>{["open", "in_progress", "resolved", "closed"].map((s) => <option key={s}>{s}</option>)}</select>
        <select className="input" value={e.verdict || ""} onChange={(x) => save.mutate({ verdict: x.target.value || null })}><option value="">verdict…</option>{["attack", "normal", "false_positive", "unknown"].map((s) => <option key={s}>{s}</option>)}</select>
        <div className="grow" /><button className="btn sm" onClick={exp}>Export (Markdown, masked)</button></div>
      <div className="row small">Investigations: {c.investigation_ids.map((i: string) => <Link key={i} to={`/inv/${i}`}>{i.slice(0, 8)} </Link>)}</div>
      <div className="grid2">
        <Panel title="Summary" right={<button className="btn ghost sm" onClick={() => setEdit(edit ? null : { ...c })}>{edit ? "취소" : "편집"}</button>}>
          {edit ? <><textarea className="input" rows={5} value={edit.summary_md} onChange={(x) => setEdit({ ...edit, summary_md: x.target.value })} /><button className="btn sm primary" onClick={() => save.mutate({ summary_md: edit.summary_md, response_md: edit.response_md })}>저장</button></> : <div className="pre">{c.summary_md || "—"}</div>}
        </Panel>
        <Panel title="Response (사람이 수행한 대응 기록)">
          {edit ? <textarea className="input" rows={5} value={edit.response_md} onChange={(x) => setEdit({ ...edit, response_md: x.target.value })} /> : <div className="pre">{c.response_md || "—"}</div>}
        </Panel>
      </div>
      <Panel title={`Items (${c.items.length})`}>
        {c.items.map((it: any) => (
          <div key={it.id} className="col" style={{ borderBottom: "1px solid var(--line)", padding: "4px 0" }}>
            {it.type === "finding" ? (<><div className="row"><Sev level={it.snapshot.risk_level} score={it.snapshot.risk_score} /><b>{it.snapshot.display_id} {it.snapshot.title}</b><span className="muted small">snapshot {fmtTime(it.added_at)}</span></div><FindingChecks checks={it.snapshot.checks || []} /></>)
              : <div className="small"><span className="tag">{it.type}</span> {it.ref_id}</div>}
          </div>
        ))}
        {!c.items.length && <span className="muted small">Finding 상세에서 “Add to Case”로 추가</span>}
      </Panel>
      <Panel title="History">{(hist.data || []).map((h: any) => <div key={h.rev} className="small mono">r{h.rev} {fmtTime(h.at)} {h.actor} {Object.keys(h.diff).join(", ")}</div>)}</Panel>
      <ErrorBox error={save.error} />
    </div>
  );
}
