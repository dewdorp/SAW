import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtNum, fmtTime, pct } from "../../lib/format";
import { RequestEvolution } from "../analyze/DiffPage";
import { StepPlot } from "./FindingsTab";

/** HTTP tab: behavioral patterns, parameter analyzer, request compare from log events (docs/19 §4-5, docs/18). */
export function HttpTab({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const pats = useQuery({ queryKey: ["patterns", inv], queryFn: () => api.get(`/investigations/${inv}/patterns`) });
  const params = useQuery({ queryKey: ["parameters", inv], queryFn: () => api.get(`/investigations/${inv}/parameters`) });
  const [src, setSrc] = useState("");
  const [path, setPath] = useState("");
  const diff = useMutation({ mutationFn: () => api.post(`/investigations/${inv}/diff`, { src_ip: src, url_path: path || null }) });
  const [open, setOpen] = useState<number | null>(0);
  return (
    <div className="col">
      <Panel title={`Behavioral Patterns (${pats.data?.length ?? "…"}) — 수백만 이벤트를 패턴으로`}>
        {pats.isLoading && <Loading />}<ErrorBox error={pats.error} />
        <table className="t"><thead><tr><th>#</th><th>Pattern</th><th className="num">Events</th><th className="num">Src</th><th>First → Last</th><th>Tags</th></tr></thead>
          <tbody>{(pats.data || []).slice(0, 60).map((p: any) => (
            <tr key={p.id} style={{ cursor: "pointer" }} onClick={() => p.key?.uri_template && ctx.addFilter({ field: "uri_template", op: "is", value: p.key.uri_template })}>
              <td className="muted">{String(p.seq).padStart(2, "0")}</td><td className="mono ellipsis" style={{ maxWidth: 520 }}>{p.template} <span className="muted">{p.key?.status_class || ""}</span></td>
              <td className="num">{fmtNum(p.count)}</td><td className="num">{p.srcs || ""}</td><td className="small">{fmtTime(p.first, false)} → {fmtTime(p.last, false)}</td>
              <td>{p.tags.map((t: string) => <span key={t} className={`tag ${/probe|injection|scanner/.test(t) ? "warn" : ""}`}>{t}</span>)}</td>
            </tr>))}</tbody></table>
      </Panel>
      <Panel title="Parameter Analyzer">
        {params.isLoading && <Loading />}
        {(params.data || []).slice(0, 30).map((p: any, i: number) => {
          const pr = p.profile;
          return (
            <div key={i} style={{ borderBottom: "1px solid var(--line)", padding: "4px 0" }}>
              <div className="row small" style={{ cursor: "pointer" }} onClick={() => setOpen(open === i ? null : i)}>
                <span className="mono"><b>{p.param}</b> @ {p.uri_template}</span><span className="tag">{pr.type}</span>
                <span>Unique {fmtNum(pr.unique)}</span>
                {pr.sequential_ratio !== undefined && <span>Sequential {pct(pr.sequential_ratio)} {pr.increment}</span>}
                {pr.potential_behavior && <span className="tag warn">Potential Behavior: {pr.potential_behavior}</span>}
                {pr.payload_families && <span className="tag bad">payload: {Object.keys(pr.payload_families).join(",")}</span>}
                {pr.sampled && <span className="muted">sampled</span>}
              </div>
              {open === i && (
                <div className="grid2" style={{ marginTop: 4 }}>
                  <div className="small mono">
                    <div>length {pr.length.min}/{pr.length.p50}/{pr.length.p95}/{pr.length.max} · entropy {pr.entropy_avg}</div>
                    {pr.numeric_range && <div>range {pr.numeric_range.min} ~ {pr.numeric_range.max} (coverage {pct(pr.numeric_range.coverage)})</div>}
                    {pr.common_prefix && <div>prefix {pr.common_prefix}</div>}
                    <div className="muted">samples: {pr.samples.join(", ")}</div>
                  </div>
                  {pr.step_sample?.length > 0 && <StepPlot values={pr.step_sample} label="value step" />}
                </div>
              )}
            </div>
          );
        })}
      </Panel>
      <Panel title="Request Compare (로그 이벤트 기반, partial: 헤더/바디 없음)">
        <div className="row"><input className="input" placeholder="src_ip" value={src} onChange={(e) => setSrc(e.target.value)} /><input className="input grow" placeholder="url_path (선택)" value={path} onChange={(e) => setPath(e.target.value)} />
          <button className="btn sm" disabled={!src} onClick={() => diff.mutate()}>Compare</button>
          {ctx.selection?.type === "ip" && <button className="btn sm ghost" onClick={() => setSrc(ctx.selection!.value)}>선택 IP 사용</button>}</div>
        <ErrorBox error={diff.error} />
        {diff.data && <RequestEvolution r={diff.data} />}
      </Panel>
    </div>
  );
}
