import { useQuery } from "@tanstack/react-query";
import { IocCard } from "../../components/analysis";
import { TargetChecks } from "../../components/Checks";
import { ErrorBox, Loading, Panel, Sev } from "../../components/common";
import { entityKey } from "../../context/invContext";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtNum, fmtTime } from "../../lib/format";

export function EntityTab({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const e = ctx.selection;
  const q = useQuery({ queryKey: ["entity", inv, e], enabled: !!e, queryFn: () => api.get(`/investigations/${inv}/entities/${e!.type}?value=${encodeURIComponent(e!.value)}`) });
  if (!e) return <div className="empty">Entity를 선택하세요.</div>;
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data;
  return (
    <div className="col">
      <div className="row"><b>{e.type}</b><span className="mono">{e.value}</span><span className="muted">{fmtNum(d.total)} events</span>
        <button className="btn sm" onClick={() => ctx.addFilter({ field: e.type === "ip" ? "src_ip" : e.type === "uri" ? "uri_template" : e.type, op: "is", value: e.value })}>Filter include</button>
        <button className="btn sm" onClick={() => ctx.set({ tab: "timeline" })}>Timeline</button><button className="btn sm" onClick={() => ctx.set({ tab: "relations" })}>Graph</button></div>
      <Panel title="확인 기록"><TargetChecks inv={inv} target={{ type: "entity", key: entityKey(e), label: `${e.type} ${e.value}` }} /></Panel>
      {Object.entries(d.stats).map(([f, s]: any) => (
        <Panel key={f} title={`as ${f}`}>
          <div className="small">{fmtTime(s.first)} ~ {fmtTime(s.last)} · {s.by_source.map((b: any) => `${b.key} ${fmtNum(b.count)}`).join(" · ")}</div>
          <div className="grid2"><div>{s.top_uri.map((b: any) => <div key={b.key} className="row small mono"><span className="grow ellipsis">{b.key}</span><span>{fmtNum(b.count)}</span></div>)}</div>
            <div>{s.top_status.map((b: any) => <div key={b.key} className="row small mono"><span className="grow">{b.key}</span><span>{fmtNum(b.count)}</span></div>)}</div></div>
        </Panel>
      ))}
      <Panel title="Related Findings">{d.findings.map((f: any) => <div key={f.id} className="row"><Sev level={f.risk_level} /><a onClick={() => ctx.set({ tab: "findings", findingId: f.id })}>{f.display_id} {f.title}</a></div>)}{!d.findings.length && <span className="muted small">없음</span>}</Panel>
      {d.ioc && <IocCard r={d.ioc} />}
    </div>
  );
}
