import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Panel } from "../components/common";
import { api } from "../lib/api";
import { fmtTime } from "../lib/format";

/** Admin › Integrations: SecurityDataConnector configs (read-only connectors, write-only secrets). */
export function Integrations() {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["connectors-admin"], queryFn: () => api.get("/admin/connectors") });
  const [f, setF] = useState({ name: "siem-mock", kind: "mock_logpresso", url: "", secret: "" });
  const save = useMutation({ mutationFn: () => api.post("/admin/connectors", { name: f.name, kind: f.kind, settings: f.url ? { url: f.url } : {}, secret: f.secret || null }), onSuccess: () => { setF({ ...f, secret: "" }); qc.invalidateQueries({ queryKey: ["connectors-admin"] }); } });
  const health = useMutation({ mutationFn: (id: string) => api.post(`/admin/connectors/${id}/health`), onSuccess: () => qc.invalidateQueries({ queryKey: ["connectors-admin"] }) });
  return (
    <Panel title="Integrations — Security Data Connectors (read-only)">
      <div className="muted small">실제 Logpresso Connector는 공식 API 문서 확보 전까지 구현하지 않습니다 (ENV-11). Mock Connector는 합성 데이터입니다. 비밀값은 암호화 저장되며 다시 조회할 수 없습니다.</div>
      <table className="t"><thead><tr><th>name</th><th>kind</th><th>enabled</th><th>secret</th><th>health</th><th /></tr></thead>
        <tbody>{(list.data || []).map((c: any) => (
          <tr key={c.id}><td>{c.name}</td><td className="mono">{c.kind}</td><td>{c.enabled ? "✓" : "–"}</td><td>{c.has_secret ? "🔒 set" : "–"}</td>
            <td className="small">{c.last_health?.detail ? `${c.last_health.ok ? "✓" : "✗"} ${c.last_health.detail} ${fmtTime(c.last_health.at)}` : "–"}</td>
            <td><button className="btn sm" onClick={() => health.mutate(c.id)}>Health check</button></td></tr>))}</tbody></table>
      <div className="row wrap" style={{ marginTop: 8 }}>
        <input className="input" placeholder="name" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />
        <select className="input" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}><option value="mock_logpresso">mock_logpresso</option><option value="logpresso">logpresso (미구현)</option></select>
        <input className="input" placeholder="https://siem.internal (선택)" value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} />
        <input className="input" type="password" placeholder="API secret (write-only)" value={f.secret} onChange={(e) => setF({ ...f, secret: e.target.value })} autoComplete="new-password" />
        <button className="btn primary sm" onClick={() => save.mutate()}>저장</button>
      </div>
      <ErrorBox error={save.error || health.error} />
    </Panel>
  );
}
