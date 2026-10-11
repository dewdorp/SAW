import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox } from "../../components/common";
import { api } from "../../lib/api";

/** Pull events from a SIEM connector into this investigation (read-only, custody-tracked). */
export function ConnectorImport({ inv, onClose }: { inv: string; onClose: () => void }) {
  const conns = useQuery({ queryKey: ["connectors"], queryFn: () => api.get("/connectors") });
  const [cid, setCid] = useState("");
  const [field, setField] = useState("src_ip");
  const [value, setValue] = useState("");
  const m = useMutation({ mutationFn: () => api.post(`/investigations/${inv}/connector-import`, { connector_id: cid || conns.data?.[0]?.id, filters: [{ field, op: "is", value }] }) });
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="modal panel" role="dialog" aria-label="Import from SIEM">
        <div className="ph"><span className="grow">SIEM에서 가져오기 (read-only)</span><button className="btn ghost sm" onClick={onClose}>✕</button></div>
        <div className="pb col">
          {!conns.data?.length ? <div className="muted">활성 Connector가 없습니다 (Admin › Integrations).</div> : (
            <>
              <div className="row wrap">
                <select className="input" value={cid} onChange={(e) => setCid(e.target.value)}>{conns.data.map((c: any) => <option key={c.id} value={c.id}>{c.name} ({c.kind})</option>)}</select>
                <input className="input" value={field} onChange={(e) => setField(e.target.value)} />
                <span>=</span>
                <input className="input grow" placeholder="값 (예: 104.248.11.20)" value={value} onChange={(e) => setValue(e.target.value)} />
                <button className="btn primary" disabled={!value} onClick={() => m.mutate()}>가져오기</button>
              </div>
              {m.data && <div className="tag ok">{m.data.imported}건 가져옴 · 재분석 Job 시작</div>}
              <ErrorBox error={m.error} />
            </>
          )}
        </div>
      </div>
    </>
  );
}
