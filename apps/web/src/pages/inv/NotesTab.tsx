import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Panel } from "../../components/common";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtTime } from "../../lib/format";

/** Notes: plain text rendering (no HTML), optional timeline anchor. */
export function NotesTab({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const qc = useQueryClient();
  const [body, setBody] = useState("");
  const [anchor, setAnchor] = useState(true);
  const notes = useQuery({ queryKey: ["notes", inv], queryFn: () => api.get(`/investigations/${inv}/notes`) });
  const ev = useQuery({ queryKey: ["event", inv, ctx.eventId], queryFn: () => api.get(`/investigations/${inv}/events/${ctx.eventId}`), enabled: !!ctx.eventId });
  const add = useMutation({
    mutationFn: () => api.post(`/investigations/${inv}/notes`, { body_md: body, ts: anchor ? ev.data?.event?.timestamp || new Date().toISOString() : null,
      links: [ctx.eventId ? `evt:${ctx.eventId}` : null, ctx.selection ? `${ctx.selection.type}:${ctx.selection.value}` : null].filter(Boolean) }),
    onSuccess: () => { setBody(""); qc.invalidateQueries({ queryKey: ["notes", inv] }); qc.invalidateQueries({ queryKey: ["timeline", inv] }); },
  });
  return (
    <div className="col">
      <Panel title="새 노트">
        <textarea className="input" rows={3} value={body} onChange={(e) => setBody(e.target.value)} placeholder="예) DB팀 확인: 배치 아님" />
        <div className="row small"><label className="row"><input type="checkbox" checked={anchor} onChange={(e) => setAnchor(e.target.checked)} />Timeline에 표시 ({ctx.eventId ? "선택 이벤트 시각" : "현재 시각"})</label>
          {ctx.selection && <span className="tag">link: {ctx.selection.type}:{ctx.selection.value}</span>}
          <div className="grow" /><button className="btn sm primary" disabled={!body.trim()} onClick={() => add.mutate()}>추가</button></div>
        <ErrorBox error={add.error} />
      </Panel>
      {(notes.data || []).map((n: any) => (
        <Panel key={n.id} title={`${n.author} · ${fmtTime(n.created_at)}${n.ts ? ` · ⏱ ${fmtTime(n.ts)}` : ""}`}>
          <div className="pre">{n.body_md}</div>
          {n.links.length > 0 && <div className="small muted">{n.links.join(" · ")}</div>}
        </Panel>
      ))}
    </div>
  );
}
