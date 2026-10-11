import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { fmtTime } from "../lib/format";
import { ErrorBox } from "./common";

/** Support: one separate question of an investigation handed to a colleague. The owner stays the owner. */
const TONE: Record<string, string> = { requested: "accent", working: "accent", done: "ok", declined: "warn", cancelled: "" };

function Report({ r, onDone }: { r: any; onDone: () => void }) {
  const [note, setNote] = useState("");
  const [remaining, setRemaining] = useState("");
  const send = useMutation({ mutationFn: (status: string) => api.post(`/support/${r.id}`, { status, result_note: note, remaining }), onSuccess: onDone });
  return (
    <div className="col" style={{ gap: 6 }}>
      <input className="input" aria-label="지원 결과" placeholder="확인한 결과 한 줄 (완료 시 필수) — 확인 기록은 조사 안에 따로 남기세요" value={note} onChange={(e) => setNote(e.target.value)} />
      <input className="input" aria-label="남은 확인" placeholder="확인하지 못한 것 (선택)" value={remaining} onChange={(e) => setRemaining(e.target.value)} />
      <ErrorBox error={send.error} />
      <div className="row">
        <Link className="btn sm" to={`/inv/${r.investigation_id}`}>조사 열기</Link><div className="grow" />
        {r.status === "requested" && <button className="btn sm" onClick={() => send.mutate("working")}>맡아서 진행</button>}
        <button className="btn sm" onClick={() => send.mutate("declined")}>맡을 수 없음</button>
        <button className="btn sm primary" disabled={note.trim().length < 5} onClick={() => send.mutate("done")}>완료 보고</button>
      </div>
    </div>
  );
}

export function SupportItem({ r, me, showInv = false, onChanged, canCancel = false }: { r: any; me: string; showInv?: boolean; onChanged: () => void; canCancel?: boolean }) {
  const cancel = useMutation({ mutationFn: () => api.post(`/investigations/${r.investigation_id}/support/${r.id}/cancel`, {}), onSuccess: onChanged });
  return (
    <div className="ck-item">
      <div className="row wrap small">
        <span className={`tag ${TONE[r.status] || ""}`}>{r.status_ko}</span><b>{r.question}</b>
        {showInv && r.investigation && <Link to={`/inv/${r.investigation.id}`}>{r.investigation.display_id} {r.investigation.title}</Link>}
        <span className="grow" /><span className="muted">{r.requested_by} → {r.helper} · {fmtTime(r.created_at)}</span>
      </div>
      {r.scope_note && <div className="small"><span className="muted">범위</span> {r.scope_note}</div>}
      {r.result_note && <div className="small"><span className="muted">결과({r.helper})</span> {r.result_note}</div>}
      {r.remaining && <div className="small d-chg">확인하지 못한 것: {r.remaining}</div>}
      {r.open && r.helper_id === me && <Report r={r} onDone={onChanged} />}
      {r.open && canCancel && r.helper_id !== me && <div className="row small"><a onClick={() => cancel.mutate()}>요청 취소</a></div>}
      <ErrorBox error={cancel.error} />
    </div>
  );
}

export function SupportPanel({ inv }: { inv: string }) {
  const qc = useQueryClient();
  const [ask, setAsk] = useState(false);
  const [question, setQuestion] = useState("");
  const [scope, setScope] = useState("");
  const [helper, setHelper] = useState("");
  const q = useQuery({ queryKey: ["support", inv], queryFn: () => api.get(`/investigations/${inv}/support`) });
  const people = useQuery({ queryKey: ["reviewers"], queryFn: () => api.get("/reviews/reviewers"), enabled: ask });
  const changed = () => { qc.invalidateQueries({ queryKey: ["support", inv] }); qc.invalidateQueries({ queryKey: ["support-inbox"] }); };
  const send = useMutation({
    mutationFn: () => api.post(`/investigations/${inv}/support`, { question, scope_note: scope, helper_id: helper }),
    onSuccess: () => { setAsk(false); setQuestion(""); setScope(""); setHelper(""); changed(); },
  });
  const rows = q.data?.items || [];
  return (
    <div className="col" style={{ gap: 6 }}>
      <div className="row small">
        <span className="muted">{rows.length ? `지원 요청 ${rows.length}건` : "지원 요청 없음"}</span><span className="grow" />
        {q.data?.can_request && !ask && <button className="btn sm" onClick={() => setAsk(true)}>지원 요청</button>}
      </div>
      {ask && (
        <div className="ck-item">
          <div className="small muted">다른 사람이 따로 맡아 동시에 확인할 수 있는 질문일 때만 요청하세요. 조사 담당과 결론은 그대로 담당자에게 남고, 지원자는 이 조사의 결론을 검토할 수 없게 됩니다.</div>
          <input className="input" aria-label="지원 질문" placeholder="확인할 질문 예) 응답·패킷에서 실행 성공 여부 확인" value={question} onChange={(e) => setQuestion(e.target.value)} />
          <input className="input" aria-label="지원 범위" placeholder="대상·시간 범위 (선택) 예) 10.20.1.15, 03시 이후" value={scope} onChange={(e) => setScope(e.target.value)} />
          <select className="input" aria-label="지원자" value={helper} onChange={(e) => setHelper(e.target.value)}>
            <option value="">지원자 선택</option>
            {(people.data || []).map((p: any) => <option key={p.id} value={p.id}>{p.name} ({p.username})</option>)}
          </select>
          <ErrorBox error={send.error} />
          <div className="row"><div className="grow" /><button className="btn sm ghost" onClick={() => setAsk(false)}>취소</button>
            <button className="btn sm primary" disabled={!helper || question.trim().length < 5 || send.isPending} onClick={() => send.mutate()}>요청 보내기</button></div>
        </div>
      )}
      {rows.map((r: any) => <SupportItem key={r.id} r={r} me={q.data.me} onChanged={changed} canCancel={q.data.can_request} />)}
      <ErrorBox error={q.error} />
    </div>
  );
}

/** Home: questions colleagues asked me to take on. */
export function SupportInbox() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["support-inbox"], queryFn: () => api.get("/support/inbox"), refetchInterval: 60000 });
  const me = useQuery<any>({ queryKey: ["me"], queryFn: () => api.get("/auth/me"), staleTime: 60_000 });
  const rows = q.data?.items || [];
  if (!rows.length) return null;
  return (
    <section className="panel">
      <div className="ph"><span className="grow">지원 요청받은 것 {rows.length}건</span></div>
      <div className="pb col" style={{ gap: 6 }}>{rows.map((r: any) => <SupportItem key={r.id} r={r} me={me.data?.id || ""} showInv onChanged={() => qc.invalidateQueries({ queryKey: ["support-inbox"] })} />)}</div>
    </section>
  );
}
