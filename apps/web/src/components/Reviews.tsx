import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { fmtTime } from "../lib/format";
import { ErrorBox } from "./common";

/** Peer review of one important conclusion: asked of someone else, answered with how far they agree. */
export type ReviewSubject = { type: "finding" | "conclusion" | "other"; id?: string; label?: string; conclusion?: string; evidence?: string[] };
const OUTCOMES: [string, string, string][] = [
  ["approved", "근거가 결론을 지지함", "ok"], ["too_broad", "결론 범위가 너무 넓음", "warn"],
  ["insufficient", "자료 부족", "warn"], ["changes_requested", "보완 요청", "warn"],
];
const TONE: Record<string, string> = { needed: "bad", requested: "accent", approved: "ok", too_broad: "warn", insufficient: "warn", changes_requested: "warn", withdrawn: "" };

export function ReviewRequestDialog({ inv, subject, onClose }: { inv: string; subject: ReviewSubject; onClose: () => void }) {
  const qc = useQueryClient();
  const people = useQuery({ queryKey: ["reviewers"], queryFn: () => api.get("/reviews/reviewers") });
  const [reviewer, setReviewer] = useState("");
  const [conclusion, setConclusion] = useState(subject.conclusion || "");
  const [scope, setScope] = useState("");
  const send = useMutation({
    mutationFn: () => api.post(`/investigations/${inv}/reviews`, { subject_type: subject.type, subject_id: subject.id || "", subject_label: subject.label || "",
      conclusion, scope_note: scope, evidence: subject.evidence || [], reviewer_id: reviewer }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["reviews", inv] }); qc.invalidateQueries({ queryKey: ["briefing", inv] }); onClose(); },
  });
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="modal panel" role="dialog" aria-label="검토 요청" style={{ width: 560 }}>
        <div className="ph"><span className="grow">검토 요청</span><button className="btn ghost sm" onClick={onClose}>닫기</button></div>
        <div className="pb col" style={{ gap: 10 }}>
          <div className="small muted">검토자는 조사 전체를 다시 하는 것이 아니라, 아래 결론이 근거와 확인 범위에 맞는지를 봅니다. 요청하면 검토자에게 이 조사의 읽기 권한이 주어집니다.</div>
          {subject.label && <div className="small"><span className="muted">대상</span> {subject.label}</div>}
          <textarea className="input" rows={2} aria-label="검토받을 결론" placeholder="검토받을 결론 한 줄 예) 02~03시 요청은 정산 배치의 정상 조회로 판단" value={conclusion} onChange={(e) => setConclusion(e.target.value)} />
          <input className="input" aria-label="확인한 범위" placeholder="확인한 범위와 아직 모르는 것 (선택) 예) 응답 본문은 확인하지 못함" value={scope} onChange={(e) => setScope(e.target.value)} />
          <select className="input" aria-label="검토자" value={reviewer} onChange={(e) => setReviewer(e.target.value)}>
            <option value="">검토자 선택</option>
            {(people.data || []).map((p: any) => <option key={p.id} value={p.id}>{p.name} ({p.username}){p.senior ? " · 선임/매니저" : ""}</option>)}
          </select>
          <div className="small muted">자료의 한계(빠진 자료, 표본 확인 등)는 자동으로 함께 전달됩니다.</div>
          <ErrorBox error={send.error || people.error} />
          <div className="row"><div className="grow" /><button className="btn primary" disabled={!reviewer || !conclusion.trim() || send.isPending} onClick={() => send.mutate()}>검토 요청 보내기</button></div>
        </div>
      </div>
    </>
  );
}

function Decide({ r, onDone }: { r: any; onDone: () => void }) {
  const [outcome, setOutcome] = useState("");
  const [note, setNote] = useState("");
  const send = useMutation({ mutationFn: () => api.post(`/reviews/${r.id}/decide`, { outcome, note }), onSuccess: onDone });
  return (
    <div className="col" style={{ gap: 6 }}>
      <div className="row wrap">{OUTCOMES.map(([k, l]) => (
        <label key={k} className={`chip-check ${outcome === k ? "on" : ""}`}><input type="radio" name={`rv-${r.id}`} checked={outcome === k} onChange={() => setOutcome(k)} />{l}</label>))}</div>
      <input className="input" aria-label="검토 의견" placeholder="어떤 근거를 확인했고 어디까지 동의하는지 한 줄 (필수)" value={note} onChange={(e) => setNote(e.target.value)} />
      <ErrorBox error={send.error} />
      <div className="row"><div className="grow" /><button className="btn sm primary" disabled={!outcome || note.trim().length < 5 || send.isPending} onClick={() => send.mutate()}>검토 결과 저장</button></div>
    </div>
  );
}

export function ReviewItem({ r, me, inv, canEdit = true, showInv = false, onChanged }: { r: any; me: string; inv?: string; canEdit?: boolean; showInv?: boolean; onChanged: () => void }) {
  const [ask, setAsk] = useState(false);
  const withdraw = useMutation({ mutationFn: () => api.post(`/investigations/${r.investigation_id}/reviews/${r.id}/withdraw`, {}), onSuccess: onChanged });
  return (
    <div className="ck-item" style={r.latest === false ? { opacity: 0.55 } : undefined}>
      <div className="row wrap small">
        <span className={`tag ${TONE[r.status] || ""}`}>{r.status_ko}</span>
        {r.required && <span className="tag" title="높은 위험 탐지를 정상·오탐으로 낮추거나 공격으로 종결하면 자동으로 생깁니다">검토 대상</span>}
        {r.stale && <span className="tag bad">결론이 바뀜 — 다시 검토 필요</span>}
        <b>{r.subject_ko}</b><span className="ellipsis" style={{ maxWidth: 320 }}>{r.subject_label}</span>
        {showInv && r.investigation && <Link to={`/inv/${r.investigation.id}`}>{r.investigation.display_id} {r.investigation.title}</Link>}
        <span className="grow" /><span className="muted">{r.requested_by}{r.reviewer ? ` → ${r.reviewer}` : ""} · {fmtTime(r.created_at)}</span>
      </div>
      <div className="small"><span className="muted">결론</span> {r.conclusion}</div>
      {r.scope_note && <div className="small"><span className="muted">확인 범위</span> {r.scope_note}</div>}
      {r.limits?.length > 0 && r.status === "requested" && <div className="small muted">자료의 한계: {r.limits.join(" / ")}</div>}
      {r.outcome_note && <div className="small"><span className="muted">검토 의견({r.reviewer})</span> {r.outcome_note}</div>}
      {r.status === "requested" && r.reviewer_id === me && <Decide r={r} onDone={onChanged} />}
      {canEdit && inv && r.latest !== false && (
        <div className="row small">
          {(r.status === "needed" || r.stale || ["too_broad", "insufficient", "changes_requested"].includes(r.status)) && r.open &&
            <a onClick={() => setAsk(true)}>{r.status === "needed" ? "검토자 지정해 요청" : "보완해서 다시 요청"}</a>}
          {r.status === "requested" && r.requested_by_id === me && <a onClick={() => withdraw.mutate()}>요청 취소</a>}
        </div>
      )}
      <ErrorBox error={withdraw.error} />
      {ask && inv && <ReviewRequestDialog inv={inv} subject={{ type: r.subject_type, id: r.subject_id, label: r.subject_label, conclusion: r.conclusion, evidence: r.evidence }} onClose={() => { setAsk(false); onChanged(); }} />}
    </div>
  );
}

/** Reviews of an investigation (optionally of one subject), with a way to ask for one. */
export function ReviewPanel({ inv, subject, canEdit = true }: { inv: string; subject?: ReviewSubject; canEdit?: boolean }) {
  const qc = useQueryClient();
  const [ask, setAsk] = useState(false);
  const q = useQuery({ queryKey: ["reviews", inv], queryFn: () => api.get(`/investigations/${inv}/reviews`) });
  const rows = (q.data?.reviews || []).filter((r: any) => !subject || (r.subject_type === subject.type && (r.subject_id || "") === (subject.id || "")));
  const changed = () => { qc.invalidateQueries({ queryKey: ["reviews", inv] }); qc.invalidateQueries({ queryKey: ["briefing", inv] }); qc.invalidateQueries({ queryKey: ["review-inbox"] }); };
  const open = rows.filter((r: any) => r.open).length;
  return (
    <div className="col" style={{ gap: 6 }}>
      <div className="row small">
        <span className="muted">{rows.length ? `검토 ${rows.length}건${open ? ` · 끝나지 않은 것 ${open}건` : ""}` : "검토 요청 없음"}</span>
        <span className="grow" />
        {canEdit && <button className="btn sm" onClick={() => setAsk(true)}>검토 요청</button>}
      </div>
      {rows.map((r: any) => <ReviewItem key={r.id} r={r} me={q.data.me} inv={inv} canEdit={canEdit} onChanged={changed} />)}
      <ErrorBox error={q.error} />
      {ask && <ReviewRequestDialog inv={inv} subject={subject || { type: "other" }} onClose={() => setAsk(false)} />}
    </div>
  );
}

/** Home: what I was asked to review, and answers to my requests that need something from me. */
export function ReviewInbox() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["review-inbox"], queryFn: () => api.get("/reviews/inbox"), refetchInterval: 60000 });
  const me = useQuery<any>({ queryKey: ["me"], queryFn: () => api.get("/auth/me"), staleTime: 60_000 });
  const todo = q.data?.to_review || [], back = q.data?.returned || [];
  if (!todo.length && !back.length) return null;
  const changed = () => qc.invalidateQueries({ queryKey: ["review-inbox"] });
  return (
    <section className="panel">
      <div className="ph"><span className="grow">검토 {todo.length ? `요청받은 것 ${todo.length}건` : ""}{todo.length && back.length ? " · " : ""}{back.length ? `내 요청 중 처리할 것 ${back.length}건` : ""}</span></div>
      <div className="pb col" style={{ gap: 6 }}>
        {todo.map((r: any) => <ReviewItem key={r.id} r={r} me={me.data?.id || ""} showInv onChanged={changed} canEdit={false} />)}
        {back.map((r: any) => <ReviewItem key={r.id} r={r} me={me.data?.id || ""} inv={r.investigation_id} showInv onChanged={changed} />)}
      </div>
    </section>
  );
}
