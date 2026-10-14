import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { useMe } from "../App";
import { ErrorBox, Loading, Panel } from "../components/common";
import { api, ApiError } from "../lib/api";
import { fmtTime } from "../lib/format";

const LABELS: Record<string, string> = { required_facts_actions: "필수 사실과 조사 항목 확인",
  judgement_evidence: "판단과 근거 확인", followups: "후속확인 확인", forbidden_claims: "금지 주장 확인" };
const CATEGORIES: Record<string, string> = { attack: "공격", benign_pattern: "정상 업무", false_positive: "오탐", operational: "운영·정보 부족", tuning: "탐지 조정" };
const VERDICTS: Record<string, string> = { attack: "공격 시도", normal: "정상", false_positive: "오탐", unknown: "미확인" };
const STATES: Record<string, string> = { draft: "채택 초안", adopted: "채택됨", declined: "미채택", withdrawn: "철회됨" };
const SPLITS: Record<string, string> = { train: "학습용", dev: "개발평가용", holdout: "비공개 평가용" };
export type GoldenChoice = { payload?: any; valid: boolean };
const lines = (v: string) => v.split("\n").map(x => x.trim()).filter(Boolean);
const followText = (v: any) => typeof v === "string" ? v : [v.target, ...(v.needed_data || []), ...(v.items || []), v.priority].filter(Boolean).join(" · ");

export function GoldenReview({ experience: e, onChoice }: { experience: any; onChoice: (v: GoldenChoice) => void }) {
  const qc = useQueryClient();
  const me = useMe();
  const enabled = !!e.source_investigation_id && (me.data?.id === e.analyst_id || me.data?.permissions.includes("knowledge.approve"));
  const q = useQuery({ queryKey: ["golden", e.id], enabled,
    queryFn: () => api.get(`/knowledge/golden/experience/${e.id}`) });
  const g = q.data?.versions?.[0];
  const [decision, setDecision] = useState("none");
  const [split, setSplit] = useState("dev");
  const [confirmed, setConfirmed] = useState<Record<string, boolean>>({});
  const [changed, setChanged] = useState<any>(null);
  useEffect(() => { setDecision("none"); setConfirmed({}); setChanged(null); }, [g?.id, g?.status, e.rev]);
  const answer = changed || g?.answers;
  const payload = useMemo(() => decision === "none" || !g ? undefined : ({
    version_id: g.id, expected_content_sha256: g.content_sha256, decision, split,
    confirmations: confirmed, ...(changed ? { review_answers: changed } : {}),
  }), [decision, g, split, confirmed, changed]);
  const judgementChanged = !!changed && JSON.stringify(changed.judgement) !== JSON.stringify(g?.answers?.judgement);
  const valid = decision !== "adopt" || (!judgementChanged && Object.keys(LABELS).every(k => confirmed[k]));
  useEffect(() => { onChoice({ payload, valid }); }, [payload, valid, onChoice]);
  const refresh = () => { qc.invalidateQueries({ queryKey: ["golden", e.id] }); qc.invalidateQueries({ queryKey: ["goldens"] }); };
  const prepare = useMutation({ mutationFn: () => api.post(`/knowledge/golden/experience/${e.id}/prepare`,
    { expected_experience_rev: e.rev }), onSuccess: refresh });
  const save = useMutation({ mutationFn: () => api.patch(`/knowledge/golden/${g.id}`,
    { expected_content_sha256: g.content_sha256, answers: answer }), onSuccess: refresh });
  const review = useMutation({ mutationFn: () => {
    if (!payload) throw new Error("채택 결정을 선택하세요.");
    const { version_id, ...body } = payload;
    return api.post(`/knowledge/golden/${version_id}/review`, body);
  }, onSuccess: refresh });
  const set = (k: string, v: any) => { setChanged({ ...answer, [k]: v }); setConfirmed({}); };
  if (!enabled) return null;
  if (q.isLoading) return <Loading />;
  if (q.error) return <Panel title="정답 사례 채택"><div className="small">원본 조사에 접근할 권한이 필요합니다. 조사 담당자에게 접근 범위를 확인하세요.</div><ErrorBox error={q.error} /></Panel>;
  return <Panel title="정답 사례 채택"><div className="col">
    <div className="small muted">경험 승인과 별도로 선택합니다. 조사 기록을 재사용하며 모델 학습은 실행하지 않습니다.</div>
    {!g ? <button className="btn" disabled={prepare.isPending} onClick={() => prepare.mutate()}>조사 기록에서 채택 초안 만들기</button> : <>
      <div className="row wrap"><span className="tag">{STATES[g.status] || g.status}</span>
        <span className="small">버전 {g.version} · 방법론 {g.methodology_version} · 근거 {g.manifest?.length || 0}개</span></div>
      <div className="small muted">당시 입력과 선택 근거는 저장된 스냅샷으로 고정됩니다. 아래 판단·검토 내용은 평가자 정답에만 포함됩니다.</div>
      <label className="col small">필수 사실과 조사 항목<textarea className="input" rows={3}
        value={(answer?.required_facts_actions || []).map((x: any) => x.text).join("\n")}
        onChange={x => set("required_facts_actions", lines(x.target.value).map((text, i) => ({
          text, evidence_refs: answer.required_facts_actions?.[i]?.evidence_refs || g.manifest.map((m: any) => m.sha256) })))} /></label>
      <label className="col small">관측 행위 판단<input className="input" value={answer?.judgement?.behavior || ""}
        onChange={x => set("judgement", { ...answer.judgement, behavior: x.target.value })} /></label>
      <label className="col small">침해·영향 확인 내용<textarea className="input" rows={2} value={answer?.judgement?.impact || ""}
        onChange={x => set("judgement", { ...answer.judgement, impact: x.target.value })} /></label>
      <label className="col small">판단 근거<textarea className="input" rows={2} value={answer?.judgement?.reason || ""}
        onChange={x => set("judgement", { ...answer.judgement, reason: x.target.value })} /></label>
      <label className="col small">필수 후속확인<textarea className="input" rows={2}
        value={(answer?.followups || []).map(followText).join("\n")} onChange={x => set("followups", lines(x.target.value))} /></label>
      {!answer?.followups?.length && <label className="col small">후속확인이 불필요한 이유<input className="input"
        value={answer?.no_followups_reason || ""} onChange={x => set("no_followups_reason", x.target.value)} /></label>}
      <label className="col small">해서는 안 되는 단정<textarea className="input" rows={2}
        value={(answer?.forbidden_claims || []).join("\n")} onChange={x => set("forbidden_claims", lines(x.target.value))} /></label>
      {changed && g.can_edit && <div className="col small"><button className="btn" disabled={save.isPending} onClick={() => save.mutate()}>새 초안으로 저장</button>
        <span className="muted">새 초안의 편집자는 다른 검토자의 검토가 필요합니다. 검토자는 필수 확인·후속확인·금지 주장만 채택과 함께 보완할 수 있습니다.</span></div>}
      {judgementChanged && <div className="small warn">판단·근거를 변경했습니다. 새 초안으로 저장한 뒤 다른 검토자가 채택해야 합니다.</div>}
      {g.status === "draft" && g.can_review && <>
        <label className="row small">정답 사례 결정<select aria-label="정답 사례 결정" className="input" value={decision} onChange={x => setDecision(x.target.value)}>
          <option value="none">이번에는 경험만 승인</option><option value="adopt">정답 사례로 채택</option><option value="decline">정답 사례 미채택</option>
        </select></label>
        {decision === "adopt" && <><label className="row small">사용 용도<select aria-label="사용 용도" className="input" value={split} onChange={x => setSplit(x.target.value)}>
          {Object.entries(SPLITS).map(([k, v]) => <option value={k} key={k}>{v}</option>)}</select></label>
          <div className="small muted">같은 사건군은 한 용도로 고정됩니다. 기존 사건 연결과 충돌하면 서버가 채택을 거부합니다.</div>
          {Object.entries(LABELS).map(([k, label]) => <label className="row small" key={k}><input type="checkbox"
            checked={!!confirmed[k]} onChange={x => setConfirmed({ ...confirmed, [k]: x.target.checked })} />{label}</label>)}</>}
        {e.status === "approved" && decision !== "none" && <button className="btn primary" disabled={!valid || review.isPending}
          onClick={() => review.mutate()}>정답 사례 결정 저장</button>}
      </>}
      {g.status === "draft" && !g.can_review && <span className="small muted">작성자·편집자와 다른 검토자가 채택해야 합니다.</span>}
      {g.experience_rev !== e.rev && <button className="btn" disabled={prepare.isPending} onClick={() => prepare.mutate()}>현재 경험 버전으로 초안 다시 만들기</button>}
      <details><summary className="small">버전과 근거 이력</summary>
        {(q.data?.versions || []).map((v: any) => <div key={v.id} className="small">버전 {v.version} · {STATES[v.status]} · 경험 r{v.experience_rev} · {v.reviewer || "검토 전"} · {fmtTime(v.reviewed_at)}</div>)}
        {(g.manifest || []).map((m: any) => <div key={m.sha256} className="mono small">{m.kind} · {m.sha256.slice(0, 16)} · {m.size_bytes} bytes</div>)}
      </details>
    </>}
    <ErrorBox error={prepare.error || save.error || review.error} />
  </div></Panel>;
}

async function downloadGolden(body: any) {
  const match = document.cookie.match(/(?:^|; )saw_csrf=([^;]+)/);
  const r = await fetch("/api/v1/knowledge/golden/export", { method: "POST", credentials: "same-origin",
    headers: { "content-type": "application/json", "x-csrf-token": match ? decodeURIComponent(match[1]) : "" },
    body: JSON.stringify(body) });
  if (r.status === 401) window.dispatchEvent(new CustomEvent("saw:unauthorized"));
  if (!r.ok) { const d = await r.json(); throw new ApiError(r.status, d.detail || "내보내기 실패"); }
  const href = URL.createObjectURL(await r.blob());
  const a = document.createElement("a");
  a.href = href;
  a.download = /filename="([^"]+)"/.exec(r.headers.get("content-disposition") || "")?.[1] || "golden-export";
  a.click();
  setTimeout(() => URL.revokeObjectURL(href), 5000);
}

export function GoldenCases() {
  const me = useMe();
  const [filters, setFilters] = useState<Record<string, string>>({ split: "dev", status: "adopted" });
  const [selected, setSelected] = useState<string[]>([]);
  const qs = new URLSearchParams(Object.entries(filters).filter(([, v]) => v)).toString();
  const q = useQuery({ queryKey: ["goldens", qs], queryFn: () => api.get("/knowledge/golden?" + qs) });
  const set = (k: string, v: string) => { setFilters({ ...filters, [k]: v }); setSelected([]); };
  const exp = useMutation({ mutationFn: ({ format, audience }: { format: string; audience: string }) =>
    downloadGolden({ version_ids: selected, split: filters.split, format, audience }) });
  const canAnswers = me.data?.permissions.includes("knowledge.approve");
  return <div className="col"><div className="row wrap">
    <input className="input" aria-label="사례명 검색" placeholder="사례명 검색" value={filters.q || ""} onChange={e => set("q", e.target.value)} />
    <select className="input" aria-label="정답 사례 용도" value={filters.split} onChange={e => set("split", e.target.value)}>
      {Object.entries(SPLITS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
    <select className="input" aria-label="채택 상태" value={filters.status} onChange={e => set("status", e.target.value)}>
      <option value="">전체 상태</option>{Object.entries(STATES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
    <select className="input" aria-label="사례 유형" value={filters.category || ""} onChange={e => set("category", e.target.value)}>
      <option value="">전체 유형</option>{Object.entries(CATEGORIES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
    <select className="input" aria-label="사례 판정" value={filters.verdict || ""} onChange={e => set("verdict", e.target.value)}>
      <option value="">전체 판정</option>{Object.entries(VERDICTS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
    <input className="input" aria-label="검토자" placeholder="검토자" value={filters.reviewer || ""} onChange={e => set("reviewer", e.target.value)} />
    <input className="input" aria-label="방법론 버전" placeholder="방법론 버전" value={filters.methodology_version || ""} onChange={e => set("methodology_version", e.target.value)} />
  </div><div className="small muted">승인된 선택 버전만 내보냅니다. 에이전트 입력·근거와 평가자 정답은 별도 파일입니다.</div>
    {q.isLoading ? <Loading /> : <table className="t"><thead><tr><th>선택</th><th>사례</th><th>유형·판정</th><th>상태</th><th>검토자</th><th>방법론</th><th>용도</th></tr></thead>
      <tbody>{(q.data || []).map((g: any) => <tr key={g.id}><td><input type="checkbox" aria-label={`버전 ${g.version} ${g.title} 선택`}
        disabled={g.status !== "adopted" || g.evaluable === false} checked={selected.includes(g.id)} onChange={e => setSelected(e.target.checked ? [...selected, g.id] : selected.filter(x => x !== g.id))} /></td>
        <td><Link to={`/knowledge/exp/${g.experience_id}`}>{g.title}</Link> · v{g.version}</td><td>{CATEGORIES[g.category] || g.category} · {VERDICTS[g.verdict] || g.verdict}</td>
        <td>{STATES[g.status]}{g.status === "adopted" && g.evaluable === false && <span className="tag warn">평가 불가 · 근거·승인 확인 필요</span>}</td><td>{g.reviewer || "검토 전"}</td><td>{g.methodology_version}</td><td>{SPLITS[g.split] || "미지정"}</td></tr>)}</tbody></table>}
    <div className="row wrap">{[["bundle", "agent", "선택 근거 묶음"], ["jsonl", "agent", "에이전트 JSONL"],
      ...(canAnswers ? [["jsonl", "evaluator", "평가자 정답 JSONL"], ["csv", "evaluator", "목록 CSV"]] : [])].map(([format, audience, label]) =>
      <button className="btn" key={label} disabled={!selected.length || exp.isPending} onClick={() => exp.mutate({ format, audience })}>{label}</button>)}</div>
    <ErrorBox error={q.error || exp.error} />
  </div>;
}
