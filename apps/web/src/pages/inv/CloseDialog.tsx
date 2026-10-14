import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { ErrorBox } from "../../components/common";
import { api } from "../../lib/api";

const VERDICTS: [string, string][] = [["attack", "공격"], ["normal", "정상 활동"], ["false_positive", "오탐"], ["unknown", "판단 보류"]];

/** Investigation close → five-point check → verdict → experience draft (docs/32 §4). Nothing here blocks the close:
 *  open points are shown so that they are closed knowingly, and limits are written down instead of hidden. */
export function CloseDialog({ inv, onClose }: { inv: any; onClose: () => void }) {
  const [verdict, setVerdict] = useState("");
  const [reason, setReason] = useState("");
  const [behavior, setBehavior] = useState("");
  const [impact, setImpact] = useState("");
  const initialized = useRef(false);
  const edited = useRef({ behavior: false, impact: false, limits: false });
  const [response, setResponse] = useState("");
  const [idea, setIdea] = useState("");
  const [limits, setLimits] = useState("");
  const [save, setSave] = useState(true);
  const pre = useQuery({ queryKey: ["closing-check", inv.id], queryFn: () => api.get(`/investigations/${inv.id}/closing-check`) });
  const draft = useQuery({ queryKey: ["closure-draft", inv.id], queryFn: () => api.get(`/investigations/${inv.id}/guidance/closure-draft`), retry: false });
  useEffect(() => {
    if (!draft.data || initialized.current) return;
    initialized.current = true;
    if (!edited.current.behavior) setBehavior(draft.data.behavior_assessment || "");
    if (!edited.current.impact) setImpact(draft.data.impact_assessment || "");
    if (!edited.current.limits) setLimits((draft.data.limits || []).join("\n"));
  }, [draft.data]);
  const m = useMutation({
    mutationFn: () => api.post(`/investigations/${inv.id}/close`, { verdict, reason, checks: [], response, detection_idea: idea, limits, save_experience: save, behavior_assessment: behavior, impact_assessment: impact, follow_up: [] }),
    onSuccess: onClose,
  });
  const open = (pre.data?.items || []).filter((x: any) => !x.ok).length;
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="modal panel" role="dialog" aria-label="조사 종결">
        <div className="ph"><span className="grow">조사 종결 · {inv.display_id}</span></div>
        <div className="pb col">
          <div className="col" style={{ gap: 4 }} aria-label="종결 전 점검">
            <div className="small"><b>종결 전 점검</b> <span className="muted">{pre.isLoading ? "확인 중…" : open ? `살펴볼 항목 ${open}개 — 종결은 막지 않습니다. 남기는 것은 아래 '범위 제한'에 적어 주세요.` : "살펴볼 항목 없음"}</span></div>
            {(pre.data?.items || []).map((x: any) => (
              <div key={x.key} className="ck-item" style={{ padding: "4px 9px" }}>
                <div className="row small"><span className={`tag ${x.ok ? "ok" : "warn"}`}>{x.ok ? "✓" : "확인"}</span><b>{x.title}</b></div>
                {x.lines.map((ln: string) => <div key={ln} className="small d-chg">· {ln}</div>)}
                {x.hint && <div className="small muted">{x.hint}</div>}
              </div>))}
            <ErrorBox error={pre.error} />
          </div>
          <div className="row wrap">판정
            {VERDICTS.map(([v, l]) => (
              <label key={v} className="row small"><input type="radio" name="v" checked={verdict === v} onChange={() => setVerdict(v)} />{l}</label>
            ))}
          </div>
          {verdict === "attack" && <div className="small muted">공격 판정은 보고에 쓰이므로 다른 사람의 검토 대상이 됩니다. 종결 후 "확인·검토" 탭에서 검토자를 지정하세요.</div>}
          <label className="col small">판정 사유<textarea className="input" rows={3} aria-label="판정 사유" placeholder="판정 사유 (필수) — 첫 줄이 보고용 요약의 결론에 들어갑니다" value={reason} onChange={(e) => setReason(e.target.value)} /></label>
          <div className="col small" aria-label="기존 확인 기록 재사용">
            <b>기존 확인 기록 {draft.data?.check_ids?.length ?? "–"}건 재사용</b>
            <span className="muted">저장한 답변·근거·조회 범위·후속확인을 종결과 경험 초안에 함께 남깁니다. 미확인인 채로 종결할 수 있습니다.</span>
            {(draft.data?.follow_up || []).map((f: any, i: number) => <div key={i}>후속확인 · {f.target} · {(f.items || []).join(" / ")} · 필요 자료 {(f.needed_data || []).join(", ")}</div>)}
            <ErrorBox error={draft.error} />
          </div>
          <label className="col small">행위 판단<textarea className="input" rows={2} aria-label="행위 판단" placeholder="행위의 성격 (예: 공격 시도 관측)" value={behavior} onChange={e => { edited.current.behavior = true; setBehavior(e.target.value); }} /></label>
          <label className="col small">실제 영향 판단<textarea className="input" rows={2} aria-label="실제 영향 판단" placeholder="실제 침해·영향과 확인 근거 (예: WAS 미수집으로 영향 미확인)" value={impact} onChange={e => { edited.current.impact = true; setImpact(e.target.value); }} /></label>
          <label className="col small">조치한 내용<textarea className="input" rows={2} aria-label="조치한 내용" placeholder="조치한 내용 — 사람이 수행한 대응 (SAW는 차단·정책 변경을 하지 않습니다)" value={response} onChange={(e) => setResponse(e.target.value)} /></label>
          <label className="col small">범위 제한<textarea className="input" rows={2} aria-label="범위 제한" placeholder="범위 제한 — 확인하지 못한 것, 확보하지 못한 자료 (보고용 요약의 유의할 점에 표시됩니다)" value={limits} onChange={(e) => { edited.current.limits = true; setLimits(e.target.value); }} /></label>
          <label className="col small">재발 탐지 방안<textarea className="input" rows={2} aria-label="재발 탐지 방안" placeholder="재발 탐지 방안 (선택)" value={idea} onChange={(e) => setIdea(e.target.value)} /></label>
          <label className="row small"><input type="checkbox" checked={save} onChange={(e) => setSave(e.target.checked)} />처리 경험으로 저장 (초안 — 다른 사람이 승인하기 전에는 지식에 반영되지 않습니다)</label>
          <ErrorBox error={m.error} />
          <div className="row"><div className="grow" /><button className="btn" onClick={onClose}>취소</button><button className="btn primary" disabled={!verdict || !reason.trim() || m.isPending} onClick={() => m.mutate()}>종결</button></div>
        </div>
      </div>
    </>
  );
}
