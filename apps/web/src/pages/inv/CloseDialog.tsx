import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { ErrorBox } from "../../components/common";
import { api } from "../../lib/api";

// Conclusions an analyst records. An alert name, device severity, HTTP 200 or a firewall "allow" alone never decides one.
const VERDICTS: [string, string, string][] = [
  ["normal", "정상 업무로 확인", "관측 범위와 일치하는 업무 근거(작업 기록·담당자 확인)가 있을 때"],
  ["attack_attempt", "공격 시도 확인", "공격성 요청·행위는 확인되지만 성공·영향은 확인하지 못했을 때"],
  ["compromise_confirmed", "침해·실제 영향 확인", "해당 요청·자산·시간에 연결된 결과 증거(서버·인증·전송 기록 등)가 있을 때"],
  ["insufficient_evidence", "증거 부족 · 추가 확인 필요", "회신이 없거나 범위가 다르거나 필요한 근거가 없을 때"],
  ["data_quality_limited", "데이터 품질로 판단 제한", "수집 공백·파싱 문제·시각 불일치로 판단할 수 없을 때"],
  ["false_positive", "탐지 오탐", "탐지 조건 자체가 잘못 적용된 경우"],
];
const ATTACK = new Set(["attack", "attack_attempt", "compromise_confirmed"]);

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
          <fieldset className="col" style={{ gap: 2 }}><legend className="small"><b>판단</b></legend>
            {VERDICTS.map(([v, l, hint]) => (
              <label key={v} className="row small" title={hint}><input type="radio" name="v" checked={verdict === v} onChange={() => setVerdict(v)} />{l} <span className="muted">— {hint}</span></label>
            ))}
          </fieldset>
          {ATTACK.has(verdict) && <div className="small muted">공격 시도·침해 판단은 보고에 쓰이므로 다른 사람의 검토 대상이 됩니다. 종결 후 "확인 요청·검토" 탭에서 검토자를 지정하세요.</div>}
          {(verdict === "normal" || verdict === "false_positive") && <div className="small muted">확인 요청이 회신 대기·검증 전·범위 불일치·일부만 설명된 상태면 정상·오탐으로 종결할 수 없습니다. 그 경우 '증거 부족'으로 종결하거나 요청을 한계와 함께 닫으세요.</div>}
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
