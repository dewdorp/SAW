import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox } from "../../components/common";
import { api } from "../../lib/api";

const CHECKS = ["WAF 차단 여부 확인", "배치 스케줄 확인", "계정 소유자 확인", "응답 크기·데이터 유출 확인", "동일 지문(JA4/UA) 확장 검색", "과거 사례 비교"];
const VERDICTS: [string, string][] = [["attack", "공격"], ["normal", "정상 활동"], ["false_positive", "오탐"], ["unknown", "판단 보류"]];

/** Investigation close → five-point check → verdict → experience draft (docs/32 §4). Nothing here blocks the close:
 *  open points are shown so that they are closed knowingly, and limits are written down instead of hidden. */
export function CloseDialog({ inv, onClose }: { inv: any; onClose: () => void }) {
  const [verdict, setVerdict] = useState("");
  const [reason, setReason] = useState("");
  const [checks, setChecks] = useState<string[]>([]);
  const [response, setResponse] = useState("");
  const [idea, setIdea] = useState("");
  const [limits, setLimits] = useState("");
  const [save, setSave] = useState(true);
  const pre = useQuery({ queryKey: ["closing-check", inv.id], queryFn: () => api.get(`/investigations/${inv.id}/closing-check`) });
  const m = useMutation({
    mutationFn: () => api.post(`/investigations/${inv.id}/close`, { verdict, reason, checks, response, detection_idea: idea, limits, save_experience: save }),
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
          <textarea className="input" rows={3} aria-label="판정 사유" placeholder="판정 사유 (필수) — 첫 줄이 보고용 요약의 결론에 들어갑니다" value={reason} onChange={(e) => setReason(e.target.value)} />
          <div className="small">확인한 항목</div>
          <div className="row wrap">{CHECKS.map((c) => <label key={c} className="row small"><input type="checkbox" checked={checks.includes(c)} onChange={(e) => setChecks(e.target.checked ? [...checks, c] : checks.filter((x) => x !== c))} />{c}</label>)}</div>
          <textarea className="input" rows={2} aria-label="조치한 내용" placeholder="조치한 내용 — 사람이 수행한 대응 (SAW는 차단·정책 변경을 하지 않습니다)" value={response} onChange={(e) => setResponse(e.target.value)} />
          <textarea className="input" rows={2} aria-label="범위 제한" placeholder="범위 제한 — 확인하지 못한 것, 확보하지 못한 자료 (보고용 요약의 유의할 점에 표시됩니다)" value={limits} onChange={(e) => setLimits(e.target.value)} />
          <textarea className="input" rows={2} aria-label="재발 탐지 방안" placeholder="재발 탐지 방안 (선택)" value={idea} onChange={(e) => setIdea(e.target.value)} />
          <label className="row small"><input type="checkbox" checked={save} onChange={(e) => setSave(e.target.checked)} />처리 경험으로 저장 (초안 — 다른 사람이 승인하기 전에는 지식에 반영되지 않습니다)</label>
          <ErrorBox error={m.error} />
          <div className="row"><div className="grow" /><button className="btn" onClick={onClose}>취소</button><button className="btn primary" disabled={!verdict || !reason.trim() || m.isPending} onClick={() => m.mutate()}>종결</button></div>
        </div>
      </div>
    </>
  );
}
