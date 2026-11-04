import { useState } from "react";
import { Link } from "react-router-dom";
import { conclusion, loadBundledPack, type PracticePack } from "../practice/casebookData";
import { notesFor } from "../practice/caseNotes";

type Props = { inv: string; observed: string; title: string; onEvidence: () => void };

export function ActivityCaseComparison({ inv, observed, title, onEvidence }: Props) {
  const [open, setOpen] = useState(false);
  const [pack, setPack] = useState<PracticePack | null>(null);
  const [failed, setFailed] = useState(false);
  const [id, setId] = useState("");
  const load = () => {
    setFailed(false);
    loadBundledPack().then(setPack).catch(() => setFailed(true));
  };
  const toggle = () => {
    if (!open && !pack) load();
    setOpen(!open);
  };
  const c = pack?.cases.find(entry => entry.id === id);
  const focus = c && notesFor(c.title)?.[1];
  return <div className="activity-case-reference">
    <button type="button" className="btn sm" aria-expanded={open} onClick={toggle}>이 활동과 사례 직접 대조</button>
    {open && <section aria-label="직접 선택한 사례와 대조">
      {failed ? <p role="alert">참고 사례를 불러오지 못했습니다. <button type="button" onClick={load}>다시 불러오기</button></p>
        : !pack ? <p role="status">참고 사례를 불러오는 중입니다.</p>
        : <label>참고할 가상 사례 <select className="input" aria-label="참고할 가상 사례" value={id} onChange={e => setId(e.target.value)}>
          <option value="">사례를 선택하세요</option>
          {pack.cases.map(entry => <option key={entry.id} value={entry.id}>{entry.id} · {entry.title}</option>)}
        </select></label>}
      {c && <><div className="case-side-by-side">
        <div><h4>내 조사 · {title}</h4><p>{observed}</p>
          <button type="button" className="btn sm" onClick={onEvidence}>이 활동의 원문 열기</button></div>
        <div><h4>{c.id} · {c.title}</h4><p>{c.initial.observation}</p>
          <strong>사례의 모범 판단</strong><p>{conclusion(c.initial, c.title)}</p>
          <Link to={`/casebook?case=${encodeURIComponent(c.id)}&investigation=${encodeURIComponent(inv)}`}>이 사례의 근거와 후속 자료</Link></div>
      </div>{focus && <p><strong>서로 대조할 항목</strong> · {focus}</p>}
        <small>직접 고른 참고 사례입니다. 실제 조사 판단은 내 원문과 확인 자료로 작성하세요.</small></>}
    </section>}
  </div>;
}
