/// <reference types="vite/client" />
import { useEffect, useId, useRef, useState } from "react";
import { Loading, Panel } from "../../components/common";
import { PageHeader } from "../../components/ui";

type PracticeEvidence = {
  id: string; source: string; summary: string;
  fields?: Record<string, string | number | boolean | null>;
};
export type PracticeStage = {
  id: string; title: string; observation?: string; evidence: PracticeEvidence[]; question: string;
  options: { id: string; text: string; explanation: string }[];
  correctId: string; rationale: string; nextCheck?: string;
};
type PracticeCase = {
  id: string; title: string; summary?: string; sources: string[];
  initial: PracticeStage; followups: PracticeStage[];
};
export type PracticePack = { version: string; cases: PracticeCase[] };

// The release contains this module. Loading it does not query or write an investigation.
async function loadBundledPack(): Promise<PracticePack> {
  const { default: pack } = await import("./practice-cases.json");
  return pack as unknown as PracticePack;
}

const meanings: Record<string, string> = {
  event_time: "관측 시각", _time: "기록 시각", _site: "수집 지점", app: "애플리케이션", _schema: "자료 형식",
  protocol: "프로토콜", src_ip: "출발지 IP", src_port: "출발지 포트", src_country: "출발지 국가",
  dest_ip: "목적지 IP", dst_ip: "목적지 IP", dest_port: "목적지 포트", dst_port: "목적지 포트",
  dest_country: "목적지 국가", _device_ip: "수집 장비 IP", _device_name: "수집 장비",
  method: "HTTP 메서드", host: "요청 호스트", path: "요청 경로", query: "쿼리 문자열",
  user_agent: "요청 프로그램 표기", referer: "참조 주소", req_cookie: "요청 쿠키", uuid: "원천 식별자",
  status: "HTTP 응답 코드", cs_bytes: "클라이언트 → 서버 바이트", sc_bytes: "서버 → 클라이언트 바이트",
  action: "FW 처리 결과", tcp_flag: "TCP 플래그", duration: "장비 기록 지속 시간",
  sent_bytes: "장비 기준 송신 바이트", rcvd_bytes: "장비 기준 수신 바이트",
};

function Evidence({ stage }: { stage: PracticeStage }) {
  return <div className="col">
    {stage.observation && <p>{stage.observation}</p>}
    {stage.evidence.map((e, i) => <details key={i} className="panel pb">
      <summary style={{ cursor: "pointer", overflowWrap: "anywhere" }}>
        <span className="tag">{e.source}</span>{" "}<span>{e.summary}</span>
      </summary>
      <div className="small muted" style={{ margin: "10px 0 4px" }}>근거 위치: {e.id}</div>
      {e.fields && <dl style={{ margin: 0 }}>
        {Object.entries(e.fields).map(([key, value]) => <div key={key} className="row wrap" style={{ alignItems: "baseline" }}>
          <dt className="muted">{meanings[key] ? `${meanings[key]} (${key})` : key}</dt>
          <dd className="mono" style={{ margin: 0, whiteSpace: "pre-wrap", overflowWrap: "anywhere", minWidth: 0 }}>
            {value == null || value === "" ? "(빈 값)" : String(value)}
          </dd>
        </div>)}
      </dl>}
    </details>)}
  </div>;
}

type Answer = { choice?: string; revealed: boolean };
function Exercise({ item }: { item: PracticeCase }) {
  const [step, setStep] = useState(0);
  const [answers, setAnswers] = useState<Record<number, Answer>>({});
  const [resetKey, setResetKey] = useState(0);
  const radioGroup = useId();
  const stage = step === 0 ? item.initial : item.followups[step - 1];
  const answer = answers[step] ?? { revealed: false };
  const put = (value: Answer) => setAnswers(old => ({ ...old, [step]: value }));
  const reset = () => { setStep(0); setAnswers({}); setResetKey(n => n + 1); };
  const files = `${import.meta.env.BASE_URL}practice-data/v1/${encodeURIComponent(item.id)}/`;
  const showFollowups = !!item.followups.length && (answers[0]?.revealed || step !== 0);

  return <>
    {showFollowups && <Panel>
      <div className="col">
        <label className="row wrap"><b>검토할 자료</b>
          <select aria-label="검토할 자료" className="input" value={step} onChange={e => setStep(Number(e.target.value))}>
            <option value={0}>처음 자료</option>
            {item.followups.map((f, i) => <option key={i} value={i + 1}>{f.title}</option>)}
          </select>
        </label>
        <div className="small muted">각 추가 자료는 같은 처음 기록에 따로 적용하는 가정입니다. 다른 추가 자료와 합쳐 판단하지 마세요.</div>
      </div>
    </Panel>}
    <Panel title={step === 0 ? "처음 관측한 자료" : stage.title}>
      <div className="col">
        {step !== 0 && <details><summary>처음 관측한 자료 다시 보기</summary><Evidence stage={item.initial} /></details>}
        <Evidence key={`${step}-${resetKey}`} stage={stage} />
        <div className="row wrap small">
          <span className="muted">처음 자료 전체</span>
          {item.sources.filter(s => s === "NDR" || s === "FW").map(s =>
            <a className="btn sm" key={s} href={`${files}${s.toLowerCase()}.csv`} download={`${item.id}-${s.toLowerCase()}.csv`}>{s} 전체 CSV</a>)}
        </div>
      </div>
    </Panel>
    <Panel title="판단해 보기">
      <div className="col">
        <fieldset className="col" style={{ minWidth: 0, border: 0, padding: 0, margin: 0 }}>
          <legend style={{ marginBottom: 8 }}><b>{stage.question}</b></legend>
          {stage.options.map(option => <div key={option.id}>
            <label className="row" style={{ alignItems: "baseline", cursor: "pointer" }}>
              <input type="radio" name={radioGroup} checked={answer.choice === option.id}
                onChange={() => put({ choice: option.id, revealed: false })} />
              <span>{option.text}</span>
            </label>
            {answer.revealed && <div className="row small" style={{ alignItems: "baseline", margin: "3px 0 5px 20px" }}>
              <span className={`tag ${option.id === stage.correctId ? "ok" : "bad"}`}>{option.id === stage.correctId ? "정답" : "오답"}</span>
              <span>{option.explanation}</span>
            </div>}
          </div>)}
        </fieldset>
        {answer.revealed ? <div className="col" role="status" aria-live="polite">
          <b>{answer.choice ? `내 선택: ${answer.choice === stage.correctId ? "정답" : "오답"}` : "예제 해설"}</b>
          <p>{stage.rationale}</p>
          {stage.nextCheck && <div><b>다음 확인</b> · {stage.nextCheck}</div>}
          {step === 0 && item.followups.length > 0 &&
            <div><button className="btn primary" onClick={() => setStep(1)}>추가 자료로 판단하기</button></div>}
        </div> : <div className="row wrap">
          <button className="btn primary" onClick={() => put({ ...answer, revealed: true })}>정답·해설 보기</button>
          <span className="small muted">선택하지 않고 해설만 읽을 수도 있습니다.</span>
        </div>}
      </div>
    </Panel>
    <button className="btn sm" onClick={reset}>처음부터 다시 풀기</button>
  </>;
}

export function PracticeCases({ loadPack = loadBundledPack }: { loadPack?: () => Promise<PracticePack> } = {}) {
  const [pack, setPack] = useState<PracticePack | null>(null);
  const [failed, setFailed] = useState(false);
  const [retry, setRetry] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const heading = useRef<HTMLDivElement>(null);
  const listButton = useRef<HTMLButtonElement>(null);
  const [lastOpened, setLastOpened] = useState("");
  useEffect(() => {
    let live = true;
    setFailed(false);
    loadPack().then(p => {
      if (!live) return;
      if (!p?.cases?.length) { setFailed(true); return; }
      setPack(p);
    }).catch(() => { if (live) setFailed(true); });
    return () => { live = false; };
  }, [loadPack, retry]);
  useEffect(() => {
    if (selected) heading.current?.focus();
    else if (lastOpened) listButton.current?.focus();
  }, [selected, lastOpened]);
  const choose = (id: string) => { setLastOpened(id); setSelected(id); };
  const item = pack?.cases.find(c => c.id === selected);
  const term = search.trim().toLowerCase();
  const shown = pack?.cases.filter(c => `${c.id} ${c.title} ${c.summary ?? ""}`.toLowerCase().includes(term)) || [];
  return <div className="page">
    <div ref={heading} tabIndex={-1}>
      <PageHeader eyebrow="연습용 합성 자료" title={item ? `${item.id} · ${item.title}` : "가상 로그 예제"}
        desc={item ? item.summary : "가상 NDR·FW 기록으로 조사 판단을 연습하세요. 선택한 답은 실제 조사나 골든셋에 저장되지 않습니다."} />
    </div>
    {failed ? <div className="col"><p role="alert">가상 예제를 불러올 수 없습니다. 새로고침한 뒤에도 같으면 업데이트 파일을 확인해 주세요.</p>
      <div><button className="btn" onClick={() => setRetry(n => n + 1)}>다시 불러오기</button></div></div>
    : !pack ? <Loading label="가상 예제를 불러오는 중…" />
    : !item ? <Panel title={`예제 ${pack.cases.length}개 · 추가 자료 ${pack.cases.reduce((n, c) => n + c.followups.length, 0)}가지`}>
      <label className="row wrap" style={{ marginBottom: 12 }}>예제 찾기
        <input className="input" type="search" value={search} onChange={e => setSearch(e.target.value)} placeholder="제목 또는 사례 번호" />
      </label>
      {!shown.length && <p role="status">검색어에 맞는 예제가 없습니다. <button className="btn sm" onClick={() => setSearch("")}>검색 지우기</button></p>}
      <div className="quick" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 235px), 1fr))" }}>
        {shown.map(c => <button key={c.id} onClick={() => choose(c.id)} ref={c.id === lastOpened ? listButton : undefined}>
          <b>{c.id} · {c.title}</b><small>{c.sources.join(" · ")} · 추가 자료 {c.followups.length}가지</small>
        </button>)}
      </div>
    </Panel>
    : <>
      <div className="row wrap" style={{ marginBottom: 12 }}>
        <button className="btn" onClick={() => setSelected(null)}>예제 목록</button>
        <label className="small">연습할 예제{" "}
          <select className="input" style={{ maxWidth: "100%" }} value={item.id} onChange={e => choose(e.target.value)}>
            {pack.cases.map(c => <option key={c.id} value={c.id}>{c.id} · {c.title}</option>)}
          </select>
        </label>
      </div>
      <Exercise key={item.id} item={item} />
    </>}
  </div>;
}
