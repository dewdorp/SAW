/// <reference types="vite/client" />
import { useEffect, useId, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { conclusion, loadBundledPack, type PracticeCase, type PracticePack, type PracticeStage, type PracticeEvidence } from "./casebookData";
import { notesFor } from "./caseNotes";
import { Loading, Panel } from "../../components/common";
import { PageHeader } from "../../components/ui";
import "./practice.css";

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

const PREVIEW_ROWS = 3;

function EvidenceRow({ evidence: e }: { evidence: PracticeEvidence }) {
  return <details className="practice-row">
    <summary><span className="tag">{e.source}</span> {e.summary}</summary>
    <p className="small muted">근거 위치: {e.id}</p>
    {e.fields && <dl>{Object.entries(e.fields).map(([key, value]) => <div key={key}>
      <dt>{meanings[key] ? `${meanings[key]} (${key})` : key}</dt>
      <dd>{value == null || value === "" ? "(빈 값)" : String(value)}</dd>
    </div>)}</dl>}
  </details>;
}

function Evidence({ stage }: { stage: PracticeStage }) {
  const [showAll, setShowAll] = useState(false);
  const remainingId = useId();
  const extra = stage.evidence.slice(PREVIEW_ROWS);
  return <div className="practice-evidence">
    {stage.observation && <p className="practice-observation">{stage.observation}</p>}
    <b className="practice-row-count">대표 근거 {stage.evidence.length}개</b>
    {stage.evidence.slice(0, PREVIEW_ROWS).map(e => <EvidenceRow key={e.id} evidence={e} />)}
    {!!extra.length && <>
      <div hidden={!showAll} id={remainingId}>{showAll && extra.map(e => <EvidenceRow key={e.id} evidence={e} />)}</div>
      <button type="button" className="btn sm ghost" aria-controls={remainingId} aria-expanded={showAll} onClick={() => setShowAll(!showAll)}>
        {showAll ? `대표 근거 ${PREVIEW_ROWS}개만 보기` : `남은 대표 근거 ${extra.length}개 모두 보기`}
      </button>
    </>}
  </div>;
}

function responseLabel(stage: PracticeStage) {
  const first = stage.evidence[0];
  const fields = first?.fields || {};
  if (first?.source === "자료 요청 이력") return "회신 미도착";
  if ("declared_scope" in fields || "approved_by" in fields) return "승인 작업과 일치";
  if ("job_id" in fields) return "작업 시간 일부만 일치";
  if ("claimed_window_start" in fields) return "회신과 관측 범위 대조";
  return first?.source === "담당자 회신" ? "원천 기록으로 확인" : (first?.source || stage.title);
}

function WorkedExample({ item }: { item: PracticeCase }) {
  const [branch, setBranch] = useState(0);
  const initial = item.initial, response = item.followups[branch];
  const notes = notesFor(item.title);
  const files = `${import.meta.env.BASE_URL}practice-data/v1/${encodeURIComponent(item.id)}/`;
  const checksField = item.followups.flatMap(s => s.evidence).find(e => e.fields?.requested_questions)?.fields?.requested_questions;
  let checks: string[] = [];
  if (typeof checksField === "string") { try { const v: unknown = JSON.parse(checksField); if (Array.isArray(v)) checks = v.filter((s): s is string => typeof s === "string"); } catch { /* optional detail */ } }
  if (!checks.length && notes) checks = [notes[1]];
  const plain = (s: string) => s.split(" 근거 참조:")[0];
  const why = item.title.endsWith("장비 간 9시간 차이")
    ? "출발지 포트가 개별 대응하고 시각 차이가 일정하므로 같은 연결을 다른 시간대로 기록했을 가능성이 있다. 시각 설정을 확인하기 전에는 두 기록을 합치지 않는다."
    : plain(initial.rationale);
  const scope = initial.observation?.match(/관심 구간 ([^.]+? KST)/)?.[1];
  const refs = (stage: PracticeStage) => <small className="muted case-refs">대표 근거 위치: {stage.evidence.map(e => e.id).join(" · ")}</small>;
  return <>
    <p className="small" role="note"><span className="tag warn">가상 로그</span> 합성 자료로 작성한 모범 분석입니다. 실제 조사 자료와 결론은 별도로 검토하세요.</p>
    <Panel title="1. 처음 관측한 증적"><Evidence stage={initial} />
      <div className="row wrap small practice-downloads"><span>배경 기록을 포함한 원본</span>
        {item.sources.filter(s => s === "NDR" || s === "FW").map(s => <a className="btn sm" key={s} href={`${files}${s.toLowerCase()}.csv`} download={`가상-${item.id}-${s.toLowerCase()}.csv`}>가상 {s} 전체 CSV</a>)}
      </div>
    </Panel>
    <Panel title="2. 모범 분석"><div className="case-reading">
      <h3>판단에 사용한 근거</h3><p>{why}</p>
      {notes && <><h3>정상 업무로 설명할 수 있는 경우</h3><p>{notes[0]} 아래 자료를 대조하기 전에는 가설로 남긴다.</p></>}
      <h3>분석가가 확인할 질문과 자료</h3>
      {!!checks.length && <ul>{checks.map(q => <li key={q}>{q}</li>)}</ul>}
      {initial.nextCheck && <p>{initial.nextCheck}</p>}
      <div className="case-conclusion"><h3>현재 증적으로 쓴 결론 예시</h3>{scope && <small>관측 범위: {scope}</small>}<p>{conclusion(initial, item.title)}</p>{refs(initial)}</div>
    </div></Panel>
    {response && <Panel title="3. 다른 후속 자료의 결론"><p>아래는 같은 초기 증적에 서로 다른 자료를 받았다고 가정한 독립 사례입니다. 하나를 골라 그 자료가 바꾸는 판단과 남은 질문을 비교하세요.</p>
      <div className="row wrap case-branches" role="group" aria-label="후속 자료별 분석 예시">{item.followups.map((s, i) => <button type="button" className={i === branch ? "btn primary" : "btn"} key={s.id} aria-pressed={branch === i} onClick={() => setBranch(i)}>{responseLabel(s)}</button>)}</div>
      <section className="case-reading case-response" aria-label="선택한 후속 자료의 분석" key={response.id}>
        <h3>{responseLabel(response)}</h3><Evidence stage={response} />
        <h3>초기 증적과 대조한 근거</h3><p>{plain(response.rationale)}</p>
        <div className="case-conclusion"><h3>이 자료를 받았을 때의 결론 예시</h3><p>{conclusion(response, item.title)}</p>{refs(response)}</div>
        {response.nextCheck && <><h3>남겨 둔 확인 사항</h3><p>{response.nextCheck}</p></>}
      </section>
    </Panel>}
    <details className="case-review"><summary>실제 조사에 적용하는 순서</summary><ol>
      <li>실제 로그에서 관심 구간과 시간대, 수집 장비, 출발지·목적지·포트를 기록한다. 대표 행과 전체 건수를 구분한다.</li>
      <li>관측 사실과 업무 가설을 따로 적고, 위 질문에 답할 원천 기록이나 승인 이력을 요청한다.</li>
      <li>회신의 자산·시각·동작이 실제 로그와 어디까지 일치하는지 대조한다. 일치하지 않거나 자료가 없는 부분은 미확인으로 남긴다.</li>
      <li>실제 근거 위치, 확인한 범위, 남은 질문을 조사 결론에 함께 적는다.</li>
    </ol></details>
  </>;
}
export function PracticeCases({ loadPack = loadBundledPack }: { loadPack?: () => Promise<PracticePack> } = {}) {
  const [pack, setPack] = useState<PracticePack | null>(null);
  const [failed, setFailed] = useState(false);
  const [retry, setRetry] = useState(0);
  const [params, setParams] = useSearchParams();
  const selected = params.get("case");
  const investigation = params.get("investigation") || "";
  const returnPath = /^[a-zA-Z0-9_-]{1,128}$/.test(investigation) ? `/inv/${encodeURIComponent(investigation)}` : null;
  const setSelected = (id: string | null) => setParams(current => {
    const next = new URLSearchParams(current);
    if (id) next.set("case", id); else next.delete("case");
    return next;
  });
  const [search, setSearch] = useState("");
  const [sector, setSector] = useState("");
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
  // The synthetic sector is the first part of each summary ("가상 은행 · ...").
  const sectorOf = (c: PracticeCase) => (c.summary ?? "").split(" · ")[0];
  const sectors = [...new Set((pack?.cases || []).map(sectorOf).filter(Boolean))];
  const shown = pack?.cases.filter(c => (!sector || sectorOf(c) === sector)
    && `${c.id} ${c.title} ${c.summary ?? ""}`.toLowerCase().includes(term)) || [];
  return <div className="page practice-page">
    <div ref={heading} tabIndex={-1}>
      <PageHeader eyebrow="NDR · FW 모범 분석" title={item ? `${item.id} · ${item.title}` : "분석 사례집"}
        desc={item ? item.summary : "가상 로그의 어떤 행에서 질문이 나왔는지, 어떤 자료를 대조했고 어디까지 결론을 낼 수 있는지 읽어 보세요."} />
    </div>
    {returnPath && <div><Link className="btn sm" to={returnPath}>실제 조사로 돌아가기</Link></div>}
    {pack && selected && !item && <p role="status">해당 번호의 사례를 찾을 수 없습니다. 목록에서 사례를 선택하세요.</p>}
    {failed ? <div className="col"><p role="alert">분석 사례를 불러올 수 없습니다. 새로고침한 뒤에도 같으면 업데이트 파일을 확인해 주세요.</p>
      <div><button className="btn" onClick={() => setRetry(n => n + 1)}>다시 불러오기</button></div></div>
    : !pack ? <Loading label="분석 사례를 불러오는 중…" />
    : !item ? <Panel title={`사례 ${pack.cases.length}개 · 후속 자료 ${pack.cases.reduce((n, c) => n + c.followups.length, 0)}가지`}>
      <div className="row wrap" style={{ marginBottom: 12, gap: 12 }}>
        <label className="row wrap">사례 찾기
          <input className="input" type="search" value={search} onChange={e => setSearch(e.target.value)} placeholder="제목·사례 번호·주제" />
        </label>
        {sectors.length > 1 && <label className="row wrap">업권
          <select className="input" value={sector} onChange={e => setSector(e.target.value)}>
            <option value="">전체</option>{sectors.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>}
        {(term || sector) && <span className="small muted" role="status">{shown.length}개 표시</span>}
      </div>
      {!shown.length && <p role="status">검색어에 맞는 사례가 없습니다. <button className="btn sm" onClick={() => { setSearch(""); setSector(""); }}>검색 지우기</button></p>}
      <div className="quick" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 235px), 1fr))" }}>
        {shown.map(c => <button key={c.id} onClick={() => choose(c.id)} ref={c.id === lastOpened ? listButton : undefined}>
          <b>{c.id} · {c.title}</b><small>{sectorOf(c) || "가상 로그"} · {c.sources.join(" · ")} · 추가 자료 {c.followups.length}가지</small>
        </button>)}
      </div>
    </Panel>
    : <>
      <div className="row wrap" style={{ marginBottom: 12 }}>
        <button className="btn" onClick={() => setSelected(null)}>사례 목록</button>
        <label className="small">다른 사례{" "}
          <select className="input" style={{ maxWidth: "100%" }} value={item.id} onChange={e => choose(e.target.value)}>
            {pack.cases.map(c => <option key={c.id} value={c.id}>{c.id} · {c.title}</option>)}
          </select>
        </label>
      </div>
      <WorkedExample key={item.id} item={item} />
    </>}
  </div>;
}
