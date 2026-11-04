/// <reference types="vite/client" />
import { useEffect, useId, useState } from "react";
import "./platformCases.css";

type Summary = { id: string; title: string; classification: string; category?: string; route?: string; keywords?: string };
type Step = { action: string; finding: string; facts?: { label: string; value: string }[]; rows?: Record<string, unknown>[]; image?: string };
type Case = Summary & { steps: Step[] };
type Props = { assetBase?: string; assetUrl?: (filename: string) => string; loadJson?: (filename: string) => Promise<unknown>; onDownload?: (id: string) => void };
const casePageSize = 9;
const autoStages = ["조사 범위", "SAW 계산과 선정 근거", "원문 필터와 실제 행", "추가 자료 대조", "판단 예시"];

const pivotStages = autoStages.map((label, i) => i === 1 ? "경보 단서로 1차 조회" : label);

async function fetchAsset(url: string): Promise<unknown> {
  const response = await fetch(url);
  if (!response.ok) throw Error(String(response.status));
  return response.json();
}

function StepRows({ rows }: { rows: Record<string, unknown>[] }) {
  const keys = [...new Set(rows.flatMap(row => Object.keys(row)))];
  return <div className="pc-table" tabIndex={0} aria-label="기록 표 가로 스크롤"><table><caption>대조에 사용한 기록</caption><thead><tr>{keys.map(k => <th scope="col" key={k}>{k}</th>)}</tr></thead>
    <tbody>{rows.map((row, i) => <tr key={i}>{keys.map(k => <td key={k}>{row[k] == null || row[k] === "" ? "—" : String(row[k])}</td>)}</tr>)}</tbody></table></div>;
}

export function PlatformCases({ assetBase = `${import.meta.env.BASE_URL}reference-data/platform-cases/`, assetUrl, loadJson, onDownload }: Props) {
  const [items, setItems] = useState<Summary[]>([]);
  const [selected, select] = useState("");
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("");
  const [listPage, setListPage] = useState(0);
  const [page, setPage] = useState(0);
  const [record, setRecord] = useState<Case | null>(null);
  const [failure, setFailure] = useState("");
  const [attempt, retry] = useState(0);
  const heading = useId();
  const asset = assetUrl ?? ((filename: string) => assetBase + filename);
  const categories = [...new Set(items.map(c => c.category).filter((c): c is string => !!c))];
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const matches = items.filter(c => {
    const fields = [c.id, c.title, c.category, c.classification, c.keywords].join(" ").toLowerCase();
    return (!category || category === c.category) && terms.every(t => fields.includes(t));
  });
  const pages = Math.ceil(matches.length / casePageSize);
  const currentPage = Math.max(0, Math.min(listPage, pages - 1));
  const visible = matches.slice(currentPage * casePageSize, (currentPage + 1) * casePageSize);
  const current = visible.find(c => c.id === selected) ?? visible[0];
  const currentId = current?.id;
  useEffect(() => {
    let active = true;
    const source = loadJson ? loadJson("index.json") : fetchAsset(assetBase + "index.json");
    source.then(data => {
      if (!active) return;
      const index = data as Summary[];
      if (!Array.isArray(index) || !index.length) throw Error("empty index");
      setItems(index);
      select(previous => previous || (index.find(c => c.route === "pivot") ?? index[0]).id);
    }).catch(() => { if (active) setFailure("index"); });
    return () => { active = false; };
  }, [assetBase, loadJson, attempt]);

  useEffect(() => {
    if (!currentId) return;
    setFailure(previous => previous === currentId ? "" : previous);
    let active = true;
    const filename = `${currentId}.json`;
    const source = loadJson ? loadJson(filename) : fetchAsset(assetBase + filename);
    source.then(data => {
      if (!active) return;
      const item = data as Case;
      if (item.id !== currentId || item.steps?.length !== autoStages.length) throw Error("incomplete case");
      setRecord(item);
    }).catch(() => { if (active) setFailure(currentId); });
    return () => { active = false; };
  }, [currentId, assetBase, loadJson, attempt]);

  const item = record && record.id === currentId ? record : null;
  const step = item?.steps[page];
  const stages = (item?.route ?? current?.route) === "pivot" ? pivotStages : autoStages;
  function resetList() {
    setListPage(0);
    select("");
    setPage(0);
  }
  return <section className="platform-cases" aria-labelledby={heading}>
    <header><small>SAW 조사 기록 · 합성 FW 및 NDR 로그</small><h2 id={heading}>플랫폼 분석 따라보기</h2>
      <p>조사 단서부터 원문 행, 후속 증적, 최종 판단까지 다섯 단계로 살펴보세요. W01–W06은 SAW가 계산한 후보에서 출발합니다. W07부터는 경보에 나온 주소나 경로로 실제 SAW 읽기 전용 조회를 실행하고 조건을 좁힌 결과를 보여줍니다. 이 사례들은 같은 정상 배경 로그를 공유합니다.</p></header>
    {items.length > 0 && <>
      <div className="pc-filters">
        <label>사례 검색<input type="search" value={query} placeholder="ID, 제목, 범주, 판단 분류" onChange={e => { setQuery(e.target.value); resetList(); }} /></label>
        <label>사례 범주<select value={category} onChange={e => { setCategory(e.target.value); resetList(); }}><option value="">전체 범주</option>{categories.map(c => <option key={c}>{c}</option>)}</select></label>
        {(query || category) && <button type="button" onClick={() => { setQuery(""); setCategory(""); resetList(); }}>필터 초기화</button>}
      </div>
      <div className="pc-list-bar"><span role="status">전체 {items.length}건 중 {matches.length}건{visible.length > 0 && ` · ${currentPage * casePageSize + 1}–${currentPage * casePageSize + visible.length}번째`}</span>
        {pages > 1 && <nav aria-label="사례 목록 페이지"><button type="button" disabled={!currentPage} onClick={() => { setListPage(currentPage - 1); select(""); setPage(0); }}>이전 페이지</button><span>{currentPage + 1} / {pages}</span><button type="button" disabled={currentPage + 1 >= pages} onClick={() => { setListPage(currentPage + 1); select(""); setPage(0); }}>다음 페이지</button></nav>}</div>
      {!!visible.length && <nav aria-label="플랫폼 분석 사례" className="pc-cases">{visible.map(c => <button type="button" key={c.id} aria-pressed={currentId === c.id} onClick={() => { select(c.id); setPage(0); }}><small>{c.id}{c.category && ` · ${c.category}`}</small>{c.title}</button>)}</nav>}
    </>}
    {failure && (failure === "index" || failure === currentId) ? <p role="alert">사례 기록을 불러오지 못했습니다. <button type="button" onClick={() => { setFailure(""); retry(n => n + 1); }}>다시 시도</button></p> : items.length && !currentId ? <p>조건에 맞는 사례가 없습니다.</p> : !step || !item ? <p role="status">사례 기록을 불러오는 중…</p> : <article>
      <div className="pc-title"><h3>{item.id} · {item.title}</h3>{onDownload ? <button type="button" onClick={() => onDownload(item.id)}>이 사례 원본 ZIP 받기</button> : <a href={asset(`${item.id}.zip`)} download={`${item.id}.zip`}>이 사례 원본 ZIP 받기</a>}</div>
      <nav className="pc-steps" aria-label="분석 단계">{stages.map((stage, i) => <button type="button" key={stage} aria-current={page === i ? "step" : undefined} onClick={() => setPage(i)}>{i + 1}. {stage}</button>)}</nav>
      <section key={`${item.id}-${page}`} aria-label="선택한 분석 단계" className="pc-step"><small>단계 {page + 1} / {stages.length}</small><h4>{stages[page]}</h4>
        <p className="pc-action"><b>화면에서 할 일</b> {step.action}</p>
        {!!step.facts?.length && <dl>{step.facts.map((f, i) => <div key={i}><dt>{f.label}</dt><dd>{f.value}</dd></div>)}</dl>}
        {!!step.rows?.length && <StepRows rows={step.rows} />}
        {page === 4 && <strong className="pc-class">판단 분류 · {item.classification}</strong>}
        <p>{step.finding}</p>
        {step.image && <details open><summary>SAW 화면 보기</summary><a href={asset(step.image)} target="_blank" rel="noreferrer" aria-label="실행 화면 원본 크기로 열기"><img loading="lazy" src={asset(step.image)} alt={`${item.id} ${item.title}의 ${stages[page]} 실행 화면`} /></a></details>}
        {page < stages.length - 1 && <button className="pc-next" type="button" onClick={() => setPage(page + 1)}>다음 · {stages[page + 1]} →</button>}
      </section>
    </article>}
  </section>;
}
