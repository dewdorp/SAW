/// <reference types="vite/client" />
import { useEffect, useId, useState } from "react";
import "./platformCases.css";

type Summary = { id: string; title: string; classification: string };
type Step = { action: string; finding: string; facts?: { label: string; value: string }[]; rows?: Record<string, unknown>[]; image?: string };
type Case = Summary & { steps: Step[] };
type Props = { assetBase?: string; assetUrl?: (filename: string) => string; loadJson?: (filename: string) => Promise<unknown> };
const stages = ["조사 범위", "SAW 계산과 선정 근거", "원문 필터와 실제 행", "추가 자료 대조", "판단 예시"];

function StepRows({ rows }: { rows: Record<string, unknown>[] }) {
  const keys = [...new Set(rows.flatMap(row => Object.keys(row)))];
  return <div className="pc-table" tabIndex={0} aria-label="기록 표 가로 스크롤"><table><caption>대조에 사용한 기록</caption><thead><tr>{keys.map(k => <th scope="col" key={k}>{k}</th>)}</tr></thead>
    <tbody>{rows.map((row, i) => <tr key={i}>{keys.map(k => <td key={k}>{row[k] == null || row[k] === "" ? "—" : String(row[k])}</td>)}</tr>)}</tbody></table></div>;
}

export function PlatformCases({ assetBase = `${import.meta.env.BASE_URL}reference-data/platform-cases/`, assetUrl, loadJson }: Props) {
  const [items, setItems] = useState<Summary[]>([]);
  const [selected, select] = useState("");
  const [record, setRecord] = useState<Case | null>(null);
  const [page, setPage] = useState(0);
  const [failure, setFailure] = useState(false);
  const [attempt, retry] = useState(0);
  const heading = useId();
  const asset = assetUrl ?? ((filename: string) => assetBase + filename);
  useEffect(() => {
    let active = true;
    setFailure(false);
    const filename = selected ? `${selected}.json` : "index.json";
    const source = loadJson ? loadJson(filename) : fetch(assetBase + filename).then(r => {
      if (!r.ok) throw Error(String(r.status));
      return r.json();
    });
    source.then(data => {
      if (!active) return;
      if (!selected) {
        const index = data as Summary[];
        if (!Array.isArray(index) || !index.length) throw Error("empty index");
        setItems(index); select(index[0].id);
      } else {
        const item = data as Case;
        if (item.id !== selected || item.steps?.length !== stages.length) throw Error("incomplete case");
        setRecord(item);
      }
    }).catch(() => { if (active) setFailure(true); });
    return () => { active = false; };
  }, [selected, assetBase, loadJson, attempt]);
  const item = record?.id === selected ? record : null;
  const step = item?.steps[page];
  return <section className="platform-cases" aria-labelledby={heading}>
    <header><small>SAW 조사 기록 · 합성 FW 및 NDR 로그</small><h2 id={heading}>플랫폼 분석 따라보기</h2>
      <p>가상 조사에서 SAW가 고른 후보를 열고 원문과 후속 자료를 대조해 보세요. 각 단계에는 예시 조사의 실행 결과를 담았습니다.</p></header>
    {items.length > 0 && <nav aria-label="플랫폼 분석 사례" className="pc-cases">{items.map(c => <button type="button" key={c.id} aria-pressed={selected === c.id} onClick={() => { select(c.id); setPage(0); }}><small>{c.id}</small>{c.title}</button>)}</nav>}
    {failure ? <p role="alert">사례 기록을 불러오지 못했습니다. <button type="button" onClick={() => retry(n => n + 1)}>다시 시도</button></p> : !step || !item ? <p role="status">사례 기록을 불러오는 중…</p> : <article>
      <div className="pc-title"><h3>{item.id} · {item.title}</h3><a href={asset(`${item.id}.zip`)} download={`${item.id}.zip`}>이 사례 원본 ZIP 받기</a></div>
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
