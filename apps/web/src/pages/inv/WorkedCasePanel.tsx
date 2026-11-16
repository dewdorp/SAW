import { useState } from "react";
import { Link } from "react-router-dom";
import { fmtNum, fmtPeriod, fmtInstant, getTz } from "../../lib/format";
import { matchCasebook } from "../practice/caseApplicability";
import "./worked-case-panel.css";

// Keep the casebook's large synthetic evidence pack off the investigation's loading path.
const EXAMPLES: Record<string, string> = { C007: "HTTP 바이트와 자산 방향", C008: "외부 송신과 자료 범위",
  C009: "반복 통신의 주기", C010: "같은 포트의 여러 목적지", C011: "같은 자산의 여러 포트" };
const ids = Object.keys(EXAMPLES);
const labels = { matched: "관측 조건 일치", no_match: "일치 관측 없음", missing: "자료 부족", partial: "일부만 확인", unsupported: "비교 미지원", failed: "계산 실패" };

type Props = { inv: string; bundles?: any[]; scope?: any; status?: "loading" | "error"; onEvidence?: (bundle: any, item: any) => void };
export function WorkedCasePanel({ inv, bundles = [], scope, status, onEvidence }: Props) {
  const [selection, select] = useState({ id: "", index: 0 });
  const comparisons = status ? [] : matchCasebook({ scope, bundles }, inv, ids);
  const matches = comparisons.filter(c => c.status === "matched" && c.evidence.length);
  const selected = matches.find(c => c.caseId === selection.id) || matches[0];
  const index = selected && selected.caseId === selection.id && selected.evidence[selection.index] ? selection.index : 0;
  const obs = selected?.evidence[index];
  const bundle = obs && bundles.find(b => b.id === obs.bundleId);
  const item = obs && bundle?.items?.[obs.itemIndex];
  const runAt = bundle?.scope?.run_at || scope?.run_at;
  const casebook = (caseId?: string) => {
    const params = new URLSearchParams();
    if (caseId) params.set("case", caseId);
    params.set("investigation", inv);
    return `/casebook?${params}`;
  };
  return <section className="worked-case-panel" aria-label="내 로그와 비교할 사례">
    <div className="worked-case-heading"><h3>내 로그와 비교할 사례</h3><Link to={casebook()}>전체 분석 사례집 보기</Link></div>
    {selected && obs ? <>
      {matches.length > 1 ? <label className="worked-case-picker">비교할 사례 <select className="input" value={selected.caseId} onChange={e => select({ id: e.target.value, index: 0 })}>
        {matches.map(c => <option key={c.caseId} value={c.caseId}>{c.caseId} · {EXAMPLES[c.caseId]}</option>)}
      </select></label> : <strong>{selected.caseId} · {EXAMPLES[selected.caseId]}</strong>}
      {selected.evidence.length > 1 && <label className="worked-case-picker">이번 조사에서 연결된 관측 <select className="input" value={index} onChange={e => select({ id: selected.caseId, index: Number(e.target.value) })}>
        {selected.evidence.map((e, i) => <option key={i} value={i}>{i + 1} / {selected.evidence.length} · {fmtNum(e.records)}건</option>)}
      </select></label>}
      <dl><div><dt>내 로그에서 본 것</dt><dd>{obs.observed} <span className="queue-scope">({fmtNum(obs.records)}건)</span></dd></div>
        <div><dt>연결한 이유</dt><dd>{selected.criterion}</dd></div>
        <div><dt>판단의 한계</dt><dd>{selected.detail} 사고 여부는 이 일치만으로 판단할 수 없습니다.</dd></div></dl>
      <div className="row wrap"><Link className="btn sm" to={casebook(selected.caseId)}>모범 분석 읽기</Link>
        {item && onEvidence && <button type="button" className="btn sm" onClick={() => onEvidence(bundle, item)}>내 로그의 근거 보기</button>}</div>
      <p className="queue-scope">{obs.time?.start || obs.time?.end ? `근거 조회 범위 ${fmtPeriod(obs.time.start, obs.time.end)} ${getTz()}${obs.time.end ? (obs.time.end_exclusive ? " (끝 시각 제외)" : " (끝 시각 포함)") : ""}` : "근거 조회 범위: 기간 제한 없음"}{runAt && ` · 계산 시각 ${fmtInstant(runAt)} ${getTz()}`}</p>
    </> : <p>{status === "loading" ? "현재 조사에서 비교할 관측을 불러오고 있습니다." : status === "error" ? "현재 조사 결과를 불러오지 못해 사례를 연결할 수 없습니다." : "현재 계산 결과에서 자동으로 연결할 사례를 찾지 못했습니다. 정상 여부는 판단할 수 없습니다."}</p>}
    <details className="worked-case-coverage"><summary>자동 비교 범위</summary>
      <p>현재 자동 비교하는 대표 사례는 C007~C011입니다. 다른 사례는 분석 사례집에서 직접 비교할 수 있습니다.</p>
      {comparisons.length > 0 && <ul>{comparisons.map(c => <li key={c.caseId}>{c.caseId} {EXAMPLES[c.caseId]} · {labels[c.status]}{c.partial && c.status === "matched" ? " (일부 범위)" : ""}</li>)}</ul>}
    </details>
  </section>;
}
