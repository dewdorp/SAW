/// <reference types="vite/client" />
import { useEffect, useState } from "react";
import { Panel } from "../../components/common";
import { api } from "../../lib/api";
import "../inv/flows/flows.css";

const base = `${import.meta.env.BASE_URL}reference-data/`;

async function asset(path: string) {
  const r = await fetch(base + path, { cache: "no-store" });
  if (!r?.ok) throw Error(String(r?.status));
  return r.json();
}

/** A plain loader: this page is also rendered where no query client exists (and must never break the casebook). */
function useLoad(load: () => Promise<any>, key: string) {
  const [state, setState] = useState<{ data?: any; error?: unknown; isLoading: boolean }>({ isLoading: true });
  useEffect(() => {
    let active = true;
    setState({ isLoading: true });
    load().then(data => { if (active) setState({ data, isLoading: false }); }).catch(error => { if (active) setState({ error, isLoading: false }); });
    return () => { active = false; };
  }, [key]); // eslint-disable-line react-hooks/exhaustive-deps
  return state;
}

function List({ title, items }: { title: string; items?: string[] }) {
  if (!items?.length) return null;
  return <div className="fk-lines"><h5>{title}</h5><ul>{items.map((t, i) => <li key={i}>{t}</li>)}</ul></div>;
}

function Case({ id }: { id: string }) {
  const q = useLoad(() => asset(`flow-cases/${id}.json`), id);
  if (q.isLoading) return <p role="status">사례를 불러오는 중…</p>;
  if (q.error) return <p role="alert">이 사례 파일을 불러올 수 없습니다. 업데이트가 화면 파일까지 적용됐는지 확인하세요.</p>;
  const c = q.data;
  const keys: string[] = c.rows.length ? Object.keys(c.rows[0]) : [];
  return <div className="fk-detail">
    <p><b>{c.observed.summary}</b></p>
    <p className="small muted">입력: {c.input.files.join(", ")} · {c.input.note}</p>
    <div className="fk-lines"><h5>플랫폼에서 한 일</h5><ol>{c.platform_steps.map((s: string, i: number) => <li key={i}>{s}</li>)}</ol></div>
    <div className="fk-cols">
      <List title="적용한 지식" items={c.knowledge_applied} />
      <List title="확인된 사실" items={c.observed.confirmed} />
      <List title="추정(후보)" items={c.observed.inferred} />
      <List title="확인되지 않은 것" items={c.observed.unknown} />
      <List title="다음에 확인할 것" items={c.observed.next_checks} />
      <List title="등록된 흐름과 비교" items={c.observed.conformance.map((x: any) => `${x.name}: ${x.status === "matched" ? "순서·결과 같음" : "다름"}${x.deviations.length ? ` — ${x.deviations.join(" / ")}` : ""}`)} />
      <List title="보안장비 연계" items={c.devices.map((d: any) => `${String(d.source).toUpperCase()} ${d.alert_name} · 장비 조치 ${d.device_action} · HTTP ${d.http_status ?? "—"} · ${d.link === "same_request" ? "같은 요청" : "관련 후보"} (${d.link_basis})`)} />
    </div>
    {c.comparison && <div className="fk-lines"><h5>{c.comparison.title}</h5><p className="small">{c.comparison.summary}</p>
      <p className="small muted">연결: {c.comparison.link} · {Object.entries(c.comparison.counts).map(([k, v]) => `${k} ${v}`).join(" · ")}</p></div>}
    <div className="fk-cols">
      <div className="fk-lines"><h5>정상일 수 있는 설명</h5><p className="small">{c.normal_alternative}</p></div>
      <div className="fk-lines"><h5>결론</h5><p className="small">{c.conclusion}</p></div>
      <List title="한계" items={c.limits} />
    </div>
    <div className="fk-table" tabIndex={0} aria-label="원문 근거 표"><table className="t"><caption>원문 근거(파일·행 번호)</caption><thead><tr>{keys.map(k => <th key={k} scope="col">{k}</th>)}</tr></thead>
      <tbody>{c.rows.map((row: any, i: number) => <tr key={i}>{keys.map(k => <td key={k} className="small">{row[k] == null || row[k] === "" ? "—" : String(row[k])}</td>)}</tr>)}</tbody></table></div>
  </div>;
}

/** Worked business-flow cases, the content version and what changed, and what is actually installed. */
export function FlowCases() {
  const [open, setOpen] = useState<string | null>(null);
  const index = useLoad(() => asset("flow-cases/index.json"), "index");
  const content = useLoad(() => asset("content-version.json"), "content");
  const installed = useLoad(() => api.get("/system/versions"), "installed");
  const loaded = typeof __APP_VERSION__ === "string" ? __APP_VERSION__ : "";
  const v = installed.data;
  return <>
    <Panel title="설치된 버전과 사례 콘텐츠">
      <p className="small" role="status">
        앱 <b>{v?.app_version ?? "확인 중"}</b> · 이 화면 <b>{loaded || "?"}</b> · 사례 콘텐츠 <b>{content.data?.version ?? (content.error ? "버전 파일 없음" : "확인 중")}</b>
        {v?.casebook && <> · 분석 사례 <b>{v.casebook.cases}개</b>{v.casebook.cases > 0 && ` (${v.casebook.first}~${v.casebook.last})`} · 데이터베이스 {v.schema ?? "개발 모드"}</>}
        {v?.knowledge && <> · 등록된 업무 의미·흐름 {v.knowledge.flow_items}건 · 공격명 해석 {v.knowledge.device_signatures}건</>}
      </p>
      {v && loaded && v.app_version !== loaded && <p role="alert">서버는 {v.app_version}인데 이 화면은 {loaded}입니다. <button className="btn sm primary" onClick={() => location.reload()}>새로 고침</button> 하면 새 사례가 보입니다.</p>}
      {v?.notes?.map((n: string, i: number) => <p key={i} role="alert">{n}</p>)}
      {content.data && <details><summary>사례가 추가·변경된 내역</summary>{content.data.changes.map((c: any) => <div key={c.version} className="fk-version small">
        <b>{c.version}</b><span className="muted">앱 {c.app}</span><span>추가 {c.added.join(", ") || "없음"}{c.changed.length ? ` · 변경 ${c.changed.join(", ")}` : ""}</span><span>{c.reason}</span></div>)}
        <p className="small muted">{content.data.note} 사용자 메모·조사·판단·등록한 지식은 업데이트로 바뀌지 않습니다.</p></details>}
    </Panel>
    <Panel title={`업무 흐름 사례 ${index.data?.length ?? 0}개`} right={<a className="btn sm" href={`${base}flow-cases/flow-sample.zip`} download>재현 자료 받기 (CSV 6개 + 등록할 지식)</a>}>
      <p className="small muted">업무 의미를 등록한 뒤 "업무 흐름" 분석이 실제로 낸 결과를 정리한 사례입니다. 가상 자료이며, 묶음에는 로그와 등록할 지식만 있고 결론은 들어 있지 않습니다.</p>
      {!!index.error && <p role="alert">업무 흐름 사례를 불러올 수 없습니다. 업데이트가 화면 파일까지 적용됐는지 위의 버전을 확인하세요.</p>}
      <ul className="fk-flows">{(index.data || []).map((c: any) => <li key={c.id} className={open === c.id ? "open" : ""}>
        <button className="fk-flow" aria-expanded={open === c.id} onClick={() => setOpen(open === c.id ? null : c.id)}>
          <span className="fk-flow-main"><b>{c.id} · {c.title}</b></span><span className="fk-flow-tags"><span className="tag">{c.classification}</span></span></button>
        {open === c.id && <Case id={c.id} />}</li>)}</ul>
    </Panel>
  </>;
}
