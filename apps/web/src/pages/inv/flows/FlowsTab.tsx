import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ErrorBox, Loading, Panel } from "../../../components/common";
import { useInv } from "../../../context/invContext";
import { api } from "../../../lib/api";
import { fmtTime } from "../../../lib/format";
import { RememberDialog, ROLE_KO, type Seed } from "./RememberDialog";
import "./flows.css";

const STATUS_KO: Record<string, string> = { complete: "전체 검사 완료", partial: "일부만 검사", no_data: "HTTP 요청 기록 없음", failed: "실행 실패", running: "실행 중" };
const OUTCOME_KO: Record<string, string> = { success: "성공", failure: "실패", unknown: "미확인" };
const VERDICT_KO: Record<string, string> = { normal: "정상으로 확인", suspicious: "의심", undetermined: "미확정" };
const FLAG_KO: Record<string, string> = { lookup_after_failed_auth: "인증 실패 뒤 조회", lookup_after_logout: "로그아웃 뒤 조회", other_target: "다른 대상 조회",
  device_block_vs_success: "장비 차단 ↔ 요청 처리 상충", deviates_from_registered_flow: "등록된 흐름과 다름", http_200_but_failed: "HTTP 200이지만 인증 실패",
  no_prior_auth_observed: "앞선 인증 기록 없음", several_accounts: "계정 여러 개" };
const SOFT = new Set(["no_prior_auth_observed", "http_200_but_failed"]);

function Lines({ title, items, tone }: { title: string; items: string[]; tone?: string }) {
  if (!items?.length) return null;
  return <div className={`fk-lines ${tone || ""}`}><h5>{title}</h5><ul>{items.map((t, i) => <li key={i}>{t}</li>)}</ul></div>;
}

function FlowDetail({ inv, runId, flowKey, onRemember, onChanged }: { inv: string; runId: string; flowKey: string; onRemember: (seed: Seed, flow?: any) => void; onChanged: () => void }) {
  const ctx = useInv(inv);
  const q = useQuery({ queryKey: ["flow-detail", inv, runId, flowKey], queryFn: () => api.get(`/investigations/${inv}/flows/runs/${runId}/flow?key=${encodeURIComponent(flowKey)}`) });
  const [name, setName] = useState("");
  const [cls, setCls] = useState("undetermined");
  const saveFlow = useMutation({ mutationFn: (steps: any[]) => api.post("/knowledge/flow-items", { kind: "flow", content: { host: q.data.host, name, classification: cls, steps },
      evidence: { investigation_id: inv, event_ids: q.data.steps.slice(0, 50).map((s: any) => s.event_id), source: "flow" } }), onSuccess: () => { setName(""); onChanged(); } });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const f = q.data;
  const ids = f.steps.map((s: any) => s.event_id).filter(Boolean);
  const asFlow = () => {
    const steps: any[] = [];
    for (const s of f.steps) {
      const last = steps[steps.length - 1];
      if (last && last.activity === s.knowledge.id) { last.repeat = true; continue; }
      steps.push({ activity: s.knowledge.id, state: s.role === "auth_attempt" && s.outcome === "success" ? "success" : "", optional: false, repeat: false });
    }
    return steps;
  };
  return <div className="fk-detail">
    <div className="row wrap small"><b>연결 근거</b><span>{f.link_text}</span>
      <button className="btn sm" onClick={() => { ctx.set({ tab: "raw", filters: [{ field: "event_id", op: "in", value: ids }], time: null, selection: null }); }}>이 흐름의 원문 {ids.length}건 보기</button></div>
    <div className="fk-table" tabIndex={0} aria-label="시간순 단계 표"><table className="t">
      <thead><tr><th>시각</th><th>업무 의미</th><th>요청</th><th>HTTP</th><th>업무 결과</th><th>인증 문맥</th><th>대상·계정</th><th>지식</th></tr></thead>
      <tbody>{f.steps.map((s: any, i: number) => <tr key={s.event_id || i} className="fk-step" onClick={() => ctx.set({ eventId: s.event_id })} title="기록 상세 열기">
        <td className="small nowrap">{fmtTime(s.time)}{s.order_uncertain && <span className="tag warn" title="같은 시각의 기록이 있어 순서를 확정하지 않았습니다">순서 미확정</span>}</td>
        <td><b>{s.meaning}</b><div className="small muted">{ROLE_KO[s.role] || s.role}</div></td>
        <td className="mono small">{s.method} {s.path}</td>
        <td className="mono small">{s.status_code ?? "—"}</td>
        <td className="small"><span className={`tag ${s.outcome === "success" ? "ok" : s.outcome === "failure" ? "bad" : ""}`}>{OUTCOME_KO[s.outcome]}</span>
          <div className="muted">{s.outcome_basis}</div></td>
        <td className="small">{s.auth_context_text || "—"}{s.auth_context_note && <div className="muted">{s.auth_context_note}</div>}</td>
        <td className="small">{s.object != null && <div>대상 <span className="mono">{String(s.object)}</span> {s.object_relation === "self" ? "(본인)" : s.object_relation === "other" ? <span className="tag warn">계정과 다름</span> : ""}</div>}
          {s.account && <div>계정 <span className="mono">{s.account}</span>{s.account_note && <div className="muted">{s.account_note}</div>}</div>}</td>
        <td className="small muted">v{s.knowledge.version}</td>
      </tr>)}</tbody></table></div>
    {f.steps_omitted > 0 && <p className="small" role="note">뒤쪽 {f.steps_omitted}개 단계는 표시 한도를 넘어 생략했습니다.</p>}
    <div className="fk-cols">
      <Lines title="확인된 사실" items={f.confirmed} tone="ok" />
      <Lines title="추정(후보)" items={f.inferred} />
      <Lines title="확인되지 않은 것" items={f.unknown} tone="warn" />
      <Lines title="다음에 확인할 것" items={f.next_checks} tone="next" />
    </div>
    {f.conformance.length > 0 && <div className="fk-lines"><h5>등록된 흐름과 비교</h5><ul>{f.conformance.map((c: any) => <li key={c.knowledge_id}>
      <span className={`tag ${c.status === "matched" ? "ok" : "warn"}`}>{c.status === "matched" ? "순서·결과 같음" : "다름"}</span> <b>{c.name}</b> <span className="muted">v{c.version} · {c.note}</span>
      {c.deviations.map((d: string, i: number) => <div key={i} className="small">· {d}</div>)}</li>)}</ul></div>}
    {f.devices.length > 0 && <div className="fk-lines"><h5>보안장비 기록 {f.devices.length}건</h5>
      <div className="fk-table" tabIndex={0} aria-label="보안장비 기록 표"><table className="t"><thead><tr><th>시각</th><th>장비·공격명(원문)</th><th>룰 ID·버전</th><th>장비 조치</th><th>HTTP</th><th>연결</th><th>등록된 해석</th></tr></thead>
        <tbody>{f.devices.map((d: any) => <tr key={d.event_id + d.step_event_id} className="fk-step" onClick={() => ctx.set({ eventId: d.event_id })}>
          <td className="small nowrap">{fmtTime(d.time)}</td><td className="small"><b>{String(d.source || "").toUpperCase()}</b> {d.device} · {d.alert_name}</td>
          <td className="mono small">{d.rule_id || "—"}{d.rule_version ? ` · v${d.rule_version}` : ""}</td>
          <td className="small">{d.device_action || "—"}</td><td className="mono small">{d.http_status ?? "—"}</td>
          <td className="small"><span className={`tag ${d.link === "same_request" ? "ok" : ""}`}>{d.link === "same_request" ? "같은 요청" : "관련 후보"}</span><div className="muted">{d.link_basis}</div></td>
          <td className="small">{d.signature?.registered ? <><b>{d.signature.meaning || "의미 미기재"}</b>{d.signature.cannot_prove?.length > 0 && <div className="muted">입증하지 못하는 것: {d.signature.cannot_prove.join(" / ")}</div>}</>
            : <><span className="muted">해석 미등록</span> <Link to="/registry" onClick={e => e.stopPropagation()}>공격명 해석 저장</Link></>}</td></tr>)}</tbody></table></div>
      <p className="small muted">장비 탐지, 장비 조치, HTTP 응답, 업무 결과는 서로 다른 값입니다. 하나로 합쳐 판정하지 않았습니다.</p></div>}
    {f.network && <p className="small"><b>FW·연결 기록</b> {f.network.records > 0 ? `${f.network.records}건 (허용 ${f.network.pairs.reduce((a: number, p: any) => a + p.allowed, 0)} · 차단 ${f.network.pairs.reduce((a: number, p: any) => a + p.blocked, 0)})` : ""} <span className="muted">{f.network.text}</span>
      {f.network.records > 0 && <button className="btn sm" style={{ marginLeft: 8 }} onClick={() => ctx.set({ tab: "raw", filters: f.network.pairs[0].filters, time: f.network.pairs[0].time, selection: null })}>연결 기록 보기</button>}</p>}
    <details><summary>사용한 지식 {f.knowledge_used.length}개</summary><ul className="small">{f.knowledge_used.map((k: any) => <li key={k.id}>{k.title} — 적용 v{k.applied_version}
      {k.current_version !== k.applied_version && <span className="tag warn">현재 v{k.current_version ?? "삭제"}</span>}{k.status === "stopped" && <span className="tag">적용 중지됨</span>}</li>)}</ul>
      <Link className="small" to="/knowledge/flows">지식 고치기</Link></details>
    {f.judgements.length > 0 && <div className="fk-lines"><h5>이 사건의 판단</h5><ul>{f.judgements.map((j: any) => <li key={j.id}><b>{VERDICT_KO[j.verdict]}</b> {j.note} <span className="muted">— {j.by} · {fmtTime(j.created_at)}</span></li>)}</ul></div>}
    <div className="row wrap fk-actions">
      <button className="btn sm primary" onClick={() => onRemember({ host: f.host, eventIds: ids, source: "flow" }, { runId, key: f.key, eventIds: ids })}>판단 남기기 · 기억하기</button>
      <details className="fk-saveflow"><summary className="btn sm">이 순서를 흐름으로 기억하기</summary>
        <div className="row wrap small"><input className="input" aria-label="흐름 이름" placeholder="흐름 이름(예: 인증 후 본인정보 조회)" value={name} onChange={e => setName(e.target.value)} style={{ width: 260 }} />
          <select className="input" aria-label="흐름 분류" value={cls} onChange={e => setCls(e.target.value)}><option value="undetermined">분류 미확정</option><option value="normal">정상 업무 흐름</option><option value="suspicious">의심 흐름</option></select>
          <button className="btn sm" disabled={!name.trim() || saveFlow.isPending || asFlow().length < 2} onClick={() => saveFlow.mutate(asFlow())}>저장</button></div>
        <p className="small muted">단계: {f.sequence.join(" → ")}. 저장한 흐름은 다음 분석부터 순서·결과를 비교하는 기준이 됩니다. 정상으로 분류해도 개별 사건을 자동으로 정상 처리하지 않습니다.</p>
        {asFlow().length < 2 && <p className="small">단계가 2개 이상이어야 흐름으로 저장할 수 있습니다.</p>}
        <ErrorBox error={saveFlow.error} />{saveFlow.isSuccess && <p className="small" role="status">흐름을 저장했습니다. 다시 분석하면 비교 결과가 나옵니다.</p>}
      </details>
    </div>
  </div>;
}

/** What business flows were observed, why they were linked, how they differ from registered flows, what is unknown. */
export function FlowsTab({ inv }: { inv: string }) {
  const qc = useQueryClient();
  const ctx = useInv(inv);
  const [open, setOpen] = useState<string | null>(null);
  const [remember, setRemember] = useState<{ seed: Seed; flow?: any } | null>(null);
  const [filter, setFilter] = useState<"attention" | "all">("attention");
  const [more, setMore] = useState(20);
  const q = useQuery({ queryKey: ["flows", inv], queryFn: () => api.get(`/investigations/${inv}/flows`) });
  const refresh = () => { qc.invalidateQueries({ queryKey: ["flows", inv] }); qc.invalidateQueries({ queryKey: ["flow-detail", inv] }); };
  const run = useMutation({ mutationFn: (reason: string) => api.post(`/investigations/${inv}/flows/run`, { reason }), onSuccess: refresh });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const { run: r, stale, knowledge_items } = q.data;
  const dialog = remember && <RememberDialog inv={inv} seed={remember.seed} flow={remember.flow} onClose={() => setRemember(null)} onSaved={() => { setRemember(null); refresh(); }} />;
  if (!r) return <div className="col"><Panel title="업무 흐름">
    <p>아직 분석한 적이 없습니다. 자료를 올리면 자동으로 분석합니다{knowledge_items ? "" : ". 등록된 업무 의미가 아직 없어, 먼저 로그에서 의미를 기억시켜 주세요"}.</p>
    <div className="row wrap"><button className="btn primary" disabled={run.isPending} onClick={() => run.mutate("manual")}>{run.isPending ? "분석 중…" : "지금 분석"}</button>
      <button className="btn" onClick={() => setRemember({ seed: {} })}>업무 의미 등록</button></div><ErrorBox error={run.error} /></Panel>{dialog}</div>;
  const res = r.result;
  if (r.status === "failed") return <Panel title="업무 흐름"><p role="alert">분석 실행이 실패했습니다({res.error}). 결과 없음이 아니라 실행 실패입니다.</p>
    <button className="btn" disabled={run.isPending} onClick={() => run.mutate("manual")}>다시 분석</button></Panel>;
  const flows: any[] = res.flows || [];
  const attention = flows.filter(f => f.attention > 0);
  const shown = (filter === "attention" && attention.length ? attention : flows);
  const unexplained = (res.discovery?.transitions || []).filter((t: any) => !t.explained_by_registered_flow);
  const c = res.counts;
  return <div className="col fk-tab">
    <Panel title="업무 흐름" right={<span className="small muted">분석 v{r.version} · {fmtTime(r.finished_at)} · {({ ingest: "자료 추가 뒤 자동", knowledge_changed: "지식 변경 뒤", manual: "직접 실행" } as any)[r.reason]}</span>}>
      <p className="fk-summary" role="status"><b>{STATUS_KO[r.status]}</b> · HTTP 요청 {c.records_read.toLocaleString()}건 중 <b>{c.labeled.toLocaleString()}건</b>에 업무 의미 적용 · 흐름 {res.completeness.flows_total.toLocaleString()}개
        (세션으로 연결 {c.sessions_confirmed.toLocaleString()} · IP·시간 후보 {c.sessions_candidate.toLocaleString()}) · <b>살펴볼 흐름 {(res.completeness.flows_needing_a_look ?? attention.length).toLocaleString()}개</b>
        {c.duplicates > 0 && ` · 중복 기록 ${c.duplicates}건 제외`}{c.no_time > 0 && ` · 시각 없는 기록 ${c.no_time}건 제외`}</p>
      {r.status === "partial" && <p role="alert" className="small">처리 한도 때문에 일부만 검사했습니다. {res.completeness.note} 검사하지 않은 범위에 흐름이 더 있을 수 있습니다.</p>}
      {res.knowledge_note && <p className="small" role="note">{res.knowledge_note}</p>}
      {stale.stale && <div className="fk-stale" role="alert"><b>이 결과는 최신이 아닙니다.</b> {stale.reasons.join(" ")}
        <button className="btn sm primary" disabled={run.isPending} onClick={() => run.mutate("knowledge_changed")}>{run.isPending ? "다시 분석 중…" : "최신 지식으로 다시 분석"}</button>
        <span className="small muted">이전 결과(v{r.version})는 그대로 남습니다.</span></div>}
      {res.conflicts?.length > 0 && <div className="error small" role="alert"><b>상충하는 지식 {res.conflicts.length}건은 적용하지 않았습니다.</b>{res.conflicts.map((x: any, i: number) => <div key={i}>· {x.text}</div>)}
        <Link to="/knowledge/flows">지식에서 정리하기</Link></div>}
      {r.changes && !r.changes.first_run && (r.changes.reasons?.length > 0 || r.changes.flows?.changed?.length > 0) && <details className="small"><summary>이전 분석(v{r.changes.previous_version})과 달라진 점</summary>
        {r.changes.reasons.map((x: string, i: number) => <div key={i}>· {x}</div>)}
        {r.changes.knowledge.map((k: any) => <div key={k.id}>· 지식 {k.title || k.id.slice(0, 8)}: {k.from == null ? "새로 적용" : `v${k.from}`} → {k.to == null ? "적용 중지" : `v${k.to}`}</div>)}
        <div>· 의미가 붙은 기록 {r.changes.labeled.before ?? 0} → {r.changes.labeled.after}건 · 새 흐름 {r.changes.flows.added.length} · 사라진 흐름 {r.changes.flows.removed.length} · 내용이 바뀐 흐름 {r.changes.flows.changed.length}</div>
        {r.changes.flows.changed.slice(0, 5).map((x: any) => <div key={x.key} className="muted">  이전: {x.before} / 지금: {x.after}</div>)}</details>}
      <div className="row wrap"><button className="btn sm" disabled={run.isPending} onClick={() => run.mutate("manual")}>{run.isPending ? "분석 중…" : "다시 분석"}</button>
        <button className="btn sm" onClick={() => setRemember({ seed: { host: res.services?.[0]?.host } })}>업무 의미 등록</button>
        <Link className="btn sm" to="/knowledge/flows">등록된 지식 보기</Link><ErrorBox error={run.error} /></div>
    </Panel>

    {flows.length > 0 && <Panel title={`관측된 흐름 ${shown.length}개`} right={<div className="row small" role="group" aria-label="흐름 보기">
      <button className={`btn sm ${filter === "attention" ? "primary" : ""}`} aria-pressed={filter === "attention"} onClick={() => setFilter("attention")}>살펴볼 흐름 {attention.length}</button>
      <button className={`btn sm ${filter === "all" ? "primary" : ""}`} aria-pressed={filter === "all"} onClick={() => setFilter("all")}>전체 {flows.length}</button></div>}>
      {res.completeness.flows_total > flows.length && <p className="small" role="note">흐름 {res.completeness.flows_total.toLocaleString()}개 중 살펴볼 순서로 {flows.length}개를 표시합니다.</p>}
      {filter === "attention" && !attention.length && <p className="small">등록된 기준에서 따로 살펴볼 흐름은 없습니다. 정상이라는 뜻은 아니며, 전체 흐름을 표시합니다.</p>}
      <ul className="fk-flows">{shown.slice(0, more).map((f: any) => <li key={f.key} className={open === f.key ? "open" : ""}>
        <button className="fk-flow" aria-expanded={open === f.key} onClick={() => setOpen(open === f.key ? null : f.key)}>
          <span className="fk-flow-main"><b>{f.summary}</b>
            <span className="small muted">{fmtTime(f.start)} ~ {fmtTime(f.end)} · {f.host} · 출발지 {f.src_ips.join(", ")} · 요청 {f.requests}건 · {f.sequence.join(" → ")}</span></span>
          <span className="fk-flow-tags">{f.link === "session" ? <span className="tag ok">세션 연결</span> : <span className="tag">IP·시간 후보</span>}
            {f.flags.map((x: string) => <span key={x} className={`tag ${SOFT.has(x) ? "" : "warn"}`}>{FLAG_KO[x] || x}</span>)}
            {f.devices.length > 0 && <span className="tag warn">보안장비 {f.devices.length}</span>}
            {f.ddos_interval_ids.length > 0 && <span className="tag" title="같은 시간대의 서비스 구간입니다. 이 흐름의 행위로 연결하지 않았습니다.">DDoS 구간과 같은 시간대</span>}
            {f.judgement && <span className="tag ok">판단: {VERDICT_KO[f.judgement.verdict]}</span>}</span>
        </button>
        {open === f.key && <FlowDetail inv={inv} runId={r.id} flowKey={f.key} onRemember={(seed, flow) => setRemember({ seed, flow })} onChanged={refresh} />}
      </li>)}</ul>
      {shown.length > more && <button className="btn sm" onClick={() => setMore(more + 20)}>더 보기 ({shown.length - more}개 남음)</button>}
    </Panel>}

    {res.ddos?.length > 0 && <Panel title={`DDoS 관측 구간 ${res.ddos.length}개 (서비스 단위 집계)`}>
      <div className="fk-table" tabIndex={0} aria-label="DDoS 구간 표"><table className="t"><thead><tr><th>구간</th><th>서비스·대상</th><th>벡터</th><th>지표</th><th>집계 주기</th><th>탐지</th><th>완화</th><th>구간 안 HTTP 요청</th><th>5xx</th></tr></thead>
        <tbody>{res.ddos.map((d: any) => <tr key={d.id} className="fk-step" onClick={() => ctx.set({ eventId: d.event_id })}><td className="small nowrap">{fmtTime(d.start)} ~ {d.end_raw}</td><td className="small">{d.host || "—"} {d.target_ip}</td><td>{d.vector}</td>
          <td className="mono small">{d.value} {d.unit} ({d.metric})</td><td className="small">{d.interval_seconds}초</td><td className="small">{d.detection_state}</td><td className="small">{d.mitigation_state}</td>
          <td className="num">{d.requests.toLocaleString()}</td><td className="num">{d.server_errors.toLocaleString()}</td></tr>)}</tbody></table></div>
      <p className="small muted">집계 자료이므로 특정 계정·세션의 행위로 연결하지 않았습니다. 같은 시간대라는 사실만으로 같은 공격자·인과관계를 뜻하지 않습니다. 요청 수·5xx는 HTTP 기록에서 센 값이며 서비스 영향의 증명이 아닙니다.</p>
    </Panel>}

    {(unexplained.length > 0 || res.unregistered?.length > 0) && <Panel title="새로 보인 흐름과 미등록 경로">
      <p className="small muted">{res.discovery.baseline.note}</p>
      {unexplained.length > 0 && <div className="fk-table" tabIndex={0} aria-label="등록된 흐름으로 설명되지 않는 전이"><table className="t"><thead><tr><th>앞 단계</th><th>뒤 단계</th><th>흐름 수</th><th>횟수</th><th>간격(중앙값)</th><th>처음 본 시각</th><th>기준과 비교</th><th /></tr></thead>
        <tbody>{unexplained.slice(0, 30).map((t: any, i: number) => <tr key={i}><td>{t.from}</td><td>{t.to}</td><td className="num">{t.sessions}</td><td className="num">{t.count}</td><td className="small">{t.median_gap_seconds ?? "—"}초</td><td className="small nowrap">{fmtTime(t.first)}</td>
          <td className="small">{t.new_since_baseline === true ? <span className="tag warn">기준 기간에 없던 전이</span> : t.new_since_baseline === false ? "기준 기간에도 있음" : t.new_vs_earlier_analyses === true ? <span className="tag warn">이전 분석에 없던 전이</span> : "비교할 기준 없음"}</td>
          <td><button className="btn sm" disabled={!t.example_event_ids.length} onClick={() => ctx.set({ tab: "raw", filters: [{ field: "event_id", op: "in", value: t.example_event_ids }], time: null, selection: null })}>예시 원문</button></td></tr>)}</tbody></table></div>}
      {res.unregistered?.length > 0 && <><h5 className="fk-h">의미가 등록되지 않은 경로 {res.unregistered.length}개</h5>
        <div className="fk-table" tabIndex={0} aria-label="미등록 경로 표"><table className="t"><thead><tr><th>서비스</th><th>요청</th><th>건수</th><th>처음 ~ 마지막</th><th>참고</th><th /></tr></thead>
          <tbody>{res.unregistered.slice(0, 30).map((u: any, i: number) => <tr key={i}><td className="small">{u.host}</td><td className="mono small">{u.method} {u.path}</td><td className="num">{u.count.toLocaleString()}</td><td className="small nowrap">{fmtTime(u.first)} ~ {fmtTime(u.last)}</td>
            <td className="small muted">{u.suggestion?.text || ""}</td>
            <td><button className="btn sm" onClick={() => setRemember({ seed: { host: u.host, method: u.method, path: u.path, eventIds: [u.example_event_id], source: "discovery", meaning: u.suggestion?.meaning, role: u.suggestion?.role } })}>의미 기억하기</button></td></tr>)}</tbody></table></div></>}
    </Panel>}

    <Panel title="서비스별 적용 현황">
      <div className="fk-table" tabIndex={0} aria-label="서비스별 적용 현황 표"><table className="t"><thead><tr><th>서비스</th><th>요청</th><th>의미 적용</th><th>적용된 업무 의미</th><th>연결 기준</th><th /></tr></thead>
        <tbody>{(res.services || []).map((s: any) => <tr key={s.host}><td>{s.host}</td><td className="num">{s.requests.toLocaleString()}</td><td className="num">{s.labeled.toLocaleString()}</td>
          <td className="small">{s.activities.map((a: any) => `${a.meaning} ${a.count.toLocaleString()}`).join(" · ") || <span className="muted">등록된 의미 없음</span>}</td>
          <td className="small">{s.link.text}</td>
          <td>{!s.link.session_cookie && <button className="btn sm" onClick={() => setRemember({ seed: { host: s.host, kind: "link" } })}>연결 기준 등록</button>}</td></tr>)}</tbody></table></div>
      <p className="small muted">{res.time.note} 기준 시각: {res.time.basis}. 보조 기록: 애플리케이션 {res.side.app_events.toLocaleString()}건 · 보안장비 {res.side.alerts.toLocaleString()}건 · DDoS 구간 {res.side.ddos_intervals}개.</p>
    </Panel>
    {dialog}
  </div>;
}
