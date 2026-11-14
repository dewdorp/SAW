import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { ErrorBox, Loading } from "../../components/common";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtTime } from "../../lib/format";
import { AiPanel } from "./AiPanel";
import "./hunt.css";

export const REVIEW_KO: Record<string, string> = { unreviewed: "미검토", needs_check: "추가 확인", normal_work: "정상 업무", threat_confirmed: "위협 확인" };
const METHOD_TONE: Record<string, string> = { found: "warn", partial: "warn", failed: "bad", insufficient_data: "", unsupported: "", no_match: "ok" };
const SOURCE_KO: Record<string, string> = { web: "NDR HTTP·웹", connection: "FW·연결", firewall: "방화벽", waf: "WAF", ips: "IPS", ddos: "DDoS", app: "애플리케이션" };

/** Per-investigation view state kept across a trip to the raw logs: selection, filter, scroll and the unsent note. */
function useKept<T>(inv: string, name: string, initial: T): [T, (v: T) => void] {
  const key = `saw.hunt.${inv}.${name}`;
  const [value, setValue] = useState<T>(() => { try { const raw = sessionStorage.getItem(key); return raw == null ? initial : JSON.parse(raw); } catch { return initial; } });
  return [value, (v: T) => { setValue(v); try { sessionStorage.setItem(key, JSON.stringify(v)); } catch { /* storage may be unavailable */ } }];
}

function Section({ title, items, empty }: { title: string; items?: string[]; empty?: string }) {
  return <section className="ha-section"><h4>{title}</h4>
    {items?.length ? <ul>{items.map((t, i) => <li key={i}>{t}</li>)}</ul> : <p className="muted small">{empty || "기록된 내용이 없습니다."}</p>}</section>;
}

/** The records behind the statement, shown where it is read: an analyst should not have to leave to see the basis. */
function EvidenceRows({ inv, a, onOpen }: { inv: string; a: any; onOpen: (eventId?: string) => void }) {
  const q = useQuery({ queryKey: ["hunt-evidence", inv, a.id], queryFn: () => api.get(`/investigations/${inv}/hunt/activities/${a.id}/evidence`), retry: false });
  if (q.isLoading) return <p className="small muted">근거 기록을 불러오는 중…</p>;
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data;
  if (!d.rows.length) return <p className="small" role="note">{d.missing}</p>;
  return <div className="ha-evidence">
    <p className="small"><b>근거 기록 {d.total != null ? `${Number(d.total).toLocaleString()}건 중 ` : ""}{d.shown}건</b> — {d.basis}</p>
    <div className="fk-table"><table className="t"><thead><tr><th>시각</th><th>자료</th><th>출발지</th><th>목적지</th><th>요청·경보</th><th>결과</th><th></th></tr></thead>
      <tbody>{d.rows.map((r: any) => <tr key={r.event_id}><td className="small nowrap">{r.time ? fmtTime(r.time) : "시각 없음"}</td><td className="small">{r.source}</td>
        <td className="mono small">{r.src}</td><td className="mono small">{r.dst}</td><td className="mono small ha-what">{r.what}</td><td className="small">{r.result}</td>
        <td><button className="btn ghost sm" onClick={() => onOpen(r.event_id)}>원문</button></td></tr>)}</tbody></table></div>
    {d.total != null && d.total > d.shown && <p className="small muted">나머지는 아래 단추로 모두 볼 수 있습니다.</p>}</div>;
}

function Detail({ inv, a, runVersion, onReviewed }: { inv: string; a: any; runVersion: number; onReviewed: () => void }) {
  const ctx = useInv(inv);
  const [notes, setNotes] = useKept<Record<string, string>>(inv, "notes", {});
  const note = notes[a.id] ?? "";
  const review = useMutation({ mutationFn: (state: string) => api.post(`/investigations/${inv}/hunt/reviews`, { activity_id: a.id, state, note }),
    onSuccess: () => { setNotes({ ...notes, [a.id]: "" }); onReviewed(); } });
  const ev = a.evidence || {};
  const openEvidence = () => {
    if (ev.finding_id) return ctx.set({ tab: "findings", findingId: ev.finding_id });
    if (ev.tab === "flows" && !ev.event_ids?.length) return ctx.set({ tab: "flows" });
    if (ev.filters?.length) return ctx.set({ tab: "raw", filters: ev.filters, time: ev.time?.start && ev.time?.end ? ev.time : null, selection: null });
    if (ev.event_ids?.length) return ctx.set({ tab: "raw", filters: [{ field: "event_id", op: "in", value: ev.event_ids }], time: null, selection: null });
  };
  const evidenceLabel = ev.finding_id ? `탐지 ${ev.display_id || ""} 근거 보기` : ev.tab === "flows" && !ev.event_ids?.length ? "업무 흐름에서 단계 보기"
    : `관련 원문 ${ev.records ?? ev.event_ids?.length ?? ""}건 보기`;
  return <article className="ha-detail" aria-label="활동 상세">
    <header><h3>{a.title}</h3>
      <p className="small muted">{a.time?.start ? `${fmtTime(a.time.start)} ~ ${fmtTime(a.time.end)}` : "시각 범위 없음"} · 연결 강도: {a.strength}{a.not_in_this_run ? " · 최신 분석에는 다시 나오지 않은 활동(판단은 보존)" : ""}</p></header>
    <Section title="1. 무엇을 관측했나" items={a.observed} />
    <Section title="2. 왜 확인할 만한가" items={a.why} />
    <Section title="3. 정상 업무로 설명될 가능성" items={a.normal} empty="정상 가능성이 기록되지 않았습니다. 없다는 뜻이 아닙니다." />
    <Section title="4. 아직 확인되지 않은 것" items={a.unknown} />
    <section className="ha-section"><h4>5. 시간 흐름과 관련 원문</h4>
      <EvidenceRows inv={inv} a={a} onOpen={id => ctx.set({ tab: "raw", filters: [{ field: "event_id", op: "is", value: id }], time: null, selection: null })} />
      <div className="row wrap"><button className="btn sm primary" onClick={openEvidence}>{evidenceLabel}</button>
        {ev.tab === "flows" && <button className="btn sm" onClick={() => ctx.set({ tab: "flows" })}>업무 흐름 열기</button>}
        <button className="btn sm" onClick={() => ctx.set({ tab: "timeline" })}>타임라인</button>
        <button className="btn sm" onClick={() => ctx.set({ tab: "raw", filters: [], time: null, selection: null })}>전체 로그 검색</button></div>
      {a.next_checks?.length > 0 && <><h5>다음에 확인할 것</h5><ul>{a.next_checks.map((t: string, i: number) => <li key={i}>{t}</li>)}</ul></>}
      {Object.keys(a.counts || {}).length > 0 && <p className="small muted">계산 값: {Object.entries(a.counts).map(([k, v]) => `${k} ${v}`).join(" · ")}</p>}</section>
    <section className="ha-section ha-judge"><h4>6. 판단 남기기</h4>
      <p className="small">현재 검토 상태: <b>{REVIEW_KO[a.review.state]}</b>{a.review.by ? ` — ${a.review.by} · ${fmtTime(a.review.at)}` : ""}{a.review.note ? ` · ${a.review.note}` : ""}</p>
      <textarea className="input" rows={2} aria-label="판단 근거" placeholder="판단 근거 또는 확인할 내용" value={note} onChange={e => setNotes({ ...notes, [a.id]: e.target.value })} />
      <div className="row wrap">
        <button className="btn sm" disabled={review.isPending} onClick={() => review.mutate("needs_check")}>추가 확인 필요</button>
        <button className="btn sm" disabled={review.isPending || !note.trim()} title={note.trim() ? "" : "근거를 적어야 합니다"} onClick={() => review.mutate("normal_work")}>정상 업무로 확인</button>
        <button className="btn sm" disabled={review.isPending || !note.trim()} title={note.trim() ? "" : "근거를 적어야 합니다"} onClick={() => review.mutate("threat_confirmed")}>위협 확인</button>
        <button className="btn sm" onClick={() => ctx.set({ tab: "checks" })}>확인 요청·회신</button>
        <a className="btn sm" href={`/inv/${inv}/report`}>보고서</a></div>
      <ErrorBox error={review.error} />
      {a.review.history?.length > 1 && <details className="small"><summary>판단 이력 {a.review.history.length}건</summary>{a.review.history.map((h: any, i: number) =>
        <div key={i}>{fmtTime(h.at)} · {h.by} · {REVIEW_KO[h.state]} {h.note} <span className="muted">(분석 v{h.run_version ?? "?"})</span></div>)}</details>}
      <p className="small muted">판단은 분석가가 남깁니다. 계산 결과가 "조건 일치 없음"이어도 정상으로 자동 종결하지 않습니다. 분석 v{runVersion} 기준.</p></section>
  </article>;
}

/** The hunt workbench: scope and what was actually examined on top, activities on the left, one activity in full on the right. */
export function HuntActivities({ inv }: { inv: string }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["hunt", inv], queryFn: () => api.get(`/investigations/${inv}/hunt`), refetchInterval: (query) => (query.state.data as any)?.progress?.state === "running" ? 4000 : false });
  const refresh = () => { qc.invalidateQueries({ queryKey: ["hunt", inv] }); qc.invalidateQueries({ queryKey: ["hunts"] }); };
  const run = useMutation({ mutationFn: () => api.post(`/investigations/${inv}/hunt/run`, {}), onSuccess: refresh });
  const [selected, setSelected] = useKept<string>(inv, "selected", "");
  const [filter, setFilter] = useKept<string>(inv, "filter", "all");
  const [scroll, setScroll] = useKept<number>(inv, "scroll", 0);
  const list = useRef<HTMLDivElement>(null);
  useEffect(() => { if (list.current && scroll) list.current.scrollTop = scroll; }, [q.data?.run?.id]); // eslint-disable-line react-hooks/exhaustive-deps
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const { run: r, progress, stale } = q.data;
  if (!r) return <div className="ha-empty"><p><b>{progress.state === "running" ? "자료를 처리하는 중입니다." : "아직 분석한 자료가 없습니다."}</b> {progress.state === "running" ? "끝나면 확인할 활동이 여기에 나옵니다." : "자료를 추가하면 자동으로 분석합니다."}</p>
    {progress.active?.map((j: any) => <p key={j.id} className="small muted">{j.kind} · {j.state} {j.item}</p>)}
    <button className="btn" disabled={run.isPending} onClick={() => run.mutate()}>{run.isPending ? "분석 중…" : "지금 분석"}</button><ErrorBox error={run.error} /></div>;
  const all: any[] = [...r.activities, ...(r.carried || [])];
  const shown = all.filter(a => filter === "all" || a.review.state === filter);
  const current = shown.find(a => a.id === selected) ?? shown[0];
  const s = r.scope || {};
  const counts = r.summary.review || {};
  return <div className="ha">
    <div className="ha-scope" role="status">
      <span className="tag">{r.mode_label}</span>
      <span><b>{s.org_unit || "관계사 미지정"}</b></span>
      <span>관측 {s.observed?.first ? `${fmtTime(s.observed.first)} ~ ${fmtTime(s.observed.last)}` : "기간 없음"}</span>
      <span>선택 자료 <b>{(s.selected_records ?? 0).toLocaleString()}건</b> ({Object.entries(s.by_source || {}).map(([k, v]) => `${SOURCE_KO[k] || k} ${(v as number).toLocaleString()}`).join(" · ") || "원천 없음"})</span>
      {s.records_without_time > 0 && <span className="tag warn">시각 없는 기록 {s.records_without_time.toLocaleString()}건</span>}
      <span>진행: <b>{progress.label}</b></span>
      <span>분석 v{r.version} · {fmtTime(r.created_at)} · {r.status === "complete" ? "전체 처리" : r.status === "partial" ? "일부 처리" : "실행 실패"}</span>
      <button className="btn sm" disabled={run.isPending} onClick={() => run.mutate()}>{run.isPending ? "분석 중…" : "다시 분석"}</button>
    </div>
    {stale.length > 0 && <div className="ha-stale" role="alert">이 결과는 최신이 아닙니다. {stale.join(" ")} <button className="btn sm primary" disabled={run.isPending} onClick={() => run.mutate()}>다시 분석</button></div>}
    <ErrorBox error={run.error} />
    <details className="ha-methods"><summary>분석 방법 {r.methods.length}개와 실제 처리 범위 — {r.methods.map((m: any) => m.status_label).filter((v: string, i: number, arr: string[]) => arr.indexOf(v) === i).join(" · ")}</summary>
      <table className="t"><thead><tr><th>분석 방법</th><th>계산 결과</th><th>후보·표시</th><th>검사한 범위</th><th>필요한 자료·한계</th></tr></thead>
        <tbody>{r.methods.map((m: any) => <tr key={m.id}><td>{m.name}{m.condition && <div className="small muted">{m.condition}</div>}</td>
          <td><span className={`tag ${METHOD_TONE[m.status] || ""}`}>{m.status_label}</span></td>
          <td className="small">{m.found ?? 0}개{m.shown != null && m.shown !== m.found ? ` 중 ${m.shown}개 표시` : ""}</td>
          <td className="small">{m.records != null ? `기록 ${Number(m.records).toLocaleString()}건` : "—"}{m.examined && Object.keys(m.examined).length > 0 && <div className="muted">{Object.entries(m.examined).map(([k, v]) => `${k} ${v}`).join(" · ")}</div>}</td>
          <td className="small">{[...(m.needs || []), ...(m.partial_reasons || []), m.error ? `오류 ${m.error}` : ""].filter(Boolean).join(" / ") || "—"}</td></tr>)}</tbody></table>
      <p className="small muted">{s.note} "조건 일치 없음"은 이 기준에서 보이지 않았다는 뜻이며 정상이라는 뜻이 아닙니다. "자료 부족"·"미지원"은 계산하지 못한 것입니다.</p></details>
    <AiPanel inv={inv} />
    <div className="ha-body">
      <aside className="ha-list" aria-label="확인할 활동 목록">
        <div className="row wrap ha-filters" role="group" aria-label="검토 상태로 걸러 보기">
          {[["all", `전체 ${all.length}`], ["unreviewed", `미검토 ${counts.unreviewed || 0}`], ["needs_check", `추가 확인 ${counts.needs_check || 0}`], ["normal_work", `정상 업무 ${counts.normal_work || 0}`], ["threat_confirmed", `위협 확인 ${counts.threat_confirmed || 0}`]].map(([k, l]) =>
            <button key={k} className={`btn sm ${filter === k ? "primary" : ""}`} aria-pressed={filter === k} onClick={() => setFilter(k)}>{l}</button>)}</div>
        {r.summary.activities > r.summary.shown && <p className="small" role="note">활동 {r.summary.activities}개 중 {r.summary.shown}개를 표시합니다.</p>}
        <div className="ha-items" ref={list} onScroll={e => setScroll((e.target as HTMLDivElement).scrollTop)}>
          {!shown.length && <p className="small muted">{all.length ? "이 상태의 활동이 없습니다." : "이 기준에서 확인할 활동을 찾지 못했습니다. 정상이라는 뜻은 아니며, 위의 분석 방법별 결과와 전체 로그 검색을 확인하세요."}</p>}
          {shown.map(a => <button key={a.id} className={`ha-item ${current?.id === a.id ? "sel" : ""}`} aria-current={current?.id === a.id} onClick={() => setSelected(a.id)}>
            <b>{a.title}</b>
            <span className="small muted">{a.time?.start ? fmtTime(a.time.start) : ""} · {r.methods.find((m: any) => m.id === a.method || a.method.startsWith(m.id))?.name || a.method}</span>
            <span className={`tag ${a.review.state === "threat_confirmed" ? "bad" : a.review.state === "normal_work" ? "ok" : a.review.state === "needs_check" ? "warn" : ""}`}>{REVIEW_KO[a.review.state]}</span>
          </button>)}</div>
      </aside>
      {current ? <Detail key={current.id} inv={inv} a={current} runVersion={r.version} onReviewed={refresh} /> : <div className="ha-detail"><p className="muted">왼쪽에서 활동을 고르세요.</p></div>}
    </div>
  </div>;
}
