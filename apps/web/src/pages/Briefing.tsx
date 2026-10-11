import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ErrorBox, Loading } from "../components/common";
import { Icon } from "../components/ui";
import { api } from "../lib/api";
import { fmtBytes, fmtNum } from "../lib/format";

const SECTIONS: [key: string, title: string, hint: string][] = [
  ["what", "1. 무슨 일이 있었나", "언제, 어디서 어디로, 무엇을 시도했는지 (한 줄에 한 가지)"],
  ["impact", "2. 영향", "대상 시스템, 성공 여부, 유출 정황"],
  ["done", "3. 조치한 내용", "이미 한 조치 (차단, 통보, 점검 등)"],
  ["todo", "4. 남은 일", "앞으로 할 일과 담당"],
];
const RISKS = ["critical", "high", "medium", "low", "info"];
const RISK_KO: Record<string, string> = { critical: "매우 높음", high: "높음", medium: "보통", low: "낮음", info: "참고" };

function Lines({ text }: { text: string }) {
  const rows = (text || "").split("\n").map((s) => s.trim()).filter(Boolean);
  if (!rows.length) return <p className="muted small">기록된 내용이 없습니다.</p>;
  return <ul className="rp-list">{rows.map((r, i) => <li key={i}>{r.replace(/^[-•]\s*/, "")}</li>)}</ul>;
}

/** One-page summary of an investigation for reporting upward: generated from the analysis, rewritable, printable. */
export function Briefing() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const [mask, setMask] = useState(true);
  const [draft, setDraft] = useState<Record<string, string> | null>(null);
  const url = `/investigations/${id}/briefing`;
  const q = useQuery({ queryKey: ["briefing", id, mask], queryFn: () => api.get(`${url}?mask=${mask}`) });
  const save = useMutation({
    mutationFn: (fields: Record<string, string>) => api.put(`${url}?mask=${mask}`, { fields }),
    onSuccess: (d) => { qc.setQueryData(["briefing", id, mask], d); qc.invalidateQueries({ queryKey: ["briefing", id] }); setDraft(null); },
  });
  const file = useMutation({ mutationFn: () => api.download(`${url}.html?mask=${mask}`, "report.html") });
  if (q.isLoading) return <div className="page"><Loading /></div>;
  if (q.error || !q.data) return <div className="page"><ErrorBox error={q.error} /></div>;
  const b = q.data;
  const i = b.investigation, f = b.facts, t = b.text;
  const people = [...new Set([i.owner, ...i.members].filter(Boolean))].join(", ") || "—";
  const day = (v?: string | null) => (v ? new Date(v).toLocaleDateString("ko-KR") : "");
  // only what differs from the generated text is stored, so later analysis results keep flowing into untouched sections
  const submit = () => draft && save.mutate(Object.fromEntries(Object.entries(draft).map(([k, v]) => [k, v.trim() === (b.auto[k] || "").trim() ? "" : v])));
  return (
    <div className="page report-page">
      <div className="row wrap no-print" style={{ marginBottom: 14 }}>
        <Link to={`/inv/${id}`} className="btn ghost sm">← 조사 작업대</Link>
        <div className="grow" />
        <label className="row small" title="끄면 IP 주소를 끝자리까지 표시합니다 (내부 검토용)"><input type="checkbox" checked={mask} onChange={(e) => { setMask(e.target.checked); setDraft(null); }} /> IP 끝자리 가리기</label>
        {b.can_edit && !draft && <button className="btn sm" onClick={() => setDraft({ ...t })}>문구 고치기</button>}
        {draft && <button className="btn sm primary" disabled={save.isPending} onClick={submit}>저장</button>}
        {draft && <button className="btn sm ghost" onClick={() => setDraft(null)}>취소</button>}
        {!draft && <button className="btn sm" onClick={() => window.print()}><Icon name="report" size={14} /> 인쇄 / PDF로 저장</button>}
        {!draft && <button className="btn sm" disabled={file.isPending} onClick={() => file.mutate()}><Icon name="download" size={14} /> 파일로 받기</button>}
      </div>
      <ErrorBox error={save.error || file.error} />
      <article className="report" aria-label="보고용 요약">
        <div className="rp-eyebrow">보안 사건 분석 보고 (요약)</div>
        <h1>{i.title}</h1>
        <div className="muted small">{i.display_id}</div>
        {draft
          ? <textarea className="input rp-headline-edit" rows={2} aria-label="결론 한 줄" value={draft.headline} onChange={(e) => setDraft({ ...draft, headline: e.target.value })} />
          : <div className="rp-headline">{t.headline}</div>}
        <div className="rp-grid">
          <div><span>상태</span><b>{i.status_ko}</b></div>
          <div><span>판정</span><b>{i.verdict_ko || "판정 전"}</b></div>
          <div><span>위험도</span><b className={`sev ${i.risk_level}`}>{i.risk_ko}</b></div>
          <div><span>담당</span><b>{people}</b></div>
          <div><span>접수 / 종결</span><b>{day(i.created_at)} / {day(i.closed_at) || "진행 중"}</b></div>
        </div>
        {SECTIONS.map(([k, title, hint]) => (
          <section key={k}>
            <h2>{title}{b.edited[k] && !draft && <span className="badge no-print" style={{ marginLeft: 8 }}>직접 작성</span>}</h2>
            {draft ? (
              <>
                <textarea className="input" rows={Math.max(3, (draft[k] || "").split("\n").length + 1)} aria-label={title} placeholder={hint} value={draft[k]} onChange={(e) => setDraft({ ...draft, [k]: e.target.value })} />
                <div className="row small muted">{hint}
                  {draft[k] !== b.auto[k] && <a onClick={() => setDraft({ ...draft, [k]: b.auto[k] })}>자동 작성 문구로 되돌리기</a>}</div>
              </>
            ) : <Lines text={t[k]} />}
          </section>
        ))}
        <section>
          <h2>5. 근거 <span className="muted small">핵심 탐지 {b.top_findings.length}건 / 전체 {f.findings_total}건</span></h2>
          <div className="row wrap small">{RISKS.filter((k) => f.findings[k]).map((k) => <span key={k} className={`sev ${k}`}>{RISK_KO[k]} {f.findings[k]}</span>)}
            {!f.findings_total && <span className="muted">탐지 없음</span>}</div>
          {b.top_findings.length > 0 && (
            <table className="t rp-table"><thead><tr><th>위험도</th><th>시각 (한국 시간)</th><th>내용</th><th>성공 정황</th><th>분석가 확인</th></tr></thead>
              <tbody>{b.top_findings.map((x: any) => (
                <tr key={x.id}><td className={`sev ${x.risk_level}`}>{x.risk_ko}</td><td className="small">{x.when}</td>
                  <td><b>{x.what}</b><div className="small">{x.fact}</div></td><td>{x.success ? "있음" : "—"}</td><td>{x.reviewed ? "확인함" : "확인 전"}</td></tr>))}</tbody></table>
          )}
          <div className="small" style={{ marginTop: 6 }}>{b.check_line}</div>
        </section>
        <section>
          <h2>6. 분석한 자료</h2>
          <div>자료 {f.files}개 ({fmtBytes(f.bytes)}), 기록 {fmtNum(f.events)}건, 기간 {f.time_range_kst.filter(Boolean).join(" ~ ") || "—"} (한국 시간)</div>
          <div className="small muted">{f.sources.map((s: any) => `${s.label} ${fmtNum(s.count)}건`).join(", ")}</div>
        </section>
        {b.caveats.length > 0 && (
          <section>
            <h2>7. 이 결과를 볼 때 유의할 점</h2>
            <ul className="rp-list rp-warn">{b.caveats.map((c: string) => <li key={c}>{c}</li>)}</ul>
          </section>
        )}
        <div className="rp-foot">SAW 분석 결과를 바탕으로 한 요약이며 최종 판단은 분석 담당자가 합니다.
          {b.masked && " IP 주소 끝자리는 가려져 있습니다."}{b.edit && ` 문구 수정: ${b.edit.by} (${new Date(b.edit.at).toLocaleString("ko-KR")})`}</div>
      </article>
    </div>
  );
}
