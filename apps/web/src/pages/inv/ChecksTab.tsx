import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { QUESTIONS } from "../../components/Checks";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { ReviewPanel } from "../../components/Reviews";
import { SupportPanel } from "../../components/Support";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtNum, fmtTime } from "../../lib/format";

const TYPE_KO: Record<string, string> = { event: "기록", entity: "주소·이름", finding: "탐지", set: "검색 결과" };

/** Everything confirmed in this investigation and every review of its conclusions, in one place. */
export function ChecksTab({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const [history, setHistory] = useState(false);
  const q = useQuery({ queryKey: ["checks", inv, "all", history], queryFn: () => api.get(`/investigations/${inv}/checks?history=${history}`) });
  const s = q.data?.summary;
  const open = (c: any) => {
    if (c.target_type === "event") ctx.set({ eventId: c.target_key });
    else if (c.target_type === "finding") ctx.set({ tab: "findings", findingId: c.target_key });
    else if (c.target_type === "entity") { const [type, ...rest] = c.target_key.split(":"); ctx.set({ tab: "entity", selection: { type, value: rest.join(":") } as any }); }
  };
  return (
    <div className="col">
      <Panel title="중요한 판단의 검토">
        <div className="small muted" style={{ marginBottom: 6 }}>높은 위험 탐지를 정상·오탐으로 낮추거나 공격으로 종결하면 검토 대상이 됩니다. 일은 막지 않지만, 검토가 끝날 때까지 보고용 요약과 현황판에 표시됩니다.</div>
        <ReviewPanel inv={inv} />
      </Panel>
      <Panel title="분석 지원 (급하거나 복잡한 조사에서만)"><SupportPanel inv={inv} /></Panel>
      <Panel title="확인 기록" right={<label className="row small muted"><input type="checkbox" checked={history} onChange={(e) => setHistory(e.target.checked)} /> 변경·취소 이력 포함</label>}>
        {q.isLoading && <Loading />}
        <ErrorBox error={q.error} />
        {s && (
          <div className="row wrap small" style={{ marginBottom: 8, gap: 14 }}>
            <span>직접 확인 <b>{fmtNum(s.direct)}</b>건</span>
            {QUESTIONS.map(([k, l]) => <span key={k} className="muted">{l} {s.by_question[k]}</span>)}
            {s.sample_only > 0 && <span className="tag warn">표본만 본 확인 {s.sample_only}건</span>}
            {s.cited > 0 && <span className="tag">다른 조사 참고 {s.cited}건</span>}
            {s.source_changed > 0 && <span className="tag bad">참고한 확인이 바뀜 {s.source_changed}건</span>}
            {s.shared > 0 && <span className="tag accent">공유함 {s.shared}건</span>}
          </div>
        )}
        {q.data?.checks.length ? (
          <table className="t"><thead><tr><th>종류</th><th>대상</th><th>확인한 것</th><th>판단</th><th>범위</th><th>근거</th><th>확인자</th><th>시각</th></tr></thead>
            <tbody>{q.data.checks.map((c: any) => (
              <tr key={c.id} style={c.state !== "active" ? { opacity: 0.5 } : undefined}>
                <td className="small">{TYPE_KO[c.target_type]}{c.kind === "cited" ? " · 참고" : ""}</td>
                <td className="mono small ellipsis" style={{ maxWidth: 280 }}>{c.target_type === "set" ? c.target_label : <a onClick={() => open(c)}>{c.target_label}</a>}</td>
                <td className="small">{c.question_labels.join(" · ")}</td>
                <td>{c.judgement ? <span className={`ck ${c.judgement}`}>{c.judgement_ko}</span> : <span className="muted small">판단 없음</span>}</td>
                <td className="small">{c.coverage === "sample" ? `표본 ${fmtNum(c.checked)}/${fmtNum(c.total)}` : c.coverage === "all" && c.total != null ? `전체 ${fmtNum(c.total)}` : ""}</td>
                <td className="small ellipsis" style={{ maxWidth: 300 }} title={c.note}>{c.note}{c.state === "cancelled" ? ` (취소: ${c.state_note || "사유 없음"})` : c.state === "superseded" ? " (이전 기록)" : ""}</td>
                <td className="small">{c.author}</td><td className="small">{fmtTime(c.created_at)}</td>
              </tr>))}</tbody></table>
        ) : !q.isLoading && <span className="muted small">아직 확인 기록이 없습니다. 이벤트 상세의 "확인" 탭이나 원본 로그의 "검색 결과 확인 기록"에서 남길 수 있습니다.</span>}
      </Panel>
    </div>
  );
}
