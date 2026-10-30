import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtNum, fmtTime } from "../../lib/format";

const STATUS: Record<string, [string, string]> = {
  found: ["확인할 근거 있음", "warn"], looked_none: ["이 기준에서는 보이지 않음 (정상 판정 아님)", ""],
  insufficient_data: ["자료 부족 — 판단 불가", "warn"], failed: ["계산 실패", "warn"],
};

/** The four investigation questions, computed from the logs; each item leads to its logs and to a check. */
export function QuestionBundles({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const qc = useQueryClient();
  const [sensitivity, setSensitivity] = useState("normal");
  const q = useQuery<any>({ queryKey: ["question-bundles", inv, sensitivity],
    queryFn: () => api.get(`/investigations/${inv}/question-bundles?sensitivity=${sensitivity}`) });
  const record = useMutation({
    // A check on the item's own records: the follow-up drafted from it is filled from those records.
    mutationFn: async (item: any) => {
      const page = await api.post<any>(`/investigations/${inv}/query/events`, { filters: item.filters, limit: 50 });
      return api.post(`/investigations/${inv}/checks`, { target_type: "set", target_label: item.title.slice(0, 500), questions: ["nature"],
        note: `${item.observed} 확인 필요: ${item.next_questions[0] || ""}`.slice(0, 2000),
        evidence: (page.events || []).slice(0, 20).map((e: any) => e.event_id),
        // Everything loaded is "all"; otherwise the 20 kept records are a sample of what was loaded.
        scope: (page.events || []).length >= item.records
          ? { coverage: "all", query: { filters: item.filters }, loaded: (page.events || []).length, event_ids: (page.events || []).slice(0, 20).map((e: any) => e.event_id) }
          : { coverage: "sample", query: { filters: item.filters }, checked: Math.min(20, (page.events || []).length),
            loaded: (page.events || []).length, event_ids: (page.events || []).slice(0, 20).map((e: any) => e.event_id) } });
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["checks", inv] }); ctx.set({ tab: "checks" }); },
  });
  if (q.isLoading) return <Loading label="확인할 질문 계산 중" />;
  return (
    <Panel title="확인할 질문 — 로그에서 바로 계산 (정책·규칙 작성 없이)"
      right={<label className="small row" style={{ gap: 4 }}>민감도<select className="input" aria-label="질문 민감도" value={sensitivity} onChange={(e) => setSensitivity(e.target.value)}>
        <option value="low">낮음</option><option value="normal">보통</option><option value="high">높음</option></select></label>}>
      <ErrorBox error={q.error || record.error} />
      {q.data && <div className="small muted">{q.data.note} 기준: 경로 {q.data.thresholds.paths}개 · 전송 {fmtNum(Math.round(q.data.thresholds.bytes / 1048576))}MB · 반복 {q.data.thresholds.periodic_min}회 · 대상 {q.data.thresholds.targets}개/포트 {q.data.thresholds.ports}개 ({q.data.version})</div>}
      {(q.data?.bundles || []).map((b: any) => (
        <section key={b.id} aria-label={b.title} className="col" style={{ gap: 6, marginTop: 10 }}>
          <div className="row" style={{ gap: 8 }}><b className="grow">{b.title}</b>
            <span className={`tag ${STATUS[b.status]?.[1] || ""}`}>{STATUS[b.status]?.[0] || b.status}</span></div>
          {b.status === "insufficient_data" && <div className="small muted">필요한 자료: {(b.missing || []).join(", ")}. 이 질문 말고 다른 분석은 계속됩니다.</div>}
          {b.note && <div className="small muted">{b.note}</div>}
          {(b.items || []).map((it: any, i: number) => (
            <article key={i} className="panel pb col" style={{ gap: 4 }}>
              <b>{it.title}</b>
              <div className="small"><b>관측된 근거</b> {it.observed} (관련 기록 {fmtNum(it.records)}건{it.time?.start ? ` · ${fmtTime(it.time.start)} ~ ${fmtTime(it.time.end)}` : ""})</div>
              <div className="small"><b>아직 알 수 없는 것</b> {(it.unknown || []).join(" · ")}</div>
              <div className="small"><b>정상 가능성</b> {(it.normal_possibilities || []).join(" · ")}</div>
              <div className="small"><b>다음 확인</b> {(it.next_questions || []).join(" / ")}</div>
              <div className="row wrap" style={{ gap: 6 }}>
                <button className="btn sm" onClick={() => ctx.set({ tab: "raw", filters: it.filters, time: null, selection: null })}>관련 로그 보기</button>
                <button className="btn sm" disabled={record.isPending} onClick={() => record.mutate(it)}>확인 기록으로 남기고 확인 요청 작성</button>
              </div>
            </article>
          ))}
        </section>
      ))}
    </Panel>
  );
}
