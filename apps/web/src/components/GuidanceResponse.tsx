import type { Filter, TimeRange } from "../context/invContext";

export const DATA_STATES: Record<string, string> = {
  available: "자료 있음", no_match: "조회했으나 해당 기록 없음", partial: "일부 자료만 있음",
  not_collected: "미수집", query_failed: "조회 실패", forbidden: "조회 권한 없음",
  not_queried: "아직 조회하지 않음", not_applicable: "이번 범위에 해당 없음",
};
export const SOURCE_LABELS: Record<string, string> = { origin_service: "웹·WAS 처리 결과", threat_intelligence: "위협 평판", edr: "EDR", process: "프로세스", events: "이벤트", authorization: "승인된 점검", direct_compromise: "직접 침해 근거" };
export const ANSWER_STATES: Record<string, string> = { answered: "답변 기록", follow_up: "후속확인 필요", not_applicable: "이번 범위에 해당 없음" };
export type GuidanceScope = { target_type: string; target_key: string; role: string; filters: Filter[]; time: TimeRange; as_of: string | null; methodology_version: string };
export type GuidanceResponse = {
  methodology_version: string; rule_id: string; scope: GuidanceScope; title?: string;
  answer_status?: string; data_states: { source: string; state: string; reason: string }[];
  follow_up?: { target: string; due_at?: string | null; needed_data: string[]; items: string[]; priority: string };
};

export function GuidanceResponseFields({ value, onChange }: { value: GuidanceResponse; onChange: (v: GuidanceResponse) => void }) {
  const follow = value.follow_up || { target: "", due_at: null, needed_data: [], items: [], priority: "normal" };
  const updateFollow = (patch: Partial<typeof follow>) => onChange({ ...value, follow_up: { ...follow, ...patch } });
  return <div className="col" style={{ gap: 7 }}>
    <b>{value.title || `조사 안내 ${value.rule_id}`}</b>
    <div className="small muted">이 범위의 답변만 저장합니다. 자료 부족과 후속확인은 확인 완료·정상 판단을 뜻하지 않습니다.</div>
    <label className="col small">답변 상태<select className="input" aria-label="답변 상태" value={value.answer_status || "follow_up"} onChange={e => onChange({ ...value, answer_status: e.target.value })}>
      {Object.entries(ANSWER_STATES).map(([v, t]) => <option key={v} value={v}>{t}</option>)}
    </select></label>
    {!!value.data_states.length && <details><summary className="small">외부 자료 상태 기록 (분석가가 확인한 내용)</summary>
      {value.data_states.map((d, i) => <div key={d.source} className="col small" style={{ paddingTop: 6 }}>
        <label>{SOURCE_LABELS[d.source] || d.source}<select className="input" aria-label={`${d.source} 자료 상태`} value={d.state} onChange={e => onChange({ ...value, data_states: value.data_states.map((x, n) => n === i ? { ...x, state: e.target.value } : x) })}>
          {Object.entries(DATA_STATES).map(([v, t]) => <option key={v} value={v}>{t}</option>)}
        </select></label>
        <input className="input" aria-label={`${d.source} 상태 근거`} placeholder="조회 시각·권한 또는 자료 부족의 이유" value={d.reason} onChange={e => onChange({ ...value, data_states: value.data_states.map((x, n) => n === i ? { ...x, reason: e.target.value } : x) })} />
      </div>)}
    </details>}
    {(value.answer_status || "follow_up") === "follow_up" && <fieldset className="col" style={{ gap: 6, border: "1px solid var(--line)" }}>
      <legend className="small">후속확인</legend>
      <input className="input" aria-label="확인할 대상" placeholder="확인할 자산·계정 또는 담당자" value={follow.target} onChange={e => updateFollow({ target: e.target.value })} />
      <input className="input" aria-label="확인 기한" placeholder="확인 기한 (선택, ISO 시각)" value={follow.due_at || ""} onChange={e => updateFollow({ due_at: e.target.value || null })} />
      <textarea className="input" rows={2} aria-label="필요 자료" placeholder="필요 자료 (한 줄에 하나)" value={follow.needed_data.join("\n")} onChange={e => updateFollow({ needed_data: e.target.value.split("\n") })} />
      <textarea className="input" rows={2} aria-label="후속 확인 항목" placeholder="확인할 내용 (한 줄에 하나)" value={follow.items.join("\n")} onChange={e => updateFollow({ items: e.target.value.split("\n") })} />
      <label className="row small">우선순위<select className="input" value={follow.priority} onChange={e => updateFollow({ priority: e.target.value })}><option value="normal">보통</option><option value="high">높음</option><option value="low">낮음</option></select></label>
    </fieldset>}
  </div>;
}
