import type { Choices, Owner, EvidenceRef, FollowUpPayload } from "./types";
export type Draft = {
    question: string;
    reason: string;
    needed: string;
    items: string;
    priority: string;
    owner: Owner;
    due: string;
};
export const blankDraft = (): Draft => ({ question: "", reason: "", needed: "", items: "", priority: "normal", owner: { org_unit_id: null, department: null, user_id: null }, due: "" });
export const fromPayload = (p: FollowUpPayload): Draft => ({ question: p.question, reason: p.reason, needed: p.needed_data.join("\n"), items: p.items.join("\n"), priority: p.priority, owner: { ...p.owner }, due: p.due_at || "" });
const lines = (value: string) => value.split("\n").filter(line => line.trim().length > 0);
export function draftBody(d: Draft) { if (!d.question.trim() || !d.reason.trim())
    throw new Error("확인할 질문과 필요한 이유를 입력하세요."); let due_at = null; if (d.due) {
    if (!/(Z|[+-]\d{2}:\d{2})$/i.test(d.due))
        throw new Error("기한에 시간대를 포함하세요. 예: +09:00");
    const date = new Date(d.due);
    if (Number.isNaN(date.getTime()))
        throw new Error("기한을 시간대가 있는 날짜·시각으로 입력하세요.");
    due_at = date.toISOString();
} return { question: d.question, reason: d.reason, needed_data: lines(d.needed), items: lines(d.items), priority: d.priority, owner: d.owner, due_at }; }
export function FollowUpFields({ draft: d, onChange: set, choices }: {
    draft: Draft;
    onChange: (d: Draft) => void;
    choices?: Choices;
}) { const change = (key: keyof Draft, value: any) => set({ ...d, [key]: value }); const owner = (key: keyof Owner, value: string) => change("owner", { ...d.owner, [key]: value || null }); return <div className="col" style={{ gap: 8 }}><label>확인할 질문<textarea className="input" maxLength={1000} value={d.question} onChange={e => change("question", e.target.value)}/></label><label>필요한 이유<textarea className="input" maxLength={8000} value={d.reason} onChange={e => change("reason", e.target.value)}/></label><label>필요 자료 (한 줄에 하나)<textarea className="input" value={d.needed} onChange={e => change("needed", e.target.value)}/></label><label>확인 항목 (한 줄에 하나)<textarea className="input" value={d.items} onChange={e => change("items", e.target.value)}/></label><label>우선순위<select className="input" value={d.priority} onChange={e => change("priority", e.target.value)}>{Object.entries({ low: "낮음", normal: "보통", high: "높음", urgent: "긴급" }).map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label><div className="row wrap"><label>책임 관계사<select className="input" value={d.owner.org_unit_id || ""} onChange={e => owner("org_unit_id", e.target.value)}><option value="">미지정</option>{choices?.org_units.map(o => <option key={o.id} value={o.id}>{o.label} · {o.id}</option>)}{d.owner.org_unit_id && !choices?.org_units.some(o => o.id === d.owner.org_unit_id) && <option value={d.owner.org_unit_id}>{d.owner.org_unit_id} (현재 지정값)</option>}</select></label><label>담당 부서 (설명)<input className="input" maxLength={128} value={d.owner.department || ""} onChange={e => owner("department", e.target.value)}/></label><label>담당자<select className="input" value={d.owner.user_id || ""} onChange={e => owner("user_id", e.target.value)}><option value="">미지정</option>{choices?.users.map(o => <option key={o.id} value={o.id}>{o.label} · {o.id}</option>)}{d.owner.user_id && !choices?.users.some(o => o.id === d.owner.user_id) && <option value={d.owner.user_id}>{d.owner.user_id} (현재 지정값)</option>}</select></label></div><p className="small muted">책임 관계사는 관측 대상·장비 소유 관계사와 다를 수 있습니다. 부서는 설명이며 담당 지정으로 접근 권한을 부여하지 않습니다.</p><label>기한 (시간대 포함, 비우면 기한 없음)<input className="input" placeholder="2026-10-25T18:00:00+09:00" value={d.due} onChange={e => change("due", e.target.value)}/></label></div>; }
export function EvidenceFields({ value, onChange, inv }: {
    value: EvidenceRef[];
    onChange: (value: EvidenceRef[]) => void;
    inv: string;
}) { return <div className="col"><span>근거 원문 참조 (최대 200개)</span>{value.map((r, i) => <div className="row wrap" key={i}><label>근거 조사 ID {i + 1}<input className="input" value={r.investigation_id} onChange={e => onChange(value.map((x, j) => j === i ? { ...x, investigation_id: e.target.value } : x))}/></label><label>근거 이벤트 ID {i + 1}<input className="input" value={r.event_id} onChange={e => onChange(value.map((x, j) => j === i ? { ...x, event_id: e.target.value } : x))}/></label><button className="btn sm" onClick={() => onChange(value.filter((_, j) => j !== i))}>참조 {i + 1} 제거</button></div>)}<button className="btn sm" disabled={value.length >= 200} onClick={() => onChange([...value, { investigation_id: inv, event_id: "" }])}>근거 참조 추가</button></div>; }
