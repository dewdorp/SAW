import type { Choices, Owner, EvidenceRef, FollowUpPayload } from "./types";
import { fmtPeriod, getTz } from "../../../lib/format";
export type Connection = { src_ip: string | null; dst_ip: string | null; dst_port: number | null };
export type Draft = {
    question: string;
    reason: string;
    needed: string;
    items: string;
    priority: string;
    owner: Owner;
    due: string;
    src: string;
    dst: string;
    ports: string;
    behavior: string;
    start: string;
    end: string;
    /** Exact source→destination:port connections of the activity; dropped once the analyst edits the addresses. */
    connections?: Connection[];
};
export type ScopeDraft = { src: string; dst: string; ports: string; start: string; end: string; org: string };
export const blankDraft = (): Draft => ({ question: "", reason: "", needed: "", items: "", priority: "normal", owner: { org_unit_id: null, department: null, user_id: null }, due: "",
    src: "", dst: "", ports: "", behavior: "", start: "", end: "" });
export const blankScope = (): ScopeDraft => ({ src: "", dst: "", ports: "", start: "", end: "", org: "" });
export const fromPayload = (p: FollowUpPayload): Draft => ({ question: p.question, reason: p.reason, needed: p.needed_data.join("\n"), items: p.items.join("\n"), priority: p.priority, owner: { ...p.owner }, due: p.due_at || "",
    src: (p.target?.src_ips || []).join(", "), dst: (p.target?.dst_ips || []).join(", "), ports: (p.target?.dst_ports || []).join(", "),
    behavior: p.target?.behavior || "", start: p.period?.start || "", end: p.period?.end || "" });
const lines = (value: string) => value.split("\n").filter(line => line.trim().length > 0);
const list = (value: string) => value.split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
function ports(value: string) {
    const out = list(value).map(Number);
    if (out.some(p => !Number.isInteger(p) || p < 0 || p > 65535))
        throw new Error("포트는 0~65535 숫자로 입력하세요.");
    return out;
}
function instant(value: string, label: string) {
    if (!value.trim())
        return null;
    if (!/(Z|[+-]\d{2}:\d{2})$/i.test(value.trim()))
        throw new Error(`${label}에 시간대를 포함하세요. 예: 2026-10-13T10:00:00+09:00`);
    const date = new Date(value.trim());
    if (Number.isNaN(date.getTime()))
        throw new Error(`${label}을 시간대가 있는 날짜·시각으로 입력하세요.`);
    return date.toISOString();
}
export function draftBody(d: Draft) {
    if (!d.question.trim() || !d.reason.trim())
        throw new Error("확인할 질문과 필요한 이유를 입력하세요.");
    const due_at = instant(d.due, "기한");
    const start = instant(d.start, "확인 대상 시작"), end = instant(d.end, "확인 대상 끝");
    if ((start === null) !== (end === null))
        throw new Error("확인 대상 기간은 시작과 끝을 함께 입력하세요.");
    const hasTarget = d.src.trim() || d.dst.trim() || d.ports.trim() || d.behavior.trim();
    return { question: d.question, reason: d.reason, needed_data: lines(d.needed), items: lines(d.items), priority: d.priority, owner: d.owner, due_at,
        target: hasTarget ? { src_ips: list(d.src), dst_ips: list(d.dst), dst_ports: ports(d.ports), behavior: d.behavior.trim() || null, connections: d.connections || [] } : null,
        period: start && end ? { start, end } : null };
}
export function replyScopeBody(s: ScopeDraft) {
    const start = instant(s.start, "회신 범위 시작"), end = instant(s.end, "회신 범위 끝");
    if (!s.src.trim() && !s.dst.trim() && !s.ports.trim() && !start && !end && !s.org)
        return null;
    return { org_unit_id: s.org || null, src_ips: list(s.src), dst_ips: list(s.dst), dst_ports: ports(s.ports), start, end };
}
/** One line for the whole target, with the full connection list folded; a kept sample is never called the whole group. */
export function TargetSummary({ summary: s, connections }: { summary?: any; connections?: Connection[] }) {
    if (!s)
        return null;
    const ports: number[] = s.ports || [];
    const portText = s.port_count ? (s.port_count <= 3 ? `포트 ${ports.join("·")}` : `포트 ${s.port_count}개`) : "포트 미기록";
    const span = s.start && s.end ? ` · ${fmtPeriod(s.start, s.end)} (${getTz()})` : "";
    const basis = s.basis === "whole_group"
        ? (s.complete ? `계산한 그룹 전체: 기록 ${Number(s.records || 0).toLocaleString()}건 · 연결 ${s.connections}개`
            : `연결이 많아 처음 ${s.connections}개만 담았습니다. 그룹 전체가 아닙니다.`)
        : `근거로 남긴 표본 기록 ${s.records}건 기준입니다. 그룹 전체가 아닙니다.`;
    return <div className="col" style={{ gap: 4 }} aria-label="확인 대상 요약">
        <b>출발지 {s.sources}개 → 목적지 {s.destinations}개 · {portText}{span}</b>
        <span className="small muted">{basis}</span>
        {connections?.length ? <details><summary>요청할 연결 {connections.length}개 펼치기</summary>
            <ul className="small mono">{connections.map((c, i) => <li key={i}>{c.src_ip || "출발지 미기록"} → {c.dst_ip || "목적지 미기록"}:{c.dst_port ?? "포트 미기록"}</li>)}</ul></details>
            : <span className="small muted">개별 연결 목록 없음: 회신은 주소·포트 목록으로만 비교합니다.</span>}
    </div>;
}
/** What the request is about. A reply is compared with exactly this before it can explain the activity. */
function TargetFields({ d, change }: { d: Draft; change: (key: keyof Draft, value: any) => void }) {
    return <fieldset className="col" style={{ gap: 6 }}><legend><b>확인 대상과 기간</b> <span className="small muted">회신이 이 범위를 다루는지 자동으로 비교합니다.</span></legend>
        <div className="row wrap"><label>출발지 IP (쉼표로 구분)<input className="input" value={d.src} onChange={e => change("src", e.target.value)} /></label>
            <label>목적지 IP<input className="input" value={d.dst} onChange={e => change("dst", e.target.value)} /></label>
            <label>목적지 포트<input className="input" value={d.ports} onChange={e => change("ports", e.target.value)} /></label></div>
        <label>확인할 행위<input className="input" maxLength={1000} placeholder="예: 10:00~10:05 사이 /admin 경로 대량 404 요청" value={d.behavior} onChange={e => change("behavior", e.target.value)} /></label>
        <div className="row wrap"><label>대상 기간 시작<input className="input" placeholder="2026-10-13T10:00:00+09:00" value={d.start} onChange={e => change("start", e.target.value)} /></label>
            <label>대상 기간 끝<input className="input" placeholder="2026-10-13T10:05:00+09:00" value={d.end} onChange={e => change("end", e.target.value)} /></label></div>
        <p className="small muted">비워 두면 조사의 관계사·조사 기간으로 비교합니다. 대상을 구체적으로 적을수록 다른 작업에 대한 회신으로 의심 행위를 정상 처리하는 일을 막을 수 있습니다.</p>
    </fieldset>;
}
export function ReplyScopeFields({ value: s, onChange, choices }: { value: ScopeDraft; onChange: (s: ScopeDraft) => void; choices?: Choices }) {
    const set = (key: keyof ScopeDraft, v: string) => onChange({ ...s, [key]: v });
    return <fieldset className="col" style={{ gap: 6 }}><legend><b>회신이 다루는 범위</b> <span className="small muted">작업 기록·답변에 실제로 적힌 관계사·주소·포트·시간</span></legend>
        <div className="row wrap"><label>관계사<select className="input" value={s.org} onChange={e => set("org", e.target.value)}><option value="">미기재</option>{choices?.org_units.map(o => <option key={o.id} value={o.id}>{o.label}</option>)}</select></label>
            <label>출발지 IP<input className="input" value={s.src} onChange={e => set("src", e.target.value)} /></label>
            <label>목적지 IP<input className="input" value={s.dst} onChange={e => set("dst", e.target.value)} /></label>
            <label>포트<input className="input" value={s.ports} onChange={e => set("ports", e.target.value)} /></label></div>
        <div className="row wrap"><label>작업 시작<input className="input" placeholder="2026-10-13T09:59:00+09:00" value={s.start} onChange={e => set("start", e.target.value)} /></label>
            <label>작업 끝<input className="input" placeholder="2026-10-13T10:06:00+09:00" value={s.end} onChange={e => set("end", e.target.value)} /></label></div>
        <p className="small muted">기간이나 대상이 다른 회신, 범위가 적혀 있지 않은 회신은 '확인됨'으로 검증할 수 없습니다. 일부만 다루면 남은 부분은 계속 확인 대상으로 남습니다.</p>
    </fieldset>;
}
export function FollowUpFields({ draft: d, onChange: set, choices }: {
    draft: Draft;
    onChange: (d: Draft) => void;
    choices?: Choices;
}) { const change = (key: keyof Draft, value: any) => set({ ...d, [key]: value }); const owner = (key: keyof Owner, value: string) => change("owner", { ...d.owner, [key]: value || null }); return <div className="col" style={{ gap: 8 }}><label>확인할 질문<textarea className="input" maxLength={1000} value={d.question} onChange={e => change("question", e.target.value)}/></label><label>필요한 이유<textarea className="input" maxLength={8000} value={d.reason} onChange={e => change("reason", e.target.value)}/></label><TargetFields d={d} change={change}/><label>필요 자료 (한 줄에 하나)<textarea className="input" value={d.needed} onChange={e => change("needed", e.target.value)}/></label><label>확인 항목 (한 줄에 하나)<textarea className="input" value={d.items} onChange={e => change("items", e.target.value)}/></label><label>우선순위<select className="input" value={d.priority} onChange={e => change("priority", e.target.value)}>{Object.entries({ low: "낮음", normal: "보통", high: "높음", urgent: "긴급" }).map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label><div className="row wrap"><label>책임 관계사<select className="input" value={d.owner.org_unit_id || ""} onChange={e => owner("org_unit_id", e.target.value)}><option value="">미지정</option>{choices?.org_units.map(o => <option key={o.id} value={o.id}>{o.label} · {o.id}</option>)}{d.owner.org_unit_id && !choices?.org_units.some(o => o.id === d.owner.org_unit_id) && <option value={d.owner.org_unit_id}>{d.owner.org_unit_id} (현재 지정값)</option>}</select></label><label>담당 부서 (설명)<input className="input" maxLength={128} value={d.owner.department || ""} onChange={e => owner("department", e.target.value)}/></label><label>담당자<select className="input" value={d.owner.user_id || ""} onChange={e => owner("user_id", e.target.value)}><option value="">미지정</option>{choices?.users.map(o => <option key={o.id} value={o.id}>{o.label} · {o.id}</option>)}{d.owner.user_id && !choices?.users.some(o => o.id === d.owner.user_id) && <option value={d.owner.user_id}>{d.owner.user_id} (현재 지정값)</option>}</select></label></div><p className="small muted">책임 관계사는 관측 대상·장비 소유 관계사와 다를 수 있습니다. 부서는 설명이며 담당 지정으로 접근 권한을 부여하지 않습니다. 확인 요청은 플랫폼 안에서만 관리하며 이메일·메신저를 보내지 않습니다.</p><label>기한 (시간대 포함, 비우면 기한 없음)<input className="input" placeholder="2026-10-25T18:00:00+09:00" value={d.due} onChange={e => change("due", e.target.value)}/></label></div>; }
export function EvidenceFields({ value, onChange, inv }: {
    value: EvidenceRef[];
    onChange: (value: EvidenceRef[]) => void;
    inv: string;
}) { return <div className="col"><span>근거 원문 참조 (최대 200개)</span>{value.map((r, i) => <div className="row wrap" key={i}><label>근거 조사 ID {i + 1}<input className="input" value={r.investigation_id} onChange={e => onChange(value.map((x, j) => j === i ? { ...x, investigation_id: e.target.value } : x))}/></label><label>근거 이벤트 ID {i + 1}<input className="input" value={r.event_id} onChange={e => onChange(value.map((x, j) => j === i ? { ...x, event_id: e.target.value } : x))}/></label><button className="btn sm" onClick={() => onChange(value.filter((_, j) => j !== i))}>참조 {i + 1} 제거</button></div>)}<button className="btn sm" disabled={value.length >= 200} onClick={() => onChange([...value, { investigation_id: inv, event_id: "" }])}>근거 참조 추가</button></div>; }
