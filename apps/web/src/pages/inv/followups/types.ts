export type EvidenceRef = {
    investigation_id: string;
    event_id: string;
};
export type Owner = {
    org_unit_id: string | null;
    department: string | null;
    user_id: string | null;
};
export type Target = {
    org_unit_id?: string | null;
    src_ips: string[];
    dst_ips: string[];
    dst_ports: number[];
    behavior?: string | null;
};
export type ReplyScope = {
    org_unit_id?: string | null;
    src_ips: string[];
    dst_ips: string[];
    dst_ports: number[];
    start?: string | null;
    end?: string | null;
};
export type ScopeCheck = {
    result: "matches" | "partial" | "mismatch" | "not_stated" | "no_request_scope";
    summary: string;
    uncovered: string[];
    components: Record<string, { status: string; detail: string }>;
};
export type FollowUpPayload = {
    schema: string;
    check_ref: {
        check_id: string;
        revision_id: string;
        revision: number;
        payload_sha256: string;
    };
    question: string;
    reason: string;
    needed_data: string[];
    items: string[];
    priority: string;
    owner: Owner;
    due_at: string | null;
    target?: Target | null;
    period?: { start: string; end: string } | null;
    status: string;
    reply: null | {
        note: string;
        evidence: EvidenceRef[];
        received_by?: string;
        received_at?: string;
        scope?: ReplyScope | null;
        scope_check?: ScopeCheck;
    };
    verification: null | {
        outcome: string;
        basis: string;
        evidence: EvidenceRef[];
        verified_by?: string;
        verified_at?: string;
        scope_check?: ScopeCheck;
        remaining_questions?: string[];
    };
    disposition: null | {
        reason: string;
        by: string;
        at: string;
    };
    origin: {
        kind: string;
        check_id: string;
    };
};
export type FollowUpVersion = {
    id: string;
    revision: number;
    payload_sha256: string;
    payload: FollowUpPayload;
    created_by?: string;
    created_at?: string;
    action: string;
};
export type FollowUp = {
    id: string;
    investigation_id: string;
    current: FollowUpVersion;
    overdue: boolean;
    eligibility: {
        edit: boolean;
        reply: boolean;
        verify: boolean;
        close_with_limits: boolean;
        cancel: boolean;
        reopen: boolean;
        reasons: Record<string, string[]>;
    };
};
export type Choices = {
    org_units: {
        id: string;
        label: string;
    }[];
    users: {
        id: string;
        label: string;
    }[];
    department_kind: "descriptive_text";
};
export const STATUS: Record<string, string> = { open: "요청 등록 · 회신 대기", replied: "회신 수신 · 검증 전", verified: "검증 완료", closed_with_limits: "한계를 남기고 종료", cancelled: "취소됨" };
export const PRIORITY: Record<string, string> = { low: "낮음", normal: "보통", high: "높음", urgent: "긴급" };
export const OUTCOME: Record<string, string> = { confirmed: "확인됨", partially_confirmed: "일부만 확인됨(남은 의문 있음)", not_confirmed: "확인되지 않음", insufficient_data: "자료 부족" };
export const SCOPE_RESULT: Record<string, string> = { matches: "범위 일치", partial: "일부만 설명", mismatch: "범위 불일치", not_stated: "범위 미기재", no_request_scope: "비교할 요청 범위 없음" };
