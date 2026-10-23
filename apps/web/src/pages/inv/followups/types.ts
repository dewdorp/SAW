export type EvidenceRef = {
    investigation_id: string;
    event_id: string;
};
export type Owner = {
    org_unit_id: string | null;
    department: string | null;
    user_id: string | null;
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
    status: string;
    reply: null | {
        note: string;
        evidence: EvidenceRef[];
        received_by?: string;
        received_at?: string;
    };
    verification: null | {
        outcome: string;
        basis: string;
        evidence: EvidenceRef[];
        verified_by?: string;
        verified_at?: string;
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
export const STATUS: Record<string, string> = { open: "확인 대기", replied: "회신 수신 · 검증 전", verified: "검증 기록됨", closed_with_limits: "한계를 남기고 종료", cancelled: "취소됨" };
export const PRIORITY: Record<string, string> = { low: "낮음", normal: "보통", high: "높음", urgent: "긴급" };
export const OUTCOME: Record<string, string> = { confirmed: "확인됨", not_confirmed: "확인되지 않음", insufficient_data: "자료 부족" };
