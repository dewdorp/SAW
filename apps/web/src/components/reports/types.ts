export type ReportSelection = {
    investigation_id: string;
    analysis_run_id: string;
    followup_version_ids: string[] | null;
};
export type ReportScope = {
    kind: "investigation" | "selected_followups" | "investigations";
    selections: ReportSelection[];
};
export const SHEETS = ["요약", "상세", "확인 필요", "통계", "시간 추이", "근거", "적용 기준", "범위·한계"];
export const TERMINAL = ["COMPLETED", "FAILED", "CANCELLED"];
export const eligibleRun = (r: any) => !!r && ["completed", "complete", "partial", "insufficient_data", "limited"].includes(r.status);
