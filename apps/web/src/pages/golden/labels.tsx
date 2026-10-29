import type { Eligibility } from "./types";
export const SPLITS: Record<string, string> = { train: "학습용", dev: "개발평가용", holdout: "비공개 평가용" };
export const STATES: Record<string, string> = { draft: "채택 초안", adopted: "채택됨", declined: "반려됨", withdrawn: "철회됨", building: "파일 생성 중", awaiting_review: "반출 승인 대기", approved: "반출 승인됨", revoked: "반출 철회됨", expired: "만료됨", ineligible: "사용 요건 미충족" };
export const REASONS: Record<string,string> = {
 // Public DTO limits describe constraints without marking profile saves or file builds as failed.
 profile_is_not_export_authorization:"프로필은 변환 규칙을 정의합니다. 반출 승인은 패키지별로 별도로 필요합니다.",
 representative_input:"대표 근거가 포함된 해석용 자료입니다. 전체 범위 재계산에는 별도 검증이 필요합니다.",
 analysis_version_not_captured:"이 입력에는 분석 실행의 정확한 버전이 고정되어 있지 않습니다.",
 matching_policy_not_captured:"탐지 정답의 일치 판정 정책이 이 버전에 기록되어 있지 않습니다.",
 bounded_plain_text_preview:"미리보기는 크기가 제한된 텍스트 표본입니다. 생략된 파일과 바이트 수를 함께 확인하세요.",
 pseudonymization_is_not_anonymization:"가명처리 후에도 재식별 가능성이 있어 익명화를 보장하지 않습니다.",
 target_identity_operator_declared:"대상 이름·버전·파일 해시는 사용자가 기재한 값이며 실제 대상 파일의 검증 결과는 아닙니다.",
 operator_report_is_not_model_execution:"결과는 사용자가 별도 환경에서 실행한 내용의 보고입니다. SAW의 모델 실행·품질 평가를 뜻하지 않습니다.",
 unapproved_free_text_omitted:"반출이 승인되지 않은 자유 입력 문구는 제외됩니다.",
 source_metadata_kept_private:"원천 메타데이터는 내부에 보관하며 반출 파일에 포함하지 않습니다.",
 original_source_metadata_kept_private:"원본의 원천 메타데이터는 내부에 보관하며 반출 파일에 포함하지 않습니다.",
 legacy_context_not_provided:"v1 호환 출력에는 새 형식의 문맥 정보가 제공되지 않습니다.",
 source_revision_history_kept_private:"원천 자료의 변경 이력은 내부에 보관하며 반출 파일에 포함하지 않습니다.",
 // Server action requirements describe compound conditions without guessing which condition failed.
 golden_preview_permission_required:"실제 파일 미리보기는 이 버전의 작성자 또는 반출 검토 권한이 있는 사용자에게 제공됩니다.",
 golden_independent_preview_approval_required:"승인하려면 반출 요건을 충족한 현재 버전과 미리보기를 확인한 독립 검토자가 필요합니다.",
 golden_independent_decline_required:"반려는 반출 검토 권한이 있는 독립 검토자가 만료·철회되지 않은 현재 버전에서 진행합니다.",
 golden_active_release_approval_required:"내려받으려면 반출 권한과 유효한 독립 승인이 필요합니다.",
 golden_approved_release_required:"철회하려면 반출 검토 권한과 현재 승인 결정이 필요합니다.",
 golden_release_build_pending_or_permission:"새 버전은 반출 작성 권한이 있고 진행 중인 파일 생성 작업이 없을 때 요청할 수 있습니다.",
 golden_build_pending:"파일 생성 중입니다. 생성이 완료되면 반출 버전에서 다음 작업을 확인하세요.",
 golden_holdout_input_unavailable:"입력은 이 평가 시도의 작성자가 유효한 반출 승인과 반복 평가 요건을 충족할 때 내려받을 수 있습니다.",
 golden_holdout_result_unavailable:"결과는 이 평가 시도의 작성자가 입력을 받은 뒤 정답 열람 전에 한 번 등록할 수 있습니다.",
 golden_holdout_result_and_evaluator_required:"정답 열람에는 결과 등록과 내부 평가자 권한이 필요합니다.",
 golden_release_ineligible:"반출 가능한 채택 사례와 반출 작성 권한이 필요합니다.",
 golden_holdout_attempt_required:"비공개 평가 시도에 입력 사용과 결과를 기록한 뒤 내부 평가자 경로에서 정답을 확인하세요.",
 golden_evaluator_permission_required:"정답을 열람하려면 내부 평가자 권한이 필요합니다.",
 golden_job_manage_required:"파일 생성 취소와 재시도에는 이 작업을 관리할 권한이 필요합니다.",
 independent_reviewer_required:"작성자·편집자와 다른 검토자가 필요합니다.", permission_denied:"이 작업의 권한이 없습니다.",
 preview_required:"이 정확한 파일의 미리보기를 먼저 확인하세요.", preview_not_reviewed:"이 정확한 파일의 미리보기를 먼저 확인하세요.",
 release_changed:"현재 버전이 변경되었습니다. 입력을 유지했으며 최신 상태를 다시 확인해야 합니다.",
 source_changed:"원천 자료가 변경되었습니다.", release_expired:"반출 유효 기간이 지났습니다.", release_revoked:"반출 승인이 철회되었습니다.",
 approval_required:"독립 반출 승인이 필요합니다.", historical_version:"과거 버전은 새 승인 대상이 아닙니다.",
 holdout_attempt_required:"비공개 평가 시도를 먼저 등록하세요.", result_required:"직접 실행한 결과를 먼저 등록하세요.",
 holdout_repeat_requires_new_evaluation_policy:"같은 사건군과 대상 파일을 이미 평가했습니다. 이름 변경으로 새 평가를 만들 수 없습니다.",
 legacy_context_not_captured:"이전 형식에는 정확한 장비·실행 문맥이 없습니다.", representative_only:"대표 근거의 해석 용도입니다.",
 operator_declared:"사용자 기재값 · 파일 직접 검증 전", unsupported_engine:"전체 재계산을 지원하지 않는 탐지입니다.",
 full_recalculation_requires_complete_run:"완료된 단일 FW 실행이 필요합니다. 일부 처리된 다중 분석은 사용할 수 없습니다."
};
export function Reasons({ value }: { value?: Eligibility | string[] }) {
 const codes = Array.isArray(value) ? value : value?.reasons || [];
 return <>{codes.map((code,i) => <div className="small muted" key={i}>{REASONS[code] || "현재 조건에서 작업할 수 없습니다."}</div>)}</>;
}
export function Applicability({ value, validation }: {value?: any; validation?: any}) {
 const full = value?.mode === "full_recalculation";
 return <div className="col small"><span className="tag">{full ? "전체 재계산 검증 자료" : "대표 근거 해석용"}</span>
 {full && validation?.state !== "passed" && validation && <span>전체 재계산 검증 통과가 확인되지 않았습니다.</span>}
 {!full && <span>대표 자료만으로 전체 자료의 탐지 재현이나 모델 품질을 보장하지 않습니다.</span>}<Reasons value={value?.reasons}/><Reasons value={validation?.reasons}/></div>;
}
