// Explain fixed backend model errors without treating them as successful generation.
export function aiError(error: unknown): unknown {
  if (!(error instanceof Error)) return error;
  const code = error.message;
  const messages: Record<string, string> = {
    local_ai_synthetic_investigation_required: "합성 시험용으로 허용된 조사에서만 로컬 모델을 사용할 수 있습니다.",
    ai_context_authorization_changed: "참조한 지식의 승인 또는 접근 권한이 바뀌었습니다. 답변을 표시하지 않습니다.",
    ai_authorization_changed: "사용 권한이 변경되어 답변을 표시하지 않습니다.",
    model_selection_changed_output_not_published: "추론 중 모델 선택이 바뀌어 답변을 표시하지 않습니다. 현재 선택을 확인하세요.",
    cpu_wall_budget: "CPU 추론이 허용된 실행 시간을 넘겨 중지되었습니다. 입력 범위를 줄인 뒤 다시 시도하세요.",
    cpu_output_limit: "CPU 실행기의 출력 크기가 허용 한도를 넘어 중지되었습니다. 답변을 표시하지 않습니다.",
    cpu_cancelled: "CPU 추론 요청이 취소되어 답변을 표시하지 않습니다.",
    cpu_native_failed: "CPU 실행기가 정상적으로 종료되지 않았습니다. 관리자에게 실행 기록 확인을 요청하세요.",
    ai_session_changed: "로그인 세션이 만료되거나 변경되어 답변을 표시하지 않습니다. 다시 로그인하세요.",
    cpu_context_limit: "입력 크기가 CPU 모델의 한도를 넘었습니다. 선택한 탐지나 질문의 범위를 줄이세요.",
    cpu_prompt_limit: "입력 크기가 CPU 모델의 한도를 넘었습니다. 선택한 탐지나 질문의 범위를 줄이세요.",
    cpu_single_execution_busy: "다른 CPU 추론이 실행 중입니다. 완료 후 다시 요청하세요.",
    cpu_runtime_not_configured: "CPU 실행 환경이 설정되지 않았습니다. 관리자 설정을 확인하세요.",
    model_inbox_not_configured: "모델 반입 폴더가 설정되지 않았습니다. 관리자 설정을 확인하세요.",
    model_pack_not_validated: "먼저 반입한 모델 묶음을 검증 등록하세요.",
    model_file_hash_mismatch: "모델 파일의 무결성 확인에 실패했습니다. 반입한 파일과 검증 명세를 확인하세요.",
    model_file_size_mismatch: "모델 파일의 크기가 검증 명세와 다릅니다. 반입한 파일을 확인하세요.",
    model_manifest_changed_revalidate_required: "모델 검증 명세가 바뀌었습니다. 다시 검증 등록하세요.",
    active_model_changed_deactivate_before_revalidation: "선택된 모델 파일이 바뀌었습니다. 선택을 해제한 뒤 다시 검증하세요.",
    model_selection_changed_retry: "다른 관리자가 모델 선택을 변경했습니다. 목록을 새로 확인한 뒤 다시 요청하세요.",
  };
  const message = messages[code] || (/^(?:model_|foundation_|active_model_)[a-z0-9_]+$/.test(code)
    ? "모델 묶음 검증에 실패했습니다. 반입 파일과 지원 형식을 확인하세요."
    : /^cpu_[a-z0-9_]+$/.test(code) ? "CPU 추론을 완료하지 못했습니다. 실행 환경과 자원 제한을 확인하세요." : null);
  return message ? `${message} (${code})` : error;
}
