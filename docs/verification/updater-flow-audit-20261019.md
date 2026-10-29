# 업데이트 전체 흐름 감사 — 2026-10-19

## 최종 결과 — 후보 7과 동결된 생산 코드

전체 서버 r3는 **1,733 PASS / 6 SKIP / 기존 경고 2건 / 1,305.21초 / exit 0**다. 후보 7 실제 합성 순서는 시작 69.47초, 점검 39.36초, 적용 492.39초, 복구 497.54초에 모두 통과했다. 복구 ACL 32,701개·9행 PASS·health 완료를 공개 영수증으로 확인했다. 점검 전후·적용 후·복구 후 자료와 계정·암호 해시·역할·MFA·설정·키·TLS·원본 동일성 및 같은 합성 계정·암호·MFA/TLS 로그인이 통과했다.

복구 후 계정 2·이벤트 9·Finding 10·증거 2·노트 1·완료 작업 2, schema 0014를 확인했다. 적용 후 새로 추가한 50바이트 객체는 보관 설치에 있고 복구된 snapshot에는 없었다. 시험 계정 비활성화·세션 폐기와 최종 정상 중지 28.56초, 세 시험 포트 닫힘·PG PID 파일 부재도 통과했다. native 순서 세션 75049는 exit 0으로 끝났다.

후보 6 첫 복구 실패의 정확한 원인은 여전히 미확정이며 이를 후보 7 성공으로 소급 변경하지 않는다. 아래의 진행 중·미확정 문구는 각 기록 당시 상태이며 최신 결과는 이 절이다. Windows 11/PS5.1/NoAdmin/실제 WinForms 버튼 이벤트의 합성 검증으로 한정하며 목표 LTSC 관리자 서비스·HTTPS 443·재부팅·조직 운영 인수는 별도다. 최종 배포 ZIP 봉인·게시 결과는 소스 커밋 이후 별도 배포 기록으로 남긴다.


## 범위와 판정 기준

사용자 요청의 24단계와 문제 A–E를 현재 코드의 실제 분기에 연결했다. 기준 main은 **723e2a677dfc19e2079acbc0c6b604518a8c76aa**, 작업 브랜치는 **codex/updater-stabilization-20261019**다. 이 문서는 해당 브랜치 소스의 감사이며 최종 매체의 시험·배포 완료 증명서가 아니다.

운영 대상은 **Windows 10 Enterprise LTSC 2019 x64, build 17763, Windows PowerShell 5.1, 폐쇄망, HTTPS 443**이다. 개발 PC build 26200의 native API 시험과 합성 fixtures는 대상 OS의 실측 인수를 대신하지 않는다. 운영 C:\SAW, D:\SAW-0.1.0의 서비스·레지스트리·설치를 이 감사에서 변경하지 않았다.

테스트 경로는 개발 저장소 기준이며 오프라인 매체에 포함되지 않으므로 일반 코드 경로로 표시한다. 아래 테스트는 구현을 검증하는 회귀의 위치다. 테스트 존재와 최종 커밋·최종 ZIP에서의 통과는 구분한다. 최종 전체 시험 수, 새 ZIP 해시, 실제 저장소 데이터 보존 및 LTSC 인수 결과는 실행 담당자의 최종 증거에 기록한다.

## A–E 원인과 통합 결정

| 요청 | 기존 원인·동작 | 통합된 동작과 영향 범위 | 회귀 위치 |
|---|---|---|---|
| A. 매체 검증 | 상위 오류 하나로 소스 ZIP, 누락, 손상을 구분하기 어려움 | PS verifier와 Python manifest 검증이 소스 ZIP, manifest 없음·형식 오류, 필수 payload 목록 누락, 실제 파일 누락, 해시 불일치, 추가 파일을 구분한다. 신뢰한 진입점의 verifier가 선택 매체의 Python/controller 실행보다 먼저 동작한다. 파일 목록·해시·핀 검증 유지. | `tests/unit/test_update_diagnostics.py`: test_media_errors_are_distinct_and_safe, test_native_ps_and_python_media_agree; `tests/unit/test_update_worker.py`: 변조 매체 실행 금지 |
| B. 상태 소유권 | 관리자 토큰 기본 owner가 Administrators이면 상태 파일이 private 정책과 충돌 | PR #1의 생성 시점 owner·protected DACL 지정을 통합했다. worker의 New-PrivateWorkerFile, backend의 _private_file_fd/_private_directory를 재사용하여 상태·잠금·진단·복구 메타데이터에 같은 정책을 적용한다. flush·원자 교체 유지. 운영 ACL 수리 또는 임시 소유권 도구에 의존하지 않는다. | `tests/unit/test_private_update_state.py`, `tests/unit/test_update_state_handoff.py`, `tests/unit/test_update_acl_policy.py` |
| C. ACL | OWNER RIGHTS를 실제 owner와 분리해 외부 주체처럼 거절 | OWNER RIGHTS를 실제 owner로 해석한 뒤 신뢰 owner와 NetworkService 경로별 마스크를 평가한다. protected DACL·deny ACE를 다루고 Users/Authenticated Users의 위험한 allow, 신뢰하지 않는 owner, 서비스 최소 범위 밖 권한을 계속 거절한다. 전수 읽기 진단을 집계하고 복사 시 OWNER RIGHTS 의미 변경도 사전 검사한다. 검사에 ACL 수리 기능을 추가하지 않았다. | `tests/unit/test_update_acl_policy.py`, `tests/unit/test_offline_update.py`: service scope·ACL 복사·untrusted snapshot |
| D. 구형 설치 기준 | manifest가 없을 때 원래 매체 선택 이유와 후속 재사용이 불명확 | 설치 manifest를 우선하며 손상 시 옛 매체로 대체하지 않는다. 없으면 검증한 원래 전체 매체와 설치 소스·runtime을 대조한다. 원본이 없으면 조치 필요로 중단한다. 앱 교체 시 새 manifest를 기록해 이후 점검에서 사용한다. 복구는 별도로 검증한 전체 snapshot을 사용한다. | `tests/unit/test_desktop_update.py`: test_installed_manifest_supersedes_old_baseline_for_inspect_start_and_apply, test_corrupt_installed_manifest_never_falls_back_to_old_media |
| E. Procrun | Registry64만 조회해 정상 Registry32 등록을 거절 | PR #2의 양쪽 view 조회를 통합·확장했다. 32 단독·64 단독·양쪽 동일은 허용한다. 존재하는 어느 view라도 불완전·타입 오류·옵션 중복·경로 불일치·옵션 충돌이면 거절한다. JVM/WorkingPath/home/config 및 환경 override 검증. registry 복사·수정·서비스 재등록 없음. | `tests/unit/test_updater_services.py`: test_procrun_valid_view_profiles, test_procrun_bad_shadow_is_never_hidden, test_procrun_missing_both_views_fails |

PR 검토 참조:

- [PR #1](https://github.com/dewdorp/SAW/pull/1), 검토 head **c62633d76758e4ac8b550f71cd59528b0f861c42**. 명시적 owner/DACL 생성, PS→Python handoff, 게시 실패 후 private 임시 파일 검증을 채택했다. Python helper는 공통 backend 생성부로 통합해 상태와 복구 메타데이터의 정책을 일치시켰다. 초안의 Linux 시험을 Windows 통과 증거로 재사용하지 않는다.
- [PR #2](https://github.com/dewdorp/SAW/pull/2), 검토 head **25cf808c97ecc0c176b2ca17ec35d08c7d1a9068**. 양쪽 registry view를 독립 검사하는 구조를 채택했다. 초안에 더해 Parameters만 존재하는 불완전 view, registry 자료형, 잘못된 따옴표, 전체 옵션 상충과 환경 override를 거절한다. 단순 따옴표 제거로 malformed 값을 정상화하지 않는다.
- 검토 시 두 PR은 main 기준 OPEN·미병합 상태다. 이번 브랜치는 내용을 통합·확장했으며 두 PR을 그대로 병합했다는 의미가 아니다.
- Apache의 [Procrun registry 문서](https://commons.apache.org/proper/commons-daemon/procrun.html#Windows_Registry_Usage)는 64비트 Windows에서도 설정이 32비트 view에 저장됨을 설명한다.

## 검사 시점과 변경 경계

| 시점 | 검사 | 변경 범위 |
|---|---|---|
| 실행 준비 | 로컬 경로, private 상태 폴더, 매체 전체, runtime ZIP entry | UI가 만든 보호 작업 폴더에 상태·잠금·검증된 내장 Python 생성. 선택 payload는 verifier 성공 전 실행하지 않는다. |
| 설치 점검 | ACL, 기준, 매체, 서비스·프로세스, 저장소, runtime·migration 계보, 복구 위치·공간·디렉터리 변경 권한 | 설치·서비스·registry는 읽기 전용. 설치 옆 유지보수 잠금과 별도 작업 폴더의 진단은 생성될 수 있다. 독립 검사는 계속하고 의존 검사는 미실행으로 표시한다. |
| 적용 직전, 중지 전 | 동의, 유지보수 잠금, 사전 검사 재실행, process/service handle | 과거 UI 결과를 실행 권한으로 재사용하지 않는다. 달라진 경로·소스·매체·구성·공간은 중지 전에 거절한다. |
| 중지 후, 교체 전 | 전체 process/port 정지, 최신 inventory·공간, snapshot 원본 대조 | 새 recovery에 전체 복구본과 검증 receipt 생성. 복사·receipt 실패 시 앱 교체·재시작 금지. |
| 앱 교체·기동 | 재검증된 매체, 보존 설정/app-var, 설치 manifest, 기동 migration·health | 앱을 교체하며 pinned runtime 유지. 기동/health 실패는 실패 상태와 복구 위치를 보존한다. |
| 명시적 복구 | 별도 동의, receipt·ACL·지문·journal, 정지 상태, stage/retained | snapshot을 별도 stage로 복사한 뒤 교체. 직전 설치는 retained sibling에 보관하고 자동 병합하지 않는다. |

읽기 전용 점검은 “아무 파일도 만들지 않음”이 아니다. 상태·진단·잠금은 설치 자료와 별도로 생성한다. 검사 통과를 위해 설치 ACL이나 서비스 상태를 시험적으로 변경하지 않는다.

## 사용자 24단계 감사표

단계명은 사용자 요청 순서를 유지했다. 구현은 일부 검사를 앞당기거나 잠금 안에서 반복한다. 시험 열은 대표 회귀이며 최종 실행 증거와 별도다.

| 번호·사용자 단계 | 현재 코드 경로·시점 | 주요 실패·중단 조건과 처리 | 대표 회귀 |
|---|---|---|---|
| 1. 업데이트 프로그램 실행 | UPDATE-SAW.cmd → update-ui.ps1/psm1; PS5.1·STA | 로컬 경로만 허용. 승인된 process-only RemoteSigned 사용; 전역 정책 변경 없음. 실행 실패를 성공으로 취급하지 않는다. | test_actual_winforms_has_update_restore_and_distinct_acknowledgements |
| 2. 내장 Python 및 PowerShell 초기화 | worker Expand-VerifiedRuntime; 매체 검증 후 private Python -I -B | ZIP 탈출·중복·과도한 크기·Python 없음 거절. SAW 환경 override 제거, 셸 평가 없이 인자 전달. | test_worker_archive_cannot_escape_private_runtime; test_worker_validated_python_gets_exact_arguments_and_clean_environment |
| 3. 상태 기록 디렉터리 생성 | New-SawUpdateStateDirectory, Assert-PrivateState, State.write | 현재 사용자 owner·사용자/SYSTEM protected DACL. 기존·중첩·reparse 폴더 거절. private 생성 후 flush/원자 교체; 게시 실패는 성공 금지. | test_private_state_survives_powershell_python_handoff; test_status_publish_failure_never_returns_completed |
| 4. 설치 경로 및 권한 확인 | _path/_separate/_access_gate, _require_directory_write; 중지 전 | alias·network·중첩·reparse·hardlink·열거 실패·외부 owner/allow 거절. OWNER RIGHTS 실제 owner 평가. 디렉터리 변경에 필요한 접근권은 파일 생성 없이 native handle 요청으로 확인한다. | test_untrusted_access_is_refused_before_installation_content_reads; test_owner_rights_native_dacl_is_accepted_without_repair |
| 5. 설치 버전 및 설치 방식 판별 | _mode, 설치 journal·서비스 표식·manifest; 중지 전 | 미완료 설치, 불명확한 service/noadmin 혼합, 다른 설치 서비스 거절. 관리자 요구와 전체 검증 완료를 구분한다. | test_ambiguous_or_incomplete_installation_refuses_control; test_admin_required_inspection_is_not_reported_as_full_acceptance |
| 6. 신규 업데이트 매체 무결성 검증 | PS verifier + release_manifest.verify; bootstrap/적용·교체 직전 | A의 원인별 코드. 추가·누락·변조 매체는 payload 실행 또는 교체 전 거절한다. | test_native_ps_and_python_media_agree; test_worker_tampered_media_never_extracts_or_executes_controller |
| 7. 기존 설치 기준 버전 검증 | _baseline/_installed_source; 중지 전 | 설치 manifest 우선, 구형 설치는 원래 전체 매체 필요. 소스 수정·추가 파일·손상 기준 거절. 추정 manifest 없음. | test_missing_baseline_does_not_hide_media_result; test_changed_installed_code_is_refused_before_stop |
| 8. Windows 서비스 등록 정보 검증 | ServiceLease의 SCM query, _mode; 중지 전 | 정확한 name/image, 독립 프로세스 형식, LocalSystem/NetworkService, 허용 dependency. 정상 빈 dependency API 표현도 처리. 등록/수정 없음. | test_scm_account_normalization; test_scm_unverified_dependencies_are_refused_before_service_control; test_service_lease_reads_native_configuration_and_pid_without_mutating_scm |
| 9. 서비스 XML 및 레지스트리 설정 검증 | _xml_policy/_service_configuration/_service_environment/_verify_opensearch_procrun; 중지 전 및 기동 직전 | WinSW 실행·정지 인자/data/working directory, hook/env override, Procrun 양 view·타입·옵션·경로 검증. malformed shadow를 정상 view로 숨기지 않는다. | test_service_xml_rejects_environment_overrides_and_execution_hooks; test_procrun_bad_shadow_is_never_hidden |
| 10. 기존 프로세스 식별 및 실행 상태 검증 | claim/ProcessLease; 중지 전 재조회 | image·command·부모·생성 시각·tracking bytes와 원래 kernel handle 유지. PG fork/console child는 검증한 부모 필요. PID 재사용/부모 변경 거절. 서비스 모드는 query-only process handle. | test_foreign_tracked_pid_is_rejected_before_any_termination; test_postgresql_fork_child_needs_retained_verified_parent |
| 11. PostgreSQL 및 OpenSearch 구성 검증 | backend _config; 중지 전 | bundled local PG16/OpenSearch, 설치 안 data/log/repo, URL·포트/transport 구분. 외부 storage와 지원하지 않는 PG include/data_directory 거절. 비밀값 진단 금지. | test_unmanaged_mutable_paths_and_runtime_drift_refuse_mutation; test_generated_service_configuration_accepts_https_443 |
| 12. 애플리케이션 설정 및 런타임 호환성 검증 | _installed_runtime/_runtime_rows/_migration_chain; 중지 전 | 고정 runtime/wheel/WinSW 해시·Python import path·추가 파일 확인. 과거 migration 변경·분기·downgrade 거절. 일반 앱 업데이트로 runtime 교체 금지. | test_native_and_dependency_drift_and_migration_regression_are_refused; test_migration_failure_is_reported_during_inspect |
| 13. 업데이트 가능 여부 최종 판정 | _inspect_all/_recovery_preflight; 중지 전 | 9행에 오류·미실행이 있으면 최종 pass 금지. 복원까지의 여유 공간·fresh recovery·경로 길이 확인. apply는 같은 잠금 안에서 다시 검사. | test_inspection_returns_nine_rows_and_private_details; test_apply_rechecks_after_inspection; test_preflight_space_failure_does_not_stop |
| 14. 사용자에게 점검 결과 표시 | Inspection, Get/Set-SawUpdateInspection, private viewer | 상태 구분, 원인·위치·기대/실제·조치·code·마지막 단계 표시. schema/action/root/status 불일치와 위조 상세 경로·owner/allow·hardlink 거절. | test_native_summary_selection_displays_safe_diagnosis; test_invalid_inspection_summary_is_never_accepted; test_details_open_refuses_unsafe_target |
| 15. 업데이트 동의 확인 | UI action gate, worker, run; 중지 전 | apply/restore 유지보수 동의, restore 시점 복구 동의, recovery 경로를 중복 확인한다. 없으면 bootstrap 또는 stop 전 거절. | test_destructive_actions_require_operator_acknowledgement; test_worker_missing_acknowledgement_never_bootstraps_runtime; test_unacknowledged_mutation_never_stops |
| 16. 서비스 안전 중지 | WindowsController.stop; 동의·검사 후 | 앱 중지→검색 flush→OpenSearch/PG 중지. noadmin은 retained handle로 owned process 제어. SCM pending은 대기하며 중복 control 금지. 전체 port/process 미정지 시 복사·교체 금지. | test_pending_service_transition_does_not_send_duplicate_control; test_tracked_live_process_and_pg_lock_refuse_copy |
| 17. 전체 복구본 생성 및 무결성 확인 | backend apply; 중지 후 | 전체 설치를 새 protected recovery/installation에 복사하고 원본·snapshot inventory/ACL 대조. receipt 전 실패는 검증 완료로 표시하지 않는다. 앱 교체와 재시작 금지. | test_snapshot_copy_failure_does_not_switch_application; test_apply_failures_preserve_synthetic_evidence; test_failed_receipt_publish_keeps_previous_and_private_pending |
| 18. 새 버전 적용 | _stage_public_app, 설정/app-var 복사, app rename | 별도 stage와 설치 ACL 보존. 교체 직전 매체·정지·inventory 재확인. 두 번째 rename 실패 시 원래 앱 이름 복원 시도. 중단된 교체는 전체 snapshot으로 복구. | test_update_uses_installed_acls_and_safe_parent_for_new_public_files; test_partial_application_switch_can_restore_verified_snapshot |
| 19. 데이터 마이그레이션 및 호환성 검증 | 사전 계보 검사 + 기동 SAW_SCHEMA_MODE=migrate | 사전 검사는 계보/runtime 호환성에 한정. 실제 DB migration은 앱 기동 시 실행. 기동/health 실패는 성공 금지, 전체 시점 복구 선택 가능. | test_migration_failure_is_reported_during_inspect; test_lifecycle_failures_never_report_success_or_retry; 실제 DB 인수 별도 |
| 20. 서비스 재시작 | WindowsController.start; 적용/복구 후 재검증 | PG→OpenSearch→웹 순서. 서비스 모드는 기동 직전 XML/registry/environment 재검사. 등록·계정·설정 재작성 없음. 시작 실패 시 실패와 복구 위치 보존. | test_lifecycle_failures_never_report_success_or_retry; test_backend_failure_keeps_snapshot_and_does_not_restart |
| 21. HTTPS·DB·검색 서비스 상태 검증 | healthy/_service_runtime_verified/_pg_ready | service PG는 관리자 pg_ctl status에만 의존하지 않는다. SCM PID, WinSW→정확한 postgres -D 부모, retained handles·생성 시각·재조회 + pg_isready + OpenSearch + 인증서 HTTPS. fork backend 오인 거절. | test_service_postgresql_health_requires_scm_linked_live_processes; test_health_does_not_accept_postgres_process_without_readiness; 443 포함 |
| 22. 업데이트 성공 기록 및 설치 매니페스트 갱신 | backend receipt/manifest, controller 최종 state | **manifest는 앱 교체 단계에서 기록**한다. applied_stopped_schema_pending은 완료가 아니다. health 뒤 completed, 업무 인수는 needs_acceptance로 남김. 게시 실패·exit 0 단독은 성공 금지. | test_status_publish_failure_never_returns_completed; test_worker_never_reports_success_for_failed_or_mismatched_controller; test_completed_state_cannot_override_nonpassing_overall_diagnosis |
| 23. 업데이트 실패 시 롤백 | 명시적 restore, _pending_restore/restore | 자동 전체 복구로 새 자료를 덮지 않는다. 별도 동의 뒤 receipt·ACL·지문 재검사. 현재 설치는 retained sibling에 보관. staged/root_retained/complete journal로 중단 구분, root 소실도 검증 journal만 재개. | test_restore_interruption_can_resume_without_losing_either_version; test_tampered_restore_state_is_rejected_read_only; test_controller_resumes_missing_root_after_restore_interruption |
| 24. 롤백 후 서비스·데이터 상태 확인 | 복구 검사→start→health + 운영자 인수 | 복구 파일·ACL을 snapshot과 대조하고 새 자료는 retained에 보존. 계정·MFA·index·원본의 기능적 인수는 별도 필요. 복구/결과 기록 오류 시 journal 보존·재시도. | test_apply_and_whole_restore_preserve_private_state_and_new_records; test_result_write_failure_finishes_same_swap_on_retry; test_journal_publication_failure_preserves_retryable_state |

주요 코드: [desktop_update.py](../../saw/devtools/desktop_update.py), [offline_update.py](../../saw/devtools/offline_update.py), [release_manifest.py](../../saw/devtools/release_manifest.py), [update_diagnostics.py](../../saw/devtools/update_diagnostics.py), [update-worker.ps1](../../deploy/windows/update-worker.ps1), [update-ui.psm1](../../deploy/windows/update-ui.psm1).

테스트 묶음: `tests/unit/test_desktop_update.py`, `tests/unit/test_offline_update.py`, `tests/unit/test_update_diagnostics.py`, `tests/unit/test_restore_interruption.py`, `tests/unit/test_updater_services.py`, `tests/unit/test_update_worker.py`, `tests/unit/test_update_ui.py`, `tests/unit/test_update_acl_policy.py`.

## 추가 감사 결과와 안전한 진단

원시 예외 문자열을 UI에 전달하지 않는다. 상태는 고정 code/message를 사용하고 명시적으로 만든 구조화 diagnostics만 기록한다. 매체의 추가 파일명과 private 자료 ACL 경로는 표식으로 숨긴다. 환경변수 값·registry 옵션 원문·DB 접속 비밀은 출력하지 않는다. worker는 child stdout/stderr를 동시에 비우며 원문을 로그에 보존하지 않는다. UI는 schema/action/root, 필드 자료형과 진단 행 구조를 검증한다.

추가 감사에서 두 후속 문제를 발견해 구현 담당자에게 전달했고, 담당자가 코드 보완을 통합했다.

1. 복구 parent 존재·같은 볼륨·경로 길이·공간만 확인하면 실효 create/write 권한 거절을 중지 뒤에야 알 수 있었다. **_require_directory_write**가 native CreateFileW로 필요한 directory 접근권만 요청하여 실제 파일 생성 없이 중지 전에 확인하도록 보완했다.
2. 일반 restore가 root를 교체한 뒤 활성화될 XML을 다시 검증하지 않고 기존 claim에 의존했다. 서비스 모드는 기동 전에 **_service_configuration**을 다시 실행해 현재 XML·registry·environment를 확인하도록 보완했다.

이 보완의 최종 회귀 결과는 전체 시험 증거에서 확인한다. 검사 후 다른 관리자 프로세스의 강제 변경, 전원 중단, 하드웨어 I/O 실패까지 미래 성공을 보증하지 않는다. 유지보수 잠금, 반복 검증·inventory, kernel handle, 복구 journal과 별도 retained 자료로 경합·중단을 처리한다.

## 최종 검토의 추가 중요 항목 — 수정·독립 재검토 완료

후보 5의 합성 실행 뒤 확인한 아래 세 항목을 수정했고 독립 재검토에서 새 Critical/Important 문제는 없었다. 특히 단계 4·13의 권한·복구 준비 범위는 이 보완을 포함한다. 코드 검토 항목의 해결과 최종 매체 합격은 구분하며, 후보 6 동결 코드의 두 번째 전체 시험은 1,647 통과·6 건너뜀·기존 경고 2건(1,376.79초)으로 완료됐다. 이후 ACL 표시·live 재검사 보완의 최종 통합 검증은 별도다. 후보 6 적용·적용 후 보존은 통과했으나 첫 복구가 접근 권한 사전 검사에서 실패해 후속 검증이 필요하다.

| 발견 사항 | 재현 조건·영향 | 보완 범위·현재 상태 |
|---|---|---|
| start와 snapshot 준비 검사 결합 | 정상 설치의 다시 시작만 요청해도 전체 복구본을 위한 공간 부족이나 복구 위치 쓰기 거절 때문에 중단될 수 있음 | start가 실제 사용하는 자원만 요구하도록 action별 사전 검사를 분리했다. apply/restore의 복구 검사는 유지한다. 후보 6 native 시작 PASS(52.72초), recovery_not_required 행을 공개 영수증에서 확인했다. |
| 실제 rename의 실효 권한 미완전 검사 | 디렉터리 create/write는 허용하되 source DELETE와 parent FILE_DELETE_CHILD가 모두 거절된 ACL에서, 사전 검사가 통과해도 서비스 중지 후 실제 rename이 실패할 수 있음 | 실제 source·destination별 root/parent 생성 권한과 source DELETE 또는 parent FILE_DELETE_CHILD를 파일 생성·ACL 변경 없는 읽기 전용 접근 검사로 확인하도록 보완했다. native ACL 회귀 11건 PASS(9.96초). |
| 현장 OS 분류가 build에 의존 | Windows Server 2019도 build 17763이므로 목표 Windows 10 Enterprise LTSC 2019 client로 잘못 분류할 수 있음 | ProductType 1, OperatingSystemSKU 125/126, build 17763, Windows version 10.0, PowerShell 5.1, OS·process 64비트 조건을 모두 요구하도록 수정했다. native 4건 PASS(4.11초, OS 경계 사례 14개). 실제 목표 OS 인수는 미완료. |

최초 전체 서버 시험은 **1,589 통과 / 6 건너뜀 / 알려진 문서·시험 실패 2건 / 3,258.21초**로 끝났다. 문서 시험 수정 후 관련 manifest 회귀는 **67 통과**했다. 이전 포트 사례는 최초 81건 묶음에서 79 통과·1 건너뜀·1 실패였고, 단독 재시험 1 통과(40.08초), 전체 suite 종료 뒤 직렬 재시험도 1 통과(32.55초)였다. 동시 포트 사용은 시점상 가능한 설명이며 실패 당시 소유 PID가 없어 원인 확정으로 쓰지 않는다.

위 보완의 관련 mock 회귀는 **32 PASS**다. 두 번째 전체 suite는 **후보 6 동결 코드 기준 1,647 PASS / 6 SKIP / 경고 2건 / 1,376.79초**로 완료됐다. 이후 변경을 포함하는 최종 소스 검증은 미완료다. 후보 6은 native 시작 **52.72초 / ACL 32,651개 / 9행 PASS**, 점검 **39.93초 / ACL 32,658개 / 9행 PASS**를 공개 영수증으로 확인했다. 적용은 **508.17초 / ACL 32,658개 / 9행 PASS / health 완료**했고 적용 후 자료 비교와 같은 계정·MFA·TLS 로그인도 통과했다. 첫 복구 시도는 **40.52초 / unsafe_access / validate / FAIL**이다. 검증된 복구본과 재시도 가능 상태는 있지만 이후 복구·보관 검증은 미실행이다. 시험 계정 정리는 첫 복구 실패 직후에는 미실행이었으나 후보 7 준비 전 별도 안전 정리로 완료했다. 별도 안전 정지 도구의 정상 중지는 PASS 28.73초로 확인했다. 후보 2·5의 성공 이력은 해당 후보에 한정한다. 구조화 결과와 증거 범위는 [검증 기록](updater-stabilization-20261019.json)에 남긴다.

## 후보 6 첫 복구의 공개 실패 기록

`restore-form-20261019-233833-431da8.json`은 **FAIL**이며 접근 권한 행의 `unsafe_access`와 전체 `preflight_failed`를 표시한다. 현재 단계는 `validate`, `can_retry=true`, `recovery_verified=true`이고 retained 설치는 보고되지 않았다. 기준·서비스·저장소·설정·복구 항목은 미실행이다. 이는 복구 완료나 자료 보관 완료가 아니며, 원인은 확인 중이다. 승인된 오류 종류·건수 확인에서 설치 범위 32,690개 중 접근 권한 정보 조회 실패(access_metadata_unreadable) 4건을 확인했고 목록 생략은 없었습니다. 경로·SID·파일 내용은 확인하지 않았으며, 조회 실패의 근본 원인은 아직 조사 중입니다.

후보 6의 적용과 적용 후 보존·로그인 통과, 후보 5의 복구 통과는 각 범위의 별도 증거로 유지한다. 실패 화면 원본은 [안내 HTML의 후보 6 실패 절](../UPDATER-STABILIZATION-GUIDE-20261019.html#native6-restore-failed)에 바이트 변경 없이 내장했다. 원시/private 로그는 이 문서 작업에서 읽지 않았다.

## 후보 6 중지와 후속 코드·후보 7 상태

후보 6 시험 설치는 별도의 기존 안전 정지 도구로 28.73초에 정상 중지했습니다. PostgreSQL·OpenSearch·API의 세 시험 포트가 닫히고 PostgreSQL PID 파일이 없는 것을 공개 영수증으로 확인했습니다. 이는 복구 성공을 뜻하지 않습니다. 이후 후보 7 준비 단계에서 기존 합성 계정의 활성 상태가 확인돼 기존 안전 정리 도구를 실행했으며, 후보 6 계정 비활성화·세션 폐기는 공개 영수증으로 통과를 확인했습니다. 이후 같은 합성 계정을 후보 7 시험에 다시 준비했습니다.

권한 변경 없는 별도 metadata-only 재검사는 32,690개 전체를 8.0초에 통과했다. 최초 오류는 Win32 번호를 보존하지 않았으므로 이 재검사 성공을 최초 4건의 원인 확정이나 해결 증명으로 사용하지 않는다.

후속 표시는 고정 오류 enum·안전한 위치·검사/확인 필요 건수·유효한 전체 검사 시도 횟수를 요약한다. 진단 파일 전체는 표현/enum 후속 조정 전 51 PASS(115.16초), 최종 순수 요약 시험은 46 PASS(0.09초)다. 각 실행에 기존 Starlette 경고 1건이 있다. 새 코드가 후보 6에 포함됐다고 표시하지 않는다. live preflight만 명시적으로 허용한 최대 3회 전체 재검사는 항목 건너뜀 없이 수행하며 실제 정책 위반은 즉시 실패하고 cold 기본값은 엄격하게 유지한다. 이 연결의 별도 표적 회귀 37 PASS가 보고됐고 최종 통합 검증은 대기 중이다.

후보 7 매체는 빌드·검증을 마쳤고 별도 r3 private/public/recovery 경로를 사용한 실제 합성 순서를 실행 중이다. 결과는 미확정이다. 새 최종 ZIP·통합 PR·게시도 아직 없다. 이전 후보 5 성공과 후보 6 실패, 최초 전체 시험 실패를 모두 이력으로 보존한다.

## 전체 시험의 PowerShell 실행 정책

사용자가 승인한 범위는 시험 프로세스의 **RemoteSigned**다. 전역 실행 정책 변경, Bypass, 조직 정책 무시, 파일 차단 표시의 자동 제거를 사용하지 않는다.

rg 읽기 조사에서 기존 단위 시험 8개 파일의 subprocess 호출 9곳에 Bypass가 있었다. 아래 위치의 **문자열 인자만 RemoteSigned로 교체**했으며 파일별 기존 줄 끝을 유지했다. 이 변경 자체는 해당 시험 실행 완료를 뜻하지 않는다.

| 파일 | 호출 줄 |
|---|---|
| `tests/unit/test_install_paths.py` | 26 |
| `tests/unit/test_install_python.py` | 35 |
| `tests/unit/test_install_state.py` | 23 |
| `tests/unit/test_offline_update.py` | 153 |
| `tests/unit/test_opensearch_install.py` | 24 |
| `tests/unit/test_release_manifest.py` | 55, 214 |
| `tests/unit/test_postgresql_setup.py` | 19 |
| `tests/unit/test_windows_bundle.py` | 53 |

updater UI·worker·진단·현장 점검 테스트도 process-only RemoteSigned를 사용한다. 조직 정책이나 다운로드 차단으로 실행이 거절되면 원인을 보고하고 승인된 매체 반입·서명 절차를 사용한다. 시험 통과를 위한 별도 우회 경로를 만들지 않는다.

## 남은 실제 인수와 증거

후보 5의 실제 PG/OpenSearch/HTTPS 합성 점검·업데이트·복구와 자료 보존은 공개 영수증으로 확인했다. 다만 최종 검토 후 수정이 추가되므로 후보 7의 실제 실행, 최종 소스 전체 회귀, 최종 ZIP 생성·봉인·모든 entry 재검증을 새로 확인해야 한다. 이전 후보나 부분 회귀를 최종 합격으로 확장하지 않는다.

특히 LTSC 17763에서 다음의 실측 결과가 필요하다.

- 일반 사용자·관리자·기본 owner Administrators 토큰의 PS→embedded Python 상태 전달.
- 실제 LocalSystem/NetworkService 서비스 중지·기동·프로세스 권한, Registry32 단독, HTTPS 443, 재부팅 후 기동.
- 실제 PG migration 이후 계정·비밀번호·MFA·권한·조사·index·업로드·증거·설정·TLS 보존과 전체 시점 복구.
- backup·교체·기동·health·restore interruption·결과 기록 실패 후 보존과 재시도.
- 물리 폐쇄망, 조직 TLS·방화벽, 여러 분석가 접속, 정전/강제 종료, 운영 인수.

현장 읽기 점검은 [test-update-environment.ps1](../../deploy/windows/test-update-environment.ps1)과 [현장 인수 절차](updater-native-acceptance-20261019.md)를 사용한다. 검증한 worker의 inspect만 실행하고 OS/PS/token, 서비스 상태, registry view 자료형과 선택한 파일·ACL 범위의 전후 지문을 기록한다. 성공해도 업데이트·복구·재부팅은 **not_run**으로 남는다.

현재 소스 전체 서버 시험 r3가 실행 중이다(세션 35105, server-final-r3.log/.xml). 후보 7 빌드·매체 검증은 완료됐고 실제 합성 순서는 2026-10-20 00:16 KST에 시작됐다(세션 27747). 두 실행의 결과는 아직 미확정이며 시작 상태를 통과 근거로 사용하지 않는다. 후보 7 inventory는 675개 파일·1,494,876,567바이트, manifest SHA256 e60ed0a62768ab28427df1f7d4b480e8dce2a71d1c0189c9d06ad10090b81781이다. 최종 ZIP 메타데이터는 아니다.

## 후보 7 준비·초기 점검 당시 기록

후보 7 시작은 PASS 69.47초, ACL 32,688개·9행 PASS·health 완료다. 첫 합성 준비는 synthetic_account_state_not_disabled로 실패했다. 후보 6 복구 실패 후 남은 활성 합성 계정 때문에 준비 조건이 충족되지 않은 것이며 업데이트 작업 실패가 아니다. 기존 guarded 정리 도구가 계정 비활성화·세션 폐기를 완료한 뒤 새 보호 작업 경로에서 준비를 다시 수행해 통과했다. 생산 코드는 바꾸지 않았다.

점검 전 같은 합성 계정·암호·MFA/TLS 로그인, 기준 저장, 설치 점검 PASS 39.36초(ACL 32,698개·9행), 점검 후 읽기 전용 자료·계정·설정 대조를 공개 영수증에서 확인했다. 기준 수량은 이벤트 9·Finding 10·증거 2·노트 1·완료 작업 2·계정 2다. 이후 적용은 통과했고 현재 복구와 전체 서버 r3는 실행 중이다. 복구·보관·최종 정리까지 통과했다고 표시하지 않는다.

이전 전체 서버 r2의 6 SKIP은 SAW_TEST_DATABASE_URL 미설정 1건, symlink 권한 없음 1건, 격리 PostgreSQL initdb binary directory 조건 3건, POSIX bits 전용 ACL 시험 1건이었다. 현재 r3의 건너뜀 수와 결과는 미확정이며 이전 수를 그대로 적용하지 않는다.

## 후보 7 실제 적용과 후속 검증 — 완료 전 기록

공개 apply-form-20261020-002053-a87ea8.json에서 적용 PASS 492.39초, ACL 32,698개·9행 PASS·health 완료를 확인했다. after-apply-20261020-002915-eabdeb.json의 정확한 label은 after-apply이며 기준 수량과 계정·암호 해시·역할·MFA·증거·작업·노트·설정·키·TLS·원본 동일성이 모두 통과했다. after-apply-login-20261020-002917-6185e6.json도 같은 합성 계정·암호·MFA/TLS 로그인과 logout 통과다.

업데이트 후 50바이트 합성 객체 추가는 통과했으며, 복구는 2026-10-20 00:29 KST 무렵 시작돼 현재 결과 대기 중이다. 아직 새 자료가 retained 설치에 보관됐다고 판정하지 않는다. 적용 화면은 공개 PNG 원본 바이트를 HTML의 native7-apply 절에 직접 내장했다. 전체 서버 r3와 복구 후 검증·최종 정리 결과는 미확정이다.

## 동결된 최종 생산 코드 전체 서버 r3 결과

세션 35105는 exit 0으로 끝났으며 **1,733 PASS / 6 SKIP / 경고 2건 / 1,305.21초(21분 45초)**다. 근거는 server-final-r3.log/.xml 실행 결과 보고이며 원시 서비스/private 로그를 추가로 읽지 않았다. 두 경고는 기존 Starlette/httpx deprecation과 JUnit record_property/xunit2 보고 형식이다. 앞선 1차 시험 실패와 후보 6 시점 r2 결과는 이력으로 유지한다. 이 전체 시험 성공이 아직 진행 중인 후보 7 복구나 목표 LTSC 관리자 환경의 인수를 대신하지 않는다.

단독 배포할 HTML의 초기 01–04 화면도 각 PNG의 원본 바이트를 img src와 확대 링크 href에 직접 넣었다. 후보 5–7 화면을 포함해 현재 9개 이미지가 모두 HTML에 내장돼 별도 assets 폴더 없이 표시된다. Markdown용 원본 이미지 파일은 유지했다.

## 후보 7 복구·보존·정리의 공개 근거

restore-form-20261020-002918-d753c3.json, after-restore-20261020-003745-ca7d03.json, after-restore-login-20261020-003747-0d4f8e.json, newer-data-verify.json, cleanup-20261020-003748-1c22f2.json, final-stop-20261020-003818-5d09d0.json의 허용 상태·숫자·불리언 및 SHA256만 구조화 검증 기록에 반영했다. 원시/private 로그·계정값·키 내용은 읽거나 문서에 포함하지 않았다. 실제 복구 PNG 원본을 HTML native7-restore 절에 내장했으며, 초기 4개와 후보별 적용·복구 화면을 포함한 이미지 10개가 모두 단독 HTML에 들어 있다.
