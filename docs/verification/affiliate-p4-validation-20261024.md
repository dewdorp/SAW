# P4 골든셋·반출 검증 — 2026-10-24

정확한 골든셋·분석·확인 기록·프로필·파일 버전과 독립 반출 승인, 평가 입력/정답 분리를 구현했습니다. 새 전체 설치 매체와 운영 인수는 P5 및 대상 환경의 별도 확인 범위입니다.

## 이번 최종 확인

| 구분 | 실제 실행 결과 |
|---|---|
| 전체 서버 | 서버 2,179통과·8건너뜀·실패0·오류0. JUnit 2276.70초. 아래 로그 요약·건너뜀 사유 참고 |
| 최종 웹 | 348통과/51파일, 78.46초. TypeScript exit0, Vite exit0·22.51초 |
| 실제 저장소 | PostgreSQL16.15/OpenSearch2.19.6/Nori. 아래 세 번의 결과를 구분 |
| 실제 브라우저 | 합성21행·7세션 전체 재계산 파일 생성→일반 MFA 독립 승인→ZIP 내려받기→철회. 이후 다운로드 버튼 비활성 및 HTTP409 |
| 평가 입력과 답안 | 평가 이력 생성→입력 ZIP→외부 합성 파일 검사 실행→결과 등록→내부 답안 명시 열람. 모델 실행·학습·품질 평가 아님 |
| 재시작 | schema0021→0022. 분석·탐지실행·Finding·반출버전·승인·평가·사용 이력7종의 기존 행과 지문 보존 |

서버 로그 최종 집계: 2179 passed, 8 skipped, 2 warnings in 2276.73s (0:37:56).

건너뜀 사유:
- tests.unit.test_detector_version_migration.test_fresh_schema_preserves_complete_detector_versions[postgresql]: SAW_TEST_DATABASE_URL not set; actual PostgreSQL not exercised
- tests.unit.test_detector_version_migration.test_0022_populated_0021_upgrade_twice_preserves_provenance_and_history[postgresql]: SAW_TEST_DATABASE_URL not set; actual PostgreSQL not exercised
- tests.unit.test_migrations.test_fresh_upgrade_matches_models[1]: SAW_TEST_DATABASE_URL not set
- tests.unit.test_model_pack_builder.test_builder_rejects_source_links: Windows symlink creation is unavailable
- tests.unit.test_postgresql_setup.test_native_initdb_ba_system_only_secret_and_exact_acl_restore: explicit isolated PostgreSQL binary directory required
- tests.unit.test_postgresql_setup.test_native_initdb_success_already_has_selected_secure_configuration: explicit isolated PostgreSQL binary directory required
- tests.unit.test_postgresql_setup.test_native_initdb_with_korean_runtime_share_and_data_paths: explicit isolated PostgreSQL binary directory required
- tests.unit.test_private_update_state.test_untrusted_existing_state_is_still_rejected: POSIX access-bit rejection; native ACL cases use the handoff test

## 실제 PostgreSQL·OpenSearch 실패와 수정 이력

| 실행 | 결과 | 확인 범위 |
|---|---|---|
| r1 | 2통과/1실패, 시험52.234초·전체140.078초 | Finding 탐지기 버전 VARCHAR16 부족 발견 |
| r2 | 59통과/1실패, 시험835.593초·전체905.594초 | additive0022의64자로 확장 및 신규/기존 PostgreSQL 마이그레이션 통과. 공유 시험 fixture 충돌 발견 |
| r3 | 6통과/0실패/0건너뜀, 시험104.797초·전체172.156초 | 조사/이벤트 시험 식별자 분리 후 영향 순서와 오류 사유 확인 |

노드별 최신 결과는 서로 다른62개 통과입니다. 단일 최종 전체 실행62통과를 뜻하지 않습니다. 각 실행은 소유 프로세스 정상 종료, flush 실패 shard0, 시험 포트 닫힘을 확인했습니다. 제품 검증을 약화해 시험 충돌을 통과시키지 않았습니다.

## 실제 화면과 파일

[그림 사용법](../AFFILIATE-GOLDEN-GUIDE-20261023.md)은 실제 캡처6장입니다. 합성 개발용 ZIP103,010바이트/13항목의 CRC·안전 경로·SHA256을 확인했습니다. 지문은756162547173c89c396570ef044611da2e329a482483762017037e8c8ee7b9d1입니다.

Holdout 반출 준비는 일반 HTTP/MFA API이며, 평가 이력·입력 내려받기·결과 등록·답안 열람은 실제 브라우저입니다. 입력ZIP11항목/JSONL1행/답안 없음은 실제 외부 QA 구조 검사기로 확인했습니다. SAW가 모델을 실행한 것처럼 표시하지 않습니다.

처음 답안 열람에서 NDJSON 한 행이 객체로 해석되어 React 화면이 비었습니다. 성공 응답의 원문 text 처리를 수정하고13개 직접 회귀·관련76개·최종 웹348개, 독립 검토와 실제 브라우저 재확인을 마쳤습니다. 첫 실패 요청을 지우지 않아 최종 답안 열람 이력은2회입니다.

이전 전체 웹 r3의334통과/1로딩시점 실패는 이력으로 유지합니다. 코드 변경 없이 해당2개/관련18개, 동시 worker2로 제한한 전체335개가 통과했고, NDJSON 수정 뒤 최종348개가 통과했습니다. 이 결과는 과거 간헐적 History503 원인 해결의 근거가 아닙니다.

## 검토와 매체

원천 권한과 정확 버전, 숨겨진 현재/대기 참조, 고정된 탐지 정답 비교 의미, native 시간창/누락값 처리, v1 답안 보존, 안전한 실패 사유, UI의 정확 버전·독립 승인·답안 노출을 독립 검토하고 발견된 사항을 수정·재검토했습니다.

전체 서버 시험 중 안내 문서와 새 캡처가 잠시 정식 docs에 놓였다가 원래 안내의 정확한 바이트로 복원되고 캡처가 QA로 이동했습니다. 서버 제품·시험 코드는 유지됐습니다. 이후 최종 안내·캡처와 공개 검증 기록을 명시적인 매체 허용 목록에 넣었으며, 이 변경은 별도 매체 회귀 결과로 기록합니다.

## 남은 범위

P5의 안전한 재처리·공정 큐·실제 대량/공동사용 측정, 새 모델 제외 전체 매체의 최초 설치/0014업데이트/재시작/실패/전체복구, 최종 전체 브랜치 검토와 새 비공개 릴리스를 이어갑니다.

개발기 Windows11 build26200/약32GiB의 합성 검증이며 깨끗한 LTSC2019 build17763·실제16GB·관리자 서비스/UAC/재부팅·조직TLS/서명·물리폐쇄망·운영 인수는 미검증입니다. 모델 가중치·추론·학습은 이번 P4에서 실행하지 않았습니다. 과거 History503·권한metadata4건의 직접 원인은 계속 미확정입니다.

근거: [전체 게이트](affiliate-p4-final-gate-20261024.json), [실제 저장소](affiliate-p4-native-20261024.json), [실제 브라우저](affiliate-p4-browser-20261024.json).

최종 안내·캡처·검증 기록의 명시적 매체 포함 변경 뒤 관련 전체 매체 회귀73개 통과·기존경고1·12.56초·exit0을 확인했습니다. 이 결과는 새 전체 ZIP 설치 시험과 구분합니다.
