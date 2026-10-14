# 조사 안내·검토된 정답 사례·폐쇄망 콘텐츠 반입 설계

기준: 2026-10-15, 05fe73b. 사용자 첨부 요구사항과 외부에서 만든 룰·파서 반입 요청을 기존 SAW에 증분 반영한다. 일반 구현 선택은 사용자가 위임했다. 원본 F:/claude/saw, 실제 은행 자료, 비밀값은 변경·복제하지 않는다. 개발 시험은 합성 자료만 쓴다.

## 재사용과 사용자 흐름

기존 조사에서 IP/탐지를 선택한다. 우측 참고 패널에 확인된 사실·자료의 한계·다음 확인을 표시한다. 기존 Check의 불변 변경 이력에 답변과 실제 조회 범위를 보존한다. 확인되지 않은 상태로도 후속확인과 함께 종결할 수 있다. 실제 확인 기록을 종결 및 Experience 초안에 재사용하며 모든 Finding을 검토 완료로 만들지 않는다. Experience 승인과 골든셋 채택은 기존 경험 검토 화면의 별도 선택이다. 새로운 조사나 자동 조치는 만들지 않는다.

## 조사 안내 계약

POST /investigations/{id}/guidance/preview: target_type(entity/investigation/finding), target_key, role(src/dst/either), filters, time, as_of, methodology_version. 서버는 조사 권한과 시간/필터를 적용한다. either는 src 일치와 dst 일치+src 불일치의 배타적 분기로 중복을 없앤다. count와 표본을 혼동하지 않는다.

응답: methodology(id/version/digest), scope(scope_key/effective_time/evidence_manifest), facts, unknowns, questions, queries, limits. 자료 상태는 available/no_match/partial/not_collected/query_failed/forbidden/not_queried/not_applicable의 8개다. 조회 실패·권한 없음·미수집을 0건으로 바꾸지 않는다. 실제 연결이 없는 EDR/평판은 조회했다고 하지 않는다.

A–G 규칙은 버전 YAML로 관리한다. 혼합 차단/허용, 평판 없음과 공격 요청, 반복 외부 통신, 승인된 점검 범위, HTTP200/대용량, 자료 부재/실패, 직접 침해 근거를 다룬다. 조건·목적·필요 자료·해결 근거·종료/후속 조건·금지 주장을 갖는다. 답변은 선택적이며 열람/클릭은 확인 완료가 아니다. 승인된 점검도 출발지·대상·시각·방법의 이번 범위에 한정한다.

기존 Check API에 guidance를 추가한다. 서버가 범위와 근거를 검증하고 실제 조회를 다시 수행하여 영수증과 초기 입력 스냅샷을 저장한다. 클라이언트 counts/receipts는 받지 않는다. Check.note/judgement는 정답 쪽이며 입력 스냅샷에서 제외한다. 과거 as_of가 입증되지 않으면 평가 가능으로 만들지 않는다. 종결 초안은 행동 판단·영향 판단·근거·한계·후속확인·실제 check_ids를 분리한다.

## 정답 사례 계약

별도 GoldenFamily, GoldenFamilyMember, GoldenVersion, GoldenBlob 테이블. Experience의 공개 data에 정답 기준을 섞지 않는다. immutable 채택본 수정은 새 초안, 재검토를 요구한다. 작성자와 입력/판단/근거 편집 기여자는 자기 채택 불가. 검토 기준은 필수 사실/확인, 판단/근거, 후속확인, 금지 주장 4개를 명시적으로 확인한다. Experience 승인과 골든셋 채택은 별개이며 자동 학습은 없다.

저장된 초기 scope/material-state/query receipt와 선택 원문만 agent input으로 허용한다. 종결, 경험, Note, Story, 파생 정답/검토 기준은 evaluator answer에만 저장한다. 당시 captured_at/known_at와 증거 수집·처리 이력을 검증한다. 자료가 없는 사례는 자료 상태 스냅샷 자체가 유효한 입력이다. 선택 원문 최대200건, blob256KiB/사례4MiB. bounded masked JSON의 content-addressed DB 저장으로 승인과 원자적으로 고정하고 중복 제거한다. 관계/방향/시간은 보존한다.

Case 연결 및 과거 소속으로 서버가 사건군을 계산한다. 사건군의 train/dev/holdout은 최초 채택 후 고정한다. 나중에 연결을 바꿔 다른 split 사건군을 합치면 채택/내보내기를 거부한다. 원본 조사 접근권한과 source 만료/삭제 정책을 적용한다. 내보내기는 승인본만 CSV, agent-input.jsonl+선택 evidence bundle, 별도 evaluator-answer.jsonl. 누락/해시불일치 증거는 실패한다. export는 실시간 RAG/Experience/context 조회를 호출하지 않는다. 평가 실행기/모델 학습은 이번 범위가 아니다.

## 폐쇄망 콘텐츠 묶음

단일 엄격 JSON(schema/package_id/revision/requires/payload_sha256/entries), 최대1MiB/20항목. 지원 항목은 기존 검증 가능한 Sigma와 선언형 ParserSpec이다. 양성·정상 합성 fixtures를 포함한다. 명령/스크립트/Python/모델/ZIP 경로는 지원하지 않는다. SHA256 무결성과 발행자 신원 검증을 구분한다. 내장 YAML 엔진/앱 코드 업데이트는 이 데이터 반입 경로와 별개다.

파일 만들기/내보내기 → 폐쇄망 반입 → 검증/차이/시험 → 다른 현재 권한자의 승인·적용 → 이력/되돌리기. staging은 현재 활성 룰/파서를 변경하지 않는다. fixture 결과는 digest에 연결된 package_fixture 검증으로 표시하며 실제 조사 replay와 구별한다. 적용은 precondition/version/digest 재검증과 동시성 제어 후 전체 원자적 transaction이다. 항목 하나 실패해도 전체 취소. 감사는 importer/author/reviewer 실제 actor를 기록한다. 기존 중간 commit API를 호출해 원자성을 깨지 않는다.

rollback은 적용 영수증에 고정된 직전 승인본으로만, 이유와 별도 실행자/현재 권한 및 drift 검사 후 수행한다. Sigma는 이전 payload의 새 보상 버전, 파서는 한 slug active 하나 유지. 기존 분석 결과를 지우거나 자동 재처리/외부 배포하지 않는다. restart 보존 및 PostgreSQL 동시성을 별도 확인한다.

## 수용 시험과 한계

우선 A(120 WAF,118 차단,2 허용,WAS/평판 없음)를 조사→안내→답변→종결→경험 검토→채택→분리 export까지 잇는다. 다음 B 승인점검의 일치 범위와 C 반복 통신/프로세스 없음/EDR권한 없음. 권한·자기승인·범위·답변 재사용·버전·split·해시·정보누출·재시작·기존 회귀를 시험한다. pack tamper/미지원/한도/자기승인/fixture실패/stale/원자성/rollback drift를 시험한다.

개발 Windows11 결과를 LTSC17763 인수로 표현하지 않는다. 신규 모델·학습·운영 데이터·관리자 서비스·운영 배포 승인은 별도다. 기존 설치 ZIP과 History503/Node 간헐 종료 기록을 새 성공으로 덮지 않는다.
