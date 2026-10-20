# 관계사별 탐지 관리 P0 코드 감사 — 2026-10-20

## 1. 범위와 검증 경계

- 작업본: `F:/codex/SAW-Claude-main`, 루트 감사 기준 HEAD `4072e9d`.
- 기준: 사용자 최종 요구사항 7·8절, 의심 항목 2·5·6·7, 인수 T10–T13 및 시험 정답 계약.
- AGENTS.md, STATE.md, docs/HANDOVER.md와 최종 요구사항 전체를 읽었다.
- 제품 코드·DB·서비스·운영 설정·원본 자료를 변경하지 않았다. 이 감사 문서만 작성했다.
- 실제 은행 자료, 원본 `F:/claude/saw`, 사용자 계정, 비밀값·dotenv에 접근하지 않았다.
- 이번 담당 감사의 실제 실행은 순수 함수에 대한 인메모리 합성 probe 한 번이다.
- 루트의 중앙 pytest·Vitest·TypeScript 실행과 별개이며, 이 문서는 그 통과 수를 자기 실행으로 재기록하지 않는다.
- 실제 브라우저 입력·운영 PostgreSQL/OpenSearch·대상 LTSC2019·대량 공동 부하 인수는 이번 담당 감사에서 수행하지 않았다.

## 2. 현재 구현 판정

| 요구 범위 | 판정 | 근거와 남은 일 |
|---|---|---|
| 기본 탐지기 목록 | 연결 보완 | [DetectionCatalog.tsx](../../apps/web/src/pages/DetectionCatalog.tsx) 131–136행, [detection.py](../../saw/apps/api/routers/detection.py) 173–175행: 이름·ID·단계·자료 종류만 제공. 상세 조건·필수 필드·정책 출처·미실행 사유 필요. |
| 시그니처 설명·전환 | 이미 가능 + 연결 보완 | DetectionCatalog.tsx 183–216행: 설명·응답 조건·양성 예제·확인 권고·전환. 정확한 일치 조건·정상 예제와 승인 흐름을 상세에 연결할 필요. |
| 기본 룰 내보내기 | 이미 가능 | [exporting.py](../../saw/detection/exporting.py) 41–61행: 시그니처 일치 조건·정상 예제·NDR 설정·코드 탐지기 버전 포함. Python 구현은 미포함이라고 명시. |
| 관계사·장비별 정책 | 신규 필요 | detection.py 179–199행의 시그니처 전환은 전역 즉시 변경. 기존 `SignatureSetting`에 범위별 승인 정책 계약이 없다. |
| NDR 정책 편집 | 연결 보완 | DetectionCatalog.tsx 137–145행: YAML 수정·재시작 안내. [ndr_policy.py](../../saw/detectors/ndr_policy.py) 65행의 스키마 검증과 356행의 설정 주입 지점 재사용 가능. |
| 사용자 Sigma 관리 | 이미 가능 + 연결 보완 | [service.py](../../saw/detection/service.py) 190–251·395–438행: 생성·버전·시험·독립 승인·사용중단. 초안과 적용 버전의 분리가 필요. |
| 일회성 행위 분석 기준 | 이미 가능 | [BehaviorTab.tsx](../../apps/web/src/pages/inv/BehaviorTab.tsx) 135–141행의 숫자·제외 폼, [definitions.py](../../saw/behavior/definitions.py) 123–161행의 제한된 프로필 검증. |
| 선택 사례·정답 시험 | 연결 보완 + 신규 계약 | API의 조사 선택은 존재하지만 UI는 전체 접근 범위를 요청. 사건/구간/개체별 탐지 정답과 조사 판단 정답의 분리가 필요. |
| 실제 운영 인수 | 현재 검증 불가 | 합성 순수 함수 검증을 운영 환경 정확도·오탐률·LTSC 지원 완료로 해석하지 않는다. |

## 3. 의심 항목 재확인

### 의심 2 — 기본 탐지기 상세

- 기본 탐지기 탭은 이름·ID·단계·자료 종류의 정적 표다(DetectionCatalog.tsx 131–136행).
- API 역시 동일한 4필드만 구성하며 엔진 버전도 이 응답에는 없다(detection.py 173행).
- 시그니처·공격 흐름·NDR 정책에는 이미 설명이 있다. “전체 카탈로그에 설명이 없다”는 판정은 부정확하다.
- 기본 룰 Export에는 코드 탐지기의 버전이 있으므로 API·화면 상세 연결에 재사용한다(exporting.py 59행).

### 의심 5 — Threshold JSON 입력

- [Detections.tsx](../../apps/web/src/pages/Detections.tsx) 96행은 `JSON.stringify(c.threshold)`를 제어 입력값으로 사용한다.
- 매 입력마다 JSON.parse가 성공해야 상태를 갱신하고 실패하면 이전 값을 유지한다.
- 닫는 괄호 삭제 등 유효하지 않은 중간 문자열이 보존되지 않는 구현이다. 실제 브라우저 재현은 수행하지 않았다.
- 같은 파일 148–157행의 예제 편집기는 문자열을 별도 상태로 유지하고 버튼에서 파싱한다. 이 방식을 재사용할 수 있다.
- 일반 숫자·시간·그룹·예외 폼을 기본으로 두고 고급 JSON은 검증·저장 시 검사하는 계약이 필요하다.

### 의심 6 — 조사 판단을 이벤트 정답으로 사용

- service.py 318–321행은 `attack` 조사에서 일치한 모든 이벤트를 TP로, `normal/false_positive` 조사에서 일치한 모든 이벤트를 FP로 센다.
- 332–345행은 범위 내 모든 공격 조사에서 최소 한 건씩 일치해야 공격 탐지 조건을 통과시킨다.
- 따라서 해당 룰과 무관한 공격 조사도 실패 원인이 될 수 있고, 승인된 점검의 패턴 적중도 FP가 될 수 있다.
- API는 조사 ID 목록을 받는다(detection.py 35–36·101–104행). UI는 빈 본문을 전송한다(Detections.tsx 73행).
- 서버 기본 범위는 접근 가능한 최대 500개 조사다(service.py 273–274행). 전체 조사를 모두 시험했다는 보장은 없다.
- 337–338행은 일치 건수가 없는 조사 행을 결과 목록에서 제외하므로 미탐 사례가 비교 화면에 드러나지 않는다.
- 325–330행의 합성 `test_events`는 단일 이벤트 evaluate만 호출하여 임계값·시간창·예외를 시험하지 않는다.
- 322–336행의 예상 일일 경보량은 일치 이벤트 첫/끝 시각을 분모로 사용한다. 전체 관측 기간 기반 예상량이 아니다.

### 의심 7 — 편집 시 적용 승인본 제외

- service.py 246–248행은 새 버전 저장과 함께 탐지 전체 상태를 draft로 바꾼다.
- [auto.py](../../saw/detection/auto.py) 135–154행은 approved/deployed 상태의 최신 버전만 실행한다.
- 재분석 시 편집한 룰의 이전 결과는 정리 대상으로 분류될 수 있다(auto.py 137행).
- [analysis.py](../../saw/core/application/analysis.py) 199–215행은 미검토 new Finding을 제거하고 상태 변경·피드백·사례 연결이 있는 결과는 보존한다.
- 따라서 “편집 직후 모든 과거 결과 삭제”는 아니다. 실제 문제는 기존 승인본이 더 실행되지 않고 재분석에서 미검토 결과가 사라질 수 있다는 점이다.
- [test_phase14_detection.py](../../tests/api/test_phase14_detection.py) 71–73행은 실제 수정 후 v2/draft 전환을 현재 기대값으로 고정한다.
- [test_sigma_auto.py](../../tests/api/test_sigma_auto.py) 61–64행은 current_version을 직접 불일치시켜 자동 실행에서 제외되는 것을 검증한다. 서비스 편집 호출 시험과 구분한다.

## 4. 실행 결과·설명·보존의 추가 차이

- 기본 탐지기 공통 계약은 Finding 목록 반환뿐이다([base.py](../../saw/detectors/base.py) 81–88행).
- analysis.py 163–170행은 탐지기 예외를 로그에 남기고 계속한다. 실패 사유를 조회할 공통 실행 결과가 없다.
- [web.py](../../saw/detectors/web.py) 468·497행에는 작은 모집단·자산 정보 부족 시 빈 목록 반환 경로가 있다.
- Sigma는 건수·정규식·시간·메모리 상한과 실패 시 이전 결과 보존을 구현했다(auto.py 114–122·184–216행).
- 과거 Sigma 시험은 부분·오류 결과를 승인 근거로 거부한다(service.py 385–392행).
- NDR는 필수 정보 부족·처리 상한을 표시한다(ndr_policy.py 324–342행).
- 다만 Sigma/NDR 품질 안내가 `sigma.coverage`와 `ndr.coverage` Finding으로 저장된다. 새 공통 계약에서는 위협 후보 수와 분리해야 한다.
- [sigma_eval.py](../../saw/detection/sigma_eval.py) 242–246행은 일반 선택 필드가 없으면 보통 무일치로 평가한다. 임계값 그룹·시각 누락의 오류 처리(418–427행)와 다르다.
- 필드 부재를 의도적으로 검사하는 exists/null 조건은 유지하되, 필수 수집 조건 미충족과 패턴 무일치를 별도 상태로 기록해야 한다.
- 원본 Discovery는 조사 전체에서 출발지별 404 100건·경로 50개다(web.py 195–200행).
- 생성 Sigma 후보는 300초 내 경로 100개다(service.py 119–122행). 검토 필요 문구만 있고 원본과 달라진 조건의 구조화된 비교는 없다(228행).
- Sigma 시간창은 정확한 span 경계를 포함한다(sigma_eval.py 440행의 `>` 조건).
- 행위 분석은 `[start,end)`이고 NDR는 UTC 고정 버킷이다([calculator.py](../../saw/behavior/calculator.py) 508행, ndr_policy.py 268행). 차이를 오류로 단정하지 말고 명세에 공개해야 한다.
- analysis.py 105–125행은 기존 dedup_key Finding의 메트릭·버전·근거를 덮어쓴다. 실행별 불변 결과 저장은 아니다.
- [behavior/models.py](../../saw/behavior/models.py) 8–18행과 [behavior/worker.py](../../saw/behavior/worker.py) 142–168행은 범위·적용 프로필·방법론·원본 manifest·결과 버전·해시를 저장하는 재사용 가능한 선례다.

## 5. 실제 독립 합성 probe

명령 형태는 `.venv/Scripts/python.exe -B -c <인메모리 합성 코드>`이며 한 번 실행하여 exit 0을 확인했다.
`compile_rule`, `evaluate`, `apply_threshold`, `calculate`를 호출했고, 후보 생성은 service.py에서 해당 순수 함수 두 개만 AST로 추출했다.
DB 세션·컨테이너 초기화·dotenv·서비스·파일 쓰기 없이 예약 시험 IP와 직접 만든 이벤트를 사용했다.

| probe | 실제 결과 | 해석 범위 |
|---|---|---|
| 단일 이벤트 시험과 임계값 | evaluate=True, 같은 이벤트에 count_gte=2 적용 시 0건 | 단일 이벤트 예제 성공은 집계 조건 성공을 보장하지 않음. |
| 선택 필드 미수집 | 상태 코드 조건에 빈 이벤트를 주면 False | 일반 선택 조건에서 미수집을 오류로 표시하지 않는 동작 확인. |
| Sigma 정확한 시간 경계 | 정확히 60초 떨어진 두 이벤트를 60초 창에 넣으면 2건 | 현재 창의 양 끝 포함 동작 확인. |
| Discovery 후보 생성 | group_by=src_ip, timespan_sec=300, count_gte=100, distinct_field=url_path | 원본의 100건·50경로·조사 전체 조건과 다름. |
| 행위 결과 계약 | methodology.window=`[start, end)`, 적용 profile 존재, 작은 입력 truncated=False | 저장 가능한 방법론·기준의 반환을 확인. |

원본 Discovery의 전체 실행, UI 키 입력, 실제 승인·적용·복구, 데이터베이스 이관을 이 probe로 검증했다고 주장하지 않는다.
대량 자료 성능, 취소 경쟁, 운영 검색 저장소 경계 및 실제 정확도는 이 실행의 검증 범위 밖이다.

## 6. 승인 검토용 정책·버전 설계

1. 기존 탐지기 ID와 구현을 유지하고 `DetectorSpec` 계약을 추가한다.
2. 엔진/조건 스키마 버전, 지원 기록 의미, 필수·선택 필드, 그룹 키·단위·시간창·경계·기본값·허용 범위·제외·한도·예제를 한 정의에서 공유한다.
3. API·화면 폼·실행 검증·문서가 같은 정의를 사용한다. Python 및 임의 실행 코드는 편집 대상으로 제공하지 않는다.
4. 불변 `PolicyVersion`과 범위별 `PolicyBinding`을 두고 그룹 기본 → 관계사 → 장비 순서로 실제 적용값을 결정한다.
5. 예외에는 관계사·장비·망·조건·사유·작성자·유효기간을 둔다. 일회성 분석 프로필은 공용 정책과 분리한다.
6. 기존 `DetectionVersion`을 재사용하고 초안·승인·활성 버전 포인터를 분리한다. 저장은 초안만 바꾸고 기존 활성본은 유지한다.
7. 해당 버전의 최초 작성자와 모든 편집 기여자를 승인자에서 제외한다. 시험·정답·정책·엔진 해시가 승인 당시와 일치해야 한다.
8. 승인과 적용을 분리하고 적용 시 예상 활성 버전·해시를 비교한 뒤 원자적으로 포인터를 교체한다.
9. 실행 시작 시 적용값·각 값의 출처·버전·해시를 고정한다. 실행 도중 초안·정책 변경을 섞지 않는다.
10. 복구는 검증된 이전 승인본으로의 새 활성화 이력이다. 이전 분석 결과를 소급 덮어쓰지 않는다.
11. [content_packages/service.py](../../saw/content_packages/service.py) 285–320행의 지문 재검증·독립 적용·동시 변경 차단과 362–432행의 복구를 확장해 재사용한다.
12. 불변 분석 실행과 탐지기별 결과에 범위·원본 manifest/data_epoch·파서/정규화/엔진/룰/정책 버전·한도·처리 건수·상태·사유를 저장한다.
13. 완료 일치/완료 무일치/부분/자료 부족/해당 없음/비활성/실패/취소를 구분하고 품질 안내를 위협 후보에서 분리한다.
14. 기존 Finding ID·분석가 기록은 보존하면서 최신 표시와 과거 실행 보관을 분리한다.

이관에서는 기존 설정을 현재 의미 그대로 기준 스냅샷으로 보존하며, 새 독립 승인 완료로 표시하지 않는다.
기존 시험의 TP/FP는 `legacy_investigation_verdict` 방식으로 남기고 새 이벤트 정답으로 승격하지 않는다.
과거 실행에서 알 수 없는 정책·엔진·자료 버전은 미기록으로 두며 임의로 현재 버전을 채우지 않는다.

## 7. 시험 정답 계약과 인수 기대값

- `TestRun`을 유지하되 버전·해시가 있는 선택 사례, 고정 자료 범위, 기대 정답과 연결한다.
- 판정 단위는 이벤트/구간/개체/순서·상관으로 명시하고 중복 정책·분모·필수 필드·허용 범위를 저장한다.
- 패턴 정답은 expected_match / expected_no_match / unlabeled로 구분한다.
- 조사 판단 정답은 실제 침해/공격 시도/정상·승인 활동/오탐/보류/자료 부족의 별도 축이다.
- 승인된 탐색은 패턴 적중이면서 승인 활동일 수 있다. 조사 전체의 공격 라벨을 이벤트 TP로 확장하지 않는다.
- 정답이 없으면 품질 수치를 만들지 않는다. 관련 없는 공격 조사는 FN 분모에 넣지 않는다.
- 미일치·보류·미탐 사례도 선택·표시하고 탐지된 Finding만 시험집합으로 만들지 않는다.
- 단일 이벤트 조건 시험과 시간창·고유값·예외·순서·상관 시험을 분리한다.
- 중도 실패·잘림·정답/자료/권한/룰 버전 변경이 있으면 품질 승인을 막는다.

| 인수 | 추가·변경할 핵심 기대값 | 기존 시험 기반 |
|---|---|---|
| T10 | 예외·필수 필드/기준선 부족·상한·취소를 각각 저장. 실패/미수집을 무일치로 바꾸지 않음. 품질 안내는 위협 수 제외. | [test_sigma_auto.py](../../tests/api/test_sigma_auto.py), [test_sigma_contract.py](../../tests/unit/test_sigma_contract.py), [test_ndr_policy.py](../../tests/unit/test_ndr_policy.py), [test_behavior_jobs.py](../../tests/api/test_behavior_jobs.py) |
| T11 | 임계값 직전/도달, 정확한 시간 경계, 동률 순서, IPv6/NAT·조직 분리, 중복·단위, distinct 누락을 엔진 명세에 맞게 검증. | [test_scenario_boundaries.py](../../tests/unit/test_scenario_boundaries.py), [test_behavior_calculator.py](../../tests/unit/test_behavior_calculator.py), test_sigma_contract.py |
| T12 | 상세→정책 초안→선택 사례·전후 비교→독립 승인→별도 적용→복구를 UI/API/DB/워커까지 연결. 오래된 시험/해시로 승인 불가. | test_phase14_detection.py, [test_content_packages.py](../../tests/api/test_content_packages.py), [test_detection_scope_boundary.py](../../tests/api/test_detection_scope_boundary.py) |
| T13 | v2 초안 생성/시험 실패에도 활성 v1 실행 유지. 진행 중 실행은 고정 버전 사용. 후보 차이 표시. 불완전 JSON·붙여넣기·검증·저장 회귀. | 현재 버전 전환 기대값 변경, [DetectionCatalog.test.tsx](../../apps/web/src/pages/DetectionCatalog.test.tsx)와 새 입력 회귀 |
| 8절/T16 | 공격 조사 내부 정상 이벤트를 자동 TP로 세지 않음. 승인 스캔의 적중과 판단 분리. unlabeled·미탐 사례 포함. 부분 시험 승인 불가. | 기존 lifecycle 시험을 명시적 사례 정답으로 전환 |

기존 시험이 통과해도 새 계약이 충족됐다는 뜻은 아니다. 특히 draft 전환·조사 라벨 기반 시험은 기존 기대값 자체를 검토해야 한다.
본 문서는 P0 감사·설계 검토 자료이며 P2 구현 완료 또는 운영 승인 자료가 아니다.
