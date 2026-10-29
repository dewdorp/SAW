# 관계사 분석 P0 — 확인 기록·보고·Excel·Golden 감사

- 기준: 2026-10-20, 부모 작업에서 확인한 HEAD `4072e9d`의 현재 구현.
- 범위: 통합 요구사항 9–14절, 의심 항목 8, 인수 T14–T18.
- 상태: 승인 검토용 P0 감사·설계 제안. 제품 기능·DB·검색 저장소·배포 변경은 수행하지 않았다.
- 시험 구분: root가 선택 시험을 별도로 실행했다. 수치·환경·명령은 [중앙 검증 영수증](../../docs/verification/affiliate-p0-validation-20261020.json)을 참조한다. 이 감사 담당은 자체 시험을 실행하지 않았다.
- 코드와 기존 시험을 읽은 결과이며, 과거 배포 성공을 이번 기능 인수 성공으로 사용하지 않는다.

## 1. 요구사항별 현재 상태

| 항목 | 분류 | 현재 구현과 남은 연결 |
|---|---|---|
| Check·메모·종결 연결 | 이미 가능 / 연결 보완 | 질문·판단·근거·범위, 변경 시 새 행, 이전 기록 보존. 구조화된 행위 판단·영향 판단 축은 확장 필요. |
| 상황별 질문·후속확인 | 이미 가능 / 연결 보완 | guidance와 behavior가 후속 질문·필요 자료를 제시. 담당 조직·담당자, 회신 수신/검증 완료, 후속항목별 이력은 추가 필요. |
| 저장 행위 결과 | 이미 가능 | BehaviorResult 버전·SHA, 결과 범위와 선택 근거, Check·종결·Experience의 정확한 결과 참조. |
| 승인 보고서 고정 | 연결 보완 / 신규 필요 | 계산 결과는 고정되지만 HTML은 현재 active Check를 다시 결합. 보고서 자체의 승인 버전은 없음. |
| 단일/다중 조사 XLSX | 신규 필요 | Golden 목록 CSV는 있으나 업무 XLSX 생성기·API·화면·작성 의존성은 확인되지 않음. |
| Experience→Golden | 이미 가능 / 연결 보완 | 별도 채택, 기여자와 다른 검토자, 해시·버전·접근권한 확인. 관계사·장비·의미 계약 확장 필요. |
| train/dev/holdout | 이미 가능 / 연결 보완 | 사건군별 분할과 입력/정답 출력 분리. 평가 이력·이중 정답 스키마·파일명 누출 방어 추가 필요. |
| 외부 반출 승인 | 신규 필요 | 목적·수신처·사용 조건·변환본·최종 패키지를 묶는 독립 승인 모델 없음. |
| 가명처리·변환 검증 | 신규 필요 | 기존 마스킹은 비밀값·일부 개인정보 가리기. 관계를 유지하는 일관된 가명처리와 의미 검증은 별도 기능. |
| 대량 출력 작업·보존 | 연결 보완 / 신규 필요 | Job 취소·진행·시도 번호 재사용 가능. Export는 현재 동기 메모리 생성이며 생성물 보존·만료·다운로드 재검증 추가 필요. |

## 2. 기존 기능과 정확한 연결 지점

- [models.py](../../saw/storage/models.py) 353행: Check는 질문·판단·근거·scope와 supersedes_id를 갖고 이전 기록을 보존한다.
- [checks.py](../../saw/core/application/checks.py) 226·261·299행: 작성·새 버전 변경·취소를 감사 기록과 연결한다. 단순 열람을 검증 완료로 기록하지 않는다.
- [guidance.py](../../saw/core/application/guidance.py) 79행: FollowUp은 target, due_at, needed_data, items, priority를 이미 갖는다.
- 같은 파일 82행의 due_at은 현재 문자열이다. 날짜 검증과 미지정 기한의 집계 계약은 추가해야 한다.
- [Checks.tsx](../../apps/web/src/components/Checks.tsx) 108행: 현재 CheckDialog에서 행위 답변 상태와 후속확인을 편집한다.
- [behavior/models.py](../../saw/behavior/models.py) 9행: BehaviorResult는 조사별 version, Job, result JSON, result_sha256을 저장한다.
- [behavior/service.py](../../saw/behavior/service.py) 155·174행: Check의 result ID/SHA·metric·범위·선택 근거를 저장 결과와 대조한다.
- 같은 파일 196행: 종결 시 정확한 Check/결과 ID·SHA·version과 작성 기여자를 보존한다.
- [experience.py](../../saw/knowledge/experience.py) 144·175행: 편집 초안과 approved_data를 분리하며 Experience 승인과 Golden 채택은 별개다.
- [Golden.tsx](../../apps/web/src/pages/Golden.tsx) 19·116행: 기존 경험 검토와 SOC 지식 목록에서 Golden 검토·선택 내보내기를 제공한다.
- [golden_models.py](../../saw/knowledge/golden_models.py) 12·20·26·35행: Family/Member/Blob/Version을 이미 분리하므로 새 독립 골든셋 작성 업무를 만들 필요가 없다.
- [golden.py](../../saw/knowledge/golden.py) 336·449행: 수정은 새 초안이며 채택 검토자는 모든 기여자와 달라야 한다.
- 같은 파일 390·420행: Case와 보존된 FamilyMember의 전이적 사건군이 split을 고정한다. 같은 IP로 사건군을 만들지 않는다.
- 같은 파일 547행: 채택 상태·현재 검토자 권한·정확한 경험 승인 이력·분할·현재 원천 조사 접근권한을 검사한다.
- 같은 파일 570·603행: agent 입력과 evaluator 정답을 분리하고 agent bundle에는 정답 파일을 넣지 않는다.

## 3. 의심 항목 8 — 필드 허용 목록의 실제 손실

1. [guidance.py](../../saw/core/application/guidance.py) 184행은 org_unit을 범위에 넣는다.
2. [golden.py](../../saw/knowledge/golden.py) 34·188행의 SCOPE_KEYS 투영은 org_unit을 허용하지 않아 Golden 입력에서 제거한다.
3. 같은 파일 35행 EVENT_KEYS에는 관계사·장비·망/NAT·로그 종류·측정 의미·정규화 버전의 공통 계약이 없다.
4. [behavior/worker.py](../../saw/behavior/worker.py) 16·56행도 Golden의 EVENT_KEYS를 공유하므로 Golden Export만 수정하면 저장 결과 단계의 누락이 남는다.
5. worker 57–92행의 selected_evidence.source에는 파일·파서·원문 위치·관측 메타데이터가 있다.
6. golden 254–257행은 event와 known_at만 event blob에 복사하므로 위 source 객체를 직접 전달하지 않는다.

모든 버전이 사라지는 것은 아니다. [guidance.py](../../saw/core/application/guidance.py) 135–140행은 parser_version과 processing run digest를 보존한다.
[behavior/service.py](../../saw/behavior/service.py) 220–224행도 methodology/profile·결과 SHA·source_manifest를 Golden 관측에 고정한다.
따라서 기존 버전 필드를 재사용하고 관계사·장비·자료 의미·정규화/엔진/정책 버전을 공통 스키마로 확장해야 한다.

## 4. 현재 보고서와 공유 정책의 경계

[behavior/router.py](../../saw/behavior/router.py) 36–46행은 저장 계산 결과를 읽은 뒤 현재 active Check 목록을 다시 결합한다.
Check를 수정·취소하면 동일한 결과 URL의 분석가 판단 부분이 달라질 수 있다. 계산 결과 불변과 승인 보고서 불변은 구별해야 한다.
[models.py](../../saw/storage/models.py) 341–350행의 Briefing도 수정 문구만 저장하고 나머지는 재생성한다.
[briefing.py](../../saw/core/application/briefing.py) 207·282·308행은 현재 자료·Check 요약·생성시각을 사용한다.

공유 Check는 원천 조사 전체를 열지 못해도 제한된 확인 정보를 공유하는 기존 정책이다.
[checks.py](../../saw/core/application/checks.py) 378행 team_for는 현재 조사 권한을 확인하고 원천 권한은 can_open에만 반영한다.
같은 파일 423행 evidence_view는 일반 investigation.read 역할을, 457행 cite는 인용 대상 조사의 쓰기 권한을 검사한다.
[기존 공유 시험](../../tests/api/test_checks.py) 122·156·193행이 이 동작을 명시적으로 검증한다.
이를 무조건 새 취약점으로 단정하지 않는다. 요구사항 3의 동일한 원천 조사 ACL 원칙으로 변경하는 정책 결정이 필요하다.
제안 계약은 공유 목록·근거·인용·후속 결과 다운로드에 원천 조사 권한과 관계사/망 문맥을 함께 적용하는 것이다.
관계사 분류를 접근권한으로 사용하거나 관리자에게 분석 권한을 자동 추가하지 않는다.
[authz.py](../../saw/core/security/authz.py) 9·39·63행의 역할 AND 조사 멤버십 구조를 재사용한다.

## 5. P3 제안 — Check·후속확인·보고·XLSX

- 기존 Check에 종속된 후속항목 ID·revision을 두고 현재 follow_up 입력을 확장한다.
- 담당 관계사·부서·담당자·기한은 null을 허용한다. 미지정 기한을 기한 초과로 집계하지 않는다.
- 회신 수신과 검증 완료를 다른 상태로 저장하며 회신 근거·검증자·시점·변경 사유를 남긴다.
- 회신 수신만으로 Check를 answered로 바꾸지 않는다. 미확인을 남긴 종결과 영향 없음도 구별한다.
- 관측 사실·장비 조치·행위 판단·영향 판단을 별도 축으로 고정하고 각 판단에 근거·시점을 연결한다.
- ReportVersion 또는 동등한 Briefing revision snapshot에 결과 IDs/SHA, 정확한 Check IDs/내용 hash, 후속항목 revisions를 저장한다.
- scope hash, 관계사/장비 문맥, 필터·시간대·자료 상태·분모·단위·표본·잘림·버전·마스킹 정책도 같은 snapshot에 포함한다.
- HTML과 XLSX는 그 snapshot을 읽는다. 승인 이후 자료나 Check 변경은 새 보고서 버전으로 처리한다.
- 기존 작업대·ChecksTab·조사 목록/현황판에 Excel 진입점을 추가하고 같은 서버 계산 경로를 사용한다.
- XLSX는 요약·상세·후속확인·통계·시간 추이·근거·적용 기준·범위/한계 시트를 제공한다.
- 원문·메모·식별자는 명시적 문자열 셀로 기록한다. 자동 수식·DDE·외부 링크·매크로 생성을 금지한다.
- 안전한 앱 계산식과 원문 문자열을 구분하고 한글·긴 ID·시간대·차트·필터·틀 고정·인쇄영역을 검증한다.
- 행/셀 상한은 분할·선택 근거·별도 묶음과 생략 목록으로 처리한다. 다른 단위나 다른 회사의 고유 IP 합계를 혼동하지 않는다.
- XLSX 작성 의존성은 아직 선정·설치하지 않았다. 버전·라이선스·LTSC·오프라인 매체 검증 후 잠금 파일에 반영한다.

## 6. P4 제안 — Golden v2와 독립 반출 승인

- 기존 GoldenVersion/Blob/Family를 유지하고 detection_truth와 investigation_truth를 명시적으로 분리한다.
- 탐지 정답은 이벤트/구간/개체·판정 단위·중복 정책을, 조사 정답은 적절한 확인·해석·판단 한계를 갖는다.
- 당시 이용 가능한 입력과 후일 확정 사실을 나누며 interpretation_only/full_recalculation 용도를 표시한다.
- v1 blob·승인본·hash를 소급 재작성하지 않는다. 확장 필드는 새 버전에서만 추가하고 과거 미확인 값을 추정하지 않는다.
- Golden 품질 승인과 별도로 ReleaseVersion을 추가한다. 사례 IDs/hash, split, 목적·수신처·사용 조건을 고정한다.
- 변환 프로파일·버전·재제공 권리 확인·검증 결과·전체 파일 목록/크기/hash·최종 패키지 digest를 승인 대상에 포함한다.
- 작성·편집 기여자와 다른 권한자가 정확한 반출 버전을 승인한다. 승인 대상 내용 변경 시 재승인한다.
- 반출 승인 permission은 품질 승인과 구분하고 기존 선임/매니저 정책 안에서 배정한다.
- train/dev는 허용된 입력·정답·근거를 담고 holdout-input과 내부 evaluator 정답은 별도 생성물로 관리한다.
- holdout 정답을 같은 ZIP의 다른 폴더나 숨김 시트에 넣지 않는다. 반복 평가 실행 이력을 남긴다.
- README·필드 사전·방법론·JSON Schema·데이터셋 버전·전체 manifest·한계를 포함한다.
- 실제 기록된 도구 명세·인자·응답이 없으면 근거 해석 평가용으로 표시하며 실행 기록을 만들어내지 않는다.

메타데이터도 입력 누출 검사 대상이다. [behavior/service.py](../../saw/behavior/service.py) 89·92행의 title/display_name이 223행에서 Golden 관측으로 복사된다.
라벨 포함 파일명·제목·내부 URL·검토자 정보·원문 내 정답 단서를 평가 입력으로 내보내지 않도록 용도별 투영이 필요하다.
[golden.py](../../saw/knowledge/golden.py) 51행과 [masking.py](../../saw/core/security/masking.py) 100–107행의 기존 마스킹만으로 가명처리가 완료되지 않는다.
관계사·장비·IP·계정·도메인을 문맥에 맞게 일관되게 변환하고 대응표는 내부에만 보관한다.
변환 전후 참조·통계·순서·업무시간/요일·CIDR 등 정답 근거를 검증한다. 보존할 수 없는 사례는 제외하거나 재검토한다.
변환본의 근거 ID·참조·hash를 함께 재생성하며 해시를 발행자 인증이나 자동 반출 허가로 표현하지 않는다.

## 7. 작업·다운로드·보존 계약

현재 [golden.py](../../saw/knowledge/golden.py) 28–31·579–625행은 최대 100사례/20MiB를 동기 메모리에서 생성한다.
[Job 모델](../../saw/storage/models.py) 184–205행의 idempotency·attempt·취소·진행 상태와 기존 worker/object store를 재사용한다.
다중 조사 Export는 단일 Job.investigation_id 외에 전체 원천 조사 연결을 관리하고 모든 조사 권한을 검사한다.
생성 시작·최종 게시·다운로드 때 현재 권한, 승인 유효성, 사례/근거/패키지 hash를 확인한다.
취소·실패·미승인 파일은 다운로드할 수 없게 하고 청크별 취소·진행률·목록 대조·재시도 경계를 둔다.
만료·철회 시 접근을 차단하고 임시/실패/만료 파일을 안전하게 정리하되 승인·감사·manifest 이력은 유지한다.
대량 출력 큐·동시 작업·파일 수·메모리/시간 한도를 제한한다. 상한에 도달한 작업을 전체 완료로 표시하지 않는다.
[golden.py](../../saw/knowledge/golden.py) 329–332행의 원천 재검증은 behavior 관측에 특화돼 있다. guidance 관측의 source 참조 검증도 같은 계약으로 정리해야 한다.

## 8. 인수 시험 대응표와 미검증 경계

| 인수 | 기존 시험 경로·행 | 추가할 시험 |
|---|---|---|
| T14 | [test_behavior.py](../../tests/api/test_behavior.py) 24·50행, [test_behavior_report.py](../../tests/unit/test_behavior_report.py) 55행 | 동일 scope/result/check revision의 통계·원문·HTML·XLSX, 승인 보고서 불변, 재시작, 다중 조사 ACL. |
| T15 | [test_golden.py](../../tests/api/test_golden.py) 137행, [test_behavior_report_http.py](../../tests/api/test_behavior_report_http.py) 9행 | 실제 XLSX 셀 유형·한글/긴 ID·시간·차트·필터·잘림 및 formula/externalLink/DDE/macro 부재. CSV 시험을 XLSX 검증으로 대체하지 않음. |
| T16 | [test_golden.py](../../tests/api/test_golden.py) 85·97행 | 승인 스캐너의 탐지 적중/정상 활동 정답 동시 보존, 품질 승인만 받은 사례의 외부 반출 거부. |
| T17 | [test_golden.py](../../tests/api/test_golden.py) 59·109·122·177·229·301행 | 파일명/제목/검색 정답 누출, holdout 이력, 생성 후 권한 철회, 다운로드 재검사, 원천 근거 검증 일관성. |
| T18 | 현재 전용 가명변환·외부 승인 시험 없음 | 변환 후 의미·통계·참조/hash 보존, 내부 대응표 제외, 승인 artifact와 최종 bytes 일치, 내용 변경 시 승인 무효. |

UI 회귀는 [Golden.test.tsx](../../apps/web/src/pages/Golden.test.tsx) 42·59·66·75행과 [Checks.test.tsx](../../apps/web/src/components/Checks.test.tsx) 11·28·68행을 확장한다.
실제 XLSX·외부 반출, PostgreSQL/OpenSearch 동시성, 백만 건/공동 부하, LTSC와 새 의존성 포함 설치/업데이트는 현재 미검증이다.
구현 승인은 P3/P4 단계별 UI·API·저장·worker·시험까지 포함해야 하며 이 문서 작성만으로 해당 기능이 완료된 것은 아니다.
