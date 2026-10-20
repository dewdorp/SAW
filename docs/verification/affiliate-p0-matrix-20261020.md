# 통합 개선 P0 요구사항·코드·시험 대응표
기준: 2026-10-20 / 4072e9d / F:/codex/SAW-Claude-main.
이 문서는 현재 기능과 새 요구 사이의 차이다. 아래 계획된 인수 시험은 아직 PASS가 아니다.
[설계·단계별 계획](../plans/affiliate-soc-design-20261020.md) · [실행 영수증](affiliate-p0-validation-20261020.json)

## 1. 점검한 버전과 실제 실행

- 시작 브랜치 codex/updater-stabilization-20261019, HEAD4072e9d, 작업 트리 깨끗함.
- 검토용 브랜치 codex/affiliate-p0-20261020을 같은 HEAD에서 만들었다. 제품 코드는 변경하지 않았다.
- 게시 매체 source26f5d1a/schema0014와 HEAD 차이는 문서뿐이다.
- 대표5개 서버 코드와 빌드 UI index.html은 작업본·게시 ZIP 해제본·합성 설치본의 SHA가 모두 같았다.
  전체 payload 재검증이나 JS/CSS 전 파일 대조가 아니므로 그 범위로 확대하지 않는다.
- 예상 운영 경로 C:/SAW/app/saw/storage/models.py 및 D:/SAW-0.1.0/release-manifest.json은 현재 호스트에서 찾지 못했다.
  다른 PC/다른 경로의 운영 설치 상태는 미검증이며 운영 자료/비밀값을 찾기 위해 탐색하지 않았다.
- 새 요구의 실제 기능·매체는 아직 없다. 기존 v0.1.0-pilot.20261019는 이번 제안의 배포본이 아니다.

| 이번 실행 | 결과 | 의미와 제한 |
|---|---|---|
| 서버 선별 회귀 30파일 | 547 PASS, 133.33초, 경고1 | 기존 통계·행위·룰·Golden·파서/Check·근거 동작, 임시 SQLite |
| 서버 추가 회귀 7파일 | 103 PASS, 54.16초, 경고1 | Sigma·시나리오 경계·한글CSV·데이터 정확성·기존 ACL·대용량 수집 |
| 화면 vitest 순차 실행 | 177 PASS / 31파일, 118.94초 | DOM 자동 시험, 실제 브라우저 사용·새 화면 인수가 아님 |
| TypeScript | exit0 | 현재 코드 형식 검사, 새 UI 빌드/배포가 아님 |
| 합성 파서 함수 probe | CSV in100/out900, Zeek out100/in900 | 같은 orig_bytes100/resp_bytes900의 방향 차이 재현 |
| 합성 Sigma 함수 probe | 조건 일치와 2건 임계값 결과 다름; 정확60초 포함 | 선택자만의 시험과 실제 임계값 계산을 구분할 근거 |

서버 경고는 기존 Starlette/httpx 지원 변경 예고이다.
화면은 기존 React Router future 및 Admin act 경고를 출력했다.
전체 서버 suite나 native PG/OpenSearch·LTSC·새 설치/업데이트·백만 건 부하를 이번에 재실행하지 않았다.
상세 명령과 로그 경로는 영수증을 따른다.

## 2. 먼저 확인하라고 한 8개 항목

| 번호 | 현재 확인 | 근거 | 필요한 변경 |
|---|---|---|---|
| 1 org_unit 전달 | 저장/생성은 있음, 응답·수정·목록/화면 누락. guidance에는 있음 | models.py:108; routers/investigations.py:39,70; guidance.py:184 | P1 기존 필드 연결 및 안정 ID 이관 |
| 2 기본 탐지 설명 | built-in 표는 id/title/stage/data_sources. 시그니처·시나리오·NDR 설명은 있음 | DetectionCatalog.tsx:131; routers/detection.py:173; exporting.py:41 | P2 공통 DetectorSpec 상세·실제 기준 |
| 3 CSV 출처 | 일반 연결 CSV를 zeek_conn으로 분류. product=csv·ext는 남음 | parsers/structured.py:234–242; registry.py:101 | P1 출처와 공통 연결 어댑터 분리 |
| 4 FW 탐지 누락 | 일부 엔진은 ext.zeek.duration/state/service 전용 | detectors/network.py:135,165,290 | P1 의미 검증된 공통 필드와 preflight |
| 5 JSON 편집 | 입력마다 JSON.parse 성공 때만 상태 갱신 | Detections.tsx:96 | P2 입력 문자열 보존·저장 시 검증 |
| 6 룰 시험 정답 | 조사 attack/normal 판단으로 적중 이벤트 TP/FP 계산, UI 선택 없음 | detection/service.py:273,318–345; Detections.tsx:73 | P2 명시적 사례/이벤트·구간 정답 및 unlabeled |
| 7 승인본과 초안 | 편집→전역 draft, 자동 실행 승인본 제외. 재분석에서 일부 미검토 결과 정리 | service.py:246; auto.py:135; analysis.py:199 | P2 active/draft 분리, 실행별 보존 |
| 8 Golden 문맥 | org_unit 투영 탈락, 장비/의미 필드 없음. 기존 파서/processing/methodology 일부는 보존 | golden.py:34,188,254; behavior/worker.py:56 | P4 버전 있는 허용 목록, 문맥/근거 참조 확장 |

이 표의 8개는 동일한 심각도의 버그 목록이 아니다.
기존 설계에서 의도된 동작도 새 요구에 맞춰 변경해야 한다.
세부 경로·행·재현·한계는 아래 3개 감사 문서에 있다.

- [관계사·정규화·장비·성능](affiliate-normalization-audit-20261020.md)
- [탐지 설명·정책·정답 시험](affiliate-detection-audit-20261020.md)
- [Check·보고서·Excel·Golden·반출](affiliate-golden-audit-20261020.md)

## 3. 전체 요구 대응

“이미 가능”은 해당 세부 기반에 대한 판정이다. 해당 절 전체 완료를 뜻하지 않는다.
“현재 검증 불가”는 이번 환경/실행으로 입증하지 않았다는 뜻이며 개발 작업을 막는 이유가 아니다.

| ID / 요구 범위 | 상태 | 재사용 근거·기존 시험 | 보완/새 인수 및 단계 |
|---|---|---|---|
| R0 서비스/의심IP 없이 시작 | 연결 보완 | 조사 title 생성·Evidence 업로드·자동 분석; phase1_foundation/phase6_network | 관계사·장비만으로 FW 전체 흐름 T01/P1 |
| R1 현재 코드/매체/변경 점검 | 이미 가능 | git/허용된 public source hash 직접 대조 | 운영 설치는 확인 못함; 이 표/영수증/P0 |
| R2 사용자/MFA/ACL/원본 보존 | 이미 가능 | authz·require·provenance; phase1_foundation/provenance | 새 API/Job/Export에도 전파 T02,17,19/P1–5 |
| R2 LTSC/폐쇄망/저사양 | 현재 검증 불가 | 기존 Windows 패키지·업데이터, 실제 검증 이력 | 새 매체와 깨끗한17763·16GB 공동부하 T20/P5 |
| R3 org_unit CRUD/표시/조회 | 연결 보완 | Investigation.org_unit·guidance context | 안정 ID/legacy mapping 및 UI/필터/Export T01–03/P1 |
| R3 장비·관측·수집·자료 귀속 | 신규 필요 | Evidence/EvidenceFile·ProcessingRun | DeviceProfile/source context/혼합 행 귀속 T03/P1 |
| R3 원천 ACL/자산·공유/망 경계 | 연결 보완 | 조사 권한, 자산 company, shared Check | asset lookup/Check 인용/예외에 범위·승인 T02/P1–4 |
| R4 원본과 파서 추적 | 이미 가능 | registry raw_ref/parser/version; provenance 시험 | 새 문맥·정규화 버전 추가, 과거 값 보존 T14,17/P1 |
| R4 공통 의미·값 상태 | 신규 필요 | CES·UA missing/empty·명시 action | 전 필드 provenance·시간·단위·조치 프로필 T04–09/P1–2 |
| R4 CSV/Zeek 의미 호환 | 연결 보완 | structured/network/ndr parsers; text_ingest/data_accuracy | 바이트 방향·duration/action·출처 어댑터 T04–05/P1 |
| R5 분석 가능·실행 상태 | 연결 보완 | behavior execution/quality, Sigma bounded runner, NDR coverage | 기본 탐지 예외 ledger, 품질 Finding 분리 T10/P1–2 |
| R5 baseline·수집 범위 | 연결 보완 | 공유 baseline fail-closed, peer/temporal | 승인 비교 자료·기간/범위 없으면 제한 T09–10/P1–2 |
| R6.1 FW | 연결 보완 | network scan/beacon/transfer/long-lived | 세션 생애주기/누적/거부/방향 T01,04,05,11/P1 |
| R6.2 WAF | 연결 보완 | HTTP/behavior UA·중복·프로필; behavior_* | 요청vs적중, Edge/Origin/forwarded 신뢰 T06/P2 |
| R6.3 IPS | 연결 보완 | Suricata parser/alert detector; phase6_network | detect/drop/reset·mode·packet, 반복/확산/다양패턴/후속통신 T07/P2 |
| R6.4 DDoS | 신규 필요 | 기존 event store/Job 재사용 | 출발지 없는 interval/alert, 단위·평균/peak·급증/반복/지속/집중/완화전후 T08/P2 |
| R6.5 NDR | 연결 보완 | flow/HTTP/PCAP/프로토콜 분석; ndr_policy | 경보vs전체흐름·센서손실·공통 연결 T09/P2 |
| R6 제품별 실제 매핑 | 현재 검증 불가 | 합성 공통 입력/일부 지원 파서 | 승인 샘플·필드 사전별 검증, 미검증 명시/P1–5 |
| R7 카탈로그 설명 | 연결 보완 | catalog/export·signatures/scenarios/NDR | DetectorSpec UI/계산/예제 공통화 T12/P2 |
| R7 정책 폼/고급 JSON | 연결 보완 | Behavior 숫자 폼, NDR schema, custom rule editor | 부분 JSON 보존, 검증된 정책/허용 범위 T13/P2 |
| R7 범위·독립 승인·적용·복구 | 연결 보완 | DetectionVersion, content_packages 승인·복구 | org/device binding·active/draft·contributors T12–13/P2 |
| R7 실행 당시 버전 보존 | 연결 보완 | BehaviorResult 불변값, ProcessingRun | 공통 AnalysisRun/FindingSnapshot T13–14/P1–2 |
| R8 선택 사례·탐지 정답 | 연결 보완 | TestRun/investigation_ids API | UI 선택·event/window/entity truth·분모·unlabeled T11,16/P2 |
| R8 판단 정답 분리 | 신규 필요 | investigation verdict/Golden answer | detection_truth vs investigation_truth·미탐 사례 T16/P2,4 |
| R9 작업대 순서·드릴다운 | 연결 보완 | Statistics/Behavior/Raw/RequestCompare/Checks | scope/단위/품질/제한 일치 T01,14/P1–3 |
| R9 후속확인 | 연결 보완 | guidance FollowUp·Check revision | 담당/기한 null·회신/검증 상태·근거 이력 T14/P3 |
| R9 장비 간 관계 | 연결 보완 | relation/scenario·entity roles | org/망/NAT/ID/시각 품질, 확인vs후보 T02,11/P2 |
| R10 근거 보고 | 연결 보완 | Behavior A4 standalone HTML | Check revision까지 고정한 ReportVersion T14/P3 |
| R10 백서 참고 | 이미 가능 | 이번 PDF5.2/5.3/A.2·그림5/표7 확인 | 웹 참고프로필 한정·측정 근거로만 사용/P2–3 |
| R11 XLSX 3진입점/8시트 | 신규 필요 | 기존 통계·선택 근거·CSV 방어 | 실제 작성기, snapshot·분모·차트·긴ID T14–15/P3 |
| R11 XLSX 입력/용량 안전 | 신규 필요 | masking/escape/Job 기반 | 문자열 강제·외부링크/매크로 금지·분할/생략 T15/P3 |
| R12 기존 경험→Golden | 이미 가능 | Check/closure/Experience/GoldenVersion/Blob | 별도 작성업무 없이 v2 문맥 확장 T16–17/P4 |
| R12 split/입력-정답 분리 | 연결 보완 | GoldenFamily 사건군·agent/evaluator 분리 | dual truth·메타데이터 누출·holdout 이력 T17/P4 |
| R13 용도별 외부 패키지 | 연결 보완 | agent-input/evaluator-answer/evidence bundle | train/dev/holdout별 artifact·schema/README·자료완전성·v1/v2·모델 변환 T17–18/P4 |
| R13 독립 반출 승인 | 신규 필요 | 현재 Golden 채택/ACL 검증 | ReleaseVersion·목적/수신처/조건·exact bytes T16–18/P4 |
| R13 가명처리·재검증 | 신규 필요 | 현재 비밀값 마스킹 | 일관 가명·내부 대응표·정답 의미/참조 검사 T18/P4 |
| R13 취소/철회/다운로드 | 연결 보완 | Job lease/cancel·object store·현재 Export ACL | 전체원천 ACL·artifact 완료/철회/만료 T17–19/P4 |
| R14 대량분석/공동자원 | 연결 보완 | streaming ingest/search_after·heavy worker1 | 그룹순회/외부 상태·공정한 bounded queue T10,19/P5 |
| R14 이관/색인/재처리 | 연결 보완 | migrations/ProcessingRun/업데이터 | generation staging·안전전환·승인본 보존 T14,20/P1–5 |
| R15 통합검증/매체/사용법 | 현재 검증 불가 | 기존 회귀·배포 도구 재사용 | 구현 후 전체 회귀·실제 UI·새 매체 T19–20/P5 |

## 4. 최소 인수 T01–T20와 계획된 합성 사례

아래 모두 **새 요구의 통합 인수는 미실행**이다. 기존 일부 유사 시험의 통과와 혼동하지 않는다.

| 인수 | 합성 입력/기대 결과 | 기존 기반 / 추가 검사 |
|---|---|---|
| T01 | 서비스/IP 미지정 A사 FW 하루 → 품질·이상 후보·근거·보고 | phase1_foundation, phase6_network + 새 종단 |
| T02 | A/B 동일 사설IP·장비명, 별도 예외/자산/기준선/ACL | detection_scope_boundary, checks + 전체 원천/Export 격리 |
| T03 | 공유 FW 파일: 매핑 일치·상충·미확인 | 새 행 귀속/충돌 시험, UI 선택으로 덮어쓰기 금지 |
| T04 | 같은 세션 start/interim/end bytes0→100→300 | 기록3/세션1/최종300, 가짜주기0; reset/ID재사용/부분 세션 |
| T05 | deny 스캔·allow만 있고 handshake 없음·방향 미확인 | data_accuracy + 시도/성립/정상/유출을 구별 |
| T06 | 한 요청에 WAF hit3, UA 미수집/빈값, Edge200/Origin500 | behavior_observation/calculator + 장비 의미 |
| T07 | IPS detected/drop/reset + inline/mirror + packet 유무 | phase6_network + 프로필/자료 부족·반복/확산·후속통신 후보 |
| T08 | src 없는 두 DDoS구간·bps/pps/rps/mean/peak/샘플링변화 | 새 급증/지속/집중/완화전후 엔진, 비동시peak합산 금지 |
| T09 | NDR alert-only/flow/DNS/HTTP/TLS/PCAP 조합 | ndr_policy + 입력 범위/preflight |
| T10 | 필드/기준선 부족·잘못된 정규식·상한·취소·실패 | sigma_contract/auto, behavior_jobs + 공통 실행 ledger |
| T11 | threshold직전/도달·정확시간경계·동일시각·NAT/IPv6·중복 | scenario_boundaries/behavior_calculator + FW 공통 경계 |
| T12 | 상세→정책초안→선택사례→다른 승인자→적용→복구 | phase14_detection/content_packages + 실제 UI/API/워커 |
| T13 | 활성v1 유지하며 v2초안 작성/반려, 불완전 JSON 수정 | 기존 버전 기대값 수정, 후보와원본조건차이·동시전환 |
| T14 | same scope/result/check revision → 통계/원문/HTML/XLSX | behavior_* + ReportVersion/후속항목/재시작 |
| T15 | 한글·긴ID·시각·원문 =/+/-/@·수식URL·행셀경계 | 새 XLSX 구조/표시/차트/분할/외부링크 검사 |
| T16 | 승인스캔=탐색적중+승인활동, Golden품질승인만 있음 | golden + 외부반출거부·dual truth |
| T17 | 사건파생 split·제목라벨·검색누출·hash변조·ACL철회 | golden + metadata/evaluation history/artifact재검사·표본전체재계산표시거부 |
| T18 | 일관가명·주소/시간변환→통계/정답/참조 동일 | 새 변환/모델프로필 검증·전체재계산용완전성·대응표 제외·승인bytes동일 |
| T19 | API→전용PG→전용OS→worker→브라우저 | SQLite와 별도 실제 환경시험, 1/3분석가·100만건 |
| T20 | 새 설치/0014업데이트·재시작·실패/전체복구 | 기존 매체/업데이터 재사용+새 migration/UI/dependency 실반입 |

## 5. 승인과 다음 실행

P0 문서는 새 기능을 구현 완료했다고 보고하기 위한 문서가 아니다.
최신 사용자 요구 15절에 따라 설계와 P1–P5 순서를 먼저 검토받는다.
승인되면 P1의 관계사/장비/정규화/품질/FW 한 흐름부터 구현·회귀한다.
운영자료 반입·운영 DB 변경·관리자 설치·외부 반출·운영 배포 승인은 별도다.
기존 모델/탐지/원본의 승인 상태를 자동 변경하지 않는다.
