# 관계사·정규화·장비 분석 P0 감사 — 2026-10-20

## 1. 범위와 증거 기준

- 기준 저장소: `F:\codex\SAW-Claude-main`, HEAD `4072e9d0b0c182def8ff576bc68740585eae13e8`.
- 범위: 최종 요구사항 3~6절·14절 및 선행 의심 1·3·4. 구현 전 설계 감사이며 제품 변경 완료 보고가 아니다.
- [AGENTS](../../AGENTS.md), [STATE](../../STATE.md), [HANDOVER](../HANDOVER.md)와 제공된 최종 요구사항 전체를 읽었다.
- 원본 `F:\claude\saw`, 운영 설치·DB·서비스·계정·은행 자료·비밀 파일을 수정하거나 시험 입력으로 사용하지 않았다.
- 제품 코드·시험 코드·마이그레이션·색인 변경 및 커밋은 없다. 이번 추가 파일은 이 보고서뿐이다.
- 판정은 `이미 가능 / 연결 보완 / 신규 필요 / 현재 검증 불가`로 나누며, 정적 확인과 실제 실행을 구분한다.
- 중앙 회귀 기록: [P0 검증 영수증](affiliate-p0-validation-20261020.json). 부모 작업의 시험을 본 감사 자체 실행으로 중복 계산하지 않는다.

## 2. 핵심 결론

1. `org_unit` 저장은 있으나 조사 응답·수정·목록 필터·화면으로 이어지지 않는다. 조사 안내 context에는 일부 전달된다.
2. 일반 CSV는 연결 열 조합만으로 `zeek_conn`이 된다. `product=csv`와 미매핑 원본 필드는 남지만 실제 장비 계약이 없다.
3. 동일한 `orig_bytes / resp_bytes`가 일반 CSV와 Zeek에서 반대 방향으로 매핑된다. 순수 합성 파서 실행으로 재현했다.
4. FW 시작·중간·종료 기록과 누적 카운터를 구분하는 계약이 없어 기존 연결 수·바이트 합계·주기성 재사용에 전제 조건이 필요하다.
5. 기존 HTTP 품질·상한·취소·불변 결과 기반은 재사용할 수 있다. 모든 탐지기의 공통 실행 상태와 DDoS 집계 분석은 신규 범위다.
6. 조사 ACL은 재사용한다. 관계사 분류를 접근 허가로 쓰지 않으며 자산·기준선·예외의 관계사/망 경계를 추가해야 한다.

## 3. 요구사항 3: 관계사·장비·권한

| 항목 | 판정 | 코드 근거와 현재 범위 |
|---|---|---|
| 관계사 생성·저장 | 이미 가능 | [모델](../../saw/storage/models.py) 108행, [조사 서비스](../../saw/core/application/investigations.py) 41~48행, [API](../../saw/apps/api/routers/investigations.py) 16~18·54~57행 |
| 조사 응답·수정 | 연결 보완 | 같은 API 39~50행 반환에 org_unit 없음. 70~72행 PATCH 입력은 title/clock_skew뿐 |
| 목록 필터·화면 | 연결 보완 | API 60~62행에 관계사 필터 없음. `apps/web/src` 전체 검색에서 org_unit 사용 없음 |
| 조사 안내 context | 일부 이미 가능 | [guidance](../../saw/core/application/guidance.py) 184행은 org_unit 반환. Export 전체 보존은 Golden 감사와 함께 판단 |
| 장비·귀속·망·수집 경로 | 신규 필요 | [Evidence API](../../saw/apps/api/routers/evidence.py) 24~35행, 모델 121~156행에 등록 장비·행 귀속·관측 기능 계약 없음 |
| 조사 접근 제어 | 이미 가능 | 조사 서비스 23~38·55~64행, [authz](../../saw/core/security/authz.py) 62~77행의 역할 AND 멤버십; 기존 매니저 전역 정책 유지 |
| 자산·정상 예외 경계 | 연결 보완 | [asset](../../saw/knowledge/asset.py) 24행 company는 있으나 95~106행 전체 자산의 동일 IP 첫 항목 반환, 128~137행 조사 문맥 없이 전체 로드 |

- 장비 이름과 IP는 관계사 식별자가 아니다. 같은 사설 IP·장비명이 다른 관계사에서 충돌하는 합성 시험이 필요하다.
- asset 145~153행은 expected_uri로 조사 이벤트를 비교한다. 관계사·망 조건 없는 기존 매칭을 자동 정책 근거로 확대하면 안 된다.
- 관리자에게 분석권한을 자동 부여하지 않는 기존 정책을 유지한다. 관계사 등록과 조사 멤버십 변경은 별도 행위다.
- 여러 관계사 사건 연결은 각 조사 권한을 유지한다. 연결된 조사 전체를 한 번에 허용하는 권한 합집합을 만들지 않는다.

## 4. 요구사항 4: 원본·정규화 의미

| 항목 | 판정 | 코드 근거와 현재 범위 |
|---|---|---|
| 원본 위치·파서·버전 | 이미 가능 | [registry](../../saw/parsers/registry.py) 97~119행: event ID, evidence, parser/version, source_file, offset/length/line, raw truncation, 제품별 ext |
| 원본 무결성 | 이미 가능 | 모델 144행 파일 SHA256. registry 119행 미매핑 ext는 최대 200필드이며 원본 파일 참조는 별도 유지 |
| 공통 버전 | 연결 보완 | [normalize](../../saw/analyzers/log/normalize.py) 15·250행 CES 1.0. 의미별 프로파일·귀속·정규화 버전 계약 추가 필요 |
| 시간 구분 | 연결 보완 | normalize 90~154행 UTC/assumed_tz/invalid. [observation](../../saw/behavior/observation.py) 7~19행 원본 정밀도. [structured](../../saw/parsers/structured.py) 46~49행은 발생/수집/시작을 timestamp_raw 후보로 합침 |
| 조치 | 연결 보완 | normalize 173~189행 명시 action→blocked/allowed/conflicting. HTTP 코드로 차단을 추론하지 않음. 제품별 detected/reset/unknown 계약 부족 |
| 미수집·빈값·0 | 연결 보완 | [base](../../saw/parsers/base.py) 28~31행과 observation 22~27행에서 UA 상태 보존. 일반 필드는 structured 95~98행에서 빈값이 ext로 이동 |
| CSV 연결 형식 | 연결 보완 | structured 234~242행 src/dst+port/bytes→zeek_conn/conn. registry 101행 product는 csv 유지 |
| 방향별 바이트 | 연결 보완 | structured 27~29행 resp_bytes→bytes_out, orig_bytes→bytes_in. [network parser](../../saw/parsers/network.py) 52행은 반대 방향 |
| 세션·카운터·집계 의미 | 신규 필요 | session_id는 존재하지만 start/interim/end, ID 재사용 세대, counter reset/delta/cumulative 공통 계약은 없음 |

- 원본 필드가 모두 소실된다고 표현하지 않는다. CSV의 duration/action/record_type/device_id는 확장 필드에 남을 수 있다.
- 그러나 [network detector](../../saw/detectors/network.py) 135행 장기 연결은 ext.zeek.duration, 165행 실패율은 ext.zeek.conn_state에 의존한다.
- 같은 파일이 zeek_conn으로 분류돼도 ext.csv.duration은 장기 연결 탐지에 쓰이지 않는다. deny가 있어도 Zeek state 없으면 실패 건수 0이 될 수 있다.
- 실제 장비 출처와 내부 분석용 연결 형식을 분리하고 기존 Zeek/NDR/PCAP 호환 계층은 유지해야 한다.

## 5. 요구사항 5: 품질과 실행 가능 상태

- **신규 공통 계약:** [detector base](../../saw/detectors/base.py) 82~88행은 data_sources/run만 선언한다. 필수 의미·최소 기간·기준선·실행 가능 상태 선언이 없다.
- [analysis](../../saw/core/application/analysis.py) 161~170행은 출처 교집합으로 실행하고 예외는 로그 후 continue한다. 실행별 실패 상태 저장은 없다.
- [pipeline](../../saw/workers/pipeline.py) 438행은 상위 분석 작업을 COMPLETED 처리하므로 탐지기 실패를 별도로 보존해야 한다.
- **재사용:** [behavior calculator](../../saw/behavior/calculator.py) 295~306·498~541행에 자료 부족·부분·상한·분모·처리 수 표시가 있다.
- **연결 보완:** [NDR policy](../../saw/detectors/ndr_policy.py) 324~342행은 부족·상한을 표시하지만 `ndr.coverage` Finding으로 생성한다. 품질 안내와 위협 후보 통계를 분리해야 한다.
- **현재 제한 유지:** analysis 81~89행은 공유 승인·철회 계약 부재로 과거 기준선을 빈 값으로 반환한다. 단순 정상 종결을 공유 승인으로 취급하지 않는다.
- [anomaly](../../saw/detectors/anomaly.py) 319~322행 신규 관계 탐지는 기준선 없으면 빈 결과다. 앞으로는 기준선 부족 상태를 명시해야 한다.

## 6. 요구사항 6: 장비별 재사용 범위

| 장비 | 판정 | 재사용과 추가 조건 |
|---|---|---|
| FW | 연결 보완+신규 의미 계약 | network detector 43~78행 전송량, 82~127행 주기성, 130~147행 장기 연결, 150~190행 탐색 재사용. 세션 생애주기·조치·방향·카운터 확인 후 적용 |
| WAF | 연결 보완 | 기존 웹/행위 분석, UA 품질, 명시 조치, 요청ID 중복 제거 재사용. 경보 대 요청 수·Edge/Origin·전달 헤더 신뢰 계약 추가 |
| IPS | 연결 보완+프로파일 신규 | network parser 195~225행 Suricata alert/flow/HTTP/TLS/DNS, detector 309~329행 경보 재사용. 탐지 전용/차단/reset·운영 모드·집계기간 명시 |
| DDoS | 신규 필요 | parsers/detectors/behavior/core 검색에서 DDoS·bps/pps/rps 전용 집계 엔진 없음. 출발지 없는 interval_stat/aggregate_alert 허용 필요 |
| NDR | 연결 보완 | [ndr parser](../../saw/parsers/ndr.py) 124~174행 흐름·HTTP 문맥/요청응답 재사용. 경보만/흐름/프로토콜/PCAP 자료 범위별 preflight 추가 |

- FW network detector 98~115행은 모든 일치 timestamp를 주기성에 사용하고 기록 수를 Connections로 표시한다.
- NDR policy 277~278행은 매 기록 count 증가·bytes 합계다. start/interim/end 누적 기록을 넣으면 중복 연결·전송량·가짜 주기성 위험이 있다.
- HTTP 요청 중복 제거는 calculator 441~458행의 request/주소/서비스/메서드/원본 URI/시각+source 조건을 따른다. 기본은 중복 제거 안 함.
- calculator 490~496행은 관측값·센서 중복·UA 빈값·인과 한계를 이미 안내한다. 이 표현과 분모 구조를 재사용한다.
- 원본 제조사별 실제 샘플 검증은 이번 감사에서 하지 않았다. 합성 공통 계약 지원을 제조사 전체 지원으로 표현하지 않는다.

## 7. 요구사항 14: 처리 한도·성능·보존

- **재사용:** pipeline 273~352행 배치/체크포인트/취소, [OpenSearch store](../../saw/storage/opensearch_store.py) 168행 bulk, 214~223행 5천 건 cursor 반복.
- **연결 보완:** network detector 54·58·90·127·136·159·179행에 그룹 2천/3천·결과 5/10·검색 50건 상한이 있다. 모두 전체 검사 완료와 같지 않다.
- network detector 98행은 한 그룹의 이벤트 전체를 list로 만든다. 그룹이 큰 경우 iterator 존재만으로 메모리 한도를 보장하지 못한다.
- OpenSearch store 275~319행 group_by는 terms/multi_terms 상위 버킷만 반환하며 생략 수/after cursor가 없다.
- **재사용+보완:** [config](../../saw/config.py) 39~42행 heavy worker 기본1. [runner](../../saw/workers/runner.py) 33~48행은 실행 스레드를 제한하지만 대기 큐·누적 futures 명시 상한이 없다.
- **현재 검증 불가:** 백만 건·동시 사용자·실제 LTSC2019·새 오프라인 매체의 성능과 호환성은 이번에 실행하지 않았다.

## 8. 제안하는 공통 데이터 계약

1. 기존 org_unit은 표시 문자열/API 호환 필드로 유지하고 안정된 org_unit_id를 연결한다. 원문 문자열·승인 ID·승인자·시각·상태를 이관표에 보존한다.
2. 조사 대상 org와 기록 귀속 subject.org_unit_id/status/mapping_version을 분리한다. 장비 소유/운영 조직은 observer의 별도 의미 필드다.
3. 장비 등록은 ID, vendor/product/version, 가상 장비/tenant/network, 기능, 관측 위치/모드를 가진다. Evidence에는 업로드 당시 source context snapshot을 고정한다.
4. data_source는 즉시 제거하지 않는다. record_kind/analysis_kind/device_function/normalization_version/profile_id/version을 추가하고 새 탐지기는 의미 계약으로 선택한다.
5. timestamp는 발생시각 호환 필드로 유지한다. 시작/종료/수집시각, 원문·시간대·정밀도·가정/보정 근거를 별도 저장한다.
6. raw action과 제품 프로파일별 allowed/blocked/reset/detected/challenged/unknown/conflicting을 구분한다. 연결 성립·응답·분석가 판단은 별도다.
7. traffic은 src→dst/dst→src bytes·packets, 측정 구간, delta/cumulative/total/unknown, sum/mean/max, unit/sampling/direction basis를 가진다.
8. 필드 상태는 present/recorded_empty/not_collected/unknown_meaning/invalid와 producer-owned provenance로 기록한다. 실제0은 present+0이다.
9. 세션 식별은 org/network/device/virtual domain/protocol/원본ID/시작시각·재사용 세대를 포함한다. 의미 부족 시 관측 기록 수만 집계한다.
10. DDoS interval_stat/aggregate_alert는 src_ip를 필수로 요구하지 않는다. 단위·평균/최대·시각·관측 위치·샘플링이 다른 값을 무조건 합산하지 않는다.
11. analysis_run/detector_execution에는 입력 generation/hash, 실행 범위, 엔진·정책 실효 버전, preflight, 처리·누락·상한·상태·오류/취소 사유를 고정한다.
12. 완료-일치/완료-무일치/부분/자료부족/비활성/대상아님/실패/취소를 구분한다. 품질 기록은 탐지 후보 수와 위험점수에서 분리한다.

## 9. 안전한 이관·색인·ACL 순서

1. 0015 후보는 registry/legacy mapping/source context/nullable FK 등 additive 변경으로 설계한다. 컬럼·인덱스까지 존재 검사해 중단 후 재실행할 수 있게 한다.
2. [0014 migration](../../saw/storage/migrations/versions/0014_behavior_results.py) 15~28행의 멱등 기반을 재사용하되 새 객체별 검증을 추가한다. 현장 DB에는 이번에 적용하지 않았다.
3. 구버전 org_unit 생성 API를 유지하고 응답에 선택 필드를 추가한다. 충돌/미확인 문자열을 임의 ID에 배정하지 않는다. 수정은 조사 write+감사로 기록한다.
4. 서버 관계사 필터와 cursor pagination을 함께 추가한다. 관계사 드롭다운 선택은 파일 내 행 귀속 덮어쓰기 허가가 아니다.
5. CES v2 색인은 org/network/device/kind/profile/version을 keyword, 주소/NAT를 IPv4·IPv6 ip, 시간 date, bytes/packets long으로 명시한다. provenance는 비동적 객체로 제한한다.
6. 현 OpenSearch template 42행 ignore_malformed만으로 품질 성공을 판단하지 않는다. 잘못된 필드는 수락/누락/오류 통계와 연결한다.
7. 새 generation을 비공개 staging index에 청크 생성→건수/참조/hash/실패 대조→active generation 원자 전환한다. 기존 색인을 덮어쓰지 않는다.
8. 안정 원본 event ID와 실제 색인 document generation을 분리하고 조회를 generation에 고정한다. 구·신 색인이 같은 검색에서 이중 집계되지 않게 한다.
9. 관계사 표시 이관, 파서 변경 재처리, 룰 재분석을 구분한다. CSV 방향 수정은 새 profile/version으로 승인된 재처리 때만 적용한다.
10. 승인 보고·Golden·Export는 당시 결과/확인 기록 버전을 유지한다. 실패 시 기존 active generation을 유지하고 checkpoint에서 재개한다.
11. org 분류는 ACL이 아니다. 선택한 모든 조사에 기존 ACL을 검사하고 생성·다운로드 시점에 재검사한다. 관리자/선임/매니저 역할을 임의 확대하지 않는다.
12. 자산·기준선·예외에 org/network/device 범위를 둔다. 범위 없는 legacy 항목은 참고만 허용하고 A사의 예외를 B사에 적용하지 않는다.
13. 전체 그룹 pagination/반복 처리와 표시 상한을 분리한다. worker 공정 큐·사용자/조사별 대기 한도·취소·시간/메모리 budget을 추가한다.
14. 구현 후 합성 PostgreSQL/OpenSearch·재시작·새 설치/업데이트를 별도 검증한다. SQLite 성공은 운영 구성 성공의 대체 근거가 아니다.

## 10. 실제 실행과 미실행 경계

- 성공한 직접 실행: 환경변수 전체 clear 후 `.venv\Scripts\python.exe -B -c`에서 CsvParser와 zeek_record 순수 함수로 합성 입력1건을 비교했다.
- 입력: `orig_bytes=100`, `resp_bytes=900`, `duration=7200`, `action=deny`, `session_id=S1`, `record_type=interim`, `device_id=FW-01`.
- CSV 결과: `data_source=zeek_conn`, `event_type=conn`, parser product `csv`, `bytes_in="100"`, `bytes_out="900"`, `session_id="S1"`.
- CSV ext: `duration="7200"`, `action="deny"`, `record_type="interim"`, `device_id="FW-01"`. 장비/조치 원문이 완전히 사라진다는 주장은 하지 않는다.
- Zeek 결과: `data_source=zeek_conn`, `bytes_out=100`, `bytes_in=900`, ext.duration=7200, ext.conn_state=REJ.
- 앞선 to_ces/normalize import 포함 시도는 환경변수 전체 삭제로 Windows 실행 환경까지 제거되어 asyncio `_overlapped` import의 WinError10106에서 중단됐다.
- 그 첫 시도는 제품 결함·회귀 시험 실패로 계산하지 않는다. Windows SystemRoot 의존성 추정과 import 단계 중단을 기록하고 순수 파서만으로 다시 재현했다.
- Python -B로 bytecode 쓰기를 방지했다. 의존성 경로가 원본 가상환경을 참조하므로 원본에 생성 파일을 남기지 않도록 했다.
- 이 담당자는 pytest를 실행하지 않았다. 중앙 작업의 서버650(547+103), UI177/31파일, TypeScript exit0은 중앙 영수증에서 확인할 별도 실행 결과다.
- 이번 결과는 native PG/OpenSearch·LTSC2019·운영 데이터·제조사 원본 샘플·백만 건 부하 검증이 아니다.

## 11. 인수 시험 연결과 다음 실행 지점

| 인수 | 추가 검증 내용 | 재사용할 기존 시험 |
|---|---|---|
| T01 | 서비스·의심IP 없이 관계사 FW→품질→후보→근거→저장 보고 | test_phase6_network.py, test_text_ingest.py |
| T02 | A/B 동일 IP/장비명·상이한 자산/예외/기준선·멤버 권한/Export 격리 | test_phase1_foundation.py, test_phase8_knowledge.py |
| T03 | 공유 장비 행 매핑 일치/충돌/미확인 보존, 조사 선택값의 덮어쓰기 방지 | 새 귀속 매핑 시험 필요 |
| T04 | start/interim/end·누적/reset/역전/부분세션·ID재사용, 관측3/세션1·가짜 주기0 | test_ndr_policy.py, test_data_accuracy.py 확장 |
| T05 | deny·allowed-but-no-handshake·방향 미확인을 성립/유출로 단정하지 않음 | test_phase6_network.py 확장 |
| T06 | WAF 경보 다건/request1·UA 상태·Edge200/Origin500·전달 헤더 신뢰 | test_behavior_observation.py, test_behavior_calculator.py |
| T07 | IPS detected/drop/reset·탐지 전용·패킷 유무와 재검증 범위 | test_phase6_network.py 확장 |
| T08 | src 없는 DDoS·단위·평균/최대·샘플링·완화/영향 미확인 | 신규 집계 엔진 시험 |
| T09 | NDR 경보/flow/HTTP/DNS/TLS/PCAP 가용 조합별 preflight | test_text_ingest.py, test_ndr_policy.py |
| T10 | 필수 의미/기준선 부족·예외·상한·취소가 0건 완료가 되지 않음 | test_ndr_policy.py, test_behavior_jobs.py |
| T11 | 시간창 경계·임계값·순서·NAT·IPv6·세션 중복/카운터 | 기존 NDR/behavior 경계 시험+새 세션 시험 |
| T19 | 합성 전용 API→PostgreSQL→OpenSearch→worker→UI 실제 연결 | test_large_ingest.py, test_detection_scope_boundary.py |
| T20 | 새 migration/schema/profile/UI/의존성 포함 매체·0014 전환·재시작·실패복구 | test_migrations.py, test_windows_bundle.py+native 인수 |

- 다음 구현은 승인된 P1 범위에서 관계사·장비·품질 계약과 FW 한 흐름부터 진행한다. P2에서 다른 장비로 확장한다.
- 승인된 설계·중앙 요구사항 대응표·이 보고서의 미검증 항목을 함께 사용하고, 과거 STATE의 성공 수치를 새 기능 인수로 재사용하지 않는다.
