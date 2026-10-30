# 영문 NDR·FW 필드 기반 자동 조사 검증 (2026-10-30)

기준: main a6cd0a0 위 PR #6(v0.2.1, 2ba11ed)에서 이어진 브랜치 `claude/ndr-fw-fields-20261030`. 모든 시험 자료는 가상 자료이며 운영 자료(var/objects, INV-20261008-001)·실제 계정·비밀정보는 쓰지 않았다.

## 1. 분석가가 더 이상 하지 않아도 되는 것

| 이전 | 이제 |
|---|---|
| 영문 NDR/FW 내보내기를 올리면 일반 CSV로 처리되어 목적지·요청 대상·바이트가 빠짐 | 머리글을 보고 전용 파서(`en_ndr_http_csv`, `en_fw_csv`)가 자동 선택됨 |
| 열 이름 대응표·정책 YAML·정규식 작성 | 필요 없음. 필드 의미 사전이 기본 연결 |
| 질문별 탐지 규칙·시나리오 작성 | 네 가지 조사 질문이 로그에서 바로 계산됨(정책 작성 없음) |
| 같은 장비 설정을 조사마다 다시 입력 | 같은 관계사의 이전 조사에서 확인된 장비 설정을 골라 이 조사의 독립 사본으로 등록 |
| 원본 열 중 무엇을 볼지 직접 고르기 | 원본 로그 표의 "NDR 기본 열"/"FW 기본 열" 버튼 |

## 2. 지원 머리글과 변형

- NDR: `event_time,_site,app,_schema,protocol,src_ip,src_port,src_country,dest_ip,dest_port,dest_country,_device_ip,_device_name,method,host,path,query,user_agent,referer,req_cookie,uuid,status,sc_bytes,cs_bytes` 및 앞에 `| # fields `가 붙은 형태.
- FW: `_time,_device_ip,_device_name,action,src_ip,src_port,dst_ip,dst_port,protocol,tcp_flag,duration,sent_bytes,rcvd_bytes`.
- 열 순서 변경, 머리글 앞뒤 공백, BOM, 따옴표, 쉼표/탭 구분자를 처리한다. 잘못된 행은 그 행만 실패로 격리된다.
- 쿠키 값은 이벤트 저장소·원문 표시에 넣지 않는다(쿠키 이름만 저장, 값은 원본 파일에만 남음).
- `query`는 HTTP 요청 문맥(메서드·경로·상태 중 2개 이상)일 때 요청 대상(`path?query`)으로 합치며 DNS 도메인으로 바꾸지 않는다. DNS 기록의 query는 그대로 도메인이다.

## 3. 필드별 연결 결과

상태: **연결**(공통 필드로 분석에 사용) / **후보**(연결했으나 방향·단위·행 의미를 장비에서 확인해야 함) / **원문**(보존만, 기본 분석에 쓰지 않음). 화면의 "필드 의미와 분석 연결" 칸에서 조사별로 값이 있는 기록 수와 함께 보인다(서버 집계).

### NDR

| 원래 필드 | 의미 | 연결 | 공통 필드 |
|---|---|---|---|
| event_time | 이벤트 기록 시각 | 연결 | timestamp |
| protocol | 통신 프로토콜 | 연결 | protocol |
| src_ip / src_port | 기록된 출발지 | 연결 | src_ip / src_port |
| dest_ip / dest_port | 기록된 목적지 | 연결 | dst_ip / dst_port |
| method | HTTP 메서드 | 연결 | method |
| host | HTTP 대상 호스트 후보 | 연결 | hostname |
| path | 요청 경로 | 연결 | url_path |
| query | 쿼리 문자열 | 연결 | url_query (요청 대상에 합침) |
| user_agent | User-Agent | 연결 | user_agent |
| status | 응답 상태 | 연결 | status_code |
| sc_bytes | 서버→클라이언트 바이트 후보 | 후보 | bytes_in |
| cs_bytes | 클라이언트→서버 바이트 후보 | 후보 | bytes_out |
| _site, app, _schema, src_country, dest_country, _device_ip, _device_name, referer, uuid | 원천 정보 | 원문 | — |
| req_cookie | 요청 쿠키 | 원문(이름만) | — |

### FW

| 원래 필드 | 의미 | 연결 | 공통 필드 |
|---|---|---|---|
| _time | 로그 기록 시각 | 연결 | timestamp |
| action | 장비 처리 결과 | 연결 | enforcement_action |
| src_ip / src_port / dst_ip / dst_port | 기록된 출발지·목적지 | 연결 | 같은 이름 |
| protocol | 통신 프로토콜 | 연결 | protocol |
| sent_bytes / rcvd_bytes | 송·수신 바이트(방향 기준 확인 필요) | 후보 | bytes_out / bytes_in |
| duration | 지속시간(단위 미확인) | 후보 | — |
| _device_ip, _device_name, tcp_flag | 원천 정보 | 원문 | — |

이름만 보고 바이트 방향·지속시간 단위·uuid 역할을 확정하지 않는다. 처리 작업 화면에 "바이트 방향은 장비 기준 확인 필요" 안내가 함께 나온다.

## 4. 네 가지 조사 질문(질문 묶음)

`GET /investigations/{id}/question-bundles?sensitivity=low|normal|high`. 조사 기간([시작, 종료일 다음 날 00:00))의 전체 기록을 서버에서 집계한다. 각 항목은 관측 사실·판단 근거(기준값)·관련 기록 수와 재조회 필터·모르는 것·정상 가능성·다음 확인 질문을 담는다.

| 묶음 | 질문 | 필요한 필드 |
|---|---|---|
| A web_attack | 웹 공격·영향(경로 탐색, 오류 다발 후 성공 등) | url_path 또는 uri, status_code |
| B transfer | 대량 전송: 외부 반출 후보 vs 다운로드 후보(관계사 내부/외부 주소로 방향 구분) | bytes_in/bytes_out |
| C periodic | 일정 간격 반복 접속 | timestamp, src/dst |
| D spread | 한 출발지의 많은 대상·포트 접속(확산) | src_ip, dst_ip/dst_port |

상태: **찾음**(found) / **살펴봤으나 해당 없음**(looked_none) / **필드 부족으로 판단 불가**(insufficient_data, 부족한 필드 표시) / **실패**(failed). 후보 0건은 "정상"이 아니라는 안내를 함께 보인다.

### 합성 표본 기대값과 결과(자동 시험 `tests/api/test_question_bundles.py`)

| 표본 | 묶음 | 기대 | 결과 |
|---|---|---|---|
| NDR web_probe | A | 찾음 | 일치 |
| NDR web_normal | A | 해당 없음 | 일치 |
| NDR large_response_out | B | 찾음(외부 반출 후보, 12건) | 일치, 필터 재조회 12건 |
| NDR download_in | B | 찾음(다운로드 후보) | 일치 |
| NDR no_bytes | B | 판단 불가 | 일치 |
| FW periodic | C | 찾음 | 일치 |
| FW irregular | C | 해당 없음 | 일치 |
| FW spread | D | 찾음 | 일치 |
| FW few_targets | D | 해당 없음 | 일치 |
| FW(웹 필드 없음) | A | 판단 불가(부족 필드 표시) | 일치 |

표본 생성기: `saw/devtools/en_security_samples.py`. "애매함" 사례는 별도 표본으로 만들지 않았고, 다운로드 후보(B)와 민감도 낮음/높음 전환으로 경계를 보였다.

## 5. 계약 수정

- ndr.policy 규칙이 모두 꺼져 있으면 실행 기록이 `disabled`(policy_disabled)로 남고 전체 요약에 "비활성(규칙 꺼짐)"으로 보인다. "분석했는데 없음"과 구분된다.
- 탐지 목록 화면에서 ndr.policy(Zeek conn, 기본 꺼짐)와 ndr.observation(장비 관측)을 구분해 표시한다.
- 장비 관측(DeviceObservation) 후보가 대표 기록의 시작·종료 시각과 대상 주소를 가지게 되어 시나리오·타임라인에 연결된다.

## 6. 장비 설정 템플릿

- 같은 관계사의 열람 가능한 이전 조사에 있는 최신 장비 설정 버전을 목록으로 보여 주고(시간·카운터 의미 확인 여부 표시), 고르면 이 조사의 **독립 사본**으로 등록한다. 원본을 바꿔도 사본은 바뀌지 않는다.
- 다른 관계사의 설정은 목록에 나오지 않고, 직접 요청해도 거부된다.

## 7. 시험

| 범위 | 결과 |
|---|---|
| 영문 파서 신규 5건 | 통과 |
| 파서·가져오기 회귀 235건 | 통과 |
| 장비 관측 회귀 129건 | 통과 |
| 질문 묶음·필드 의미 12건 | 통과 |
| 원천 문맥·템플릿 15건 | 통과 |
| 화면 inv 폴더 20파일·158건, TypeScript | 통과 |
| 서버 전체(r4) | §9 참조 |

## 8. 브라우저 시연

§9 참조.

## 9. 미검증·경계

- 대상 LTSC17763 설치 검증은 PENDING_ENV. 운영 서버는 업데이트하지 않았다.
- OpenSearch/PostgreSQL native 실행, 대용량(10만 건 이상) 질문 묶음 응답 시간은 측정하지 않았다.
- 바이트 방향·duration 단위·uuid 역할은 장비별 확인이 필요하며 자동으로 확정하지 않는다.
- 쿠키는 이름만 저장한다. 원본 파일에는 값이 남아 있으므로 원본 접근 권한 관리는 기존과 같다.
