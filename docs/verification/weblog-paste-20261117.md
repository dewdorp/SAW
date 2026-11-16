# 웹 서버 로그 붙여넣기 분석·대형 조사 스토리 한도 수정 검증 (2026-11-17)

브랜치 `claude/weblog-paste-20261117` (main 3fd4d73 위). 요청: ① 10만 행 업로드에서 기존 탐지 단계(공격 스토리)가 `derived_source_scope_limit`로 실패하던 문제 수정, ② 각 웹 서버의 일반 로그를 붙여넣어 분석, ③ 사례 포함.

## 1. 스토리 출처 한도 (`derived_source_scope_limit`)

- 원인: `run_story`가 조사의 모든 탐지 결과 dict 목록 전체를 **한 값으로** `source_ids`에 넘겼다. 이 함수는 한 값을 훑을 때 2만 항목 한도가 있어서, 결과 하나하나는 평범해도 결과가 많으면(10만 행 업로드) 합계가 한도를 넘었다. 유사 사례 색인(`similar.index_investigation`)도 같은 방식이었다.
- 수정: `combined_source_ids`(기록마다 따로 훑고 합친 출처 수는 기존과 같은 500개 한도), `graph_source_ids`(스토리 그래프를 노드·간선·연관별로). 한 기록이 비정상적으로 큰 경우의 2만 항목 한도와 잘못된 출처 형식 거부는 그대로다.
- 재현: 탐지 결과 1,000개 조사에서 수정 전 `analysis.py:478`에서 `Forbidden: derived_source_scope_limit`(RED) → 수정 후 통과. 유사 사례 색인도 수정 전 실패(RED) → 통과. 시험 `tests/api/test_story_source_scope_scale.py` 3건.
- 확인하지 못한 것: 실제 10만 행 업로드 전체 흐름을 다시 돌려 공격 스토리 단계가 끝나는 것까지는 보지 않았다(자동 시험의 1,000개 결과 재현으로 확인).

## 2. 웹 서버 로그 형식

| 파서 | 형식 | 비고 |
|---|---|---|
| nginx_combined / apache_combined (기존) | NCSA combined·common | Tomcat AccessLogValve·WebtoB·JEUS도 이 형식이면 같이 읽음. 서버 이름은 구분하지 못함 |
| apache_vhost_combined (신규) | `%v:%p` 앞붙임 | Host·포트 보관 |
| iis_w3c (기존) | W3C 확장 | `#Fields:` 필요, UTC |
| haproxy_http (신규) | `option httplog` | syslog 앞부분 허용, 헤더 기록 시 Host·User-Agent |
| web_json_access (신규) | Nginx JSON, Caddy, ECS 등 | 출발지·요청·응답 코드가 있어야 함. 추가 값은 글자로 통일해 `ext.web_json`에 보관 |
| apache_error (신규) | error_log | ModSecurity 메시지는 `waf` 기록(규칙 번호·차단 여부), 서버 파일 경로는 요청 주소로 쓰지 않음 |
| nginx_error (신규) | error.log | 요청·출발지·호스트, 오류 종류(없는 파일·접근 금지·요청 제한·뒤쪽 서버 실패 등) |

OpenSearch 고정 이름 목록에 `haproxy`·`web_json`을 더했다(`docs/opensearch-vendor-extensions.md`). native OpenSearch에서 실제로 쓰는 것은 확인하지 못했다.

## 3. 붙여넣기 분석

- `/analyze/log`(화면: 도구·설정 > 붙여넣기 분석 > 로그). 웹 기록이 있으면 요청 한 번 동안만 쓰는 메모리 SQLite에 넣고 조사와 같은 웹 탐지기 10종을 돌린 뒤 닫는다. 조사 저장소에는 쓰지 않는다(시험으로 확인).
- 결과: 형식 이름(한글), 결과별 제목·설명·숫자·판단 근거·다음 확인·근거 줄 번호, 오류 기록 묶음, 출발지별 요약, 응답 분포.
- 계정 이름이 없는 형식에서는 계정 수를 판단하지 않고 "로그에 계정 이름 없음"으로 표시한다.
- 기존 탐지기 수정: `web.scripted_client`가 User-Agent 열이 없는 형식(common·Tomcat 기본)의 빈 값을 자동화 도구로 세던 것을, 다른 기록에 User-Agent가 있을 때만 세도록 고쳤다. 조사 분석에도 같이 적용된다.

## 4. 사례 WL01~WL11

`saw/analyzers/weblog_cases.py`가 시드로 같은 로그를 만든다(문서용·사설 주소, example.test). 공격 요청은 널리 쓰이는 짧은 탐지 시험 문자열이다.

| 사례 | 서버·형식 | 기대 결과(시험으로 정확히 일치 확인) |
|---|---|---|
| WL01 | Apache combined, Nikto 스캔 뒤 /admin/·/.git/config 200 | 경로 탐색, 민감 파일, 자동화 도구 |
| WL02 | Nginx combined, 로그인 84회 실패 뒤 성공 | 로그인 대입 |
| WL03 | IIS, 게시판 번호에 SQL 구문·500 | 주입 구문 |
| WL04 | Tomcat common+%D, manager·actuator·백업 파일 | 민감 파일 |
| WL05 | WebtoB·JEUS common, 고객 번호 260개 순차 조회 | 번호 대량 조회 |
| WL06 | HAProxy, sqlmap | 주입 구문, 자동화 도구 |
| WL07 | Nginx JSON, CSV 64개 약 130MB | 큰 응답 |
| WL08 | Caddy JSON, 정상 업무 | 없음(대조) |
| WL09 | Apache 오류 로그, ModSecurity 경고·차단 | 없음(오류 묶음으로 규칙별 건수) |
| WL10 | Nginx 오류 로그, 비밀 파일 요청·요청 제한 | 민감 파일 |
| WL11 | vhost_combined, 403 뒤 POST 200 | 요청 변조 뒤 성공, 민감 파일 |

한계: 문서용 주소(198.51.100.0/24 등)는 SAW에서 내부로 분류되므로 "외부 단일 출발지만 접근한 드문 경로" 판단은 사례에 나오지 않는다.

## 5. 시험

- 신규: 서버 `test_web_server_parsers.py`(14건), `test_web_log_paste.py`(18건), `test_story_source_scope_scale.py`(3건), 화면 `LogPage.test.tsx`(3건).
- 단위 전체와 파서·탐지·업로드 관련 API 시험: 첫 실행에서 `test_generation_vendor_extensions` 1건 실패(새 파서 이름이 OpenSearch 고정 목록에 없음) → 목록에 추가 후 통과.
- **서버 전체 r1(f282b20): 3,138건 중 3,119 통과·19 건너뜀(환경 조건)·실패 0·오류 0, 3,144초.**
- 화면 전체 68파일·449건 통과, TypeScript 오류 0, 웹 빌드 통과.

## 6. 실제 브라우저

격리 QA 서버(localhost:8130, 이 브랜치로 빌드한 화면), 합성 자료, 사용자가 직접 로그인한 합성 계정 manager.

- 로그 분석 화면에 사례 11개가 보이고, 11개를 차례로 "이 사례 넣기"로 넣어 **11개 모두 "기대한 결과와 같음"**(결과 수 WL01 3·WL02 1·WL03 1·WL04 1·WL05 1·WL06 2·WL07 1·WL08 0·WL09 0·WL10 1·WL11 2).
- WL01: 민감 파일(32건, 2xx 2)·경로 탐색(404 162건)·자동화 도구(Nikto 165건), 출발지 요약 1위 198.51.100.23.
- WL02: 로그인 대입 85건·실패 비율 98.8%·성공 1, "서로 다른 계정이 많음"은 "로그에 계정 이름 없음"으로 판단하지 않음. "근거 줄 보기"로 116번 줄부터 원문이 열림.
- WL09: 판단 0개와 "안전하다는 확인은 아닙니다" 안내, 오류 기록 묶음 6개(ModSecurity 942100 14건·941100 13건·949110 12건·930120 9건, Apache AH01630·AH00489).
- 직접 붙여넣기: 손으로 친 Nginx 오류 로그 2줄 → 형식 "Nginx 오류 로그", 민감 파일 1개(성공 응답 ✗), 오류 묶음 "없는 파일 요청"·"접근 금지 규칙". 글을 고치면 사례 표시가 사라짐.
- 콘솔 오류는 로그인 전 401 한 건뿐.
- 화면에서 발견해 고친 것: 출발지 요약의 접속 도구에 `mobile_app`이 영문으로 나옴 → "모바일 앱"(그리고 `unknown` → "알 수 없음")으로 고쳤다. 이 수정은 서버 시험 32건(붙여넣기·파서)으로 확인했고, 서버를 다시 켜면 로그아웃되므로 화면에서는 다시 보지 않았다.

## 7. 확인하지 못한 것

- 실제 10만 행 업로드 전체 흐름의 공격 스토리 단계 재실행.
- native OpenSearch/PostgreSQL에서 새 파서 자료의 저장·조회.
- 각 서버의 사용자 정의 로그 형식(항목 순서를 바꾼 것)은 지원 범위 밖이며 파서 관리로 만들어야 할 수 있다.
- 새 설치 매체·설치 리허설은 만들지 않았다.
