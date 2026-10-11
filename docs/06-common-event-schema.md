# 06. Common Event Schema (CES)

버전: `ces/1.0`. 모든 정규화 이벤트는 이 스키마를 따르며, **원본(raw)과 정규화본을 함께 보존**한다 ([ADR-0014](adr/0014-raw-and-normalized-retention.md)).

## 1. 설계 원칙

1. 필드명은 요구사항의 평면(flat) 이름을 정규 이름으로 사용 — 분석가가 쿼리에서 바로 쓰기 쉬움.
2. ECS/OCSF는 **매핑 테이블**로 상호운용 (Export·Connector 변환 시 사용).
3. Unknown/제품 고유 필드는 버리지 않고 `ext.<product>.*`에 보존.
4. 모든 이벤트는 **출처 추적 가능**: evidence_id, 파일, 라인/오프셋, 파서 버전.
5. 시간은 UTC 저장, 원본 문자열과 TZ 보존.

## 2. 필드 정의

### 2.1 Core (요구사항 필드)

| 필드 | 타입(OpenSearch) | 필수 | 설명 |
|---|---|---|---|
| event_id | keyword | ✓ | 결정적 UUID: `hash(evidence_file_id, byte_offset)` 기반 → 재처리 시 동일 ID (멱등 인덱싱, [10](10-job-processing-design.md)). Connector 유래 이벤트는 `hash(connector, source_event_id)` |
| timestamp | date_nanos | ✓ | 이벤트 발생 시각 (UTC) |
| ingest_timestamp | date | ✓ | SAW 인덱싱 시각 |
| data_source | keyword | ✓ | `web, waf, firewall, ips, ndr, zeek, suricata, windows, linux, db_audit, vpn, proxy, dns, custom` |
| product | keyword | ✓ | `nginx, apache, iis, cloudflare, <waf vendor>, zeek, suricata …` |
| event_type | keyword | ✓ | `http_access, waf_block, conn, dns_query, tls_handshake, ids_alert, auth, process, file …` |
| severity | keyword | | 원본 심각도를 정규화 `critical/high/medium/low/info` |
| src_ip | ip | | |
| src_port | integer | | |
| dst_ip | ip | | |
| dst_port | integer | | |
| protocol | keyword | | `tcp/udp/icmp/http/https/dns/tls …` |
| hostname | keyword | | 로그 생성 호스트 또는 HTTP Host |
| user | keyword | | 계정 (마스킹 정책 적용 대상) |
| session_id | keyword | | 애플리케이션 세션/쿠키 해시 |
| method | keyword | | HTTP method |
| uri | keyword + text(`uri.text`) | | 원본 URI (query 포함) |
| status_code | short | | |
| bytes_in | long | | 요청/수신 바이트 |
| bytes_out | long | | 응답/송신 바이트 |
| user_agent | keyword(ignore_above 2048) + text | | |
| domain | keyword | | DNS query/SNI/Host |
| process | keyword | | 프로세스명/경로 |
| hash | keyword | | 파일 해시 (sha256 우선) |
| ja3 | keyword | | |
| ja4 | keyword | | |
| raw_event | text (index: false, store) | ✓ | 원본 라인 (≤ 32 KB, 초과 시 truncate + raw_ref) |
| parser | keyword | ✓ | 파서 ID |
| parser_version | keyword | ✓ | SemVer |

### 2.2 Provenance (추가)

| 필드 | 타입 | 설명 |
|---|---|---|
| investigation_id | keyword | **모든 쿼리에 강제 필터** |
| evidence_id | keyword | |
| source_file | keyword | 원본 내 상대 경로 (sanitize) |
| raw_ref | object `{object_key, offset, length, line_no}` | S3 원본 위치 |
| raw_truncated | boolean | |
| timestamp_raw | keyword(index:false) | 원본 시간 문자열 |
| timestamp_tz | keyword | 원본 TZ 또는 `assumed:+09:00` |
| timestamp_quality | keyword | `exact / assumed_tz / inferred / ingest_time` |
| org_unit | keyword | 계열사/조직 구분 |
| ces_version | keyword | `1.0` |

### 2.3 Derived / Enrichment (파이프라인 계산)

| 필드 | 타입 | 설명 |
|---|---|---|
| url_path | keyword | query 제외 경로 |
| url_query | keyword(index:false) | |
| uri_template | keyword | `/api/customer?id=<NUM>` 결정적 정규화 ([19](19-bulk-log-analysis-design.md)) |
| params | nested? → **flattened** `params.*` | 파라미터 이름→값(마스킹 적용) |
| param_names | keyword[] | |
| ua_class | keyword | `browser / mobile_app / script(python-requests…) / scanner / bot / empty / unknown` |
| src_asn, src_as_org | long, keyword | 오프라인 ASN DB |
| src_geo_country | keyword | |
| src_cloud | keyword | `aws / gcp / azure / oci / vps:<provider> / none` |
| src_ip_scope | keyword | `internal / external / reserved` |
| dst_asset_id | keyword | Asset Knowledge 매칭 |
| community_id | keyword | Zeek/Suricata 상관용 |
| pattern_id | keyword | Pattern Clustering 결과 |
| tags | keyword[] | 탐지 태그 (`libinjection:sqli` 등) |
| finding_ids | keyword[] | 연결 Finding (사후 업데이트, 필요 시) |

### 2.4 Extension
| 필드 | 타입 | 설명 |
|---|---|---|
| ext.<product>.* | `flattened` | 제품 고유 필드 전체 보존. 검색은 가능하나 집계는 제한 → 자주 쓰면 승격 |

**승격 정책**: `ext` 필드가 쿼리/집계에 반복 사용되면 CES 마이너 버전업으로 정식 필드화.

## 3. data_source별 필수 필드

| data_source | 필수 |
|---|---|
| web / waf | timestamp, src_ip, method, uri, status_code, (bytes_out) |
| zeek conn | timestamp, src_ip, src_port, dst_ip, dst_port, protocol, bytes_in, bytes_out, ext.zeek.duration, community_id |
| zeek dns | timestamp, src_ip, dst_ip, domain, ext.zeek.qtype, ext.zeek.rcode |
| zeek ssl | timestamp, src_ip, dst_ip, domain(SNI), ja3/ja4, ext.zeek.version |
| suricata alert | timestamp, src_ip, dst_ip, ext.suricata.signature, ext.suricata.signature_id, severity |
| auth (win/linux) | timestamp, user, hostname, event_type, ext.<os>.outcome |

## 4. 시간 처리 규칙

1. 원본에 TZ가 있으면 그대로 변환 (`exact`).
2. 없으면 Evidence 업로드 시 지정한 TZ(기본 `Asia/Seoul`) 적용 (`assumed_tz`), UI에 아이콘 표시.
3. 파싱 실패 시 같은 파일의 직전 이벤트 시간 (`inferred`) — 비율이 1% 초과면 Job 경고.
4. Cross-source Timeline에서 소스별 **Clock Skew 보정값**을 Investigation 설정으로 허용 (원본은 불변, 표시만 보정).

## 5. ECS / OCSF 매핑 (발췌)

| CES | ECS | OCSF |
|---|---|---|
| timestamp | @timestamp | time |
| src_ip | source.ip | src_endpoint.ip |
| dst_port | destination.port | dst_endpoint.port |
| method | http.request.method | http_request.http_method |
| uri | url.original | http_request.url.url_string |
| status_code | http.response.status_code | http_response.code |
| user_agent | user_agent.original | http_request.user_agent |
| bytes_out | http.response.bytes / destination.bytes | traffic.bytes_out |
| user | user.name | actor.user.name |
| ja4 | tls.client.ja4 (커뮤니티) | tls.ja4_fingerprint_list (버전 확인) |
| hash | file.hash.sha256 | file.hashes |
| domain | dns.question.name / tls.client.server_name | query.hostname |
| raw_event | event.original | raw_data |

전체 매핑은 `core/schemas/mappings/{ecs,ocsf}.yaml`로 관리 (Phase 5).

## 6. 마스킹과 스키마

- 마스킹은 **표시/Export/LLM 계층**에서 적용 (저장은 원본 유지 — 분석 재현성).
- 예외: 기관 정책상 저장 전 마스킹이 필요한 필드(예: 주민등록번호 원문)는 파서 단계 `pre_index_masking` 규칙으로 토큰화(HMAC) — 정책 설정 가능.
- `params.*`, `uri`, `raw_event`, `user`는 마스킹 검사 대상 필드로 등록.

## 7. 예시

```json
{
  "event_id": "01927f4e-8c1a-7b2e-9c3d-1f2e3a4b5c6d",
  "timestamp": "2026-10-04T18:11:04.512Z",
  "ingest_timestamp": "2026-10-05T01:02:11Z",
  "data_source": "web", "product": "nginx", "event_type": "http_access",
  "src_ip": "43.201.x.x", "dst_ip": "10.10.1.21", "dst_port": 443,
  "hostname": "service.example.com",
  "method": "GET", "uri": "/api/customer?id=10001", "status_code": 200,
  "bytes_out": 1832, "user_agent": "python-httpx/0.27",
  "url_path": "/api/customer", "uri_template": "/api/customer?id=<NUM>",
  "param_names": ["id"], "ua_class": "script",
  "src_asn": 16509, "src_as_org": "AMAZON-02", "src_cloud": "aws",
  "investigation_id": "…", "evidence_id": "…",
  "source_file": "access.log.18.gz:access.log.18", "raw_ref": {"object_key": "…", "line_no": 482113},
  "timestamp_quality": "exact",
  "raw_event": "43.201.x.x - - [05/Oct/2026:03:11:04 +0900] \"GET /api/customer?id=10001 HTTP/1.1\" 200 1832 \"-\" \"python-httpx/0.27\"",
  "parser": "nginx_combined", "parser_version": "1.0.0", "ces_version": "1.0"
}
```
