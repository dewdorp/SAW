# 17. HTTP Analysis Design

(IOC Analyzer 설계 포함 — §7)

## 1. 파싱

- **관대한(lenient) 파서**: 공격 트래픽은 RFC를 어긴다. 엄격 파싱 실패 시에도 최대한 구조화하고 `anomalies[]`에 기록.
  - 예: 중복 헤더, `Content-Length` + `Transfer-Encoding` 동시 존재(Request Smuggling 지표), obs-fold, 비ASCII 헤더, CRLF 대신 LF.
- 입력 형식: Raw HTTP/1.x, Burp “Copy to file”, Chrome DevTools “Copy as cURL”(curl 명령 파싱), HTTP/2 pseudo-header, HAR 엔트리(JSON).
- Body 처리: Content-Type 기반 + 내용 스니핑. gzip/br 인코딩 Body는 크기 상한 내 해제.

## 2. 구조화 출력

```
Request
  method, scheme, host, port, uri, path, path_segments[], query(raw), fragment
  headers[] (순서 보존, 원문 케이스 보존), cookies[], authorization{scheme, masked}
  user_agent{raw, class, library, version}
  content_type, body{raw(masked), length, parsed_kind}
Response
  status_code, reason, headers[], content_type, size, body_preview(text/hex, 렌더 금지)
Parameters[]  {name, value(masked), location, path(예: JSON $.user.id), decoded_value, decode_chain[], type_guess}
Anomalies[]   {code, detail}
```

### Parameter 위치(location)
`query | form | json | xml | multipart | cookie | header | path`(예: `/user/123` → path segment 숫자 파라미터 추정)

## 3. Canonicalization → Pattern Detection

```
param value
  → decode chain (URL 재귀, HTML entity, Unicode escape, Base64 후보 — Payload Analyzer 재사용)
  → normalize (대소문자, 공백/주석 제거 사본: SQL `/**/`, 연속공백)
  → detectors
```

| Pattern | 방법 | Evidence 예 |
|---|---|---|
| Potential SQL Injection | libinjection SQLi fingerprint + 키워드/구문 휴리스틱 (UNION SELECT, OR 1=1, SLEEP(, quote 불균형) | `' OR 1=1--` (decoded from `%27%20OR%201%3D1--`), fingerprint `s&1c` |
| Potential XSS | libinjection XSS + 태그/이벤트 핸들러/`javascript:` | `<svg/onload=…>` |
| Potential LFI / Traversal | `../` 변형(이중 인코딩, `..%c0%af`, `....//`), 민감 경로(`/etc/passwd`, `win.ini`) | |
| Potential RFI / SSRF | 파라미터 값이 URL/IP, 내부 대역, 메타데이터 주소(169.254.169.254), `file://`, `gopher://` | |
| Potential Command Injection | `; | && $( ) \``와 명령어 사전 | |
| Potential SSTI | `{{7*7}}`, `${…}`, `<%= %>`, `#{}` | |
| Potential Deserialization | Java 직렬화 매직(`rO0AB`, `aced0005`), .NET ViewState 비정상, PHP `O:\d+:"`, Python pickle | |
| Potential Credential Attack | 로그인 경로 + 반복(로그 문맥 필요) / Basic Auth 패턴 | 단일 요청에서는 “Context Required” |
| Potential API Enumeration | 순차 ID 파라미터(단일 요청에선 힌트, 로그 문맥에서 확정 지표) | |
| Potential Request Smuggling | CL+TE, TE 변형 | |
| Header Manipulation | `X-Forwarded-For` 체인 이상, `X-Original-URL`/`X-Rewrite-URL`, Host 불일치 | |

### 출력 형식 (단정 금지)
```json
{"pattern":"potential_sql_injection","label":"Potential SQL Injection Pattern",
 "confidence":"medium","location":"query.id",
 "evidence":[{"kind":"decoded_value","value":"' OR 1=1--","span":[0,10]},
             {"kind":"libinjection","fingerprint":"s&1c"},
             {"kind":"encoding","detail":"URL encoded quote (%27)"}],
 "not_evidence":["응답 status 403 (차단 가능성)"]}
```
- `confidence`: low/medium/high — 신호 수·종류로 결정적 산정 (규칙 표 문서화).
- `not_evidence`(반대 근거)도 표시: 차단 응답, 정상 사용자 행동 등.
- Response가 있으면 **결과 신호** 추가: SQL 에러 문자열, 응답 크기 급변, 200 vs 403.

## 4. UI

```
┌ REQUEST ───────────────────────────────────┐┌ PATTERNS ──────────────────────────────┐
│ GET  /api/customer ?id=123                 ││ ■ Potential SQL Injection Pattern  MED  │
│ Host service.example.com                   ││   at query.id                           │
│ UA   python-httpx/0.27   [script]          ││   Evidence  ' OR 1=1--                  │
│ XFF  1.2.3.4 [external · AWS]              ││   ✓ libinjection s&1c                   │
├ PARAMETERS ────────────────────────────────┤│   ✓ URL encoded quote                   │
│ loc    name   value        decoded  type   ││   ✗ Response 403 (blocked?)             │
│ query  id     123          —        num    │└────────────────────────────────────────┘
│ cookie sid    ●●●●a91f     —        token  │┌ ANOMALIES ─────────────────────────────┐
│ json   $.q    %2527…       ' OR 1…  str ⛓  ││ ⚠ Duplicate header: Host               │
└────────────────────────────────────────────┘└────────────────────────────────────────┘
 ⛓ = decode chain 보기 (Payload Analyzer로 이동)
```
Tabs: Overview / Headers / Parameters / Body / Response / Raw.

## 5. 로그 문맥 결합

단일 요청에서 판단 불가한 패턴(Credential Attack, Enumeration)은 “**Context Required**” 배지 + [Related Logs] 버튼 → Investigation 내 동일 uri_template/src_ip 검색.

## 6. Payload Analyzer (요약, ADR-0011)

- Transform 연산: `url_decode`, `url_decode_recursive`, `base64`, `base64url`, `hex`, `unicode_escape`, `html_entity`, `jwt`, `gzip`, `deflate`, `zlib`, `ps_encoded`(Base64→UTF-16LE), `rot13`(옵션), `xor_single_byte_bruteforce`(P2).
- 자동 체인 탐색: BFS, 깊이 ≤ 8, 각 단계 후 “유의미성 점수”(printable 비율, 엔트로피 감소, 알려진 구조 탐지) 증가 시만 진행, 출력 ≤ 10 MB.
- 시각화:
```
%252e%252e%252f
   │  ⓵ URL Decode       (%25 → %)
%2e%2e%2f
   │  ⓶ URL Decode       (%2e → . , %2f → /)
../                       ⚑ Potential Directory Traversal
```
- [Open in CyberChef]: 동일 Recipe를 CyberChef 정적 인스턴스로 (URL fragment 사용).

## 7. IOC Analyzer

### 7.1 Enrichment 소스
| 소스 | 모드 | 내용 |
|---|---|---|
| 오프라인 ASN/Geo DB (예: IPinfo Lite, DB-IP Lite — 라이선스 확인, 또는 기관 구매 DB) | 오프라인 | ASN, AS Org, Country |
| Cloud/VPS 대역 목록 (AWS/GCP/Azure/OCI 공개 JSON, 주요 VPS ASN 사전) | 오프라인 번들 | src_cloud |
| Tor exit / 공개 Proxy 목록 | 오프라인 번들 | |
| 내부 TI / 블랙리스트 | 내부 | |
| RDAP/WHOIS/rDNS | Egress Proxy, 수동 | 등록정보 |
| IntelOwl / 외부 TI | 수동, 정책 | 평판 |

### 7.2 Internal SOC Context (우선 표시)
| 항목 | 출처 |
|---|---|
| First Seen / Last Seen | 모든 Investigation 이벤트 + Connector(Phase 10) |
| WAF/IPS/NDR/Firewall 이벤트 수 | OpenSearch 집계 (data_source별), Connector |
| Related URI / Assets / Accounts / JA3/JA4 | Pivot 집계 Top-5 |
| Related Cases | case_item, entity 테이블 |
| Previous Analyst Verdict | Closed Investigation/Case의 verdict + 날짜 + 분석가 |

### 7.3 화면 순서
```
[43.201.12.7]  AWS · AS16509 · KR · Cloud ✓ · Tor ✗
─ INTERNAL CONTEXT ────────────────────────────────
 First 2026-10-04 18:02  Last 2026-10-05 03:42
 WAF 1,203 · IPS 0 · NDR 12 · FW 8,421 sessions
 URI: /api/customer?id=<NUM> (21,322) …
 JA4: t13d1516h2_8daaf6152771_e5627efa2ab1 (shared with 42 IPs) 🔗
 Cases: CASE-20261002-013 (Attack)
─ PREVIOUS VERDICTS ───────────────────────────────
 2026-10-02 · Attack · 김선임 · "API Enumeration, 동일 JA4"
─ EXTERNAL (수동) ─────────────────────────────────
 [RDAP 조회] [TI 조회]   ⚠ 외부 조회는 기록됩니다
```
