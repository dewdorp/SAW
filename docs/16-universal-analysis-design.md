# 16. Universal Analysis Design

플랫폼의 **진입점**. 사용자는 데이터 타입을 고르지 않는다.

## 1. 흐름

```
Paste / Drop (≤ 5 MB)
   │
   ▼
Pre-processing: 인코딩 감지(UTF-8/UTF-16/CP949), 개행 정규화, BOM 제거, 제어문자 표시용 맵
   │
   ▼
Detectors (병렬, 각 결과 = {type, span, confidence, evidence})
   │
   ▼
Resolver: 겹치는 Span 정리, 상위 구조 우선(HTTP Request ⊃ Host ⊃ Domain)
   │
   ▼
Recommended Analyses + 자동 실행(가벼운 것)
   │
   ▼
Result View: 입력 하이라이트 + 감지 목록 + 분석 결과 카드 + 다음 행동
```

## 2. Detectors

| Detector | 방법 | 신뢰도 근거 |
|---|---|---|
| HTTP Request | 첫 줄 `METHOD SP target SP HTTP/x` 또는 HTTP/2 pseudo-header(`:method`) + 헤더 블록 | 문법 일치, Host 존재 |
| HTTP Response | `HTTP/x NNN` 상태줄 | |
| IPv4/IPv6 | 정규식 후 `ipaddress` 검증, 사설/예약 대역 분류 | 유효 옥텟, 문맥(버전 문자열 `1.2.3.4` 오탐 방지: 앞뒤 문자) |
| Domain | PSL(Public Suffix List, 오프라인) 기반 eTLD 검증 | 유효 TLD, 파일 확장자 오탐(`config.php`) 배제 |
| URL | scheme + authority, Defang(hxxp, [.], [:]//) 복원 | |
| Hash | 길이(32/40/64/128) + hex, ssdeep/TLSH 형식 | 문맥 키워드(md5, sha256) 가산 |
| JSON / XML | 파서 시도(안전 모드), 부분 JSON(로그 내 삽입) 탐지 | 파싱 성공 |
| JWT | `eyJ…\.eyJ…\.…` + 헤더 디코드 성공 | |
| Base64/Base64URL | charset, 길이%4, 디코드 결과의 printable 비율·엔트로피 | 디코드 결과 유의미 |
| Hex / URL-encoded / Unicode escape / HTML entity | 패턴 밀도 | |
| PowerShell EncodedCommand | `-e(nc(odedcommand)?)` + Base64 → UTF-16LE | |
| Log Line | 파서 프레임워크의 `detect()` 재사용 (Apache/Nginx/Syslog/JSON…) | 파서 스코어 |
| Email / Account / Card(마스킹 대상) | 패턴 | 마스킹 트리거 |

모든 Detector는 `analyzers/universal/detectors/*` 플러그인: `detect(text) -> list[Detection]`, 결정적, 단위테스트 Fixture 필수.

## 3. Recommended Analysis 매핑

| 감지 | 추천 (자동 실행 여부) |
|---|---|
| HTTP Request | HTTP Analysis(자동), IOC(Host/XFF IP)(자동, 내부 Context만), Payload Decode(파라미터에 인코딩 감지 시 자동), Related Logs(Investigation 선택 시), Similar Case, Timeline |
| IP/Domain/URL/Hash | IOC Analysis(자동, 오프라인+내부), External TI(수동 버튼) |
| Encoded String | Payload Decode(자동 체인) |
| JWT | JWT Decode(자동) + 경고(alg none, exp 경과, kid 이상) |
| Log Line(s) | Log Analysis(자동) → 추출 IOC |
| 여러 HTTP Request | Request Diff 추천 |
| 대용량 텍스트(> 5 MB) | Upload Flow 안내 |

## 4. 결과 화면 (요약)

```
┌ INPUT (하이라이트) ───────────────────────────┐┌ DETECTED ──────────────────┐
│ GET /api/customer?id=123 HTTP/1.1            ││ ✓ HTTP Request      0.99   │
│ Host: [service.example.com]                  ││ ✓ IPv4 (XFF)        0.98   │
│ User-Agent: [python-httpx/0.27]              ││ ✓ Host              0.99   │
│ X-Forwarded-For: [1.2.3.4]                   ││ ✓ User-Agent(script)0.95   │
└──────────────────────────────────────────────┘│ ✓ Query Param (id)  0.99   │
                                                └────────────────────────────┘
RECOMMENDED: [HTTP Analysis ✓완료] [IOC ✓완료] [Payload Decode –] [Related Logs] [Similar Case] [Timeline]
```
감지 항목 hover → 입력 Span 하이라이트 (양방향).

## 5. 출력 계약

```json
{
  "input_ref": "paste:sha256:…",
  "detections": [{"type":"http_request","span":[0,128],"confidence":0.99,"evidence":["request-line","Host header"]},
                 {"type":"ipv4","span":[101,108],"value":"1.2.3.4","context":"X-Forwarded-For","scope":"external"}],
  "recommended": [{"analysis":"http","auto":true,"status":"done"},{"analysis":"similar_case","auto":false}],
  "results": {"http": {...}, "ioc": {...}},
  "meta": {"analyzer_version":"universal/1.0.0","masked":["cookie.session"]}
}
```

## 6. 안전

- 입력은 서버 메모리에서만 처리, “Add to Investigation” 하지 않으면 **저장하지 않음** (감사에는 해시·크기만).
- 외부 조회는 자동 실행하지 않는다.
- 렌더는 텍스트 전용, 제어문자·Bidi 문자 기호화.
