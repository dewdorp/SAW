# 18. Request Diff Design

공격자는 차단(403)을 만나면 요청을 **조금씩 바꿔가며** 우회 지점을 찾는다. Request Diff는 그 “진화 과정”과 **성공으로 바뀐 지점(Bypass Point)** 을 한눈에 보여준다.

## 1. 입력

- 붙여넣기: 2~200개 Request(+선택적 Response), 구분자 자동 인식(빈 줄 2개, `###`, HAR, Burp 내보내기)
- Investigation에서: 이벤트 테이블 다중 선택 → “Compare Requests” / Finding의 [Request Compare]
- 로그 이벤트(헤더·바디 없음)는 로그에 있는 필드만 비교하고 “partial request” 표시

## 2. Canonical Request Model

```
CanonicalRequest
  idx, timestamp?, src?
  method
  path_segments[]            # /api/user/100 → ["api","user","100"]
  params: [{name, location, value, decoded, type}]   # query/form/json/xml/cookie/header/path
  headers: {lower(name): value}   (순서 별도 보존)
  cookies: {name: value(masked)}
  body: {kind, size, hash}
  response: {status, size, content_type, error_signature?}
```

## 3. Diff 알고리즘

1. 각 요청을 Canonical로 변환 (Decode Chain 적용값 병행 보관).
2. 연속 요청 쌍 `(i-1, i)` 비교 + 기준 요청(#1) 대비 누적 비교.
3. 필드별 변경 분류:

| 변경 유형 | 판정 |
|---|---|
| `METHOD_SWITCH` | method 다름 |
| `PATH_CHANGE` | 세그먼트 추가/삭제/변경 (case 변경은 `CASE_VARIATION`) |
| `PARAM_RENAME` | 값이 같고 이름이 다름 (`id`→`userId`) |
| `PARAM_LOCATION_MOVE` | 이름·값 동일, 위치 다름 (query → json) |
| `PARAM_VALUE_CHANGE` | 값 변경 (숫자 증감이면 `+n` 표시) |
| `PARAM_ADDED / REMOVED` | |
| `ENCODING_CHANGE` | decoded 동일, raw 다름 (이중 인코딩 등) |
| `HEADER_ADDED / CHANGED` | 특히 우회 헤더(X-Forwarded-For, X-Original-URL, X-HTTP-Method-Override, Origin, Referer) 강조 |
| `AUTH_CHANGE` | Authorization/세션 쿠키 변경 (값은 해시 비교) |
| `BODY_CHANGE` | kind/size/hash |
| `RESPONSE_CHANGE` | status/size/error signature |

4. **Bypass Point**: `status ∈ {401,403,404,405,4xx}` → `2xx` 로 바뀐 전이, 혹은 응답 크기가 baseline 대비 급변(×3 이상)한 전이.
5. **Mutation Strategy 요약**: 변경 유형 빈도 → “Parameter renaming + Method switching 기반 우회 시도 패턴”.
6. 요청이 많으면(> 20) `uri_template` + 변경 유형으로 **그룹화** 후 대표 요청만 흐름에 표시.

## 4. 시각화 — Request Evolution

```
REQUEST EVOLUTION                                   Strategy: param rename → method switch → location move

 ┌ #1 ───────────┐      ┌ #2 ───────────┐      ┌ #3 ───────────┐
 │ GET           │      │ GET           │      │ POST       ~  │
 │ /api/user     │ ───▶ │ /api/user     │ ───▶ │ /api/user     │
 │ id=100  query │      │ userId~ =100  │      │ id=100  json~ │
 │ ▲ 403  512B   │      │ ▲ 403  512B   │      │ ✓ 200 1.8KB   │ ⚑ BYPASS POINT
 └───────────────┘      └───────────────┘      └───────────────┘
        PARAM_RENAME            METHOD_SWITCH + PARAM_LOCATION_MOVE
```

- 노드 = 요청, 엣지 라벨 = 변경 유형. 변경 필드는 색 + 기호(`+` 추가, `−` 삭제, `~` 변경).
- 상태 코드는 아이콘(▲ 실패, ✓ 성공)과 텍스트 병기.
- 노드 클릭 → 하단에 **Side-by-side Diff**(구조화 테이블) / [Raw Diff](Monaco Diff, lazy).

### Structured Diff Table
| Field | #2 | #3 | Change |
|---|---|---|---|
| method | GET | POST | ~ METHOD_SWITCH |
| param `id` | — (query `userId`) | json `$.id` = 100 | ~ LOCATION query→json |
| Content-Type | — | application/json | + |
| status | 403 | 200 | ⚑ BYPASS |
| size | 512 | 1,832 | ×3.6 |

## 5. 다음 행동

- [이 변경 패턴으로 로그 검색]: Bypass 이후 형태(`POST /api/user` + json `id`)로 Investigation 검색
- [Finding 생성]: “Potential Access Control Bypass via Request Mutation” (분석가 수동 생성)
- [Detection Candidate]: 403 이후 동일 src에서 method/location 변경 후 200 — 시퀀스 조건 초안
- [Add to Case]

## 6. 구현 메모

- `analyzers/diff/` 순수 함수: `canonicalize(raw) → CanonicalRequest`, `diff(a,b) → list[Change]`, `evolution(reqs) → EvolutionGraph`.
- Frontend: React Flow(노드 레이아웃 좌→우, 20개 초과 시 래핑), Monaco Diff는 Raw 탭에서만 로드.
