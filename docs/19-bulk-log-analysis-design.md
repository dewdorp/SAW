# 19. Bulk Log Analysis Design

다수 로그 파일 업로드는 **CORE** 기능이다. 목표: 수백만 이벤트를 사람이 한 줄씩 보지 않고 **Overview → Pattern → Findings** 로 이해.

## 1. 파이프라인

```
Drag & Drop (37 files, 12.8 GB)
  → Resumable Upload (파일별 진행률, 재개)                 [api → S3]
  → Safe Decompress                                       [worker-ingest]
  → File Detection (magic + 샘플)                          [worker-ingest]
  → Parser Detection (스코어링) → 확인 필요 시 WAITING_INPUT
  → Streaming Parse → Normalize(CES) → Enrich(offline)    [worker-parse]
  → OpenSearch Bulk Indexing
  → Statistics (부분 → 최종)                              [worker-analyze]
  → Pattern Clustering → Parameter Analysis → Detectors → Findings
  → Relations → Attack Story
```
상세 Job 설계: [10](10-job-processing-design.md)

## 2. Parser Framework

```python
class LogParser(Protocol):
    id: str                 # "nginx_combined"
    version: str            # "1.2.0"
    data_source: str        # "web"
    def detect(self, sample: list[str]) -> float: ...        # 0..1
    def parse(self, lines: Iterator[RawLine]) -> Iterator[ParseResult]: ...
    # ParseResult = Parsed(CESEvent, ext={...}) | Failed(raw, reason)
```

| Parser | 대상 | 비고 |
|---|---|---|
| ApacheParser | common/combined/vhost_combined, 커스텀 LogFormat 지정 | LogFormat 문자열 → 파서 생성 |
| NginxParser | combined, main, `$request_time` 등 확장 | log_format 문자열 지원 |
| IISParser | W3C Extended (`#Fields:` 헤더 기반) | |
| JsonParser | JSON Lines, 필드 매핑 프로파일 | 매핑 프로파일 = YAML |
| CsvParser | 헤더 기반, 구분자 감지 | |
| SyslogParser | RFC3164/5424, 메시지부는 하위 파서 위임 | |
| CloudflareParser | Logpush HTTP requests / Firewall events (JSON) | 필드 사전 |
| GenericWafParser | 벤더별 프로파일(YAML) + KV/JSON/CEF/LEEF | 국내 WAF 벤더 프로파일 추가 대상 |
| KeyValueParser | `k=v` / `k="v"` | |
| CustomParser | Grok/Regex(RE2) 정의 + 필드 매핑, UI에서 테스트 | 버전관리, Senior 승인 후 공유 |

규칙:
- **Unknown field는 버리지 않는다** → `ext.<product>.*`
- Raw + Normalized 동시 보존 ([ADR-0014](adr/0014-raw-and-normalized-retention.md))
- 파서마다 `tests/fixtures/parsers/<id>/` 의 입력/기대출력 골든 테스트 필수
- 파싱 실패 라인은 `Failed`로 카운트·샘플 보관 (조용히 버리지 않음)

### Parser Detection
샘플 200줄(파일 앞·중간·끝)에 모든 파서 `detect()` → 최고 점수 ≥ 0.8 자동, 0.5~0.8 후보 제시 + 미리보기(파싱된 5행), < 0.5 Custom Parser 안내.

## 3. 결정적 정규화 (uri_template)

| 원본 토큰 | 치환 |
|---|---|
| 순수 숫자 (경로 세그먼트/값) | `<NUM>` |
| UUID | `<UUID>` |
| 16진 ≥ 16자 | `<HEX>` |
| ISO/epoch 시간 | `<TIME>` |
| Base64/JWT 토큰 형태 (≥ 20자) | `<TOKEN>` |
| 이메일 | `<EMAIL>` |
| IP | `<IP>` |
| 쿼리 파라미터 값 | 위 규칙 적용, 그 외 `<STR>` (이름은 보존, 정렬) |

`/api/customer?id=10001&fmt=json` → `/api/customer?fmt=<STR>&id=<NUM>`

## 4. Pattern Clustering

```
8,238,291 events  ──▶  37 Behavioral Patterns
```
- 1단계(결정적): `(method, uri_template, status_class, ua_class)` 그룹.
- 2단계: 그룹 수가 많거나 URI 외 비정형 메시지(Syslog 등)는 **Drain3** 템플릿 마이닝.
- 3단계: 의미 그룹 태깅 (사전 규칙): `sensitive_file_probe(/.env, /.git/*, /config*, /backup*)`, `cms_probe(/wp-admin/*)`, `injection_like(libinjection 태그 비율)`, `static_assets`.
- 클러스터 표시:

```
#  Pattern                              Events   Src IP  2xx%  First→Last     Tags
01 GET /api/customer?id=<NUM>          21,322     43    91.4  02:58→03:41   ▲ sequential-param
02 GET /wp-admin/*                     18,441    812     0.2  종일            cms-probe
03 GET /.env | /.git/* | /config        4,293    207     0.0  종일            sensitive-file-probe
04 * /search?q=<STR> (SQLi-like)          383      3    12.0  03:02→03:05   ■ injection-like
```
클릭 → 전역 필터 `pattern_id`.

## 5. Parameter Analyzer

`(uri_template, param_name, location)` 별 프로파일:

| 지표 | 계산 |
|---|---|
| Type | numeric / uuid / hex / base64 / email / free-text / enum(≤ 20 values) |
| Unique | cardinality (≈) |
| Sequential Ratio | src(또는 session)별 시간순 정렬 후 연속 값 차이가 동일 상수(|d| ≤ 2)인 비율 |
| Increment | 최빈 차이 (`+1`) |
| Entropy | 값 문자 엔트로피 평균/분포 |
| Length | min/p50/p95/max |
| Numeric Range | min~max, 커버리지(unique/range) |
| Prefix/Suffix | 공통 접두/접미 |
| Mutation | 동일 src에서 값 형태 변화(숫자→따옴표 포함 등) |
| Payload Family | libinjection/패턴 태그 분포 (sqli/xss/traversal …) |

시각화:
```
PARAMETER  id  @ /api/customer (query)      Type NUMERIC · Unique ≈18,991 · Sequential 98.2% · Increment +1
Value Step Plot (time →)
 10001 ▁▂▃▄▅▆▇█  (계단형 직선 = 순차 열거)
 Potential Behavior: Sequential Enumeration   [Related Events] [Create Finding]
```

## 6. Visual Summary (첫 화면)

```
WEB LOG ANALYSIS   37 Files · 8,238,291 Events · 2026-10-01 ~ 2026-10-05
Unique IP ≈143,882 · Unique URI 8,172 · Patterns 37 · Findings 14 (▲3 ■7 ●4)   Parse errors 0.02%
```
아래 9개 시각화 (모두 클릭 가능 → 전역 필터):

| 차트 | 형태 | 클릭 |
|---|---|---|
| Event Volume Timeline | Area + 상태코드 stack, brush | 시간 필터 |
| HTTP Status Distribution | Bar(2xx/3xx/4xx/5xx → 세부) | status 필터 |
| Response Size Trend | p50/p95 line + 이상점 | 구간 필터 |
| Unique IP Trend | line (bucket별 cardinality) | 시간 필터 |
| Top Source | H-bar (IP + ASN 칩) | src_ip include/exclude |
| Top URI (template) | H-bar | uri_template |
| Top User-Agent | H-bar (ua_class 아이콘) | user_agent |
| Top ASN | H-bar (cloud 배지) | src_asn |
| Top Country | H-bar (지도 아님) | country |

## 7. Web Detectors (Findings)

| Detector | 핵심 지표 |
|---|---|
| API Enumeration | sequential ratio, unique objects, 2xx 비율, rate vs baseline, 다수 src 동일 fingerprint |
| Discovery / Forced Browsing | 404 burst, 경로 다양성, 단시간 |
| Sensitive File Probe | 민감 경로 사전 매칭, 2xx 발생 시 위험 상승 |
| Credential Attack | 로그인 엔드포인트 POST, 401/실패 비율, 계정 다양성(stuffing) vs 반복(brute) |
| Injection-like Requests | libinjection 태그, 동일 src의 payload 변이 |
| Scripted Client | ua_class=script/empty, 일정 간격(CV 낮음) |
| Large Response / Data Volume | bytes_out 이상치, 특정 src 누적 |
| Off-hours Sensitive Access | Asset expected_access_time 벗어남 |
| Request Mutation then Success | 동일 src 403→변형→200 (Request Diff 연계) |
| Rare Path Access | 전체에서 희귀 + 2xx |

각 Detector는 [24](24-finding-design.md)의 Finding 계약을 따르고, Asset Knowledge가 있으면 baseline을 사용, 없으면 **Investigation 내부 상대 비교**(다른 src 대비)로 대체하며 그 사실을 표시한다.

## 8. 성능 전략

- 파싱: 파일당 프로세스, 정규식 사전 컴파일, `orjson`, 배치 normalize. 병목 시 Rust 확장(PyO3) 검토(Phase 5 벤치마크 후).
- 통계는 OpenSearch 집계 사용 (Python으로 전체 스캔 금지). Parameter 분석의 sequential ratio는 `uri_template`별 **composite agg + 샘플링(최대 200k 값)** 후 Python 계산, 샘플 사용 시 “sampled” 표시.
- Drain3는 그룹 대표 샘플(템플릿당 ≤ 1k)로 실행.
