# 03. System Architecture

## 1. 아키텍처 스타일

- **Modular Monolith + Hexagonal (Ports & Adapters)** — 하나의 Python 코드베이스, 두 종류의 프로세스(API / Worker).
- **Analyzer = 순수 라이브러리**: IO 없이 `입력 + ContextProvider(Port)` → 결과. API(소량 동기)와 Worker(대량 비동기)가 같은 코드를 사용.
- 무거운 처리(PCAP, 대용량 로그)는 **절대 API 프로세스에서 하지 않는다.**
- 외부 OSS(Zeek/Suricata/tshark/IntelOwl/Arkime/LLM)는 모두 **Adapter 뒤**에 둔다.

근거: [ADR-0002](adr/0002-modular-monolith-hexagonal.md). 마이크로서비스는 팀 규모·운영 부담 대비 이득이 없다.

## 2. Context Diagram

```
                         ┌───────────────┐
  SOC Analyst / Hunter ─▶│               │──▶ Existing SIEM (Logpresso)  [read-only Connector]
  Detection Engineer  ─▶ │      SAW      │──▶ WAF / NDR / EDR / FW / ASM [read-only, 향후]
  Reviewer / Manager  ─▶ │               │──▶ Internal TI / IntelOwl     [optional]
  Admin               ─▶ │               │──▶ Egress Proxy (RDAP/WHOIS)  [policy-gated]
                         │               │──▶ Local LLM (Ollama/vLLM)    [no egress]
                         └───────┬───────┘
                                 │ audit/ops logs
                                 ▼
                          Existing SIEM (플랫폼 감사로그 수집)
```

## 3. Container Diagram

```
 Zone U (사용자)           Zone A (Application)                     Zone P (Processing, no internet)
┌───────────┐  TLS   ┌────────────┐      ┌───────────────┐        ┌──────────────────────────────┐
│ Browser   │──────▶ │ gateway    │────▶ │ api (FastAPI) │──┐     │ worker-ingest  (q.ingest)    │
│ React SPA │        │ nginx      │      │  routers      │  │     │ worker-parse   (q.parse)     │
└───────────┘        │ static web │      │  app services │  │     │ worker-pcap    (q.pcap)      │
                     │ CSP / WAF  │      │  SSE progress │  │     │   └ zeek/suricata/tshark     │
                     └────────────┘      └──────┬────────┘  │     │ worker-analyze (q.analyze)   │
                                                │           │     │   stats/pattern/finding/     │
                                                │           │     │   correlation/anomaly        │
                                                │           │     │ worker-ai      (q.ai)        │
                                                │           │     │   embedding / llm tasks      │
                                                │           │     │ scheduler (beat)             │
                                                │           │     └──────────────┬───────────────┘
                                                ▼           ▼                    ▼
 Zone D (Data)      ┌──────────────┐ ┌──────────────┐ ┌─────────────┐ ┌──────────────────┐
                    │ PostgreSQL   │ │ OpenSearch   │ │ Valkey/Redis│ │ Object Storage   │
                    │ + pgvector   │ │ (events)     │ │ queue/cache │ │ (MinIO, S3 API)  │
                    └──────────────┘ └──────────────┘ └─────────────┘ └──────────────────┘

 Zone E (Egress, optional)                 Zone L (AI, optional, no internet)
┌───────────────────────────────┐        ┌─────────────────────────────────┐
│ worker-enrich (q.enrich)      │──proxy▶│ ollama / vLLM / embed-server    │
│  RDAP/WHOIS/TI via allowlist  │        └─────────────────────────────────┘
└───────────────────────────────┘
 Optional integrations: cyberchef (static), intelowl, arkime — 각각 별도 Compose profile
```

### 3.1 컴포넌트 책임

| 컴포넌트 | 책임 | 비고 |
|---|---|---|
| `gateway` | TLS 종료, 정적 SPA, CSP·보안 헤더, 업로드 크기 제한, Rate limit | nginx |
| `api` | 인증/인가, 입력 검증, 동기 소형 분석, Job 생성, 조회 API, SSE | 비즈니스 로직은 `core/application` |
| `worker-ingest` | 업로드 완료 처리, 해시 검증, Safe Decompress, 파일/파서 감지 | 샌드박스 |
| `worker-parse` | 스트리밍 파싱 → 정규화 → Bulk 인덱싱 | LogParserWorker |
| `worker-pcap` | Zeek/Suricata/tshark 실행, 결과 → OpenSearch | PcapWorker, 가장 강한 샌드박스 |
| `worker-analyze` | 통계, Pattern Clustering, Parameter, Finding Detector, Correlation, Anomaly | Statistics/Correlation/AnomalyWorker |
| `worker-enrich` | IOC 외부 Enrichment (정책 허용 시) | IOCWorker. 유일한 Egress 경로 |
| `worker-ai` | 임베딩 생성, LLM Task | Zone L 접근 |
| `scheduler` | Baseline 갱신, Knowledge 만료 알림, 보존기간 정리 | Celery beat |
| PostgreSQL | 관계형 메타데이터, Knowledge, Audit, Vector | [07](07-database-design.md) |
| OpenSearch | 이벤트 검색·집계, Knowledge Keyword(nori) | [08](08-opensearch-design.md) |
| Valkey/Redis | Celery broker/result, 진행률, 캐시, Rate limit | [ADR-0006](adr/0006-celery-valkey-queues.md) |
| Object Storage | Evidence 원본, 추출물, 도구 산출물, Export | [09](09-object-storage-design.md) |

## 4. Network Zones / Egress Control

| From → To | 허용 | 비고 |
|---|---|---|
| U → gateway | 443 | 사내 관제망 |
| gateway → api | 8000 | |
| api → PG/OS/Redis/S3 | 각 포트 | |
| workers(P) → PG/OS/Redis/S3 | 각 포트 | **인터넷 차단** |
| worker-enrich → egress proxy | 3128 | Allowlist 도메인만 (RDAP, 승인된 TI) |
| worker-ai, api → LLM(L) | 11434 / 8000 | LLM 서버는 Egress 차단 |
| 모든 컨테이너 → Docker socket | **금지** | |
| OpenSearch/PG 외부 노출 | **금지** | API만 접근 |

Docker Compose에서는 `networks:` 분리(internal: true)로 구현하고, 호스트 방화벽(nftables)으로 이중 통제한다.

## 5. Backend Layering

```
apps/api (routers, DTO, deps)            ← HTTP 관심사만
   │
core/application (use cases, ports)      ← 트랜잭션, 권한 검사 호출, 오케스트레이션
   │                ▲ ports (interfaces)
core/domain (entities, policies)         ← 순수 도메인 규칙
   │
analyzers/ parsers/ (pure libs)          ← 결정적 분석 로직
   ▲
storage/ connectors/ integrations/ llm/  ← adapters (PG, OpenSearch, S3, Redis, Zeek, Ollama …)
workers/                                 ← Celery task = application service 호출하는 얇은 진입점
```

규칙:
- `analyzers/`, `parsers/`는 `storage/`를 import하지 않는다. (lint로 강제: import-linter)
- Controller/Task는 Application Service만 호출한다.
- 모든 쓰기 Use Case는 Audit Port를 호출한다.

## 6. Data Flows

### F1. Paste 분석 (동기)
```
Browser ─POST /analyze/universal─▶ api
  → 크기 검사(≤5MB) → UniversalDetector(analyzers/universal)
  → 감지 결과별 Analyzer (HTTP/IOC/Payload) 실행 (순수 함수)
  → InternalContextPort(OpenSearch/PG 조회, 타임아웃 2s)
  → 결과 + Recommended Actions 반환
  → (선택) "Add to Investigation" 시 Evidence(type=paste)로 S3 저장 + 감사
```

### F2. Bulk Log (비동기)
```
Browser ─resumable chunks─▶ api ─stream─▶ S3 multipart (evidence-original)
  → upload complete: SHA-256 검증, Evidence 레코드, Job 생성 → q.ingest
worker-ingest: Safe Decompress → evidence-extracted/ → 파일 타입·파서 감지 → 파일별 q.parse 분할
worker-parse: stream parse → normalize → bulk index (saw-web-*, saw-waf-* …) → 파일별 진행률
(모든 파일 완료) → q.analyze: Statistics → Pattern → Parameter → Detectors → Findings(PG)
api SSE: job 진행률 / 부분 통계 → Overview 점진 표시
```

### F3. PCAP (비동기)
```
upload → q.ingest (capinfos 검증, 형식 확인) → q.pcap
worker-pcap: S3 → local scratch → zeek -r / suricata -r / tshark(metadata)
  → zeek logs (JSON) + eve.json → 정규화 → saw-net-* 인덱싱
  → 산출물 원본 보관 (artifacts/) → q.analyze (Network Detectors) → Findings
```

### F4. Unified Investigation (조회 시)
```
Investigation = {Evidence 집합 + Connector 조회 범위}
Timeline/Graph/Story 요청 → api → InvestigationQueryService
  → OpenSearch multi-index query (investigation_id 필터 강제)
  → Correlation(entity + time window) 결과는 worker-analyze가 사전 계산하여 PG에 저장
```

### F5. Knowledge Loop
```
Investigation 종료 → Verdict → Experience Draft(PG) → Review → Approved
  → worker-ai: 임베딩(pgvector) + Keyword 인덱스(saw-knowledge, nori)
  → Similar Case 검색에 반영 → Detection Candidate → Historical Test → Approved → Export
```

## 7. Tech Stack

| 영역 | 선택 | 비고 |
|---|---|---|
| Frontend | React 18+, TypeScript, Vite | |
| 상태 | TanStack Query(서버 상태) + Zustand(Investigation Context) | |
| 시각화 | ECharts, Cytoscape.js, React Flow, TanStack Table/Virtual, Monaco(Diff) | [ADR-0010](adr/0010-frontend-visualization-stack.md) |
| Backend | Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy 2 + Alembic | |
| Worker | Celery 5 | |
| DB | PostgreSQL 16+, pgvector | |
| Event Store | OpenSearch 2.x (nori 플러그인) | |
| Queue/Cache | Valkey 8 (Redis 프로토콜) | Redis 사용 가능 |
| Object | MinIO (S3 API) | 교체 가능 설계 |
| PCAP | Zeek 7.x, Suricata 7.x+, tshark 4.x | |
| 패턴 | Drain3, libinjection | |
| LLM | Ollama / OpenAI-compatible / vLLM | Phase 11 |
| 배포 | Docker Compose (profiles), 향후 Kubernetes(Helm) | |

## 8. Deployment (Docker Compose Profiles)

| Profile | 포함 서비스 | 용도 |
|---|---|---|
| `core` | gateway, api, worker-ingest, worker-parse, worker-analyze, scheduler, postgres, opensearch, valkey, minio | 기본 |
| `pcap` | worker-pcap | Phase 6 |
| `enrich` | worker-enrich, egress-proxy(squid) | 외부 조회 허용 시 |
| `ai` | worker-ai, ollama 또는 vllm, embed-server | Phase 9/11 |
| `tools` | cyberchef(static), intelowl, arkime | 선택 |

오프라인 설치: 이미지 tar 번들 + 내부 레지스트리, GeoIP/ASN DB·Suricata 룰·Zeek 패키지 오프라인 업데이트 번들.

## 9. Kubernetes 이전 경로

- Worker → Deployment + HPA(큐 길이 기반, KEDA)
- worker-pcap → 전용 노드풀, PodSecurity `restricted`, NetworkPolicy
- OpenSearch → OpenSearch Operator, PG → CloudNativePG(+pgvector)
- 설정은 12-factor 환경변수, 상태 없는 컨테이너 유지 → 매니페스트 변경만으로 이전

## 10. Observability

- 플랫폼 로그: JSON stdout → 기존 SIEM 전송 (분석 데이터 원문 미포함)
- 메트릭: Prometheus exporter (api, celery, opensearch, pg) → 내부 Grafana(선택)
- 추적: OpenTelemetry (job_id, investigation_id 전파)

## 11. Repository Structure

모노레포. Python은 `uv` workspace(단일 패키지 `saw`의 하위 모듈), Frontend는 pnpm.

```
saw/
├─ apps/
│  ├─ web/                    React + TS (Vite)
│  │  └─ src/
│  │     ├─ app/              라우팅, 레이아웃(Workbench shell, 탭)
│  │     ├─ features/         home, analyze, investigation, findings, knowledge, cases, jobs, admin
│  │     ├─ visualizations/   attack-story, timeline, graph, charts, diff, raw-viewer, json-tree
│  │     ├─ context/          InvestigationContext store (Zustand), cross-highlight bus
│  │     ├─ entities/         IP/URI/JA4/User 등 Entity 칩 + 공통 Pivot 메뉴
│  │     └─ lib/              api client(OpenAPI 생성), safe-render, format
│  └─ api/                    FastAPI: routers / dto / deps (로직 금지)
├─ core/
│  ├─ domain/                 Entity, Value Object, 상태머신, 도메인 정책
│  ├─ application/            Use Case 서비스, Port 인터페이스
│  ├─ schemas/                Common Event Schema(Pydantic), JSON Schema export
│  └─ security/               authz 정책, masking, sanitization, upload guard
├─ analyzers/                 universal, ioc, http, payload, log, pcap, diff,
│                             timeline, relation, anomaly, pattern, parameter, story
├─ detectors/                 Finding Detector 플러그인 (web/, network/, cross/)
├─ parsers/                   apache, nginx, iis, cloudflare, syslog, json, csv, kv, waf_generic, custom
├─ visualization/             Backend View-model builder (attack_story, timeline, graph, charts)
├─ connectors/                siem/(port), logpresso/(mock 우선), cloudflare, ndr, edr, ti
├─ integrations/              zeek, suricata, tshark, intelowl, cyberchef, timesketch, arkime, malcolm(ref)
├─ knowledge/                 experience, asset, playbook, false_positive
├─ investigations/  cases/  hunting/  detection/  llm/
├─ workers/                   celery app, tasks(얇은 진입점), sandbox runner
├─ storage/                   postgres(repo), opensearch, objectstore, cache
├─ deploy/
│  ├─ compose/                docker-compose.yml + profiles, .env.example
│  ├─ nginx/  opensearch/(templates, ISM)  postgres/(init)  sandbox/(seccomp, apparmor)
│  └─ offline/                오프라인 번들 스크립트
├─ tests/
│  ├─ unit/  contract/  integration/  e2e/
│  └─ fixtures/               샘플 로그(포맷별), PCAP, HTTP, 악성 입력(zip bomb, XSS payload 등)
└─ docs/
```

경계 규칙(import-linter로 CI 강제):
- `analyzers`, `parsers`, `detectors` → `core.domain`, `core.schemas`만 의존
- `apps.api`, `workers` → `core.application`만 호출
- `storage`, `connectors`, `integrations`, `llm` → Port 구현 (application이 인터페이스 소유)
