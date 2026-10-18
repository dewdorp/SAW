# SAW — SOC Analysis Workbench

> 금융권 보안관제센터용 **On-Premise SOC Analyst & Threat Hunting Platform**
> 코드명 `SAW` (SOC Analysis Workbench)

| 항목 | 값 |
|---|---|
| 현재 상태 | **Windows 폐쇄망 개발 파일럿 · 개발기 설치/분석/업데이트/복구 확인** |
| 문서 기준일 | 2026-10-18 |
| 최신 매체 | **v0.1.0-pilot.20261018.1 · 모델 제외 · 더블클릭 업데이트 포함** |
| 남은 인수 | 깨끗한 LTSC2019 x64·실제 관리자 서비스·무GPU 16/32GB 공동 부하·모델 품질·운영 승인 |

모델 가중치를 제외한 본체 설치 매체와 별도 모델 반입을 지원합니다. 지정 모델의 CPU 생성은 확인했지만 한국어·인용 품질은 미채택이며 운영 답변에 자동 적용하지 않습니다. 최신 구현·검증 범위와 현재 작업은 [STATE.md](STATE.md)에 기록합니다. 상세 이력은 [PROGRESS.md](PROGRESS.md)에 보존합니다.

**설치 매체:** [최신 비공개 사전 배포](https://github.com/dewdorp/SAW/releases/tag/v0.1.0-pilot.20261018.1)에서 `SAW-0.1.0-pilot.20261018.1-model-free-win-x64.zip`을 받습니다. 저장소 접근 권한이 필요합니다. 기존 설치를 업데이트하려면 ZIP을 기존 설치 밖에 해제하고 `UPDATE-SAW.cmd`를 실행한 뒤 창에서 기존 설치를 선택합니다. [더블클릭 그림 안내](docs/DOUBLE-CLICK-UPDATE-GUIDE.html)와 [업데이트·전체 복구 설명](docs/DOUBLE-CLICK-UPDATE-GUIDE.md)을 먼저 확인하세요. 새 설치와 실패 재개는 매체의 START-HERE.md 및 [설치 위치·재개 안내](docs/INSTALL-RECOVERY-2026-10-18.md)를 따릅니다.

| 하고 싶은 일 | 화면에서 시작할 곳 | 안내 |
|---|---|---|
| 로그·PCAP 분석 | 조사 목록 → 조사 열기 → 증거 추가 | [사용 설명서](docs/USER-MANUAL.md) · [합성 자료로 처음 써보기](docs/DEMO-GUIDE.md) |
| 통계와 원문 확인 | 조사 열기 → 로그 통계 | [통계·시간별 행동 변화](docs/STATISTICS-TEMPORAL-GUIDE.md) |
| 웹 행위 분석·보고서 | 조사 열기 → 행위 분석 | [사용법·실제 화면](docs/BEHAVIOR-ANALYSIS-GUIDE.md) |
| 기본 탐지 확인 | 탐지 룰 → 기본 탐지 목록 | [탐지 목록](docs/DETECTION-CATALOG-GUIDE.md) · [화면 따라하기](docs/DETECTION-LIVE-WALKTHROUGH.md) |
| 룰·파서 JSON 반입 | 오프라인 룰·파서 | [합성 예제·독립 승인·적용·되돌리기](docs/OFFLINE-CONTENT-GUIDE.md) |
| 조사 기록·Golden | 조사 작업대 → 확인 기록·종결 | [조사·Golden 사용법](docs/GUIDANCE-GOLDEN-GUIDE.md) |
| 로컬 모델 반입·교체 | 관리 → 로컬 모델 | [모델 반입·교체](docs/LOCAL-MODEL-GUIDE.md) · [AI 권한 계약](docs/LOCAL-AI-DESIGN.md) |

실제 확인한 환경은 Windows 11 / PowerShell 5.1의 합성 NoAdmin 설치입니다. 대상 LTSC·관리자 서비스·운영 인수 범위와 모델 한계는 [현재 상태](STATE.md)에서 확인합니다. 아래 설계 문서와 단계 표는 설계 이력이며 현재 실행 성공의 근거로 사용하지 않습니다.

---

## 1. 이 제품은 무엇인가

SAW는 **SIEM이 아니다.** 기존 SIEM / SOAR / NDR / WAF / IPS / Firewall / EDR / ASM / API Gateway / DB Audit는 그대로 두고,
그 위에서 분석가의 판단을 돕는 **Analysis Intelligence Layer** 다.

```
            ┌──────────────────────── SAW (Analysis Intelligence Layer) ────────────────────────┐
 Alert ───▶ │  Paste / Upload  →  Analyze  →  Correlate  →  Visualize  →  Knowledge  →  Hunt  →  Detect │
 Evidence ─▶│  (IOC·HTTP·Payload·Log·PCAP)   (Findings·Story·Timeline·Graph)  (Experience·Similar) (Sigma) │
            └───────────────▲─────────────────────────────▲─────────────────────────────────────┘
                            │ read-only connectors          │ export only (자동 배포 금지)
       SIEM(Logpresso) · WAF · NDR · EDR · FW · DB Audit     SIEM / IPS / WAF 룰 저장소
```

분석가는 데이터를 **붙여넣거나 업로드**하고 →
**무슨 일이 일어났는지(Story)** → **왜 그렇게 판단했는지(Evidence)** → **원본(Raw)** 순으로 내려간다.
분석 결과는 **Case**로 저장되고, 검토를 거쳐 **SOC Experience**가 되며, 유사 사건에서 다시 쓰이고, **Detection Candidate**로 전환된다.

## 2. 핵심 원칙 (요약)

1. **Not a SIEM** — 수집·장기보관·상시 상관룰은 기존 SIEM의 몫. SAW는 “분석”에 집중한다.
2. **Story First → Evidence Second → Raw on Demand**
3. **Evidence-backed** — 모든 판단은 근거와 함께. “SQL Injection 공격”이 아니라 “Potential SQL Injection Pattern + Evidence”.
4. **Deterministic First, AI Second** — Rule·통계·Baseline·ML이 후보를 찾고, LLM은 설명·요약·제안만.
5. **Internal Context > External IOC** — 우리 자산·과거 판단·내부 로그가 외부 TI보다 우선.
6. **Human-in-the-loop** — 차단·정책 변경·룰 배포는 절대 자동으로 하지 않는다.
7. **Everything is Untrusted** — Log·Payload·PCAP·File 내용은 모두 신뢰할 수 없는 데이터.
8. **Reuse OSS** — Zeek·Suricata·OpenSearch·pySigma 등을 재구현하지 않는다.
9. **Knowledge Compounds** — Reviewer가 승인한 경험만 조직 지식이 된다.

## 3. 문서 맵

### Product
| # | 문서 | 내용 |
|---|---|---|
| 00 | [Product Vision](docs/00-product-vision.md) | 문제, 비전, 포지셔닝, Persona, 원칙, 성공지표 |
| 01 | [Functional Requirements](docs/01-functional-requirements.md) | 기능 요구사항 (FR-ID, 우선순위, Phase) |
| 02 | [Non-Functional Requirements](docs/02-non-functional-requirements.md) | 성능·확장성·보안·감사·설명가능성 |

### Architecture
| # | 문서 | 내용 |
|---|---|---|
| 03 | [System Architecture](docs/03-system-architecture.md) | 컨테이너 구조, 네트워크 Zone, Data Flow, 배포 |
| 04 | [Open Source Evaluation](docs/04-open-source-evaluation.md) | OSS / Frontend 라이브러리 평가, 라이선스 정책 |
| 05 | [Domain Model](docs/05-domain-model.md) | Bounded Context, Aggregate, 상태 머신 |
| 06 | [Common Event Schema](docs/06-common-event-schema.md) | 정규화 이벤트 스키마, ECS/OCSF 매핑 |
| 07 | [Database Design](docs/07-database-design.md) | PostgreSQL / pgvector 테이블 |
| 08 | [OpenSearch Design](docs/08-opensearch-design.md) | Index, Mapping, ISM, 쿼리 패턴 |
| 09 | [Object Storage Design](docs/09-object-storage-design.md) | Bucket, Key, 무결성, Chain of Custody |
| 10 | [Job Processing Design](docs/10-job-processing-design.md) | Queue, Worker, 상태 머신, 진행률 |
| 11 | [API Design](docs/11-api-design.md) | REST 리소스, 비동기, 에러 모델 |
| 12 | [Security Architecture](docs/12-security-architecture.md) | 인증·RBAC·감사·마스킹·샌드박스 |
| 13 | [Threat Model](docs/13-threat-model.md) | STRIDE + 플랫폼 특화 위협 |

### UX / Visual
| # | 문서 | 내용 |
|---|---|---|
| 14 | [UI/UX Principles](docs/14-ui-ux-principles.md) | Visual SOC Analyst IDE 원칙, Design Language |
| 15 | [Visual Investigation Design](docs/15-visual-investigation-design.md) | Workbench 구조, Cross-highlighting, 시각화 선택 규칙 |
| — | [UI Wireframes](docs/wireframes/README.md) | 15개 핵심 화면 Wireframe |

### Analysis Modules
| # | 문서 |
|---|---|
| 16 | [Universal Analysis](docs/16-universal-analysis-design.md) |
| 17 | [HTTP Analysis](docs/17-http-analysis-design.md) |
| 18 | [Request Diff](docs/18-request-diff-design.md) |
| 19 | [Bulk Log Analysis](docs/19-bulk-log-analysis-design.md) |
| 20 | [PCAP Analysis](docs/20-pcap-analysis-design.md) |
| 21 | [Attack Story](docs/21-attack-story-design.md) |
| 22 | [Relation Graph](docs/22-relation-graph-design.md) |
| 23 | [Timeline](docs/23-timeline-design.md) |
| 24 | [Finding](docs/24-finding-design.md) |

### Knowledge / Intelligence
| # | 문서 |
|---|---|
| 25 | [SOC Experience](docs/25-soc-experience-design.md) |
| 26 | [Similar Case](docs/26-similar-case-design.md) |
| 27 | [Asset Knowledge](docs/27-asset-knowledge-design.md) |
| 28 | [Anomaly Detection](docs/28-anomaly-detection-design.md) |
| 29 | [Local LLM](docs/29-local-llm-design.md) |
| 30 | [Threat Hunting](docs/30-threat-hunting-design.md) |
| 31 | [Detection Engineering](docs/31-detection-engineering-design.md) |
| 32 | [Case & Investigation](docs/32-case-investigation-design.md) |
| 33 | [Development Roadmap](docs/33-development-roadmap.md) |
| 34 | [MITRE ATT&CK Integration & Visualization](docs/34-mitre-attack-integration-design.md) |

### Decisions
- [Architecture Decision Records](docs/adr/README.md)

## 4. 핵심 결정 요약

| 영역 | 결정 | ADR |
|---|---|---|
| 제품 경계 | SIEM 대체가 아닌 Analysis Layer. 외부 시스템은 read-only 연동 | [0001](docs/adr/0001-analysis-layer-not-siem.md) |
| 백엔드 구조 | 모듈러 모놀리스 + Hexagonal(Ports & Adapters), Analyzer는 순수 라이브러리 | [0002](docs/adr/0002-modular-monolith-hexagonal.md) |
| 이벤트 저장 | OpenSearch (Raw + Normalized 동시 보존) | [0003](docs/adr/0003-opensearch-event-store.md), [0014](docs/adr/0014-raw-and-normalized-retention.md) |
| PCAP | MVP = Zeek + Suricata + tshark → OpenSearch (Option A). Arkime는 Deep-dive 옵션, Malcolm은 Reference | [0004](docs/adr/0004-pcap-pipeline-option-a.md) |
| Object Storage | S3 호환 Port 뒤에 MinIO. 라이선스·배포정책 리스크로 교체 가능 설계 | [0005](docs/adr/0005-s3-compatible-object-storage.md) |
| Queue/Worker | Celery + Redis 프로토콜(Valkey 권장), 큐 분리 | [0006](docs/adr/0006-celery-valkey-queues.md) |
| AI | Deterministic First. LLM은 Assistant, Raw Log 미전달, Shell 권한 없음 | [0007](docs/adr/0007-deterministic-first-llm-assistant.md) |
| Similar Case | Keyword(nori) + Structured Feature + Vector(pgvector) Hybrid | [0008](docs/adr/0008-hybrid-similarity.md) |
| Knowledge | Reviewer 승인 후에만 Production Knowledge (4-eyes) | [0009](docs/adr/0009-experience-four-eyes.md) |
| Frontend 시각화 | ECharts / Cytoscape.js / React Flow / TanStack Table+Virtual / Monaco(Diff) | [0010](docs/adr/0010-frontend-visualization-stack.md) |
| Payload Decode | 결정적 Decode Chain은 자체 구현(작고 감사 가능), CyberChef는 정적 호스팅 Deep-dive | [0011](docs/adr/0011-payload-decode-strategy.md) |
| SIEM 연동 | Connector 추상화 + MockLogpressoConnector 우선. 실제 API 문서 확보 전 구현 금지 | [0012](docs/adr/0012-connector-mock-first.md) |
| ATT&CK | 관찰 기반 Story 유지 + ATT&CK은 출처·신뢰도·조건이 붙은 Overlay. Navigator·Attack Flow·TIE 연동 | [0015](docs/adr/0015-attack-as-evidence-backed-lens.md) |
| 대용량 업로드 | API 경유 Resumable Chunked Upload → S3 Multipart (파싱은 Worker) | [0013](docs/adr/0013-resumable-upload-through-api.md) |

## 5. 단계 (초기 설계 이력)

| Phase | 범위 | 마일스톤 |
|---|---|---|
| 0 | 설계 문서 | — |
| 1 | Repo, Docker Compose, PG/Redis/MinIO/OpenSearch, Auth, RBAC, Audit | Foundation |
| 2–3 | Universal / IOC / HTTP / Payload / Request Diff / Single Log / Basic Timeline | **Analyzer Alpha** |
| 4–5 | Workbench UI, Findings, Attack Story, Bulk Log 파이프라인, Pattern/Parameter | **MVP** |
| 6–7 | PCAP, Unified Investigation, Cross-source Correlation | Beta |
| 8–9 | SOC Experience, Asset, Similar Case | **V1** |
| 10–14 | Connector, Local LLM, Anomaly, Hunting, Detection Engineering | V2+ |

상세: [33-development-roadmap.md](docs/33-development-roadmap.md)

## 6. Phase 0 당시의 착수 조건 (이력)

초기 설계 단계에는 문서 작성 뒤 구현을 시작하지 않고, 명시적 승인 문구 `Phase 1 진행` 이후 Phase 1을 시작하도록 정했습니다. 이후 구현·검증·배포 이력은 [PROGRESS.md](PROGRESS.md), 현재 승인된 작업과 남은 인수는 [STATE.md](STATE.md)를 따릅니다.
