# 33. Development Roadmap

가정: 핵심 팀 4–5명 (Backend 2, Frontend 1–2, Security/Detection 1, PO/UX 겸임 1). 기간은 **추정**이며 Phase 1 완료 후 재산정.

## 1. Milestones

| Milestone | 포함 Phase | 의미 |
|---|---|---|
| Foundation | 1 | 안전한 기반 (Auth, RBAC, Audit, 저장소) |
| Analyzer Alpha | 2–3 | 붙여넣기 분석이 실무에서 쓸 만함 |
| **MVP** | 4–5 | 대용량 로그를 Workbench에서 시각적으로 분석 |
| Beta | 6–7 | PCAP + Unified Investigation |
| **V1** | 8–9 | 경험 축적·유사사례 → V1 Success Criteria 10개 충족 |
| V2 | 10–14 | Connector, LLM, Anomaly, Hunting, Detection |

## 2. Phase 상세

| Phase | 범위 | 주요 산출물 | Exit Criteria | 추정 |
|---|---|---|---|---|
| 0 | 설계 | 본 문서 세트, ADR, Wireframe | 승인 “Phase 1 진행” | 완료 |
| 1 | Repo, Compose, PG, Redis(Valkey), MinIO, OpenSearch, Auth(+MFA), RBAC, Audit | 실행 가능한 빈 Workbench Shell, CI(lint/test/SAST/SBOM) | 보안 회귀 테스트 기본 세트 통과, 오프라인 설치 1회 성공 | 4주 |
| 2 | Universal, IOC(오프라인+내부), HTTP, Payload Decode | Home 붙여넣기 → 결과 화면 | 실제 Alert 샘플 50건 중 90% 정상 인식 | 5주 |
| 3 | Request Diff, Single Log Analyzer, Basic Timeline | Diff Evolution, 로그 붙여넣기 요약 | 분석가 파일럿 피드백 | 4주 |
| 4 | Workbench, Finding UI, Attack Story, Timeline, Relations, Context Panel, Case(기본) | Investigation 화면 | Drill-down 경로 Finding→Raw 동작, Cross-highlight | 6주 |
| 5 | Bulk Upload, Parser Framework, Async Jobs, Indexing, Stats/Charts, Pattern, Parameter, Web Detectors | Bulk Log Overview | 10M events < 10분, Finding 정밀도 측정 시작 | 7주 |
| 6 | PCAP (Zeek/Suricata/tshark), Overview, Tabs, Network Findings; 6b Arkime 평가 | PCAP 분석 | 6 GB PCAP < 20분, 탭 전체 동작 | 6주 |
| 7 | Unified Investigation, Cross-log Timeline, Correlation | 다중 Evidence | PCAP+Web+WAF 시나리오 E2E | 4주 |
| 8 | SOC Experience, Asset, FP, Playbook | Knowledge 메뉴, Close 플로우 | 4-eyes 승인, Context Panel 표시 | 5주 |
| 9 | Similar Case (pgvector, nori, Feature) | Similar 패널, Compare | Recall@5 ≥ 0.7 (골든셋) | 4주 |
| 10 | SecurityDataConnector, MockLogpresso | Connector 프레임워크 | Mock 기반 Internal Context 동작 | 3주 |
| 11 | Local LLM (Ollama/OpenAI-compat) | AI Actions | Injection 테스트 30종 통과, 인용 정확도 ≥ 95% | 5주 |
| 12 | Anomaly Engine | Baseline, Sequence, Cross-log | 라벨셋 평가 | 6주 |
| 13 | Threat Hunting Assistant | Hunt 화면 | — | 5주 |
| 14 | Detection Engineering | Sigma 후보·테스트·Export | — | 5주 |

V1까지 약 **45주** (병렬화 시 단축 가능). MVP까지 약 26주.

## 3. MVP Scope (Phase 1–5)

| 포함 | 제외 (V1 이후) |
|---|---|
| Home 붙여넣기 / Universal / IOC(오프라인+내부) / HTTP / Payload / Request Diff | PCAP (Phase 6) |
| Bulk 웹·WAF 로그 업로드·파싱·Overview·Pattern·Parameter | Experience/Similar (8–9) |
| Web Findings (API Enumeration 등 10종) | LLM, Anomaly ML, Hunting, Detection |
| Workbench (Story/Timeline/Relations/Context 기본) | Connector 실연동 |
| Case 기본 (저장·스냅샷) | LDAP/OIDC |
| Auth+MFA, RBAC, Audit, 마스킹 | Kubernetes |

## 4. V1 Success Criteria 추적

| # | 기준 | Phase |
|---|---|---|
| 1 | IP/URL/HTTP/Payload/Log 붙여넣기 분석 | 2–3 |
| 2 | 다수 웹로그 업로드 | 5 |
| 3 | 수백만 이벤트를 Overview/Visualization/Findings/Pattern/Timeline으로 이해 | 4–5 |
| 4 | PCAP → Connections/DNS/HTTP/TLS/Findings/Timeline | 6 |
| 5 | PCAP과 로그를 하나의 Investigation에서 연결 | 7 |
| 6 | 중요 Finding 시각적 이해 | 4 |
| 7 | Finding → Evidence → Timeline → Relations → Raw Drill-down | 4 |
| 8 | 분석 결과 Case 저장 | 4 |
| 9 | SOC Experience Draft 저장 | 8 |
| 10 | 유사 Case 조회 | 9 |

## 5. Phase 1 상세 계획 (승인 시 착수)

| 주차 | 작업 |
|---|---|
| W1 | 모노레포 골격(uv/pnpm), import-linter 경계, pre-commit, CI(ruff, mypy, pytest, eslint, tsc, Semgrep, Trivy, SBOM) / Compose `core` 프로필 (PG16+pgvector, OpenSearch 2.x+nori, Valkey, MinIO, nginx) / 네트워크 Zone 분리 |
| W2 | Alembic 기본 스키마(iam, audit, evidence, inv 최소) / 인증(argon2id, TOTP, 세션, CSRF) / Audit 해시체인 + SIEM 전송 어댑터 |
| W3 | RBAC PDP + 권한 매트릭스 테스트 / ObjectStorePort(MinIO·SeaweedFS 계약 테스트) / Resumable Upload 골격(Safe 한도 포함) / Celery+큐 골격, Job 상태머신, SSE |
| W4 | React Shell: Top bar, Investigation Tabs, 3-pane 레이아웃, Command Palette, Entity Chip, safe-render 유틸 + lint / 보안 회귀 테스트(XSS·IDOR·zip slip·CSV injection) / 오프라인 설치 번들 리허설 / Phase 2 상세 설계 리뷰 |

Phase 1 착수 전 확인 필요 사항(Blocker 후보):
1. MinIO 현행 배포·라이선스 정책 → 대안 확정
2. 사내 오픈소스 반입 절차·내부 레지스트리
3. 감사로그 보존기간·개인(신용)정보 처리 기준 (컴플라이언스)
4. 오프라인 ASN/Geo DB 라이선스 확보
5. Logpresso API 문서 확보 일정 (Phase 10)
6. 대상 로그 샘플 (웹/WAF 벤더별 포맷, 익명화) — Parser Fixture

## 6. Major Risks

| Risk | 영향 | 완화 |
|---|---|---|
| “또 하나의 SIEM Dashboard”로 변질 | 제품 가치 상실 | UX 원칙 리뷰 게이트, Phase별 분석가 파일럿·Time-to-Understand 측정 |
| Python 파싱 성능 부족 | 대용량 SLA 미달 | Phase 5 초기 벤치마크, 병목만 Rust(PyO3) |
| OpenSearch 용량·운영 부담 | 비용, 장애 | 보존기간 짧게 + 재인덱싱 전략, ISM |
| Finding 오탐 다수 → 신뢰 하락 | 채택 저하 | Detector precision 지표, 피드백, 음성 Fixture, 보수적 기본값 |
| Knowledge 축적 부진 | 차별점 약화 | Close 플로우에 자연스럽게 통합, Draft 자동 생성, 리뷰 큐 운영 KPI |
| 라이선스(MinIO/AGPL, JA4+, Redis) | 법적 리스크 | 정책 표·법무 검토, Port 추상화로 교체 가능 |
| 악성 Evidence로 Worker 침해 | 보안 사고 | 샌드박스, Egress 차단, 패치 주기 |
| 망분리 환경 업데이트 지연 (룰·DB·이미지) | 탐지력 저하 | 오프라인 번들 절차·주기 정의 |
| LLM 기대 과잉 | 신뢰 문제 | LLM을 Phase 11로 미룸, 라벨·인용 강제 |
| 범위 팽창 | 일정 지연 | Phase Exit Criteria, “하지 말 것” 목록 준수 |

## 7. ATT&CK 연계 단계 배치 (2026-10-06 추가)

| Phase | 추가 범위 |
|---|---|
| 4 | ATT&CK 적재, Detector 조건부 매핑, Finding 배지, Compact Matrix, Story Overlay (+약 1.5주) |
| 6 | 룰 메타데이터 매핑 |
| 7 | Technique Swimlane Timeline |
| 8–9 | Experience/Similar 기법 Feature, Org Heatmap |
| 11 | AI 매핑 제안(후보), Mapping Assistant |
| 13 | TIE → Hunting 가설 |
| 14 | Coverage Heatmap, Navigator Layer·Attack Flow Export/Import |

설계: [34](34-mitre-attack-integration-design.md)
