# 02. Non-Functional Requirements

모든 수치는 **Reference HW** 기준이며 Phase 1에서 벤치마크로 확정한다.

## 0. Reference Hardware (MVP 단일 노드)

| 역할 | 사양 |
|---|---|
| App + Workers | 32 vCPU / 128 GB RAM / NVMe 2 TB (scratch) |
| OpenSearch | (동일 노드 또는 분리) heap 31 GB, NVMe 4 TB |
| PostgreSQL | 8 vCPU / 32 GB 할당 |
| Object Storage | HDD/SSD 20 TB+ (Evidence 원본) |
| (옵션) LLM | GPU 48 GB+ (예: L40S 1장) 또는 CPU-only 소형 모델 |

확장 구성: OpenSearch 3-node, Worker 노드 수평 확장, PostgreSQL Primary/Replica.

## 1. Performance

| ID | 요구사항 | 목표 |
|---|---|---|
| NFR-PERF-01 | 붙여넣기 분석 (Universal/HTTP/Payload, ≤ 100 KB) 응답 | p95 < 1 s (외부 Enrichment 제외) |
| NFR-PERF-02 | IOC 내부 Context 조회 | p95 < 2 s |
| NFR-PERF-03 | Bulk Log Ingest (파싱+정규화+인덱싱) | ≥ 30,000 EPS (Reference HW), 10 M events < 10 min |
| NFR-PERF-04 | Progressive Overview 첫 표시 | 업로드 완료 후 ≤ 60 s (부분 통계) |
| NFR-PERF-05 | Overview 집계/필터 재계산 (10 M events) | p95 < 2 s |
| NFR-PERF-06 | PCAP 처리 (Zeek+Suricata) | 1 GB당 ≤ 3 min |
| NFR-PERF-07 | Timeline 스크롤 (가상화) | 60 fps 근접, 100k 행 렌더 메모리 < 300 MB |
| NFR-PERF-08 | Relation Graph 렌더 | ≤ 500 visible nodes에서 상호작용 < 100 ms |
| NFR-PERF-09 | Similar Case 검색 | p95 < 1.5 s (Knowledge 100k건) |

## 2. Scalability

| ID | 요구사항 |
|---|---|
| NFR-SCAL-01 | Worker는 Stateless, 큐별 수평 확장 |
| NFR-SCAL-02 | Investigation당 Evidence ≥ 50 GB, 이벤트 ≥ 100 M 지원 (OpenSearch 클러스터 확장 시) |
| NFR-SCAL-03 | 동시 사용자 50명, 동시 대용량 Job 5개 (Reference HW) |
| NFR-SCAL-04 | Docker Compose → Kubernetes 이전 시 코드 변경 없이 배포 매니페스트만 변경 |

## 3. Availability / Recovery

| ID | 요구사항 | 목표 |
|---|---|---|
| NFR-AVL-01 | 서비스 가용성 (업무시간) | 99.5% |
| NFR-AVL-02 | PostgreSQL (Knowledge/Case/Audit) | RPO 15 min (WAL archiving), RTO 4 h |
| NFR-AVL-03 | Object Storage Evidence 원본 | RPO 24 h (복제/백업), 무결성 해시 검증 |
| NFR-AVL-04 | OpenSearch | **재생성 가능 데이터**로 취급 (원본 + 파서 버전으로 재인덱싱). Snapshot 일 1회 |
| NFR-AVL-05 | Job 실패 시 부분 재시도 (파일 단위), 전체 재처리 불필요 |

## 4. Security (상세: [12](12-security-architecture.md))

| ID | 요구사항 |
|---|---|
| NFR-SEC-01 | 모든 입력 데이터는 Untrusted. 렌더링은 텍스트 전용(escape), HTML 렌더 금지 |
| NFR-SEC-02 | 파일 처리 Worker 샌드박스 (non-root, read-only rootfs, cap_drop ALL, no-new-privileges, 인터넷 Egress 차단) |
| NFR-SEC-03 | 통신 TLS 1.2+ (외부), 내부 구간 TLS 권장(Phase 1 옵션, 운영 필수) |
| NFR-SEC-04 | 저장 암호화 (디스크 암호화 + Object SSE) |
| NFR-SEC-05 | 비밀정보는 평문 설정 파일 금지 (Docker secrets → 향후 Vault) |
| NFR-SEC-06 | 민감정보 마스킹 기본 ON (주민등록번호, 카드번호(Luhn), 계좌번호, 전화번호, 이메일, 인증토큰) |
| NFR-SEC-07 | 의존성 SBOM 생성, 컨테이너 이미지 digest 고정, 취약점 스캔 게이트 |
| NFR-SEC-08 | 망분리 환경 오프라인 설치 지원 (내부 레지스트리, 오프라인 GeoIP/ASN/룰 업데이트 번들) |

## 5. Auditability

| ID | 요구사항 |
|---|---|
| NFR-AUD-01 | 인증, 조회(Evidence/Event/Unmask), 변경, Export, 승인, AI 호출 모두 감사 기록 |
| NFR-AUD-02 | Audit Log append-only + 해시 체인, 외부 SIEM으로 실시간 전송 |
| NFR-AUD-03 | Knowledge/Detection/Case 모든 리비전 보존 (삭제 대신 deprecated) |
| NFR-AUD-04 | Evidence Chain of Custody: 업로드자, 시간, SHA-256, 접근 이력 |
| NFR-AUD-05 | 보존기간은 기관 정책·규정에 따라 설정 가능 (컴플라이언스팀 확정 필요) |

## 6. Explainability

| ID | 요구사항 |
|---|---|
| NFR-XAI-01 | 모든 Finding은 측정값(Observed), 기준값(Baseline), 체크 항목, 근거 이벤트 쿼리를 포함 |
| NFR-XAI-02 | Detector는 버전·파라미터 기록, 재현 가능 (동일 입력 → 동일 Finding) |
| NFR-XAI-03 | 유사도 점수는 구성 요소별로 분해 표시 |
| NFR-XAI-04 | AI 출력은 “AI 생성” 라벨 + 인용 Evidence ID 검증 + 결정적 결과와 시각적으로 구분 |
| NFR-XAI-05 | 근사치(HyperLogLog cardinality 등)는 “≈” 표시 |

## 7. Usability / Accessibility

| ID | 요구사항 |
|---|---|
| NFR-UX-01 | Dark Mode 기본, Light Mode 지원 |
| NFR-UX-02 | 심각도는 아이콘 + 텍스트 + 색상 병행 (색상 단독 금지) |
| NFR-UX-03 | WCAG 2.1 AA 대비, 키보드 전 기능 접근, Command Palette |
| NFR-UX-04 | 최소 해상도 1920×1080 최적화, 1440×900 지원, 듀얼 모니터(팝아웃 패널) |
| NFR-UX-05 | 한국어 UI 기본, 영어 전환. 기술 용어는 원어 유지 |
| NFR-UX-06 | 시간 표시: 기본 KST, UTC 토글, 원본 타임존 보존 |

## 8. Maintainability

| ID | 요구사항 |
|---|---|
| NFR-MNT-01 | API Controller에 비즈니스 로직 금지 (Application Service 경유) |
| NFR-MNT-02 | Analyzer·Parser·Detector는 Plugin 인터페이스 + 버전 + Fixture 테스트 |
| NFR-MNT-03 | 테스트 커버리지: core/analyzers/parsers ≥ 80% |
| NFR-MNT-04 | OSS 연동은 Adapter 뒤에 위치 (교체 가능) |
| NFR-MNT-05 | 모든 스키마(Event/API)는 버전 관리, 하위 호환 규칙 문서화 |

## 9. Observability

| ID | 요구사항 |
|---|---|
| NFR-OBS-01 | 구조화 JSON 로그 (분석 데이터 원문 미포함) |
| NFR-OBS-02 | Prometheus 메트릭: 큐 길이, EPS, Job 지연, 파서 오류율, OpenSearch 지연 |
| NFR-OBS-03 | OpenTelemetry Trace (API → Worker) |
| NFR-OBS-04 | 플랫폼 운영 로그는 기존 SIEM으로 전송 (SAW 자신을 SIEM으로 쓰지 않음) |

## 10. Data Governance

| ID | 요구사항 |
|---|---|
| NFR-DATA-01 | Evidence 보존기간·삭제 정책 (Legal Hold 지원) |
| NFR-DATA-02 | 데이터 분류 태그 (공개/내부/기밀/개인정보 포함) |
| NFR-DATA-03 | LLM에 전달되는 데이터는 마스킹 후 최소 범위 |
| NFR-DATA-04 | Export 시 마스킹 정책 적용, Export 감사 |
