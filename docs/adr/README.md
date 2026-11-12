# Architecture Decision Records

| ADR | 제목 | 상태 |
|---|---|---|
| [0001](0001-analysis-layer-not-siem.md) | SAW는 SIEM이 아닌 Analysis Intelligence Layer | Accepted |
| [0002](0002-modular-monolith-hexagonal.md) | 모듈러 모놀리스 + Hexagonal 아키텍처 | Accepted |
| [0003](0003-opensearch-event-store.md) | OpenSearch를 이벤트 저장·검색 엔진으로 사용 | Accepted |
| [0004](0004-pcap-pipeline-option-a.md) | PCAP MVP는 Zeek + Suricata + tshark → OpenSearch (Option A) | Accepted |
| [0005](0005-s3-compatible-object-storage.md) | S3 호환 Object Storage(MinIO) + 교체 가능 Port | Accepted |
| [0006](0006-celery-valkey-queues.md) | Celery + Valkey(Redis 프로토콜), 큐 분리 | Accepted |
| [0007](0007-deterministic-first-llm-assistant.md) | Deterministic First, LLM은 Assistant | Accepted |
| [0008](0008-hybrid-similarity.md) | Similar Case는 Keyword + Feature + Vector Hybrid | Accepted |
| [0009](0009-experience-four-eyes.md) | SOC Experience는 Reviewer 승인 후에만 Production Knowledge | Accepted |
| [0010](0010-frontend-visualization-stack.md) | Frontend 시각화 스택 | Accepted |
| [0011](0011-payload-decode-strategy.md) | Payload Decode: 자체 결정적 체인 + CyberChef 정적 Deep-link | Accepted |
| [0012](0012-connector-mock-first.md) | SIEM Connector는 추상화 + Mock 우선 | Accepted |
| [0013](0013-resumable-upload-through-api.md) | 대용량 업로드는 API 경유 Resumable Chunk → S3 Multipart | Accepted |
| [0014](0014-raw-and-normalized-retention.md) | Raw Event + Normalized Event 동시 보존 | Accepted |
| [0015](0015-attack-as-evidence-backed-lens.md) | ATT&CK은 근거 기반 “렌즈”로 통합한다 | Accepted |
| [0016](0016-windows-airgapped-deployment-and-builtin-pcap.md) | Windows 10 LTSC 2019 폐쇄망: 네이티브 설치 + 내장 PCAP 분석기 | Accepted |
| [0017](0017-adopted-from-codex-comparison.md) | Codex 비교 채택 항목(마이그레이션·ATT&CK·SBOM·멱등성·근거 유형·UI) + PCAP 포렌식 확장 | Accepted |
| [0018](0018-large-logs-on-analyst-pcs.md) | 저사양 분석가 PC에서 대용량 TXT/CSV 처리(NDR 파서·슬림 인덱스·체크포인트·-LocalOnly) | Accepted |
| [0019](0019-flow-knowledge-and-state-analysis.md) | 분석가 지식의 자동 적용과 시간 흐름·상태 분석(업무 의미·연결 기준·흐름, 결정적 엔진) | Accepted |

새 ADR은 [template](0000-template.md)을 복사해 작성한다. 결정 변경 시 기존 ADR은 수정하지 않고 `Superseded by ADR-XXXX`로 표시한다.
