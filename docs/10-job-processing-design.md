# 10. Job Processing Design

## 1. 원칙

- 대용량 처리는 API 프로세스에서 하지 않는다 (API = 업로드 스트리밍 + Job 생성 + 조회).
- Job = **여러 Task의 DAG**. 파일 단위로 분할하여 병렬화·부분 재시도.
- 모든 Task는 **멱등**: `(job_id, task_type, item_ref)` 키로 중복 실행 시 결과 동일 (인덱싱은 결정적 `_id = event_id` 사용, event_id는 `hash(evidence_file_id, offset)` 기반 UUIDv8로 재처리 시 동일).
- 상태의 Source of Truth는 PostgreSQL. Redis는 진행률 캐시·브로커.

## 2. Queues & Workers

| Queue | Worker | 동시성(기본) | 특성 |
|---|---|---|---|
| `q.ingest` | worker-ingest | 4 | 압축해제, 감지. I/O 중심 |
| `q.parse` | worker-parse (LogParserWorker) | CPU 코어 수 | 파싱+정규화+bulk |
| `q.pcap` | worker-pcap (PcapWorker) | 2 (메모리 큼) | Zeek/Suricata/tshark |
| `q.analyze` | worker-analyze (Statistics/Correlation/Anomaly) | 4 | OpenSearch 집계 중심 |
| `q.enrich` | worker-enrich (IOCWorker) | 4 | Egress 프록시, rate limit |
| `q.file` | worker-file (FileAnalysisWorker) | 2 | P2 |
| `q.ai` | worker-ai | GPU 수 | 임베딩·LLM |
| `q.maint` | scheduler 작업 | 1 | 보존·Baseline·만료 |

Celery 설정: `task_acks_late=True`, `worker_prefetch_multiplier=1`, `task_reject_on_worker_lost=True`, broker `visibility_timeout` ≥ 최장 Task 시간(예: 6h) — PCAP Task는 내부적으로 heartbeat 갱신.

## 3. Log Ingest DAG

```
upload.complete
   │
   ▼
[ingest.verify]            sha256/size 검증, Evidence 상태 갱신
   │
   ▼
[ingest.extract]           Safe Decompress (아래 §5) → child files
   │
   ▼
[ingest.detect]            파일별 type/parser 감지 (샘플 200줄 스코어링)
   │                       ※ 신뢰도 < 0.8 → Job 일시정지(WAITING_INPUT)로 분석가 확인 요청
   ▼
chord( [parse.file(f1)], [parse.file(f2)], … )      파일 단위 병렬, 대형 파일은 byte-range 분할(비압축만)
   │   parse → normalize → enrich(offline ASN/geo/cloud/asset) → bulk index(5–10 MB batch)
   ▼
[analyze.stats]            Overview 통계 스냅샷 → artifacts/ + PG
   ▼
[analyze.patterns]         uri_template 집계 + Drain3 (샘플/스트리밍)
   ▼
[analyze.parameters]
   ▼
[analyze.detectors]        Web Detector 실행 → Findings
   ▼
[analyze.relations]        Entity/Relation 물질화
   ▼
[analyze.story]            Attack Story 자동 생성 (Investigation 수준)
   ▼
COMPLETED
```

Progressive: `parse.file`이 일정 비율(예: 10%마다) 처리 시 `analyze.stats.partial` 트리거 → Overview가 점진 갱신.

## 4. PCAP DAG

```
[ingest.verify] → [pcap.inspect] capinfos: 형식, 패킷 수, 기간, 링크타입, 손상 여부
      → parallel( [pcap.zeek], [pcap.suricata] )   같은 파일을 각자 읽기
      → [pcap.normalize_index]  zeek json + eve.json → CES → saw-net*/dns/tls/ids
      → [analyze.network_stats] → [analyze.network_detectors] → [analyze.relations] → [analyze.story]
```

## 5. Safe Decompress 규칙

| 항목 | 기본 한도 |
|---|---|
| 중첩 깊이 | ≤ 3 |
| 압축비 (파일별) | ≤ 200:1 (초과 시 중단, “Possible archive bomb”) |
| 총 해제 크기 | ≤ Evidence 업로드 크기 × 20, 그리고 ≤ 500 GB |
| 엔트리 수 | ≤ 10,000 |
| 경로 | 절대경로, `..`, 드라이브 문자, NUL, 제어문자 → 거부. 해제는 키 기반(파일명 미사용) |
| 링크 | symlink/hardlink/device 엔트리 무시 |
| 암호 ZIP | 분석가가 암호 입력 시에만 (입력값 저장 안 함) |
| 처리 방식 | **스트리밍** 해제 + 바이트 카운터로 한도 실시간 체크 (헤더의 선언 크기 신뢰 금지) |

## 6. Job 상태 & 진행률

```
QUEUED → UPLOADING → PARSING → INDEXING → ANALYZING → COMPLETED
                                         ↘ FAILED / CANCELLED
 (보조) WAITING_INPUT : 파서 확인 필요, 암호 필요
```
- PARSING과 INDEXING은 파이프라인상 동시에 진행 → UI는 **단계별 바**로 각각 표시.
- 진행률 레코드(Redis hash, 1s 갱신; PG는 10s 간격 flush):
```json
{"job_id":"…","state":"PARSING",
 "stages":{"upload":{"done":true},"parse":{"pct":78},"index":{"pct":42},"analyze":{"pct":0}},
 "events_done":8320131,"events_total_est":10720000,
 "current_item":"access.log.18.gz","eps":31200,"eta_sec":77,
 "errors":{"parse_failed":1203,"samples_ref":"…"}}
```
- `events_total_est`: 압축 해제 크기 / 샘플 평균 라인 길이로 추정 → 진행하며 보정 (UI에 “추정” 표시).
- API는 SSE `/jobs/{id}/events`로 push.

## 7. 실패 / 재시도 / 취소

| 상황 | 처리 |
|---|---|
| 파일 파싱 오류율 > 5% | 파일 상태 `degraded`, 오류 샘플 50건 저장, Job은 계속 |
| 파일 전체 실패 | 해당 파일만 FAILED, 재시도 버튼 (파서 변경 후 재시도 가능) |
| Worker 크래시 | acks_late로 재전달, 최대 3회, 이후 Dead-letter(`q.dead`) + 알림 |
| OpenSearch 429/backpressure | 지수 백오프, bulk 크기 축소 |
| 취소 | `cancel_requested` 플래그 → Task가 배치 경계에서 확인 후 종료, 이미 인덱싱된 데이터는 `evidence_id` 기준 delete_by_query로 정리(옵션) |
| 재처리(파서 버전업) | `reanalyze` Job: 기존 evidence_id 문서 삭제 후 재인덱싱 (결정적 event_id로 upsert 가능) |

## 8. 자원 보호 / 공정성

- 사용자별 동시 대용량 Job 2개, 전체 5개 (설정).
- Job 우선순위: 소형(≤1 GB) 우선 큐 라우팅으로 대형 Job이 전체를 막지 않게 (`q.parse.small`, `q.parse.large`).
- Worker 컨테이너 메모리 한도, `--max-memory-per-child`로 메모리 누수 보호.
- Scratch 디스크 사용량 모니터링, 부족 시 신규 Task 지연.
