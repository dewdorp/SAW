# 05. Domain Model

## 1. Bounded Contexts

```
┌──────────────────┐   ┌───────────────────┐   ┌──────────────────────┐
│ Identity & Audit │   │ Evidence & Ingest │   │ Analysis             │
│ User, Role, ACL, │   │ Evidence, File,   │   │ Event(OS), Entity,   │
│ Session, Audit   │   │ Job, ParserRun    │   │ Finding, Pattern,    │
└──────────────────┘   └─────────┬─────────┘   │ ParameterProfile     │
                                 │             └──────────┬───────────┘
                                 ▼                        ▼
                     ┌───────────────────────────────────────────────┐
                     │ Investigation                                 │
                     │ Investigation, AttackStory, Relation, Note,   │
                     │ TimelineMark, SavedView, Correlation          │
                     └───────────────┬───────────────────────────────┘
                                     ▼
┌──────────────────┐   ┌───────────────────┐   ┌──────────────────────┐
│ Case             │◀──│ Knowledge         │──▶│ Detection            │
│ Case, CaseItem,  │   │ Experience, Asset,│   │ Detection, Version,  │
│ Verdict          │   │ FPRule, Playbook  │   │ TestRun              │
└──────────────────┘   └───────────────────┘   └──────────────────────┘
          ▲                     ▲
          │            ┌────────┴──────────┐   ┌──────────────────────┐
          └────────────│ Hunting           │   │ AI Assist            │
                       │ HuntSession, Step │   │ LlmInteraction       │
                       └───────────────────┘   └──────────────────────┘
```

Context 간 참조는 **ID 참조**만 사용(직접 객체 참조 금지). 이벤트(OpenSearch 문서)는 `event_id` + `index`로 참조.

## 2. 핵심 Aggregate

### Investigation (Aggregate Root)
| 속성 | 설명 |
|---|---|
| id | `INV-YYYYMMDD-NNN` 표시 ID + UUID |
| title, status | `open / in_progress / pending_review / closed` |
| risk | 최고 Finding Risk에서 도출 + 분석가 Override |
| time_range | Evidence 범위의 합 (자동) / 분석 범위(수동) |
| evidence_ids[] | 연결된 Evidence |
| connector_scopes[] | Connector 조회 범위 (source, query, time range) |
| owner, members[] | ACL |
| verdict | `attack / normal / false_positive / unknown` (closed 시 필수) |

### Evidence
| 속성 | 설명 |
|---|---|
| id, investigation_id | |
| kind | `pcap, web_log, waf_log, fw_log, sec_log, db_audit, ioc_list, http, paste, file, document, screenshot` |
| files[] | EvidenceFile (original key, sha256, size, detected_type, parser, status) |
| uploaded_by, uploaded_at | Chain of Custody |
| classification | 데이터 분류 |
| legal_hold | bool |

### Job
상태 머신 ([10](10-job-processing-design.md)):
```
QUEUED → UPLOADING → PARSING → INDEXING → ANALYZING → COMPLETED
   └──────────┴──────────┴──────────┴───────────┴──▶ FAILED | CANCELLED
```

### Entity (Investigation 범위 물질화)
`type ∈ {ip, domain, url, uri_template, user, account, session, asset, ja3, ja4, hash, process, host, asn, user_agent, case}`
`value`(정규화), `display`, `first_seen`, `last_seen`, `event_count`, `tags`, `asset_id?`

### Relation
`(src_entity, edge_type, dst_entity)` + `count`, `first_seen`, `last_seen`, `sources[]`, `evidence_query`
`edge_type ∈ {CONNECTED_TO, USED, ACCESSED, RESOLVED_TO, OBSERVED_WITH, RELATED_TO, AUTHENTICATED_AS, DOWNLOADED}`

### Finding (Aggregate Root)
상세: [24](24-finding-design.md)
```
new → triaged → (valid | benign | false_positive | duplicate)
                      │
                      └─ (case에 연결 시 linked)
```

### AttackStory
`investigation_id`, `version`, `nodes[] (stage, title, metrics, finding_ids, evidence_query, time_range, confidence, origin=auto|analyst)`, `edges[] (from, to, link_reason, confidence)`, `edited_by`.
자동 생성본과 분석가 편집본 모두 버전 보존.

### Case (Aggregate Root)
```
open → in_progress → resolved → closed
                         ▲          │
                         └─ reopen ─┘
```
CaseItem: `finding | event_ref | entity | evidence | story_snapshot | note | detection`

### Experience (Aggregate Root)
```
draft ──submit──▶ review ──approve(reviewer≠author)──▶ approved ──▶ deprecated
  ▲                 │                                      │
  └──reject(사유)───┘                                      └─ revise → draft(new revision)
```
불변식:
- `approved`는 reviewer_id ≠ analyst_id
- 수정은 새 revision 생성 (approved 본문 직접 수정 불가)
- `expires_at` 경과 시 `needs_review` 플래그 (검색 결과에 표시, 자동 삭제 아님)

### Asset
[27](27-asset-knowledge-design.md). `known_exception`은 `expires_at` 필수.

### Detection (Aggregate Root)
```
draft → test → approved → deployed(외부에서 배포됨을 수동 기록) → deprecated
```
불변식: `approved`는 최소 1회 TestRun 통과 + reviewer ≠ creator. SAW는 deployed를 **기록만** 한다.

### HuntSession
`hypothesis`, `steps[] (query, rationale, actor=analyst|ai, result_summary, pivots[])`, `outcome`.

### LlmInteraction
`task`, `model`, `prompt_hash`, `context_refs[]`, `output`, `citations[]`, `citation_valid`, `user_feedback`.

## 3. Value Objects

| VO | 설명 |
|---|---|
| `TimeRange` | start/end (UTC), 원본 TZ |
| `EvidenceRef` | index, event_id 또는 저장된 쿼리(DSL hash) + 샘플 ID |
| `Metric` | name, observed, baseline(min/max/median), unit, ratio |
| `Check` | label, passed(bool/partial), value, detail |
| `Observable` | type, value, defanged 표시 |
| `RiskScore` | level(critical/high/medium/low/info), score 0–100, factors[] |
| `FeatureSet` | Similarity용 canonical feature key-value |

## 4. Domain Events (내부)

`EvidenceUploaded`, `JobStateChanged`, `FindingCreated`, `FindingFeedbackGiven`, `InvestigationClosed`, `ExperienceSubmitted`, `ExperienceApproved`, `DetectionTested`, `DetectionApproved`, `UnmaskPerformed`.
→ Audit 기록, 알림, 임베딩 재계산 트리거로 사용. (Outbox 패턴으로 PG 트랜잭션과 큐 발행 일관성 보장)
