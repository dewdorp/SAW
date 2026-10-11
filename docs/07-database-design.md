# 07. Database Design (PostgreSQL + pgvector)

## 1. 원칙

- PostgreSQL = **Source of Truth** (메타데이터, Knowledge, Case, Audit). OpenSearch는 재생성 가능.
- 모든 테이블: `id uuid (UUIDv7)`, `created_at`, `updated_at`, `created_by`.
- 변경 이력이 필요한 Aggregate는 `*_revision` 테이블 (append-only).
- 소프트 삭제(`deleted_at`) 대신 **상태 전이**(deprecated/closed) 원칙. 법적 삭제는 별도 절차.
- 스키마 마이그레이션: Alembic, 롤백 스크립트 필수.
- 스키마 분리: `iam`, `evidence`, `analysis`, `inv`, `knowledge`, `detection`, `audit`, `ai`.

## 2. 테이블

### iam
```sql
iam.user(id, username UNIQUE, display_name, email, password_hash /*argon2id*/,
         mfa_secret_enc, status /*active|locked|disabled*/, last_login_at, failed_count,
         auth_source /*local|ldap|oidc*/)
iam.role(id, name UNIQUE /*admin|soc_manager|senior_analyst|analyst|viewer*/)
iam.user_role(user_id, role_id)
iam.permission(id, code UNIQUE)            -- 'investigation.create', 'experience.approve', 'data.unmask' ...
iam.role_permission(role_id, permission_id)
iam.session(id, user_id, created_at, expires_at, ip, user_agent, revoked_at)
iam.api_token(id, user_id, name, token_hash, scopes[], expires_at)   -- 향후 자동화 용
```

### evidence
```sql
evidence.evidence(id, investigation_id, kind, title, classification, legal_hold bool,
                  uploaded_by, uploaded_at, total_size, file_count, status, tz_assumed)
evidence.file(id, evidence_id, parent_file_id /*압축 해제 계보*/, rel_path_sanitized,
              object_key, sha256, size, mime_detected, type_detected, parser_id, parser_version,
              parse_status, events_parsed, events_failed, first_ts, last_ts)
evidence.upload_session(id, user_id, evidence_id, filename_original, declared_size,
                        received_bytes, s3_upload_id, parts jsonb, status, expires_at)
evidence.custody_log(id, evidence_id, file_id, action /*upload|access|download|export|delete*/,
                     actor, at, detail jsonb)
```

### jobs
```sql
analysis.job(id, investigation_id, evidence_id, kind /*log_ingest|pcap|ioc_bulk|reanalyze*/,
             state, stage_progress jsonb, events_total, events_done, current_item,
             error jsonb, requested_by, started_at, finished_at, cancel_requested bool)
analysis.job_task(id, job_id, task_type, item_ref, state, attempts, error, started_at, finished_at)
```

### analysis
```sql
analysis.finding(id, investigation_id, detector_id, detector_version, title, category,
                 risk_level, risk_score, confidence, status, time_start, time_end,
                 metrics jsonb, checks jsonb, entities jsonb, evidence_refs jsonb,
                 explanation_md /*결정적 템플릿*/, dedup_key, created_at)
  INDEX (investigation_id, risk_score DESC), UNIQUE(investigation_id, dedup_key)
analysis.finding_feedback(id, finding_id, user_id, verdict /*valid|benign|fp|duplicate*/, comment, at)
analysis.pattern(id, investigation_id, evidence_id, template, event_count, sample_event_ids[],
                 first_ts, last_ts, status_dist jsonb, src_count, tags[])
analysis.parameter_profile(id, investigation_id, uri_template, param_name, location,
                           value_type, unique_count, sequential_ratio, increment, entropy_avg,
                           len_min, len_max, num_min, num_max, payload_families jsonb, samples jsonb)
analysis.detector_registry(id, version, category, params_schema jsonb, enabled, precision_30d)
```

### inv (Investigation)
```sql
inv.investigation(id, display_id UNIQUE, title, status, risk_level, risk_override,
                  time_start, time_end, owner_id, verdict, verdict_reason, closed_at, org_unit)
inv.member(investigation_id, user_id, access /*owner|editor|viewer*/)
inv.entity(id, investigation_id, type, value_norm, display, first_seen, last_seen,
           event_count, asset_id, tags[])  UNIQUE(investigation_id, type, value_norm)
inv.relation(id, investigation_id, src_entity_id, edge_type, dst_entity_id,
             count, first_seen, last_seen, sources[], evidence_query jsonb)
inv.correlation(id, investigation_id, kind, entity_ids[], event_refs jsonb,
                window_sec, score, explanation jsonb)
inv.attack_story(id, investigation_id, version, origin /*auto|analyst*/, graph jsonb,
                 generated_by_algo_version, edited_by, created_at)
inv.note(id, investigation_id, author_id, body_md, links jsonb, created_at)  + note_revision
inv.timeline_mark(id, investigation_id, ts, label, color, event_ref, author_id)
inv.saved_view(id, investigation_id, owner_id, name, state jsonb)   -- 필터·선택·탭 상태 (URL 대신)
inv.connector_scope(id, investigation_id, connector_id, query jsonb, time_start, time_end)
```

### case
```sql
inv.case(id, display_id, title, severity, status, assignee_id, summary_md,
         response_md, created_at, closed_at, related_detection_ids[])
inv.case_item(id, case_id, item_type, ref_id, snapshot jsonb, added_by, added_at)
inv.case_investigation(case_id, investigation_id)
inv.case_revision(id, case_id, rev, diff jsonb, actor, at)
```

### knowledge
```sql
knowledge.experience(id, display_id, current_revision_id, status, expires_at, last_reviewed_at)
knowledge.experience_revision(id, experience_id, rev, title, category, event_type, product,
     asset_ids[], attack_type, observables jsonb, behavior_features jsonb,
     initial_assessment, analysis_steps jsonb, recommended_checks jsonb,
     final_verdict, reason, response, false_positive_conditions jsonb,
     detection_conditions jsonb, related_case_ids[], analyst_id, reviewer_id,
     confidence, review_comment, status_at_rev, created_at)
knowledge.experience_embedding(experience_revision_id PK, model, dim, embedding vector(1024),
     text_hash, created_at)
  INDEX USING hnsw (embedding vector_cosine_ops)
knowledge.asset(id, service, company, hostname, domain, ip inet[], cidr cidr[], owner, department,
     criticality, environment, internet_exposed, data_classification,
     expected_country[], expected_asn[], expected_user_agent jsonb, expected_access_time jsonb,
     expected_request_rate jsonb, expected_uri jsonb, batch_schedule jsonb,
     authentication, notes, source /*manual|csv|cmdb*/, updated_at)  + asset_revision
knowledge.known_exception(id, asset_id, condition jsonb, reason, approved_by, expires_at)
knowledge.false_positive_rule(id, title, detector_id, condition jsonb, reason,
     evidence_case_ids[], status, approved_by, expires_at)  + revision
knowledge.playbook(id, title, applies_to jsonb /*finding category 등*/, steps jsonb, status) + revision
knowledge.case_embedding(case_id PK, model, embedding vector(1024), feature_set jsonb, text_hash)
```

### detection
```sql
detection.detection(id, display_id, current_version_id, status)
detection.detection_version(id, detection_id, version, title, description, data_source,
     format /*sigma|suricata|snort|regex|generic_query*/, logic text, threshold jsonb,
     time_window, exceptions jsonb, false_positive, severity, confidence,
     related_case_ids[], created_by, reviewed_by, status_at_version, created_at)
detection.test_run(id, detection_version_id, target /*opensearch index pattern*/, time_range,
     hits, hits_in_confirmed_cases, hits_in_fp_cases, sample_refs jsonb, ran_by, ran_at, result)
detection.test_event(id, detection_version_id, expected /*match|no_match*/, event jsonb)
```

### hunting / ai
```sql
inv.hunt_session(id, investigation_id, hypothesis, status, outcome_md, owner_id)
inv.hunt_step(id, session_id, seq, actor /*analyst|ai*/, rationale, query jsonb,
              result_summary jsonb, pivots jsonb, created_at)
ai.llm_interaction(id, user_id, investigation_id, task, provider, model, prompt_hash,
     context_refs jsonb, output_md, citations jsonb, citation_valid bool,
     latency_ms, tokens_in, tokens_out, feedback, created_at)
```
> 프롬프트 원문은 저장하지 않고 `prompt_hash` + `context_refs`로 재구성 가능하게 한다 (민감정보 중복 저장 방지). 정책상 원문 보존이 필요하면 암호화 컬럼으로 옵션 제공.

### audit
```sql
audit.event(id bigserial, at timestamptz, actor_id, actor_ip, action, target_type, target_id,
            investigation_id, outcome, detail jsonb, prev_hash bytea, hash bytea)
```
- `hash = SHA-256(prev_hash || canonical_json(row))` — 해시 체인.
- 애플리케이션 DB 역할은 `INSERT`만 가능 (`UPDATE/DELETE` REVOKE), 월 단위 파티션.
- 일 단위 체인 헤드 해시를 외부 SIEM에도 기록 (변조 탐지 앵커).

### outbox
```sql
public.outbox(id, aggregate_type, aggregate_id, event_type, payload jsonb, created_at, published_at)
```

## 3. 접근 제어 (DB 계층)

- 앱 계정 3종: `saw_app`(DML), `saw_migrator`(DDL), `saw_readonly`(리포트/백업 검증).
- Investigation 단위 ACL은 **Application 계층에서 강제** + 중요 테이블에 RLS(Row Level Security) 이중 적용 검토 (`SET app.user_id` 세션 변수).

## 4. 용량 추정 (1년)

| 테이블 | 건수 | 비고 |
|---|---|---|
| finding | ~500k | Investigation당 평균 20~50 |
| entity / relation | ~50M / ~100M | Investigation 종료 후 압축/보존 정책 필요 → 파티셔닝(investigation 생성월) |
| experience_revision | ~10k | |
| audit.event | ~50M | 월 파티션, 보존정책 |
| embedding | ~100k × 1024 float4 ≈ 400 MB | HNSW 충분 |
