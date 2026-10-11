# 11. API Design

## 1. 원칙

- REST + JSON, prefix `/api/v1`. OpenAPI 3.1 자동 생성 → Frontend 타입/클라이언트 생성.
- Controller(Router)는 DTO 변환·권한 데코레이터·Application Service 호출만.
- 동기 API는 **소형 입력**만 (≤ 5 MB). 대용량은 Upload Session + Job.
- 에러: RFC 9457 `application/problem+json`.
- 페이지네이션: cursor 기반 (`next_cursor`). OpenSearch 결과는 PIT+search_after를 cursor로 캡슐화.
- 변경 요청: `Idempotency-Key` 헤더 지원 (업로드 완료·Job 생성·승인).
- 실시간: **SSE** (Job 진행률, Investigation 이벤트). WebSocket은 필요 시 Phase 11(LLM 스트리밍)에 검토 — SSE로 충분하면 유지.
- 인증: HttpOnly Secure SameSite=Strict 세션 쿠키 + CSRF 토큰(double submit). 자동화용 API Token은 별도 scope.
- **URL에 민감 데이터 금지**: 분석 입력(IP/URL/Payload)은 GET 쿼리 파라미터가 아니라 POST body. 공유 링크는 `saved_view_id` 사용.

## 2. 리소스 개요

### Auth / Admin
```
POST   /auth/login                  {username,password} → mfa_required
POST   /auth/mfa/verify             {code}
POST   /auth/logout
GET    /me
GET    /admin/users | POST | PATCH /admin/users/{id}
GET    /admin/audit?actor=&action=&from=&to=
GET    /admin/connectors | POST | PATCH
GET    /admin/masking-policy | PUT
```

### Analyze (동기, 소형)
```
POST /analyze/universal   {input, hints?}                → {detections[], spans[], recommended[], results{}}
POST /analyze/ioc         {observables[]}                → {items[{observable, offline, internal_context, previous_verdicts, external?}]}
POST /analyze/ioc/{type}/{id}/external   (분석가 명시 실행, 정책 체크, q.enrich 비동기)
POST /analyze/http        {request, response?}           → {parsed, parameters[], patterns[], decode_chains[]}
POST /analyze/payload     {input, chain?, auto:true}     → {chains[{steps[], output, confidence}], iocs[], patterns[]}
POST /analyze/diff        {requests[{raw, response?}]}   → {canonical[], diffs[], evolution, bypass_points[]}
POST /analyze/log         {text, parser_hint?}           → {parser, events[], summary, findings[]}
```

### Evidence / Upload / Jobs
```
POST   /investigations/{inv}/evidence                       {kind, title, tz?, classification} → evidence
POST   /uploads                                             {evidence_id, filename, size, sha256?} → upload_session
PUT    /uploads/{sid}/parts/{n}   (application/octet-stream, ≤ 64 MB)  → {received}
GET    /uploads/{sid}                                       → 재개용 상태
POST   /uploads/{sid}/complete                              → {file_id, job_id}
DELETE /uploads/{sid}
GET    /evidence/{id}  | GET /evidence/{id}/files | GET /evidence/{id}/custody
POST   /evidence/{id}/files/{fid}/parser    {parser_id}     → 파서 Override + 재처리
GET    /jobs?state=&mine=   GET /jobs/{id}   GET /jobs/{id}/events (SSE)
POST   /jobs/{id}/cancel    POST /jobs/{id}/retry {task_ids?}
```

### Investigation
```
POST /investigations  GET /investigations  GET|PATCH /investigations/{id}
POST /investigations/{id}/close            {verdict, reason, checks[], response, detection_idea, save_experience:bool}
GET  /investigations/{id}/overview         ?filters  → 카운트, 차트 데이터(서버 집계)
POST /investigations/{id}/query/events     {filters, sort, fields, cursor, limit≤500}
POST /investigations/{id}/query/aggregate  {filters, agg:{type, field, size, interval}}
POST /investigations/{id}/query/pivot      {entity:{type,value}, target_field}
GET  /investigations/{id}/events/{event_id}?index=   → normalized + raw(masked) + raw_ref
POST /investigations/{id}/events/{event_id}/unmask  {reason}  → 감사 후 원문
GET  /investigations/{id}/timeline         ?filters&cursor&collapse=true
GET  /investigations/{id}/timeline/density ?filters
GET  /investigations/{id}/graph            ?filters&group_by=&max_nodes=
POST /investigations/{id}/graph/expand     {entity_id, edge_types[]}
GET  /investigations/{id}/story            → latest  | GET /story/versions | PUT /story (analyst edit)
GET  /investigations/{id}/patterns         | GET /investigations/{id}/parameters?uri_template=
GET  /investigations/{id}/entities/{type}/{value}  → 엔티티 상세 (통계, Finding, 관련 Case)
POST /investigations/{id}/notes | GET | PATCH
POST /investigations/{id}/saved-views | GET
GET  /investigations/{id}/correlations
```

### Findings
```
GET   /investigations/{id}/findings?risk=&status=&category=
GET   /findings/{fid}                       → 전체 (metrics, checks, evidence_refs, explanation)
GET   /findings/{fid}/events?cursor          → 근거 이벤트 (evidence_refs 실행)
POST  /findings/{fid}/feedback              {verdict, comment}
GET   /findings/{fid}/similar               → Similar Cases/Experiences
```

### Case
```
POST /cases  GET /cases  GET|PATCH /cases/{id}
POST /cases/{id}/items  {item_type, ref_id}  (snapshot 생성)
GET  /cases/{id}/history
POST /cases/{id}/export {format: md|pdf|docx, masking: default|strict}
```

### Knowledge
```
GET|POST /experiences   GET|PATCH /experiences/{id}  (PATCH = 새 revision draft)
POST /experiences/{id}/submit | /approve {comment} | /reject {comment} | /deprecate {reason}
GET  /experiences/{id}/revisions
GET|POST|PATCH /assets   POST /assets/import (CSV)   GET /assets/match?ip=&domain=
GET|POST|PATCH /fp-rules   GET|POST|PATCH /playbooks
POST /similar/search  {investigation_id? | finding_id? | features?, text?, k=10} → {results[{ref, score, breakdown, same[], different[]}]}
```

### Hunting / Detection / AI (V2)
```
POST /hunts  POST /hunts/{id}/steps {query, rationale}  GET /hunts/{id}
POST /detections  PATCH /detections/{id} (new version)
POST /detections/{id}/versions/{v}/test {time_range, index_pattern}  → job
POST /detections/{id}/versions/{v}/approve
GET  /detections/{id}/versions/{v}/export?format=sigma|suricata|opensearch|logpresso
POST /ai/actions  {action: explain_finding|next_steps|compare_cases|summarize_timeline|hunting_query|detection_idea|report_draft, context:{…}}
POST /ai/ask      {question, context:{investigation_id, selection}}  → SSE stream
```

## 3. 공통 응답 형태

```json
// 분석 결과에 근거 연결
{
  "data": {...},
  "meta": {
    "analyzer": "http", "analyzer_version": "1.2.0",
    "approximate": ["unique_ip"],          // ≈ 표시 필드
    "masked_fields": ["params.ssn"],
    "took_ms": 132
  }
}
```

에러 예:
```json
{"type":"https://saw.local/problems/input-too-large","title":"Input exceeds sync limit",
 "status":413,"detail":"Paste input 7.2 MB > 5 MB. Use upload.","instance":"/api/v1/analyze/universal",
 "action":{"type":"upload","href":"/api/v1/uploads"}}
```

## 4. 권한 매핑

각 Router 핸들러는 `@require(permission, resource=investigation)` 선언. 정책은 `core/security/authz.py`의 단일 PDP(Policy Decision Point)에서 결정:
`allow = role_has(permission) ∧ (resource 없음 ∨ member_of(investigation) ∨ role ∈ {soc_manager})`

## 5. Rate Limit / 보호

| 대상 | 한도 |
|---|---|
| /auth/login | IP당 10/min, 계정 5회 실패 시 15분 잠금 |
| /analyze/* | 사용자당 60/min |
| /analyze/ioc/*/external | 사용자당 30/hour (OPSEC, 외부 쿼터) |
| /ai/* | 사용자당 30/min, 동시 2 |
| /query/* | timeout 30s, 결과 limit |

## 6. 버전 관리

- URL 메이저 버전(`/v1`). 필드 추가는 하위호환, 제거/의미 변경은 `/v2`.
- 분석 결과에 `analyzer_version`, `detector_version`, `ces_version` 포함 → 재현성.
