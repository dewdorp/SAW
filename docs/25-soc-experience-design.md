# 25. SOC Experience Design

**핵심 차별점.** 조직의 분석 경험을 **구조화**해 축적하고, 분석 화면에서 항상 다시 쓰이게 한다. 단순 Wiki가 아니다.

## 1. Experience 스키마

| 필드 | 타입 | 설명 |
|---|---|---|
| experience_id | `EXP-YYYY-NNNN` | |
| title | text | “Customer API 순차 ID 열거 — 클라우드 IP 분산” |
| category | enum | attack / benign_pattern / false_positive / operational / tuning |
| event_type | keyword[] | http_access, waf_block … |
| product | keyword[] | nginx, <WAF>, zeek |
| asset | asset_id[] | |
| attack_type | keyword | api_enumeration, credential_stuffing … (taxonomy 관리) |
| observables | [{type, value, role}] | IOC (만료 고려 — IP는 재할당 가능) |
| behavior_features | FeatureSet | **Similarity 핵심** (아래 §3) |
| initial_assessment | text | 처음 보였던 모습 |
| analysis_steps | [{step, finding, tool}] | 실제 수행 절차 |
| recommended_checks | [{check, why, how(query)}] | 다음 분석가를 위한 체크리스트 |
| final_verdict | enum | attack / normal / false_positive / unknown |
| reason | text | 판단 근거 |
| response | text | 대응 (차단 요청, 개발팀 통보 등 — 사람 수행 기록) |
| false_positive_conditions | [{condition, reason}] | “이 조건이면 정상” |
| detection_conditions | [{logic, data_source}] | 탐지 아이디어 |
| related_case_ids | id[] | |
| analyst / reviewer | user | reviewer ≠ analyst |
| confidence | low/med/high | |
| created_at / updated_at / last_reviewed_at / expires_at | ts | |
| status | draft / review / approved / deprecated | |

## 2. Workflow (Capture → Review → Production)

```
Investigation Close
  Final Verdict  ○ Attack ○ Normal ○ False Positive ○ Unknown
  Analyst Comment / Checks Performed / Response / Detection Idea
  ☑ Save as SOC Experience
        │
        ▼ (자동 Draft 생성: 아래 매핑)
     DRAFT ──submit──▶ REVIEW ──approve──▶ APPROVED (Production Knowledge)
       ▲                 │reject(사유)            │expires_at 도래 → needs_review
       └─────────────────┘                        └─revise→ 새 revision DRAFT (기존 approved 유지)
```

### 자동 Draft 매핑
| Draft 필드 | 출처 |
|---|---|
| title | Investigation title + 최상위 Finding category |
| behavior_features | 연결 Finding들의 metrics/checks → Feature 추출기 (결정적) |
| observables | Investigation 핵심 Entity (Finding entities 상위) |
| analysis_steps | 분석가가 실행한 주요 액션 로그 (Finding 열람, 필터, Diff, Hunting) 요약 — 분석가 편집 |
| recommended_checks | Checks Performed 입력 + Playbook |
| final_verdict/reason/response | Close 입력 |
| detection_conditions | Detection Idea 입력 |
| related_case_ids | 연결 Case |

### 안전장치 (Knowledge Poisoning 방지)
- 분석가 판단을 **자동 학습하지 않는다**. Draft는 검색 결과에 기본 제외 (작성자 본인에게만 “내 Draft”로 표시).
- 승인 체크리스트(Reviewer): 근거 충분성, FP 조건 범위가 과도하지 않은지, 개인정보 포함 여부(관측값 마스킹), 만료일 적절성.
- FP 조건 저장 시 과거 Confirmed Attack 이벤트와 매칭 검사 → 충돌 시 경고.
- `expires_at` 기본: attack 12개월, false_positive/benign 6개월(환경 변화가 빠름).
- 모든 revision 보존, deprecated도 이력 조회 가능.

## 3. Behavior Features (FeatureSet)

결정적 추출, 정규화된 key-value. Similar Case와 Same/Different 비교의 기반.

| Key | 값 예 |
|---|---|
| ua_class | script |
| ua_family | python-httpx |
| uri_template | /api/customer?id=<NUM> |
| param_sequential | true |
| param_type | numeric |
| request_interval_bucket | sub_second / 1-10s / periodic_60s |
| src_infra | cloud_multi |
| src_ip_count_bucket | 10-100 |
| ja4 | t13d1516h2_… |
| success_ratio_bucket | >0.9 |
| rate_vs_baseline_bucket | >10x |
| time_of_day | off_hours |
| target_asset_criticality | high |
| attack_stage_set | {DISCOVERY, EXPLOITATION, DATA_ACCESS} |
| payload_family | none / sqli / traversal … |

Feature 사전(키·버킷 정의)은 버전 관리 (`knowledge/experience/features.yaml`).

## 4. UI — “OUR SOC EXPERIENCE” (우측 패널 상시)

```
OUR SOC EXPERIENCE                         (현재 선택: Finding #1042)
────────────────────────────────────────────────
2026-09-14  API Enumeration        ▲ Attack     ✔approved
  Same  ✓UA type ✓URI pattern ✓Sequential ✓Cloud multi
  Diff  △JA4 △Time(업무시간)
  → 확인 체크 3개 · 대응: WAF rate-limit 요청        [열기]
2026-07-23  Internal Batch         ○ Normal     ✔approved
  Same  ✓URI pattern ✓Sequential
  Diff  △Src internal(10.x) △UA Java △Time 03:00 batch
  ⚑ FP 조건: src ∈ 10.20.0.0/16 AND 03:00–03:15
2026-05-11  Automated Scan         ▲ Attack
  …
[모든 경험 검색]  [이 사건을 경험으로 기록]
```
- 현재 사건과 **Same / Different**를 아이콘으로 비교 (Feature 단위).
- “recommended_checks”는 클릭 시 해당 쿼리/화면 실행 → 경험이 실제 행동으로 이어짐.

## 5. Knowledge 메뉴 화면

- Experience 목록: 필터(category, attack_type, asset, status, 만료 임박), 정렬(최근 사용, 승인일).
- Review Queue (Reviewer): 대기 건, 차이(diff) 보기, 승인/반려.
- 사용 통계: 열람 수, “도움됨” 피드백 → 품질 지표.
