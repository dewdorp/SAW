# 13. Hunting

설계: [30-threat-hunting-design](../30-threat-hunting-design.md)

| 항목 | 내용 |
|---|---|
| Purpose | 가설 기반 탐색을 단계별로 수행·기록하고, 왜 다음 질의를 했는지 남김 |
| Primary User Action | Hypothesis 작성 → Query 실행 → 결과 검토 → Pivot 선택(이유 입력) → 반복 → 결론 |
| Layout | 상단 Hypothesis / 좌: Investigation Graph(질의 흐름) / 우: Query History / 하: Results + Pivot Candidates |
| Main Components | Hypothesis 편집, Query Builder(구조화 + 사람이 읽는 표현), ✦ AI 제안(수락 시 기록), Results 테이블·집계, Pivot 후보(이유 포함), Conclude 다이얼로그 |
| Visualization | React Flow 흐름 그래프(질의→결과→pivot), 결과 집계 H-bar |
| Drill-down Flow | 결과 행 → Event Drawer → Raw; Pivot → 다음 Query 초안; 결과 → Finding/Case/Detection 생성 |
| Context Panel | Entity Internal Context, Experience(유사 가설), Assistant |
| Raw Data Access | 결과 이벤트 Raw, 실행된 쿼리 원문(OpenSearch DSL 보기, 읽기 전용) |

```
┌ HUNT H-2026-017 ─ Hypothesis: 동일 JA4를 사용하는 다른 Cloud IP 존재 여부 ─ Scope: Global(30d) ─ Active ──────────────┐
├ INVESTIGATION GRAPH ──────────────────────────────────────┬ QUERY HISTORY ─────────────────────────────────────────┤
│ (Hypothesis)                                              │ #1 👤 ja4 = t13d… | top src_ip (30d)     → 47 events     │
│     │ #1 → 47 events                                      │    why: 공격 인프라 공통 지문                           │
│     ▼                                                     │ #2 ✦→👤 src_asn ∈ {16509,15169,14061}    → 2 assets      │
│ [3 related ASNs] ── pivot ──▶ #2 ──▶ [2 assets]           │    why: #1 결과 ASN 집중 81% (AI 제안, 박분석 수락)      │
│                                   └▶ #3 → 0 results       │ #3 👤 assets × outbound >1GB (7d)        → 0             │
├ RESULTS #2 ───────────────────────────────────────────────┴───────────────┬ PIVOT CANDIDATES ──────────────────────┤
│ src_asn  events  assets          first   last                             │ ▸ AS16509 31 IPs — #1 결과 66%        │
│ 16509    31      api-cust01, …   09-28   10-05                            │ ▸ JA4 sibling t13d…_b — 동일 prefix   │
│ 15169     9      api-cust01      10-03   10-05                            │ [Use as next query] [Dismiss]          │
├───────────────────────────────────────────────────────────────────────────┴───────────────────────────────────────┤
│ [Conclude ▾ Confirmed/Refuted/Inconclusive]  [Create Finding] [Add to Case] [Create Detection Candidate]           │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
