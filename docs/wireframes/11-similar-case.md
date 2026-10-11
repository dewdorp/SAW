# 11. Similar Case

설계: [26-similar-case-design](../26-similar-case-design.md)

| 항목 | 내용 |
|---|---|
| Purpose | 현재 사건과 비슷한 과거 사건·경험을 근거(Same/Different)와 함께 찾기 |
| Primary User Action | 상위 결과 확인 → Compare로 나란히 비교 → 과거 판단·대응 참고 → 유용함 피드백 |
| Layout | (패널 모드) 우측 Context의 요약 리스트 / (전체 모드) 좌 결과 리스트 + 우 Compare View |
| Main Components | 기준 선택(Investigation/Finding/수동 Feature), 결과 카드(점수·분해·Same/Different·Verdict), Compare Table, 필터(verdict, 기간, 자산), 피드백 |
| Visualization | 점수 분해 미니 바(feature/vector/keyword), Feature 일치 매트릭스 |
| Drill-down Flow | 결과 → Case/Experience 상세(읽기 전용 탭) → 해당 Case의 Story 스냅샷 |
| Context Panel | (전체 모드) 선택된 과거 사례의 Recommended Checks, Response |
| Raw Data Access | 과거 Case 스냅샷 이벤트 (보존기간 내면 원본 링크) |

```
┌ SIMILAR CASES ─ 기준: [Finding #1042 ▾]  Filter: verdict [all ▾] period [1y ▾] ──────────────────────────────────┐
├ RESULTS ───────────────────────────────────────────┬ COMPARE: 현재 vs CASE-20261002-013 ─────────────────────────┤
│ 92% CASE-20261002-013 API Enumeration ▲Attack 10-02│ Feature            현재                 CASE-…013        │
│     ▕feature .95▕vector .91▕keyword .84▏            │ uri_template      /api/customer?id=<N> 동일          ✓   │
│     Same ✓UA ✓URI ✓Sequential ✓Interval ✓JA4       │ param_sequential  true                 true          ✓   │
│     Diff △IP △Payload                       [Compare]│ ja4               t13d1516h2_8daa…     동일          ✓   │
│ 71% CASE-20260914-004 API Enumeration ▲Attack       │ ua_class          script/httpx         script/requests △  │
│     Diff △JA4 △Time △Asset                          │ src_infra         cloud 43             cloud 27      ✓   │
│ 58% EXP-2026-0031 Internal Batch ○Normal ⚑FP조건    │ time_of_day       off_hours            business      △   │
│     Diff △Src internal △UA Java                     │ payload_family    none                 none          ✓   │
│                                                    ├ 과거 판단 ─────────────────────────────────────────────┤
│                                                    │ Verdict Attack · 김선임 · "동일 JA4 클라우드 분산"        │
│                                                    │ Response: WAF rate-limit 요청, 개발팀 IDOR 점검 요청      │
│ [👍 유용함] [👎 무관함]                              │ Checks: ① JA4 동일 IP 확장 ② 응답 크기 ③ 계정 소유자     │
└────────────────────────────────────────────────────┴───────────────────────────────────────────────────────────┘
```
