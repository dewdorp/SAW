# 12. SOC Experience

설계: [25-soc-experience-design](../25-soc-experience-design.md)

| 항목 | 내용 |
|---|---|
| Purpose | 조직의 분석 경험을 구조화해 기록·검토·재사용 |
| Primary User Action | (분석가) Close 시 Draft 확인·보완 → Submit / (Reviewer) Review Queue에서 승인·반려 |
| Layout | 좌: 목록·필터·Review Queue / 중: Experience 편집기(구조화 섹션) / 우: 연결 정보(Case, Finding, Feature 미리보기, Revision) |
| Main Components | Status Badge, 구조화 폼(관측값·Behavior Features·Analysis Steps·Recommended Checks·Verdict·FP 조건·Detection 조건), Feature Preview, FP 충돌 경고, Revision Diff, 승인 체크리스트 |
| Visualization | Behavior Feature 칩 매트릭스, Revision diff |
| Drill-down Flow | Related Case → Case; Recommended Check → 쿼리 실행 화면; Feature → 유사 Experience 검색 |
| Context Panel | 유사 Experience(중복 방지), 연결 Case 요약 |
| Raw Data Access | 관련 Case 스냅샷 이벤트 |

```
┌ KNOWLEDGE › EXPERIENCE ──────────────────────────────────────────────────────────────────────────────────────────────┐
├ LIST ─────────────────────┬ EXP-2026-0142  Customer API 순차 ID 열거 — 클라우드 분산   ◐ REVIEW   rev 2 ───┬ LINKS ─────────┤
│ [Review Queue 4]          │ Category attack · Attack type api_enumeration · Asset Customer API ▲HIGH   │ CASE-…013      │
│ ◐ 0142 API 열거 (review)  │ Verdict ▲ Attack · Confidence HIGH · Expires 2027-10-05                   │ INV-…013       │
│ ✔ 0131 WAF 우회 (approved)│ ─ BEHAVIOR FEATURES (auto) ──────────────────────────────────────────── │ F-1042, 1047   │
│ ✔ 0031 Batch (normal)     │ [ua_class=script] [uri=/api/customer?id=<NUM>] [param_seq=true]           │────────────────│
│ ⏳ 0098 만료 임박          │ [interval=sub_second] [src=cloud_multi] [ja4=t13d…] [time=off_hours]      │ SIMILAR EXP    │
│                           │ ─ ANALYSIS STEPS ─────────────────────────────────────────────────────── │ 0131 72%       │
│ Filters: category ▾       │ 1. Parameter 분석으로 순차성 확인 (97.2%)                                 │────────────────│
│ asset ▾ status ▾          │ 2. Request Diff로 403→200 우회 지점 확인                                  │ REVISIONS      │
│                           │ ─ RECOMMENDED CHECKS ─────────────────────────────────────────────────── │ r2 박분석 10-05 │
│                           │ ☐ 동일 JA4의 다른 IP [Run query]  ☐ 응답 크기 분포  ☐ 계정 소유자 확인     │ r1 auto  10-05 │
│                           │ ─ FALSE POSITIVE CONDITIONS ─────────────────────────────────────────── │                │
│                           │ src ∈ 10.20.0.0/16 AND 03:00–03:15 (Customer Sync)  ✓ 과거 Attack 충돌 없음│                │
│                           │ ─ DETECTION CONDITIONS ── value_count(query) ≥500 by src 10m              │                │
│                           │ REVIEWER CHECKLIST ☑근거 ☑FP범위 ☐개인정보 마스킹 ☐만료일                  │                │
│                           │                                    [Reject…] [Approve] (작성자와 다른 사용자)│                │
└───────────────────────────┴───────────────────────────────────────────────────────────────────────────┴────────────────┘
```
