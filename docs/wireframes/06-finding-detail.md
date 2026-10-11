# 06. Finding Detail

| 항목 | 내용 |
|---|---|
| Purpose | “왜 이상한가”를 지표·기준·체크·근거로 설명하고 다음 행동으로 연결 |
| Primary User Action | WHY/Baseline/Checks 확인 → Related Events 확인 → Feedback 또는 Add to Case |
| Layout | Header(제목·Risk·Confidence·시간·자산) → WHY + Baseline 2열 → Evidence Checks → Entities → Actions → Feedback |
| Main Components | Risk Badge(factor 툴팁), Metric List, Baseline Range Bar, Check List(✓/✗/△), Entity Chips, Action Bar(9종), Feedback Radio, Explanation(결정적 템플릿) |
| Visualization | Baseline vs Observed Range Bar, (카테고리별) 미니 시각화: Value Step Plot / Interval Histogram / Status Bar |
| Drill-down Flow | Metric → 해당 시계열 차트(구간 강조) → Events; Check → 근거 이벤트 필터; [Related Events] → Bottom Drawer 테이블 → Event Drawer → Raw |
| Context Panel | Finding 기준 Similar Cases, Experience, FP 매칭, Playbook 체크리스트 |
| Raw Data Access | Supporting Events 샘플 원문 / Evidence Query “Show query” (구조화 필터 표시) |

```
┌ Finding #1042 ──────────────────────────────────────────── ▲ HIGH 82 ⓘ · Confidence HIGH · New ▾ ┐
│ Possible API Enumeration                           02:58–03:41 KST · [🏦 Customer Lookup API ▲HIGH] │
├ WHY? ────────────────────────────────────┬ BASELINE vs OBSERVED ──────────────────────────────────┤
│ 21,338 requests                          │ Request rate /min   Normal 18 ━━━ 32                  │
│ ≈18,927 unique objects                   │                     Now   ████████████████████ 684 ×21│
│ 97.2% sequential (+1)                    │ Access time         Normal 07–23   Now 02:58 ⚠         │
│ 91.4% HTTP 200                           │ ┌ id value step plot ───────────────────────────┐     │
│ 43 source IP · same JA4                  │ │ 10001 ▁▂▃▄▅▆▇█ 28928  (계단형 = 순차)            │     │
│                                          │ └───────────────────────────────────────────────┘     │
├ EVIDENCE CHECKS ─────────────────────────┴───────────────────────────────────────────────────────┤
│ ✓ Sequential identifier 97.2%   ✓ High success 91.4%   ✓ Automated interval Δt .74s CV .08      │
│ ✓ Multiple Cloud IP AWS31 GCP8 VPS4   ✓ Same fingerprint 43/43   ✗ Known batch (다른 URI)         │
├ ENTITIES [🌐 43 IPs ▾] [🔗 /api/customer?id=<NUM>] [🔑 JA4 t13d…] ─────────────────────────────────┤
├ [Related Events 21,338] [Attack Flow] [Timeline] [Request Compare] [Relations] [Similar 3]          │
│ [Hunting] [Add to Case] [Create Detection Candidate]                                               │
├ FEEDBACK ( ) Valid ( ) Benign ( ) False Positive ( ) Duplicate  [comment…]  detector web.api_enum 1.1.0 ┤
└───────────────────────────────────────────────────────────────────────────────────────────────────┘
```
