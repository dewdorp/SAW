# 04. Bulk Log Analysis Overview

| 항목 | 내용 |
|---|---|
| Purpose | 수백만 이벤트를 테이블 없이 “규모·분포·이상 패턴·Findings”로 이해 |
| Primary User Action | Findings/Pattern 확인 → 차트 클릭으로 필터 → 의심 영역 Drill-down |
| Layout | Workbench Center의 Overview 탭. 상단 Summary Bar → Top Findings 3 → 차트 그리드(3×3) → Patterns 테이블 |
| Main Components | Summary Bar(≈ 표시), Top Findings Strip, 9 Charts, Pattern Cluster Table, Parameter Profile 링크, Parse Quality 배지 |
| Visualization | Volume Timeline(stack+brush), Status Bar, Size Trend(p50/p95), Unique IP Trend, Top Source/URI/UA/ASN/Country H-bar |
| Drill-down Flow | 차트 요소 클릭 → 전역 필터(Include/Exclude) → 모든 패널 갱신; Pattern 행 → pattern 필터 + Parameter Analyzer; Finding → [06] |
| Context Panel | 필터된 대상의 Asset Context, Similar(필터 기준) |
| Raw Data Access | Raw 탭(가상화 테이블) / 차트 요소 우클릭 “View events” → Bottom Drawer 테이블 |

```
WEB LOG ANALYSIS  37 Files · 8,238,291 Events · 10-01 ~ 10-05 · Unique IP ≈143,882 · Unique URI 8,172 · Findings 14 · Parse err 0.02%
┌ TOP FINDINGS ──────────────────────────────────────────────────────────────────────────────────────────────┐
│ ▲ Possible API Enumeration 21,338 req ×21 baseline │ ▲ Sensitive File Probe 2xx 3건 │ ■ Injection-like 383 req │
├ EVENT VOLUME (brush) ─────────────────────────────────────┬ HTTP STATUS ──────────┬ RESPONSE SIZE (p50/p95) ──┤
│ ▁▁▂▁▁▂▁▁▂▁▁▂▁▁▂▁▁▂▁▁▂▁▁▂▁▁▂▁▁▂▁▁▂▁▁▂▁▁███▇▁▁ 2xx■4xx■5xx │ 200 █████████ 71%     │ ──────────╱╲───── p95     │
│ 10-01                                        10-05 03:00 │ 404 ███ 18%           │ ─────────────── p50       │
├ UNIQUE IP TREND ──────────────────┬ TOP SOURCE ─────────┴─────┬ TOP URI ─────────┴───────────┬ TOP UA ──────────┤
│ ───────────────╱╲──────           │ 43.201.x.x AWS  12,831 I E│ /api/customer?id=<NUM> 21,322 │ python-httpx 21k │
│                                   │ 18.x.x.x   AWS   8,421 I E│ /wp-admin/*            18,441 │ Mozilla/5.0  6.1M│
├ TOP ASN ──────────────────────────┼ TOP COUNTRY ──────────────┴────────────────────────────────┴──────────────────┤
│ AS16509 AMAZON ☁ 31%             │ KR ████████ 64%  US ███ 22%  …     (지도 사용 안 함)                            │
├ PATTERNS (37) ───────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 01 GET /api/customer?id=<NUM>   21,322  43 src  2xx 91%  ▲ sequential-param   [Parameters] [Filter]             │
│ 02 GET /wp-admin/*              18,441 812 src  2xx 0.2% cms-probe                                               │
│ 03 /.env | /.git/* | /config     4,293 207 src  2xx 0%   sensitive-file-probe                                    │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
