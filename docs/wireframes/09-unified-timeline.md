# 09. Unified Timeline

설계: [23-timeline-design](../23-timeline-design.md)

| 항목 | 내용 |
|---|---|
| Purpose | 여러 소스의 사건을 하나의 시간축에서 순서·간격·연쇄로 이해 |
| Primary User Action | Density에서 구간 brush → 수직 타임라인 탐색 → 접힌 그룹 펼치기 → 이벤트 Drawer |
| Layout | 상단 Density Strip(소스 토글) / 본문 Vertical Timeline / 우측 미니 Jump 목록(Findings·Marks) |
| Main Components | Density chart, Source Toggles, Timeline Rows(●/◆/⋯/✎/⚑), Δt 표시, Collapse Group, Context 밴드(배치·업무시간), Jump list, Mark/Note 추가 |
| Visualization | Custom 가상화 Vertical Timeline + ECharts Density |
| Drill-down Flow | 행 → Right Drawer(Raw/Normalized/Entity/Finding/Pivot); Entity → Cross-highlight; ◆ → Finding Detail |
| Context Panel | 선택 이벤트 Entity 기준 Asset/Similar |
| Raw Data Access | Drawer Raw 탭, 그룹 “Expand all” 시 개별 이벤트 원문 |

```
┌ TIMELINE ─ KST ▾ ─ [Δ relative] ─ Sources: [■WAF][■WEB][■DB][■PCAP][■IDS][■NOTE] ─ collapse ≥5 ▾ ──────────────┐
│ 02:58 ▁▁▂▅██████▇▆▃▂▁▁ 03:46     ░░ 03:00–03:10 Known Batch (Customer Sync)                                   │
├──────────────────────────────────────────────────────────────────────────────────────────┬ JUMP ──────────────┤
│ 03:01:12.004 ⚑ WAF   POST /api/user {"id":100}  200  ← Bypass Point (#1047)  [43.201..] │ ◆ #1047 03:01      │
│              │ +2.1s                                                                      │ ◆ #1042 03:01      │
│ 03:11:04.512 ● WAF   GET /api/customer/10001  200                                        │ ◆ #1051 03:14      │
│              │ +0.8s                                                                      │ ◆ #1060 03:15      │
│ 03:11:05.301 ● WAF   GET /api/customer/10002  200                                        │ ✎ note  03:16      │
│              ┊ ⋯ 18,925 similar (GET /api/customer/<NUM> 200 · 43 src · Δt .74s)  [Expand]│                    │
│ 03:14:02     ◆ DB    Customer Table · Query volume +32x          ▲ #1051                 │                    │
│              │ +1m09s                                                                     │                    │
│ 03:15:11     ◆ PCAP  10.10.1.21 → 185.x.x.x  3.2 GB              ▲ #1060                 │                    │
│ 03:16:00     ✎ NOTE  "DB팀 확인: 배치 아님" — 박분석                                       │                    │
└──────────────────────────────────────────────────────────────────────────────────────────┴────────────────────┘
```
