# 07. Investigation Workbench

상세 구조·상태모델: [15-visual-investigation-design](../15-visual-investigation-design.md)

| 항목 | 내용 |
|---|---|
| Purpose | 하나의 사건에 대한 모든 Evidence·분석·맥락을 한 화면에서 (기본 작업 공간) |
| Primary User Action | 탭 간 이동(Overview→Findings→Story→Timeline→Relations→Raw), 필터·선택으로 Cross-highlight, Note·Case 추가, 종료 시 Verdict |
| Layout | TOP Context Header / LEFT Evidence·Sources·Facets / CENTER Tabs / RIGHT Context / BOTTOM Detail Drawer |
| Main Components | Context Header(Investigation, Risk, Time Range, Evidence Count, Filter Chips), Evidence Tree, Facets(I/E), Center Tabs 11종, Context Panel 4섹션, Detail Drawer, Close Investigation 다이얼로그 |
| Visualization | 탭별(Overview 차트, Story Flow, Timeline, Graph, 테이블) — 모두 Investigation Context 공유 |
| Drill-down Flow | 어떤 탭에서든 Entity 클릭 → selection(전 패널 강조) → “Filter to this” → Drawer → Raw. Breadcrumb로 복귀 |
| Context Panel | Asset Context → Similar Cases → Our SOC Experience → SOC Assistant (selection 반응) |
| Raw Data Access | Raw 탭(가상화 이벤트 테이블, 컬럼 제어), Drawer Raw(원문·앞뒤 50줄) |

```
┌ [INV-20261005-013 API 대량조회 ×] [PCAP-329 ×] [+] ───────────────────────────────── ⌘K ─ Jobs ─ 박분석 ┐
│ INV-20261005-013 Customer API 대량 조회 의심  ▲HIGH 82  🕑10-05 02:58~03:42 ▾  Evidence 3 (PCAP 6.3G·Web 12.8G·WAF 2.1G) │
│ Findings 14 (▲3 ■7 ●4)   Filters: [src_cloud=aws ×] [− status=404 ×] [+ Add]   [Save view] [Close Investigation] │
├──────────────────┬───────────────────────────────────────────────────────────────┬──────────────────────┤
│ EVIDENCE         │ Overview│Findings│Story│Timeline│Relations│HTTP│DNS│TLS│Conn│Raw│Notes│ ASSET CONTEXT   │
│ ▾☑ PCAP 6.3G ✓   │ ┌ FINDINGS (14) ── group: stage ▾ ─────────────────────────────┐ │ Customer API ▲H │
│ ▾☑ Web 12.8G ✓   │ │ ▲ #1042 Possible API Enumeration  ×21 rate  43 IP  02:58     │ │ 18–32 → 684/min │
│    37 files      │ │ ▲ #1060 Potential Large Outbound  3.2 GB        03:15       │ │ Batch 03:00 ✗   │
│ ▾☑ WAF 2.1G ✓    │ │ ▲ #1051 Potential DB Query Spike  +32x          03:14       │ ├─────────────────┤
│ [+ Add Evidence] │ │ ■ #1047 Request Mutation→Success  403→200       03:01       │ │ SIMILAR         │
│ SOURCES          │ │ ■ #1063 Potential Periodic Comm.  60s           03:20       │ │ 92% CASE-…013 ▲ │
│ ☑web 8.2M ☑waf … │ │ …                                                          │ │ 71% CASE-…004 ▲ │
│ FACETS           │ └────────────────────────────────────────────────────────────┘ │ ├─────────────────┤
│ src_cloud        │                                                                 │ OUR EXPERIENCE  │
│  aws   61%  I E  │  (선택 시 → Finding Detail [06]이 Center에 열림, ← Back)          │ 09-14 Enum ▲    │
│  none  30%  I E  │                                                                 │ 07-23 Batch ○   │
│ ua_class …       │                                                                 │ ├─────────────────┤
│                  │                                                                 │ ✦ ASSISTANT     │
├──────────────────┴─────────────────────────────────────────────────────────────────┴──────────────────────┤
│ ▾ DRAWER  Event 01927f4e… │ Normalized │ Raw │ Entities │ Findings │ Pivot     access.log.18:482113  [±50 lines] │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
