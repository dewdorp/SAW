# 08. Attack Story

설계: [21-attack-story-design](../21-attack-story-design.md)

| 항목 | 내용 |
|---|---|
| Purpose | 사건 전체 흐름을 한 장의 그림으로 이해 |
| Primary User Action | 흐름 읽기 → 노드 클릭으로 근거 확인 → 필요 시 편집(이름·병합·수동 노드) → Case 첨부 |
| Layout | Center 전체 캔버스(좌→우 흐름, 2행 래핑) + 상단 툴바 + 노드 선택 시 Right Drawer |
| Main Components | Stage Node(Stage·제목·Risk·지표 2–3·시간·Finding 수), Edge(link_reason, 실선/점선), Toolbar(Auto/Edited 버전, Edit mode, Show weak links, Export SVG, Add to Case), Version 비교 |
| Visualization | React Flow + elkjs layered layout, Stage 색 띠 + 아이콘, 미니맵 |
| Drill-down Flow | Node → Drawer(Supporting Events / Raw Logs / Related IOC / Findings / Timeline 구간) → Event → Raw |
| Context Panel | 선택 노드 기준 Similar·Experience (예: DATA_ACCESS 노드 → 과거 Enumeration 사례) |
| Raw Data Access | Drawer “Raw Logs” 샘플 원문, “View all events” 테이블 |

```
┌ ATTACK STORY ─ v3 (auto 2 + analyst edit) ▾ ─ [✎ Edit] [☐ weak links] [Export SVG] [Add to Case] ────────────┐
│                                                                                                             │
│  INFRASTRUCTURE        DISCOVERY            EXPLOITATION          EXPLOITATION                              │
│ ┌──────────────┐     ┌──────────────┐     ┌────────────────┐     ┌──────────────┐                           │
│ │43 Cloud IP   │ ──▶ │API Discovery │ ──▶ │Request Mutation│ ──▶ │API Success   │                           │
│ │AWS/GCP/VPS   │     │404 / 403     │     │id→userId       │     │HTTP 200 ⚑    │                           │
│ │same JA4      │     │1,203 req     │     │GET→POST        │     │03:01         │                           │
│ └──────────────┘     └──────────────┘     └────────────────┘     └──────┬───────┘                           │
│        ┌───────────────────────────────────────────────────────────────┘ shared ip_group, Δt 42s           │
│        ▼  DATA_ACCESS              DATA_ACCESS              OUTBOUND                                        │
│ ┌──────────────────┐        ┌──────────────┐         ┌──────────────┐                                       │
│ │Object Enumeration│ ─────▶ │DB Query Spike│ ─ ─ ─ ▶ │Outbound Spike│   (점선 = asset 기준 약한 연결)         │
│ │18,927 IDs ▲HIGH  │        │+32x  ▲HIGH   │         │PCAP 3.2 GB ▲ │                                       │
│ │97.2% Sequential  │        │03:14         │         │03:15         │                                       │
│ └──────────────────┘        └──────────────┘         └──────────────┘                                       │
│                                                                           [minimap]                         │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
