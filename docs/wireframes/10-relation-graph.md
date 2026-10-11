# 10. Relation Graph

설계: [22-relation-graph-design](../22-relation-graph-design.md)

| 항목 | 내용 |
|---|---|
| Purpose | IP·JA4·Session·Account·URI·Asset 관계로 같은 행위자/인프라를 묶어 이해 |
| Primary User Action | Group by 선택 → 의심 클러스터 확인 → Expand/Focus → Pivot |
| Layout | 상단 컨트롤 바 / Center 그래프 캔버스 / 우하단 Legend·Minimap / [Table view] 토글 |
| Main Components | Group by, Type 필터, Min edges, Focus(k-hop), Layout 선택, Node/Edge Drawer, “+N more” 노드 |
| Visualization | Cytoscape (fcose/dagre/concentric), compound group node, edge 두께=count(log), 점선=약한 관계 |
| Drill-down Flow | 노드 클릭 → selection(Cross-highlight) + Entity Drawer; 더블클릭 → Expand; 엣지 → 해당 쌍 이벤트 테이블 |
| Context Panel | 선택 Entity의 Internal Context / Similar / Experience |
| Raw Data Access | 엣지 → evidence_query 이벤트 → Raw |

```
┌ RELATIONS ─ Group by [JA4 ▾] Types ☑IP ☑JA4 ☑Session ☑Account ☑URI ☑Asset ☐Domain  Min edges [5]  Focus [2-hop] Layout [fcose] [Table] ┐
│                                                                                                                               │
│  ┏━━━━━━━━━━━━━━━━━━━━━━━━━┓                                                                                                  │
│  ┃ 43 IPs  ☁AWS31 GCP8 V4 ┃━━USED━━▶ ⬢ JA4 t13d1516h2… ━━USED━━▶ ▢ Session ×12 ━━AUTH━━▶ 👤 ●●●a91 ━ACCESSED━┓             │
│  ┗━━━━━━━━━━━━━━━━━━━━━━━━━┛ [expand]                                                                        ▼             │
│                                                                                       🔗 /api/customer?id=<NUM>             │
│   🌐 185.x.x.x ◀━━CONNECTED_TO 3.2GB━━ 🏦 10.10.1.21 Customer API ▲HIGH ◀━━━━━━━━━━━━━━━━━━━━━━━━━━━┛                       │
│                                          ┆ RELATED_TO                                                                       │
│                                       📁 CASE-20261002-013 (Attack)                                                         │
│                                                                                              ( +1,204 more · grouped )      │
├ Legend: ━ observed  ┆ inferred/weak  두께=count  ◆=Finding 연결 ─────────────────────────────────── [minimap] ───────────────┤
└───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
