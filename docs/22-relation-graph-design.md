# 22. Relation Graph Design

## 1. 목적

IOC·Entity 간 관계를 보여 **같은 행위자/인프라를 묶어 보게** 한다. 예: 다른 IP가 같은 JA4·Session으로 연결되면 시각적으로 Cluster.

```
AWS IP ─USED─ JA4-A ─USED─ Session-X ─AUTHENTICATED_AS─ Account-A ─ACCESSED─ /api/customer ─ACCESSED─ Customer Objects
```

## 2. Model

| Node type | 키 | 표시 |
|---|---|---|
| ip | 정규화 IP | 아이콘 🌐, 내부/외부 테두리, cloud 배지 |
| domain | eTLD+1 / FQDN | |
| user / account | 계정 | 마스킹 정책 |
| session | 세션 해시 | |
| asset | asset_id | criticality 배지 |
| uri | uri_template | |
| ja3 / ja4 | fingerprint | |
| process / hash | | |
| case | case_id | 과거 사건 연결 |
| group (가상) | ASN, /24, cloud provider, JA4 cluster | compound node |

| Edge | 예 |
|---|---|
| CONNECTED_TO | ip → ip (netflow) |
| USED | ip → ja4, ip → user_agent, ip → session |
| ACCESSED | ip/user/session → uri / asset |
| RESOLVED_TO | domain → ip |
| OBSERVED_WITH | 같은 이벤트에 함께 등장 |
| RELATED_TO | case ↔ entity, 분석가 수동 |
| AUTHENTICATED_AS | session → account |

## 3. 데이터 생성 (DB 없이 Graph DB 대체)

- **Graph DB(Neo4j 등)는 도입하지 않는다** (MVP). Investigation 범위 그래프는 수십만 엣지 이하 → PostgreSQL `inv.entity` / `inv.relation` 물질화로 충분.
- `analyze.relations` Task: OpenSearch composite aggregation으로 `(src_entity, dst_entity)` 쌍의 count/first/last 계산 → upsert.
- 추출 규칙(엣지 정의)은 data_source별 선언형 YAML:
```yaml
- source: web
  edges:
    - {from: src_ip, to: ja4, type: USED}
    - {from: src_ip, to: uri_template, type: ACCESSED}
    - {from: session_id, to: user, type: AUTHENTICATED_AS}
- source: zeek_dns
  edges:
    - {from: domain, to: ext.zeek.answers, type: RESOLVED_TO}
```
- Cross-investigation 엣지: entity 값이 과거 Case에 존재하면 `RELATED_TO case` 노드(옵션 레이어).

## 4. 가독성 전략 (과도한 Node 방지)

| 기법 | 규칙 |
|---|---|
| **Grouping** | 같은 이웃 집합을 갖는 노드(structural equivalence) → 묶음 노드 “43 IPs (AWS 31, GCP 8, VPS 4)” |
| **Group by** 선택 | ASN / Cloud / Country / /24 / JA4 |
| **Filtering** | 노드 타입 on/off, 최소 엣지 count, 시간 범위, 현재 전역 필터 반영 |
| **Collapse / Expand** | compound node 펼치기/접기 (cytoscape-expand-collapse) |
| **Focus mode** | 선택 노드 기준 k-hop(기본 2) 서브그래프만 |
| **Budget** | 렌더 ≤ 300 노드. 초과 시 자동 그룹화 + “+1,204 more” 노드 |
| **Edge bundling** | 같은 타입 다중 엣지는 굵기·count 라벨로 합침 |
| **Pinning** | 분석가가 노드 위치 고정, 레이아웃 저장 |

## 5. UI

```
┌ RELATIONS ─ Group by: [JA4 ▾]  Types: ☑IP ☑JA4 ☑Session ☑Account ☑URI ☐Domain   Min edges: [5]  Focus: 2-hop ┐
│                                                                                                         │
│   ┌──────────────────────┐                                                                              │
│   │ 43 IPs  AWS31 GCP8 V4│──USED──▶ (JA4 t13d1516h2…) ──USED──▶ [Session ×12] ──AUTH──▶ (Account ●●●a91)│
│   └──────────────────────┘                                              │                               │
│   (185.x.x.x) ─CONNECTED─ [10.10.1.21 Customer API ▲HIGH] ◀──ACCESSED──┘ /api/customer?id=<NUM>        │
│                                                                                                         │
├ Legend: 실선=관찰 엣지  점선=약한/추론  두께=count(log)  ◆=Finding 관련 ─────────────── [Table view] ──┤
```
- 노드 클릭 → selection(Cross-highlight) + Entity Drawer; 더블클릭 → Expand
- 우클릭 → Pivot 메뉴, “Hide”, “Group with…”
- [Table view]: 동일 데이터를 Node/Edge 테이블로 (접근성·Export)

## 6. 레이아웃

- 기본: `fcose`(force, compound 지원) — 50 노드 이하
- 계층 흐름이 의미 있을 때: `dagre`/`elk` (출발지 → 대상 방향)
- Network Story(PCAP): `concentric` (내부 호스트 중심)
- 레이아웃 계산은 Web Worker에서, 결과 캐시.

## 7. API

`GET /investigations/{id}/graph?group_by=ja4&types=ip,ja4,session&min_count=5&focus=ip:43.201.12.7&hops=2&max_nodes=300`
→ `{nodes[], edges[], groups[], truncated: {hidden_nodes: 1204}}`
