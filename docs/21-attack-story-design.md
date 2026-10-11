# 21. Attack Story Design

분석가는 이 그림 **하나만 보고도 사건의 전체 흐름**을 이해할 수 있어야 한다.

## 1. 정의

Attack Story = Investigation 범위에서 **Finding과 이벤트 그룹을 단계(Stage)로 묶고, 시간·Entity 연결로 이은 흐름 그래프**.

```
[43 Cloud IP]          [API Discovery]     [Request Mutation]    [API Success]
 AWS/GCP/VPS     ───▶   404 / 403    ───▶   id→userId       ───▶  HTTP 200
 same JA4                                    GET→POST
                                                                     │
      ┌──────────────────────────────────────────────────────────────┘
      ▼
[Object Enumeration]      [DB Query Spike]       [Outbound Spike]
 18,927 IDs        ───▶    +32x           ───▶    PCAP 3.2 GB
 97.2% Sequential
```

## 2. Stage 체계

ATT&CK을 억지로 매핑하지 않는다. SAW 고유의 **관찰 기반 Stage** 를 쓰고, 근거가 명확할 때만 ATT&CK Technique을 보조 태그로 붙인다.
ATT&CK Overlay(기법 배지, 전술 Swimlane 보기, Attack Flow Export/Import)는 [34 §4 V2](34-mitre-attack-integration-design.md) 참조.

| Stage | 의미 | 대표 신호 |
|---|---|---|
| INFRASTRUCTURE | 공격 출발지 특성 | Cloud/VPS 다수 IP, 공통 JA4/UA |
| RECON | 탐색 | Scanning, Forced Browsing, 404 burst |
| DISCOVERY | API/자원 탐색 | API 경로 다양성, 403/404 |
| AUTHENTICATION | 인증 시도·성공 | 로그인 실패/성공, 토큰 획득 |
| EXPLOITATION | 우회/주입 시도 | Request Mutation, Injection-like, Bypass Point |
| DATA_ACCESS | 데이터 접근 | Enumeration, 대량 2xx, DB Query Spike |
| EXECUTION | 실행 | 프로세스 생성, 명령 실행 (EDR/Windows 로그) |
| PERSISTENCE / LATERAL | 지속·이동 | (해당 로그 있을 때만) |
| OUTBOUND | 반출·통신 | Large Outbound, Periodic, DNS Tunneling 의심 |

## 3. 생성 알고리즘 (결정적, `analyzers/story`)

1. **입력**: Findings(+risk), Correlations, Pattern 클러스터, Entity 그래프.
2. **Stage 분류**: `detector_id → stage` 매핑 표 (예: `web.api_enumeration → DATA_ACCESS`, `net.large_outbound → OUTBOUND`). 매핑 없는 Finding은 `UNCLASSIFIED`(Story에 회색 노드).
3. **노드 구성**: 같은 Stage 안에서 공통 Entity(src 그룹, uri_template, asset)를 공유하는 Finding을 병합 → Story Node. 노드 메트릭 = 대표 지표 2~3개 (Finding metrics에서 선택 규칙).
4. **연결(Edge)**: 노드 A→B 연결 조건
   - 시간: `A.start ≤ B.start` 그리고 간격 ≤ 윈도우(기본 2h, 설정)
   - Entity 공유: src IP 그룹/JA4/session/account/asset 중 1개 이상 공유 → `link_reason`
   - Cross-source: src IP가 다르더라도 **Asset**(대상 서버)과 시간 근접 시 약한 연결(점선)
5. **신뢰도**: edge confidence = f(공유 Entity 종류·수, 시간 간격) — high(실선) / medium / low(점선).
6. **정렬**: 위상 정렬 + 시간 → 좌→우(또는 상→하) 레이아웃 (elkjs layered).
7. **가지치기**: Risk가 낮고 연결 없는 노드는 “Other Activity”로 접기.

## 4. 분석가 편집

- 노드 이름 변경, Stage 변경, 병합/분리, 삭제(숨김), 수동 노드 추가(“DB Audit 확인 결과 …”), 엣지 추가·삭제, 노드 고정.
- 편집본은 `origin=analyst` 새 버전. 자동 재생성 시 분석가 편집 노드는 보존하고 차이를 “New since your edit” 배지로 표시.
- Story 스냅샷을 Case에 첨부 → 보고서에 SVG/PNG로 포함.

## 5. 노드 UI

```
┌ DATA_ACCESS ──────────────────────┐
│ Object Enumeration          ▲ HIGH│
│ 18,927 IDs · 97.2% sequential     │
│ 03:01 → 03:41 · 43 src            │
│ Findings: #1042  Evidence: 21,338 │
└───────────────────────────────────┘
```
노드 클릭 → Right Drawer:
- Supporting Events (필터된 테이블, 상위 샘플)
- Raw Logs (샘플 원문)
- Related IOC (Entity Chips)
- 관련 Finding (상세로 이동)
- Timeline에서 이 구간 보기

엣지 hover → `link_reason` (“shared JA4 t13d…, Δt 2m”).

## 6. 표시 규칙

- 각 노드 숫자는 Finding metrics와 **동일 출처** (Story 전용 계산 금지 → 불일치 방지).
- 근거가 약한 연결은 점선 + “weak link” 라벨.
- AI 생성 내레이션(Phase 11)은 그래프 아래 별도 블록(✦ AI 라벨), 그래프 자체는 결정적.

## 7. 데이터 계약

```json
{"version":3,"origin":"auto","algo_version":"story/1.0.0",
 "nodes":[{"id":"n4","stage":"DATA_ACCESS","title":"Object Enumeration","risk":"high",
           "metrics":[{"name":"unique_ids","value":18927},{"name":"sequential_ratio","value":0.972}],
           "finding_ids":["F-1042"],"time":{"start":"…","end":"…"},
           "entities":["ip_group:g1","uri_template:/api/customer?id=<NUM>"],
           "evidence_query":{"filters":[…]},"pinned":false}],
 "edges":[{"from":"n3","to":"n4","confidence":"high","link_reason":["ip_group:g1","ja4:t13d…"],"delta_sec":42}]}
```
