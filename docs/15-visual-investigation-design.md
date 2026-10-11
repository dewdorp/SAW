# 15. Visual Investigation Design

Investigation Workbench는 SAW의 **기본 작업 공간**이다. (Dashboard가 아님)
Wireframe: [wireframes/07-investigation-workbench.md](wireframes/07-investigation-workbench.md)

## 1. Workbench 구조

```
┌ SAW ─ [INV-20261005-013 API 대량조회 ×] [PCAP-329 ×] [+] ───────────── ⌘K Search ─ Jobs(2) ─ 박분석 ┐
├─────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ INV-20261005-013  Customer API 대량 조회 의심     ▲ HIGH (82)   🕑 10-05 02:58 ~ 03:42 KST ▾          │
│ Evidence 3 · PCAP 6.3GB · Web 12.8GB · WAF 2.1GB   Findings 14 (▲3 ■7 ●4)   Status: In Progress ▾    │
│ Filters: [src_cloud = aws ×] [uri_template = /api/customer?id=<NUM> ×] [− status_code = 404 ×] [+]  │
├──────────────────┬──────────────────────────────────────────────────────┬───────────────────────────┤
│ EVIDENCE         │ Overview│Findings│Story│Timeline│Relations│HTTP│DNS│TLS│Conn│Raw│Notes            │
│ ▾ PCAP 6.3GB  ✓  │ ┌──────────────────────────────────────────────────┐ │ ASSET CONTEXT             │
│ ▾ Web 12.8GB  ✓  │ │                                                  │ │ Customer Lookup API       │
│   37 files       │ │            (선택된 탭의 Visual Analysis)          │ │ Crit: HIGH · 개인정보     │
│ ▾ WAF 2.1GB   ✓  │ │                                                  │ │ Normal 18–32/min          │
│ + Add Evidence   │ │                                                  │ │ Now    684/min  ▲34x      │
│                  │ │                                                  │ │ Batch 03:00 (대상 아님)    │
│ DATA SOURCES     │ │                                                  │ ├───────────────────────────┤
│ ☑ web    8.2M    │ │                                                  │ │ SIMILAR CASES             │
│ ☑ waf    1.1M    │ │                                                  │ │ 92% CASE-20261002-013     │
│ ☑ zeek   3.4M    │ │                                                  │ │ 71% CASE-20260914-004     │
│ ☑ suri   212     │ │                                                  │ ├───────────────────────────┤
│                  │ │                                                  │ │ OUR SOC EXPERIENCE        │
│ FACETS           │ │                                                  │ │ 09-14 API Enum · Attack   │
│ src_cloud        │ │                                                  │ │ 07-23 Batch · Normal      │
│  aws     61%  I E│ │                                                  │ ├───────────────────────────┤
│  none    30%  I E│ │                                                  │ │ ✦ SOC ASSISTANT           │
│ status_code …    │ └──────────────────────────────────────────────────┘ │ [왜 이상한가?][다음 확인]   │
├──────────────────┴──────────────────────────────────────────────────────┴───────────────────────────┤
│ ▾ DETAIL DRAWER: Event 01927f4e… │ Normalized │ Raw │ Entities │ Findings │ Pivot                     │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 1.1 TOP (Context Header)
| 요소 | 내용 | 상호작용 |
|---|---|---|
| Investigation | display_id, 제목 | 제목 인라인 편집 |
| Risk | 아이콘+레벨+점수, 근거 툴팁(최고 Finding, Asset Criticality) | 클릭 → Findings 탭 정렬 |
| Time Range | Evidence 범위 / 분석 범위 | 프리셋, 브러시와 연동 |
| Evidence Count | 종류별 크기·상태 | 클릭 → Left Rail 포커스 |
| Findings 요약 | 레벨별 수 | 클릭 → 해당 레벨 필터 |
| Filters | Include/Exclude 칩 | 토글, 저장(Saved View) |

### 1.2 LEFT (Evidence / Data Source / Filter)
- **Evidence Tree**: Evidence → 파일 → (파서, 이벤트 수, 상태, 오류 수). 체크 해제 시 분석 범위에서 제외.
- **Data Sources**: data_source별 이벤트 수, on/off.
- **Facets**: 핵심 필드 Top-N(현재 필터 반영), 각 항목 `I`(Include) `E`(Exclude). 필드 목록은 data_source에 따라 동적.
- Job 진행 중인 Evidence는 진행 바 + “partial” 배지.

### 1.3 CENTER (Visual Analysis) — Tabs
| Tab | 내용 | 주 시각화 | 문서 |
|---|---|---|---|
| Overview | 규모·분포·Top-N·추세, Top Findings 3 | ECharts 묶음 | [19](19-bulk-log-analysis-design.md), [20](20-pcap-analysis-design.md) |
| Findings | Finding 목록 + 선택 시 상세 | 리스트 + Baseline 바 | [24](24-finding-design.md) |
| Attack Story | 단계 흐름 | React Flow | [21](21-attack-story-design.md) |
| Timeline | 통합 Vertical Timeline + 밀도 | Custom + ECharts | [23](23-timeline-design.md) |
| Relations | Entity Graph | Cytoscape | [22](22-relation-graph-design.md) |
| HTTP | URI Pattern, Parameter, Status/Size, Request Diff 진입 | Table + Chart | [17](17-http-analysis-design.md), [18](18-request-diff-design.md) |
| DNS / TLS / Connections | PCAP 유래 | Table + Chart | [20](20-pcap-analysis-design.md) |
| ATT&CK | Compact Matrix, Technique Swimlane, Inferred(TIE) | Custom Grid + ECharts | [34](34-mitre-attack-integration-design.md) |
| Raw | 가상화 이벤트 테이블 / Raw Viewer | TanStack | — |
| Notes | Markdown + 링크 | — | [32](32-case-investigation-design.md) |

탭은 데이터가 있을 때만 활성(예: PCAP 없으면 DNS/TLS/Conn 비활성 + “PCAP 추가” 안내).

### 1.4 RIGHT (Context)
순서 고정(내부 맥락 우선):
1. **Asset Context** — 현재 선택/필터에 해당하는 자산, Normal vs Current 비교 ([27](27-asset-knowledge-design.md))
2. **Similar Cases** — 점수 + Same/Different ([26](26-similar-case-design.md))
3. **Our SOC Experience** — 승인된 경험, FP 조건 매칭 표시 ([25](25-soc-experience-design.md))
4. **SOC Assistant** — Contextual AI Actions + Ask (Phase 11) ([29](29-local-llm-design.md))

Context Panel은 **현재 선택(selection)** 에 반응한다: Finding 선택 → 해당 Finding 기준 Similar/Experience, IP 선택 → IP 기준.

### 1.5 BOTTOM (Detail Drawer)
이벤트·Entity 상세. 탭: Normalized(필드 트리) / Raw(원문, 마스킹, 제어문자 시각화) / Entities / Related Findings / Pivot.
Raw 원문 위치(`source_file:line_no`)와 “원본 파일에서 앞뒤 50줄 보기” 제공 (S3 range read).

## 2. Investigation Context (Cross-highlighting 아키텍처)

### 2.1 상태 모델 (Frontend, Zustand store per investigation tab)
```ts
type InvestigationContext = {
  investigationId: string;
  timeRange: { from: string; to: string; source: 'evidence' | 'user' | 'brush' };
  filters: Filter[];                  // {field, op: 'is'|'is_not'|'in'|'range'|'exists', value}
  selection: EntityRef | EventRef | FindingRef | StoryNodeRef | null;  // 고정 선택
  hover: EntityRef | null;            // 임시 하이라이트 (debounce 50ms)
  highlightSet: Set<EntityKey>;       // selection으로부터 파생된 연관 entity 집합
  activeTab: TabId;
  dataSources: Record<string, boolean>;
};
```

### 2.2 동작 규칙
| 이벤트 | 효과 |
|---|---|
| 필터 변경 | 모든 서버 쿼리 키에 포함 → TanStack Query 재요청 (Overview/Findings/Timeline/Graph/Table) |
| selection 변경 | 각 뷰가 자기 데이터에서 해당 Entity를 강조 (재쿼리 없음). Context Panel은 재쿼리 |
| hover | 강조만 (가벼움) |
| brush (시간) | timeRange 갱신 = 필터 변경과 동일 |
| Timeline에서 IP 클릭 | selection = IP → Graph 노드 강조·중심 이동, HTTP 차트의 해당 IP 막대 강조, Table 행 강조, Findings에서 해당 IP 포함 Finding 상단 배지 |
| “Filter to this” | selection → filter 승격 |

### 2.3 Entity Key 정규화
모든 뷰는 `entityKey = type + ':' + normalized(value)` 로 같은 대상을 식별 (IPv6 압축 표기, 도메인 소문자·trailing dot 제거, URI template 등).

### 2.4 공유 / 복원
- URL: `/inv/{id}?view={saved_view_id}` — 필터 값(IP·계정 등)을 URL에 넣지 않음.
- 탭 전환·새로고침 시 마지막 Context 복원 (사용자별, 서버 저장).

## 3. Multi-Investigation UX

- 상단 Investigation Tabs (최대 8개 권장, 초과 시 오버플로 메뉴).
- 탭마다 독립 Context store. 메모리 보호: 비활성 탭은 시각화 언마운트(상태만 유지).
- 탭 간 Entity 드래그 → “이 IP를 다른 Investigation에서 검색”.
- 같은 Entity가 다른 열린 Investigation에도 존재하면 Entity Chip에 🔗 배지.

## 4. Visualization Selection Rule (§64)

| 분석 질문 | 데이터 특성 | 시각화 | 라이브러리 |
|---|---|---|---|
| 언제 늘었나? | 시계열 | Line/Area + brush | ECharts |
| 어떤 순서로? | 이벤트 순서 | Vertical Timeline | Custom |
| 누가 누구와? | 관계 | Node-Link Graph | Cytoscape |
| 어떻게 진행됐나? | 단계 | Attack Story Flow | React Flow |
| 무엇이 많나? | 대범주 비교 | Horizontal Bar (정렬) | ECharts |
| 어떻게 분포하나? | 연속값 | Histogram / Box | ECharts |
| 누가 어디로 통신? | 호스트-목적지 | Network Graph (호스트 중심 방사형) | Cytoscape |
| 요청이 어떻게 변했나? | Request 시퀀스 | Diff Flow | React Flow + Custom |
| 평소와 얼마나 다른가? | Baseline vs Current | Range Bar + Observed Marker | ECharts/Custom SVG |
| 행동 순서가 이상한가? | 시퀀스 | Sequence Diagram (정상 vs 관찰) | Custom SVG |
| 주기적인가? | 간격 분포 | Interval Histogram + Scatter | ECharts |
| 파라미터 값이 연속인가? | 값 시퀀스 | Value Step Plot | ECharts |

규칙:
1. 장식용 시각화 금지 — 각 시각화는 **하나의 분석 질문**에 답해야 함 (컴포넌트 메타데이터로 question 명시).
2. 모든 시각화 요소는 근거 이벤트로 연결 (click → filtered events).
3. 데이터가 적으면(예: 3건) 차트 대신 리스트.
4. 카테고리 > 20은 Top-N + “Others” + 전체 보기.
5. Log scale 자동 적용 시 축에 명시.

## 5. Drill-down 표준 경로

```
Finding ──▶ Evidence Checks ──▶ Supporting Events(필터된 테이블) ──▶ Event Drawer ──▶ Raw(원본 위치)
   │              │                                                    │
   └▶ Story Node  └▶ Metric(Baseline) ──▶ 시계열 차트(해당 구간 강조)      └▶ Pivot(Entity)
```
모든 단계에서 Breadcrumb 유지, 뒤로가기 = 이전 Context 상태 복원.

## 6. 성능 설계

- 서버 집계 우선 (브라우저로 원시 이벤트 대량 전송 금지).
- 차트당 응답 ≤ 2,000 포인트 (서버 다운샘플링: LTTB).
- 테이블 가상화, 페이지 500행 cursor.
- Graph 기본 ≤ 300 노드, 초과 시 그룹화 강제.
- Web Worker에서 대용량 JSON 파싱/정렬.
