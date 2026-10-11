# 23. Timeline Design

## 1. 원칙

- 기본은 **Vertical Timeline** (위→아래 시간 순), 상단에 **Density Strip**(전체 분포 + brush).
- 여러 소스(WAF/WEB/DB/PCAP/IDS)를 하나의 축에 — 소스는 색 + 라벨 + 아이콘.
- **반복 이벤트는 접는다** (수만 건의 동일 요청을 한 줄로).
- 이벤트 사이 **간격(Δt)** 을 표시 → 자동화/주기성 직관.

## 2. 레이아웃

```
DENSITY  02:58 ▁▁▂▅█████▇▆▃▂▁▁ 03:46     [WAF][WEB][DB][PCAP][IDS]  ← 소스 토글, brush로 범위
────────────────────────────────────────────────────────────────────────────
03:11:04.512  ● WAF   GET /api/customer/10001   200                 [43.201.12.7]
              │ +0.8s
03:11:05.301  ● WAF   GET /api/customer/10002   200
              │ +0.7s
              ┊ ⋯ 18,925 similar events collapsed  (GET /api/customer/<NUM> 200, 43 src, Δt median 0.74s)  [Expand ▾]
              │
03:14:02      ◆ DB    Customer Table · Query volume +32x        ▲ Finding #1051
              │ +1m09s
03:15:11      ◆ PCAP  Outbound 10.10.1.21 → 185.x.x.x  3.2 GB   ▲ Finding #1060
              │
03:16:00      ✎ NOTE  "DB팀 확인: 배치 아님" — 박분석
```

| 마커 | 의미 |
|---|---|
| ● | 개별 이벤트 |
| ◆ | Finding 앵커 이벤트/집계 이벤트 |
| ⋯ | 접힌 반복 그룹 |
| ✎ | 분석가 Note / Mark |
| ⚑ | Bypass Point, Story 단계 경계 |

## 3. 반복 이벤트 접기 (Collapse)

- 키: `(data_source, src 그룹, method, uri_template, status_code)` 또는 소스별 정의 키.
- 연속 구간에서 같은 키가 N(기본 5)회 이상 이어지면 그룹.
- 그룹 요약: count, src 수, Δt median/CV, first/last, 대표 샘플 2건.
- Expand: 그룹 내부를 가상 스크롤로, 또는 “샘플 50” 모드.
- 서버 계산: OpenSearch composite agg + 시간 버킷 → `/timeline?collapse=true`

## 4. 타임라인 소스 계층

| 레벨 | 내용 | 기본 |
|---|---|---|
| Story | Story 노드 경계 | 표시 |
| Findings | Finding 시작/끝 | 표시 |
| Events | 원시 이벤트(접힘) | 표시 |
| Notes/Marks | 분석가 기록 | 표시 |
| Context | Asset 배치 스케줄, 업무시간 음영 | 표시 (배경 밴드) |

배경 밴드 예: `03:00–03:10 Known Batch (Customer Sync)` 회색 띠 → 분석가가 배치와 겹치는지 즉시 확인.

## 5. 상호작용

- 이벤트 클릭 → **Right Drawer**: Raw Event / Normalized / Related Entity / Related Finding / Pivot
- Entity 클릭 → Cross-highlight (Graph, 차트, 테이블)
- Brush → 시간 필터
- 키보드 J/K 이동, `M` 마크 추가, `N` 노트
- “Jump to” (시간 입력, 다음 Finding, 다음 소스 변화)
- 시간 표기: KST 기본, UTC 토글, 상대시간(+Δ) 토글. `timestamp_quality ≠ exact` 이벤트는 ⏱? 아이콘

## 6. Cross-source 정렬

- 소스별 Clock skew 보정(Investigation 설정, 예: WAF −2.1s) — 표시만 보정, 보정 사실 배지.
- 동일 초 내 순서: timestamp(ns) → 소스 우선순위 → event_id.

## 7. 성능

- 가상 리스트(TanStack Virtual), 행 높이 가변 측정.
- 서버 cursor(PIT + search_after), 앞/뒤 양방향 로딩.
- Density는 별도 경량 API (`/timeline/density`).

## 8. 내보내기

- Case 첨부: 선택 구간 스냅샷(JSON + 렌더 이미지)
- CSV/JSONL Export (마스킹 적용)
- (향후) Timesketch 형식 Export
