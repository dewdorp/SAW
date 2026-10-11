# 14. UI/UX Principles — Visual SOC Analyst IDE

> 목표는 “예쁜 SaaS Dashboard”가 아니라 **Visual SOC Analyst IDE** 다.
> 참고: VS Code(패널·탭·Command Palette), Kibana(필터 칩·Discover), Arkime(세션 Drill-down), Wireshark(계층 상세), DFIR Workstation(Timeline·Evidence 중심).

## 1. 최상위 원칙

| # | 원칙 | 구체 규칙 |
|---|---|---|
| U1 | **Story First → Evidence Second → Raw on Demand** | 모든 분석 결과 화면의 기본 탭은 Overview/Story. Raw는 마지막 탭 또는 Drawer |
| U2 | **Every number is clickable** | 숫자·차트 요소·Entity는 필터·Pivot·상세로 연결. 막다른 숫자 금지 |
| U3 | **One Investigation Context** | 필터·선택·시간범위는 전 시각화 공유 (Cross-highlighting) |
| U4 | **Explain, don't assert** | “Potential …” + WHY + Evidence. 확정 표현은 분석가 Verdict에만 |
| U5 | **Density over decoration** | 큰 카드·여백 과다 금지. 장식용 차트 금지 |
| U6 | **Stay in context** | 새 페이지보다 Drawer/Side Panel/Tab. 뒤로가기로 분석 흐름 유지 |
| U7 | **Keyboard first** | Command Palette(Ctrl+K), 단축키, 포커스 이동 |
| U8 | **Deterministic vs AI 구분** | AI 출력은 별도 색·아이콘·라벨 “AI 생성 · 검증 필요” |
| U9 | **Honest numbers** | 근사치 ≈, 추정 “est.”, 샘플 기반 “sampled n=…”, 부분 결과 “partial” |
| U10 | **Safe rendering** | 모든 데이터는 텍스트로, 제어문자 시각화, HTML 렌더 금지 |

## 2. 정보 계층 (모든 분석 화면 공통)

```
L0  Summary Bar      무엇을 봤나: 범위·규모·위험·Findings 수
L1  Visual Story     무슨 일이: Attack Flow / Network Story / Request Evolution
L2  Findings         왜: 근거·지표·체크
L3  Timeline         언제: 순서·간격
L4  Relations        누구·무엇이: Entity 관계
L5  Detail Tabs      HTTP / DNS / TLS / Connections / Patterns / Parameters
L6  Raw              원본: Raw Event / Raw Session / 원본 파일 위치
```

## 3. Layout System

```
┌ Top Bar: 로고 · Investigation Tabs · Global Search(Ctrl+K) · Jobs · User ──────────────┐
├ Context Header: Investigation / Risk / Time Range / Evidence Count / Filters(chips) ────┤
├───────────┬───────────────────────────────────────────────┬────────────────────────────┤
│ Left Rail │ Center (Analysis)                             │ Right (Context)            │
│ 240–320px │ flex                                          │ 320–420px, 접기 가능         │
│ Evidence  │ Center Tabs                                   │ Asset / Similar / Experience│
│ Sources   │                                               │ / SOC Assistant             │
│ Filters   │                                               │                            │
├───────────┴───────────────────────────────────────────────┴────────────────────────────┤
│ Bottom Drawer (resizable): Event Detail · Raw · Query                                  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

- 모든 패널 리사이즈·접기·팝아웃(듀얼 모니터).
- Layout 상태는 사용자별 저장.

## 4. Visual Design Language

### 4.1 Theme
- Dark 기본(장시간 관제), Light 지원. 배경은 순흑 대신 `#0F1115` 계열, 패널 경계는 1px 라인.
- 폰트: UI는 Pretendard(OFL)/Inter, 데이터·로그는 고정폭 JetBrains Mono(OFL) / D2Coding(OFL). 숫자는 tabular-nums.
- 기본 글자 13px, 테이블 12px, 행 높이 24px(compact) / 28px(comfortable).

### 4.2 Severity — 아이콘 + 텍스트 + 색
| Level | 아이콘 | 텍스트 | 색 (Dark) |
|---|---|---|---|
| Critical | ◆ (채움) | CRITICAL | Magenta-Red |
| High | ▲ | HIGH | Red-Orange |
| Medium | ■ | MEDIUM | Amber |
| Low | ● | LOW | Blue |
| Normal/Info | ○ | NORMAL / INFO | Gray |

색맹(적록) 고려: 아이콘 모양으로 구분 가능, 색은 보조.

### 4.3 의미 색 (Semantic)
| 의미 | 용도 |
|---|---|
| Accent | 선택·포커스 |
| Highlight | Cross-highlight 대상 (외곽선 + 배경 tint) |
| Diff Added / Removed / Changed | Request Diff (아이콘 `+ − ~` 병행) |
| AI | 보라 계열 + ✦ 아이콘 |
| Internal / External | Entity 칩 테두리 스타일(실선/점선) |
| Masked | 회색 해칭 + 🔒 |

### 4.4 Entity Chip (공통 컴포넌트)
```
[🌐 43.201.12.7 · AWS · KR ▾]   [🔗 /api/customer?id=<NUM> ▾]   [🔑 JA4 t13d1516h2_… ▾]
```
- 클릭: Pivot Menu (Detail / Filter Include / Exclude / Timeline / Graph Focus / Similar / Copy(defanged) / Add to Case)
- Hover: 미니 통계 (이벤트 수, First/Last seen, 관련 Finding 수)
- Copy는 기본 **Defanged** (`43[.]201[.]12[.]7`), Shift+Copy로 원문.

## 5. Interaction Patterns

| 패턴 | 규칙 |
|---|---|
| Filter Chips | Include(파랑) / Exclude(빨강 취소선). 모든 화면 상단 Context Header에 표시, 클릭 토글, 저장 가능 |
| Brush | 시계열 차트 드래그 → Time Range 필터 |
| Hover | Cross-highlight (임시), Click = 선택(고정) |
| Drawer | 이벤트/Entity 상세는 Right/Bottom Drawer, 스택 가능(뒤로) |
| Breadcrumb | Finding #1042 › Evidence › Event 01927… (Drill-down 경로) |
| Undo | 필터·Story 편집 Undo/Redo |
| Empty state | “다음에 할 일” 제시 (예: Evidence 추가, 파서 선택) |
| Loading | 스켈레톤 + 부분 결과 우선 표시, 긴 작업은 Job으로 |

## 6. 단축키 (초안)

| 키 | 동작 |
|---|---|
| Ctrl+K | Command Palette / Global Search |
| Ctrl+V (Home) | 붙여넣기 즉시 분석 |
| G then F/T/R/S | Findings / Timeline / Relations / Story 탭 |
| J / K | 목록 다음/이전 |
| Enter | 상세 Drawer |
| I / E | 선택 값 Include / Exclude |
| P | Pivot 메뉴 |
| . | Raw 보기 토글 |
| N | Note 추가 (현재 선택 링크) |
| Shift+A | Add to Case |
| Esc | Drawer 닫기 / 선택 해제 |

## 7. Accessibility

- WCAG 2.1 AA 대비, 포커스 링 항상 표시.
- Canvas 기반(Graph/Chart)은 **동일 데이터 테이블 뷰** 토글 제공.
- ECharts `aria` + decal(패턴) 활성 옵션.
- 애니메이션 최소화, `prefers-reduced-motion` 존중.

## 8. Anti-patterns (금지)

- 로그인 직후 KPI 대시보드 · 지도 위 공격 애니메이션 · 3D 차트 · 파이 차트 남용(카테고리 > 5)
- 페이지네이션된 수백만 행 테이블을 첫 화면으로
- 근거 없는 Risk 숫자, 설명 없는 AI Score
- 색상만으로 상태 표현
- 모달 위 모달, 분석 컨텍스트를 잃는 전체 페이지 이동
