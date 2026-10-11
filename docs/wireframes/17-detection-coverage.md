# 17. Detection Coverage (ATT&CK Heatmap)

설계: [34 §4 V5·V6](../34-mitre-attack-integration-design.md)

| 항목 | 내용 |
|---|---|
| Purpose | “실제로 당한 공격 기법”과 “우리가 볼 수 있고 탐지할 수 있는 기법”의 차이(Gap)를 한눈에 |
| Primary User Action | Gap 셀(관찰됨+탐지 없음) 확인 → 근거 Case 확인 → Detection Candidate 생성 또는 데이터 소스 확보 요청 |
| Layout | 상단 필터(기간, 도메인, 플랫폼, 레이어) / 중앙 Full Matrix Heatmap / 우: 선택 기법 상세 / 하: Gap Top 10 |
| Main Components | Layer 선택(Coverage / Observed Threat / Visibility / Group Overlap), 셀 상태 범례(아이콘+텍스트+색), 기법 상세(Data Components 보유, Detection 목록·검증 상태, 관찰 Case), Gap 목록, Export(Navigator layer, Gap 보고서) |
| Visualization | ATT&CK Full Matrix Heatmap, 분기 비교(증감 화살표), Group Overlap 막대(귀속 아님 경고) |
| Drill-down Flow | 셀 → 기법 상세 → 관찰 Case 목록 → Case; Detection → [14]; “Create Detection Candidate” → [14] 초안 |
| Context Panel | 기법 설명(ATT&CK), v18 Detection Strategy/Analytic 요약, (P2) D3FEND, Atomic Red Team 테스트 링크(참고) |
| Raw Data Access | 관찰 Case의 근거 이벤트(보존기간 내) |

```
┌ KNOWLEDGE › DETECTION › COVERAGE ─ Period [12m ▾] Domain [Enterprise ▾] Layer [Coverage ●|Observed|Visibility|Group overlap] ─ [Export layer] ┐
├ MATRIX ────────────────────────────────────────────────────────────────────────────────────┬ T1110.004 Credential Stuffing ──────────┤
│ Recon        Init.Access     Execution   Persistence  Cred.Access     Discovery   Exfil     │ Observed  12 Cases (최근 03-14)          │
│ ▣T1595.003   ▣T1190          ▨T1059      ▨T1505.003   ⛔T1110.004     ▣T1046      ◩T1041     │ Visibility web ✓ waf ✓ auth ✓            │
│ ▣T1595.001   ◩T1078          …           …            ▣T1110.001      …           ▨T1048     │ Detection 없음 ⛔                         │
│ …                                                                                          │ Data Components: Logon Session ✓,        │
│                                                                                            │  Application Log Content ✓               │
│ ▣ 탐지+검증  ◩ 탐지 있음·미검증  ⛔ 관찰됨·탐지 없음(Gap)  ▨ 가시성 없음  □ 해당 없음           │ [Create Detection Candidate]             │
├ GAP TOP 10 (관찰됨 + 탐지 없음) ───────────────────────────────────────────────────────────┴──────────────────────────────────────────┤
│ 1 ⛔ T1110.004 Credential Stuffing   12 cases   가시성 ✓  → 룰 후보 생성 가능                                                           │
│ 2 ⛔ T1505.003 Web Shell              2 cases   가시성 ✗ (File/Process 로그 없음) → 데이터 소스 확보 필요                                 │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
