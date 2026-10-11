# 16. ATT&CK View (Investigation)

설계: [34-mitre-attack-integration-design](../34-mitre-attack-integration-design.md)

| 항목 | 내용 |
|---|---|
| Purpose | 이 사건에서 관찰된 행위를 ATT&CK 표준 언어로 보고, 다음에 찾아볼 기법을 제시 |
| Primary User Action | Compact Matrix에서 기법 셀 확인 → 근거 Finding으로 이동 → (필요 시) 매핑 수정/수락 → Inferred 기법으로 Hunting 시작 |
| Layout | Workbench Center 탭 “ATT&CK”. 상단 툴바 / 좌: Compact Matrix / 하: Technique Timeline(Swimlane) / 우측 하위패널: Inferred(TIE) |
| Main Components | Compact Matrix(가상화 그리드), 셀 배지(근거 수·출처 아이콘·confidence), Mapping Drawer(근거·조건·rationale·수락/거부), Unmapped Findings 목록, TIE 패널(필요 Data Component·보유 여부), Export 메뉴 |
| Visualization | Matrix Heatmap(실선=Observed/점선=Inferred), Tactic Swimlane Timeline, Story Overlay 토글 |
| Drill-down Flow | 셀 → Mapping Drawer → 근거 Finding [06] → Events → Raw; Swimlane 점 → Unified Timeline 동일 시각 |
| Context Panel | 선택 기법의 과거 Case/Experience, (옵션) D3FEND 대응, 우리 Detection 보유 여부 |
| Raw Data Access | 근거 Finding의 Supporting Events, 룰 메타데이터 원문(Suricata/Sigma) |

```
┌ ATT&CK ─ v18.1 ─ [Compact ●|Full] [☐ Inferred] [☐ Mitigations] [Story lens ↗] ─ [Export Navigator layer] [Open in Navigator] [Attack Flow ↗] ┐
├ COMPACT MATRIX (관찰된 전술만) ──────────────────────────────────────────────────────────────┬ INFERRED (TIE · not observed) ────┤
│ Reconnaissance      Initial Access        Credential Access    Collection      Exfiltration   │ 1 T1505.003 Web Shell       .41  │
│ ┌───────────────┐  ┌────────────────┐    ┌───────────────┐   ┌┄┄┄┄┄┄┄┄┄┄┄┄┄┐ ┌┄┄┄┄┄┄┄┄┄┄┄┄┐ │   필요: File/Process (EDR) ✗     │
│ │T1595.003 ◆ 3  │  │T1190 ◆⚙ 2 MED  │    │T1110.004 ◆ 1  │   ┆T1213 ◆ cand.┆ ┆T1041 cand. ┆ │   [가설로 Hunting 시작]            │
│ │Wordlist  HIGH │  │Exploit Public- │    │Cred Stuffing  │   ┆low          ┆ ┆low         ┆ │ 2 T1083 File/Dir Discovery  .33  │
│ └───────────────┘  │Facing App      │    │HIGH           │   └┄┄┄┄┄┄┄┄┄┄┄┄┄┘ └┄┄┄┄┄┄┄┄┄┄┄┄┘ │ 3 T1059.004 Unix Shell      .29  │
│                    └────────────────┘    └───────────────┘                                    │──────────────────────────────────│
│ ◆Detector ⚙Rule 👤Analyst ✦AI · 실선=Observed 점선=Candidate/Inferred                           │ UNMAPPED FINDINGS (2)             │
│                                                                                              │ #1042 API Enumeration — 후보만    │
├ TECHNIQUE TIMELINE (tactic swimlanes, synced) ────────────────────────────────────────────────┤ #1063 Periodic Comm — 후보만      │
│ Recon      ●T1595.003 02:58                                                                  │ [매핑 지정…]                       │
│ Init.Acc.          ●T1190 03:01                                                              │                                  │
│ Collection                      ○T1213 03:11                                                 │                                  │
│ Exfil                                             ○T1041 03:15                               │                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────┴──────────────────────────────────┘
```
