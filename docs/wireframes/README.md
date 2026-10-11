# UI Wireframes

각 화면은 다음 8개 항목으로 기술한다: **Purpose · Primary User Action · Layout · Main Components · Visualization · Drill-down Flow · Context Panel · Raw Data Access** + ASCII Wireframe.
공통 원칙: [14-ui-ux-principles](../14-ui-ux-principles.md), Workbench 구조: [15-visual-investigation-design](../15-visual-investigation-design.md)

| # | 화면 | 주 Phase |
|---|---|---|
| 01 | [Home](01-home.md) | 2 |
| 02 | [Universal Analyzer](02-universal-analyzer.md) | 2 |
| 03 | [HTTP Analyzer](03-http-analyzer.md) | 2 |
| 04 | [Bulk Log Analysis Overview](04-bulk-log-overview.md) | 5 |
| 05 | [PCAP Analysis Overview](05-pcap-overview.md) | 6 |
| 06 | [Finding Detail](06-finding-detail.md) | 4 |
| 07 | [Investigation Workbench](07-investigation-workbench.md) | 4 |
| 08 | [Attack Story](08-attack-story.md) | 4 |
| 09 | [Unified Timeline](09-unified-timeline.md) | 4/7 |
| 10 | [Relation Graph](10-relation-graph.md) | 4 |
| 11 | [Similar Case](11-similar-case.md) | 9 |
| 12 | [SOC Experience](12-soc-experience.md) | 8 |
| 13 | [Hunting](13-hunting.md) | 13 |
| 14 | [Detection Candidate](14-detection-candidate.md) | 14 |
| 15 | [Job Progress](15-job-progress.md) | 5 |
| 16 | [ATT&CK View](16-attack-matrix.md) | 4/7/13 |
| 17 | [Detection Coverage (ATT&CK Heatmap)](17-detection-coverage.md) | 14 |

## 공통 Shell

```
┌ SAW ─ [INV-…013 ×] [PCAP-329 ×] [+] ─────────────── ⌘K Search ── ⏳Jobs(2) ── 🔔 ── 박분석 ▾ ┐
│ ☰ Home · Analyze▾ · Investigations · Timeline · Hunting · Knowledge▾ · Cases · Jobs · Integrations · Admin │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
Analyze ▾ : Universal · IOC · HTTP · Payload · Log · Bulk Logs · PCAP · File · Compare
Knowledge ▾ : Experience · False Positive · Playbook · Asset · Detection
```
메인 메뉴는 좌측 Activity Bar(아이콘, VS Code 방식)로도 접을 수 있다.
