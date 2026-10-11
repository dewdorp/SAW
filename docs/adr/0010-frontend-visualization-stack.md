# ADR-0010: Frontend 시각화 스택

- 상태: Accepted (Phase 0)
- 날짜: 2026-10-05

## Context
대량 데이터 차트, 관계 그래프(그룹/접기), 흐름도(Story/Diff), 가상화 테이블, Diff 편집기가 필요. 라이선스는 permissive 선호.

## Decision
- ECharts(통계), Cytoscape.js(Relation/Network), React Flow + elkjs(Story/Request Evolution/Hunting), TanStack Table+Virtual(테이블·Timeline·Raw), Monaco(Raw Diff·편집기, lazy), D3(유틸 한정).
- Recharts 미채택(대량 데이터 한계).

## Consequences
+ 성능·라이선스·유지보수 양호
- ECharts formatter XSS 주의 → safeTooltip 강제, Canvas 접근성 → Table view 제공
