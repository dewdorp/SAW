# ADR-0001: SAW는 SIEM이 아닌 Analysis Intelligence Layer

- 상태: Accepted (Phase 0)
- 날짜: 2026-10-05

## Context
분석가의 병목은 수집이 아니라 수집 이후의 이해·판단 단계다. SIEM 기능을 재구현하면 비용이 두 배가 되고 분석 경험은 개선되지 않는다.

## Decision
- SAW는 상시 수집·장기 보관·실시간 상관룰을 제공하지 않는다.
- 데이터는 (1) 분석가가 넣은 Evidence (2) 기존 시스템 read-only Connector 조회로만 들어온다.
- 기존 시스템에 대한 쓰기(차단·정책·룰 배포)는 하지 않는다. Detection은 Export만.

## Consequences
+ 범위가 명확, 기존 투자 보존, 운영 부담 감소
- 상시 Baseline 데이터가 없음 → Asset 수동값/Connector 집계/Evidence 내부 상대비교로 대체 ([28](../28-anomaly-detection-design.md))
