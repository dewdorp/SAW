# ADR-0003: OpenSearch를 이벤트 저장·검색 엔진으로 사용

- 상태: Accepted (Phase 0)
- 날짜: 2026-10-05

## Context
수백만~수억 이벤트의 집계·필터·Timeline이 필요. 라이선스는 Apache-2.0이 바람직. 한국어 Knowledge 검색 필요.

## Decision
- 이벤트: 데이터 클래스별 월 롤오버 인덱스 + `investigation_id` 필드 (Investigation별 인덱스 아님).
- Knowledge Keyword: `saw-knowledge` (nori).
- OpenSearch는 재생성 가능 저장소로 취급 (원본은 S3).

## Consequences
+ 집계 성능, 생태계, 라이선스
- JVM 운영 부담, 용량 → 보존기간·ISM·재인덱싱 전략
대안: ClickHouse(집계 강점, 전문검색 약함) — 향후 통계 전용 보조 저장소로 재검토 가능
