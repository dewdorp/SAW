# ADR-0006: Celery + Valkey(Redis 프로토콜), 큐 분리

- 상태: Accepted (Phase 0)
- 날짜: 2026-10-05

## Context
대용량 Job의 DAG(chord), 재시도, 취소 필요. Redis는 7.4+ 라이선스 변경 이력.

## Decision
- Celery 5, broker/result = Valkey 8 (Redis 사용 가능).
- 큐: ingest/parse(small,large)/pcap/analyze/enrich/file/ai/maint.
- acks_late, prefetch 1, json serializer, visibility_timeout ≥ 최장 Task.
- 상태 Source of Truth는 PostgreSQL.

## Consequences
+ 성숙, 팀 친숙
- Redis broker의 장시간 Task 재전달 이슈 → heartbeat·멱등 Task로 완화. 필요 시 RabbitMQ로 broker 교체 가능
