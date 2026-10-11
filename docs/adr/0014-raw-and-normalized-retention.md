# ADR-0014: Raw Event + Normalized Event 동시 보존

- 상태: Accepted (Phase 0)
- 날짜: 2026-10-05

## Context
정규화는 정보 손실과 파서 버그 가능성이 있다. 증거로서 원문이 필요하고, 파서 개선 시 재처리가 필요하다.

## Decision
- 원본 파일은 S3(Object Lock), 이벤트에 raw_ref(object_key, offset, line_no).
- OpenSearch에 raw_event(≤ 32 KB, index:false) 저장.
- Unknown 필드는 ext.<product>.* (flattened).
- 결정적 event_id로 재처리 시 upsert.

## Consequences
+ 증거성·재현성·재처리
- 저장 용량 증가 → 압축 codec, 보존기간
