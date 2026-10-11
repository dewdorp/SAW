# ADR-0005: S3 호환 Object Storage(MinIO) + 교체 가능 Port

- 상태: Accepted (Phase 0)
- 날짜: 2026-10-05

## Context
Evidence 원본 보관에 Object Lock·SSE·Multipart가 필요. MinIO는 AGPL-3.0이며 2025년 이후 커뮤니티 에디션 정책 변경 이력이 있다.

## Decision
- `ObjectStorePort`(S3 API 부분집합)만 사용.
- 기본 MinIO, Phase 1에서 현행 정책 재확인 후 확정.
- MinIO·SeaweedFS 양쪽 계약 테스트 상시 실행.

## Consequences
+ 벤더 종속 회피
- S3 기능 중 일부(Object Lock 세부)는 구현체별 차이 → 계약 테스트로 확인
