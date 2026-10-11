# ADR-0013: 대용량 업로드는 API 경유 Resumable Chunk → S3 Multipart

- 상태: Accepted (Phase 0)
- 날짜: 2026-10-05

## Context
12 GB+ 업로드, 네트워크 단절 재개, 업로드 단계 검증·감사 필요. Presigned URL 직접 업로드는 브라우저에 Object Storage를 노출한다.

## Decision
- 업로드 세션 + 파트(≤ 64 MB) PUT, API는 스트리밍 패스스루(디스크·파싱 없음) + SHA-256 계산.
- 완료 시 Job 생성. 파싱·압축해제는 Worker.

## Consequences
+ 단일 진입점 통제·감사
- API 대역폭 부하 → gateway/api 인스턴스 수평 확장, 필요 시 presigned 방식 재검토
