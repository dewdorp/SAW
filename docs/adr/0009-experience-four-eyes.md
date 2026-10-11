# ADR-0009: SOC Experience는 Reviewer 승인 후에만 Production Knowledge

- 상태: Accepted (Phase 0)
- 날짜: 2026-10-05

## Context
분석가 오판이 자동으로 지식이 되면 이후 판단을 오염시킨다(Knowledge Poisoning).

## Decision
- 상태: draft → review → approved → deprecated, reviewer ≠ analyst.
- Draft는 검색 기본 제외. 승인본 수정은 새 revision.
- expires_at 필수, 경과 시 needs_review.
- FP 조건은 억제가 아닌 표시, 과거 Confirmed Attack과 충돌 검사.

## Consequences
+ 지식 품질·감사성
- 리뷰 부담 → Review Queue KPI 운영
