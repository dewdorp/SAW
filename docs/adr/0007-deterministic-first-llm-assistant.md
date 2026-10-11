# ADR-0007: Deterministic First, LLM은 Assistant

- 상태: Accepted (Phase 0)
- 날짜: 2026-10-05

## Context
설명 가능성·재현성·감사 가능성이 최우선. LLM은 환각·Prompt Injection 위험이 있고 대용량 로그 처리에 부적합.

## Decision
- 후보 발굴: Rule → 통계 → Baseline → (선택) ML.
- LLM: 설명·요약·비교·초안만. Raw Log 전체 미전달, Shell/쓰기 도구 없음.
- AI 출력은 라벨·인용 검증, Verdict/Risk 자동 변경 금지.
- LLM은 Phase 11 (기반 기능 이후).

## Consequences
+ 신뢰·감사 가능
- AI 활용 속도는 늦어짐 (의도된 선택)
