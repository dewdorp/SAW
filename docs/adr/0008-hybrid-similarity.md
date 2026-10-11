# ADR-0008: Similar Case는 Keyword + Feature + Vector Hybrid

- 상태: Accepted (Phase 0)
- 날짜: 2026-10-05

## Context
LLM/벡터만으로는 유사도 근거를 설명할 수 없고, 키워드만으로는 행위 유사성을 놓친다. 한국어 텍스트 존재.

## Decision
- S = 0.45·Feature + 0.35·Vector(pgvector) + 0.20·Keyword(OpenSearch nori).
- Same/Different는 Feature 비교로 결정적 생성.
- 임베딩 입력은 정형 Case Card(원시 로그 제외).

## Consequences
+ 설명 가능, 점수 분해
- 가중치 튜닝 필요 → 골든셋 Recall@5로 오프라인 평가
