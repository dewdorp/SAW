# 26. Similar Case Design

## 1. 원칙

- **Hybrid**: Keyword + Structured Feature Similarity + Vector Similarity.
- LLM만으로 유사도를 계산하지 않는다. 점수는 **분해 가능**해야 한다.
- 결과는 “몇 %”만이 아니라 **Same / Different** 를 보여줘야 한다.

## 2. 검색 대상

| 대상 | 조건 |
|---|---|
| Case (closed) | verdict 있음 |
| Experience | `approved` (기본), `needs_review`는 배지 |
| Draft Experience | 작성자 본인만, 옵션 |
| FP Rule / Playbook | 별도 섹션 |

## 3. 질의 구성

현재 컨텍스트(Investigation / Finding / 수동 입력)에서:
- **Text**: 제목, Finding 설명, 노트 요약 → keyword 질의
- **FeatureSet**: Finding metrics/checks → Feature 추출기 ([25 §3](25-soc-experience-design.md))
- **Embedding**: Feature + 텍스트를 정형화한 “Case Card” 문자열의 임베딩

Case Card(임베딩 입력) 예 — 원시 로그는 포함하지 않음:
```
category: web.api_enumeration; stage: DISCOVERY>EXPLOITATION>DATA_ACCESS;
ua: script/python-httpx; uri: /api/customer?id=<NUM>; param: numeric sequential +1;
src: cloud multi (aws,gcp,vps) 43; ja4: t13d1516h2; success: >90%; rate: >10x baseline; time: off-hours;
asset: customer lookup api (high, PII)
```

## 4. 점수

```
S = w_f · S_feature + w_v · S_vector + w_k · S_keyword       (기본 w_f .45, w_v .35, w_k .20)
```

| 구성 | 계산 | 저장소 |
|---|---|---|
| S_feature | 가중 Jaccard / 키별 일치 점수 (정확 일치 1, 버킷 인접 0.5), 키 가중치(uri_template·param_sequential·ja4 높음, src_ip 낮음). ATT&CK `attack_techniques`(Observed만) 집합 포함 ([34](34-mitre-attack-integration-design.md)) | Python (후보 집합에 대해) |
| S_vector | cosine (pgvector HNSW, top 100 후보) | PostgreSQL |
| S_keyword | BM25 정규화 (nori) top 100 후보 | OpenSearch `saw-knowledge` |

절차: 벡터 top-100 ∪ 키워드 top-100 ∪ Feature 핵심 키 일치(SQL jsonb 인덱스) top-100 → 후보 통합 → 3개 점수 계산 → 재정렬 → top-k.
가중치는 피드백(“유용함/무관함”)으로 오프라인 튜닝 (자동 온라인 학습 아님).

### 임베딩 모델
- 로컬 실행, 한국어·영어 혼합 지원 모델 (후보: bge-m3, multilingual-e5-large — 라이선스·성능 Phase 9에서 평가).
- 모델 변경 시 전체 재임베딩 Job, `model` 컬럼으로 혼용 방지.

## 5. UI

```
SIMILAR CASES                                       기준: Finding #1042
──────────────────────────────────────────────────────────────
92%  CASE-20261002-013   API Enumeration     ▲ Attack   10-02
     score  feature .95 · vector .91 · keyword .84
     Same      ✓UA type ✓URI pattern ✓Sequential param ✓Request interval ✓JA4
     Different △IP  △Payload
     Verdict reason: "동일 JA4 클라우드 분산, WAF rate-limit 적용"   [열기] [비교]
71%  CASE-20260914-004   API Enumeration     ▲ Attack
     Different △JA4 △Time △Asset
58%  EXP-2026-0031       Internal Batch      ○ Normal   ⚑ FP 조건 보유
──────────────────────────────────────────────────────────────
[유용함 👍] [무관함 👎]
```

### Compare View (나란히)
| Feature | 현재 | CASE-…-013 | |
|---|---|---|---|
| uri_template | /api/customer?id=<NUM> | /api/customer?id=<NUM> | ✓ |
| ja4 | t13d1516h2_8daa… | t13d1516h2_8daa… | ✓ |
| src | 43 IP (AWS 31…) | 27 IP (AWS 20…) | △ |
| payload | none | none | ✓ |
| time | 02:58 | 14:10 | △ |

## 6. 성능·품질

- p95 < 1.5 s (Knowledge 100k).
- 평가: 승인된 Case 쌍(분석가 라벨 “유사”) 골든셋으로 Recall@5 측정, 가중치 변경은 지표 비교 후 반영.
