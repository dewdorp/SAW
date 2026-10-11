# 14. Detection Candidate

설계: [31-detection-engineering-design](../31-detection-engineering-design.md)

| 항목 | 내용 |
|---|---|
| Purpose | 확인된 사건을 탐지 룰 후보로 만들고, 과거 데이터로 검증하고, 승인 후 Export |
| Primary User Action | 초안 확인·편집 → Historical Test 실행 → FP 원인 확인·예외 추가 → 승인 요청 → Export |
| Layout | 좌: 메타데이터(제목·소스·임계·예외·상태) / 중: 룰 편집기(Sigma/Suricata) / 우: Test Results / 하: Version history |
| Main Components | Status stepper(draft→test→approved→deployed→deprecated), Monaco 편집기(+Lint/pySigma 검증), Test Run 패널, 라벨 교차 결과, 예외 제안, Unit Test Events, Export 메뉴, “deployed 기록” 폼 |
| Visualization | Hits 시간 분포 히스토그램, TP/FP/Unlabeled 스택 바 |
| Drill-down Flow | Hits → 이벤트 테이블 → Raw; FP 그룹 → 관련 Experience/FP Rule; Related Case → Case |
| Context Panel | 원본 Finding·Case·Experience 요약 |
| Raw Data Access | Test hit 샘플 원문, 변환된 OpenSearch DSL(읽기 전용) |

```
┌ DETECTION DET-0057 v3 ─ draft ▸ [test] ▸ approved ▸ deployed ▸ deprecated ─────────────────────────────────────────┐
├ META ────────────────────┬ RULE (Sigma) ✓ valid ───────────────────────────┬ TEST RUN #3 ────────────────────────────┤
│ Title Possible Sequential│ title: Possible Sequential Object Enumeration…  │ 07-01 ~ 10-05 · saw-web-*               │
│  Object Enumeration      │ logsource: {category: webserver}               │ Hits 1,284 · days 9 · est 0.9/day       │
│ Source web               │ detection:                                     │ ▁▁▁▁█▁▁▁▁▁▂▁▁▁█▁▁ (시간 분포)            │
│ Window 10m · ≥500 by src │   sel: {cs-uri-stem|startswith: '/api/cust…'}  │ TP 1,201 ███████████  CASE-…013, …004   │
│ Severity high · Conf med │   condition: sel                               │ FP    12 ▏ EXP-0031 batch               │
│ Exceptions               │ correlation: {type: value_count, group-by:     │ ?     71 ▏ unlabeled [review]            │
│  src 10.20.3.5 (batch) + │   [c-ip], timespan: 10m, gte: 500}             │ ⚠ FP 공통 src 10.20.3.5 → [예외 추가]    │
│ Related CASE-…013        │ falsepositives: [Customer Sync batch]          │ Unit tests 6/6 ✓                        │
├──────────────────────────┴────────────────────────────────────────────────┴─────────────────────────────────────────┤
│ VERSIONS v3 박분석 (test) · v2 auto from F-1042 · v1 …    [Diff]   [Request approval]  [Export ▾ Sigma/OpenSearch/Generic] │
│ ⓘ SAW는 룰을 배포하지 않습니다. 배포 후 [Record deployment]로 대상·일시를 기록하세요.                                     │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
