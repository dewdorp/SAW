# 31. Detection Engineering Design

확인된 사건을 **Detection Candidate**로 전환하고, 과거 데이터로 테스트하고, 승인 후 **Export** 한다. **자동 배포는 금지.**

## 1. Feedback Loop

```
Anomaly → Finding → Investigation → Attack Confirmed → SOC Experience
   → Detection Candidate → Historical Testing → Analyst Approval → (사람이) Deployment → Future Detection
                                                                      │
                               SAW는 "deployed" 상태를 기록만 ◀───────┘
```

## 2. Detection 모델

| 필드 | 설명 |
|---|---|
| title / description | |
| data_source | web / waf / zeek / suricata / windows … |
| format | sigma / suricata / snort / regex / generic_query (향후 logpresso) |
| logic | 룰 본문 |
| threshold / time_window | 예: count ≥ 500 by src_ip in 10m |
| exceptions | 예외 조건 (FP Rule과 연결) |
| false_positive | 알려진 FP 설명 |
| severity / confidence | |
| test_events | 양성/음성 테스트 이벤트 |
| related_case | |
| version / created_by / reviewed_by | |
| status | draft → test → approved → deployed → deprecated |

## 3. 생성 경로

1. **Finding 기반 템플릿 (결정적)**: Detector마다 Sigma 템플릿 보유. 예: API Enumeration →
```yaml
title: Possible Sequential Object Enumeration on Customer API
status: experimental
logsource: {category: webserver}
detection:
  sel:
    cs-uri-stem|startswith: '/api/customer'
    sc-status: 200
  condition: sel
# 집계 조건(Sigma correlation 또는 백엔드별 집계 확장)
correlation:
  type: value_count
  group-by: [c-ip]
  timespan: 10m
  condition: {field: cs-uri-query, gte: 500}
falsepositives: ['Customer Sync batch (10.20.3.5, 03:00)']
level: high
```
   (Sigma correlation 규격 지원 범위는 pySigma 버전별 확인. 미지원 백엔드는 Generic Query로 집계 표현)
2. **Experience.detection_conditions** 에서 초안
3. **LLM 제안** (Phase 11+): Sigma 초안 → pySigma 파싱/검증 실패 시 거부
4. **수동 작성**: Monaco 편집기 + 스키마 자동완성 + Lint

Suricata/Snort 룰은 PCAP 기반 Finding(예: 특정 SNI/JA4/URI)에서 템플릿 생성, `suricata -T`(샌드박스)로 문법 검증.

## 4. Historical Testing

```
Detection version → pySigma(OpenSearch backend) → DSL
  → Async Search on saw-* (선택 기간, 선택 Investigation 또는 전체 권한 범위)
  → hits, 시간 분포, Top 엔티티
  → 라벨 교차: hits ∩ Confirmed Attack Case 이벤트 (TP 추정), hits ∩ FP/Normal Case (FP 추정), 미라벨
  → test_events 양성/음성 단위 테스트 통과 여부
```

결과 UI:
```
TEST RUN #3  (2026-07-01 ~ 2026-10-05, saw-web-*)
Hits 1,284 · Days with hits 9 · Est. daily alerts 0.9
Labeled: TP 1,201 (CASE-…013, …004) · FP 12 (EXP-0031 batch) · Unlabeled 71
Unit tests: 6/6 pass
▲ FP 12건 공통: src 10.20.3.5 → [예외 조건 추가 제안]
```

## 5. 승인 / Export

- `approved` 조건: TestRun ≥ 1 통과, reviewer ≠ creator, 예상 일일 알림 수 기재.
- Export 형식: Sigma YAML, Suricata rules, OpenSearch DSL, Generic SIEM query, (향후) Logpresso Query (공식 문법 문서 기반 pySigma 커스텀 Backend).
- 배포는 기존 룰 관리 프로세스(SIEM/IPS 관리자)가 수행 → SAW에서 “deployed” 기록 + 배포 대상·일시 수동 입력.
- 배포 후 효과 추적(향후): Connector로 해당 룰 알림 수 조회.

## 6. 버전 관리

모든 변경 = 새 version, diff 보기, 이전 버전 복원(새 버전으로). 승인된 버전 본문 수정 불가.
