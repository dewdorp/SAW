# 24. Finding Design

Findings는 플랫폼의 **핵심 단위**다. 단순 Alert List가 아니라 “**무엇이, 왜, 얼마나 평소와 다르며, 근거는 무엇인가**”를 담는 설명 객체다.

## 1. Finding 계약

```json
{
  "id": "F-1042",
  "title": "Possible API Enumeration",
  "category": "web.api_enumeration",
  "detector": {"id": "web.api_enumeration", "version": "1.1.0", "params": {"min_unique": 1000, "seq_threshold": 0.8}},
  "risk": {"level": "high", "score": 82,
           "factors": [{"name":"behavior_severity","value":0.7},{"name":"asset_criticality","value":"high"},
                       {"name":"confidence","value":0.9},{"name":"success_ratio","value":0.914}]},
  "confidence": "high",
  "time": {"start": "2026-10-05T02:58:41+09:00", "end": "2026-10-05T03:41:12+09:00"},
  "why": {
    "metrics": [
      {"name":"requests","observed":21338},
      {"name":"unique_objects","observed":18927,"approx":true},
      {"name":"sequential_ratio","observed":0.972},
      {"name":"http_200_ratio","observed":0.914},
      {"name":"source_ips","observed":43},
      {"name":"request_rate_per_min","observed":684,"baseline":{"min":18,"max":32,"source":"asset:customer-lookup-api"},"ratio":21.4}
    ],
    "checks": [
      {"label":"Sequential identifier","passed":true,"value":"97.2%"},
      {"label":"High success ratio","passed":true,"value":"91.4% 200"},
      {"label":"Automated interval","passed":true,"value":"Δt median 0.74s, CV 0.08"},
      {"label":"Multiple Cloud IP","passed":true,"value":"43 IPs: AWS 31, GCP 8, VPS 4"},
      {"label":"Same fingerprint","passed":true,"value":"JA4 t13d1516h2_… (43/43)"},
      {"label":"Known batch window","passed":false,"value":"Batch 03:00 대상 URI 아님"}
    ],
    "counter_evidence": []
  },
  "entities": ["ip_group:g1","uri_template:/api/customer?id=<NUM>","ja4:t13d…","asset:customer-lookup-api"],
  "evidence_refs": {"query": {"filters":[...]}, "sample_event_ids": ["…"], "total": 21338},
  "explanation_md": "(결정적 템플릿으로 생성된 설명)",
  "status": "new"
}
```

### ATT&CK 매핑 필드 (추가)
```json
"attack": [{"technique_id":"T1110.004","tactic":"credential-access","source":"detector_map",
            "confidence":"high","condition_met":true,"rationale":"계정 다양성 2,104 / 계정당 시도 1.3",
            "attack_version":"18.1"}],
"attack_unmapped_reason": null
```
조건부 매핑 규칙은 [34 §3](34-mitre-attack-integration-design.md).

### 필수 규칙
1. 제목은 “Possible / Potential …” — 확정 표현 금지.
2. `why.metrics` ≥ 1, `checks` ≥ 1, `evidence_refs.query` 필수 (근거 이벤트 재현 가능).
3. Baseline이 없으면 `baseline: null` + “Investigation 내부 상대 비교”를 명시.
4. 반대 근거(`counter_evidence`)를 찾는 체크를 Detector가 함께 수행 (예: 배치 시간, 차단 응답, 내부 IP).
5. 동일 Detector·동일 입력 → 동일 결과 (결정성, 버전 기록).
6. `dedup_key` = detector + 핵심 entity + 시간 버킷 → 재분석 시 중복 생성 방지.

## 2. Risk 산정 (결정적, 설명 가능)

```
score = 100 × behavior_severity(detector 기본값 0–1)
            × confidence_factor(low .5 / med .75 / high 1.0)
            × asset_factor(critical 1.2 / high 1.0 / medium .8 / low .6 / unknown .9)
            × outcome_factor(성공 신호 있음 1.0 / 차단·실패만 .6)
  → clamp 0..100 → level: ≥85 critical, ≥65 high, ≥40 medium, ≥20 low, else info
```
UI는 factor 분해를 툴팁으로 보여준다. 가중치는 설정 파일 + 버전.

## 3. Finding Detail UI

```
┌ Finding #1042 ─────────────────────────────────────────────────── ▲ HIGH 82 · Confidence HIGH ┐
│ Possible API Enumeration                                     02:58–03:41 · Customer Lookup API │
├ WHY? ──────────────────────────────────┬ BASELINE vs OBSERVED ───────────────────────────────┤
│ 21,338 requests                        │ Request rate (/min)                                  │
│ ≈18,927 unique objects                 │ Normal  18 ━━━━ 32                                   │
│ 97.2% sequential                       │ Now     ██████████████████████████████████ 684  ×21  │
│ 91.4% HTTP 200                         │ Access time  Normal 09–18 │ Now 02:58 ⚠              │
│ 43 source IP · same JA4                │                                                      │
├ EVIDENCE CHECKS ───────────────────────┴──────────────────────────────────────────────────────┤
│ ✓ Sequential identifier   97.2%          ✓ Automated interval  Δt 0.74s CV .08                │
│ ✓ High success ratio      91.4% 200      ✓ Multiple Cloud IP   AWS31 GCP8 VPS4                │
│ ✓ Same fingerprint        JA4 43/43      ✗ Known batch window  03:00 batch는 다른 URI          │
├ ENTITIES ─────────────────────────────────────────────────────────────────────────────────────┤
│ [🌐 43 IPs ▾] [🔗 /api/customer?id=<NUM>] [🔑 JA4 t13d…] [🏦 Customer Lookup API ▲HIGH]          │
├ ACTIONS ──────────────────────────────────────────────────────────────────────────────────────┤
│ [Related Events 21,338] [Attack Flow] [Timeline] [Request Compare] [Relations] [Similar Cases 3]│
│ [Hunting] [Add to Case] [Create Detection Candidate]                                          │
├ FEEDBACK  ( ) Valid  ( ) Benign  ( ) False Positive  ( ) Duplicate   comment… ───────────────┤
└───────────────────────────────────────────────────────────────────────────────────────────────┘
```

## 4. Findings 목록

- 정렬 기본: risk desc → time. 그룹: category / stage / entity.
- 컬럼: Level(아이콘+텍스트), Title, Key metric(1개), Entities(칩 ≤ 3), Time, Status, Similar 수, FP 매칭 배지.
- FP Knowledge 매칭 시: “⚑ Matches FP-0031 (Internal batch) — 확인 필요” (억제하지 않음, 정렬 하향 옵션).

## 5. Detector Plugin 인터페이스

```python
class Detector(Protocol):
    id: str; version: str; category: str; stage: str   # Story 매핑
    data_sources: set[str]
    def run(self, ctx: DetectorContext) -> list[FindingDraft]: ...
# DetectorContext: investigation scope, query port(OpenSearch read-only), asset port, baseline port, params
```
- 테스트: Fixture 이벤트 세트 → 기대 Finding(골든) + **음성 세트**(정상 트래픽에서 미발생).
- 운영 지표: Detector별 피드백 기반 precision(30일), 비활성/튜닝 판단 근거.

## 6. 피드백 루프

```
Finding feedback (valid/benign/fp/duplicate)
  → detector precision 지표
  → FP 다수 시: FP Rule 후보 제안(조건 자동 초안, Reviewer 승인 필요)
  → valid + Case Confirmed: Experience / Detection Candidate 연결
```
