# 27. Asset Knowledge Design

“평소”를 알아야 “이상”을 말할 수 있다. Asset Knowledge는 **Baseline과 예외의 공급원**이다.

## 1. 스키마

| 필드 | 예 |
|---|---|
| asset_id | `AST-API-0012` |
| service | Customer Lookup API |
| company | ○○은행 (org_unit) |
| hostname / domain / ip | api-cust01 / service.example.com / 10.10.1.21 |
| owner / department | 홍길동 / 디지털채널개발부 |
| criticality | critical / high / medium / low |
| environment | prod / stg / dev / dr |
| internet_exposed | true |
| data_classification | 개인정보 / 신용정보 / 내부 / 공개 |
| expected_country | [KR] |
| expected_asn | [내부, 주요 국내 ISP] |
| expected_user_agent | [{class: mobile_app, pattern: "BankApp/*"}, {class: browser}] |
| expected_access_time | {weekday: "07:00-23:00", weekend: "09:00-21:00"} |
| expected_request_rate | {per_min: {p50: 22, min: 18, max: 32}, source: "manual|learned", updated: …} |
| expected_uri | [/api/customer, /api/customer/search] |
| batch_schedule | [{name: "Customer Sync", cron: "0 3 * * *", duration_min: 10, src: "10.20.3.5", uri: "/internal/sync"}] |
| known_exception | [{condition, reason, approved_by, expires_at}] |
| authentication | OAuth2 + 세션, MFA 여부 |
| notes | 자유 기술 |

## 2. 데이터 공급

| 방식 | Phase |
|---|---|
| UI 수동 등록/편집 | 8 |
| CSV Import (템플릿 제공, 검증 리포트) | 8 |
| CMDB/자산관리 시스템 Connector | P2 |
| **Learned baseline 제안**: 과거 Investigation/Connector 데이터에서 rate·시간대 분포 계산 → 담당자 승인 시 반영 | 12 |

수동 값과 학습 값은 `source`로 구분 표시. 학습 값은 **제안**일 뿐 자동 덮어쓰기 금지.

## 3. 매칭

이벤트 → Asset: `dst_ip ∈ ip/cidr` OR `hostname/domain` 일치 OR `url_path ∈ expected_uri prefix`. 다중 매칭 시 가장 구체적인 규칙 우선. 결과 `dst_asset_id`를 인덱싱 시 부여(Enrich), Asset 변경 시 재매칭 Job.

## 4. 사용처

| 사용처 | 방식 |
|---|---|
| Finding Risk | asset_factor (criticality) |
| Detector Baseline | expected_request_rate / access_time / country / UA |
| Counter-evidence | batch_schedule, known_exception과 겹치면 체크 항목으로 표시 (억제 아님) |
| Context Panel | Normal vs Current |
| Story | 노드에 대상 자산 표시 |

## 5. Context Panel UI

```
ASSET CONTEXT                                   AST-API-0012 ▲HIGH · 개인정보 · Internet ✓
Customer Lookup API  (디지털채널개발부 · 홍길동)
────────────────────────────────────────────────
Request rate  Normal 18 ━━━ 32 /min     Now 684 ██████████ ×21  ⚠
Access time   Normal 07:00–23:00         Now 02:58               ⚠
Country       Normal KR                   Now US 61% · KR 30%     ⚠
User-Agent    Normal BankApp/*, browser   Now python-httpx        ⚠
Known batch   03:00 Customer Sync (src 10.20.3.5, /internal/sync)
              → 현재 URI/소스는 배치 대상 아님                     ✓ 반대근거 아님
Exceptions    없음
[자산 상세] [담당자 연락처] [Baseline 이력]
```

## 6. 보안

Asset Knowledge는 공격자에게 고가치 정보 → 편집은 Senior 이상, 열람은 Analyst 이상, Export 감사. 담당자 연락처는 마스킹 기본.
