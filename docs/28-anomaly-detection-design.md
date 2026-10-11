# 28. Anomaly Detection Design

## 1. 원칙

- LLM에게 Raw Log 수백만 건을 넣지 않는다.
- **Rule → Statistics → Baseline → ML** 순으로 후보를 찾고, 결과는 Finding(“Potential …”)으로 낸다.
- 모든 Anomaly는 **무엇과 비교해 얼마나 다른지**를 보여준다 (단순 Score 금지).

## 2. Anomaly Types

| Type | 정의 | 방법 | 예 |
|---|---|---|---|
| Volume | 양의 급증/급감 | 시간대·요일별 robust baseline (median + MAD), robust z ≥ 5, 비율 표시 | 20 → 800 req/min |
| Rare Event | 처음/드물게 보는 값 | 빈도 사전(lookback 30일) — count ≤ k 또는 first-seen | 신규 User-Agent, 신규 JA4 |
| Sequence | 정상 순서와 다른 행동 | 세션별 액션 시퀀스(uri_template → action 라벨) n-gram/1차 Markov 확률, 시퀀스 로그우도 하위 0.1% | Login→Search→Detail 대신 Detail→Detail→Export |
| Entity Behavior | 엔티티의 평소 대비 | 엔티티별(계정·IP·호스트) 프로파일 + Peer group(같은 부서·같은 역할) 비교 | 평균 20건 조회 → 2,000건 |
| Relationship | 처음 보는 관계 | entity pair first-seen (서버↔외부 IP, 계정↔자산) | 서버가 처음 보는 외부 IP와 통신 |
| Cross-log | 소스를 넘는 연쇄 | 공통 Entity + 시간 윈도우 체인 규칙 | VPN → WAF → DB → PCAP 연쇄 |

## 3. Baseline 저장

```
analysis.baseline(id, scope /*asset|entity|global*/, scope_ref, metric, granularity /*hour_of_week*/,
                  stats jsonb /*{bucket: {median, mad, p05, p95, n}}*/, window_start, window_end,
                  version, excluded_ranges jsonb, approved bool)
```
- 데이터 출처: Connector(SIEM 집계 조회) 또는 누적 Investigation 데이터. **SAW가 상시 수집하지 않으므로** Baseline은 (a) Asset 수동값 (b) Connector 집계 조회 (c) 같은 Evidence 내 앞 구간/다른 엔티티 대비 — 이 우선순위를 명시.
- Poisoning 방지: Confirmed Attack 기간 `excluded_ranges`, 변화율 상한(주간 ±50% 초과 업데이트는 승인 필요), 버전 관리.

## 4. ML (선택적, Phase 12 후반)

- Isolation Forest / HBOS 등 비지도 모델을 **피처 테이블**(엔티티×시간창) 에 적용.
- 반드시 설명 동반: 피처별 기여(예: SHAP 근사 또는 per-feature z-score) 상위 3개를 Finding metrics로.
- 모델·피처 버전 기록, 오프라인 평가(라벨된 Case) 후 활성.

## 5. Cross-log Correlation 규칙 예

```yaml
id: cross.vpn_to_db_spike
chain:
  - {source: vpn,   event_type: auth_success, bind: {user: $u}}
  - {source: waf,   within: 30m, match: {user: $u}, agg: {count: ">100"}}
  - {source: db_audit, within: 30m, match: {db_user_map: $u}, metric: query_rate, vs_baseline: ">10x"}
  - {source: zeek,  within: 60m, match: {src_ip: $asset_ip}, metric: bytes_out, vs_baseline: ">5x"}
output: {title: "Potential Data Access Chain from VPN Session", stage_path: [AUTHENTICATION, DATA_ACCESS, OUTBOUND]}
```
엔진: `worker-analyze`의 CorrelationWorker. Entity 바인딩·시간 윈도우를 OpenSearch 쿼리로 단계 실행.

## 6. 시각화

### Volume — Baseline vs Current
```
API REQUEST RATE (/min)
Normal Range  18 ━━━━━━━━━ 32
Current       ██████████████████████████████████████████████ 684
              34x baseline (robust z = 41.2)
```
시계열: 정상 범위 밴드(p05–p95) 위에 관측선, 이탈 구간 강조.

### Sequence
```
Normal Sequence (top path, 71% of sessions)     Observed (session ●●●a91)
 Login                                           Detail
  ↓                                               ↓
 Search                                          Detail   ×1,204
  ↓                                               ↓
 Detail                                          Export
Sequence Rarity 0.018%   (log-likelihood −41.3, threshold −18.0)
```

### Rare
“First seen in 30 days” 배지 + 빈도 분포 막대에서 현재 값 위치.

## 7. 출력

Anomaly → `FindingDraft` (category `anomaly.<type>`), metrics에 baseline·observed·ratio·method 필수. Story Stage 매핑 포함.
