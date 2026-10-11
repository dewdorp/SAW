# 30. Threat Hunting Design

후기 단계(Phase 13). **가설 → 질의 → 결과 → 분석 → Pivot → 다음 질의** 루프를 기록·시각화한다.

## 1. 모델

```
HuntSession
  hypothesis: "동일 JA4를 사용하는 다른 Cloud IP가 존재하는가"
  scope: investigation | global(권한 필요) | connector
  steps[]:
    seq, actor (analyst|ai), rationale ("JA4가 공격 인프라 공통 지문이므로"),
    query (구조화 Query JSON), result_summary (count, top values), pivots[] (후보 entity + 이유)
  outcome: confirmed | refuted | inconclusive, summary, 생성된 Finding/Case/Detection 링크
```

## 2. Query 표현

- 정규 형식은 **구조화 Query JSON** (SAW Query Model):
```json
{"sources":["web","waf","zeek_ssl"],
 "time":{"from":"now-30d","to":"now"},
 "filters":[{"field":"ja4","op":"is","value":"t13d1516h2_8daa…"},
            {"field":"src_cloud","op":"is_not","value":"none"}],
 "aggs":[{"type":"terms","field":"src_ip","size":100},{"type":"terms","field":"src_asn","size":20}]}
```
- 실행 대상: OpenSearch(Investigation/누적 데이터), Connector(SIEM; `search()/aggregate()`로 변환).
- 사람이 읽는 표현으로 렌더: `ja4 = t13d… AND src_cloud ≠ none | top src_ip, src_asn (30d)`.
- LLM은 이 JSON만 생성 → Schema/필드 사전 검증 → **분석가가 실행 버튼**.

## 3. Allowed Tools (READ ONLY)

| Tool | 설명 |
|---|---|
| search_security_data | 이벤트 검색/집계 (Query JSON) |
| search_case | Case 검색 |
| search_experience | 승인 Experience 검색 |
| search_asset | 자산 조회 |
| search_ioc | IOC 내부 Context |
| search_pcap_metadata | Zeek/Suricata 메타 검색 |
| generate_query | 자연어 → Query JSON (검증만, 실행 아님) |

쓰기·차단·외부 요청 도구 없음.

## 4. UI

```
┌ HUNT H-2026-017 ───────────────────────────────────────────────────────────────────────────────┐
│ Hypothesis: 동일 JA4를 사용하는 다른 Cloud IP 존재 여부 확인            Status: Active  Owner 박분석 │
├ INVESTIGATION GRAPH ─────────────────────────────┬ QUERY HISTORY ────────────────────────────────┤
│  (Hypothesis)                                    │ #1 analyst  ja4=t13d… 30d   → 47 events        │
│      │ #1  47 events                             │    why: 공격 인프라 공통 지문                  │
│      ▼                                           │ #2 ✦ai      src_asn in {3 ASN} → 2 assets       │
│  [3 related ASNs] ──pivot──▶ #2 ──▶ [2 assets]   │    why: #1 결과 ASN 집중(81%)                  │
│                                   │              │ #3 analyst  assets × outbound 7d → 0           │
│                                   ▼ #3 0 results │                                                │
├ RESULTS (#2) ────────────────────────────────────┴────────────────┬ PIVOT CANDIDATES ────────────┤
│ src_asn   events  assets  first      last                         │ ▸ AS16509 (31 IPs) — 이유: … │
│ 16509     31      2       09-28      10-05                        │ ▸ JA4 sibling t13d…_b — 유사  │
│ …                                                                 │ [Run as next query]           │
└───────────────────────────────────────────────────────────────────┴───────────────────────────────┘
[Conclude: Confirmed / Refuted / Inconclusive]  [Create Finding] [Add to Case] [Create Detection Candidate]
```
- 그래프: React Flow, 노드 = 질의/결과/Pivot, 엣지 = 이유.
- 각 step에 **누가(분석가/AI) 왜** 수행했는지 표시 (필수 입력 rationale; AI 제안은 분석가 수락 시 기록).

## 5. 가드레일

- 쿼리 비용 상한 (time range ≤ 90d 기본, Async Search, max buckets).
- Global scope 검색은 Senior 이상 + 감사.
- 결과는 Investigation 저장 시에만 영속, 아니면 요약만.
