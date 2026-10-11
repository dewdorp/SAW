# 08. OpenSearch Design

## 1. 역할

- Investigation 범위 이벤트의 **검색·집계·Timeline**.
- Knowledge Keyword 검색 (한국어 nori).
- **재생성 가능 저장소**: 원본(S3) + 파서 버전으로 언제든 재인덱싱.
- 외부(브라우저)에 노출하지 않는다. API만 접근하며 `investigation_id` 필터를 **Query Builder에서 강제**.

## 2. Index 전략

인덱스 폭증을 막기 위해 *Investigation별 인덱스* 가 아니라 **데이터 클래스별 월 롤오버 인덱스 + investigation_id 필드** 방식.

| Alias / Pattern | 내용 | 주요 data_source |
|---|---|---|
| `saw-web-*` | 웹 액세스 로그 | nginx/apache/iis/cloudflare |
| `saw-waf-*` | WAF 이벤트 | waf, cloudflare firewall |
| `saw-netflow-*` | Zeek conn, 방화벽 세션 | zeek, firewall |
| `saw-dns-*` | Zeek dns | zeek |
| `saw-http-net-*` | Zeek http (PCAP 유래) | zeek |
| `saw-tls-*` | Zeek ssl/x509, JA3/JA4 | zeek, suricata |
| `saw-ids-*` | Suricata alert / IPS | suricata, ips |
| `saw-sec-*` | Windows/Linux/Auth/기타 | windows, linux, vpn, db_audit, custom |
| `saw-files-*` | Zeek files | zeek |
| `saw-knowledge` | Experience/Case 텍스트 (nori) | — |
| `saw-events` (alias) | 위 이벤트 인덱스 전체 | Timeline·Pivot용 |

- Rollover: 30 GB primary 또는 30일.
- Shard: 데이터 노드당 primary shard 크기 20–40 GB 목표. 단일 노드 MVP는 replica 0, 3-node부터 replica 1.
- 대형 Investigation(>100 M) 은 전용 인덱스 분리 옵션(`saw-web-inv-<id>`) — Admin 설정.

## 3. Index Template (발췌)

```json
{
  "index_patterns": ["saw-web-*"],
  "template": {
    "settings": {
      "index.codec": "zstd_no_dict",
      "index.refresh_interval": "30s",
      "index.mapping.total_fields.limit": 2000,
      "index.sort.field": ["investigation_id", "timestamp"],
      "index.sort.order": ["asc", "asc"]
    },
    "mappings": {
      "dynamic": "strict",
      "properties": {
        "event_id": {"type": "keyword"},
        "investigation_id": {"type": "keyword"},
        "evidence_id": {"type": "keyword"},
        "timestamp": {"type": "date_nanos"},
        "src_ip": {"type": "ip"},
        "method": {"type": "keyword"},
        "uri": {"type": "keyword", "ignore_above": 4096,
                "fields": {"text": {"type": "text", "analyzer": "uri_analyzer"}}},
        "uri_template": {"type": "keyword"},
        "status_code": {"type": "short"},
        "bytes_out": {"type": "long"},
        "user_agent": {"type": "keyword", "ignore_above": 2048},
        "params": {"type": "flattened"},
        "ext": {"type": "flattened"},
        "raw_event": {"type": "text", "index": false},
        "raw_ref": {"type": "object", "enabled": false}
      }
    }
  }
}
```

- `dynamic: strict` + `ext`(flattened)로 매핑 폭증 방지.
- `index.codec` 압축 옵션은 OpenSearch 버전별 지원 확인 (미지원 시 `best_compression`).
- `uri_analyzer`: `/ ? & = .` 기준 토크나이즈 → URI 부분 검색.
- 대량 인덱싱 중에는 `refresh_interval: -1` → 완료 후 복원 (Job 단위 인덱스가 아니므로 bulk 크기·스레드로 조절, refresh는 30s 유지가 현실적).

## 4. Knowledge Index (`saw-knowledge`)

```json
"settings": {"analysis": {"analyzer": {
  "ko": {"type": "custom", "tokenizer": "nori_tokenizer",
         "filter": ["nori_part_of_speech", "lowercase", "nori_readingform"]}}}},
"mappings": {"properties": {
  "doc_type": {"type": "keyword"},          // experience | case | playbook | fp_rule
  "ref_id": {"type": "keyword"}, "status": {"type": "keyword"},
  "title": {"type": "text", "analyzer": "ko", "fields": {"en": {"type": "text", "analyzer": "standard"}}},
  "body": {"type": "text", "analyzer": "ko"},
  "observables": {"type": "keyword"},
  "features": {"type": "flattened"}
}}
```
PostgreSQL FTS는 한국어 형태소 처리 한계로 사용하지 않는다.

## 5. ISM (Lifecycle)

| 단계 | 조건 | 동작 |
|---|---|---|
| hot | 생성 | 쓰기 |
| warm | 30일 | force_merge(1 segment), read_only |
| delete | 보존기간(기본 180일, 설정) | 삭제 — 단 `legal_hold` Investigation 포함 인덱스는 보류 |

보존기간 만료 후에도 원본(S3)이 남아 있으면 **재인덱싱으로 복원 가능** (UI: “Re-hydrate Investigation”).

## 6. 쿼리 패턴

| 용도 | 방식 |
|---|---|
| Overview 통계 | `terms`, `cardinality`(precision_threshold 40000, UI에 ≈ 표시), `date_histogram`, `percentiles` |
| 차트 클릭 필터 | Global Filter → bool filter (include/exclude) |
| Raw Event 페이징 | **PIT + search_after** (deep paging, from/size 금지) |
| Timeline 밀도 | `date_histogram` (auto interval) + 소스별 `terms` |
| 반복 이벤트 접기 | `composite` agg on (src_ip, uri_template, status_code) + time bucket |
| 장시간 쿼리 | Async Search (Hunting, Historical Test) |
| Pivot | `terms` on target field with filter of source entity |
| Pattern | `pattern_id` 집계 |

### Query Builder 안전장치
- 모든 쿼리에 `investigation_id` terms filter 자동 주입 (우회 불가, 단위 테스트).
- 사용자 입력은 **구조화 필터 모델**로만 받는다 (`field, op, value`). Lucene `query_string`은 Hunting 고급 모드에서만, 허용 필드·와일드카드 선두 금지·regex 금지·timeout 30s·max buckets 10k.
- `search.max_buckets`, `indices.query.bool.max_clause_count` 클러스터 설정 상한.

## 7. 보안

- OpenSearch Security plugin 활성: TLS, 내부 사용자 `saw_api`(index read/write 제한), `saw_ingest`(bulk only), `saw_admin`(운영).
- Dashboards는 배포하지 않거나 운영자 전용 (분석가 UI는 SAW).
- Audit log 플러그인으로 OpenSearch 직접 접근 기록.

## 8. 용량 산정

| 항목 | 값 |
|---|---|
| 웹 로그 1 event 평균 (raw 300B) | 인덱스 후 ~0.6–0.9 KB (raw 저장 포함, 압축) |
| 10 M events | ~6–9 GB |
| 월 50 Investigation × 평균 20 M | ~1 billion events/월 → ~600–900 GB/월 |

→ 보존기간 180일 기준 3–5 TB. 단일 노드 MVP는 보존기간 90일 권장, 3-node 확장 시 180일.
