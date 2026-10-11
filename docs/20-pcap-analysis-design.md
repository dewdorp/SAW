# 20. PCAP Analysis Design

원칙: **Packet Parser를 직접 만들지 않는다.** Wireshark Packet List부터 보여주지 않는다.

## 1. Architecture Option 비교

| 기준 | **A. Zeek + Suricata + OpenSearch** | B. Malcolm Integration | C. Zeek + Suricata + Arkime + OpenSearch |
|---|---|---|---|
| Architecture | SAW Worker가 도구 실행 → CES 정규화 → SAW 인덱스 | Malcolm 전체 스택을 별도 운영, SAW는 Malcolm OpenSearch/API 조회 | A + Arkime capture/viewer로 세션·패킷 인덱싱 |
| Resources | 낮음~중간 (도구는 Job 시에만) | 매우 높음 (상시 다수 컨테이너, 수십 GB RAM) | 높음 (Arkime SPI 인덱스 + PCAP 보관) |
| UX | SAW UX 완전 통제 (Story-first) | Malcolm Dashboards/Arkime UX로 분산, 이중 UI | SAW + Deep-dive는 Arkime |
| API | 자체 API, 스키마 통제 | Malcolm 스키마·버전에 종속 | Arkime API(viewer) 연동 필요 |
| Maintenance | Zeek/Suricata 버전 관리만 | Malcolm 릴리스 주기에 종속, 업그레이드 무거움 | Arkime 추가 운영 |
| Integration Difficulty | 중간 (정규화 매핑 작성) | 높음 (스키마 매핑·인증 연동) | 높음 |
| Scalability | Worker 수평 확장 | Malcolm 자체 확장 | Arkime 클러스터 필요 |
| Security | 샌드박스 통제 단순 | 넓은 공격면(다수 서비스) | Arkime 웹 UI 추가 공격면·인증 |
| License | Zeek BSD, Suricata GPL-2(별도 프로세스) | Apache-2.0 + 구성요소별 | + Arkime Apache-2.0 |
| Raw Packet Deep-dive | tshark로 세션 PCAP 추출·다운로드 | 우수 | **우수** |

### 권장안
- **MVP: Option A** — SAW의 Story-first UX와 데이터 모델 통제, 가장 낮은 운영 부담. ([ADR-0004](adr/0004-pcap-pipeline-option-a.md))
- **Phase 6b: Option C로 확장 옵션** — 분석가 Raw Packet 수요가 확인되면 Arkime를 “Deep-dive” 전용으로 추가 (SAW Finding → “Open in Arkime” 세션 링크, Community ID로 연결).
- **Malcolm: Reference** — Zeek/Suricata 설정, 필드 매핑, 파이프라인 구성 참고.

## 2. Option A 파이프라인

```
PCAP/PCAPNG (multi)
  → capinfos (tshark suite): 포맷, 링크타입, 패킷 수, 기간, 잘림 여부
  → Zeek  (-C -r, JSON, local.zeek + packages: ja4, community-id, (선택) hassh)
       conn, dns, http, ssl, x509, files, notice, weird, ssh, smtp, dhcp …
  → Suricata (-r, eve.json: alert, flow, http, dns, tls, fileinfo, anomaly; community_id 활성)
  → Normalize → saw-netflow / saw-dns / saw-http-net / saw-tls / saw-ids / saw-files
  → Network Stats → Network Detectors → Findings → Relations → Story
```

- 다중 PCAP: 파일별 병렬 처리. 시간이 이어지는 분할 캡처(rotate)는 `mergecap` 후 처리 옵션(경계 세션 보존).
- 대형 PCAP(> 20 GB): 시간 기준 분할 허용 (경계 세션 끊김을 UI에 고지).
- Community ID로 Zeek conn ↔ Suricata alert ↔ (향후) Arkime 세션 연결.
- Zeek file extraction은 기본 **비활성**, 분석가 요청 시 MIME 제한 + 크기 제한으로 활성 → Quarantine.

## 3. Overview (첫 화면)

```
PCAP ANALYSIS   capture-0105.pcapng · 6.3 GB
Duration 02:58:11–03:46:52 (48m)  Packets 9,120,441  Connections 48,221  Hosts 1,204  Domains 3,880
Truncated packets: 0   Zeek weird: 112

Protocol Distribution (bytes)     Top Talkers (bytes)          Top Destinations         Top Domains (queries)
 TLS   ████████████ 71%            10.10.1.21   4.1 GB          185.x.x.x  3.2 GB        suspicious.example 421
 HTTP  ███ 14%                     10.10.1.35   0.9 GB          43.x.x.x   0.4 GB        api.example.com    388
 DNS   █ 3%                        …                            …                        …
 SSH   ▏ 0.4%
 Other ██ 11%

INTERESTING CONNECTIONS (Detector 기반)       IMPORTANT FINDINGS
 10.10.1.21 → 185.x.x.x:443  3.2 GB, 41m      ▲ Potential Large Outbound Transfer
 10.10.1.21 → 43.x.x.x:443   every 60s ±2s    ▲ Potential Periodic Communication
 10.10.1.21 → suspicious.example (DNS 421)   ■ Potential DNS Anomaly (High entropy subdomains)
```

## 4. Visual Network Story

호스트 중심 방사형 그래프(Cytoscape, concentric layout). 엣지 라벨 = 프로토콜 + 핵심 지표, 엣지 두께 = 바이트(log), 점선 = 주기성.

```
                 ┌──────── TLS ────────▶ 185.x.x.x      3.2 GB · 41m · JA4 rare
                 │
 [10.10.1.21] ───┼──────── DNS ────────▶ suspicious.example   421 queries · entropy 4.1
 Customer API    │
 (Asset: HIGH)   └ ─ ─ ─ HTTPS ─ ─ ─ ─▶ 43.x.x.x       every 60s (CV 0.03)
```
노드 클릭 → 해당 호스트 필터, 엣지 클릭 → Connections 탭(해당 쌍) + 관련 Finding.

## 5. Tabs

| Tab | 데이터 | 핵심 컬럼/시각화 |
|---|---|---|
| Overview | 통계 | §3 |
| Findings | Network Detectors | [24](24-finding-design.md) |
| Connections | zeek conn + suricata flow | src, dst, port, service, duration, bytes ↑↓, conn_state, community_id / Duration×Bytes scatter |
| DNS | zeek dns | query, qtype, rcode, answers, count, entropy / NXDOMAIN 비율, TXT 비율 |
| HTTP | zeek http | host, uri, method, status, UA, mime, size → HTTP Analyzer·Request Diff 재사용 |
| TLS | zeek ssl/x509 | SNI, version, cipher, JA3/JA4, cert subject/issuer/validity, self-signed / JA4 rarity bar |
| Files | zeek files | mime, size, sha256, source conn (Quarantine 상태) |
| Alerts | suricata alert | signature, sid, severity, 연결 conn |
| Timeline | 통합 | [23](23-timeline-design.md) |
| Relations | host-domain-ip-ja4-cert | [22](22-relation-graph-design.md) |
| Raw Sessions | conn 단위 | [Extract PCAP](tshark `-Y` community_id/5-tuple 필터 → 세션 pcap, 다운로드 감사), [Open in Arkime](6b) |

## 6. Network Detectors (Findings 후보)

모든 결과는 “Potential …” 이며 근거를 포함. 예: “Potential Periodic Communication”, NOT “Confirmed C2”.

| Detector | 방법 (결정적) | 주요 Evidence |
|---|---|---|
| High Outbound Volume | 내부→외부 bytes, 호스트별 상위 및 IQR 이상치 | bytes, 비율, duration |
| Large Upload | orig_bytes ≫ resp_bytes (비율 ≥ 10, ≥ 100 MB) | 업/다운 비 |
| Rare Destination | 캡처 내 해당 dst에 연결한 내부 호스트 수 = 1 & 외부 | 접촉 호스트 수 |
| New Destination | Asset baseline/과거 Investigation에 없는 dst (Phase 12 연계) | first seen |
| Periodic Communication | (src,dst,port) 연결 간격 시퀀스: n ≥ 10, 간격 CV ≤ 0.1, 주기 히스토그램 피크, 데이터 크기 일관성 (RITA 방식 참고) | interval median, CV, n |
| Long-lived Connection | duration ≥ 1h 또는 상위 0.1% | duration |
| Port Scanning | 단일 src → 단일 dst 다수 포트, 실패(conn_state REJ/S0) 비율 | ports, 실패율 |
| Host Scanning | 단일 src → 다수 dst 동일 포트 | dst 수 |
| DNS Burst | 시간당 쿼리 급증 (호스트별) | qps |
| Rare DNS / DNS Entropy | 서브도메인 엔트로피·길이, 고유 서브도메인 수/eTLD+1, TXT 비율, NXDOMAIN 비율 | entropy, unique subdomains |
| Large Response | resp_bytes 이상치 (HTTP/DNS) | size |
| TLS/JA3/JA4 Rarity | 캡처 내/기관 baseline 내 희귀 JA4, self-signed, 만료 인증서, SNI 없음, IP 직접 TLS | ja4, cert 정보 |
| Unexpected Protocol | Zeek `service`와 포트 관례 불일치 (예: 443/tcp에 non-TLS, 53/tcp 대량) | service vs port |
| IDS Alerts Cluster | Suricata alert 묶음 (sid 그룹) | sid, count |

## 7. 샌드박스 / 운영

- worker-pcap 이미지: Zeek, Suricata, tshark/capinfos/editcap/mergecap 고정 버전, 비root, 네트워크 없는 namespace에서 실행.
- 도구 타임아웃: 파일 크기 비례 (기본 GB당 10분), 메모리 한도.
- 룰/패키지 업데이트: 오프라인 번들(Suricata ET Open, Zeek 패키지), 버전은 Finding/Artifact에 기록.
- 산출물(zeek logs, eve.json)은 `saw-artifacts`에 원본 보관 → 정규화 로직 변경 시 PCAP 재처리 없이 재인덱싱 가능.
