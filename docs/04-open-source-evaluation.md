# 04. Open Source Evaluation

> **주의**: 라이선스 정보는 2026-10 기준 작성자 지식에 근거한다. **도입 시점에 각 저장소의 LICENSE 파일과 릴리스 정책을 법무/컴플라이언스와 재확인**한다 (Phase 1 체크리스트 항목).

## 1. 결정 범주

| 범주 | 의미 |
|---|---|
| **USE DIRECTLY** | 바이너리/라이브러리를 그대로 구성요소로 사용 |
| **INTEGRATE API** | 별도 서비스로 운영, API/링크로 연동 |
| **REUSE COMPONENT** | 일부(룰, 정적 빌드, 알고리즘, 라이브러리)만 재사용 |
| **REFERENCE ONLY** | 설계 참고, 코드 미사용 |
| **DO NOT USE** | 사용하지 않음 |

## 2. 라이선스 정책 (제안)

| 등급 | 라이선스 | 사용 조건 |
|---|---|---|
| Green | MIT, BSD, Apache-2.0, ISC, PostgreSQL, MPL-2.0 | 자유 사용 (고지 의무 준수) |
| Yellow | LGPL-2.1/3.0, EPL-2.0 | 동적 링크/미수정 사용, 수정 시 공개 의무 검토 |
| Orange | GPL-2.0/3.0 | **별도 프로세스(subprocess/container)로만 실행**, SAW 코드와 링크 금지, 수정 시 법무 검토 |
| Red-Review | AGPL-3.0, SSPL, RSAL, FoxIO License, DRL | **법무 검토 필수**. 사내 전용·미수정·별도 서비스 원칙 |

SAW는 사내 전용(배포·판매 없음)이므로 GPL/AGPL 의무 발생 범위가 제한적이지만, 향후 계열사 배포·외부 이관 가능성을 고려해 위 정책을 적용한다.

## 3. Security OSS 결정 요약

| OSS | 라이선스 | 결정 | 역할 | Phase |
|---|---|---|---|---|
| **Zeek** | BSD-3 | **USE DIRECTLY** | PCAP → conn/dns/http/ssl/files/x509 메타데이터 | 6 |
| **Suricata** | GPL-2.0 | **USE DIRECTLY** (별도 프로세스) | PCAP Signature 분석, eve.json, JA3/JA4 | 6 |
| **tshark** | GPL-2.0 | **USE DIRECTLY** (별도 프로세스) | capinfos 메타, 세션 추출, 특정 필드 추출 | 6 |
| **OpenSearch** | Apache-2.0 | **USE DIRECTLY** | 이벤트 검색·집계, Knowledge Keyword | 1 |
| **pySigma** | LGPL-2.1 | **USE DIRECTLY** (미수정 라이브러리) | Sigma 파싱·변환, OpenSearch Backend | 14 |
| **Sigma Rules** | DRL 1.1 | **REUSE COMPONENT** | 참고 룰셋·테스트 (출처 표기 의무) | 14 |
| **CyberChef** | Apache-2.0 | **REUSE COMPONENT** | 정적 빌드 내부 호스팅, “Open in CyberChef” Deep-link | 2 |
| **CyberChef Server** | Apache-2.0 | **REFERENCE ONLY** | 유지보수 활동 저조 → 핵심 경로 의존 금지 | — |
| **IntelOwl** | AGPL-3.0 | **INTEGRATE API** (선택) | 외부 TI·File 분석 Backend (별도 서비스, 미수정) | 2+(옵션) |
| **Arkime** | Apache-2.0 | **INTEGRATE API** (Phase 6b 옵션) | Raw Session / Packet Deep-dive | 6b |
| **Malcolm** | Apache-2.0 (구성요소별 상이) | **REFERENCE ONLY** | 네트워크 분석 아키텍처 참고 | — |
| **Timesketch** | Apache-2.0 | **REFERENCE ONLY** → 향후 INTEGRATE API | Timeline UX 참고, 필요 시 Export 연동 | 7+ |
| **DFIR-IRIS** | LGPL-3.0 | **REFERENCE ONLY** | Case 모델 참고. 내장 Case가 Finding/Experience와 밀결합 필요 | — |
| **Hayabusa** | AGPL-3.0 (확인 필요) | **USE DIRECTLY** (별도 프로세스, P2) | EVTX → Timeline/Sigma 탐지 | 7+ |
| **Chainsaw** | GPL-3.0 | **USE DIRECTLY** (별도 프로세스, P2, Hayabusa 대안) | EVTX Hunting | 7+ |
| **libinjection** | BSD-3 | **USE DIRECTLY** | SQLi/XSS 토큰 기반 탐지 | 2 |
| **OWASP CRS** | Apache-2.0 | **REUSE COMPONENT** | 패턴 아이디어·테스트 페이로드 (정규식 직접 이식은 RE2 호환 검증 후) | 2 |
| **Drain3** | MIT | **USE DIRECTLY** | 로그 템플릿 마이닝 | 5 |
| **RITA** | GPL-3.0 | **REFERENCE ONLY** | Beacon 탐지 알고리즘 참고 | 6 |
| **Zeek ja4 package / JA4+** | JA4: BSD-3, JA4+(JA4S/H/X/SSH 등): FoxIO License 1.1 | **USE DIRECTLY (JA4)** / JA4+는 법무 검토 | TLS Client Fingerprint | 6 |
| **ET Open Rules** | BSD/GPL 혼재 (확인 필요) | **REUSE COMPONENT** | Suricata 룰셋, 오프라인 번들 | 6 |
| **ClamAV** | GPL-2.0 | **USE DIRECTLY** (선택, 별도 프로세스) | File Evidence 1차 스캔 | 7+ |

### 3.1 상세 평가

#### Zeek — USE DIRECTLY
- **장점**: 사실상 표준 네트워크 메타데이터, JSON 로그, Community ID, 패키지 생태계(ja4, hassh).
- **단점**: 단일 스레드(파일당), 대형 PCAP는 처리시간 증가.
- **SOC 적합성**: 매우 높음. Connections/DNS/HTTP/TLS 탭의 데이터 원천.
- **통합**: `zeek -C -r file.pcap LogAscii::use_json=T local` → 로그 파일 → 정규화. 샌드박스 내 subprocess.

#### Suricata — USE DIRECTLY
- **장점**: 시그니처 + 프로토콜 파서, eve.json, 멀티스레드, JA3/JA4 지원(버전 확인).
- **라이선스**: GPL-2.0 — 별도 프로세스로만 실행. SAW는 eve.json만 소비.
- **운영**: 망분리 환경에서 룰 업데이트는 오프라인 번들(`suricata-update` 내부 미러).

#### tshark — USE DIRECTLY
- 용도를 **좁게** 한정: `capinfos`(파일 메타), 특정 세션 PCAP 추출(`-Y` 필터 → 새 pcap), 필요한 필드만 `-T fields`.
- 전체 패킷 디섹션을 OpenSearch에 넣지 않는다 (용량 폭증). 디섹터 취약점이 잦으므로 가장 강한 샌드박스.

#### OpenSearch — USE DIRECTLY
- Apache-2.0, 집계·검색 성능, Security plugin, ISM, nori(한국어) 분석기, Async search, PIT.
- Elasticsearch는 라이선스(ELv2/SSPL/AGPL 선택) 및 사내 표준 여부로 제외.

#### CyberChef — REUSE COMPONENT
- 핵심 Decode Chain은 **자체 Python 구현**(작고 결정적, 테스트·감사 가능, 자동 체인 탐색 필요) — [ADR-0011](adr/0011-payload-decode-strategy.md).
- CyberChef 정적 빌드를 `tools` 프로필로 내부 호스팅, Recipe URL로 Deep-link → 분석가 Ad-hoc 작업.
- 주의: Deep-link URL에 입력값이 포함되므로 **URL fragment(#) 사용**, 서버 로그에 남지 않게 하고 민감 데이터는 경고.

#### IntelOwl — INTEGRATE API (옵션)
- **장점**: 다수 Analyzer(TI, 파일, 샌드박스) 통합, REST API.
- **단점**: 무거움(여러 컨테이너), AGPL-3.0, 대부분 Analyzer가 인터넷 필요 → 망분리 환경에선 가치 제한.
- **결정**: MVP는 자체 **오프라인 Enrichment**(ASN/Geo/Cloud 대역) + 내부 Context. IntelOwl은 `tools` 프로필의 선택 연동, `IntelEnrichmentPort` Adapter로만 접근.

#### Arkime — INTEGRATE API (Phase 6b)
- **장점**: 세션 인덱싱·패킷 뷰어 최고 수준. Apache-2.0.
- **단점**: 별도 OpenSearch/Elasticsearch 호환성·버전 제약, 별도 UI/인증, 저장공간 큼.
- **결정**: MVP 제외. Raw Packet Deep-dive 수요 확인 후 “Open in Arkime” 링크 + SPI 조회 연동. ([20](20-pcap-analysis-design.md) Option 비교)

#### Malcolm — REFERENCE ONLY
- Zeek+Suricata+Arkime+OpenSearch+Dashboards+NetBox 등 **통합 배포판**. 매우 무거움(권장 RAM 수십 GB+).
- SAW의 UX(Story-first, Findings)와 데이터 모델 통제권이 필요 → 전체 채택 시 Malcolm의 스키마·업그레이드 주기에 종속.
- 파이프라인 구성, Zeek/Suricata 설정, 인덱스 템플릿을 **참고**.

#### Timesketch — REFERENCE ONLY (향후 INTEGRATE)
- 협업 Timeline 분석의 좋은 레퍼런스(태깅, 저장된 뷰, Sketch). 자체 OpenSearch/PG/Redis 필요.
- SAW Timeline은 Finding/Story/Graph와 Cross-highlighting이 핵심이므로 자체 구현.
- DFIR 팀이 이미 사용 중이면 “Export to Timesketch”(Plaso/JSONL) 연동 고려.

#### DFIR-IRIS — REFERENCE ONLY
- 사고 대응 Case 관리. SAW Case는 Finding·Experience·Detection과 결합된 경량 모델이 필요.
- 이미 IRIS/SOAR를 운용 중이면 Case Export/동기화 Connector로 대응.

#### Sigma / pySigma — USE DIRECTLY
- Sigma를 Detection의 **정규 표현**(canonical)으로 채택. pySigma로 OpenSearch(Lucene/DSL) 변환 → Historical Test.
- Logpresso Backend는 공식 쿼리 문법 문서 확보 후 커스텀 pySigma Backend로 작성.

## 4. Infrastructure OSS

| OSS | 라이선스 | 결정 | 리스크 / 메모 |
|---|---|---|---|
| PostgreSQL | PostgreSQL | USE | — |
| pgvector | PostgreSQL | USE | HNSW 인덱스, 100k~1M 벡터 충분 |
| Valkey | BSD-3 | **USE (권장)** | Redis 포크, 프로토콜 호환 |
| Redis | 7.4+: RSALv2/SSPLv1, 8.x: AGPLv3 옵션 추가 | 대안 | 라이선스 변동 이력 → Valkey 권장 |
| MinIO | AGPL-3.0 | USE (교체 가능 설계) | 2025년 커뮤니티 에디션 정책 변경(콘솔 기능 축소·배포 방식 변경 등) — **Phase 1에서 재확인**. 대안: SeaweedFS(Apache-2.0), Ceph RGW(LGPL), 사내 S3 스토리지 |
| Celery | BSD-3 | USE | Redis broker의 visibility timeout 주의 |
| FastAPI / Pydantic / SQLAlchemy | MIT | USE | — |
| nginx | BSD-2 | USE | — |
| Ollama | MIT | USE (Phase 11) | 모델 가중치 라이선스 별도 검토 |
| vLLM | Apache-2.0 | 대안 (GPU 서버) | — |
| 임베딩 모델 (예: bge-m3, multilingual-e5) | MIT / 모델별 | 후보 | 한국어 성능·라이선스 검증 |

## 5. Frontend Visualization Library 평가

평가 척도: ●●● 우수 / ●● 보통 / ● 미흡

| 라이브러리 | 라이선스 | Maintenance | Performance | SOC 적합성 | Accessibility | Dev Cost | 결정 |
|---|---|---|---|---|---|---|---|
| **ECharts** | Apache-2.0 | ●●● | ●●● (Canvas/WebGL, 대량 포인트, dataZoom/brush) | ●●● | ●● (aria, decal 패턴) | ●● | **채택** — 모든 통계 차트 |
| Recharts | MIT | ●● | ● (SVG, 수만 포인트에서 저하) | ●● | ●● | ●●● | 미채택 (대량 데이터 한계) |
| **Cytoscape.js** | MIT | ●●● | ●●● (수천 노드 Canvas) | ●●● (compound node, expand-collapse, 레이아웃 다양) | ● (Canvas → 대체 리스트 뷰 필요) | ●● | **채택** — Relation Graph, Network Story |
| D3 | ISC | ●●● | ●● (구현 의존) | ●●● (무엇이든) | ●● | ● (높음) | **제한 채택** — 스케일·포맷 유틸, 특수 시각화만 |
| **TanStack Table + Virtual** | MIT | ●●● | ●●● (Headless + 가상화) | ●●● (컬럼 제어 자유) | ●●● (마크업 직접 통제) | ●● | **채택** — Event/Analyst Table, Timeline 가상화 |
| **Monaco** | MIT | ●●● | ●● (번들 큼, lazy load) | ●● | ●●● | ●●● | **제한 채택** — Raw Diff, Custom Parser/Sigma 편집기 |
| **React Flow (xyflow)** | MIT | ●●● | ●● (수백 노드) | ●●● (Attack Story/Request Evolution 노드-엣지 UI) | ●● | ●●● | **채택** — Attack Story, Request Evolution, Hunting Graph |
| dagre / elkjs | MIT / EPL-2.0 | ●● / ●●● | ●● | 레이아웃 | — | ●● | elkjs(계층 레이아웃) 채택, EPL 고지 |

### 5.1 SOC 특화 주의사항
- **ECharts tooltip/label formatter는 HTML을 렌더링한다** → 로그 유래 문자열은 반드시 escape 함수 경유 (XSS). 공통 `safeTooltip()` 유틸 강제, lint 규칙.
- Cytoscape는 Canvas 렌더 → 스크린리더 접근성 위해 **동일 데이터의 테이블/리스트 대체 뷰** 제공.
- Monaco는 약 수 MB 번들 → 해당 화면 진입 시 lazy load.
- Raw Log Viewer는 Monaco가 아니라 **자체 가상화 뷰어**(TanStack Virtual, 수백만 줄 스트리밍).

## 6. “재구현 금지” 체크리스트

| 하고 싶은 것 | 사용할 것 |
|---|---|
| 패킷 파싱 | Zeek / Suricata / tshark |
| IDS 시그니처 | Suricata + ET Open |
| 로그 템플릿 마이닝 | Drain3 (+ 결정적 사전 정규화) |
| SQLi/XSS 토큰 분석 | libinjection |
| Detection 표현/변환 | Sigma + pySigma |
| 이벤트 검색/집계 | OpenSearch |
| 벡터 검색 | pgvector |
| EVTX 분석 | Hayabusa / Chainsaw |
| Ad-hoc 데이터 변환 | CyberChef (정적) |

자체 구현 대상은 **SAW의 차별점**에 한정한다: Universal Detection, Request Diff, Findings/Detectors, Attack Story, Cross-highlighting Workbench, SOC Experience, Hybrid Similarity, Asset-aware Context.

## 7. ATT&CK 연계 도구 (2026-10-06 추가)

상세 평가와 시각화 설계는 [34-mitre-attack-integration-design](34-mitre-attack-integration-design.md) §2.

| 도구 | 라이선스 | 결정 |
|---|---|---|
| ATT&CK STIX Data + mitreattack-python | Apache-2.0 (데이터는 ATT&CK Terms of Use) | USE DIRECTLY |
| ATT&CK Navigator | Apache-2.0 | INTEGRATE (내부 호스팅, Layer Export) |
| Attack Flow v4 / Builder | Apache-2.0 (확인 필요) | INTEGRATE (Export/Import, 내부 호스팅) |
| Technique Inference Engine (TIE) | Apache-2.0 | REUSE COMPONENT (오프라인 추론) |
| TRAM | Apache-2.0 | REFERENCE |
| Decider (CISA) | 확인 필요 | REFERENCE |
| DeTT&CT | GPL-3.0 | REFERENCE |
| OpenCTI | Apache-2.0 (CE) | INTEGRATE API (옵션) |
| VECTR | 무료(비오픈소스) | REFERENCE / 결과 Import |
| D3FEND | 확인 필요 | REUSE COMPONENT (P2) |
| Atomic Red Team | MIT | REFERENCE |
