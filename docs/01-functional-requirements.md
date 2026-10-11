# 01. Functional Requirements

우선순위: **P0** = V1 필수, **P1** = V1 권장, **P2** = V1 이후
Phase: [33-development-roadmap](33-development-roadmap.md) 기준

## FR-HOME — Home

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-HOME-01 | 로그인 후 첫 화면은 “무엇이든 붙여넣으세요” 입력창 중심 | P0 | 2 |
| FR-HOME-02 | Quick Upload (PCAP / Web Logs / WAF Logs / IOC List / Security Logs) | P0 | 5 |
| FR-HOME-03 | Recent Investigations / Active Jobs / Recent Findings 만 표시 (Dashboard 금지) | P0 | 4 |
| FR-HOME-04 | 붙여넣기 시 자동 타입 인식 미리보기 (입력 중 debounce) | P1 | 2 |

## FR-UNI — Universal Analyzer

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-UNI-01 | 입력 타입 자동 인식: HTTP Req/Resp, IPv4/6, Domain, URL, Hash, JSON, XML, JWT, Encoded String, Log Line, PowerShell EncodedCommand | P0 | 2 |
| FR-UNI-02 | 인식 결과를 입력 원문 위 Span Highlight로 표시 (어디서 무엇을 찾았는지) | P0 | 2 |
| FR-UNI-03 | 인식 타입별 추천 분석 (HTTP / IOC / Payload / Related Logs / Similar Case / Timeline) | P0 | 2 |
| FR-UNI-04 | Defang 표기 자동 Refang (`hxxp`, `[.]`, `(dot)`) | P0 | 2 |
| FR-UNI-05 | 입력 ≤ 5 MB는 동기 분석, 초과 시 Upload Flow로 전환 안내 | P0 | 2 |
| FR-UNI-06 | 분석 결과를 Investigation에 추가 | P0 | 4 |

## FR-IOC — IOC Analyzer

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-IOC-01 | IPv4/IPv6/Domain/URL/Hash(MD5/SHA1/SHA256/SHA512/ssdeep/TLSH) 지원 | P0 | 2 |
| FR-IOC-02 | 오프라인 Enrichment: ASN, ISP/Provider, Cloud/VPS 여부, Country (로컬 DB) | P0 | 2 |
| FR-IOC-03 | RDAP/WHOIS/DNS/rDNS — 정책상 허용 시 Egress Proxy 경유, 분석가 명시 실행(OPSEC) | P1 | 2 |
| FR-IOC-04 | 외부 TI 조회 (IntelOwl 연동 또는 내부 TI 피드) | P1 | 2 |
| FR-IOC-05 | **Internal SOC Context**: First/Last Seen, WAF/IPS/NDR/FW 이벤트 수, Related URI/Assets/Accounts/JA3/JA4, Related Cases, Previous Analyst Verdict | P0 | 2(로컬)/10(Connector) |
| FR-IOC-06 | 화면 순서: Internal Context → Previous Verdict → External TI | P0 | 2 |
| FR-IOC-07 | IOC List Bulk 분석 (CSV/TXT, ≤ 100k) 비동기 처리 | P1 | 5 |
| FR-IOC-08 | 분석 대상 URL을 **절대 직접 방문하지 않는다** (passive only) | P0 | 2 |

## FR-HTTP — HTTP Analyzer

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-HTTP-01 | Raw HTTP Request/Response 파싱 (HTTP/1.x, Burp/DevTools 복사본, HTTP/2 pseudo-header 허용) | P0 | 2 |
| FR-HTTP-02 | Method/Scheme/Host/URI/Path/Query/Headers/Cookies/Authorization/UA/Content-Type/Body/Status/Size 구조화 | P0 | 2 |
| FR-HTTP-03 | Parameter 추출: Query/Form/JSON/XML/Multipart/Cookie/Header (위치 정보 포함) | P0 | 2 |
| FR-HTTP-04 | Potential Pattern 탐지(SQLi/XSS/LFI/RFI/Traversal/CmdI/SSTI/SSRF/Deserialization/Credential Attack/API Enumeration) + Evidence Span | P0 | 2 |
| FR-HTTP-05 | 탐지 전 Canonicalization(다중 Decode) 수행, Decode Chain 표시 | P0 | 2 |
| FR-HTTP-06 | “공격” 단정 금지, “Potential … Pattern” + Evidence + Confidence | P0 | 2 |
| FR-HTTP-07 | Response 분석: Error Signature(SQL error, stack trace), 민감정보 패턴 개수(마스킹) | P1 | 2 |
| FR-HTTP-08 | JWT 디코드 (서명 검증 아님 명시, alg=none/약한 alg 경고) | P0 | 2 |

## FR-PAY — Payload Analyzer

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-PAY-01 | URL(재귀), Base64, Base64URL, Hex, Unicode Escape, HTML Entity, JWT, gzip, deflate, PowerShell EncodedCommand(UTF-16LE) | P0 | 2 |
| FR-PAY-02 | 자동 Decode Chain 탐색 (최대 깊이 8, 각 단계 신뢰도·근거) | P0 | 2 |
| FR-PAY-03 | Transformation Chain 시각화 (단계별 입력/출력/연산) | P0 | 2 |
| FR-PAY-04 | 수동 Chain 편집 및 CyberChef Recipe로 “Open in CyberChef” | P1 | 2 |
| FR-PAY-05 | Decode 결과에 IOC/Pattern 재분석 자동 적용 | P0 | 2 |

## FR-DIFF — Request Diff

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-DIFF-01 | 2~N개(≤ 200) Request(+Response) 입력, 구조적 Diff | P0 | 3 |
| FR-DIFF-02 | 비교 항목: Method/Path/URI/Param Name/Value/Location/Header/Cookie/Body/Status/Response Size | P0 | 3 |
| FR-DIFF-03 | Request Evolution Flow 시각화 + 변경점 색상·아이콘 강조 | P0 | 3 |
| FR-DIFF-04 | 실패→성공 전환점(“Bypass Point”) 자동 표시 | P0 | 3 |
| FR-DIFF-05 | Mutation 유형 자동 분류 (param rename, method switch, location move, encoding change, header injection 등) | P1 | 3 |
| FR-DIFF-06 | 로그 이벤트에서 Request 선택 → Diff로 보내기 | P1 | 5 |

## FR-LOG — Log Analysis (Single / Bulk)

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-LOG-01 | 단일 로그 붙여넣기(≤ 5 MB) 파싱·정규화·요약 | P0 | 3 |
| FR-LOG-02 | 다중 파일 Drag&Drop 업로드 (≥ 50 files, ≥ 20 GB per investigation) | P0 | 5 |
| FR-LOG-03 | 포맷: Apache/Nginx/IIS/JSON Lines/CSV/Syslog(3164/5424)/Cloudflare/Generic WAF/Key-Value | P0 | 5 |
| FR-LOG-04 | 압축: gz/zip/bz2/xz/tar(.gz), Safe Decompress | P0 | 5 |
| FR-LOG-05 | 파일·파서 자동 감지 + 분석가 Override + 샘플 미리보기 | P0 | 5 |
| FR-LOG-06 | Raw Event + Normalized Event 동시 보존, Unknown Field 보존 | P0 | 5 |
| FR-LOG-07 | Visual Summary (Files/Events/Range/Unique IP/URI/Findings + 9종 차트) | P0 | 5 |
| FR-LOG-08 | 모든 차트 클릭 → 전역 필터(Include/Exclude) | P0 | 5 |
| FR-LOG-09 | Pattern Clustering (결정적 정규화 + 템플릿 마이닝) | P0 | 5 |
| FR-LOG-10 | Parameter Analyzer (type, unique, sequential ratio, increment, entropy, length, range, prefix/suffix, payload family) | P0 | 5 |
| FR-LOG-11 | Custom Parser (Regex/Grok 정의, 테스트, 버전관리, RE2 엔진) | P1 | 5 |
| FR-LOG-12 | Windows EVTX (Hayabusa/Chainsaw 연동) | P2 | 7+ |

## FR-PCAP — PCAP Analysis

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-PCAP-01 | PCAP/PCAPNG, 다중 파일, 파일당 ≤ 20 GB | P0 | 6 |
| FR-PCAP-02 | Zeek + Suricata + tshark 처리 → OpenSearch | P0 | 6 |
| FR-PCAP-03 | Overview: Duration/Packets/Connections/Hosts/Domains, Protocol 분포, Top Talkers/Destinations/Domains | P0 | 6 |
| FR-PCAP-04 | Visual Network Story (호스트 중심 통신 그래프 + 요약 라벨) | P0 | 6 |
| FR-PCAP-05 | Tabs: Overview/Findings/Connections/DNS/HTTP/TLS/Files/Alerts/Timeline/Relations/Raw Sessions | P0 | 6 |
| FR-PCAP-06 | Network Findings (periodic, long-lived, volume, rare, scan, DNS anomaly, TLS rarity, unexpected protocol) | P0 | 6 |
| FR-PCAP-07 | Raw Session Deep-dive: tshark 기반 세션 추출 다운로드, 선택적으로 Arkime 링크 | P1 | 6 |
| FR-PCAP-08 | 추출 파일은 Quarantine 저장, 해시만 노출, 다운로드는 암호 ZIP + 감사 | P1 | 6 |

## FR-INV — Investigation / Workbench

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-INV-01 | Investigation 생성, 다중 Evidence 연결 (PCAP + Web + WAF + DB Audit …) | P0 | 4/7 |
| FR-INV-02 | Workbench 3-pane(Evidence / Analysis / Context) + Center Tabs | P0 | 4 |
| FR-INV-03 | Attack Story 자동 생성 + 분석가 편집(이름변경/병합/삭제/고정) + 버전 | P0 | 4 |
| FR-INV-04 | Unified Timeline (cross-source, 반복 이벤트 접기, 간격 표시) | P0 | 4/7 |
| FR-INV-05 | Relation Graph (Grouping/Filtering/Collapse/Expand) | P0 | 4 |
| FR-INV-06 | Cross-highlighting: 모든 시각화가 하나의 Investigation Context 공유 | P0 | 4 |
| FR-INV-07 | Multi-Investigation Tabs (브라우저 내 동시 열기) | P1 | 4 |
| FR-INV-08 | Notes (Markdown, 이벤트/Finding/Entity 링크) | P0 | 4 |
| FR-INV-09 | Drill-down: Finding → Evidence → Timeline → Relations → Raw | P0 | 4 |
| FR-INV-10 | Cross-source Correlation (entity + time window) | P0 | 7 |

## FR-FIND — Findings

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-FIND-01 | Finding = Title(Potential …) + Risk + Confidence + WHY(metrics) + Baseline vs Observed + Evidence Checks + Evidence Refs | P0 | 4 |
| FR-FIND-02 | Actions: Related Events/Attack Flow/Timeline/Request Compare/Relations/Similar Cases/Hunting/Add to Case/Create Detection Candidate | P0 | 4 |
| FR-FIND-03 | 분석가 피드백 (Valid / Benign / False Positive / Duplicate) → Detector 정밀도 추적 | P0 | 4 |
| FR-FIND-04 | Detector 버전 기록, 동일 입력 재실행 시 동일 결과(결정성) | P0 | 4 |
| FR-FIND-05 | False Positive Knowledge 매칭 시 자동 표시 (억제 아님, 표시) | P1 | 8 |

## FR-KNOW — Knowledge

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-KNOW-01 | SOC Experience CRUD + 상태(draft/review/approved/deprecated) | P0 | 8 |
| FR-KNOW-02 | Investigation 종료 시 Verdict 입력 → Experience Draft 자동 생성 | P0 | 8 |
| FR-KNOW-03 | Reviewer ≠ Author 승인 후에만 Production Knowledge | P0 | 8 |
| FR-KNOW-04 | 우측 Context Panel “OUR SOC EXPERIENCE” 상시 표시 + Same/Different 비교 | P0 | 8/9 |
| FR-KNOW-05 | Asset Knowledge (CSV Import, CMDB 동기화는 P2) | P0 | 8 |
| FR-KNOW-06 | False Positive Knowledge (조건, 만료일, 근거) | P1 | 8 |
| FR-KNOW-07 | Playbook (단계별 체크리스트, Finding 유형과 연결) | P1 | 8 |
| FR-KNOW-08 | Revision History, 만료/재검토 알림 | P0 | 8 |

## FR-SIM — Similar Case

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-SIM-01 | Hybrid Search (Keyword + Structured Feature + Vector) | P0 | 9 |
| FR-SIM-02 | 점수 분해 표시 (각 요소 기여도) + Same/Different Feature | P0 | 9 |
| FR-SIM-03 | 대상: Case, Approved Experience, (옵션) Draft는 작성자 본인만 | P0 | 9 |

## FR-CASE — Case

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-CASE-01 | Case CRUD, 상태, 담당자, Severity | P0 | 4 |
| FR-CASE-02 | Finding/Event/Entity/Evidence/Note/Story 스냅샷 첨부 | P0 | 4 |
| FR-CASE-03 | Case History (모든 변경 이력) | P0 | 4 |
| FR-CASE-04 | 보고서 Export (Markdown/PDF/DOCX), 마스킹 정책 적용 | P1 | 8 |

## FR-ANOM / FR-LLM / FR-HUNT / FR-DET (V2)

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-ANOM-01 | Volume/Rare/Sequence/Entity/Relationship/Cross-log Anomaly 후보 | P2 | 12 |
| FR-ANOM-02 | Baseline vs Current, Sequence Rarity 시각화 | P2 | 12 |
| FR-LLM-01 | Provider 추상화 (Ollama / OpenAI-compatible Local / vLLM) | P2 | 11 |
| FR-LLM-02 | Contextual AI Actions 8종 + Ask SOC Assistant | P2 | 11 |
| FR-LLM-03 | 모든 AI 출력에 근거 인용·“AI 생성” 라벨, 인용 검증 | P2 | 11 |
| FR-HUNT-01 | Hypothesis → Query → Result → Pivot 루프, 이유 기록 | P2 | 13 |
| FR-HUNT-02 | Read-only Tool Allowlist | P2 | 13 |
| FR-DET-01 | Detection Candidate (Sigma/Suricata/Snort/Regex/Generic Query) | P2 | 14 |
| FR-DET-02 | Historical Testing (Hit/FP 추정) | P2 | 14 |
| FR-DET-03 | 상태 Workflow, 자동 배포 금지 (Export만) | P2 | 14 |

## FR-CONN — Connectors

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-CONN-01 | `SecurityDataConnector` 추상화 (search/get_event/get_events/aggregate/get_context/health_check) | P1 | 10 |
| FR-CONN-02 | MockLogpressoConnector (Fixture 기반) | P1 | 10 |
| FR-CONN-03 | 실제 Logpresso Connector는 공식 API 문서 확보 후 | P2 | 10+ |

## FR-JOB — Jobs

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-JOB-01 | 상태: QUEUED/UPLOADING/PARSING/INDEXING/ANALYZING/COMPLETED/FAILED/CANCELLED | P0 | 5 |
| FR-JOB-02 | 단계별 진행률, 처리 이벤트 수, 현재 파일, ETA, 실시간 갱신(SSE) | P0 | 5 |
| FR-JOB-03 | 취소, 실패 파일 재시도, 파싱 오류 샘플 표시 | P0 | 5 |
| FR-JOB-04 | 부분 결과 열람(Progressive Overview) | P1 | 5 |

## FR-ADM — Admin / Security

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-ADM-01 | Local 인증 + TOTP MFA, 세션 관리 | P0 | 1 |
| FR-ADM-02 | RBAC 5 Roles + Investigation 단위 ACL | P0 | 1 |
| FR-ADM-03 | Audit Log 조회·Export (변조 방지 해시체인) | P0 | 1 |
| FR-ADM-04 | 민감정보 마스킹 정책, Unmask(Break-glass) 권한·사유·감사 | P0 | 1/5 |
| FR-ADM-05 | LDAP/AD/OIDC | P2 | 10+ |

## 역할별 권한 개요

| 기능 | Admin | SOC Manager | Senior Analyst | Analyst | Viewer |
|---|---|---|---|---|---|
| 분석·업로드 | ○ | ○ | ○ | ○ | × |
| Investigation 생성 | ○ | ○ | ○ | ○ | × |
| Case 종결 | ○ | ○ | ○ | ○(본인) | × |
| Experience 작성 | ○ | ○ | ○ | ○ | × |
| Experience 승인 | × | ○ | ○ | × | × |
| Detection 승인 | × | ○ | ○ | × | × |
| Unmask(Break-glass) | × | ○ | ○(사유) | × | × |
| 사용자·Connector 관리 | ○ | × | × | × | × |
| Audit 조회 | ○ | ○ | × | × | × |

> Admin은 운영 관리자이며 분석 데이터·지식 승인 권한을 기본으로 갖지 않는다 (직무 분리).

## FR-ATT — MITRE ATT&CK (2026-10-06 추가)

| ID | 요구사항 | Pri | Phase |
|---|---|---|---|
| FR-ATT-01 | ATT&CK STIX 오프라인 적재·버전 관리 (v18 Detection Strategy/Analytic/Data Component 포함) | P0 | 4 |
| FR-ATT-02 | 모든 매핑에 source/confidence/condition/rationale/version 기록, candidate·unmapped 상태 지원 | P0 | 4 |
| FR-ATT-03 | Investigation Compact Matrix + Story Overlay 배지 | P0 | 4 |
| FR-ATT-04 | Suricata/Sigma 룰 메타데이터 기반 자동 매핑 | P1 | 6 |
| FR-ATT-05 | Technique Swimlane Timeline | P1 | 7 |
| FR-ATT-06 | Navigator Layer Export / Attack Flow Export·Import (내부 호스팅) | P1 | 14 |
| FR-ATT-07 | TIE 추천 → Hunting 가설, 필요 Data Component 표시 (Inferred 레이어 분리) | P2 | 13 |
| FR-ATT-08 | Detection Coverage Heatmap (가시성·탐지·검증·관찰 위협, Gap 목록) | P2 | 14 |
| FR-ATT-09 | Org Threat Heatmap, 그룹 TTP 중첩도(귀속 아님 표기) | P2 | 9 |
