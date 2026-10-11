# 34. MITRE ATT&CK Integration & Visualization Design

> 2026-10-06 추가. ATT&CK을 활용해 분석 결과를 **표준 언어로 시각화**하고, 조직의 **탐지 커버리지·Hunting 가설**까지 연결한다.
> 관련: [21 Attack Story](21-attack-story-design.md), [24 Finding](24-finding-design.md), [26 Similar Case](26-similar-case-design.md), [30 Hunting](30-threat-hunting-design.md), [31 Detection](31-detection-engineering-design.md), [ADR-0015](adr/0015-attack-as-evidence-backed-lens.md)

## 1. 원칙 — ATT&CK은 “근거 있는 렌즈”

기존 원칙 *“ATT&CK 단계를 무조건 억지로 매핑하지 않는다”* 는 유지한다.

| 원칙 | 내용 |
|---|---|
| A1. Story가 1차, ATT&CK은 2차 렌즈 | Attack Story는 관찰 기반 Stage로 그린다. ATT&CK은 같은 그림 위에 **겹쳐 보는 보기(Overlay)** 다 |
| A2. 모든 매핑은 출처·신뢰도·근거 필수 | `source`(rule_metadata / detector_map / analyst / ai_suggested / inferred), `confidence`, `rationale`, `evidence_ref` |
| A3. 관찰(Observed)과 추론(Inferred) 분리 | TIE 등으로 추론한 기법은 점선·“Inferred” 라벨, 관찰 매트릭스와 다른 레이어 |
| A4. “매핑 없음”도 정상 상태 | 깔끔한 Technique이 없으면 `unmapped`로 두고 “가장 가까운 후보(low)”만 제안 |
| A5. AI 제안은 승인 전까지 후보 | LLM/TRAM식 자동 매핑은 분석가가 수락해야 Investigation에 반영 |
| A6. 버전 고정 | ATT&CK 버전(v18.x 등)을 매핑 레코드에 저장. 버전업 시 deprecated/revoked 기법 마이그레이션 리포트 |
| A7. 귀속(Attribution) 신중 | 위협그룹 중첩은 “TTP 중첩도”로만 표기, “○○ 그룹 소행” 표현 금지 |

## 2. 조사한 유사 컨셉 도구 (ATT&CK 활용 + 시각화)

| 도구 | 제공 주체 / 라이선스 | 무엇을 보여주나 | SAW 결정 |
|---|---|---|---|
| **ATT&CK STIX Data + mitreattack-python** | MITRE / Apache-2.0 (데이터는 ATT&CK Terms of Use, 출처 표기) | 기법·전술·그룹·소프트웨어·완화책, v18의 **Detection Strategies / Analytics / Data Components** | **USE DIRECTLY** — 오프라인 번들로 적재 |
| **ATT&CK Navigator** | MITRE / Apache-2.0 | 매트릭스 Heatmap, Layer(JSON) 비교·병합 | **INTEGRATE** — 내부 정적 호스팅, SAW가 Layer JSON Export → “Open in Navigator”. 주 UI는 SAW 자체 매트릭스 |
| **Attack Flow v4 + Builder** | MITRE CTID / Apache-2.0 (확인 필요) | 공격 흐름(행동·조건·분기) 다이어그램, 트리맵·전술표·타임라인·매트릭스 보기, Mitigation·Detection Strategy 부착, TIE 내장, ATLAS·D3FEND 지원, 로컬 호스팅 API | **INTEGRATE** — Story → Attack Flow Export/Import, 내부 호스팅 Builder로 보고서용 편집. 외부 AI 생성 기능은 비활성 |
| **Technique Inference Engine (TIE)** | MITRE CTID / Apache-2.0 | 관찰된 기법 → 함께 나타날 가능성 높은 기법 추천 | **REUSE COMPONENT** — worker-ai에서 오프라인 실행, “다음에 찾아볼 기법” Hunting 가설 |
| **TRAM** | MITRE CTID / Apache-2.0 | CTI 보고서 문장 → ATT&CK 기법 자동 분류 | **REFERENCE** — Phase 11 AI 매핑 제안 설계 참고 |
| **Decider** | CISA / 오픈소스(라이선스 확인) | 질문 기반으로 분석가가 올바른 기법을 고르게 돕는 UI | **REFERENCE** — SAW “Mapping Assistant” 질문 트리 UX 참고 |
| **DeTT&CT** | Rabobank CDC / GPL-3.0 | 데이터소스 품질·가시성·탐지 커버리지 점수, Navigator Heatmap | **REFERENCE** — Coverage 모델(가시성 vs 탐지) 개념 차용, 코드 미사용 |
| **OpenCTI** | Filigran / Apache-2.0 (CE) | CTI 그래프, ATT&CK 매트릭스, Navigator Export | **INTEGRATE API (옵션)** — 기관이 CTI 플랫폼을 운영 중이면 위협그룹·캠페인 TTP 조회 |
| **VECTR** | SRA / 무료(오픈소스 아님) | 퍼플팀 테스트 결과 ATT&CK Heatmap | **REFERENCE** — 사용 중이면 결과 CSV Import → Coverage의 “검증됨” 상태 |
| **D3FEND** | MITRE (라이선스 확인) | 공격 기법 ↔ 방어 대책 매핑 | **REUSE COMPONENT (P2)** — Case 보고서의 대응 권고 근거 |
| **Atomic Red Team** | Red Canary / MIT | 기법별 재현 테스트 카탈로그 | **REFERENCE** — Detection 검증 아이디어 링크 (SAW는 실행하지 않음) |
| Sigma / Suricata ET / Hayabusa 메타데이터 | 각 라이선스 | 룰에 붙은 `attack.tXXXX` 태그, `mitre_technique_id` 메타데이터 | **USE DIRECTLY** — 매핑 1차 원천 (`rule_metadata`) |

> 라이선스는 도입 시점에 각 저장소 LICENSE로 재확인 ([04 §2](04-open-source-evaluation.md) 정책 적용).

## 3. 매핑 엔진 (Mapping Engine)

### 3.1 매핑 원천 (우선순위)
| source | 예 | 기본 confidence |
|---|---|---|
| `rule_metadata` | Suricata ET 룰 metadata `mitre_technique_id`, Sigma `tags: attack.t1110.004`, Hayabusa 출력 | 룰 품질에 따름 (medium) |
| `detector_map` | SAW Detector의 **조건부** 정적 매핑표 (아래) | 조건 충족 시 medium/high |
| `analyst` | 분석가 수동 매핑 (Mapping Assistant 사용 가능) | 분석가 지정 |
| `ai_suggested` | LLM/TRAM식 제안 (Phase 11) | 후보 — 수락 전 미반영 |
| `inferred` | TIE 추천 | 관찰 아님 — 별도 레이어 |

### 3.2 Detector 조건부 매핑표 (예시)
매핑은 **조건(Condition)** 이 충족될 때만 붙는다. 조건 미충족 시 `candidate`로 낮춰 표시.

| Detector | Technique | 조건 | confidence |
|---|---|---|---|
| web.sensitive_file_probe | T1595.003 Active Scanning: Wordlist Scanning | 외부 src, 다수 경로 사전 매칭 | high |
| web.discovery | T1595.003 | 404 burst + 경로 다양성 | medium |
| web.credential_attack (stuffing) | T1110.004 Credential Stuffing | 계정 다양성 높음, 계정당 시도 적음 | high |
| web.credential_attack (brute) | T1110.001 Password Guessing | 단일 계정 반복 | high |
| web.injection_like | T1190 Exploit Public-Facing Application | **성공 신호**(2xx 이상 응답, 에러 시그니처, 크기 급변) 있을 때만 | medium |
| web.injection_like (차단만) | T1190 | 성공 신호 없음 | candidate(low) |
| web.request_mutation_success | T1190 | 403→변형→200 | medium |
| web.api_enumeration | *(깔끔한 매핑 없음)* → 후보 T1213 Data from Information Repositories | 대량 2xx 객체 조회 | candidate(low), `unmapped_reason` 표시 |
| auth.valid_account_anomaly | T1078 Valid Accounts | 정상 자격으로 비정상 행위 | medium |
| net.port_scan (내부 src) | T1046 Network Service Discovery | 내부→내부 | high |
| net.port_scan (외부 src) | T1595.001 Scanning IP Blocks | 외부→내부 | medium |
| net.periodic_comm | T1071.001 Application Layer Protocol: Web Protocols | 주기성 + 외부 HTTP(S) | candidate(low) — C2 확정 아님 |
| net.dns_anomaly (tunneling 지표) | T1071.004 DNS / T1572 Protocol Tunneling | 높은 엔트로피 + 고유 서브도메인 다수 | low~medium |
| net.large_outbound | T1041 Exfiltration Over C2 Channel / T1048 | 대량 송신 + 다른 의심 신호 동반 시 | candidate(low) |

매핑표는 `detectors/<id>/attack_map.yaml`로 Detector와 함께 버전 관리하고, **Senior 검토 후 변경**한다.

### 3.3 집계 단위
`Event tag → Finding → Story Node → Investigation → Case → Organization` 순으로 상향 집계. 상위 레벨은 하위의 **최고 confidence + 근거 수**를 보존.

## 4. 시각화 (6종)

### V1. Investigation ATT&CK Matrix (Workbench 탭 “ATT&CK”)
- 전술 = 열, 기법 = 셀. 기본은 **Compact 모드**: 관찰된 전술/기법만 표시 (빈 매트릭스 수백 칸 금지).
- 셀 표현: 색 = 최고 confidence, 숫자 = 근거 Finding 수, 테두리 실선=Observed / 점선=Inferred, 아이콘 = 매핑 출처(⚙룰 ◆Detector 👤분석가 ✦AI).
- 셀 클릭 → 근거 Finding/이벤트 필터 (Cross-highlight: Story 노드·Timeline 구간 강조).
- 토글: [Full matrix] [Show inferred (TIE)] [Show mitigations] / [Export Navigator layer] [Open in Navigator].
- 구현: 자체 React 그리드(가상화) — Navigator 임베드 대신 SAW Context와 연동하기 위해.

### V2. Attack Story ATT&CK Overlay
- 기존 Story 노드에 기법 배지 `T1110.004` 추가, 상단 토글 `[Observed stages | ATT&CK lens]`.
- ATT&CK lens에서는 노드를 전술 레인(Swimlane)으로 재배치한 보기 제공 — 같은 노드·같은 근거.
- 매핑 없는 노드는 회색 “unmapped” 배지 (억지 매핑 금지의 시각적 표현).
- **Export → Attack Flow**(STIX 2.1 Attack Flow 확장/`.afb`) → 내부 Builder에서 보고서용 편집·발표. 공개된 Attack Flow 사례(CTI 보고서 기반)를 Import 하여 **“알려진 캠페인 흐름 vs 우리 관찰”** 나란히 비교.

### V3. Technique Timeline (전술 Swimlane)
```
           02:58      03:01        03:11            03:14      03:15
Reconnaissance  ●T1595.003
Initial Access            ◆T1190 (403→200)
Collection                            ◇T1213 candidate
Exfiltration                                               ◇T1041 candidate
```
- 레인 = 전술, 점 = 기법 관찰(채움=관찰, 빈 점=후보). Unified Timeline과 시간축 동기화.

### V4. Next Likely Techniques (TIE) 패널 — Hunting 연결
```
INFERRED (TIE · not observed)        based on: T1595.003, T1190, T1078
 1. T1505.003 Web Shell              0.41   [가설로 Hunting 시작]
 2. T1083 File and Directory Discovery 0.33  필요한 데이터: Process/File (EDR) — 현재 Evidence 없음 ⚠
 3. T1059.004 Unix Shell             0.29
```
- 각 추천에 **확인에 필요한 Data Component**(ATT&CK v18) 와 **현재 보유 여부**를 표시 → “무엇을 더 수집/조회해야 하는가”로 연결.
- [가설로 Hunting 시작] → Hunt Session 생성 (Hypothesis 자동 문구, 분석가 수정).

### V5. Detection Coverage Heatmap (Knowledge › Detection)
DeTT&CT 개념(가시성 vs 탐지)을 SAW 데이터로 재구성.

| 차원 | 출처 |
|---|---|
| Visibility | 보유 로그 소스 ↔ ATT&CK v18 Data Components (Admin이 소스 등록: web, waf, zeek, edr…) |
| Detection | SAW Detection(approved/deployed) + Sigma 태그 + (옵션) SIEM 룰 목록 Import |
| Validation | Detection TestRun 통과, VECTR 결과 Import(옵션) |
| Observed Threat | 최근 12개월 Confirmed Case에서 관찰된 기법 빈도 |

셀 상태 예: `관찰됨 + 탐지 없음` = **최우선 Gap**(빨강 테두리), `탐지 있음 + 미검증` = 주황, `가시성 없음` = 해칭.
→ [Create Detection Candidate] / [Export Navigator layer] / [Gap 보고서].

### V6. Organization Threat Heatmap & Group Overlap (Knowledge)
- 전체 Case의 관찰 기법 Heatmap(기간 비교: 분기별) + 증감 화살표.
- (옵션) ATT&CK Groups / OpenCTI 침입세트와 **TTP 중첩도**(Jaccard) — “중첩 34% (공통 6/17)”로만 표기, 귀속 아님 경고 고정.

## 5. 기존 기능과의 연결

| 기능 | 변경 |
|---|---|
| Finding ([24](24-finding-design.md)) | `attack[]` 필드: `{technique_id, name, tactic, source, confidence, condition_met, rationale, attack_version}` |
| Attack Story ([21](21-attack-story-design.md)) | 노드 기법 배지, ATT&CK lens, Attack Flow Export/Import |
| Similar Case ([26](26-similar-case-design.md)) | FeatureSet에 `attack_techniques`(관찰만) 추가, 가중 Jaccard |
| SOC Experience ([25](25-soc-experience-design.md)) | 경험에 기법 매핑(검토 대상), Experience 검색 필터 |
| Hunting ([30](30-threat-hunting-design.md)) | TIE 추천 → 가설, Data Component 기반 “필요 데이터” 안내 |
| Detection ([31](31-detection-engineering-design.md)) | Sigma 태그 자동, Coverage Heatmap, Navigator Layer Export |
| Case 보고서 ([32](32-case-investigation-design.md)) | ATT&CK 요약표 + (P2) D3FEND 대응 권고 |
| LLM ([29](29-local-llm-design.md)) | “ATT&CK 매핑 제안” Action — 근거 문장 인용 필수, 후보로만 |

## 6. 데이터 모델 추가

```sql
attack.version(id, domain /*enterprise|ics|mobile|atlas*/, version, bundle_sha256, loaded_at)
attack.object(stix_id, version_id, type /*technique|tactic|group|software|mitigation|
              detection_strategy|analytic|data_component*/, external_id /*T1110.004*/,
              name, tactics[], platforms[], revoked bool, deprecated bool, raw jsonb)
attack.relationship(src_stix_id, rel_type, dst_stix_id, version_id)
attack.mapping(id, target_type /*finding|story_node|detection|experience|case|event_tag*/,
               target_id, technique_id, tactic_id, source, confidence, condition_met bool,
               rationale, evidence_ref jsonb, attack_version, status /*active|candidate|rejected*/,
               mapped_by, reviewed_by, created_at)
attack.coverage_snapshot(id, at, technique_id, visibility_score, detection_count,
                         validated bool, observed_12m int, gap_level)
```
- ATT&CK STIX 번들은 **오프라인 번들**로 반입(망분리), `mitreattack-python`으로 파싱·적재.
- 버전 업데이트 Job: revoked/deprecated 기법을 참조하는 mapping 목록 리포트 → 일괄 갱신은 Senior 승인.

## 7. API 추가

```
GET  /attack/versions | GET /attack/techniques?q=&tactic=
GET  /investigations/{id}/attack/matrix?mode=compact|full&include_inferred=false
GET  /investigations/{id}/attack/timeline
GET  /investigations/{id}/attack/inferred          → TIE 추천 + 필요 Data Component
POST /mappings  {target_type, target_id, technique_id, rationale}   (analyst)
POST /mappings/{id}/accept | /reject                 (ai_suggested → active)
GET  /investigations/{id}/attack/navigator-layer     → Navigator Layer JSON
GET  /investigations/{id}/story/attack-flow          → Attack Flow(STIX) Export
POST /attack-flows/import                            → 참조 흐름 Import (비교용)
GET  /coverage/attack?period=12m                    → Coverage Heatmap
```

## 8. 단계별 도입

| Phase | 범위 |
|---|---|
| 4 | ATT&CK 오프라인 적재, Detector 조건부 매핑, Finding 배지, **V1 Compact Matrix**, V2 Overlay(배지) |
| 6 | Suricata/Sigma 룰 메타데이터 매핑, 네트워크 Detector 매핑 |
| 7 | **V3 Technique Timeline** (Cross-source) |
| 8–9 | Experience/Similar에 기법 Feature, **V6 Org Heatmap** |
| 11 | AI 매핑 제안(후보), Mapping Assistant(Decider식 질문 트리) |
| 13 | **V4 TIE 추천 → Hunting 가설** |
| 14 | **V5 Coverage Heatmap**, Navigator Layer Export, Attack Flow Export/Import, (P2) D3FEND |

## 9. 리스크

| 리스크 | 대응 |
|---|---|
| 억지 매핑으로 잘못된 신뢰 | 조건부 매핑, candidate/unmapped 상태, 출처 아이콘 |
| TIE 추천을 사실로 오인 | 별도 레이어·점선·“Inferred” 고정 라벨, 기본 숨김 |
| ATT&CK 버전 변경(v18 구조 변화 등) | 버전 고정·마이그레이션 리포트 |
| Navigator/Attack Flow 외부 호스팅 사용 시 정보 유출 | **내부 호스팅만** 링크, 외부 URL 금지, Builder의 외부 AI 기능 비활성 |
| 그룹 귀속 오해 | 중첩도 표현만, 경고 문구 |
