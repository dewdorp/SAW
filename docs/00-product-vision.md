# 00. Product Vision

## 1. 문제 정의

### 1.1 현재 분석 워크플로우

```
Alert 발생
  → SIEM 검색 (쿼리 작성, 결과 수천 행)
  → WAF 콘솔 접속 (별도 로그인, 별도 시간대 표기)
  → NDR 콘솔 접속
  → 외부 TI 사이트 수동 검색 (IP/Domain 하나씩)
  → 로그 다운로드 → Excel 피벗
  → CyberChef로 Payload Decode
  → 메신저로 선임에게 "이거 예전에 본 적 있나요?"
  → 분석가 판단 → 보고서 수기 작성
```

| Pain | 결과 |
|---|---|
| 도구 간 Context Switching (평균 5~8개 콘솔) | 분석 시간 증가, 시간대·필드명 불일치로 실수 |
| 대량 로그를 표로만 봄 | “무슨 일이 일어났는지” 파악까지 오래 걸림 |
| 과거 판단이 개인 기억·메신저·엑셀에 흩어짐 | 동일 오탐을 반복 분석, 담당자 이탈 시 지식 손실 |
| 외부 IOC 중심 판단 | 내부 맥락(자산·배치·정상 패턴) 누락 → 오탐/미탐 |
| 분석 결과가 탐지 룰로 이어지지 않음 | 같은 공격을 다음에도 사람이 찾아야 함 |
| PCAP는 Wireshark 전문가만 분석 | 네트워크 증거 활용도 낮음 |

### 1.2 왜 SIEM을 더 만들면 안 되는가

SIEM은 수집·보관·상시 룰 실행에 최적화되어 있다. 문제는 **수집 이후 “분석가가 이해하고 판단하는 단계”** 에 있다.
SAW가 SIEM 기능(상시 수집, 장기 보관, 실시간 상관룰)을 다시 만들면 비용은 두 배가 되고 분석 경험은 개선되지 않는다.

## 2. Vision

> **관제 데이터와 조직의 분석 경험을 지속적으로 축적·활용하여
> 이상징후 발굴 → 분석 → 상관분석 → Threat Hunting → Investigation → Detection Engineering → 탐지 룰 전환
> 까지 지원하는 On-Premise SOC Analyst & Threat Hunting Platform**

첫 번째 목표는 Autonomous AI SOC가 아니라 **SOC Analysis Workbench** 다.

## 3. 포지셔닝

```
                    ┌────────────────────────────────────────────┐
                    │ SAW — Analysis Intelligence Layer          │
                    │                                            │
                    │  Analyze · Correlate · Visualize           │
                    │  Knowledge · Similar Case · Hunt · Detect  │
                    └───────▲───────────────▲────────────────────┘
       read-only query      │               │  사용자 업로드 Evidence
                            │               │  (Log / PCAP / IOC / HTTP)
  ┌──────┬──────┬──────┬────┴─┬──────┬──────┴┬─────────┬──────────┐
  │ SIEM │ SOAR │ NDR  │ WAF  │ IPS  │ FW    │ EDR/ASM │ DB Audit │   ← 기존 유지
  └──────┴──────┴──────┴──────┴──────┴───────┴─────────┴──────────┘
```

| SAW가 하는 것 | SAW가 하지 않는 것 |
|---|---|
| 분석가가 넣은 Evidence의 분석·시각화 | 전사 로그 상시 수집 |
| Investigation 범위의 상관분석 | 실시간 상관룰 엔진 (SIEM 몫) |
| 기존 시스템 데이터의 **조회**(Connector) | 기존 시스템의 정책 변경·차단 |
| Finding / Attack Story / Timeline / Graph | 장기 로그 보관소 |
| 조직 경험 축적·유사사례 | 범용 BI Dashboard |
| Detection Candidate 생성·테스트·Export | 룰 자동 배포 |

## 4. Persona

| Persona | 주 업무 | SAW에서의 핵심 가치 |
|---|---|---|
| **L1 Analyst** | Alert Triage, 1차 판단 | 붙여넣기 한 번에 맥락 확인, 과거 판단 즉시 조회 |
| **L2/L3 Senior Analyst** | 심층 분석, 사고 조사 | 대량 로그·PCAP 시각적 이해, Attack Story, Drill-down |
| **Threat Hunter** | 가설 기반 탐색 | Pivot·Query History·Hypothesis 기록 |
| **Detection Engineer** | 룰 개발·튜닝 | 사건 → Sigma 후보 → 과거 데이터 테스트 |
| **Reviewer (Senior/Manager)** | 판단·지식 품질 관리 | Experience/Detection 승인 큐 |
| **SOC Manager** | 운영·보고 | Case 현황, 지식 축적률, 보고서 초안 |
| **Admin** | 계정·연동·정책 | RBAC, Connector, Audit |

## 5. Jobs To Be Done

1. *Alert을 받았을 때*, 이 IP/URL/요청이 **우리 환경에서** 어떤 의미인지 1분 안에 알고 싶다.
2. *수십 GB 로그를 받았을 때*, 한 줄씩 보지 않고 **이상한 패턴만** 먼저 보고 싶다.
3. *PCAP을 받았을 때*, Wireshark 없이 **누가 누구와 무엇을** 했는지 그림으로 보고 싶다.
4. *판단을 내릴 때*, 시스템이 **왜** 그렇게 보는지 근거를 확인하고 싶다.
5. *비슷한 사건을 봤을 때*, **우리가 예전에 어떻게 판단했는지** 알고 싶다.
6. *사건을 확인했을 때*, 다음에는 **자동으로 탐지**되도록 룰 후보를 만들고 싶다.

## 6. Product Principles

| ID | 원칙 | 설계에 미치는 영향 |
|---|---|---|
| P1 | **Not a SIEM** | 상시 수집 없음. Investigation 범위 Evidence + Connector 조회 |
| P2 | **Story First, Evidence Second, Raw on Demand** | 모든 분석 화면은 요약→흐름→Finding→Timeline→Relations→Raw 순 |
| P3 | **Evidence-backed Claims** | 모든 Finding/AI 출력은 근거(Evidence Ref) 필수. 단정 표현 금지(“Potential …”) |
| P4 | **Deterministic First** | Rule·통계·Baseline → (선택적) ML → LLM 설명. LLM 단독 판단 금지 |
| P5 | **Internal Context First** | IOC 화면 상단은 내부 Context, 외부 TI는 보조 |
| P6 | **Human-in-the-loop** | 차단/정책/룰 배포 기능 없음 또는 Export만. 승인 Workflow |
| P7 | **Untrusted Data** | 모든 입력은 파싱·렌더링·LLM 단계에서 격리·이스케이프 |
| P8 | **Reuse OSS** | 재구현 전에 [04](04-open-source-evaluation.md)의 결정을 따른다 |
| P9 | **Knowledge Compounds, Safely** | 승인된 경험만 Production Knowledge. 만료·재검토 주기 |
| P10 | **High Information Density** | 큰 카드 금지, IDE형 밀도, 키보드 중심 |
| P11 | **Auditability** | 누가 무엇을 보고, 무엇을 판단했는지 모두 기록 |

## 7. 진화 경로

```
Stage 1  SOC Analysis Workbench      붙여넣기/업로드 → 분석 → 시각화 → Case
Stage 2  SOC Experience Knowledge    판단 구조화 축적 (승인 기반)
Stage 3  Similar Case                Hybrid 유사도 검색, Same/Different 비교
Stage 4  Anomaly Detection           Baseline·Rarity·Sequence·Cross-log 후보 발굴
Stage 5  Local LLM Analyst           설명·요약·비교·보고서 초안 (근거 인용 강제)
Stage 6  Threat Hunting              가설 → 질의 → Pivot 루프 (Read-only)
Stage 7  Detection Engineering       사건 → Sigma 후보 → 과거 테스트 → 승인 → Export
```

각 Stage는 이전 Stage의 데이터를 **입력**으로 사용한다. (예: Similar Case는 Stage 2의 Experience가 없으면 가치가 낮다.)

## 8. 성공 지표 (운영 6개월 기준 목표, 베이스라인은 Phase 1 착수 시 측정)

| 지표 | 정의 | 목표 |
|---|---|---|
| Time-to-Understand | Evidence 투입 → 분석가가 Verdict 초안 작성까지 | 현행 대비 50% 단축 |
| Tool Switch | 1건 분석 시 사용하는 별도 콘솔 수 | ≤ 2 |
| Finding Precision | 분석가가 “유효”로 표시한 Finding 비율 | ≥ 60% (Detector별 추적) |
| Experience Reuse | Similar Case/Experience가 열람된 Investigation 비율 | ≥ 40% |
| Knowledge Growth | 월간 승인 Experience 수 | ≥ 20건 |
| Detection Conversion | Confirmed Attack 중 Detection Candidate 생성 비율 | ≥ 30% |
| Analyst Adoption | 주간 활성 분석가 / 전체 | ≥ 80% |

## 9. Non-Goals (V1)

- Autonomous Response, 자동 차단, 자동 룰 배포
- 범용 SIEM 기능 (상시 수집·실시간 상관·장기 보관)
- 자체 Packet Parser, 자체 IDS 엔진
- 외부 클라우드 LLM 사용 (On-Prem 전제)
- 멀티테넌트 SaaS (단, 금융그룹 계열사 구분용 `org_unit` 필드는 지원)
