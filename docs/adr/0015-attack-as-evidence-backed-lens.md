# ADR-0015: ATT&CK은 근거 기반 “렌즈”로 통합한다

- 상태: Accepted (Phase 0 추가, 2026-10-06)
- 날짜: 2026-10-06

## Context
ATT&CK은 SOC의 공통 언어이고 Navigator·Attack Flow·TIE 등 시각화·추론 도구가 이미 있다. 반면 웹/API 공격 등은 ATT&CK에 깔끔히 대응되지 않는 경우가 많고, 억지 매핑은 잘못된 신뢰를 만든다 (요구사항: “ATT&CK 단계를 무조건 억지로 매핑하지 않는다”).

## Options
| 옵션 | 장점 | 단점 |
|---|---|---|
| A. Story를 ATT&CK 전술로 구성 | 표준화 | 억지 매핑, 웹 공격 표현력 부족 |
| B. ATT&CK 미사용 | 단순 | 표준 언어·커버리지 관리 상실 |
| **C. 관찰 기반 Story + ATT&CK Overlay(출처·신뢰도·조건)** | 정확성과 표준화 양립 | 매핑 관리 비용 |

## Decision
- 옵션 C. 모든 매핑은 `source / confidence / condition_met / rationale / attack_version` 보유.
- Observed와 Inferred(TIE)는 별도 레이어. AI 제안은 수락 전 후보.
- 자체 Compact Matrix·Overlay·Swimlane·Coverage Heatmap 구현, Navigator·Attack Flow Builder는 **내부 호스팅 + Export/Import 연동**.
- ATT&CK 데이터는 오프라인 STIX 번들 + mitreattack-python.

## Consequences
+ 분석 결과를 표준 언어로 공유·보고, 탐지 Gap 가시화, Hunting 가설 자동 제안
- Detector별 조건부 매핑표 유지·검토 필요, ATT&CK 버전 마이그레이션 절차 필요
상세: [34](../34-mitre-attack-integration-design.md)
