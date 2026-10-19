# 최종 배포 ZIP 재검증 — 2026-10-20

**게시된 ZIP을 직접 풀어 업데이트와 전체 복구를 다시 실행했고, 개발기 합성 시험을 통과했습니다.** 실행 코드 추가 수정은 없으며 같은 설치 ZIP을 유지합니다. 이 결과를 대상 LTSC 운영 서버의 인수 완료로 해석하지 않습니다.

## 이번에 다시 실행한 것

| 확인 | 결과 |
|---|---|
| 배포 ZIP 직접 해제·자동 검증 | 677항목, payload 675파일 통과 |
| 기존 설치 시작 | 48.32초 |
| 설치 점검 | 38.21초, 9항목 통과 |
| 실제 업데이트 | 485.55초, PostgreSQL·OpenSearch·HTTPS 기동 |
| 전체 복구 | 488.11초, 복구 후 같은 계정·비밀번호·MFA 로그인 |
| 자료 보존 | 계정2·이벤트9·Finding10·증거2·노트1·완료작업2, schema0014 일치 |
| 설정·원본 보존 | 계정ID·암호hash·역할·MFA·설정·키·TLS·원본 일치 |
| 업데이트 이후 새 자료 | 복구 직전 설치에 별도 보관, 복구본에 자동 병합하지 않음 |
| 종료 | 28.77초, 3포트 닫힘·PG PID 부재 |
| 오류 회귀 | 14파일, 618통과·1건너뜀·실패0 |
| 독립 코드 감사 | A–E 및 적용·복구 흐름에서 새 Critical/Important 결함 없음 |

실제 WinForms 버튼 이벤트가 worker와 포함 런타임을 실행했습니다. 환경은 Windows11 build26200 / Windows PowerShell5.1 / NoAdmin입니다. 물리 마우스 더블클릭·관리자 서비스·새 빈 폴더 설치는 이번 시험에 포함하지 않았습니다. 전체 서버1,733통과·웹177통과·TypeScript 검사는 이전 실행 기록이며 이번에는 변경 없는 실행 코드의 관련 회귀와 최종 ZIP 흐름을 재검증했습니다. 건너뛴1건은 POSIX 권한 비트 시험이고 Windows ACL 시험은 실행했습니다. 기존 Starlette 변경 예고와 JUnit 보고 형식 경고2건이 남아 있습니다.

## 이전 오류의 현재 판단

| 오류 | 다시 확인한 보완 | 근거의 한계 |
|---|---|---|
| A. media_verification_failed | 소스 ZIP·누락·손상 구분, 실행 전 자동 매체 검증 | 실제 최종 ZIP 검증과 오류 회귀 |
| B. invalid_controller_result | 생성 순간 사용자 owner·보호 DACL, 상태 전달·원자 교체 | 실제 NoAdmin 흐름 및 native/합성 회귀. 관리자 토큰 현장 시험 별도 |
| C. unsafe_access | OWNER RIGHTS·서비스 범위 평가, 알려진 일시 오류만 전체 재검사 | 최종 ZIP 전수 검사 통과. 과거 조회4건의 직접 원인은 미확정 |
| D. baseline_required | 설치 manifest 우선, 구형 설치의 정확한 원래 매체 검증 | 이번 흐름은 설치 manifest 사용. 구형 매체 분기는 회귀 시험 |
| E. service_configuration_unverified | Procrun Registry32/64 독립 검사, 충돌·불완전 구성 거절 | 코드·회귀 검증. 실제 LTSC SCM 서비스 인수 별도 |

## 받아서 실행하는 순서

1. [GitHub 릴리스](https://github.com/dewdorp/SAW/releases/tag/v0.1.0-pilot.20261019)의 **SAW-0.1.0-pilot.20261019-model-free-win-x64.zip**을 받습니다. Source code ZIP은 설치 매체가 아닙니다.
2. 아직 없는 새 폴더, 예를 들어 **D:\SAW-update-20261019**에 풉니다. 기존 **C:\SAW**와 원래 매체 **D:\SAW-0.1.0**을 보존합니다.
3. **UPDATE-SAW.cmd**를 더블클릭합니다. 기존 설치 **C:\SAW**, 같은 드라이브의 새 복구 위치 **C:\SAW-r-20261019**를 선택합니다.
4. **설치 점검**을 누릅니다. 자동 검증이므로 수동 해시 비교는 필요 없습니다. 구형 설치가 원래 매체를 요구하면 실제 사용했던 전체 매체를 지정합니다.
5. 분석가 접속·진행 작업을 정리한 뒤 중지 동의에 체크하고 **업데이트 시작**을 누릅니다.
6. 완료 후 기존 계정·MFA로 로그인해 조사·증거·원문·노트를 확인합니다. 문제가 있으면 같은 창에서 검증된 복구본을 선택하고 **이전 상태로 복구**를 사용합니다.

복구는 백업 시점의 계정·자료·설정 전체를 되돌립니다. 그 이후 새 자료는 별도 보관하며 자동 병합하지 않습니다. ZIP·manifest·기존 릴리스는 교체하지 않았고 이번 재검증 문서만 추가합니다.

## 실제 화면

아래는 이번 최종 ZIP 시험의 원본 화면입니다. 화면의 F: 경로는 합성 시험용이며 위 C:/D: 예시와 구분합니다.

[최종 ZIP 설치 점검 — HTML에서 보기](https://github.com/dewdorp/SAW/releases/download/v0.1.0-pilot.20261019/UPDATER-RECHECK-20261020.html#native-inspect)

[최종 ZIP 업데이트 완료 — HTML에서 보기](https://github.com/dewdorp/SAW/releases/download/v0.1.0-pilot.20261019/UPDATER-RECHECK-20261020.html#native-apply)

[최종 ZIP 전체 복구 완료 — HTML에서 보기](https://github.com/dewdorp/SAW/releases/download/v0.1.0-pilot.20261019/UPDATER-RECHECK-20261020.html#native-restore)

## 아직 확인하지 못한 것

- 대상 Windows10 Enterprise LTSC2019 build17763의 관리자/UAC·LocalSystem/NetworkService·SCM·실제 Registry32 서비스·HTTPS443·재부팅 인수.
- 조직 TLS·코드서명/MOTW, 물리 폐쇄망, 저사양 공동 부하와 운영 배포 승인.
- 과거 후보6 권한 조회4건과 History503의 정확한 원인. 후속 통과로 해결 처리하지 않습니다.
- 이번 최종 ZIP으로 빈 폴더 최초 설치는 재실행하지 않았습니다.

설치 ZIP은 **1,445,832,542바이트**이며 모델 가중치는 제외됩니다. [기계 판독 검증 기록](https://github.com/dewdorp/SAW/releases/download/v0.1.0-pilot.20261019/updater-release-recheck-20261020.json) · [기존 상세 그림 안내](https://github.com/dewdorp/SAW/releases/download/v0.1.0-pilot.20261019/UPDATER-STABILIZATION-GUIDE-20261019.html) · [현장 점검 절차](https://github.com/dewdorp/SAW/releases/download/v0.1.0-pilot.20261019/updater-native-acceptance-20261019.md)
