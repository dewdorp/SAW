# SAW 현재 상태 — 2026-10-20

## 현재 상태: 업데이트 안정화 시험 배포 게시 완료 · 운영 인수 별도

- [새 모델 제외 전체 매체](https://github.com/dewdorp/SAW/releases/tag/v0.1.0-pilot.20261019)와 [통합 PR #3](https://github.com/dewdorp/SAW/pull/3)을 제출했다. main에 병합하지 않았고 기존4개 릴리스·원본 F:/claude/saw·운영 C:/SAW·D:/SAW-0.1.0은 보존했다.
- ZIP: SAW-0.1.0-pilot.20261019-model-free-win-x64.zip, 1,445,832,542바이트, SHA256 b9d7e0e7d9b3658c17690dcd276b072c03bb3330518431e1eba4e04d56b30cb5. 로컬 .release/에 보관했다. 677항목 전부 크기·hash 검증, 게시9자산 원격 크기·digest와 tag/source 대조 PASS.
- 매체 소스26f5d1a448668c127383c2e73d47d60d00ed2a28. 실제 시험한 후보7과 실행코드·런타임·의존성 및 라이선스/SBOM(발행 필드 제외)의 동일성을 확인했다. 최종 ZIP 자체로 업데이트·복구를 재실행한 것은 아니다. 이후 커밋은 게시 기록·링크만 정리한다.
- 최종 서버1,733통과·6건너뜀·2경고(1,305.21초), 웹177통과·TypeScript 성공. 실제 Windows11/PS5.1/NoAdmin 합성 업데이트492.39초·복구497.54초, 계정·암호·MFA·DB/색인·증거·노트·설정·키·TLS·원본 대조 PASS. 새50바이트객체 별도 보관·계정 정리·정상 종료28.56초 PASS.
- HTML에 원본 화면10개를 모두 내장했고 브라우저에서10개 로딩과 단계 이동·최신 실제 복구 화면을 확인했다. [그림 안내](docs/UPDATER-STABILIZATION-GUIDE-20261019.html), 로컬 열람 http://127.0.0.1:58369/UPDATER-STABILIZATION-GUIDE-20261019.html#prepare (docs 서버92434 유지).
- 사용: 새 ZIP을 D:/SAW-update-20261019에 해제 → UPDATE-SAW.cmd → 기존 C:/SAW·새 C:/SAW-r-20261019 선택 → 설치 점검 → 동의 후 업데이트. 수동 hash 대조는 없고 자동 전체 검증을 유지한다. 전체 복구는 백업 시점으로 돌아가며 이후 자료를 별도 보관하고 자동 병합하지 않는다.
- [매체 봉인](docs/verification/updater-release-20261019.json) · [게시 대조](docs/verification/github-updater-stabilization-20261019.json) · [전체 시험/실행 이력](docs/verification/updater-stabilization-20261019.json) · [24단계 감사](docs/verification/updater-flow-audit-20261019.md).
- 남은 인수: 깨끗한 Windows10 Enterprise LTSC2019 x64 build17763, 실제 관리자/UAC/SCM·LocalSystem/NetworkService·HTTPS443·재부팅·조직TLS/서명·물리폐쇄망·공동부하·운영승인. [현장 읽기 전용 점검](docs/verification/updater-native-acceptance-20261019.md)을 포함했다. 운영 설치는 변경하지 않았고 제품 전체 완료/운영 인수 승인으로 보지 않는다.
- 후보6의 권한 metadata 조회4건은 직접 Win32 원인 미확정이다. 이후 전체 재검사/후보7 통과로 최초 원인이 해결됐다고 기록하지 않는다. 모든 실패·수정·재검증 이력을 보존했다.

이하 기록은 각 시점의 경과 이력이다. 과거 승인 대기·실행 중 문구보다 위 최신 게시·검증 상태를 우선한다.

## 2026-10-19 업데이트 안정화 — 최종 리뷰 수정 중

현재 우선 작업은 전체 업데이트·복구 안정화이다. 원본 F:/claude/saw, 운영 C:/SAW, 게시된 이전 매체는 보존한다. 브랜치는 codex/updater-stabilization-20261019, 기준 커밋은 723e2a677dfc19e2079acbc0c6b604518a8c76aa. 새 최종 ZIP·PR·통합 커밋은 아직 없다.

- PR #1/#2 검토·통합 후 상태 소유권, OWNER RIGHTS, Procrun 양쪽 뷰, 9항목 진단, 적용 전 재검사, 중단 복구 journal·재시도·새 자료 보관을 보완했다.
- 사용자 승인 범위는 시험 프로세스의 RemoteSigned이다. 전역 정책·조직 정책·매체/권한/서비스 검사는 유지한다.
- 후보5: .release/updater-stabilization-20261019-candidate5, 675파일/1,494,496,954바이트, manifest e80fc67cdeb0d210714cda0da6c286f324b99c8d40904a3f2e33683c997d7688.
- 후보5 실제 Win11 build26200/PS5.1/NoAdmin 합성 설치에서 inspect63.02초/apply678.47초/restore613.99초 PASS. WinForms PerformClick→worker→실제 PG/OpenSearch/HTTPS. 물리 더블클릭·LTSC·관리자 SCM 서비스 인수는 아니다.
- 점검·적용·복구 후 계정2/이벤트9/Finding10/증거2/노트1/완료작업2/schema0014와 계정ID·비밀번호hash·역할·MFA·설정·키·TLS·원본 보존 대조 PASS. 같은 합성 계정·MFA HTTPS 로그인 PASS.
- .qa/us19-r1 전체 복구본27861파일/1,581,686,779바이트. 업데이트 후 새 합성 객체50바이트가 복구 전 설치 보관본에 남고 복구된 설치에서 빠짐을 확인했다. cleanup 및 정상중지37.31초,3시험포트닫힘/PID파일부재 PASS.
- 실제 합성 설치 .qa/packaging/installed-new2-20261017는 현재 정지 상태. HTTPS58449/PG55439/OS59209. 후보5 공개 영수증 .qa/packaging/updater-stabilization-20261019.
- 첫 전체서버:1589통과/6건너뜀/2실패/기존경고1,3258.21초. 실패는 새 START-HERE UTF8/계약 시험과 매체에 미포함된 테스트소스 문서링크. 두문제수정 후 관련67통과. 웹177통과31파일/TypeScript exit0.
- 추가81회귀 최초79통과/1건너뜀/1실패. fixture58101–58104열림을 감지해교체전중단; 다른동시시험과포트겹침추정이나당시PID미포착. 단독1통과40.08초, 전체suite종료후완전분리재시험1통과32.55초. 실패이력유지.
- 최종독립리뷰 Important3건 추가: (1) start에불필요한전체복구공간요구 (2) apply목적지root생성및renameDELETE권한사전점검누락 (3) onsite도구가build17763만으로Server2019도LTSC로분류. 모두수정·회귀진행중; 후보5를최종코드검증으로대체하지않는다.
- (3)은 ProductType1/SKU125126/10.0.17763/PS5.1/64bitOS+process로수정했고nativePS분류14경계사례포함4시험통과. (1)(2)는담당에이전트수정중.
- 최종리뷰3건 수정완료, 재검토에서 추가Critical/Important없음. mock단계회귀32/native변경권한11/OS판별4 통과, Ruff통과.
- 후보6 생성완료: .release/updater-stabilization-20261019-candidate6,675파일/1,494,682,543바이트,manifest60c8e0811a30c5d44d7d5f23dfc4c8f13ecfc02b3d5fcdaf12cc3dda4d626afc. 이후생산코드편집중단.
- 후보6동결코드 전체서버재시험 세션5121 exit0:1647통과/6건너뜀/2경고,1376.79초(22:56). 로그.qa/updater-stabilization-20261019/server-final-r2.log 및 JUnit server-final-r2.xml. 경고는기존Starlettehttpx지원예정변경 및record_property/xunit2보고형식. 후속ACL요약UI보완이전코드의결과이다.
- 후보6 native전체흐름 세션29581, 진행로그.qa/updater-stabilization-20261019/native-r2-sequence.log. run-final-updater-native-20261019.py가각성공후에만다음단계실행. 후보6start52.72초 PASS, inspect 및전후자료대조 PASS,apply508.17초 PASS 및계정/자료대조·동일계정MFA로그인 PASS. 이어진restore40.52초 unsafe_access로validate단계에서실패하여sequence exit1. 서버중지/복구전차단,backup verified true,can_retry true. 중복실행하지말것.
- 후보6복구위치.qa/us19-r2, 공개영수증.qa/packaging/updater-stabilization-20261019-r2, 새private합성비교범위사용. 이전영수증/매체보존.
- 자동승인검토가 private inspection-details 직접읽기와오류종류·건수추출도거부했다. 사용자에게합성시험오류종류·건수만읽기승인요청(call pending); 응답전접근금지. 공개receipt만사용. 실제시험설치는현재업데이트후실행중이며복구미실행. 기존후보5성공으로덮지않음.
- 봉인스크립트는SBOM serial/timestamp와NOTICE생성시각만정규화후나머지전체비교로강화; 4경계합성검사통과. 새매체예시D:/SAW-update-20261019(기존D:/SAW-0.1.0보존)로수정중.
- 공개실패PNG에서접근권한행이포괄문구/빈기대실제값만보이는요구누락확인. update_flow_ui_audit가update_diagnostics.py 및해당test만TDD로안전한reason한글표시/건수요약추가중. private진단접근승인을대체하지않으며새native실행금지. 이후후보7/최종시험필요.


다음: 후보6restore 사전권한실패 원인확인·재시험→계정/자료/새객체보관대조→cleanup/stop결과확인 → 최종문서/커밋 → 새최종ZIP봉인및후보6실행payload동일성 → 새GitHubPR·비공개사전배포. main·기존ZIP직접변경금지.

현재그림안내서브라우저: http://127.0.0.1:58369/UPDATER-STABILIZATION-GUIDE-20261019.html (로컬docs전용서버,세션92434).
[24단계 감사](docs/verification/updater-flow-audit-20261019.md) · [그림 안내](docs/UPDATER-STABILIZATION-GUIDE-20261019.html) · [현장 검증](docs/verification/updater-native-acceptance-20261019.md)

아래 2026-10-18 기록은 이전 배포 이력이며 이번 실행의 통과 근거가 아니다.

저장소·로컬 생성물 정리와 실제 브라우저 UI 확인을 완료했다. 오래된 후보 매체13개와 재생성 캐시를 삭제했다(8,591파일, 19,419,423,664바이트). 최종·이전 게시 배포, 데이터·복구본·모델·개발 의존성은 보존했다. [이번 검증 기록](docs/verification/cleanup-ui-2026-10-18.json).

## 소스와 최신 배포

| 항목 | 현재 기준 |
|---|---|
| 작업 위치 | F:/codex/SAW-Claude-main |
| 정리 시작 기준 소스 | be26d7f — 더블클릭 업데이트 사전 배포 게시 기록 |
| 작업 브랜치 | codex/detection-packs |
| 최신 배포 | [v0.1.0-pilot.20261018.1](https://github.com/dewdorp/SAW/releases/tag/v0.1.0-pilot.20261018.1), 비공개 사전 배포 |
| 매체 소스 | 4655fbba7cd0d16f42379b14bfcbac147a589925 |
| 업무 스키마 | 0014 |
| 설치 ZIP | SAW-0.1.0-pilot.20261018.1-model-free-win-x64.zip |
| 모델 | 가중치 제외, 별도 반입·명시적 선택 |

최신 ZIP은 1,444,865,907바이트이며 SHA256은 `971dda3d2c5ef4449e8efbdd47a1d4585e1804788192e5e2ef9302cfa0ab18d5`다. 내부 665항목의 크기·SHA256과 원격 게시 자산을 대조했다. 최종 매체는 `.release/desktop-update-20261018`에 있으며 이전 게시 배포도 보존한다. 근거: [봉인 검증](docs/verification/offline-desktop-release-2026-10-18.json), [게시 검증](docs/verification/github-desktop-update-2026-10-18.json).

## 설치·업데이트와 화면 안내

- **기존 설치 업데이트:** [더블클릭 안내](docs/DOUBLE-CLICK-UPDATE-GUIDE.md) · [그림 안내](docs/DOUBLE-CLICK-UPDATE-GUIDE.html). 새 ZIP을 기존 설치 밖에 해제 → `UPDATE-SAW.cmd` 실행 → 기존 설치 선택 → 점검·서버 중지 동의 → 업데이트 시작. 매체 검증과 전체 복구본 생성은 자동이다.
- **새 설치·실패 재개:** 매체의 START-HERE.md와 [설치 위치·재개 안내](docs/INSTALL-RECOVERY-2026-10-18.md). 설치 위치 이전이나 DB 제품 버전 변경은 앱 업데이트 범위에 포함되지 않는다.
- **분석 화면:** 조사 열기 → [로그 통계](docs/STATISTICS-TEMPORAL-GUIDE.md) → [행위 분석·근거 보고서](docs/BEHAVIOR-ANALYSIS-GUIDE.md). 화면 확인에는 합성 예제를 쓴다.
- **룰·파서:** [기본 탐지 목록](docs/DETECTION-CATALOG-GUIDE.md) · [오프라인 룰·파서 반입 실습](docs/OFFLINE-CONTENT-GUIDE.md). 파일 반입 뒤 합성 예제 시험과 독립된 승인·적용이 필요하다.
- **조사 기록·모델:** [조사·Golden](docs/GUIDANCE-GOLDEN-GUIDE.md) · [로컬 모델 반입·교체](docs/LOCAL-MODEL-GUIDE.md) · [전체 사용 설명서](docs/USER-MANUAL.md).

업데이트 복구는 계정·권한·MFA·DB·색인·원본·설정을 백업 시점으로 되돌리는 전체 복구다. 이후 새 자료나 계정 변경을 자동 병합하지 않으며 복구 직전 상태는 별도 보관한다.

## 실제로 확인한 범위

- Windows 11 build26200 / PowerShell 5.1 / 합성 자료를 넣은 NoAdmin 설치에서 업데이트 후보2의 창 버튼 이벤트 → worker → 실제 런타임을 실행했다. 업데이트 474.55초, 복구 406.54초였다. 물리 마우스로 런처를 더블클릭한 시험과는 구분한다.
- 업데이트 전후·복구 후 계정 2개, 이벤트 9건, Finding 10개, 증거 2개, 노트 1개, 완료 작업 2개 및 계정·원본·설정·키·TLS 보존을 대조했다. 같은 계정·MFA로 HTTPS 로그인했으며, 업데이트 뒤 추가한 가상 파일이 복구 직전 상태의 별도 보관 폴더에 남는 것도 확인했다.
- 최종 ZIP은 실제 성공한 후보2와 실행 payload·런타임·의존성이 같음을 검증했다. 최종 ZIP 자체로 업데이트·복구를 다시 실행한 결과는 아니다.
- 기록된 자동 시험은 서버 1,232통과·5건너뜀, UI 177통과·TypeScript 성공이다. GUI·worker·업데이트·매체 관련 추가 회귀 결과와 실패 이력은 [실제 검증 기록](docs/verification/desktop-update-2026-10-18.json)에 있다. 이번 문서 정리에서 전체 시험을 다시 실행한 것은 아니다.

## 남은 인수와 알려진 한계

- 깨끗한 Windows 10 Enterprise LTSC 2019 x64 build17763, 실제 관리자 서비스·UAC·재부팅·방화벽·조직 TLS 신뢰·코드서명 인수.
- 물리 폐쇄망, 무GPU 16/32GB 공동 부하, 강제 전원 중단과 ACL 복원, 운영 환경의 설치·업데이트·복구 인수.
- 지정 모델의 CPU 생성은 확인했으나 한국어·인용 품질과 운영 채택은 미완료다. 모델 교체·훈련·운영 적용 및 운영 자료 반입·배포는 별도 승인 범위를 유지한다.
- 기존 History503와 최초 UI 병렬 실행 실패의 원인은 미확정이다. 재통과만으로 원인이 해결됐다고 표시하지 않는다.

## 정리 결과와 지금 볼 수 있는 UI

- Git에는 캐시·설치 ZIP·불필요한 브랜치가 없었다. 이력과 원격 게시 배포를 유지하고 현재 상태 문서의 반복 설명과 오래된 시작 안내를 정리했다.
- 실제 [SAW 화면](http://127.0.0.1:57286/)을 합성 claude-check의 비밀번호·MFA로 로그인하여 조사4건, 사례B 83이벤트, 출발지 통계(4xx40건/48.2%), 저장된 행위분석v2와 시계열을 확인했다. 사용자 열람을 위해 서버와 탭을 유지한다. 세션 종료/PC 재시작 뒤에는 재실행·재인증이 필요하다.
- 이번 UI는 격리 SQLite/로컬 객체 저장소와 실제 API·빌드된 화면이다. 새 분석·모델 실행이나 PostgreSQL/OpenSearch 인수 시험을 이번 정리에서 수행한 것은 아니다. 좁은 브라우저 패널에서는 가로 스크롤이 필요할 수 있다.
- 현재 실행 환경, 빌드 UI, 모델, 합성 fixtures, 백업, 최종·이전 게시 배포 및 검증 이력을 보존했다. 운영 자료·계정·기존 사용자 설치와 원본 F:/claude/saw는 수정하지 않았다.

실제 은행 자료와 비밀값은 출력·인용·복사하지 않는다. 화면 확인은 합성 자료와 claude-check 또는 자동 시험으로 수행하고 사용자 계정으로 로그인하지 않는다. 자세한 경계와 실행·시험 절차는 [작업자 안내](AGENTS.md)와 [인수인계](docs/HANDOVER.md)를 따른다.

과거 단계별 결과·실패·한계는 [PROGRESS.md](PROGRESS.md), [HANDOVER.md](docs/HANDOVER.md), [검증 기록 폴더](docs/verification/)에 남긴다. 과거의 “진행 중”·“다음” 문구는 해당 날짜의 이력으로 읽고 현재 우선순위는 이 문서를 기준으로 한다.
