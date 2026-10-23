## 2026-10-23 P3 검증 완료 · P4 연속 진행
- 후속확인 요청·회신·검증의 정확 버전과 불변 다중 보고서, 같은 내용의 HTML/8시트 Excel, 취소·재시도·원천 권한 검사를 구현했다.
- 최종 코드 동결 후 전체 서버2,060통과·6건너뜀·실패0·기존경고2, 2,248.45초. 실제 DB 환경을 별도 지정해야 하는4건, Windows 심볼릭 링크1건, POSIX 권한1건을 건너뛰었다. 이전 실패·중단 이력은 보존한다.
- 최종 웹292통과/48파일·TypeScript·Vite 빌드 통과. 실제 합성 브라우저의 요청→회신→자료 부족 검증→정확 버전 Excel/HTML과 최종 권한 수정 뒤 재시작·다운로드를 확인했다.
- 실제 PostgreSQL16.15/OpenSearch2.19.6/Nori에서13통과, 최종 다운로드 권한·부분 삭제 수정은 별도15통과. 모두0실패/0건너뜀·정상 종료·시험 포트 닫힘을 확인했다.
- 긴 Windows 경로 삭제, 다운로드 중 권한 회수, 부분 증거 삭제 뒤 잔존 내보내기 Job, 조사 이동 후 남는 이전 선택을 실패 재현 뒤 수정했다.
- XlsxWriter3.2.9 실제 wheel/sdist/라이선스를 확인해 배포 입력에 등록했고 내장 Python3.12.10의 오프라인 의존성 설치·한글8시트 생성 smoke를 통과했다. 새 전체 매체 인수는 P5에서 수행한다.
- P4 골든셋/독립 반출→P5 재처리·큐·성능·모델 제외 매체·설치/업데이트/복구·검토·새 비공개 릴리스를 재승인 대기 없이 계속한다.
- 원본 Claude·운영 설치/계정/은행 자료·기존 릴리스 보존. LTSC2019/16GB/관리자 서비스·운영 인수와 과거 History503/권한metadata4건 원인 미확정은 별도로 유지한다.

## 2026-10-21 P2 검증 완료 · P3 연속 진행
- 룰·정책 초안/승인/활성본을 분리하고 정확 버전 시험·독립 승인·적용·복구를 연결했다. WAF/IPS/DDoS/NDR 장비별 분석과 단위·누락·부분 상태를 구현했다.
- 전체 서버1960통과/6건너뜀/1실패(1770.30초). 새P2안내·스크린샷의 매체 누락 1건을 고친 뒤 해당 전체 매체 회귀67개가 통과했다. 전체시험 시작 뒤 PostgreSQL JSON DISTINCT 오류를 좁은 EXISTS 쿼리로 수정했으며 해당 회귀6개와 실제 저장소11개를 별도로 통과했다.
- 전체 웹268개/43파일(독립 QA 시험1개 포함)·TypeScript·Vite 빌드 통과. 실제 PostgreSQL16.15/OpenSearch2.19.6에서 최초21개와 최종11개 통과·정상 종료를 확인했다. 중간 native 실패8통과/1실패/2미실행 이력은 보존한다.
- 실제 합성 브라우저: 선택한6개 양성/3개 음성 기록으로 TP1/TN1, 작성자 승인 차단, 다른 검토자 API 승인·적용 후 초안v3를 저장해도 활성v2 유지 확인. DDoS 숫자·단위·상속 폼도 확인했다.
- 파생 Finding/이야기/분석이력/보고/룰복사/내보내기의 원천 권한을 보존하도록 독립 검토와 회귀를 보완했다.
- 다음 P3 후속확인 버전·HTML/8시트 Excel·다중조사 내보내기를 진행한다. 이후 P4·P5 검토·모델제외매체·비공개 새릴리스까지 단계별 재승인 없이 계속한다.
- 새 패키지·릴리스와 운영 인수는 아직 없다. LTSC2019/16GB·관리자서비스·History503/과거 권한조회4건 원인 미확정은 별도다.

- [P2 검증](docs/verification/affiliate-p2-validation-20261021.md) · [실제 화면 안내](docs/AFFILIATE-DETECTION-GUIDE-20261021.md).

## 2026-10-20 P1 검증 완료 · P2 연속 진행
- 관계사/장비·불변 증거 맥락, FW 세션/누적 해석, 원천 ACL, 범위 Job·실행/보고 snapshot 및 화면을 구현했다.
- 서버 전체1833통과/6건너뜀(1458.83초). 실행 도중 추가한 최종 시간 해석/정밀도는 별도50/70개 회귀와 독립 재검토로 확인했다. 최종 전체웹230개/35파일·TypeScript/Vite 빌드 통과.
- 전용 실제 PostgreSQL16.15·OpenSearch2.19.6·Nori2.19.6에서16개 통과/0실패/0건너뜀(133.50초), 정상종료·시험포트닫힘 확인.
- 최초 native wrapper hook 오류와 후속 디스크 flood-stage 보호429×14는 실패 이력으로 보존. 전용시험에만 free-space low20gb/high12gb/flood6gb를 적용하고 보호기능을 유지했다. 운영/제품기본설정은 변경하지 않았다.
- 실제 합성 브라우저: 로그인/MFA→범위분석→9기록/1세션/6거부/1후보→6근거원문→불변HTML, 프로필v2저장 후 기존증거v1유지 확인.
- 검증: [P1 기록](docs/verification/affiliate-p1-validation-20261020.md), [실제 저장소 영수증](docs/verification/affiliate-p1-native-20261020.json), [화면 사용법](docs/AFFILIATE-FW-GUIDE-20261020.md).
- 다음 P2 정책/룰 초안·승인·활성본 분리와 선택 정답 시험/5장비 분석. 이후 P3→P4→P5 검증·검토·모델제외매체·비공개 새릴리스까지 승인된 순서로 계속한다.
- 아직 새 패키지·릴리스는 없다. LTSC2019/실제16GB·관리자서비스·운영 인수와 History503/과거권한조회4건 원인 미확정은 별도로 유지한다.

## 2026-10-20 최종 배포 ZIP 직접 재검증 및 릴리스 문서 추가

- 게시 ZIP을 직접 해제해 시작48.32초·점검38.21초·업데이트485.55초·복구488.11초 PASS. 계정/MFA·DB/색인·원본/설정 보존, 같은 계정 로그인, 새 객체 별도 보관, 계정 정리·정상 종료28.77초까지 확인했다.
- 관련14파일 회귀618통과·1POSIX건너뜀·2기존경고·실패0. Windows11/PS5.1/NoAdmin의 실제 WinForms 버튼 이벤트 시험이며 대상 LTSC 관리자 서비스 인수와 구분한다.
- 실행 코드·ZIP·manifest·기존9자산은 유지하고 최신 HTML/Markdown/JSON3문서를 비공개 사전 배포에 추가했다. 원격12자산 크기/digest·tag 및 main/이전릴리스 보존 확인. 실제 화면3장 내장/브라우저검증 완료.
- [최신 안내](docs/UPDATER-RECHECK-20261020.html)와 [검증 기록](docs/verification/updater-release-recheck-20261020.json)을 우선한다. 원본Claude/운영설치 보존. LTSC/관리자SCM/UAC/443/재부팅·조직서명·물리폐쇄망/공동부하·운영인수와 과거권한조회4건/History503 원인은 계속 미확정이다.

## 2026-10-20 업데이트 안정화 매체·PR 제출 완료

- 비공개 사전 배포 v0.1.0-pilot.20261019에 실제 모델 제외 전체 ZIP·그림 안내·검증 기록 등9자산을 게시했다. ZIP1,445,832,542바이트, SHA256 b9d7e0e7d9b3658c17690dcd276b072c03bb3330518431e1eba4e04d56b30cb5,677항목 검증 PASS.
- 매체 source26f5d1a448668c127383c2e73d47d60d00ed2a28와 후보7 실행payload 동일성, SBOM/라이선스(발행 필드 제외), 원격9자산 크기·digest 및 실제tag 확인. 최종 ZIP 자체의 native 재실행과 구분한다.
- 통합 PR https://github.com/dewdorp/SAW/pull/3 제출. main723e2a6·이전4개 릴리스와 원본Claude·운영C:/SAW 보존. 후속 문서 커밋만 추가한다.
- 최종 서버1733/6skip,웹177/TypeScript PASS. 실제 합성 적용492.39초·복구497.54초·계정/MFA/자료보존·새객체보관·정상종료 PASS. HTML10화면 내장/브라우저10개로드·단계이동 확인.
- 대상 LTSC17763·관리자 서비스/UAC/443/재부팅·조직서명/물리폐쇄망/공동부하·운영 승인은 별도다. 기존 후보6 권한조회 실패의 정확한 원인은 미확정으로 유지한다.
- 게시: https://github.com/dewdorp/SAW/releases/tag/v0.1.0-pilot.20261019. 매체 안의 START-HERE와 그림 안내를 사용하며 수동 hash 대조 없이 자동 검증한다. 상세 봉인·게시 영수증은 docs/verification/updater-release-20261019.json 및 docs/verification/github-updater-stabilization-20261019.json에 기록했다.

---

## 2026-10-20 업데이트 안정화 — 코드·개발기 실제 복구 검증 완료

- 최종 서버1,733통과·6건너뜀·2경고(1,305.21초), 웹177통과·TypeScript 성공. 독립 검토 후 생산코드를 동결했다.
- 후보7 실제 Windows11/PS5.1/NoAdmin 합성 설치: 시작69.47초·점검39.36초·적용492.39초·복구497.54초 PASS. 점검·적용·복구 뒤 계정/MFA/DB·색인·증거·노트·설정·키·TLS·원본 동일성과 같은 계정 로그인 확인.
- 새 객체50바이트의 별도 보관, 합성 계정 비활성/세션 폐기, 정상 종료28.56초 및 세 포트 닫힘·PG PID 부재 확인. 물리 더블클릭, 대상 LTSC 관리자 서비스 인수는 아니다.
- 후보6의 metadata 조회 실패4건은 정확한 Win32 원인 미확정으로 보존한다. 후보7 첫 시험 계정 준비 실패와 정상 정리 후 재개도 별도 이력이다. 후속 통과로 최초 실패를 지우지 않는다.
- 설치 안내3개의 실행 예시를 프로세스 한정 RemoteSigned로 통일하고 명령17개 PS5.1 구문 검사 통과. 사용자 정책/조직 정책 변경과 기존 ACL 자동 수리는 없다.
- 새 전체 model-free ZIP 봉인·통합 PR·비공개 사전 배포와 원격 대조는 현재 진행 중이며 최신 상태는 STATE를 따른다. 원본 Claude·운영 설치·기존 릴리스는 보존한다.
- 대상 LTSC17763/관리자 서비스/UAC/443/재부팅·조직 TLS/서명·물리 폐쇄망·공동 부하와 운영 승인은 남아 있다.

---

## 2026-10-19 기존 설치 업데이트 안정화 — 검증 진행 중

- 통합 브랜치 codex/updater-stabilization-20261019에서 상태 소유권·OWNER RIGHTS/NetworkService ACL·Procrun 양쪽 registry view·서비스/프로세스 식별·구형 설치 기준·9행 점검 UI·복구 중단 재개를 보완했다. 기존 서비스 재등록, registry 복사, 설치 ACL 자동 수리를 사용하지 않는다.
- 후보6에서 실제 업데이트 508.17초, 계정·MFA 로그인 및 자료 보존 대조를 통과했다. 이어진 복구 첫 시도는 40.52초에 설치 권한 사전 검사(unsafe_access/validate)에서 실패했다. 서버 중지·복구 이전에 차단됐으며, 복구본 검증 결과는 정상이다. 자동 승인 검토가 합성 진단 읽기를 거부했으나 사용자의 명시 승인 후 오류 종류·건수만 확인했다. 32,690개 중 metadata 조회 실패4건이며 직접 원인은 아직 미확정이다.
- 후보6 동결코드의 전체 서버 재시험은 1,647통과·6건너뜀·2경고, 1,376.79초로 완료했다. 경고는 Starlette/httpx 변경 예고와 JUnit record_property 형식이다. 웹177통과·TypeScript 성공. 이후 안전한 권한 오류 원인·건수의 화면 표시를 보완 중이며, 이 변경의 검증과 실제 복구는 별도다. 새 최종 ZIP·게시·통합 PR은 아직 없고 후보5의 복구 성공을 후보6의 성공으로 표시하지 않는다.
- 대상 Windows 10 Enterprise LTSC 2019 x64 build 17763·PS5.1의 실제 관리자 서비스/UAC·HTTPS 443·재부팅 인수는 미검증이다. 개발 PC build 26200의 시험과 구분한다.
- 운영 C:/SAW·D:/SAW-0.1.0과 원본 F:/claude/saw는 변경하지 않는다. 설치 점검은 서비스 중지나 설치 변경을 하지 않으며 별도 보호 작업 폴더와 유지보수 잠금을 사용할 수 있다.
- [새 사용자 안내](docs/UPDATER-STABILIZATION-GUIDE-20261019.md) · [그림 안내 HTML](docs/UPDATER-STABILIZATION-GUIDE-20261019.html) · [24단계 흐름·PR 통합 감사](docs/verification/updater-flow-audit-20261019.md) · [LTSC 현장 읽기 전용 점검](docs/verification/updater-native-acceptance-20261019.md). 안내의 그림01–03은 합성 UI 렌더다. 그 밖의 실제 합성 설치 실행 화면은 후보와 성공·실패 범위를 구분하며 대상 운영 인수의 증거가 아니다.

---

## 2026-10-18 저장소 정리·실제 UI 열람

- 삭제를 요청받아 최종 배포로 대체된 후보 매체13개와 재생성 캐시를 정리했다. 총56경로/8,591파일/19,419,423,664바이트(논리 크기). 절대 경로·재파스 지점·실행 프로세스를 확인한 뒤 지정한 경로만 삭제했고 후보 manifest/체크섬은 .qa/cleanup-20261018에 남겼다.
- Git 추적 소스에는 캐시/설치 ZIP이 없고 로컬 브랜치는1개, garbage0이었다. 이력·원격 release·최종 매체·게시 ZIP·모델·의존성·합성 데이터·복구본·운영 자료를 보존했다. STATE 반복 이력은 PROGRESS/HANDOVER로 연결하고 README/AGENTS를 최신 시작 안내로 정리했다.
- 실제 합성 서버57286 시작 → 브라우저 비밀번호/MFA 로그인 → 조사4건 → 사례B 83이벤트 → 출발지별 통계83건/4xx40건/48.2% → 저장된 행위분석v2와 그래프를 확인했다. 로컬 시각화 폴더에 화면4장을 저장했고 사용자 열람용 서버/로그인된 탭을 유지한다.
- 이번 UI는 격리 SQLite·객체 저장소의 실제 API/빌드 UI다. 새 분석·모델 실행·native PG/OS·LTSC·운영 인수를 검증한 것으로 세지 않는다. 기존 C: 설치·원본Claude·실제 은행 자료·사용자 계정은 변경하지 않았다.
- [정리/UI 기록](docs/verification/cleanup-ui-2026-10-18.json). 상대 링크·줄 끝·차이 검사, 최종 ZIP 크기/manifest 보존, HTTP200 확인. 제품 코드가 바뀌지 않아 전체 자동 시험은 반복하지 않았다.

---

## 2026-10-18 더블클릭 업데이트 매체 게시 완료

- [비공개 GitHub 사전 배포](https://github.com/dewdorp/SAW/releases/tag/v0.1.0-pilot.20261018.1)에 모델 제외 전체 매체와 그림 안내 등 9자산을 게시했다. 원격 크기·SHA256과 source tag를 대조했다. 이전 배포는 보존한다.
- ZIP: SAW-0.1.0-pilot.20261018.1-model-free-win-x64.zip, 1,444,865,907바이트, SHA256 971dda3d2c5ef4449e8efbdd47a1d4585e1804788192e5e2ef9302cfa0ab18d5. 내부665항목(663 payload + manifest/체크섬) 전부 크기·hash 확인. 최종 manifest 4121605a5e1f76ed821c0fbbbfac95d6baf6822153868eef0eb14f2cb15b1583.
- 매체 소스4655fbba7cd0d16f42379b14bfcbac147a589925. 실제 합성 설치에서 성공한 후보2와 최종 실행 payload/런타임/의존성 동일성을 확인했다. 최종 ZIP의 차이는 게시 문서와 메타데이터이며 실제 업데이트·복구를 ZIP으로 다시 실행했다고 보고하지 않는다.
- 사용: 새 ZIP을 기존 설치 밖에 해제 → UPDATE-SAW.cmd 더블클릭 → 기존 C:\SAW 선택 → 설치 점검 → 서버 중지 동의 → 업데이트 시작. 수동 명령·해시 대조 없이 자동 매체 검증과 전체 복구본 생성을 수행한다.
- 문제 시 같은 창의 이전 상태 복구로 백업 시점 전체를 되돌린다. 업데이트 이후 새 자료와 계정 변경을 자동 병합하지 않으며, 복구 직전 상태는 별도 보관한다. 원본 Claude·사용자 C: 설치·운영 자료는 변경하지 않았다.
- [그림 안내](docs/DOUBLE-CLICK-UPDATE-GUIDE.html), [패키지 봉인 검증](docs/verification/offline-desktop-release-2026-10-18.json), [GitHub 게시 검증](docs/verification/github-desktop-update-2026-10-18.json).
- 실제 Windows11/PS5.1 NoAdmin 합성 업데이트474.55초·복구406.54초, 동일 계정/MFA 로그인과 기준 자료 보존 PASS. 깨끗한 LTSC17763·실제 관리자서비스/UAC/재부팅·물리폐쇄망·공동부하·강제전원중단·운영 인수는 미검증/승인 전이다. 해당 환경 검증이 다음 인수 작업이다.

---

## 2026-10-18 더블클릭 업데이트·복구 실제 검증

- 새 매체의 UPDATE-SAW.cmd와 한글 WinForms 창으로 점검·중지·전체 복구본·앱 교체·재기동·복구를 실행한다. 사용자의 명령 입력/수동 해시 비교는 없다. 자동 전체 매체 검증, 동일 유지보수 잠금, 계정·권한·MFA·DB·색인·원본·설정 보존을 유지한다.
- 실제 Windows11/PS5.1 NoAdmin 합성 설치에서 후보2의 업데이트 474.55초 / 전체 복구 406.54초 PASS. 업데이트 전후·복구 후 계정2/이벤트9/Finding10/증거2/노트1/완료작업2, 암호hash·역할·MFA·원본·설정·키·TLS 동일 확인. 같은 계정/MFA로 HTTPS 로그인 PASS.
- 업데이트 뒤 만든 가상 파일98bytes가 복구된 설치에서는 빠지고 별도 보관 폴더에 그대로 남는 것을 확인했다. 합성 계정 비활성·세션 취소와 PG/검색/API 전체 종료까지 완료했다.
- 첫 후보는 PG slash 경로와 JVM의 System32 conhost 검사에서 중지 전에 실패했다. 경로 동등성 및 정확한 부모/자식·실행파일·인자·생성시각/보유handle 검증으로 고친 후 새 후보에서 실제 성공했다. 실패 기록도 유지한다.
- 기존 서버1232 PASS/5skip, UI177 PASS/tsc0, native GUI59 PASS/worker17 PASS, 최종 core68 PASS, media61 PASS. offline+core102 및 최종 독립 소유권 회귀21도 별도 PASS. 기존 Starlette 경고. 실제 시험은 WinForms 버튼 이벤트→worker→native 런타임이며 물리 마우스 더블클릭과 구분한다.
- [더블클릭 안내](docs/DOUBLE-CLICK-UPDATE-GUIDE.md), [단일 HTML 그림 안내](docs/DOUBLE-CLICK-UPDATE-GUIDE.html), [검증 기록](docs/verification/desktop-update-2026-10-18.json). 검증 후보와 실행payload가 같은 최종 매체 봉인 및 별도 비공개 사전배포를 완료했다(상단 게시 기록 참고).
- 원본 Claude/사용자 C: 설치/운영 자료 미변경. 깨끗한 LTSC17763·실제 관리자서비스/UAC/재부팅·물리폐쇄망·공동부하·강제전원중단·운영 인수는 별도 게이트로 남긴다. 새 로그/PCAP 재분석은 이번 작업에서 실행하지 않았고 저장된 결과 보존을 검증했다.

---

## 2026-10-18 업데이트 안내 r2: 수동 해시 대조 제거

- 사용자 요청으로 세 업데이트 안내서의 Get-FileHash·SHA256 눈대조 단계를 제거했다. verify-bundle/update.ps1 자동 무결성 검증과 계정·분석 자료 보존 계약은 그대로다. 제품·설치 코드는 변경하지 않았다.
- 2단계 브라우저 화면을 다시 확인·캡처했다. 관련 시험27통과/기존경고1(8.17초), PS5.1 명령13개 구문 검사 및 독립 문서 검토 PASS. 실제 설치·업데이트·복구는 이번 문서 수정에서 재실행하지 않았다.
- 비공개 GitHub 기존 사전 배포에 SAW-update-guide-20261018-r2.zip(1,094,623바이트)을 추가하고 원격 대조했다. 기존11자산 보존. 현재 그림 안내는 r2를 사용한다.
- [수정 검증](docs/verification/update-guide-r2-2026-10-18.json), [게시 대조](docs/verification/github-update-guide-r2-2026-10-18.json). 기존 운영 인수 게이트 유지.

---

## 2026-10-18 기존 설치 업데이트 그림 안내·실제 복구 확인

- 사용자 요청에 따라 [8단계 그림 안내](docs/OFFLINE-UPDATE-SCREENSHOTS-2026-10-18.md)와 [단일 HTML](docs/OFFLINE-UPDATE-WALKTHROUGH-2026-10-18.html)을 작성했다. 서비스/NoAdmin 명령, 같은 드라이브 복구 공간, 전체 시점 복구와 계정 변경의 되돌림을 설명했다. 기존 update.ps1 및 제품 코드는 변경하지 않았다.
- 안내서를 실제 브라우저로 캡처한 8장이다. PowerShell 또는 설치된 제품의 화면 캡처가 아니다. 단계 이동·설치 방식·전체 보기 검증; 명령14개 PS5.1 구문 PASS. 복사 성공 알림만 확인했고 clipboard 내용 독립 검증/직접 file: 열기/인쇄는 미검증이다.
- 최종10/18 ZIP SHA256 재대조·매체650파일 검증 PASS. Windows11 build26200/PS5.1의 별도 F: 합성 NoAdmin 설치에서 실제 적용→HTTPS/MFA→전체 종료/시작→전체 복구→HTTPS/MFA PASS. 측정: plan 453.81초 / apply 748.02초 / restore 601.58초.
- 적용 전·재시작 후·복구 후 계정2/이벤트9/Finding10/증거2/노트1/완료작업2 보존. 계정ID·비밀번호hash·역할·MFA, 원본·설정·키·인증서·증거ID·노트 비교 PASS. 합성 계정 비활성/세션 취소 후 전체 중지 완료. [상세 검증](docs/verification/update-walkthrough-2026-10-18.json).
- baseline37094e85는 이전 합성 후보이며 게시10/17 ZIP과 동일하다고 주장하지 않는다. 최종18 source403bc7d5와 적용·복구 비교했고 업무 스키마는 모두0014다. 테스트 harness의 준비 순서/app-var 가정을 바로잡은 과정을 검증 기록에 남겼다.
- 관련 release manifest 시험27 passed/기존경고1(16.36초). 제품 브라우저는 시험 인증서 신뢰 문제로 차단됐고 우회하지 않았다. 이번에는 제품 전체 서버/UI 시험이나 새 로그·PCAP 업로드를 재실행하지 않았다.
- 비공개 GitHub 사전 배포에 설명서 전용 ZIP SAW-update-guide-20261018.zip(1,096,900바이트, SHA256 4e3257c48c78630d4e8d676909569c8622aa403fb08bfedea853143428a61156)과 외부 체크섬을 추가했다. 기존 설치 ZIP/9자산은 보존했다. [게시 대조](docs/verification/github-update-guide-2026-10-18.json).
- 사용자 C: 설치·원본 Claude·운영 자료 미변경. 정상 실행 중인10/17 설치는 설치기 보완만을 위해 급히 업데이트할 필요가 없다. 설치 실패 재개는 매체 START-HERE.md를 따르며, C:→D: 이전은 이 업데이트의 지원 범위가 아니다.
- 깨끗한 LTSC17763·관리자서비스/재부팅·물리폐쇄망·공동부하·운영 인수는 여전히 미검증/승인 전이다. History503 원인 미확정과 기존 운영 게이트를 유지한다.

---

## 2026-10-18 설치기 보완 매체 게시 완료

- [비공개 GitHub 사전 배포](https://github.com/dewdorp/SAW/releases/tag/v0.1.0-pilot.20261018)에 새 모델 제외 ZIP과 안내/검증 문서 등 9자산을 게시했다. 원격 크기와 SHA256 대조 완료. 이전 20261017 배포는 보존한다.
- ZIP: SAW-0.1.0-pilot.20261018-model-free-win-x64.zip, 1,444,634,601바이트, SHA256 81eda12295cc75b221add3c34a4e6777d14cbce0e64efa5f95344c53e4c63628. 내부 652항목(650 payload + manifest/체크섬)의 크기·hash와 시험 후보5 실행 payload 동일성 PASS.
- 매체 소스 commit: 403bc7d57631e56a27dbef70cd81512029e1b9f5. 설치 위치·재개 안내는 [설치 위치·재개](docs/INSTALL-RECOVERY-2026-10-18.md), 실제 게시 영수증은 [게시 검증](docs/verification/github-release-2026-10-18.json).
- 코드 검증: 서버1201통과/2건너뜀/기존경고1, 화면순차177통과·TypeScript 성공. 최종 문서 반영 후 매체/링크27시험도 통과했다.
- 실제 격리 Windows11/PS5.1에서 후보4 최초 설치·실패 재개·HTTPS/MFA·로그/HTTP PCAP·재시작, 후보5 완료2회·중지검증·계정/데이터 보존을 확인했다. 후보5 빈폴더 전체 최초 설치는 재실행하지 않았으며 변경 실행파일1개를 대조했다.
- 게시 첫 시도는 초안 생성 직후 목록 조회에서 초안을 찾지 못해 중단됐다. 기존 초안 존재 확인 후 같은 초안에 이어 게시했다. 원인 확정이나 제품 오류 수정으로 보고하지 않는다.
- 남은 인수: 깨끗한 LTSC17763, 실제 관리자서비스/재부팅, 물리폐쇄망, 16GB 공동부하, 조직TLS/코드서명, 강제중단ACL복구, 운영 승인. History503와 최초UI병렬실패 원인은 미확정이다.
- 기존 C:/SAW와 원본 F:/claude/saw는 변경하지 않았다. 이번 수정만으로 정상 설치본 재설치가 필요하지 않다. C:→D: 자동 이전은 지원하지 않는다.

---


## 2026-10-18 설치 위치·오류 복구 보완

- 기존 C:/SAW와 원본 F:/claude/saw 미변경. C/D 절대 경로와 ChooseInstallLocation 입력으로 프로그램·DB·색인·원본·모델·백업 위치를 함께 선택한다. 기존 설치의 드라이브 자동 이전은 없다.
- OS 전용 JDK/자식 Java 변수/실제 서비스 사후 검사, PG 제한 토큰 SID ACL·한글 runtime/share 초기화, Python 출처/바이트/의존성 검사와 보존 복구, 원자 journal·잠금·정상 설치 readonly 검증을 반영했다. 업무 기능·모델·스키마는 변경하지 않았다.
- 최종 서버 1201 passed, 2 skipped, 1 warning in 1409.36s (0:23:29), UI순차177통과(31파일), tsc·PS5.1구문·주요Ruff PASS. 최초 UI 병렬실패와 History503의 원인은 미확정으로 유지한다.
- 후보4 실제 NoAdmin 합성 초기설치/재개 + 후보5 완료검사: 실행기1200초 중단→파일작업완료→같은root재개→의도한PG포트충돌→재개완료→HTTPS/MFA/로그·내장HTTP PCAP→이벤트9/Finding10/노트→종료·시작→완료설치2회재실행·중지검증→데이터재조회 PASS. 후보5 전체fresh설치를 반복한 것은 아니며, 실행파일차이는검사helper1개로확인했다. 실제서비스/깨끗한LTSC 시험을 대신하지 않는다.
- 안내: [설치 위치·재개](docs/INSTALL-RECOVERY-2026-10-18.md). 상세: [검증 기록](docs/verification/installer-recovery-2026-10-18.md).
- 위 봉인·게시·원격 대조는 완료됐다. 다음은 승인된 깨끗한 LTSC 및 관리자 서비스 환경에서의 인수 시험이다.
- 남은 게이트: 깨끗한LTSC17763·물리폐쇄망·관리자서비스/재부팅·조직TLS/서명·16GB공동부하·강제중단ACL복원·운영인수. 실제 운영데이터/계정 변경 없음.

---

## 2026-10-17 모델 제외 매체·기존 설치 업데이트/복구 검증

- 새 매체 후보5에 스키마0014·현재UI·행위 분석·통계·조사/Golden·룰/파서 콘텐츠·실제 CPU 실행기를 포함했다. 모델 가중치는 제외, 런타임 pin 변경/외부 다운로드 없음.
- 새 폴더 실제 설치→HTTPS/MFA→로그/내장HTTP PCAP→이벤트9·Finding10·노트→전체 종료/시작 보존, 설치 전체 owner/DACL 검사 PASS.
- 기존10/12 설치0011→0014→행위 분석/HTML→재시작→DB/색인 포함 전체0011복구→다시0014적용/분석/재시작 PASS. 기존9이벤트/8Finding/노트/키/MFA/원본 보존. 최신 트리는 retained로 별도 보관.
- 중간 후보2는 DACL 상속 상태 차이, 후보4 복구는 임시 경로 길이로 교체 전에 거부됐고 해당 실패를 기록했다. 복제 ACL·기존 owner/ACL 사전 검사·신규 설치 루트 보호·미디어 ACL staging 전파·디렉터리 열거 오류를 실제 Windows 회귀와 독립 검토로 보완했다. 기존 합성 QA의 권한만 별도 정비했으며 운영 권한 자동 수리는 하지 않는다.
- 서버1079/2건너뜀(559.62초), 화면177(31파일),tsc/build·주요Ruff·PS4구문 PASS. 실제 브라우저 룰/파서 r1 반입→4예제→독립 적용→영향 확인→사용중단/재조회 캡처6장. 과거r2 HTTP1→2→1과 구분.
- [설치](docs/OFFLINE-RELEASE-2026-10-17.md), [업데이트/전체복구](docs/OFFLINE-UPDATE-GUIDE.md), [실제 룰·파서 화면](docs/OFFLINE-CONTENT-GUIDE.md), [검증](docs/OFFLINE-RELEASE-VALIDATION-2026-10-17.md).
- **게시 완료:** [비공개 GitHub 사전 배포](https://github.com/dewdorp/SAW/releases/tag/v0.1.0-pilot.20261017) — ZIP 1,444,582,845바이트, 내부645파일 SHA검사·시험후보 실행파일 동일·원격10자산 크기/지문 대조 완료. ZIP SHA256 e2a09af4aee877a7d1c2f1fdf87de915a2a11491ae5010ac17aefe022fe90fe8. 소스 b4d81386d05a675a15c438f3ed3190ae831f5e75.
- **남은 게이트:** 깨끗한LTSC17763/물리적인터넷차단/16GB공동부하/관리자서비스·조직TLS/모델한국어품질·SFT/운영인수는 미완료. History503 원인미확정 유지. 원본Claude·은행자료·운영계정 미변경.

---

## 2026-10-16~17 웹 행위 분석·근거 보고서·Golden 증분

- 기존 조사/파서/Job/원문/요청비교/Check/종결/Experience/Golden을 재사용했다. 새 행위 분석 탭,5가지 이동 시간창,수집 품질,저장 버전·SHA,9절 A4 HTML,조건부 후속 질문과4-eyes 사례 내보내기를 연결했다. 모델·능동 스캔·훈련 없음.
- 스키마0014 및 saw-web-behavior/1.0, 질문 saw-web-behavior-questions/1.0. 백서 임계값은 참고이며 도구·AI·침해/정상 정답이 아니다. 원문 표본ID/동결 비교/쿼리/IPv6/미수집/멀티센서 경계를 유지한다.
- 최종 서버1004통과2건너뜀(326.44초), 화면177통과(31파일,25.56초),tsc/build/Ruff주요오류검사 성공. 실제 격리PG16.15/OS2.19.6 기능64+보완15시험(중복포함), 각 실행 종료·포트정리 성공.
- 실제 브라우저 A v2계산→구간확대→원문16건→두요청비교→Check저장→HTML, D UA미수집, B v2후속질문 확인. 별도HTTP로 종결→Experience→독립계정Golden승인→입력/정답Export→프로세스재시작 보존. 브라우저는 채택결과조회와실제ZIP다운로드까지 확인(승인클릭자체는HTTP).
- 독립검토P1 JSON비밀값노출/P2 masked필터근거누락/P2IPv6서비스충돌 수정·재검증. 브라우저CSP보고서서식/긴ID필터가로폭 수정. 기존History503 원인은 미해결 유지.
- [사용법·12장실제화면](docs/BEHAVIOR-ANALYSIS-GUIDE.md), [검증/환경게이트](docs/BEHAVIOR-VALIDATION-2026-10-16.md), [최신B보고서](docs/examples/behavior-case-B-report.html).
- NEXT: 기존10/12ZIP 미갱신. 새 모델제외 매체+스키마0014의기존설치전환·깨끗한LTSC17763·16GB공동부하·모델품질/운영인수는남는다. 현재개발OS Windows11build26200. 원본Claude·은행자료·운영계정미변경. 운영자료/고비용훈련/관리자설치/운영배포승인경계유지.

---

# SAW 구현 진행 현황 (자동 재개용)

## 2026-10-15 조사 기록과 오프라인 콘텐츠 증분

조사 안내/Check/종결/Experience/선택 Golden과 데이터 전용 룰·파서 반입/시험/독립 적용/복구를 연결했다. 스키마0013과 예제/사용 안내를 추가했다. 최종 서버913통과2건너뜀, 화면162통과, tsc/build/Ruff 성공. 실제 PG16.15/OS2.19.6 59+4통과, 합성 HTTP 탐지1→2→1, Golden export와 재시작 보존을 확인했다.

자세한 변경과 검증은 [STATE](STATE.md), [검증 기록](docs/GUIDANCE-CONTENT-VALIDATION-2026-10-15.md)에 있다. 브라우저 도구 장애로 콘텐츠 적용·복원/Golden 최종 클릭 및 캡처는 미완료이다. 기존 설치ZIP·깨끗한LTSC·모델품질·운영인수는 완료로 변경하지 않았다. [오프라인 실습](docs/OFFLINE-CONTENT-GUIDE.md)과 [조사·Golden 사용법](docs/GUIDANCE-GOLDEN-GUIDE.md)을 제공한다.

> 이 파일은 **작업 재개의 기준점**이다. 새 세션/자동 실행은 이 파일을 먼저 읽고 `NEXT` 항목부터 이어간다.
> 완료(✅) 항목은 재구현하지 않는다. 환경 미검증 항목은 [ENV-VERIFICATION.md](ENV-VERIFICATION.md)에 기록한다.
> 사용자 지시(2026-10-06): 단계별 승인 대기 없이 남은 구현·테스트·브라우저 검증을 계속 수행.


## 2026-10-15 선택 탐지 설명·조사 보조와 실제 BASE CPU 재시험

- 선택한 이상행위의 근거 요약 → 설명·추가 확인·보고서 초안 → 명시적 노트 저장·원문 이동을 연결했다. 시간 조건 누락을 고쳤고 미조회/0건, 미확인/미충족, 템플릿/모델 결과를 구분한다. 주요 생성은 탐지 1개·지표/체크/ATT&CK 각 최대 4개·원문 0개이며 기존 권한/승인 경계를 유지한다.
- 서버 851통과·2건너뜀(241.19초), 화면 144통과·26파일(26.41초), tsc/Ruff 성공. 최종 build 20.25초 exit0. 중간 AdminData 대기 실패와 Node 종료 assertion은 재통과했으나 원인 미확정으로 기록했다. 큰 chunk 경고도 유지한다.
- 실제 합성 브라우저: 160건 중 선택 구간 80건·참조 3건, 세 버튼 생성, 노트 저장/새로고침 보존, 원문 71번째 줄, 탐지 전환 시 답변 제거 확인. 좁은 창 참고 패널 1px 축소/버튼 가림을 재현·수정했다. 실제 캡처 6장 포함.
- 지정 Foundation BASE Q4 실제 CPU 짧은 생성 120.969초 성공. 선택 탐지 설명은 598 입력 토큰으로 전체 300초 예산 초과, 검증된 답변 없음. 후속 미조회 안내 수정 전 prompt임을 명시했다. 시험 후 비활성, 브라우저 템플릿 유지. 한국어 SOC 품질 미채택, Instruct/Kanana 다운로드·SFT/adapter 실행 없음.
- 보안 우선 평가 후보 Foundation Instruct/한국어 비교 Kanana 8B를 문서화하고 고정 합성 8사례를 추가했다. Foundation Instruct의 별도 template·serializer는 미지원으로 남긴다. 권리 승인/모델 선택을 변경하지 않았다.
- 사용법: [실제 화면과 Assistant](docs/ASSISTANT-EVIDENCE-GUIDE.md), [검증 기록](docs/ASSISTANT-EVIDENCE-VALIDATION-2026-10-15.md), [모델 반입 가이드](docs/MODEL-8B-KOREAN-SECURITY-GUIDE.md).
- **NEXT:** 후보 template 호환성/정확한 파일 반입과 한국어 8사례 평가, 새 모델 제외 매체 및 깨끗한 LTSC17763·16GB 공동 부하·운영 인수. 기존 10/12 ZIP 미갱신. 운영 데이터·훈련·관리자 설치·운영 모델 교체 승인 경계 유지. 원본 F:/claude/saw는 수정하지 않는다.

## 2026-10-14 통계·시간 변화 강화와 약 8B 모델 후보

- 통계에 출발지→목적지·HTTP 상태·요청 방식, 전송량/오류 정렬, 오류율 분모·누락 표시, 비교 차트와 표시된 통계 CSV를 추가했다. 50그룹 저장소 호출 157→7; 같은 실제 OpenSearch 합성 1만 건의 반복 조회 354~443ms→24~32ms(개발기/서비스 비용만).
- 같은 출발지의 직전 6개 15분 구간 대비 두 지표 이상 변화 후보를 추가했다. 표본·측정값·경계 구간·수집 공백·상한을 안내하며 정상/침해를 확정하지 않는다. 근거 시간 교집합으로 해당 구간 원문만 조회한다.
- 최종 서버 830통과·2건너뜀(234.68초), 화면 132통과(9.06초), tsc/build 성공(21.10초). 실제 격리 PG16.15/OS2.19.6 API 26통과 + 별도 단위 8통과, 시험 프로세스/포트 정리 확인.
- 실제 HTTP/브라우저 합성 160건→변화 후보 1→근거 80건→원문 71번째 줄 확인, 통계 CSV 실제 다운로드와 값/범위 검사. 단계별 캡처 8장과 가상 실습 파일을 추가했다.
- 약 8B 첫 한국어 비교 후보 Kanana1.5 8B Instruct Q4_K_M, 보안 비교군 Foundation Instruct(영어 지원), Qwen3-8B/EXAONE 제약을 문서화했다. 새 모델 다운로드·변환·추론·학습·선택 변경 없음. 지정 Foundation BASE 유지; 16GB 공동 부하/한국어 SOC 품질 미검증.
- 사용법: [통계·시간 변화와 실제 화면](docs/STATISTICS-TEMPORAL-GUIDE.md), [약 8B 후보/다운로드·반입](docs/MODEL-8B-KOREAN-SECURITY-GUIDE.md), [검증 기록](docs/STATISTICS-TEMPORAL-VALIDATION-2026-10-14.md).
- 커밋: a059bc8(통계), ebd8e0f(시간 변화), b046f18(모델 가이드). 상세 화면/최신 인계는 후속 문서 커밋에 포함.
- 게시: 이번 소스·실습·화면·모델 안내를 비공개 GitHub main에 게시하고 원격 commit 일치를 확인했다. 기존 설치 ZIP은 변경하지 않았다.
- **NEXT:** 원본은 계속 읽기 전용. 기존 10/12 ZIP 미갱신; 새 매체 제작·설치/재시작·깨끗한 LTSC17763·16/32GB 공동 부하·모델 호환/한국어 평가·운영 인수는 남는다. 8B 변환용 Python/hf/wheel 완전 lock도 준비 조건이다.

## 2026-10-14 관리자 정리·룰 Export·로그 통계 구현

- 관리자 데이터 관리: 조사 전체·증거 묶음·케이스 폐기, 영향 미리보기·ID/사유 확인·보존/진행/공유 참조 차단·영수증·실패 재시도. 감사와 케이스 리비전은 보존한다. S3 삭제는 미지원이다.
- 룰 화면: 등록·예제·시험·다른 사람 승인·재분석 안내, 기본 JSON/YAML·현재 사용자 룰 묶음 JSON·개별 원본 다운로드. 내보내기는 승인/배포가 아니다.
- 로그 통계: 로그 종류·파일·출발지·목적지·포트, 필터/기간/누락/기타 분모, 원본 이동. 같은 목적지·서비스·15분의 다른 출발지를 비교하는 행동 차이 후보를 추가했다. 표본 부족/잘림은 범위 안내로 남긴다.
- 좁은 화면 중앙 영역과 보조 패널을 보완했다. 합성 정상2,000건+행동 차이80건에서 비교출발지40개/3개 지표를 확인하고 원본80건으로 이동했다. 룰 작성·시험·개별 파일 다운로드와 관리자 예고/차단/완료 영수증을 실제 브라우저에서 확인했다.
- 최종 서버 **805통과·2건너뜀(190.64초)**, 화면 **130통과(26파일)**, TypeScript/build 성공. 실제 격리 PostgreSQL16.15/OpenSearch2.19.6에서 관리자·마이그레이션·bulk33통과1건너뜀, 룰 시험 저장 경계8통과, 재시도 실행자 감사1통과. 통계·Export도 native 실행했다.
- 실제 HTTP 합성 삭제: 케이스→증거5건→남은 조사5건 정리 완료, 대상404, 다른 조사2,080건 보존. 브라우저 최종 삭제 클릭은 실행하지 않았으며 전 과정 브라우저 성공으로 보고하지 않는다.
- 100,000건 합성 벤치(정상99,980/이상20): 후보1개, 탐지3.026초, 최대 작업 메모리118,513,664바이트. 실제 은행 자료 정확도/오탐률을 의미하지 않는다.
- 16GB 모델 우선 시험 후보 Kanana1.5 2.1B Instruct Q4_K_M의 권리/revision/반입 안내를 추가했다. 보안 특화·실제16GB 성능·현재 템플릿 적합성은 미검증이다. 지정 Foundation BASE와 선택 상태는 변경하지 않았고 새 추론/학습은 실행하지 않았다.
- 안내: [화면 따라하기](docs/ADMIN-RULES-ANALYTICS-GUIDE.md), [룰 사용법](docs/DETECTION-RULES-HOWTO.md), [16GB 모델 반입](docs/MODEL-16GB-KOREAN-GUIDE.md), [검증 기록](docs/ADMIN-RULES-ANALYTICS-VALIDATION-2026-10-14.md).
- **NEXT:** 이번 소스는 기존 10/12 ZIP에 미포함이다. 새 매체 제작·설치/재시작 재시험 후 별도 버전으로 배포한다. 깨끗한 LTSC17763·인터넷 차단·16GB 무GPU 공동 접속, 후보 모델 실측/한국어 평가, 운영 인수는 남는다. 운영 자료/서비스 설치/모델 교체 승인은 유지한다.

## 2026-10-12 GitHub 사전 배포 게시 완료

- 비공개 저장소의 실제 설치 매체: https://github.com/dewdorp/SAW/releases/tag/v0.1.0-pilot.20261012
- ZIP `SAW-0.1.0-pilot.20261012-model-free-win-x64.zip`: **1,441,648,065 bytes**, SHA256 `9e8cbacf7bee8862b5c5770d467df3f6bdc3eec5fce83a4152b3280864f67d5c`.
- 고정 배포 소스 `f10a375b653ba655628af01219aa5806092bde97`, manifest SHA256 `14142f0462b63d329bfa71a436a4b679c2761fb9539842cc272fc1d2e06a481c`. 실제 시험본과 실행 payload 해시 동등, ZIP521파일 개별 해시 검증 완료.
- GitHub 첨부8개 모두 원격 크기/sha256 digest 일치 확인 후 prerelease 게시, tag가 고정 소스를 가리킴 확인. 공개 영수증: docs/verification/github-release-2026-10-12.json. 이 게시 기록은 설치 ZIP을 다시 변경하지 않는다.
- 로컬 파일: .release/SAW-0.1.0-pilot.20261012-model-free-win-x64.zip. 설치는 첨부 START-HERE.md, 모델 반입은 LOCAL-MODEL-GUIDE.md, 실제 화면6장은 docs/DETECTION-LIVE-WALKTHROUGH.md를 따른다.
- 다음은 깨끗한 LTSC17763 대상의 오프라인 설치/재시작, 16/32GB 무GPU 공동 접속, 승인된 서비스/TLS/방화벽 인수다. 실제 장비·승인 전에는 운영 완료로 전환하지 않는다. Foundation 한국어·인용 품질 미채택, 실제 Assistant 실패 원인 미확정, SFT/학습 미실행을 유지한다.

## 2026-10-12 최종 설치 매체 검증

- 전체 서버 **743통과·2건너뜀, 184.95초, exit0**. 별도 PostgreSQL migration/API/권한 **48통과**, 화면 **115통과·TypeScript/build 성공**. Windows symlink 생성 권한과 기본 SQLite 실행의 별도 PG 환경은 건너뜀으로 남긴다.
- 최종 시험 매체를 새 폴더에 설치하고 내장 Python/62개 wheel·PostgreSQL·OpenSearch/nori·TLS·스키마0011·최초 관리자를 실제 확인했다. 합성 로그/PCAP 작업2개 완료 후 이벤트9개·Finding8개·노트1개가 전체 종료·재시작 뒤 유지됐다.
- 실제 백업과 별도 복원: PostgreSQL 집계 일치, OpenSearch 신규5색인9이벤트/공유alias0, 증거6파일 SHA256 일치. 최초 재시작 자료유실·두 번째 cold-start 실패·세 번째 복원 alias 보완 기록은 삭제하지 않는다.
- LTSC 기본 curl에 의존하지 않도록 내장 Python으로 TLS/상태/flush를 검사한다. 503·잘못된 인증서·느린 응답·flush 실패를 성공으로 넘기지 않는다. 서비스 코드·구성은 사용자 승인 범위에서 보완했으며 관리자 서비스 설치·방화벽 변경은 실행하지 않았다.
- Foundation-Sec-8B 실제 짧은 CPU 생성은 성공했으나 영어 응답/잘못된 인용으로 **한국어·관제 품질 미채택**. 실제 조사 Assistant 실패 원인은 미확정이며 답변은 저장하지 않았다. 모델 변경 화면은 실제 브라우저에서 확인했다. SFT/optimizer/adapter 학습은 실행하지 않았다.
- 새 설치는 개발 Windows11에서 검증했다. 깨끗한 LTSC17763·인터넷 차단 장비·16/32GB 다중 분석가·조직TLS/관리자서비스·운영 자료/배포 승인 게이트는 남는다. 모델 가중치와 브라우저 설치 파일은 본체 매체에서 제외한다.
- 다음: 문서 확정 후 시험 매체와 실행 payload hash 동등 확인 → 실제 ZIP 및 checksum 생성 → 비공개 GitHub 사전 배포 게시·원격 무결성 확인. 원본 F:\claude\saw는 수정하지 않는다.

## 2026-10-11 새 복사본의 탐지 확장

- 현재 수정 대상은 `F:\codex\SAW-Claude-main`, 브랜치 `codex/detection-packs`입니다. `F:\claude\saw`의 e0a7af5는 읽기 전용 원본입니다. 아래 과거 작업 로그의 경로·검증 결과는 원본의 기록이며 이번 복사본의 실행 결과로 재사용하지 않습니다.
- 원본 추적 소스·문서 397개를 해시 대조하여 복사했습니다. 원본의 운영 자료·비밀값·Git·의존성 폴더는 복제하지 않았습니다. 개발 Python 환경은 원본의 제3자 패키지만 읽기 전용 참조하므로 독립 배포 패키지는 아닙니다.
- 기본 탐지 목록 화면: 묶음·검색·설명·예시·ATT&CK, 권한에 따른 켜기/끄기와 필수 사유. 조직별 NDR 정책은 별도 조회 탭입니다.
- 웹 시그니처 166→184개(공개 취약 경로 2, 관리 API 14, PHP 래퍼 2 추가). 기존 경로 규칙 4개는 ID를 유지하고 표현·경계를 교정했습니다. 매처의 누락 가능성을 수정하고 여러 단계가 섞인 묶음의 결과를 분리했습니다.
- NDR 연결 정책 5종은 YAML 조정 가능하고 기본 비활성입니다. 흐름은 8→11종이며 시간 상한·같은 출발지·순서·미확인 정보 처리를 보강했습니다.
- 승인된 현재 Sigma 버전을 조사 분석에 연결했습니다. 작성자와 승인자 분리, 접근 범위, 완전한 버전별 시험, 미지원 조건 거부, 실행 상한을 적용합니다. 결과는 분석 후보입니다.
- 실제 실행: 읽기 전용 웹 요청 439,461건에 새 184개 규칙의 일치 0건(전 환경 오탐 0% 주장은 아님). 별도 가상 HTTP 서버에서 로그인/MFA·규칙 변경·합성 592줄 업로드→작업 완료→27탐지(흐름 3 포함)를 확인했습니다.
- 자동 검증: 서버 **576 통과·1 건너뜀**(PostgreSQL 주소 필요), 화면 **88 통과**, TypeScript·UI build·변경 서버 Ruff E9/F 통과. 실제 브라우저 렌더링·복사본의 운영 저장소·깨끗한 LTSC 2019 오프라인 설치는 이번 검증에 포함하지 않았습니다.
- 사용법: [탐지 목록 안내](docs/DETECTION-CATALOG-GUIDE.md). 비교·출처·측정·한계: [검증 기록](docs/DETECTION-VALIDATION-2026-10-11.md). 현재 재개 지점: [STATE.md](STATE.md).

## 2026-10-12 실제 화면·저장소 후속 검증

- PostgreSQL16.15/OpenSearch2.19.6 초기 전체577통과, 행동순서 수정 후 native13통과. 개발 Windows11에서 확인했으며 LTSC17763 인수가 아닙니다.
- 실제 브라우저에서 탐지 목록과 작업대 사용을 확인하고 스크린샷6장을 남겼습니다. 시간대 오차/토글 갱신과 같은 시각의 행동순서 불안정을 수정했습니다.
- 최종 SQLite587통과1건너뜀, UI93통과, tsc/build 성공. 환경 갱신으로 중단된 시험은 별도 보존하고 성공으로 세지 않았습니다.
- [화면 사용 안내](docs/DETECTION-LIVE-WALKTHROUGH.md), [검증 기록](docs/DETECTION-VALIDATION-2026-10-12.md).

## 2026-10-12 로컬 모델과 설치 매체

- 별도 모델 반입·해시/형식 검증·명시적 선택/해제와 한글 관리자 화면을 추가했다. 지정 Foundation-Sec-8B BASE의 실제 CPU 생성은 확인했으나 한국어·인용 품질은 미채택이다. 합성 조사에만 사용하며 운영 모델 자동 교체나 학습은 하지 않는다.
- Assistant는 조사 권한·승인 지식·세션·모델 선택을 생성 전후 확인하며 잘못된 형식/인용을 답변으로 채택하지 않는다. 실제 브라우저의 조사 질문 실패 원인은 확인 불가로 보존하고 이후 오류 진단을 분리했다.
- 최종 전체 서버691통과·2건너뜀, UI115통과·tsc/build성공. 실제 PostgreSQL16.15의 모델/권한/마이그레이션48통과. [AI 실행과 화면 기록](docs/LOCAL-AI-VALIDATION-2026-10-12.md).
- 모델 없는 실제 매체로 포함 Python·PostgreSQL·OpenSearch·TLS를 설치했다. 재시작 데이터 손실/PS5.1 기동 오류를 발견해 수정했으며 새 설치 흐름 재검증 중이다. [설치 안내](docs/OFFLINE-RELEASE-2026-10-12.md), [실패와 재검증 기록](docs/OFFLINE-RELEASE-VALIDATION-2026-10-12.md).
- GitHub 비공개 저장소 dewdorp/SAW에 소스를 게시했다. ZIP은 검증 후 사전 배포로 게시하며 깨끗한 LTSC/공동접속 서비스/복원 인수와 구분한다.

## NEXT — 새 복사본

사용자 추가 지시에 따라 로컬 AI 모델 반입·선택, 모델 제외 폐쇄망 설치 패키지, GitHub 비공개 배포물을 진행합니다. 현재 세부 작업과 환경 경계는 [STATE.md](STATE.md)를 따릅니다. 조직 NDR 기준과 운영 모델·운영 배포 승인, 깨끗한 LTSC 설치/재시작/복원 검증은 별도입니다.

## 원본에서 가져온 과거 실행 환경 메모
- 위치: `F:\claude\saw` (git repo), Python venv: `.venv` (Python 3.12), Node 24 + pnpm
- Docker 없음 → PG/OpenSearch/MinIO/Valkey/Zeek/Suricata 미기동. 로컬은 SQLite + 인메모리/SQLite 이벤트 저장소 + 로컬 FS Object Store + In-process Job Runner로 실행.
- 백엔드 테스트: `.venv/Scripts/python -m pytest -q`
- 백엔드 실행: `.venv/Scripts/python -m uvicorn saw.apps.api.main:app --port 8100`
- 프론트엔드: `cd apps/web && pnpm dev` (port 5180, /api → 8100 프록시; 8000/5173은 다른 로컬 프로젝트가 사용 중)

## Phase 상태

| Phase | 상태 | 비고 |
|---|---|---|
| 0 설계 | ✅ | docs/ |
| 1 Foundation | ✅ | Auth(argon2id+TOTP+세션+CSRF), RBAC PDP, Audit 해시체인, Storage Ports(SQLite/LocalFS + OpenSearch/S3 adapter), API 골격 |
| 2 Analyzers | ✅ | Universal, IOC(오프라인 fixture + 내부 Context), HTTP, Payload, Patterns(휴리스틱; libinjection은 ENV-15) |
| 3 Diff/Log/Timeline | ✅ | Request Diff(붙여넣기+로그 이벤트), Parser 10종, Single Log, Timeline collapse |
| 4 Workbench/Finding/Story/ATT&CK 기본 | ✅ | React Workbench(11 탭), Finding/Story/Timeline/Relations(그룹화)/ATT&CK/Raw/Notes, Case, Cross-highlight, 브라우저 검증 완료 |
| 5 Bulk Log | ✅ | Resumable upload, Safe extract, Parse/Index, Web detectors 10종, Pattern(Drain3), Parameter, Job SSE, 고아 Job 복구 |
| 6 PCAP (Zeek/Suricata 정규화) | ✅ | Zeek JSON/TSV·eve.json 파서, 네트워크 탐지기 8종, Network Overview/Story UI, 도구 실행 Adapter(ENV-06) |
| 7 Unified/Correlation | ✅ | same-IP cross-source + finding chain 상관, clock skew 설정/표시, 통합 Timeline |
| 8 Experience/Asset | ✅ | Experience(4-eyes, draft 비공개, 승인본 유지 revision, 만료), Asset(CRUD/CSV/매칭/Detector baseline/Context), FP rule(충돌검사·표시만), Playbook, Knowledge UI |
| 9 Similar Case | ✅ | Hybrid(feature·vector·BM25), 점수 분해, Same/Different, Context Panel, Similar 화면; 임베딩은 해시 fallback(ENV-09) |
| 10 Connector(Mock) | ✅ | SecurityDataConnector, MockLogpresso(fixture), 실제 Logpresso는 미구현(ENV-11), 비밀값 암호화 write-only, IOC 내부 Context 연동, Investigation import(custody·멱등), Integrations UI |
| 11 Local LLM | ✅ | Provider 추상화(Ollama/OpenAI-compat=ENV-08, 사설망만 허용), 오프라인 TemplateProvider(LLM 아님 표기), 신뢰/비신뢰 분리 프롬프트·랜덤 경계·지시문 탐지, 인용 검증, 감사(프롬프트 원문 미저장), Assistant UI |
| 12 Anomaly | ✅ | Volume(robust z, band), Rare(history: 정상 종결만), Sequence(Markov), Entity(HBOS, 기여도), Relationship(first-seen); 시각화(밴드·시퀀스 비교) |
| 13 Hunting | ✅ | Hunt session/steps(근거 필수, ai 수락자 기록), 결정적 Pivot, 예산·권한, Finding 생성, UI(흐름 그래프·이력·Pivot), ATT&CK inferred→가설 연결. 브라우저 검증 완료 |
| 14 Detection | ✅ | Finding→Sigma/Suricata 후보, pySigma 검증·OpenSearch(CES 매핑) 변환, 로컬 Sigma 평가기 Historical Test(TP/FP/미라벨·일일추정·unit test), 4-eyes 승인, 배포는 기록만, 버전, Coverage Heatmap·Navigator layer, UI |

## 작업 로그
(아래에 날짜·완료 항목·테스트 결과를 누적)
- 2026-10-06: Phase 1 완료 (15 tests). Phase 2 완료 + Phase 3 일부(Diff, Parser framework, single log) — 총 34 tests green.
- 2026-10-07: Phase 3-5 백엔드 + Phase 4 UI 완료. 백엔드 42 tests, 프론트 vitest 4 tests, vite build OK.
  브라우저 검증(포트 5180/8100): 로그인+MFA, Home, Workbench Overview/Findings/Finding Detail/Story/Timeline/Relations/ATT&CK, 업로드→Job→COMPLETED.
  브라우저 검증 중 발견·수정: (1) uvicorn lazy app (2) Story 레이아웃 전 렌더 (3) Graph 가독성 → Group by(cloud/asn/country) + 유형별 cap
  (4) csv.Sniffer ReDoS로 Job 정지 → 결정적 구분자 판별 + 회귀 테스트 (5) 재시작 시 고아 Job 자동 재큐잉.
  - Phase 6/7 완료: 네트워크 E2E 3 tests, 데모 Investigation에 Zeek/Suricata 증거 추가(통합 화면 브라우저 확인).
  - Phase 8/9 완료: 5 tests, 시드에 Asset·과거 사례·승인 Experience 추가, Context Panel 브라우저 확인.
  개발 계정: `python -m saw.devtools.seed` (비밀번호만 var/dev-credentials.json). MFA는 첫 로그인 시 QR 등록. 재설정: `python -m saw.cli reset-mfa <user>` 또는 Admin › Users. (자동화용 TOTP: `python -m saw.devtools.seed totp <user>`)

## 작업 로그 (계속)
- 2026-10-07: Phase 14 완료(4 tests). 브라우저 검증: ATT&CK→Hunting 시작→질의/Pivot, Finding→Detection 후보→Historical Test(TP 461/FP 0, PASS), Coverage Heatmap.
  검증 중 수정: ATT&CK 데이터 컴포넌트 매핑이 SAW data_source 이름과 불일치(가시성 오판) + 회귀 테스트, Hunt 그래프 확대 제한.
  프론트 code-splitting: 초기 번들 2MB+ → 267KB (Workbench/Hunting/Detection/Knowledge lazy).

- 2026-10-07: [버그] MFA 사용 불가 — 시드가 MFA를 사전 등록(키는 파일에만)해 사용자 인증 앱에 계정이 없었음. 수정: 사전 등록 제거, 등록 화면 QR(로컬 canvas 렌더), 관리자 MFA 재설정(API/UI/CLI, 세션 폐기·감사), 테스트 추가, 브라우저로 QR→코드→로그인 확인.

- 2026-10-07: MFA 후 로그인 루프 수정 — FastAPI 0.142의 yield 의존성은 응답 전송 *후* 종료되어 mfa_passed 커밋 전에 /auth/me가 401을 받음. 모든 Depends(db)를 scope="function"으로 변경(응답 전 commit/rollback) + 회귀 테스트, 브라우저 클릭 로그인·새로고침 유지 검증.
- 2026-10-07: 운영 대상 확정(Windows 10 LTSC 2019, 폐쇄망) → ADR-0016. 내장 PCAP 분석기(pcapkit: PCAP/PCAPNG→Zeek 호환 conn/dns/http/ssl, JA3/JA4 공식 벡터 일치, 세션 PCAP 추출), 운영 모드(웹+API 단일 HTTPS, make-cert, CSP 위반 0), OpenSearch 2.19.6 어댑터 수정·검증(템플릿/alias/refresh/terms total), PostgreSQL 16.15 검증, PG+OpenSearch 동시 전체 테스트 통과, 비밀번호 변경/임시 비밀번호, 오프라인 설치 묶음(build-bundle/install/backup/uninstall .ps1) + 설치본 dry-run E2E, docs/INSTALL-WINDOWS.md.
- 2026-10-08: Codex 구현 비교 → 채택(ADR-0017): Alembic 마이그레이션, ATT&CK 19.2 공식 카탈로그(compact), SBOM·라이선스 고지, Idempotency-Key·작업 임대, 근거 유형(관측/계산/추론/판정). PCAP 포렌식 v2(pcap-forensics-analyzer 범위 참고, 코드 미사용): 재조립·HTTP 본문·파일 추출·평문 인증·FTP 데이터·ARP·탐지기 9종·스트림 보기·HTML 보고서·CSV. UI/UX 개편(사이드바, 한글 메뉴, 페이지 머리말, 숫자 타일, PCAP 포렌식 탭). 버그 수정: 관계 재구성이 IOC/붙여넣기 엔티티를 지우던 문제.
- 2026-10-09: TXT/CSV 자동 감지 개선(사용자 NDR CSV 업로드가 일반 CSV로 처리되어 탐지 무효 + 212 eps): NDR 메타 검색 CSV 파서(요청·응답 짝짓기 → web, traffic → zeek_conn, 쿠키 값 미저장·raw 마스킹), 일반 CSV 열 이름 정규화(영문 변형·한글), 열 구성 기반 data_source 추론(web/waf/네트워크), CP949·BOM 판별, 빈 열 허용, 한국식 시간 형식, 줄 읽기 O(n²) 수정, 네트워크 소스 drain3 제외. 59MB 실파일 parse 216→1,218 eps. 샘플 12/13, 테스트 12개 추가(전체 97 중 96 통과·1 skip).
- 2026-10-09: 저사양 PC 대용량 처리(ADR-0018): 구조화 소스 raw_event 미저장+원본 파일 읽기(인코딩·마스킹 유지), 지연 마스킹, SQLite json 투영·OpenSearch _source 제한, 파라미터 프로파일 단일 패스, OpenSearch 단일 노드 튜닝(best_compression·translog async), 작업 동시 1개, 바이트 진행률·남은 시간·재시작 체크포인트, install.ps1 -LocalOnly·메모리 자동 산정, 작업 화면 한글화. 59MB NDR: OpenSearch 힙 1GB 기준 전체 약 35~40초(이전 파싱만 약 8분), 인덱스 20MB.
- 2026-10-09: Codex 재비교 후 채택: 재개 체크포인트 검증(파서 버전·마지막 이벤트, 불일치 시 파일 재색인), 따옴표 안 줄바꿈 CSV(64줄 상한, 실패 후 재읽기), 처리 범위(coverage) 보고서, IE11 안내. 관리자 권한 없는 설치 install.ps1 -NoAdmin + saw-ctl.ps1(사용자 프로세스, 시작 메뉴, 로그온 자동 시작) — 비관리자 셸에서 설치·시작·중지·재시작·제거 실검증. 기존 결함 2건 수정: 파일에 (OI)(CI) ACL → 빈 DACL로 .env 읽기 불가, requirements에 psycopg-binary 누락 → libpq 없음(서비스 설치도 해당).
- 2026-10-09: 사용자 파서(FR-LOG-11): 코드 없이 설정으로 정의(구분자·정규식·키=값·JSON, 칸 펼치기, 필드 연결, 저장 안 함·가림, 시간 형식·시간대, 자동 감지 조건), 버전 관리·감사, 내보내기/가져오기, 자동 제안·미리보기 마법사(파서 관리 화면), 작업 화면의 '새 파서 만들기'·'다른 파서로 다시 처리'. 재처리 시 같은 증거의 다른 파일까지 다시 처리하도록 수정. 미사용 CustomRegexParser 제거.
- 2026-10-09: PCAP 고도화 ①②: NDR·웹 로그·WAF 이벤트 ↔ PCAP 세션 연결(같은 IP·포트 ±5분, 포트 없는 웹 로그는 출발지·경로 ±5초) — 이벤트 상세 '연결된 기록' 탭, NDR 이벤트에서 바로 스트림 보기·세션 PCAP. TLS 서버 인증서 분석(TLS≤1.2 평문 인증서 파싱, JA3S, 발급자·유효기간·SAN·지문·키), 'Suspicious TLS Certificate' 탐지(자체 서명·이름 불일치·만료·발급 직후·약한 키, 외부 목적지), IOC 해시를 JA3/JA3S/인증서 지문과도 대조, PCAP 포렌식 'TLS 인증서' 탭. 샘플 14.
- 2026-10-10: 처리 기록(provenance): 증거 처리마다 처리자·입력 SHA-256·파서/버전·파서 지문(사용자 파서=설정, 내장=소스 코드)·설정 지문·결과 지문을 자동 기록하고 감사 해시 체인에도 기록, 검증 API(재계산+감사 사본 대조). 분석가=내 조사, 매니저=통합(분석가별·파서별, 같은 입력·다른 설정/초안 처리/정의 변경 경고), 관리자=통합 요약(파일명·제목·설정 비공개). 파서 초안→공용 요청→다른 사람 승인(4-eyes), 초안은 작성자만 사용(u:slug@N). 결함 수정: 크기 열 int4(PG 2.1GB 초과 불가)→BigInteger, SQLite 마이그레이션이 데이터 있는 DB에서 외래키로 실패→마이그레이션 중 FK 끔·이후 복구, create_all 개발 DB 대비 0003/0004 멱등. PG 실검증 122/122.
- 2026-10-10: Codex 재비교(2026-10-09 보고서)에서 지적된 결함을 재현 후 수정. ① 보안: MFA 오답 횟수 제한·잠금, 같은 코드 재사용 차단, 등록 계정은 MFA 선택 설정에서도 코드 필수, 경험 승인 4-eyes를 "지난 승인 이후 수정한 모든 사람"으로 확대, HTTP 분석의 JSON·이중 인코딩 비밀값 가림, 감사 체인 끝부분 삭제 감지(head 행 + 데이터 폴더의 앵커 파일). 추가 발견: 동시 요청 시 감사 체인이 갈라짐(PG에서 30건 중 10건이 같은 부모) → head 행을 먼저 잠그도록 수정. 마이그레이션 0005. ② 데이터 정확성: NDR 짝짓기 키에 장비·스트림·양 끝점 포함(실파일 결과 동일), 검색엔진이 확인한 건수만 완료 처리(영구 거부=보고, 일시 장애=배치 실패 후 체크포인트 재개), 중복 열 이름 보존·안내, 0점 파서 선택 방지와 붙여넣기 다중 행 CSV, 잘린 gzip 표시, 웹셸 "사용" 조건 강화. ③ PCAP: 정확한 시각(ns)·PCAPNG tsoffset, 잘림/손상 판별, 패킷 빠진 세션 표시(HTTP capture_gap, 구멍 걸친 TLS 지문·인증서 미계산), 세션 추출의 프로토콜·링크 유형 분리와 정수 시각. ④ 설치: 서비스 XML 이스케이프, .env·opensearch.yml UTF-8(BOM 없음), 위험 문자 폴더 거부, 공동 서버는 translog request. ⑤ 화면: 원본 로그·타임라인 20,000건 상한. 결정: 관제 매니저의 전체 조사 열람·수정 유지, OpenSearch 보안 플러그인 미사용 유지(폐쇄망).
- 2026-10-10: 보고 기능. ① 보고용 요약(조사 1건 → 한 장: 결론·경위·영향·조치·남은 일·근거·자료·유의점, 탐지 결과와 종결 기록에서 자동 작성, 항목별 직접 수정·되돌리기, IP 끝자리 가림, 인쇄/PDF, 단일 HTML 내려받기·감사), ② 현황판(/board: 진행·높은 위험·멈춘 조사, 판정·위험도 분포, 주별 접수·종결, 담당자별, 우선순위 목록; 매니저=전체, 분석가=참여 조사). 마이그레이션 0006. 사용자 NDR 조사 점검: 10/8에 일반 CSV로 처리되어 탐지 0건·SQLite 79만 건으로 느렸음 → 개발 저장소를 OpenSearch로 옮기고 NDR 파서로 재처리(59MB 44초, 608MB 5분, 72만 건). 실데이터에서 발견한 결함 2건 수정: 로그인 무차별 시도 탐지가 실패 0%인 공유 IP(통신사·사무실)까지 95건 보고 → 거부 응답 또는 다수 계정이 있을 때만(1.1.0); 재분석 때 더는 근거 없는 탐지가 남던 문제 → 손대지 않은 자동 탐지는 제거(평가·케이스·수동 탐지는 유지), 탐지 번호는 최대값+1.
- 2026-10-10: 협업 1·2단계(운영 원칙: 조사는 1인 책임, 확인 근거는 팀이 재사용, 중요한 결론은 타인 검토). ① 확인 기록(inv_check, 마이그레이션 0007): 대상=기록·엔티티·탐지·검색 결과, 확인 질문 4종(요청 성격/성공/피해/정상 업무)과 판단을 분리, 표본·전체 구분, 변경은 대체 기록·취소는 사유와 함께 보존, 표의 확인 열(직접 ✓ / 상위 대상 ↑), 보고용 요약 연동. ② 팀 확인 정보: 엔티티 확인을 사실·확인 범위·미확인 범위로 공유, 다른 조사에서 참고로 표시(판정·탐지에 영향 없음), 확인 당시 조건과 현재 조건 비교(같음/다름/비교 불가), 유효 기간(정상 90일·악성 180일), 근거 기록만 가려서 열람(감사), 근거 연결(직접 확인과 구분), 재확인 요청, 수정·철회 시 인용한 조사에 알림. GPT 요구서에서 실시간 공동 편집·현재 활동 표시는 업무 방식(각자 조사)에 맞지 않아 제외.
- 2026-10-10: 협업 3~5단계. ③ 검토 요청(inv_review, 0008): 높은 위험 탐지의 정상·오탐 평가와 공격 판정 종결은 자동으로 검토 대상(업무는 막지 않고 조사·현황판·보고용 요약에 표시), 검토자 지정(본인 불가, 읽기 권한 부여, 자료 한계 자동 전달), 답변 4종+동의 범위 한 줄 필수, 승인은 그때의 결론에만 유효(이후 변경 시 재검토 필요), 홈 화면 수신함. ④ 종결 전 점검 5가지(범위·미확인, 핵심 탐지 평가와 상충 판단, 시도·성공·피해, 조치·남은 일, 검토)와 '범위 제한' 기록, 종결 창 한글화. ⑤ 분석 지원(inv_support, 0009): 담당자·매니저가 질문 하나를 동료에게 요청(편집 권한 부여), 지원자 완료 보고(결과·미확인), 지원자는 그 조사의 결론 검토 불가. 현황판에 검토 대기·지원 진행 표시.
- 2026-10-11: 탐지 묶음(데이터로 된 탐지 내용 — 폐쇄망에서 AI 없이 추가·조정 가능하게). 시그니처 166종 10묶음(공격 도구, 수집 서비스, 공개 취약점, OS 명령, 웹셸, 국내 편집기·게시판 업로드, 관리 화면, 정보 노출, 값 조작, CMS)과 공격 흐름 8종(packs/*.yaml). 수집 때 sig:<id> 태그, 탐지기는 태그 집계(성공 응답은 규칙별, 거부된 시도는 묶음당 한 줄), 규칙별 끄기(마이그레이션 0010, API), 규칙마다 예시 자동 시험. 실제 NDR 요청 44만 건에서 오탐 0건(처음 1종 4건은 규칙 수정). 미완: 목록·끄기 화면, 속도 개선(요청당 50~80µs), 내용 확장. 이어받기 안내 docs/HANDOVER.md, AGENTS.md.

## 원본의 이전 NEXT (참고 기록)
1. 서버 현장: 관리자 권한으로 install.ps1 실행 → 서비스 자동 시작·재부팅·방화벽·인증서 배포 확인 (ENV-19~21)
2. 백업·복구 리허설 (ENV-22), 저사양 서버 성능 측정 (ENV-13)
3. (선택) Suricata Windows IDS 경보, Monaco 편집기, Case PDF/DOCX export, Custom Parser UI


## 2026-10-20 관계사별 장비 분석 통합 개선 — P0 설계 검토
- 최신 첨부 2문서를 읽고 P0 코드 감사·설계·요구사항/인수 대응표를 작성했다. 제품 기능을 구현한 상태는 아니다.
- 기준 HEAD 4072e9d, 검토 브랜치 codex/affiliate-p0-20261020. 원본 F:/claude/saw·운영 데이터·기존 릴리스 보존.
- [설계와 P1–P5 계획](docs/plans/affiliate-soc-design-20261020.md), [대응표](docs/verification/affiliate-p0-matrix-20261020.md), [이번 검증 영수증](docs/verification/affiliate-p0-validation-20261020.json).
- 의심8개 영역의 실제 연결 차이를 확인했다. 추가로 CSV/Zeek 바이트 방향 차이를 합성 입력으로 재현했다. 기존 정책 의도와 새 요구의 차이를 버그와 구분했다.
- 이번 관련 서버650통과(30파일547 + 추가7파일103), 화면177/31파일·TypeScript exit0. 임시 SQLite·합성/DOM 자동시험이며 전체 서버·native PG/OS·실제 브라우저·LTSC 신규 인수는 아니다.
- 독립 설계 검토에서 원천 ACL/전체 재계산 자료완전성/Export 호환·모델별 변환/IPS·DDoS 실제 분석 범위를 보완했다.
- 새로운 기능·DB/schema/index·UI build·설치 ZIP·GitHub 게시 없음. 새 문서는 로컬 승인 검토본으로 아직 커밋하지 않았다. 기존 배포 source26f5d1a/schema0014는 유지한다.
- 다음: 최신 요구15절의 설계 승인 후 P1(관계사·장비·품질·서비스 미지정 FW 한 흐름)부터 P5까지 의존 순서로 구현·회귀. 정상 단계마다 승인 대기를 반복하지 않는다. 운영 DB 변경·관리자 설치·반출·운영 배포는 별도 승인.
- 기존 History503·권한 metadata 조회4건 원인 미확정, 깨끗한 LTSC2019/16GB 공동부하·운영 인수 게이트는 유지한다.
