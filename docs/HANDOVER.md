## 2026-10-21 P2 검증 완료 · P3 연속 진행
- 룰·정책 초안/승인/활성본을 분리하고 정확 버전 시험·독립 승인·적용·복구를 연결했다. WAF/IPS/DDoS/NDR 장비별 분석과 단위·누락·부분 상태를 구현했다.
- 전체 서버1960통과/6건너뜀/1실패(1770.30초). 새P2안내·스크린샷의 매체 누락 1건을 고친 뒤 해당 전체 매체 회귀67개가 통과했다. 전체시험 시작 뒤 PostgreSQL JSON DISTINCT 오류를 좁은 EXISTS 쿼리로 수정했으며 해당 회귀6개와 실제 저장소11개를 별도로 통과했다.
- 전체 웹268개/43파일(독립 QA 시험1개 포함)·TypeScript·Vite 빌드 통과. 실제 PostgreSQL16.15/OpenSearch2.19.6에서 최초21개와 최종11개 통과·정상 종료를 확인했다. 중간 native 실패8통과/1실패/2미실행 이력은 보존한다.
- 실제 합성 브라우저: 선택한6개 양성/3개 음성 기록으로 TP1/TN1, 작성자 승인 차단, 다른 검토자 API 승인·적용 후 초안v3를 저장해도 활성v2 유지 확인. DDoS 숫자·단위·상속 폼도 확인했다.
- 파생 Finding/이야기/분석이력/보고/룰복사/내보내기의 원천 권한을 보존하도록 독립 검토와 회귀를 보완했다.
- 다음 P3 후속확인 버전·HTML/8시트 Excel·다중조사 내보내기를 진행한다. 이후 P4·P5 검토·모델제외매체·비공개 새릴리스까지 단계별 재승인 없이 계속한다.
- 새 패키지·릴리스와 운영 인수는 아직 없다. LTSC2019/16GB·관리자서비스·History503/과거 권한조회4건 원인 미확정은 별도다.

- [P2 검증](verification/affiliate-p2-validation-20261021.md) · [실제 화면 안내](AFFILIATE-DETECTION-GUIDE-20261021.md).

## 2026-10-20 P1 검증 완료 · P2 연속 진행
- 관계사/장비·불변 증거 맥락, FW 세션/누적 해석, 원천 ACL, 범위 Job·실행/보고 snapshot 및 화면을 구현했다.
- 서버 전체1833통과/6건너뜀(1458.83초). 실행 도중 추가한 최종 시간 해석/정밀도는 별도50/70개 회귀와 독립 재검토로 확인했다. 최종 전체웹230개/35파일·TypeScript/Vite 빌드 통과.
- 전용 실제 PostgreSQL16.15·OpenSearch2.19.6·Nori2.19.6에서16개 통과/0실패/0건너뜀(133.50초), 정상종료·시험포트닫힘 확인.
- 최초 native wrapper hook 오류와 후속 디스크 flood-stage 보호429×14는 실패 이력으로 보존. 전용시험에만 free-space low20gb/high12gb/flood6gb를 적용하고 보호기능을 유지했다. 운영/제품기본설정은 변경하지 않았다.
- 실제 합성 브라우저: 로그인/MFA→범위분석→9기록/1세션/6거부/1후보→6근거원문→불변HTML, 프로필v2저장 후 기존증거v1유지 확인.
- 검증: [P1 기록](verification/affiliate-p1-validation-20261020.md), [실제 저장소 영수증](verification/affiliate-p1-native-20261020.json), [화면 사용법](AFFILIATE-FW-GUIDE-20261020.md).
- 다음 P2 정책/룰 초안·승인·활성본 분리와 선택 정답 시험/5장비 분석. 이후 P3→P4→P5 검증·검토·모델제외매체·비공개 새릴리스까지 승인된 순서로 계속한다.
- 아직 새 패키지·릴리스는 없다. LTSC2019/실제16GB·관리자서비스·운영 인수와 History503/과거권한조회4건 원인 미확정은 별도로 유지한다.

## 2026-10-20 관계사별 장비 분석 통합 개선 — P0 설계 검토
- 최신 첨부 2문서를 읽고 P0 코드 감사·설계·요구사항/인수 대응표를 작성했다. 제품 기능을 구현한 상태는 아니다.
- 기준 HEAD 4072e9d, 검토 브랜치 codex/affiliate-p0-20261020. 원본 F:/claude/saw·운영 데이터·기존 릴리스 보존.
- [설계와 P1–P5 계획](plans/affiliate-soc-design-20261020.md), [대응표](verification/affiliate-p0-matrix-20261020.md), [이번 검증 영수증](verification/affiliate-p0-validation-20261020.json).
- 의심8개 영역의 실제 연결 차이를 확인했다. 추가로 CSV/Zeek 바이트 방향 차이를 합성 입력으로 재현했다. 기존 정책 의도와 새 요구의 차이를 버그와 구분했다.
- 이번 관련 서버650통과(30파일547 + 추가7파일103), 화면177/31파일·TypeScript exit0. 임시 SQLite·합성/DOM 자동시험이며 전체 서버·native PG/OS·실제 브라우저·LTSC 신규 인수는 아니다.
- 독립 설계 검토에서 원천 ACL/전체 재계산 자료완전성/Export 호환·모델별 변환/IPS·DDoS 실제 분석 범위를 보완했다.
- 새로운 기능·DB/schema/index·UI build·설치 ZIP·GitHub 게시 없음. 새 문서는 로컬 승인 검토본으로 아직 커밋하지 않았다. 기존 배포 source26f5d1a/schema0014는 유지한다.
- 다음: 최신 요구15절의 설계 승인 후 P1(관계사·장비·품질·서비스 미지정 FW 한 흐름)부터 P5까지 의존 순서로 구현·회귀. 정상 단계마다 승인 대기를 반복하지 않는다. 운영 DB 변경·관리자 설치·반출·운영 배포는 별도 승인.
- 기존 History503·권한 metadata 조회4건 원인 미확정, 깨끗한 LTSC2019/16GB 공동부하·운영 인수 게이트는 유지한다.

---

## 2026-10-20 최종 배포 ZIP 직접 재검증 및 릴리스 문서 추가

- 게시 ZIP을 직접 해제해 시작48.32초·점검38.21초·업데이트485.55초·복구488.11초 PASS. 계정/MFA·DB/색인·원본/설정 보존, 같은 계정 로그인, 새 객체 별도 보관, 계정 정리·정상 종료28.77초까지 확인했다.
- 관련14파일 회귀618통과·1POSIX건너뜀·2기존경고·실패0. Windows11/PS5.1/NoAdmin의 실제 WinForms 버튼 이벤트 시험이며 대상 LTSC 관리자 서비스 인수와 구분한다.
- 실행 코드·ZIP·manifest·기존9자산은 유지하고 최신 HTML/Markdown/JSON3문서를 비공개 사전 배포에 추가했다. 원격12자산 크기/digest·tag 및 main/이전릴리스 보존 확인. 실제 화면3장 내장/브라우저검증 완료.
- [최신 안내](UPDATER-RECHECK-20261020.html)와 [검증 기록](verification/updater-release-recheck-20261020.json)을 우선한다. 원본Claude/운영설치 보존. LTSC/관리자SCM/UAC/443/재부팅·조직서명·물리폐쇄망/공동부하·운영인수와 과거권한조회4건/History503 원인은 계속 미확정이다.

## 2026-10-20 업데이트 안정화 매체·PR 제출 완료

- 비공개 사전 배포 v0.1.0-pilot.20261019에 실제 모델 제외 전체 ZIP·그림 안내·검증 기록 등9자산을 게시했다. ZIP1,445,832,542바이트, SHA256 b9d7e0e7d9b3658c17690dcd276b072c03bb3330518431e1eba4e04d56b30cb5,677항목 검증 PASS.
- 매체 source26f5d1a448668c127383c2e73d47d60d00ed2a28와 후보7 실행payload 동일성, SBOM/라이선스(발행 필드 제외), 원격9자산 크기·digest 및 실제tag 확인. 최종 ZIP 자체의 native 재실행과 구분한다.
- 통합 PR https://github.com/dewdorp/SAW/pull/3 제출. main723e2a6·이전4개 릴리스와 원본Claude·운영C:/SAW 보존. 후속 문서 커밋만 추가한다.
- 최종 서버1733/6skip,웹177/TypeScript PASS. 실제 합성 적용492.39초·복구497.54초·계정/MFA/자료보존·새객체보관·정상종료 PASS. HTML10화면 내장/브라우저10개로드·단계이동 확인.
- 대상 LTSC17763·관리자 서비스/UAC/443/재부팅·조직서명/물리폐쇄망/공동부하·운영 승인은 별도다. 기존 후보6 권한조회 실패의 정확한 원인은 미확정으로 유지한다.
- 게시: https://github.com/dewdorp/SAW/releases/tag/v0.1.0-pilot.20261019. 매체 안의 START-HERE와 그림 안내를 사용하며 수동 hash 대조 없이 자동 검증한다. 상세 봉인·게시 영수증은 verification/updater-release-20261019.json 및 github-updater-stabilization-20261019.json에 기록했다.

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

> **현재 상태와 다음 작업은 [STATE.md](../STATE.md)를 먼저 확인하세요.** 아래 날짜별 내용은 실행 당시의 인계 이력입니다. 2026-10-18 정리에서 오래된 후보 매체는 삭제했고 최종 매체·복구본·검증 기록은 보존했습니다. 과거 후보 경로를 현재 존재하는 매체로 가정하지 마세요.

## 2026-10-19 기존 설치 업데이트 안정화 — 검증 진행 중

- 통합 브랜치 codex/updater-stabilization-20261019에서 상태 소유권·OWNER RIGHTS/NetworkService ACL·Procrun 양쪽 registry view·서비스/프로세스 식별·구형 설치 기준·9행 점검 UI·복구 중단 재개를 보완했다. 기존 서비스 재등록, registry 복사, 설치 ACL 자동 수리를 사용하지 않는다.
- 후보6에서 실제 업데이트 508.17초, 계정·MFA 로그인 및 자료 보존 대조를 통과했다. 이어진 복구 첫 시도는 40.52초에 설치 권한 사전 검사(unsafe_access/validate)에서 실패했다. 서버 중지·복구 이전에 차단됐으며, 복구본 검증 결과는 정상이다. 자동 승인 검토가 합성 진단 읽기를 거부했으나 사용자의 명시 승인 후 오류 종류·건수만 확인했다. 32,690개 중 metadata 조회 실패4건이며 직접 원인은 아직 미확정이다.
- 후보6 동결코드의 전체 서버 재시험은 1,647통과·6건너뜀·2경고, 1,376.79초로 완료했다. 경고는 Starlette/httpx 변경 예고와 JUnit record_property 형식이다. 웹177통과·TypeScript 성공. 이후 안전한 권한 오류 원인·건수의 화면 표시를 보완 중이며, 이 변경의 검증과 실제 복구는 별도다. 새 최종 ZIP·게시·통합 PR은 아직 없고 후보5의 복구 성공을 후보6의 성공으로 표시하지 않는다.
- 대상 Windows 10 Enterprise LTSC 2019 x64 build 17763·PS5.1의 실제 관리자 서비스/UAC·HTTPS 443·재부팅 인수는 미검증이다. 개발 PC build 26200의 시험과 구분한다.
- 운영 C:/SAW·D:/SAW-0.1.0과 원본 F:/claude/saw는 변경하지 않는다. 설치 점검은 서비스 중지나 설치 변경을 하지 않으며 별도 보호 작업 폴더와 유지보수 잠금을 사용할 수 있다.
- [새 사용자 안내](UPDATER-STABILIZATION-GUIDE-20261019.md) · [그림 안내 HTML](UPDATER-STABILIZATION-GUIDE-20261019.html) · [24단계 흐름·PR 통합 감사](verification/updater-flow-audit-20261019.md) · [LTSC 현장 읽기 전용 점검](verification/updater-native-acceptance-20261019.md). 안내의 그림01–03은 합성 UI 렌더다. 그 밖의 실제 합성 설치 실행 화면은 후보와 성공·실패 범위를 구분하며 대상 운영 인수의 증거가 아니다.

---

## 2026-10-18 더블클릭 업데이트 매체 게시 완료

- [비공개 GitHub 사전 배포](https://github.com/dewdorp/SAW/releases/tag/v0.1.0-pilot.20261018.1)에 모델 제외 전체 매체와 그림 안내 등 9자산을 게시했다. 원격 크기·SHA256과 source tag를 대조했다. 이전 배포는 보존한다.
- ZIP: SAW-0.1.0-pilot.20261018.1-model-free-win-x64.zip, 1,444,865,907바이트, SHA256 971dda3d2c5ef4449e8efbdd47a1d4585e1804788192e5e2ef9302cfa0ab18d5. 내부665항목(663 payload + manifest/체크섬) 전부 크기·hash 확인. 최종 manifest 4121605a5e1f76ed821c0fbbbfac95d6baf6822153868eef0eb14f2cb15b1583.
- 매체 소스4655fbba7cd0d16f42379b14bfcbac147a589925. 실제 합성 설치에서 성공한 후보2와 최종 실행 payload/런타임/의존성 동일성을 확인했다. 최종 ZIP의 차이는 게시 문서와 메타데이터이며 실제 업데이트·복구를 ZIP으로 다시 실행했다고 보고하지 않는다.
- 사용: 새 ZIP을 기존 설치 밖에 해제 → UPDATE-SAW.cmd 더블클릭 → 기존 C:\SAW 선택 → 설치 점검 → 서버 중지 동의 → 업데이트 시작. 수동 명령·해시 대조 없이 자동 매체 검증과 전체 복구본 생성을 수행한다.
- 문제 시 같은 창의 이전 상태 복구로 백업 시점 전체를 되돌린다. 업데이트 이후 새 자료와 계정 변경을 자동 병합하지 않으며, 복구 직전 상태는 별도 보관한다. 원본 Claude·사용자 C: 설치·운영 자료는 변경하지 않았다.
- [그림 안내](DOUBLE-CLICK-UPDATE-GUIDE.html), [패키지 봉인 검증](verification/offline-desktop-release-2026-10-18.json), [GitHub 게시 검증](verification/github-desktop-update-2026-10-18.json).
- 실제 Windows11/PS5.1 NoAdmin 합성 업데이트474.55초·복구406.54초, 동일 계정/MFA 로그인과 기준 자료 보존 PASS. 깨끗한 LTSC17763·실제 관리자서비스/UAC/재부팅·물리폐쇄망·공동부하·강제전원중단·운영 인수는 미검증/승인 전이다. 해당 환경 검증이 다음 인수 작업이다.

---

## 2026-10-18 더블클릭 업데이트·복구 실제 검증

- 새 매체의 UPDATE-SAW.cmd와 한글 WinForms 창으로 점검·중지·전체 복구본·앱 교체·재기동·복구를 실행한다. 사용자의 명령 입력/수동 해시 비교는 없다. 자동 전체 매체 검증, 동일 유지보수 잠금, 계정·권한·MFA·DB·색인·원본·설정 보존을 유지한다.
- 실제 Windows11/PS5.1 NoAdmin 합성 설치에서 후보2의 업데이트 474.55초 / 전체 복구 406.54초 PASS. 업데이트 전후·복구 후 계정2/이벤트9/Finding10/증거2/노트1/완료작업2, 암호hash·역할·MFA·원본·설정·키·TLS 동일 확인. 같은 계정/MFA로 HTTPS 로그인 PASS.
- 업데이트 뒤 만든 가상 파일98bytes가 복구된 설치에서는 빠지고 별도 보관 폴더에 그대로 남는 것을 확인했다. 합성 계정 비활성·세션 취소와 PG/검색/API 전체 종료까지 완료했다.
- 첫 후보는 PG slash 경로와 JVM의 System32 conhost 검사에서 중지 전에 실패했다. 경로 동등성 및 정확한 부모/자식·실행파일·인자·생성시각/보유handle 검증으로 고친 후 새 후보에서 실제 성공했다. 실패 기록도 유지한다.
- 기존 서버1232 PASS/5skip, UI177 PASS/tsc0, native GUI59 PASS/worker17 PASS, 최종 core68 PASS, media61 PASS. offline+core102 및 최종 독립 소유권 회귀21도 별도 PASS. 기존 Starlette 경고. 실제 시험은 WinForms 버튼 이벤트→worker→native 런타임이며 물리 마우스 더블클릭과 구분한다.
- [더블클릭 안내](DOUBLE-CLICK-UPDATE-GUIDE.md), [단일 HTML 그림 안내](DOUBLE-CLICK-UPDATE-GUIDE.html), [검증 기록](verification/desktop-update-2026-10-18.json). 검증 후보와 실행payload가 같은 최종 매체 봉인 및 별도 비공개 사전배포를 완료했다(상단 게시 기록 참고).
- 원본 Claude/사용자 C: 설치/운영 자료 미변경. 깨끗한 LTSC17763·실제 관리자서비스/UAC/재부팅·물리폐쇄망·공동부하·강제전원중단·운영 인수는 별도 게이트로 남긴다. 새 로그/PCAP 재분석은 이번 작업에서 실행하지 않았고 저장된 결과 보존을 검증했다.

---

## 2026-10-18 업데이트 안내 r2: 수동 해시 대조 제거

- 사용자 요청으로 세 업데이트 안내서의 Get-FileHash·SHA256 눈대조 단계를 제거했다. verify-bundle/update.ps1 자동 무결성 검증과 계정·분석 자료 보존 계약은 그대로다. 제품·설치 코드는 변경하지 않았다.
- 2단계 브라우저 화면을 다시 확인·캡처했다. 관련 시험27통과/기존경고1(8.17초), PS5.1 명령13개 구문 검사 및 독립 문서 검토 PASS. 실제 설치·업데이트·복구는 이번 문서 수정에서 재실행하지 않았다.
- 비공개 GitHub 기존 사전 배포에 SAW-update-guide-20261018-r2.zip(1,094,623바이트)을 추가하고 원격 대조했다. 기존11자산 보존. 현재 그림 안내는 r2를 사용한다.
- [수정 검증](verification/update-guide-r2-2026-10-18.json), [게시 대조](verification/github-update-guide-r2-2026-10-18.json). 기존 운영 인수 게이트 유지.

---

## 2026-10-18 기존 설치 업데이트 그림 안내·실제 복구 확인

- 사용자 요청에 따라 [8단계 그림 안내](OFFLINE-UPDATE-SCREENSHOTS-2026-10-18.md)와 [단일 HTML](OFFLINE-UPDATE-WALKTHROUGH-2026-10-18.html)을 작성했다. 서비스/NoAdmin 명령, 같은 드라이브 복구 공간, 전체 시점 복구와 계정 변경의 되돌림을 설명했다. 기존 update.ps1 및 제품 코드는 변경하지 않았다.
- 안내서를 실제 브라우저로 캡처한 8장이다. PowerShell 또는 설치된 제품의 화면 캡처가 아니다. 단계 이동·설치 방식·전체 보기 검증; 명령14개 PS5.1 구문 PASS. 복사 성공 알림만 확인했고 clipboard 내용 독립 검증/직접 file: 열기/인쇄는 미검증이다.
- 최종10/18 ZIP SHA256 재대조·매체650파일 검증 PASS. Windows11 build26200/PS5.1의 별도 F: 합성 NoAdmin 설치에서 실제 적용→HTTPS/MFA→전체 종료/시작→전체 복구→HTTPS/MFA PASS. 측정: plan 453.81초 / apply 748.02초 / restore 601.58초.
- 적용 전·재시작 후·복구 후 계정2/이벤트9/Finding10/증거2/노트1/완료작업2 보존. 계정ID·비밀번호hash·역할·MFA, 원본·설정·키·인증서·증거ID·노트 비교 PASS. 합성 계정 비활성/세션 취소 후 전체 중지 완료. [상세 검증](verification/update-walkthrough-2026-10-18.json).
- baseline37094e85는 이전 합성 후보이며 게시10/17 ZIP과 동일하다고 주장하지 않는다. 최종18 source403bc7d5와 적용·복구 비교했고 업무 스키마는 모두0014다. 테스트 harness의 준비 순서/app-var 가정을 바로잡은 과정을 검증 기록에 남겼다.
- 관련 release manifest 시험27 passed/기존경고1(16.36초). 제품 브라우저는 시험 인증서 신뢰 문제로 차단됐고 우회하지 않았다. 이번에는 제품 전체 서버/UI 시험이나 새 로그·PCAP 업로드를 재실행하지 않았다.
- 비공개 GitHub 사전 배포에 설명서 전용 ZIP SAW-update-guide-20261018.zip(1,096,900바이트, SHA256 4e3257c48c78630d4e8d676909569c8622aa403fb08bfedea853143428a61156)과 외부 체크섬을 추가했다. 기존 설치 ZIP/9자산은 보존했다. [게시 대조](verification/github-update-guide-2026-10-18.json).
- 사용자 C: 설치·원본 Claude·운영 자료 미변경. 정상 실행 중인10/17 설치는 설치기 보완만을 위해 급히 업데이트할 필요가 없다. 설치 실패 재개는 매체 START-HERE.md를 따르며, C:→D: 이전은 이 업데이트의 지원 범위가 아니다.
- 깨끗한 LTSC17763·관리자서비스/재부팅·물리폐쇄망·공동부하·운영 인수는 여전히 미검증/승인 전이다. History503 원인 미확정과 기존 운영 게이트를 유지한다.

---

## 2026-10-18 설치기 보완 매체 게시 완료

- [비공개 GitHub 사전 배포](https://github.com/dewdorp/SAW/releases/tag/v0.1.0-pilot.20261018)에 새 모델 제외 ZIP과 안내/검증 문서 등 9자산을 게시했다. 원격 크기와 SHA256 대조 완료. 이전 20261017 배포는 보존한다.
- ZIP: SAW-0.1.0-pilot.20261018-model-free-win-x64.zip, 1,444,634,601바이트, SHA256 81eda12295cc75b221add3c34a4e6777d14cbce0e64efa5f95344c53e4c63628. 내부 652항목(650 payload + manifest/체크섬)의 크기·hash와 시험 후보5 실행 payload 동일성 PASS.
- 매체 소스 commit: 403bc7d57631e56a27dbef70cd81512029e1b9f5. 설치 위치·재개 안내는 [설치 위치·재개](INSTALL-RECOVERY-2026-10-18.md), 실제 게시 영수증은 [게시 검증](verification/github-release-2026-10-18.json).
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
- 안내: [설치 위치·재개](INSTALL-RECOVERY-2026-10-18.md). 상세: [검증 기록](verification/installer-recovery-2026-10-18.md).
- 위 봉인·게시·원격 대조는 완료됐다. 다음은 승인된 깨끗한 LTSC 및 관리자 서비스 환경에서의 인수 시험이다.
- 남은 게이트: 깨끗한LTSC17763·물리폐쇄망·관리자서비스/재부팅·조직TLS/서명·16GB공동부하·강제중단ACL복원·운영인수. 실제 운영데이터/계정 변경 없음.

---

## 2026-10-17 모델 제외 매체·기존 설치 업데이트/복구 검증

- 새 매체 후보5에 스키마0014·현재UI·행위 분석·통계·조사/Golden·룰/파서 콘텐츠·실제 CPU 실행기를 포함했다. 모델 가중치는 제외, 런타임 pin 변경/외부 다운로드 없음.
- 새 폴더 실제 설치→HTTPS/MFA→로그/내장HTTP PCAP→이벤트9·Finding10·노트→전체 종료/시작 보존, 설치 전체 owner/DACL 검사 PASS.
- 기존10/12 설치0011→0014→행위 분석/HTML→재시작→DB/색인 포함 전체0011복구→다시0014적용/분석/재시작 PASS. 기존9이벤트/8Finding/노트/키/MFA/원본 보존. 최신 트리는 retained로 별도 보관.
- 중간 후보2는 DACL 상속 상태 차이, 후보4 복구는 임시 경로 길이로 교체 전에 거부됐고 해당 실패를 기록했다. 복제 ACL·기존 owner/ACL 사전 검사·신규 설치 루트 보호·미디어 ACL staging 전파·디렉터리 열거 오류를 실제 Windows 회귀와 독립 검토로 보완했다. 기존 합성 QA의 권한만 별도 정비했으며 운영 권한 자동 수리는 하지 않는다.
- 서버1079/2건너뜀(559.62초), 화면177(31파일),tsc/build·주요Ruff·PS4구문 PASS. 실제 브라우저 룰/파서 r1 반입→4예제→독립 적용→영향 확인→사용중단/재조회 캡처6장. 과거r2 HTTP1→2→1과 구분.
- [설치](OFFLINE-RELEASE-2026-10-17.md), [업데이트/전체복구](OFFLINE-UPDATE-GUIDE.md), [실제 룰·파서 화면](OFFLINE-CONTENT-GUIDE.md), [검증](OFFLINE-RELEASE-VALIDATION-2026-10-17.md).
- **게시 완료:** [비공개 GitHub 사전 배포](https://github.com/dewdorp/SAW/releases/tag/v0.1.0-pilot.20261017) — ZIP 1,444,582,845바이트, 내부645파일 SHA검사·시험후보 실행파일 동일·원격10자산 크기/지문 대조 완료. ZIP SHA256 e2a09af4aee877a7d1c2f1fdf87de915a2a11491ae5010ac17aefe022fe90fe8. 소스 b4d81386d05a675a15c438f3ed3190ae831f5e75.
- **남은 게이트:** 깨끗한LTSC17763/물리적인터넷차단/16GB공동부하/관리자서비스·조직TLS/모델한국어품질·SFT/운영인수는 미완료. History503 원인미확정 유지. 원본Claude·은행자료·운영계정 미변경.

---

# 최신 인계 — 2026-10-17

## 2026-10-16~17 웹 행위 분석·근거 보고서·Golden 증분

- 기존 조사/파서/Job/원문/요청비교/Check/종결/Experience/Golden을 재사용했다. 새 행위 분석 탭,5가지 이동 시간창,수집 품질,저장 버전·SHA,9절 A4 HTML,조건부 후속 질문과4-eyes 사례 내보내기를 연결했다. 모델·능동 스캔·훈련 없음.
- 스키마0014 및 saw-web-behavior/1.0, 질문 saw-web-behavior-questions/1.0. 백서 임계값은 참고이며 도구·AI·침해/정상 정답이 아니다. 원문 표본ID/동결 비교/쿼리/IPv6/미수집/멀티센서 경계를 유지한다.
- 최종 서버1004통과2건너뜀(326.44초), 화면177통과(31파일,25.56초),tsc/build/Ruff주요오류검사 성공. 실제 격리PG16.15/OS2.19.6 기능64+보완15시험(중복포함), 각 실행 종료·포트정리 성공.
- 실제 브라우저 A v2계산→구간확대→원문16건→두요청비교→Check저장→HTML, D UA미수집, B v2후속질문 확인. 별도HTTP로 종결→Experience→독립계정Golden승인→입력/정답Export→프로세스재시작 보존. 브라우저는 채택결과조회와실제ZIP다운로드까지 확인(승인클릭자체는HTTP).
- 독립검토P1 JSON비밀값노출/P2 masked필터근거누락/P2IPv6서비스충돌 수정·재검증. 브라우저CSP보고서서식/긴ID필터가로폭 수정. 기존History503 원인은 미해결 유지.
- [사용법·12장실제화면](BEHAVIOR-ANALYSIS-GUIDE.md), [검증/환경게이트](BEHAVIOR-VALIDATION-2026-10-16.md), [최신B보고서](examples/behavior-case-B-report.html).
- NEXT: 기존10/12ZIP 미갱신. 새 모델제외 매체+스키마0014의기존설치전환·깨끗한LTSC17763·16GB공동부하·모델품질/운영인수는남는다. 현재개발OS Windows11build26200. 원본Claude·은행자료·운영계정미변경. 운영자료/고비용훈련/관리자설치/운영배포승인경계유지.

---

# 2026-10-15 최신 인계: 조사 안내와 오프라인 콘텐츠

수정 대상은 **F:/codex/SAW-Claude-main**이다. [STATE](../STATE.md), [검증 기록](GUIDANCE-CONTENT-VALIDATION-2026-10-15.md), [콘텐츠 실습](OFFLINE-CONTENT-GUIDE.md), [조사·Golden 사용법](GUIDANCE-GOLDEN-GUIDE.md)을 먼저 읽는다.

서버913/화면162, tsc/build, 실제 격리 PG/OS59+4 시험과 실제 HTTP r1→r2→복구(1→2→1), Golden 입력/정답 export, 앱 재시작 보존을 확인했다. **실제 브라우저는 사례A 종결/Experience 검토요청까지만**이며 콘텐츠/Golden 최종 클릭과 단계별 스크린샷은 도구 실행 시간 초과로 남았다. 테스트나 API 성공으로 그 화면 검증을 완료 표시하지 않는다.

스키마0013이 필요하고 기존10/12 설치매체는 새 기능 미포함이다. install.ps1은 신규 설치용이다. 다음은 합성 전용57285 화면 검증·캡처, 새 매체와 기존설치 전환, 깨끗한LTSC17763/16GB공동부하/모델품질/운영인수다. 자격증명은 대화·문서에 출력하지 않는다. 원본/은행 운영자료/사용자 계정은 건드리지 않는다. 현재 모델 선택/학습 승인 경계도 유지한다.

---

# 2026-10-15 추가 인계: 선택 탐지 Assistant

수정 대상은 계속 **F:/codex/SAW-Claude-main**이다. [최신 STATE](../STATE.md), [실제 화면/사용법](ASSISTANT-EVIDENCE-GUIDE.md), [새 검증 기록](ASSISTANT-EVIDENCE-VALIDATION-2026-10-15.md)을 먼저 읽는다. 이전 PASS를 복사하지 않는다.

최종 서버 851/화면 144 시험, tsc/build를 통과했고 합성 브라우저에서 3동작·노트 보존·원문 71번째 줄을 확인했다. 실제 Foundation BASE 짧은 생성은 성공했지만 선택 탐지 설명은 300초 초과로 실패했다. 한국어 품질/학습/후보 채택은 미완료이며 현재 브라우저는 템플릿이다. 새 Instruct는 별도 template 계약 미지원이다. 후보 8사례는 평가 자료만 준비했다.

다음은 후보 직렬화 호환성 → 파일 반입 → 고정 한국어 보안 평가이며, 기존 설치 ZIP은 미갱신이다. LTSC17763/16GB 공동 부하/운영 자료·배포 승인 게이트를 유지한다. History503와 중간 UI/Node 일시 실패 원인을 재통과만으로 해결 처리하지 않는다. 원본 Claude와 실제 은행 자료·비밀값은 건드리지 않는다.

---

# 2026-10-14 추가 인계: 통계·시간 변화·약 8B 모델

최신 변경/실행은 [STATE](../STATE.md), [통계와 실제 화면](STATISTICS-TEMPORAL-GUIDE.md), [검증 기록](STATISTICS-TEMPORAL-VALIDATION-2026-10-14.md)을 먼저 읽는다. 아래 같은 날짜의 이전 기록은 역사적 결과다.

서버 830통과·2건너뜀, 화면 132통과·tsc/build, 별도 실제 PG/OS API 26통과를 확인했다. 합성 160건으로 통계/시간 변화/원문/CSV를 실제 브라우저에서 확인했다. [약 8B 모델 안내](MODEL-8B-KOREAN-SECURITY-GUIDE.md)는 후보·준비 절차이며 새 모델 실행 성공이 아니다. 새 스키마/의존성/제품 Phase는 추가하지 않았다. 기존 10/12 설치 매체 미갱신과 LTSC·16GB·모델 품질 게이트는 유지한다.

---

# 2026-10-14 최신 인계

이번 작업은 관리자 데이터 정리·룰 Export/사용 안내·통계/행동 차이 탐지·16GB 모델 가이드를 추가했다. 실제 변경 위치는 계속 **F:/codex/SAW-Claude-main**이며 원본은 수정하지 않는다. 상세 최신 결과는 [STATE](../STATE.md), [사용 안내](ADMIN-RULES-ANALYTICS-GUIDE.md), [검증 기록](ADMIN-RULES-ANALYTICS-VALIDATION-2026-10-14.md)을 먼저 읽는다.

스키마는 0012까지이며 새 마이그레이션은 멱등으로 시험했다. 최종805서버/130화면 시험과 별도 실제 PG/OpenSearch 시험이 통과했다. 기존10/12 설치 매체에는 이번 변경이 없으므로 새 버전 매체 제작과 설치/재시작 검증이 다음이다. Kanana 소형 후보는 가이드만 작성했으며 실제 모델 선택/추론/훈련 성공으로 간주하지 않는다. 깨끗한 LTSC2019·16GB 인수 게이트는 계속 남아 있다.

---

# 2026-10-11 복사본 우선 인계

현재 수정 대상은 **F:\codex\SAW-Claude-main**입니다. 아래의 원본 이력과 경로는 참고이며 **F:\claude\saw는 수정하지 않습니다**.
원본 e0a7af5에서 추적 소스만 독립 복사했고 개인정보·비밀값·운영 데이터·의존성은 복제하지 않았습니다.
현재 진행·검증은 [STATE.md](../STATE.md), [탐지 사용 안내](DETECTION-CATALOG-GUIDE.md), [비교·검증 기록](DETECTION-VALIDATION-2026-10-11.md)을 먼저 확인하세요.
2026-10-12 추가 요청에 따라 AI 모델 반입/명시적 교체, 모델 없는 실제 설치 매체와 GitHub 사전 배포를 진행했다. 최신 사용법은 [모델 안내](LOCAL-MODEL-GUIDE.md), [설치 안내](OFFLINE-RELEASE-2026-10-12.md), 최신 실제 실행은 [AI 검증](LOCAL-AI-VALIDATION-2026-10-12.md)과 [설치 검증](OFFLINE-RELEASE-VALIDATION-2026-10-12.md)을 확인한다.
최종 개발기 검증: 서버743통과·2건너뜀, 화면115통과·tsc/build, 실제 새 매체 설치·로그/PCAP·재시작 보존·합성 별도 복원 성공. 깨끗한 LTSC/공동 접속/관리자 서비스와 운영 승인은 미완료이다. 설치 매체 봉인과 GitHub 사전 배포의 마지막 상태는 STATE.md를 확인한다.
아래 역사적 시험 결과는 이번 복사본의 실행 결과로 간주하지 마세요. 새 복사본에서 기존 시험을 다시 실행했습니다.

---

# SAW 작업 이어받기 안내 (2026-10-11 기준)

이 문서 하나로 다음 작업자(사람 또는 AI)가 바로 이어서 일할 수 있게 정리했습니다.
세부 이력은 [PROGRESS.md](../PROGRESS.md), 사용법은 [USER-MANUAL.md](USER-MANUAL.md), 설치는 [INSTALL-WINDOWS.md](INSTALL-WINDOWS.md)에 있습니다.

## 1. 무엇을 만드는 중인가

- **SAW (SOC Analysis Workbench)**: 보안관제 분석가가 로그·패킷을 올려 분석하고, 확인한 내용을 남기고, 보고하는 웹 플랫폼.
- **운영 환경**: 폐쇄망의 Windows 10 Enterprise LTSC 2019 서버 **한 대**를 분석가 여러 명이 브라우저(Chrome)로 같이 씀. 저사양. 인터넷·외부 서비스·AI 없음.
- **업무 방식**: 분석가는 **각자 자기 조사**를 하고 결과만 공유. 관제 매니저는 모든 조사를 보고 수정하며 임원에게 보고. 교대 인계는 범위 밖.
- **주 자료**: NDR 메타 검색 결과(CSV, 수백 MB), 웹 서버 로그, WAF 로그, PCAP, 악성 지표 목록.
- **사용자 요청의 현재 방향**: 실제 서버 설치는 나중. **폐쇄망에 들어가기 전에 탐지 규칙과 공격 시나리오를 최대한 많이 넣는 것**이 지금의 목표.

## 2. 기술 구성

| 영역 | 구성 |
|---|---|
| 서버 | Python 3.12, FastAPI, SQLAlchemy + Alembic(`saw/storage/migrations`, 현재 0010까지) |
| 메타데이터 DB | 운영 PostgreSQL 16 / 개발 SQLite(`var/saw.db`) |
| 이벤트 저장 | 운영 OpenSearch 2.19.6 단일 노드 / 개발도 지금은 OpenSearch(`saw-*` 인덱스). SQLite 이벤트 저장소(`var/events.db`)는 테스트 기본값 |
| 화면 | React 18, Vite, TanStack Query, zustand (`apps/web`) |
| 테스트 | pytest(`tests/api`, `tests/unit`), vitest + Testing Library(`apps/web/src/**/*.test.tsx`) |
| 배포 | `deploy/windows/*.ps1` (오프라인 설치 묶음, 서비스 또는 사용자 프로세스) |

### 폴더 지도

```
saw/
  apps/api/routers/      API (investigations, evidence, workbench, network, forensics, knowledge, detection,
                         parser_library, provenance, briefing, checks, reviews ...)
  core/application/      업무 로직 (analysis, briefing, checks, reviews, teamwork, provenance, audit, identity ...)
  core/security/         권한(authz), 가리기(masking), 비밀번호
  parsers/               로그 파서 (ndr, structured(CSV/KV/JSON), web, network, custom(사용자 정의), library, registry)
  analyzers/             정규화(log/normalize.py), HTTP·payload 분석, 패턴 태그(patterns.py), 스토리, 관계
  detectors/             탐지기: web.py, network.py, pcap_forensics.py, anomaly.py (코드)
                         signatures.py + scenarios.py + packs/*.yaml (데이터로 된 탐지 묶음 — 6절)
  integrations/pcapkit/  내장 PCAP 분석 엔진 (reader, analyzer, tls, httpmsg, extract ...)
  storage/               models.py, eventstore.py(SQLite), opensearch_store.py, migrations/
  workers/pipeline.py    증거 처리(풀기 → 파싱 → 색인 → 분석), 체크포인트
  devtools/              가상 자료 생성(sample_data.py, pcap_writer.py), seed, bench_ingest
apps/web/src/
  pages/                 Home, Investigations, Board(현황판), Briefing(보고용 요약), Jobs, Parsers, Provenance, Admin ...
  pages/inv/             조사 작업대 탭들 (Workbench, RawTab, EventDrawer, FindingsTab, ChecksTab, CloseDialog ...)
  components/            Checks(확인 기록), Reviews(검토), Support(분석 지원), common, ui
tests/                   api/ (통합), unit/
docs/                    설계 문서, ADR, 사용 설명서, 이 문서
deploy/windows/          설치·제어 스크립트
```

## 3. 실행과 시험

```bash
# 서버 쪽 전체 시험 (SQLite, 약 4분)
.venv/Scripts/python.exe -m pytest tests -q -p no:cacheprovider

# 운영 구성으로 시험 (PostgreSQL + OpenSearch가 떠 있어야 함. 인덱스 접두어 sawtest, DB saw_test — 운영 자료와 분리)
SAW_TEST_DATABASE_URL="postgresql+psycopg://saw:<var/infra/secrets/postgres-saw.pw 의 값>@127.0.0.1:5432/saw_test" \
SAW_TEST_OPENSEARCH_URL=http://127.0.0.1:9200 .venv/Scripts/python.exe -m pytest tests -q -p no:cacheprovider

# 화면 시험과 형식 검사
cd apps/web && pnpm vitest run && pnpm tsc --noEmit
```

개발 서버(순서대로):

```bash
F:/claude/saw/var/infra/opensearch-2.19.6/bin/opensearch.bat          # 1) 검색엔진 (127.0.0.1:9200, 1~2분)
SAW_EVENT_STORE=opensearch F:/claude/saw/.venv/Scripts/python.exe -m uvicorn saw.apps.api.main:app \
  --app-dir F:/claude/saw --host 127.0.0.1 --port 8100                # 2) API
pnpm --dir F:/claude/saw/apps/web dev                                  # 3) 화면 → http://localhost:5180 (127.0.0.1 아님)
```

- 개발 DB는 `create_all`로 뜨므로 새 테이블은 재시작하면 생깁니다. 운영은 `SAW_SCHEMA_MODE=migrate`.
- 시험 계정과 비밀번호: `var/dev-credentials.json` (analyst, senior, manager, admin, qa-manager, claude-check).
  - `qa-manager`는 사용자가 자기 인증 앱을 등록해 쓰는 계정입니다. **로그인하지 마세요.**
  - 자동 점검에는 `claude-check`(관제 매니저 권한)를 쓰고, 일회용 코드는 `python -m saw.devtools.seed totp claude-check`로 얻습니다.
- 개발 DB 백업: `var/saw.db.bak-20261010*`. 예전 SQLite 이벤트 파일 `var/events.db`(2.7GB)는 지금 쓰지 않습니다(삭제는 사용자 승인 필요).

## 4. 반드시 지킬 것

1. **실제 은행 자료**: `var/objects`의 NDR CSV와 개발 OpenSearch의 조사 `INV-20261008-001`은 사용자가 올린 실제 자료입니다. 쿠키·세션·고객 번호가 들어 있으니 **내용을 출력·인용·복사하지 말고 건수·필드 이름·규칙 id만** 다룹니다. 시험과 표본에는 가상 자료만 씁니다.
2. **비밀값**: 비밀번호·토큰을 대화나 문서에 적지 않습니다. 필요하면 `var/dev-credentials.json`, `var/infra/secrets/`에서 읽어 쓰기만 합니다.
3. **사용자 계정으로 로그인하지 않습니다.** 화면 확인은 `claude-check` 또는 자동 시험으로 합니다.
4. **한글**: 사용자에게는 쉬운 한글로 답합니다. 화면 문구도 한글. 코드·주석·커밋 메시지는 영어(저장소 관례).
5. **라이선스**: `ngnicky-ai/pcap-forensics-analyzer`(라이선스 없음)의 코드는 쓰지 않습니다. 외부 규칙 묶음(Sigma 저장소 등)을 그대로 가져오지 않습니다 — 탐지 내용은 직접 작성합니다.
6. **PCAP 분석기는 비밀번호를 저장하지 않습니다.**
7. **삭제·내려받기·커밋은 사용자가 요청했을 때만.** 다만 작업 단계별 커밋은 사용자가 승인한 진행 방식입니다.
8. **줄 끝 문자가 파일마다 다릅니다**(CRLF/LF 혼재). 고치기 전에 `git ls-files --eol <파일>`로 확인하고 그 파일의 방식을 유지합니다. `sed -i`는 CRLF를 LF로 바꿉니다.
9. **셸 heredoc에서 `\n`, `\t`, `\\`가 실제 문자로 바뀌는 사고가 반복됐습니다.** 역슬래시가 있는 내용은 편집 도구로 직접 고치거나 패치 스크립트를 파일로 써서 실행합니다.
10. **마이그레이션은 멱등으로**: 개발 DB는 `create_all`로 이미 테이블이 있을 수 있으니 `if '<table>' in inspector.get_table_names(): return` 형태를 따릅니다(0005~0010 참고). SQLite 마이그레이션 중에는 외래키를 끕니다(`migrations/env.py`).
11. **기능마다 시험을 같이** 넣습니다. 실제 자료로 확인한 것과 자동 시험으로만 확인한 것을 구분해 보고합니다.

## 5. 이번 작업 기간(10-08 ~ 10-11)에 끝낸 것

| 커밋 | 내용 |
|---|---|
| e5411db, 8cd3c98 | TXT/CSV 자동 인식(NDR 메타 CSV, 한글 CSV), 대용량 처리(슬림 인덱스, 체크포인트), 관리자 권한 없는 설치 |
| 5c0bbab | 사용자 정의 파서(마법사, 버전, 승인) |
| d23d5e0 | 로그 ↔ 패킷 세션 연결, TLS 인증서 분석 |
| 50316fa | 처리 기록(누가 어떤 입력을 어떤 파서·설정으로 처리했는지, 지문) |
| 2a87cb2 | 보안: MFA 횟수 제한·코드 재사용 차단, 2인 확인 보강, 비밀값 가리기, 감사 로그 끝 삭제 감지·동시 기록 갈라짐 수정 |
| 6204766 | 데이터 정확성: NDR 짝짓기 조건, 저장 확인 건수만 완료 처리, 중복 열, 0점 파서 방지, 잘린 gzip, 웹셸 연결 조건 |
| 9e05f0a | PCAP 정확성: 정확한 시각, 잘림·손상 판별, 패킷 빠진 세션 표시, 세션 추출 오류 |
| 6864897 | 설치(경로 특수문자·한글, 안전 저장 설정), 원본 로그·타임라인 2만 건 상한 |
| febab05 | 보고용 요약(조사 → 한 장), 현황판, 로그인 탐지 오탐 수정, 재분석 시 근거 없는 탐지 제거 |
| 99dbc64 | 확인 기록(질문·판단·범위 구분), 팀 확인 정보(다른 조사 참고, 조건 비교, 유효 기간) |
| ff999cd | 검토 요청(높은 위험 하향·공격 판정은 자동 대상, 업무는 막지 않음) |
| b54b041 | 종결 전 점검 5가지, 분석 지원 요청, 종결 창 한글화 |
| f7ab5e7 | OpenSearch 삭제 직후 조회 문제 |
| (이 문서와 함께) | **탐지 묶음(시그니처 166개 + 공격 흐름 8개)** — 6절 |

시험 현황(이 문서와 같은 커밋 기준): 서버 쪽 365건 중 364건 통과·1건 건너뜀(SQLite), 운영 구성(PostgreSQL+OpenSearch)에서 365건 모두 통과, 화면 75건 통과. 서버 쪽 365건 중 174건은 탐지 묶음의 규칙별 예시 시험입니다.

## 6. 진행 중이던 일: 탐지 묶음 (가장 먼저 이어서 할 것)

### 왜 이렇게 만들었나

폐쇄망에는 AI가 없으므로 탐지 내용을 **코드가 아니라 목록 파일**로 넣었습니다. 분석가가 YAML 한 줄을 더하면 규칙이 늘고, 규칙마다 달린 예시가 자동 시험으로 검증됩니다.

### 지금 있는 것

| 파일 | 역할 |
|---|---|
| `saw/detectors/packs/web_signatures.yaml` | 시그니처 166개, 10묶음: `tool`(공격 도구), `scanner`(수집 서비스), `rce`(공개 취약점), `exec`(운영체제 명령), `webshell`, `editor`(국내 편집기·게시판 업로드), `console`(관리 화면), `exposure`(정보 노출), `inject`(NoSQL·LDAP·CRLF 등), `cms` |
| `saw/detectors/packs/scenarios.yaml` | 공격 흐름 8개 (탐색 → 공격 → 웹셸 등). 같은 IP의 탐지가 단계 순서대로 이어지면 묶음 |
| `saw/detectors/signatures.py` | 묶음 읽기, 일치 검사(`sig_ids`), 탐지기 `SignatureMatch`(id `sig.match`), 목록(`catalog`) |
| `saw/detectors/scenarios.py` | 흐름 판별(`match`), 탐지기 id `scenario.flow` |
| `saw/analyzers/log/normalize.py` | 기록을 읽어 들일 때 `sig:<규칙id>` 태그를 붙임 (`finalize` 안) |
| `saw/core/application/analysis.py` | `all_detectors()`에 `SignatureMatch` 등록, `_flows()`로 흐름 탐지 생성, 꺼 둔 규칙 전달 |
| `saw/storage/models.py` `SignatureSetting`, 마이그레이션 0010 | 규칙별 켜기·끄기 |
| `saw/apps/api/routers/detection.py` | `GET /detection-catalog`, `PUT /detection-catalog/signatures/{id}` (끄려면 이유 필수, 권한 `detection.approve`) |
| `tests/unit/test_signature_pack.py` | 규칙마다 예시 일치·비일치, 평범한 요청 32종 무탐지, 수집 시 태그, 속도 상한 |
| `tests/api/test_signature_detection.py` | 가상 공격 로그 → 탐지 목록·흐름·끄기까지 |

동작 요약:

- 한 요청이 맞는 규칙을 수집 때 한 번만 검사해 태그로 남기고, 탐지기는 태그만 셉니다.
- **성공 응답(2xx)을 받은 것은 규칙별로 따로**, 모두 거부된 시도는 **묶음당 한 줄**로 접습니다(스캐너가 200개 경로를 두드려도 한 줄).
- `success: only` 규칙은 성공 응답이 있을 때만 탐지가 됩니다(예: 백업 파일 내려받기).
- 실제 NDR 요청 439,461건에 돌린 결과 **일치 0건**(오탐 없음). 처음에 1종 4건이 걸렸는데 `resource.zip`의 "source"에 걸린 오탐이어서 규칙을 고쳤습니다.

### 아직 안 한 것 (우선순위 순)

1. **화면이 없습니다.** `GET /detection-catalog`를 보여 주는 "기본 탐지 목록" 화면(검색, 묶음별 보기, 켜기·끄기와 이유 입력)을 탐지 룰 메뉴에 넣어야 합니다. API와 권한은 준비돼 있습니다.
2. **설명서·진행 기록 반영**: `docs/USER-MANUAL.md`에 "기본 탐지 묶음" 절, 규칙을 추가하는 방법(YAML 형식은 파일 머리말에 있음).
3. **기존 자료에는 태그가 없습니다.** 태그는 수집 때 붙으므로, 이미 색인된 조사는 증거를 다시 처리해야 새 규칙이 적용됩니다(작업 화면의 "다른 파서로 다시 처리" 또는 재업로드).
4. **속도**: 일치 검사가 요청 1건당 50~80µs(실제 NDR 44만 건에 23~36초, 수집 시간의 약 10%)입니다. 필요한 단어가 있을 때만 정밀 검사하는 문(`_gate`)을 넣었지만 개선은 확인하지 못했습니다(측정할 때 같은 PC에서 다른 작업이 돌고 있어 수치가 흔들렸습니다). 기호만으로 된 규칙 18개(`_gate()[2]`)를 필드마다 매번 검사하는 부분이 주 비용으로 **추정**됩니다(측정으로 확정하지 않음). 규칙을 500개 이상으로 늘리기 전에 측정부터 하세요. 측정 스크립트: `var/tmp/sig_on_real.py`(실제 요청 전체에 돌려 규칙별 건수와 시간), `var/tmp/prof.py`(1만 건 표본으로 구간별 시간) — 둘 다 규칙 id·건수·시간만 출력합니다.
5. **표본 자료**: `saw/devtools/export_samples.py`에 시그니처·흐름을 보여 주는 표본(15번)을 추가하면 교육·시연에 쓸 수 있습니다. 가상 공격 로그는 `tests/api/test_signature_detection.py::attack_log`에 있습니다.

### 내용 확장 계획 (사용자 목표: "최대한 많이")

규칙을 더할 때는 **예시(examples)와 평범한 예(benign)를 반드시** 같이 적고, 실제 NDR 자료에 돌려 오탐이 없는지 확인합니다.

| 영역 | 넣을 것 | 방식 |
|---|---|---|
| 웹 요청 시그니처 확장 | 국내 솔루션(그룹웨어·전자결재·메일·보안 장비 관리 화면)의 알려진 취약 경로, 더 많은 공개 취약점, API 오용(대량 추출 매개변수, 관리 API), 인증 우회 경로 | `web_signatures.yaml`에 추가 |
| NDR 흐름(연결) 탐지 | 한 출발지의 대량 전송, 평소 안 쓰던 포트, 해외 목적지, 업무 외 시간 관리 포트, 응답 코드 급변, 내부 → 내부 관리 포트 접속 | 연결 기록은 `zeek_conn`으로 들어옵니다. `saw/detectors/network.py`에 탐지기 추가 또는 임계값을 데이터로 빼기 |
| 흐름(시나리오) | 내부 확산, 자료 반출(대량 조회 → 큰 전송), 랜섬웨어 전 단계(대량 파일 접근), 내부자 이상 행위 | `scenarios.yaml`에 추가 |
| PCAP | 내부 이동 통신(SMB·RDP·Kerberos·NTLM) 해석, 웹셸 명령 추출, 수 GB 파일 처리 | `saw/integrations/pcapkit` |
| 분석가가 만든 규칙 자동 적용 | 탐지 룰 메뉴의 승인된 Sigma 규칙(`saw/detection`)은 지금 과거 자료 시험만 됩니다. 승인된 규칙을 조사 분석에 자동 적용하면 폐쇄망에서 코드 없이 탐지를 늘릴 수 있습니다 | `analysis.all_detectors`에 연결 |
| 점검 절차·지식 | 탐지 종류별 점검 절차(플레이북), 흔한 오탐 조건을 미리 넣기 | `saw/knowledge`, seed |
| 한글화 | 코드 탐지기의 제목이 영어("Possible …")입니다. 보고용 요약은 `briefing.CATEGORY_KO`로 바꿔 보여 주지만 분석 화면은 영어 그대로 | 탐지기 제목 또는 화면 표시 |

## 7. 그 밖에 남은 일

- 오프라인 설치 묶음 재생성(`deploy/windows/build-bundle.ps1`)과 실제 서버 설치·백업·복구 리허설 (사용자가 "나중에"로 미룸). 마이그레이션이 0005~0010까지 늘었습니다.
- 조사별 할 일 목록(탐지 권고 → 할 일 → 보고용 요약 자동 연결), 정상 기준 등록, 기간 보고서, 알림 통합, 증거 겹침 경고와 보관·삭제.
- 사용자에게 확인받지 못한 것: 사내 보고 양식(항목 순서), 검토를 "막는 방식"으로 바꿀지 여부, 조사 `INV-20261008-001`의 두 증거가 겹치는지(기간이 같음 — 복사본 삭제는 요청 시).
- `F:\saw-dryrun-pc` 폴더(시험용 비밀번호 포함)는 보호 규칙 때문에 지우지 못했습니다. 사용자가 직접 지워야 합니다.

## 8. 알려진 한계

- 검토 요청·분석 지원의 화면 흐름과 "팀 확인 정보"가 다른 조사에 뜨는 화면은 자동 시험으로만 확인했습니다(두 계정이 필요해 직접 눌러 보지 못함).
- 보고용 요약의 인쇄 결과(종이·PDF)는 실제로 뽑아 보지 않았습니다.
- 한글 폴더에 설치했을 때 PostgreSQL·OpenSearch가 뜨는지는 확인하지 못했습니다(설정 파일 생성만 확인).
- 흐름 판별은 "같은 IP가 탐지의 엔티티에 있는가"로 묶습니다. 웹 탐지는 출발지 IP만 엔티티로 넣는 경우가 많아, 피해 서버 기준 흐름은 덜 잡힙니다.
