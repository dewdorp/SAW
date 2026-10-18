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

# SAW 현재 상태

## 2026-10-18 진행 중: 설치 위치·Java·PG 권한·안전한 재개

- 사용자 새 첨부15478365 요청 적용. 실제 C:/SAW와 원본 F:/claude/saw 미변경. 수정 대상 F:/codex/SAW-Claude-main, 기존HEAD2fa8726에서 아직 미커밋.
- C:/D: InstallRoot 및 ChooseInstallLocation 입력/용량 표시, private root/경로 별칭 거부, 상태/잠금/정상설치 읽기 전용 검증 구현 중. Python·PG·OS 소유/바이트 검증 후 재사용/부분 복구; 사용자 수정 보존. 새 안내 docs/INSTALL-RECOVERY-2026-10-18.md.
- 실제 원인: OS service BAT는 JAVA_HOME을 읽으며 오류에서 exit0 가능; PG initdb의 실제 Windows 토큰은 BA/SYSTEM-only pw 읽기 실패; 기존 fresh-only gate와 Existing Python 거부로 재개 불가.
- 현재 확인: 루트/상태27시험 PASS, 기존 통합설치62시험 PASS(당시 코드), OS36→추가재개25시험, PG 실제 BA/SYSTEM pw실패→정확한 SID 임시권한 후 실제initdb 성공/ACL 복원. Python12기본native PASS, 추가 startup hook/손상/활성프로세스 보강 중. 최신전체시험은 아직 실행하지 않음.
- UI 2026-10-18 1차 vitest는174통과/1실패/2건너뜀(31파일중2실패): App.timezone hook10초와 AdminData 버튼대기. tsc PASS. 부하 분리 후 재검증 예정이며 원인 해결로 표시하지 않음.
- .release/model-free-20261018-candidate1 실제 조립/manifest 검증646파일,1,493,566,517바이트. **이후 수정이 있어 최종배포물/수락본 아님**. 새후보 빌드와 .qa/packaging/run-install-20261018.py 실제PG포트실패→같은root재개→HTTPS로그/PCAP→2회재실행/정지검증이 다음.
- 모델/업무스키마/탐지 기능변경 없음. 실제관리자서비스/깨끗한LTSC17763/운영인수/조직서명 미검증. 새ZIP·GitHub 게시 아직 하지 않음. 이전10/17배포는 그대로 유지.

## 2026-10-17 모델 제외 매체·기존 설치 업데이트/복구 검증

- 새 매체 후보5에 스키마0014·현재UI·행위 분석·통계·조사/Golden·룰/파서 콘텐츠·실제 CPU 실행기를 포함했다. 모델 가중치는 제외, 런타임 pin 변경/외부 다운로드 없음.
- 새 폴더 실제 설치→HTTPS/MFA→로그/내장HTTP PCAP→이벤트9·Finding10·노트→전체 종료/시작 보존, 설치 전체 owner/DACL 검사 PASS.
- 기존10/12 설치0011→0014→행위 분석/HTML→재시작→DB/색인 포함 전체0011복구→다시0014적용/분석/재시작 PASS. 기존9이벤트/8Finding/노트/키/MFA/원본 보존. 최신 트리는 retained로 별도 보관.
- 중간 후보2는 DACL 상속 상태 차이, 후보4 복구는 임시 경로 길이로 교체 전에 거부됐고 해당 실패를 기록했다. 복제 ACL·기존 owner/ACL 사전 검사·신규 설치 루트 보호·미디어 ACL staging 전파·디렉터리 열거 오류를 실제 Windows 회귀와 독립 검토로 보완했다. 기존 합성 QA의 권한만 별도 정비했으며 운영 권한 자동 수리는 하지 않는다.
- 서버1079/2건너뜀(559.62초), 화면177(31파일),tsc/build·주요Ruff·PS4구문 PASS. 실제 브라우저 룰/파서 r1 반입→4예제→독립 적용→영향 확인→사용중단/재조회 캡처6장. 과거r2 HTTP1→2→1과 구분.
- [설치](docs/OFFLINE-RELEASE-2026-10-17.md), [업데이트/전체복구](docs/OFFLINE-UPDATE-GUIDE.md), [실제 룰·파서 화면](docs/OFFLINE-CONTENT-GUIDE.md), [검증](docs/OFFLINE-RELEASE-VALIDATION-2026-10-17.md).
- **게시 완료:** [비공개 GitHub 사전 배포](https://github.com/dewdorp/SAW/releases/tag/v0.1.0-pilot.20261017) — ZIP 1,444,582,845바이트, 내부645파일 SHA검사·시험후보 실행파일 동일·원격10자산 크기/지문 대조 완료. ZIP SHA256 e2a09af4aee877a7d1c2f1fdf87de915a2a11491ae5010ac17aefe022fe90fe8. 소스 b4d81386d05a675a15c438f3ed3190ae831f5e75.
- **남은 게이트:** 깨끗한LTSC17763/물리적인터넷차단/16GB공동부하/관리자서비스·조직TLS/모델한국어품질·SFT/운영인수는 미완료. History503 원인미확정 유지. 원본Claude·은행자료·운영계정 미변경.

## 2026-10-16~17 웹 행위 분석·근거 보고서·Golden 증분

- 기존 조사/파서/Job/원문/요청비교/Check/종결/Experience/Golden을 재사용했다. 새 행위 분석 탭,5가지 이동 시간창,수집 품질,저장 버전·SHA,9절 A4 HTML,조건부 후속 질문과4-eyes 사례 내보내기를 연결했다. 모델·능동 스캔·훈련 없음.
- 스키마0014 및 saw-web-behavior/1.0, 질문 saw-web-behavior-questions/1.0. 백서 임계값은 참고이며 도구·AI·침해/정상 정답이 아니다. 원문 표본ID/동결 비교/쿼리/IPv6/미수집/멀티센서 경계를 유지한다.
- 최종 서버1004통과2건너뜀(326.44초), 화면177통과(31파일,25.56초),tsc/build/Ruff주요오류검사 성공. 실제 격리PG16.15/OS2.19.6 기능64+보완15시험(중복포함), 각 실행 종료·포트정리 성공.
- 실제 브라우저 A v2계산→구간확대→원문16건→두요청비교→Check저장→HTML, D UA미수집, B v2후속질문 확인. 별도HTTP로 종결→Experience→독립계정Golden승인→입력/정답Export→프로세스재시작 보존. 브라우저는 채택결과조회와실제ZIP다운로드까지 확인(승인클릭자체는HTTP).
- 독립검토P1 JSON비밀값노출/P2 masked필터근거누락/P2IPv6서비스충돌 수정·재검증. 브라우저CSP보고서서식/긴ID필터가로폭 수정. 기존History503 원인은 미해결 유지.
- [사용법·12장실제화면](docs/BEHAVIOR-ANALYSIS-GUIDE.md), [검증/환경게이트](docs/BEHAVIOR-VALIDATION-2026-10-16.md), [최신B보고서](docs/examples/behavior-case-B-report.html).
- NEXT: 기존10/12ZIP 미갱신. 새 모델제외 매체+스키마0014의기존설치전환·깨끗한LTSC17763·16GB공동부하·모델품질/운영인수는남는다. 현재개발OS Windows11build26200. 원본Claude·은행자료·운영계정미변경. 운영자료/고비용훈련/관리자설치/운영배포승인경계유지.

## 2026-10-15 조사 안내·Golden·오프라인 룰/파서 반입

- 같은 조사 안의 IP 방향·탐지·필터·기간에 따른 A–G 안내, 8가지 자료 상태, 실제 근거/조회 기록을 기존 Check와 종결·Experience에 연결했다. 자료 부족·조회 실패는 0건이 아니다. 후속확인 수정 시 원래 범위의 새 증거를 고를 수 있다.
- Experience와 별도로 Golden을 검토·채택하며 입력/정답 분리, 선택 근거 해시, ACL, 기여자와 검토자 분리, 사건군 train/dev/holdout 고정을 적용했다. 당시 Experience 종결 내용을 고정하고 빈 후속확인으로 검토를 대신하지 못하게 했다. 모델 훈련은 없다.
- **오프라인 룰·파서** 메뉴와 CLI: 데이터 전용 JSON 작성/내보내기 → 반입/변경 비교 → 양성·정상 예제 → 별도 승인·적용 → 영향 확인/되돌리기/감사. 수동 변경·동시 적용·private parser 노출·regex timeout·버전 재사용을 검증했다. 복원에 제3 검토자가 필요한 경우 UI에 이유를 표시한다.
- 스키마0013, 새 모듈·UI·테스트·합성 r1/r2와 실습 로그를 추가했다. 다음 매체 조립에 안내/예제/guidance YAML을 포함하도록 수정했다. **기존10/12 설치ZIP은 미갱신**이다.
- 최종 서버 **913통과·2건너뜀(274.99초)**, 화면 **162통과·30파일(49.77초)**, tsc/build/Ruff 성공. 실제 격리 PG16.15/OS2.19.6에서 **59통과 + 최종 보완4통과**, 각 실행 후 flush/종료/포트 정리 확인. 기존 큰chunk·deprecation 경고/History503 미해결 상태 유지.
- 실제 HTTP 합성: r1 3건 중1 → r2 3건 중2 → 독립 검토자 복원 후1. 파서1→2→1, Sigma1→2→보상3. Golden 별도 승인과 agent/evaluator export, 서버 재시작 후 Check3/복원 이력/파서1 기록3/Golden채택/agent export 보존 확인.
- 실제 브라우저는 사례A120건·118차단·2허용·같은조사IP·원문·후속확인·종결/Experience 검토요청까지. **콘텐츠 적용/복원과 Golden 채택/export의 최종 브라우저 실행·단계별 캡처는 도구 장애로 미완료**이며 HTTP/자동UI 시험으로 대체 완료 처리하지 않는다.
- 안내: [반입·적용·되돌리기와 r1/r2 실습](docs/OFFLINE-CONTENT-GUIDE.md), [조사 안내·Golden와 실제 종결 화면](docs/GUIDANCE-GOLDEN-GUIDE.md), [새 검증 기록](docs/GUIDANCE-CONTENT-VALIDATION-2026-10-15.md).
- **NEXT:** 브라우저 도구 복구 후 합성 전용 서버57285에서 콘텐츠/Golden 마지막 화면 흐름과 캡처 → 새 모델제외 매체/기존설치 전환 검증 → 깨끗한 LTSC17763·16GB 공동부하·모델/운영 인수. 개발시험OS는 Windows11 Pro build26200이다. 원본 Claude/은행자료/운영계정 미변경. 운영 데이터·훈련·관리자 설치·운영 배포/모델 교체 승인 경계 유지.

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

- 기준: Claude 원본 e0a7af5에서 생성한 새 독립 소스 작업본.
- 수정 대상: F:\codex\SAW-Claude-main
- 원본 F:\claude\saw는 수정하지 않음. 완료 시 HEAD e0a7af55e762daf4a8067cebc76054633319bde4·git status 깨끗함 확인.
- 작업 브랜치: codex/detection-packs
- 사용자 선택: 범용 규칙 우선, 조정 가능한 NDR 기준과 기본 비활성.
- 화면 의존성은 별도 사용자 허용 범위인 고정된 패키지·검증 정보만 사용. 패키지 버전/잠금 파일 변경 없음.

## 완료된 구현

- 기본 탐지 목록 UI: 묶음·검색·설명·예시·ATT&CK와 권한에 따른 켜기/끄기.
- 웹 규칙 184개(신규 18), 기존 경로 규칙 4개 보수적 교정. 최적화 누락 방지와 단계별 집계.
- NDR 정책 5종(기본 꺼짐), 필수 입력 누락·처리 상한 표시.
- 흐름 11종, 유한 시간·명시 역할·오래된 미검토 탐지 정리.
- 승인된 정확한 Sigma 버전의 제한된 조사 분석과 불완전 시험 거부.
- 사용법: docs/DETECTION-CATALOG-GUIDE.md
- 비교·출처·실행 기록: docs/DETECTION-VALIDATION-2026-10-11.md

## 이번 실행 결과

- 서버 전체 576 통과·1 건너뜀, 123.86초. 별도 PostgreSQL 시험 주소가 필요한 마이그레이션 시험을 건너뜀.
- 화면 88 통과. TypeScript·배포 UI build·변경 서버 Ruff E9/F 검사 통과.
- 실제 HTTP: 별도 가상 저장소/임시 서버의 claude-check 계정으로 로그인·MFA·규칙 변경·재조회·로그아웃 확인.
- 합성 592줄 업로드 → 비동기 작업 COMPLETED → 592이벤트·27탐지 결과(시그니처 11·흐름 3 포함). 시험 서버 종료 확인.
- 허용된 실제 웹 요청 439,461건 읽기 전용 비교: 새 184개 규칙 일치 0건. 일반적인 오탐 0% 주장이 아님.
- 최종 코드 검토에서 나온 경계 조건을 수정한 뒤 전체 시험을 실행. 그 뒤 제품 코드 변경 없이 문서와 커밋만 정리.

## 기능별 커밋

- 60a0246: 웹 규칙 확장·매처 정확성·단계별 집계.
- 4c59883: 승인된 Sigma 버전 평가·완전성·실행 상한.
- 19af35d: NDR 기준·흐름·조사 분석 연결·범위 안내.
- af90a7c: 탐지 목록 화면과 화면 시험.
- 이 기록과 사용 안내는 별도 문서 커밋에 포함.

## 2026-10-12 추가 검증 완료

- 사용자 위임: 일반 구현·시험 선택은 작업자가 판단. 원본 보존·운영 변경·4-eyes 경계는 유지.
- 실제 브라우저의 6단계 안내: docs/DETECTION-LIVE-WALKTHROUGH.md.
- 시간대/행동 순서 결함 수정: 0a21bed, 5dc5483.
- 실제 PG16.15/OS2.19.6 초기 전체577통과 + 순서수정 영향13통과. Windows11 개발기 검증으로 LTSC 검증 아님.
- 최종 SQLite587통과1건너뜀(exit0), UI93통과·tsc/build 성공. 환경 갱신으로 중단된 최초 SQLite 실행은 성공으로 세지 않음.
- 상세: docs/DETECTION-VALIDATION-2026-10-12.md.

## 다음 실행 — 로컬 AI와 모델 제외 배포

2026-10-12 사용자가 AI 모델 연결, 별도 반입 모델 선택·변경, 모델을 제외한 실제 폐쇄망 설치 패키지, 본인 GitHub 계정 업로드를 추가 요청함.

1. 로컬 모델팩 검증·선택·CPU 실행 및 관리 화면. 기본 Foundation-Sec-8B BASE/revision 유지. 모델 변경은 사용자 명시 선택. 합성 실행·출력 검증·한국어 품질·운영 채택 구분.
2. Assistant의 다른 비공개 조사 문맥 혼입을 차단하고 승인·접근 가능한 Experience만 사용. 잘못된 생성 형식·인용은 검증된 답변으로 표시하지 않음.
3. Python·실제 의존성·빌드 UI·PG·OpenSearch·내장 PCAP·LLM native runtime을 포함하되 모델 가중치는 제외한 설치 매체 생성/검증. 대상 PC에 Python/Node/Git/Docker를 요구하지 않음.
4. 운영 자료·계정·비밀값·모델 파일을 제외한 배포물을 dewdorp 계정의 새 비공개 GitHub 저장소에 업로드. CLI 인증은 sandbox 밖에서 확인됨.
5. 깨끗한 LTSC2019/16GB·32GB/무GPU 실검증 및 운영 데이터·배포·모델 교체 승인은 별도 유지.

현재 개발 Python은 원본의 제3자 패키지를 읽기 전용 참조하므로 독립 오프라인 설치본이 아니다. 이를 배포 패키지에 그대로 복제하지 않는다.

## 2026-10-12 로컬 모델·오프라인 설치 진행

- 모델팩 검증/등록/선택/해제 API와 관리자 화면 구현. 별도 반입 도구 `python -m saw.devtools.model_pack` 및 `docs/LOCAL-MODEL-GUIDE.md` 추가.
- Foundation-Sec-8B의 지정 revision/Q4_K_M 파일 전체 hash 재검증. 최종 MinGW 정적 llama.cpp b11429/d812350의 두 실행 파일 실제 LPAC `--help`와 CPU 추론 성공.
- 최종 native API 검증·선택·해제 각각 HTTP200. 합성 한국어 요청은 입력88/출력62토큰 실제 생성·JSON구조 유효지만 영어응답/인용불일치로 품질 미채택. 시간187.297초는 포장/PG시험 병행 조건으로 성능 보장이 아님.
- CPU실행은 합성 조사 allowlist 전용. 문맥 접근권한과 승인상태를 검사하고 생성 후 세션·권한·모델선택 변경을 재검사. 형식/인용 실패는 답변 저장을 거부.
- 서버 전체677통과·2건너뜀(개발SQLite 기준). 건너뜀: 별도PG 미설정 migration, Windows symlink 생성권한. 실제 directory junction source/inbox 차단 추가9통과·symlink1건너뜀. PG실행 검증은 진행 중.
- 화면110통과·tsc/build성공. 병렬컴파일과동시 최초실행에서 기존timezone시험1회timeout, 코드/시간제한 변경 없이 worker2 전체 재실행통과. 실제 브라우저 로그인/MFA·파일검증·선택·해제·재시작 상태복원 확인. 최종 static 모델도 브라우저에서 실제 선택·해제 성공. 조사 문맥 Assistant는 cpu_native_failed/EXECUTED_OUTPUT_UNVERIFIED로 실패·답변0건이며 과거실패원인은 기록부족으로 미확정. 시험계정비활성화·로그아웃·서버종료 완료.
- 실제 model-free 설치 매체 약1.34GB 조립 및 신규 폴더에 포함Python3.12.10/62의존성·PG·OpenSearch·TLS·schema0011/최초admin 생성 성공(개발Windows11). 최종runtime 포함봉인·HTTPS분석/재시작·GitHub게시 전 검증 진행 중.
- 깨끗한 LTSC17763·16/32GB 무GPU 공동부하·서비스 설치/방화벽·조직TLS 신뢰·운영데이터/운영모델 승인은 미검증/별도승인 경계로 유지.

설치 재시작 회귀에서 NoAdmin의 async durability와 Java 강제 종료로 이벤트가 사라지는 결함을 발견했다. request durability·종료 전 flush·503 상태검사·PS5.1 cold-start 실패 처리를 수정하며 새 설치본에서 재검증 중이다. 서비스 런타임 환경 구성 코드 변경의 최초 자동 승인 거절은 이후 사용자의 코드·구성 파일 명시 승인으로 해소했다. 실제 서비스 등록은 실행하지 않았다.

## 최종 시험과 게시 진행

- 2026-10-12 진단 보완 후 전체 서버 691통과·2건너뜀(145.50초, exit0), 화면115통과·tsc/build 성공. 기존 UI timeout 기록과 실제 Assistant 원인 미확정 실패는 유지한다.
- 실제 PostgreSQL16.15의 migration0011·모델 API·문맥 권한48통과, 전용 인스턴스 정상 종료.
- GitHub https://github.com/dewdorp/SAW 비공개 저장소를 만들고 검사된 소스를 main에 게시했다. 모델/운영자료/자격증명은 제외했다. 설치 ZIP 게시와 최종 재시작 보존 확인은 아직 진행 중이다.
- 다음: 수정된 매체 신규 설치 → HTTPS 합성 로그/PCAP/노트 → 종료/재시작 후 보존 → 문서만 최종 갱신하여 실행 파일 해시 동등 확인 → ZIP/checksum/manifest 사전 배포.

사용자가 PostgreSQL 서비스의 **코드·구성 파일 수정만** 명시 승인했다. 패키지 런타임을 서비스가 찾도록 WinSW 구성/설치 코드와 가상 시험을 보완한다. 실제 관리자 설치·서비스 등록·방화벽 변경은 실행하지 않는다. 앞선 자동 승인 거절은 이 코드 범위 승인으로 해소되었으며 대상 서비스 실행 인수와는 구분한다.
