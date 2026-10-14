# SAW 구현 진행 현황 (자동 재개용)

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
