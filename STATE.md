# 현재 작업 상태

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

설치 재시작 회귀에서 NoAdmin의 async durability와 Java 강제 종료로 이벤트가 사라지는 결함을 발견했다. request durability·종료 전 flush·503 상태검사·PS5.1 cold-start 실패 처리를 수정하며 새 설치본에서 재검증 중이다. 서비스 런타임 환경 구성 코드 변경은 자동 승인 검토가 거절하여 별도 명시 승인을 요청했고, 해당 경로는 보류했다.
