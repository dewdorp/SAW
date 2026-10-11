# SAW 구현 진행 현황 (자동 재개용)

> 이 파일은 **작업 재개의 기준점**이다. 새 세션/자동 실행은 이 파일을 먼저 읽고 `NEXT` 항목부터 이어간다.
> 완료(✅) 항목은 재구현하지 않는다. 환경 미검증 항목은 [ENV-VERIFICATION.md](ENV-VERIFICATION.md)에 기록한다.
> 사용자 지시(2026-10-06): 단계별 승인 대기 없이 남은 구현·테스트·브라우저 검증을 계속 수행.

## 실행 환경 메모
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

## NEXT
1. 서버 현장: 관리자 권한으로 install.ps1 실행 → 서비스 자동 시작·재부팅·방화벽·인증서 배포 확인 (ENV-19~21)
2. 백업·복구 리허설 (ENV-22), 저사양 서버 성능 측정 (ENV-13)
3. (선택) Suricata Windows IDS 경보, Monaco 편집기, Case PDF/DOCX export, Custom Parser UI
