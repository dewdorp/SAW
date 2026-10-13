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
