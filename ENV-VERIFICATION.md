# 환경 검증 항목 추적

## 새 복사본의 최신 검증 (2026-10-12)

수정 대상은 `F:\codex\SAW-Claude-main`이며 원본 `F:\claude\saw`는 보존했습니다. 아래 A/B/C 표는 원본에서 가져온 과거 이력이고 새 작업본의 실행 증거로 재사용하지 않습니다. 현재 결과는 [설치 검증](docs/OFFLINE-RELEASE-VALIDATION-2026-10-12.md)과 [AI 검증](docs/LOCAL-AI-VALIDATION-2026-10-12.md)을 우선합니다.

| 항목 | 새 작업본에서 실제 수행한 범위 | 남은 조건 |
|---|---|---|
| 독립 설치 매체 | 포함 Python 3.12.10·62개 wheel·PostgreSQL16.15·OpenSearch2.19.6/nori·빌드 UI·내장 PCAP·CPU 실행기 | 깨끗한 LTSC17763, 물리적 인터넷 차단 시험 |
| 저장·재시작 | 새 설치본의 HTTPS/MFA, 합성 로그·PCAP 분석, 9이벤트/8Finding/노트 보존 | 저사양 다중 분석가 동시 부하·장애/재부팅 인수 |
| 합성 백업·분리 복원 | 실제 백업, 별도 PostgreSQL DB와 새 OpenSearch 색인 복원, 증거 파일 SHA 비교 | 운영 자료·장비 교체/전체 재해 복구 인수 |
| Windows 서비스 | 사용자 승인 범위의 WinSW 코드·XML, NetworkService/경로/준비 대기 회귀 | 실제 관리자 등록·서비스 ACL·TLS·종료/자동 시작 미실행 |
| Foundation-Sec-8B | 고정 revision/Q4_K_M의 실제 CPU 생성·선택·해제, 합성 전용 | 한국어/인용 품질 미채택, 실제 조사 화면 질문 실패 원인 미확정 |
| 모델 반입·변경 | 별도 매체 검증/등록/명시 선택·해제 UI/API, 지원 형식 제한 | 다른 실제 모델의 품질·운영 채택 별도 검증 |
| 학습 | 이번 작업에서 optimizer/SFT/adapter 학습·재로딩 실행 안 함 | 별도 학습 요구와 승인 경계 유지 |

운영 데이터 반입·학습, 관리자 설치, 운영 배포와 모델 교체는 이번 개발 검증이 승인하지 않습니다. 본체 매체에 모델 가중치와 브라우저 설치 파일은 없으며 분석가 PC에는 조직이 승인한 호환 Chrome/Edge가 별도로 필요합니다.

---

운영 대상: **Windows 10 Enterprise LTSC 2019 x64, 폐쇄망** ([ADR-0016](docs/adr/0016-windows-airgapped-deployment-and-builtin-pcap.md)).
아래 "검증"은 개발 PC(Windows 11, PowerShell 5.1)에서 **실제 프로그램을 띄워 자동 테스트·E2E로 확인**했다는 뜻이다.

## A. Windows 폐쇄망 운영 프로필

| ID | 항목 | 검증 방법 | 상태 |
|---|---|---|---|
| ENV-02 | PostgreSQL 16 (EDB Windows 바이너리 16.15) | 전체 테스트 72개를 PostgreSQL 대상으로 실행 (`SAW_TEST_DATABASE_URL`) | ✅ 검증 (2026-10-07) |
| ENV-03 | OpenSearch 2.19.6 Windows + nori, Index Template·Alias | 전체 테스트를 OpenSearch 대상으로 실행 (`SAW_TEST_OPENSEARCH_URL`), nori 형태소·wildcard 확인 | ✅ 검증 (2026-10-07) |
| ENV-02+03 | PostgreSQL + OpenSearch 동시(운영 조합) | 전체 테스트 동시 대상 실행 | ✅ 검증 |
| ENV-06a | PCAP 분석 (내장 분석기, Zeek 불필요) | 단위 테스트(JA4 공식 벡터, pcapng, 손상 입력) + API E2E + 설치본 E2E | ✅ 검증 |
| ENV-06c | PCAP 포렌식 엔진 v2 (재조립·HTTP 본문·파일 추출·평문 인증·ARP·탐지기 9종) | 단위 테스트(순서 뒤바뀜·gzip/chunked·위장 파일·FTP·SMTP·비밀번호 미저장·ARP·중복) + E2E(모든 탐지기·IOC) + 브라우저 확인 | ✅ 검증 (2026-10-08) |
| ENV-23 | DB 마이그레이션 (Alembic) | 새 DB upgrade = 모델 일치, 기존 create_all DB stamp→upgrade, 개발 DB 실제 이전 | ✅ 검증 (SQLite·PostgreSQL) |
| ENV-24 | SBOM·라이선스 고지 | build-bundle에서 CycloneDX 1.5 생성 (133개 구성 요소) | ✅ 검증 |
| ENV-25 | 화면 개편 (사이드바·PCAP 포렌식 탭·스트림 보기) | 개발 서버 브라우저 확인 (1440×900) | ✅ 확인 |
| ENV-17 | 오프라인 설치 묶음 (wheel 63개, 체크섬) | 새 venv에 `--no-index` 설치 + `pip check`, build-bundle.ps1 실행 | ✅ 검증 |
| ENV-18 | install.ps1 설치 흐름 | 별도 폴더에 dry run(서비스 제외) → 설치본으로 HTTPS 기동 → 관리자/분석가 로그인·PCAP 분석·감사 체인 E2E | ✅ 검증 (서비스 등록 제외) |
| ENV-19 | Windows 서비스 등록 (WinSW·procrun·pg_ctl), 재부팅 후 자동 시작, 장애 시 재시작 | **관리자 권한**으로 install.ps1 실행 후 재부팅 | ⏳ 서버(또는 관리자 권한 PC)에서 확인 필요 |
| ENV-20 | 방화벽 규칙·분석가 PC 접속·인증서 신뢰 배포 | 분석가 PC 브라우저 접속 | ⏳ 서버 현장 확인 |
| ENV-21 | 실제 OS(Windows 10 LTSC 2019, 빌드 17763)에서의 동작 | 서버에서 설치·스모크 테스트 | ⏳ 서버 현장 확인 (개발 PC는 Windows 11) |
| ENV-22 | backup.ps1 (pg_dump·스냅샷·증거 미러) 및 복구 절차 | 백업 → 별도 서버 복구 리허설 | ⏳ 미검증 |
| ENV-06b | Suricata(Windows)로 IDS 경보 추가 | Npcap 라이선스 확인 후 설치, `SAW_SURICATA_PATH` 설정 | ⏳ 선택 항목, 미검증 |
| ENV-13 | 성능 (저사양 서버 기준 처리량) | 실제 서버에서 대용량 로그/PCAP 측정 | ⏳ 미검증 |

## B. 대체되었거나 Windows 프로필에서 쓰지 않는 항목

| ID | 항목 | 상태 |
|---|---|---|
| ENV-01 | Docker Compose 전체 기동 | ⛔ 대체 — 운영 OS에서 Docker 불가, Windows 네이티브 설치(install.ps1)로 대체 |
| ENV-04 | S3 ObjectStore (MinIO) | ⛔ 미사용 — 로컬 NTFS 저장(`object_store=local`) |
| ENV-05 | Celery + Valkey | ⛔ 미사용 — 내장 작업 실행기(`job_runner=inprocess`) |
| ENV-07 | 샌드박스 (seccomp, nsjail) | ⛔ Linux 전용. Windows에서는 외부 도구 미사용(내장 PCAP 분석기)으로 위험 축소 |

## C. 공통 (운영 환경·외부 자료 필요)

| ID | 항목 | 필요한 것 | 상태 |
|---|---|---|---|
| ENV-08 | Local LLM (Ollama Windows) | 모델 파일 반입, 서버 메모리 | 미검증 (기본값: 결정적 템플릿) |
| ENV-09 | 임베딩 모델 | 모델 파일 | 미검증 (pgvector는 Windows 바이너리 없음 → 내장 유사도 사용) |
| ENV-10 | 외부 Enrichment Egress Proxy | 폐쇄망 정책 | 해당 없음(폐쇄망) — 수동 조회만 |
| ENV-11 | Logpresso 실제 Connector | 공식 API 문서·계정 | 미착수 (모의 커넥터만) |
| ENV-12 | ATT&CK 전체 STIX 번들 | 번들 반입 | 미검증 (내장 subset) |
| ENV-14 | 오프라인 ASN/Geo DB 실데이터 | 라이선스 DB | 미검증 (fixture CSV) |
| ENV-15 | libinjection 네이티브 바인딩 | 빌드 환경 | 미검증 (결정적 휴리스틱 사용) |
| ENV-16 | RE2 기반 Custom Parser | re2 wheel | 미검증 (`regex` timeout 사용) |
