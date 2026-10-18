# Windows 설치 복구 검증 기록 — 2026-10-18

이 문서는 설치기 수정의 검증 진행 기록이다. 제품 전체 완료, 운영 인수, 깨끗한 LTSC 2019 설치 성공을 뜻하지 않는다. 기존 기록의 PASS를 이번 결과로 옮기지 않았다. 최종 서버 전체 시험은 완료했다. 새 매체의 합성 통합 설치·재개·반복 실행도 완료했다. 배포물 봉인·게시의 정확한 수치는 별도 매체 manifest와 release-verification.json, GitHub 게시 기록으로 관리한다.

## 범위와 실행 환경

- 수정 작업본: F:\codex\SAW-Claude-main. 사용자가 이미 설치한 **C:\SAW는 변경하지 않았다**. 운영 DB·계정·비밀값·인증서·서비스를 초기화하거나 다시 설치하지 않았다.
- F:\claude\saw 원본과 실제 은행 자료는 수정 대상에서 제외했다. 검증 입력은 격리된 합성 자료다.
- 설치 위치, Java/서비스, PostgreSQL 권한/초기화, Python 준비, 설치 재개·검증·패키징만 다룬다. 탐지·헌팅·모델·Golden 등 업무 기능과 업무 스키마를 변경하는 작업이 아니다.
- 실제 호스트: **Windows 11 Pro build 26200, 비관리자 토큰**. 시험에서 명시적으로 실행한 Windows PowerShell은 **5.1.26100.9711**이다. 명령 조율 셸 7.6.5와 구분한다.
- 유지한 런타임: Python 3.12.10 x64 embedded, PostgreSQL 16.15-1, OpenSearch/nori 2.19.6, 포함 JDK 21.0.11 x64, WinSW 2.12.0. 모델 가중치는 본체 매체에서 제외한다.
- 실제 관리자 서비스 등록·재부팅·LTSC 17763 시험은 수행하지 않았다. 개발 호스트가 물리적으로 인터넷과 단절되었다고 주장하지 않는다.

## 오류별 원인과 수정

### A. OpenSearch

이전 setup-opensearch.ps1은 OPENSEARCH_JAVA_HOME만 설정했다. 실제 포함된 opensearch-service.bat의 doInstall은 JAVA_HOME으로 jvm.dll을 찾고 procrun 등록 인자에도 그 경로를 사용한다. JVM을 찾지 못하는 분기는 오류를 출력한 뒤 goto:eof로 빠져나가며 명시적인 실패 코드 설정이 없다. 이전 호출자는 종료 코드만 검사한 뒤 Start-Service로 진행했고 서비스 존재·등록 경로를 확인하지 않았다. 기존 서비스는 먼저 제거하는 방식이었다.

포함 배포본 bin/opensearch-service.bat의 105–118행 및 225행을 직접 대조했다. 수정 소스 — deploy/windows/setup-opensearch.ps1, 시험 — tests/unit/test_opensearch_install.py.

- 포함 JDK의 파일·release·ZIP 원본 바이트를 먼저 확인하고 실제 Java 버전/64비트를 검사한다. 핵심 JAR·서비스 실행 파일도 확인한다.
- 자식에 JAVA_HOME과 OPENSEARCH_JAVA_HOME을 함께 전달한다. 외부 Java/procrun 옵션을 자식에서 제거하고 부모 환경을 보존한다.
- 종료 코드와 실제 서비스 조회 결과를 모두 검사한다. 실행 파일·JVM·작업 폴더·home/config가 선택한 루트와 일치해야 한다.
- 서비스가 등록되지 않았거나 등록이 실패하면 시작하지 않는다. 정상 실행 중인 동일 서비스는 재등록·재시작하지 않는다. 다른 경로의 동명 서비스는 보존하고 중단한다.
- 자동 시작·복구 정책도 적용 결과를 조회한다. 설치기가 소유한 미완료 정책만 이어 적용하고 기존 운영자의 정책을 무조건 덮어쓰지 않는다.

SCM 조회·등록·시작·정책 시험에는 대체 함수를 사용했다. 실제 JDK 실행과 자식 환경 전달 성공을 관리자 서비스 등록 성공으로 세지 않는다.

### B. PostgreSQL

이전 기본 서비스 프로필은 secrets를 Administrators와 SYSTEM만 읽도록 만들었다. PostgreSQL 16 initdb는 비밀번호 파일을 읽기 전에 제한된 Windows 토큰으로 자기 자신을 다시 실행하며, Administrators/Power Users 그룹 권한을 비활성화하는 경로가 있다. DB의 -U postgres는 Windows 실행 계정을 지정하지 않는다. [공식 initdb 호출 순서](https://raw.githubusercontent.com/postgres/postgres/REL_16_STABLE/src/bin/initdb/initdb.c), [공식 restricted-token 구현](https://raw.githubusercontent.com/postgres/postgres/REL_16_STABLE/src/common/restricted_token.c).

설치 소스 — deploy/windows/setup-postgresql.ps1, ACL·클러스터 검사 — deploy/windows/setup-postgresql-state.ps1, 런타임 검사 — saw/devtools/postgresql_runtime.py.

- 실제 WindowsIdentity.User SID에 대상 비밀번호 파일 Read, 필요한 상위 폴더 Traverse만 임시 부여한다. 다른 secrets에 읽기 권한을 상속시키지 않는다.
- 초기화에 필요한 런타임·신규 데이터 범위는 별도로 제한한다. 정상 종료와 처리 가능한 오류에서는 finally로 원래 DACL을 복원한다.
- 기존 비밀번호·역할·DB를 재생성하지 않는다. 비밀번호를 명령줄이나 오류 출력으로 전달하지 않는다.
- PG_VERSION 하나 대신 필수 파일/디렉터리·버전·control-file 크기와 실제 pg_controldata를 확인한다.
- initdb -c에 포트·loopback listen·SCRAM·메모리·UTC를 전달해 성공 직후 이미 선택한 설정이 적용되게 했다.
- 실제 접속한 data directory와 앱 초기화 상태를 구분한다. 기존 설정·실행 파일·서비스 구성 충돌은 보존하고 중단한다.

실제 PG 16.15로 BA+SYSTEM-only 비밀번호 파일의 Permission denied를 재현했다. 같은 합성 조건에서 프로덕션 임시 ACL 핵심 함수를 적용한 후 실제 initdb와 클러스터 확인이 성공했다. 파일·폴더의 원래 DACL과 형제 secret의 DACL 보존도 확인했다. 현재 비관리자 토큰에서 이미 알고 있는 격리 경로에 핵심 함수를 호출한 시험이며, 관리자 전용 경로 검사까지 포함한 전체 설치 성공은 아니다.

**강제 중단 ACL 경계:** 프로세스 강제 종료·전원 중단에서는 finally가 실행되지 않을 수 있다. 임시 ACL 복원 정보를 영속화하는 별도 journal은 구현하지 않았다. 일반 오류 후 정확한 원복 PASS와 강제 중단 복구를 구분한다. 강제 중단 후에는 재개 전에 해당 임시 부여 범위를 점검해야 하며, 설치 루트 전체 ACL 초기화로 해결하지 않는다.

### C. Python과 설치 재실행

이전 설치기는 venv\Scripts\python.exe가 있으면 정확히 “Existing Python runtime: choose a fresh install directory.” 오류를 냈다. 상위의 비어 있지 않은 루트/기존 .env 거부도 부분 설치 재개를 막았다.

Python 준비 — deploy/windows/install-python.ps1, 상태·잠금 — deploy/windows/install-state.ps1, 진입점 — deploy/windows/install.ps1, 완료 검사 — saw/devtools/install_verify.py.

- 원본 ZIP 파일 동일성, 지정 _pth, 실제 3.12.10/x64 실행, 62개 고정 의존성 버전·주요 import·pip dependency closure를 확인하고 정상 런타임을 재사용한다.
- 압축 해제 전에 비밀값 없는 소유 표식을 기록한다. 관리되는 중단 파일·누락 의존성은 전체 트리를 venv.retained-*에 보관하고 로컬 매체로 다시 준비한다. 다른 버전·개발 venv·출처 불명·사용자 변경은 삭제하거나 무조건 덮어쓰지 않는다.
- 복구 이동 직전에 실행 프로세스·서비스를 확인한다. 실행 중이거나 Python 실행 경로를 확인할 수 없으면 이동하지 않는다. 정상 재사용은 허용한다.
- 실제 embedded Python에서 -S에도 _pth의 import site가 적용됨을 확인했다. Scripts·site-packages·app의 미승인 .pth/sitecustomize/usercustomize를 실행 전에 거부한다.
- 루트 단위 잠금과 원자적 journal로 단계·이전 running/failed 상태·완료 단계·비밀값 없는 종료 코드를 남긴다. 정상 설치는 읽기 전용 검증 모드로 종료한다.
- 기록 없는 과거 부분 설치는 원래 검증 매체로 출처를 확인한다. 설치 재개와 앱 업데이트를 구분한다. NoServices 구성만으로 사용 가능한 설치 완료를 표시하지 않는다.

venv.retained-*는 자동 삭제하지 않으므로 반복 실패 시 보관 사본 용량도 산정해야 한다.

## C: / D: 위치 선택

기존 -InstallRoot와 새 -ChooseInstallLocation 입력을 사용한다. 프로그램·Python·DB·색인·원본·로그·백업·모델이 선택한 로컬 절대 경로 아래에 배치된다. 최소 20GB 확인은 운영 용량 보장이 아니다.

경로 미리보기, 매체 중첩·드라이브 최상위·별칭·정션 거부, 한글·공백 경로는 자동 시험에서 다뤘다. 실제 D:\SAW 운영 설치 또는 기존 C:\SAW의 D: 이전은 수행하지 않았다. 명령과 위치별 설명은 [설치·재실행 가이드](../INSTALL-RECOVERY-2026-10-18.md)를 따른다.


## 이번 통합 시험에서 발견한 추가 오류

후보2의 실제 한글 설치 루트에서 initdb post-bootstrap 단계가 UTF8 byte sequence 오류로 실패했다. 의도했던 포트 점유 오류에 도달하기 전 발생했으므로 포트 충돌 시험 성공으로 세지 않는다. 기존 initdb 단독 시험은 데이터 경로만 한글이고 PostgreSQL 실행·share 경로는 ASCII였다는 차이가 확인됐다. 전체 런타임 경로까지 한글인 합성 회귀에서 실패를 별도로 재현했다. UHC client_encoding 변경은 파일 경로 이중 변환 때문에 실패했고 8.3 이름에도 한글이 남아 해결되지 않았다. 사용자 세션의 고유 DOS 별칭을 초기화 입력 share에만 잠시 연결하는 adapter로 실제 initdb가 성공했다. DB 인코딩·시스템 ACP·원본 파일·ACL은 바꾸지 않는다. 성공/실패 후 동일 target만 제거하며 충돌을 거부한다. 실제 DB 설정과 카탈로그에 별칭 잔존 0건을 확인했다. 독립 검토에서 SYSTEM 실행은 global namespace에 생성될 수 있음을 지적하여 이 분기를 실행 전에 거부하도록 보완했다. 전원 중단/강제 종료가 finally를 우회하면 세션 별칭이 로그오프까지 남을 수 있다. 영속 파일·드라이브 문자는 만들지 않는다. 전체 새 매체 통합은 별도로 검증한다.

추가로 data_directory 메타데이터가 실제 Windows ACP 바이트를 반환하는 문제를 확인했다. 경로는 hex로 운반해 실제 ACP로 엄격하게 복원하며 선택 루트와 다시 대조한다. psql SQL 입력은 UTF8 BOM 없는 바이트, 자식 client_encoding과 출력은 UTF8로 고정한다. Python의 경로 확인 연결과 앱 확인 연결도 client_encoding=UTF8로 고정해 외부 PGCLIENTENCODING=WIN949의 영향을 받지 않도록 했다. 최종 한글 런타임 단독 native 시험은 initdb→별칭 제거→서버 시작→실제 data_directory 일치→한국어 TEMP TABLE 삽입/조회 원문 일치→정지까지 18.92초에 통과했다. 전체 인수와 별도 증거다.

후보3로 기존 합성 설치본(10/17, 설치 journal 없음)을 중지 상태에서 검증한 실행은 성공했다. 서비스를 시작하지 않았고, live 검사는 NOT_RUN으로 구분했다. 이 실행 중 helper의 한글 메시지 BOM이 빠져 깨지는 문제도 관찰하여 UTF8 BOM을 복원하고 회귀를 추가했다. 후보4에 BOM과 회귀 검사를 포함했다.

후보4 최초 설치 시험의 실행기 제한 1200초가 PostgreSQL 압축 해제 도중 만료됐다. 당시 최상위 설치는 running/PostgreSQL 상태였으며, 약 1.5만 파일이 생성돼 있었다. PG 원래 오류 또는 포트 충돌 PASS로 세지 않는다. 압축 해제 자식 프로세스가 여전히 동작해 20,150개 파일 written/verified와 자식 프로세스 종료를 확인한 뒤 같은 폴더·매체로 재개했다. 폴더·런타임은 삭제하지 않으며, 후속 시험 실행기의 단계별 제한을 2400초로 늘렸다. 설치 스크립트 자체의 시간 제한을 높인 변경은 아니다.

후보4 재개는 의도한 PG 포트 충돌과 최상위 비영 종료를 확인한 뒤 같은 경로에서 설치 완료했다. 실제 HTTPS/MFA와 합성 로그·내장 HTTP PCAP 작업 두 개, 이벤트 9건/Finding 10건/노트 저장, 종료·시작 뒤 보존은 통과했다. 그러나 첫 완료 설치 재검사에서 열거된 data/postgresql/base/16385/pg_internal.init가 Get-Item 전에 사라져 실패했다. 이 결과를 정상 설치 반복 검사 PASS로 세지 않는다.

이 파일은 PostgreSQL relcache 내부 캐시로 트랜잭션 종료·서버 시작 때 unlink하거나 PID 임시 파일을 rename한다. 공식 relcache.c의 삭제/ENOENT 처리와 실제 오류를 대조했다. [PostgreSQL 공식 구현](https://raw.githubusercontent.com/postgres/postgres/REL_16_STABLE/src/backend/utils/cache/relcache.c). 후속 보완은 data/postgresql/global 또는 base/<숫자 DB OID> 아래 pg_internal.init[.<PID>]의 열거 당시 일반 파일이 실제 FileNotFound인 경우로 제한한다. 존재하면 기존 검사, 접근거부/다른 I/O/부모 변경/재파스/다른 파일 누락은 계속 실패해야 한다. 후보5에서 최종 정상 설치 반복 검사를 완료했다. 수정 전 실제 파일 소멸 회귀 3건 실패를 재현한 뒤 전체 상태 시험 36건을 통과했고, 부모 식별자/권한·재파스·접근거부·다른 파일 소멸 경계를 검토했다.

## T01–T12 매핑

| 요구 | 구현·관찰한 근거 | 남은 검증 |
|---|---|---|
| T01 빈 Java 변수 + 포함 JDK | 전용 JDK와 두 변수 전달 자동 시험, 실제 포함 Java 버전/64비트·자식 실행 | 후보4 실제 사용자 프로세스 설치·재개 PASS, 후보5 완료 검증 PASS. 관리자 등록·LTSC 미실행 |
| T02 다른 Java 보존 | 실제 자식에서 지정 변수 전달·외부 옵션 제거·부모 변수 보존. 등록은 서비스 스텁 | 실제 서비스 등록 후 로그오프/재부팅 미실행 |
| T03 Java/JVM 누락 | 합성 파일 구조에서 등록·시작 전 거부. 핵심 JAR 변조/누락은 Java 실행 전 거부 | 실제 관리자 서비스·LTSC 미실행 |
| T04 등록 실패 | 비영 종료와 종료 0+서비스 부재를 별도 시험, 시작 호출 없음 | 실제 SCM 실패 유발은 미실행 |
| T05 서비스 재사용/충돌 | 등록 경로·정책 확인, 정상 실행 중 재등록/재시작 없음, 다른 경로 보존 | 조회·변경은 스텁. 실제 관리자 서비스 재사용 미실행 |
| T06 비밀번호 ACL | 실제 initdb Permission denied RED → SID 임시 권한 GREEN. 파일/폴더/형제 DACL 원복 | 비관리자·격리 경로의 핵심 함수 시험. 전체 관리자 설치·LTSC·강제 종료 ACL 원복 미검증 |
| T07 PG 실패 후 재개 | 실제 embedded Python 반복 재사용, journal 실패/중단 재개와 실패 단계 완료 오인 방지 | 후보4 실제 포트 충돌 비영 종료→같은 root 재개 PASS. 선행 실행기 시간 초과는 별도 기록 |
| T08 Python 구분 | 실제 런타임 준비·누락 복구·공식 _pth 중단·변조/개발 venv 거부·실행 중 native Python 복구 거부 | 최종 전체 서버 시험에 20사례 포함. 중간 중단 실행 자체는 전체 PASS 아님 |
| T09 DB 보존 | 실제 control/config 반복 확인, 잘못된 설정 거부·보존. setup/runtime/완료 검사 자동 시험 | 후보4 설정/비밀값 바이트·mtime 보존, 재실행 뒤 합성 이벤트/Finding/노트/작업·계정 상태 조회 PASS. 운영 데이터 미사용 |
| T10 정상 설치 두 번 재실행 | journal verify 두 번의 내용/mtime 보존. 완료 검사기의 읽기 전용·중지/부분 실행 구분 | 후보4 설치본에 후보5 완료 검증 두 번·중지 상태 확인 PASS. 계정 암호/MFA/역할·상태는 메모리 readonly 비교. 실제 서비스/운영계정 시험 아님 |
| T11 경로·PS5.1·중단·중복 | PS5.1에서 실제 Python/initdb/배치 한글·공백 경로. 잠금·journal·원자 저장 자동 시험 | 깨끗한 LTSC, 실제 전원 중단, 관리자 서비스/모든 드라이브 조합 미실행 |
| T12 최종 매체 | 원래 빌드/진입점에 새 helper 연결. 후보5의 650파일과 manifest 자체 검증 완료 | 시험 후보5에 캐시 경합 수정 helper 포함. 최종 ZIP은 후보5와 실행 payload가 같아야 봉인/게시 가능; 정확한 결과는 외부 release-verification.json 및 게시 기록 참조 |

부분 근거를 합쳐 T01–T12 전체 PASS로 처리하지 않는다. SCM 스텁, initdb 단독, journal 시험은 각각 전체 설치나 대상 OS 인수를 대체하지 않는다.

## 실행 결과

실행 사이에 겹치는 시험이 있으므로 수치를 합쳐 고유 시험 총수로 보고하지 않는다.

| 실행 | 결과 | 종류·제한 |
|---|---|---|
| 설치 경로·상태 | 27 passed, 기존 경고 1, 93.33초 | 실제 Windows 파일/ACL/journal/잠금 자동 시험. .qa/packaging/install-path-state-final1.log |
| 추가 경로/기존 PG runtime 검사 | 드라이브 최상위 trim 회귀 RED→GREEN 1사례, PG 누락/수정 binary 검사 3사례 포함 state 17 passed | 부모 담당의 추가 결과. 전체 native 통합과 구분 |
| OpenSearch | 32 passed. 원본 바이트 검사 순서 보완 관련 10 passed | 실제 PS5.1·일부 JDK/자식 실행. 서비스는 스텁 |
| OpenSearch 공개 runtime 대조 | ZIP↔격리 설치 JAR·Java·procrun 동일성 PASS, 6.4초 | 서비스 실행·등록 없음 |
| Python 선행 | 12 passed, 기존 경고 1, 382.22초 | 실제 embedded/고정 의존성. 후속 보완 전 결과 |
| Python 추가 3사례 | 3 passed, 195.85초 | 시작 코드·중단 보완의 실제 런타임 시험 |
| Python 마지막 5사례 | 5 passed, 15 deselected, 기존 경고 1, 105.34초 | 공식 _pth 복구·app 시작 코드·실행 중 native Python. 경로 불명/서비스 상태는 조회 스텁 |
| Python 중간 16사례 재실행 | 7사례 통과까지 관찰 후 I/O 경합을 줄이기 위해 해당 시험 프로세스만 중단 | 전체 PASS 아님. 최종 서버 전체 회귀 1183 passed/2 skipped에 포함해 완료 |
| PG 최종 setup/runtime/install_verify/windows_bundle | 47 passed, 기존 Starlette 경고 1, 96.42초 | 실제 한글 전체 runtime/share/data 초기화·기동·한글 원문 왕복, 외부 WIN949 설정에서 UTF8 고정, ACL 복원 포함. 관리자 서비스 미실행 |
| UI 최초 병렬 | 174 passed, 1 failed, 2 skipped; 31파일 중 2 failed; 99.27초 | timezone hook 10초 초과, AdminData 버튼 대기 실패. ui-20261018.log |
| UI 순차 | 177 passed, 31파일, 127.86초 | --maxWorkers=1 --no-file-parallelism. ui-20261018-serial.log |
| TypeScript | PASS | tsc-20261018.log와 실행 종료 성공 확인 |
| PS 구문·주요 Python 정적 오류 | 변경 helper 검사 PASS | 실제 통합 성공을 대체하지 않음 |
| 서버 전체 1차 | 1174 passed, 1 failed, 2 skipped, 1028.79초 | START-HERE 상대 링크 실패 → 수정 후 release_manifest 27 passed. 마지막 PG 변경 후 전체 재실행은 아래 최종 행 참조 |
| 서버 전체 (캐시 경합 보완 전) | **1183 passed, 2 skipped, 기존 경고 1, 1297.78초, exit 0** | server-20261018-final.log. PYTHONDONTWRITEBYTECODE=1, 격리 PG_NATIVE_TEST_ROOT 지정 |
| 서버 전체 최종 (캐시 경합 보완 후) | **1201 passed, 2 skipped, 1 warning in 1409.36s (0:23:29)** | server-20261018-final2.log, exit 0 |
| 새 매체 native 설치·재개·반복·분석 | **PASS**, 후보5 완료 검증 실행기 243.47초 | 후보4 초기 설치/재개 + 후보5 완료 검사. 후보5 fresh 전체 설치 미재실행 |

UI 로그는 .qa/packaging 아래에 있다. 최초 병렬 실행에서 App.timezone.test.tsx hook이 10000ms를 초과했고, AdminData.test.tsx에서 “삭제 영향 확인” 버튼 대기가 실패했다. 순차 재실행 통과만으로 원인 해결 처리하지 않는다. 병렬 부하 관련성은 추정이며 확정 원인이 아니다. 기존 History 503 원인 미확정도 유지한다.

아래는 개발 작업본의 격리 시험 명령이다. .qa/run-assistant-tests.py는 운영 환경변수/dotenv가 시험에 섞이지 않게 하는 개발용 보조 실행기이며 설치 매체 운영 명령이 아니다.

~~~powershell
.venv/Scripts/python.exe -B .qa/run-assistant-tests.py tests/unit/test_install_state.py tests/unit/test_install_paths.py -q -p no:cacheprovider -o addopts= --tb=short

.venv/Scripts/python.exe -B .qa/run-assistant-tests.py tests/unit/test_install_python.py -q -p no:cacheprovider -o addopts= --tb=short -k "running_native or uncertain_process or application_sitecustomize or official_pth"

$env:PG_NATIVE_TEST_ROOT=(Resolve-Path .qa/packaging/installed-new2-20261017).Path
.venv/Scripts/python.exe -B .qa/run-assistant-tests.py tests/unit/test_postgresql_setup.py tests/unit/test_postgresql_runtime.py tests/unit/test_install_verify.py tests/unit/test_windows_bundle.py -q -p no:cacheprovider -o addopts= --tb=short
~~~

UI는 apps/web에서 실행했다.

~~~powershell
pnpm vitest run --maxWorkers=1 --no-file-parallelism
pnpm tsc --noEmit
~~~

최종 읽기 전용 독립 검토에서 남은 P1/P2는 없었다. UTF8 경로/앱 연결, SYSTEM 별칭 사전 거부, PS5.1 BOM, drive-root 거부를 재확인했다. 해당 5개 파일은 후보4의 app payload·manifest SHA256과 일치했다. 검토는 실제 LTSC 또는 관리자 설치 시험을 대신하지 않는다.

## 실제 새 매체 통합 결과

- 초기 설치·재개 매체: .release/model-free-20261018-candidate4 (manifest SHA256 7b5dd8c9f3bdd9df1c22d0be31b883cba298e73fb8ceaaada2b081c89dc1bd15). 완료 반복 검사 매체: .release/model-free-20261018-candidate5 (manifest SHA256 9ade5336589019001b3bf310d382f9b615881c9fb3d8298303f89b8a22d95f96).
- 후보4→5에서 공개 문서·manifest 메타데이터를 제외한 실행 payload 차이는 app/deploy/windows/install-state.ps1 한 파일이다. 나머지 런타임·앱·설치 코드는 동일성을 검사했다. 후보5에서 새 빈 폴더의 전체 최초 설치를 다시 실행한 것은 아니다. 관찰된 오류가 발생한 기존 완료 설치 검사 경로를 실제 후보5로 다시 실행했다.
- 격리 설치 루트: .qa/packaging/installed-관제 C4 20261018. 전체 런타임 경로에 한글·공백이 포함된다. 실제 D: 설치 또는 C:에서 D:로 이전한 시험은 아니다.
- Windows PowerShell 5.1, NoAdmin, HTTPS 58450 / PostgreSQL 55440 / OpenSearch 59210 / transport 59310. JAVA_HOME과 OPENSEARCH_JAVA_HOME을 비운 자식 환경으로 실행했다.
- 최초 실행은 시험 실행기 1200초 제한으로 중단됐고, 남은 파일 작업 완료 후 같은 매체·경로에서 재개했다. 이 시간 초과를 설치 성공이나 예정한 PG 포트 충돌로 세지 않았다.
- 의도한 PG 포트 점유에서는 클러스터 초기화 후 사용자 모드 시작이 실패했다. 최상위 종료 코드 1, journal failed/PostgreSQL과 원래 실패 메시지를 확인했다. 후속 설치 단계는 진행하지 않았다.
- 포트를 해제하고 같은 명령을 재실행했다. Python 실행파일 mtime·기존 비밀번호 바이트를 보존하며 정상 설치까지 완료했다.
- 실제 TLS 인증서 체인/SAN 확인 → claude-check 로그인/MFA → 합성 웹 로그와 내장 HTTP PCAP 처리 → 두 작업 완료 → 이벤트 9 / Finding 10 → 노트 저장 → 앱/DB/검색 프로세스 종료·시작 → 동일 결과·노트 보존 → 로그아웃을 확인했다. 화면 클릭 자동화가 아닌 HTTPS/API 사용자 흐름이다.
- 후보5의 완료 설치 명령 두 번과 전체 중지 상태의 검증에서도 .env·실행 구성·설치 journal·비밀값·인증서·키의 바이트와 mtime을 보존했다. 비밀값 내용과 비밀파일 hash는 보고서에 쓰지 않았다. iam_user의 id/username/password_hash/roles/mfa_secret/mfa_enabled/status도 읽기 전용 연결에서 전후 메모리 비교하여 보존을 확인하고 값은 저장·출력하지 않았다. 완료 재검사 당시 claude-check는 disabled/MFA 해제 상태였다. 앞선 HTTPS 흐름의 실제 MFA 로그인 성공과, 활성 MFA 계정을 유지한 반복 검사 인수는 구분한다.
- 그 뒤 격리 서버를 다시 시작해 읽기 전용 연결로 이벤트 9 / Finding 10, 노트 원문, 두 완료 작업, 합성 계정 정리 상태와 최초 관리자 존재를 재확인했다. 시험 프로세스는 다시 정상 종료했다.
- 세부 비밀값 없는 영수증: .qa/packaging/installed-관제 C4 20261018-receipt.json, -flow.json, -post-rerun-data.json. 해당 폴더의 각 단계 .log와 server-20261018-final2.log를 보존한다.
- 실행 코드와 고정 의존성은 후보5 이후 변경하지 않는다. 최종 매체 조립 시 공개 문서/manifest 메타데이터를 제외한 실행·데이터·라이선스 payload 동일성, SBOM 구성 동일성, ZIP 전 파일 크기·SHA256을 검사한 뒤에만 게시한다.
- 정확한 최종 소스 commit·ZIP 크기·SHA256·파일 수·manifest SHA256은 실제 매체의 release-manifest.json과 별도 release-verification.json에 기록한다. 원격 게시 결과는 docs/verification/github-release-2026-10-18.json에 기록한다.
- 조직 코드 서명은 **미완료**다. 조직 서명 권한을 부여받거나 조직 서명을 수행하지 않았다.

## 남은 대상 OS·권한 게이트

깨끗한 Windows 10 Enterprise LTSC 2019 x64 build 17763에서 Python/Node/Docker/Git/DB/cache가 없는 조건으로 매체만 반입해야 한다. 네트워크 차단 상태에서 매체 검증 → 선택 드라이브 설치 → 최초 계정/MFA → 합성 로그·PCAP 분석/저장 → 종료·시작 → 두 번 재실행 → 로그오프·재부팅 후 서비스/JVM 경로와 데이터 보존을 확인한다. 빈 Java 변수/다른 Java 환경, 한글·공백 경로, 실패 재개, 중복 실행도 각각 기록한다.

관리자 서비스·조직 TLS/방화벽·여러 분석가 공동 접속·16GB 부하·백업/복원·강제 중단 ACL 복구는 별도 환경과 권한이 필요하다. 코드 수정/격리 시험 승인이 운영 설치·설정 변경 승인인 것은 아니다. 기존 C:\SAW를 초기화하거나 다른 드라이브로 자동 이전하지 않는다.
