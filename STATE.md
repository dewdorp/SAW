## 2026-10-26 실제 첫 종료 오류 재현·수정 — 전체 r6 진행 중

## 2026-10-26 의존성 추가·복구 수정 — 최종 전체 r7 통과

- 이전0014→현재0023 매체의 exact XlsxWriter3.2.9 추가와 requirements 전이만 허용하도록 보완했다. 전체 정지 백업 뒤 검증된 완성 파일을 같은 볼륨에서 원자적으로 게시하고 설치 marker/RECORD를 갱신한다. 적용 전·후·복구 후 runtime profile을 구분하며 다른 runtime 변경/변조는 계속 거부한다.
- 구형 복구의 명시 baseline 보존과 필수 marker 사전검사도 보완했다. 종료 요청 거부 뒤 같은 retained 핸들의 기존30초 범위 종료 확인 수정은 유지한다.
- Backend 신규12건·소유 회귀77건(433.343초) 통과. 실제 pinned wheel48파일/852359바이트 비실행 매핑도 확인했으며 설치/임포트 성공으로 세지 않는다.
- Desktop/review 합동 첫113건은105통과8실패(557.01초)였다. 6건은 시험이 실제 실행 backend와 다른 모듈에 오류를 주입한 수집순서 문제, 2건은 격리 fixture에 새 복구 helper가 누락된 문제다. 제품 검사를 완화하지 않고 시험 구성을 수정했다. 같은 실패8건 재실행은8통과(85.95초)다. 113건 전체를 재통과했다고 표시하지 않는다.
- r6는 추가 결함 확인 후 중단했고 call통과870관측·실패관측0·675소스불변이나 INTERRUPTED_NOT_PASS다. 이전r5 결과로 새소스 성공을 주장하지 않는다. 최종 전체r7 PASS: 2868통과·14건너뜀·실패0·오류0·경고2, JUnit3818.044초·실행기3841.344초. 675소스 변경목록[]이며 건너뜀 대상은r5와같다. 새r4매체/a5 native 설치·업데이트·복구·설치CSV·비공개PR/사전릴리스는 다음 작업이다.
- UI183파일은 기존359/52·TypeScript·Vite 결과와 정확히 같다. 이번에 UI시험을 다시 실행한 결과는 아니다. 독립 코드 재검토 중요 지적을 보완했고 현재 추가 중요 지적 없음. LTSC17763/16GB/관리자SCM/재부팅·운영 인수·모델 추론/SFT 및 기존 성능/History503 환경 경계는 유지한다.
- 검증: [의존성 업데이트·복구](docs/verification/offline-dependency-upgrade-20261026.md). 아래는 당시 이력이다.

- r3 매체(source83e3d6b)는 포장 검증을 통과했으나 a3 첫 종료가 stop_failed로 실패해 게시하지 않았다. 설치 재개·가상 자료·MFA는 통과했고 나머지 업데이트/복구는 미실행이다. a3 재현 시점에는 시험 프로세스가 모두 사라지고 PID 기록만 남아 있었으며 그 원인은 미확정이다. 새 진단은 기동/종료 전 existing_stores_not_ready로 중단했고 원래 실패를 보존했다.
- 같은 매체의 새 a4 진단에서 설치 재개209.83초·자료 생성8.09초·기준 기록0.75초·MFA25.67초 통과 뒤 첫 종료42.11초 실패를 실제 재현했다. API Python과 콘솔은 종료됐지만 retained cmd 핸들에서 Wait0=258 → TerminateProcess FALSE/error5 → Wait0=258으로 line676의 stop_failed가 발생했다. a2/a3의 정확한 원인까지 확정한 것은 아니다.
- 수정은 실패한 종료 요청 뒤 같은 핸들의 기존30초 범위 종료 확인이다. PID 재조회·권한 확대·임의 종료나 무한대기는 없다. 실제 종료신호0만 성공이며 살아 있는 대상/WAIT_FAILED/시간 초과는 실패한다.
- 새 native 계약 시험 RED1실패(1.03초) → 기존 소유권·핸들·계속 살아 있는 권한거부 포함 GREEN7통과(53.02초). 양성은 실제 readonly 핸들 종료거부 후 별도 자연종료를 확인한 것이며 a4 cmd의 내부 종료상태를 동일 재현한 시험은 아니다. 독립 코드 검토 중요 지적 없음.
- 수정 소스 지문은 desktop_update6053fec8…/test_desktop_update7b6f1201…이며 전체 r6를 세션45981/PID19272·675소스 동결로 실행 중이다. 이전 r5의2850통과는 이번 수정 결과로 복사하지 않는다. 실제 설치 방식의 수정 후 확인·새 매체·전체 설치/업데이트/복구·PR/사전릴리스는 아직 대기다.
- 원본 Claude·운영 설치·자료·계정·기존 릴리스는 보존한다. 대상 LTSC17763/16GB/관리자SCM/재부팅·운영 인수, 100만건 성능인수, History503/과거 metadata 오류 원인, 모델 추론/SFT는 기존 미검증 범위를 유지한다. 아래 내용은 당시 이력이다.

## 2026-10-26 최종 전체 r5 통과 — 새 r3 매체·a3 인수 대기

- **최종 전체 서버 r5 실제 PASS: 세션61603·PID20272·exit0, 2850통과·14건너뜀·실패0·오류0·기존경고2(총2864건).** pytest 로그2416.29초·JUnit2416.266초·실행기2437.86초다. 최종 xlsxwriter/ProcessLease 제품·시험4파일을 포함한 675소스의 실행 전후 변경목록은[]이다. 근거: `.qa/affiliate-p1-20261020/p5-csv-backend-full-r5-gate.json`/log/XML/source-before. 이전 r3/r4·선별 결과와 합산하지 않는다.
- 14건너뜀은 r4와 같은 범위다: 전용 native OpenSearch 조건3·root native harness 조건1·명시적 PostgreSQL 바이너리3·시험DB URL1·실제PG 조건4·POSIX 권한비트1·Windows symlink1. 기존경고2는 Starlette/httpx deprecation과 record_property/JUnit xunit2 비호환 경고다. 별도 native12통과가 이14건 전체의 실행 성공을 뜻하지 않는다.
- UI183개 현재 지문은 r5에서도 불변이다. `.qa/affiliate-p1-20261020/csv-ui-freeze-r5-20261026.json`으로 확인했고, 같은 정확 UI 소스의 기존359통과/52파일·TypeScript exit0·Vite exit0(20.76초)를 유지한다. UI 시험을 이번에 다시 실행한 결과는 아니다. 제품·시험·UI·공개 안내/13자산은 그대로이며 이번 갱신은 현재 상태4문서만 다룬다.
- **xlsxwriter 검증 수정 완료:** 고정 XlsxWriter3.2.9 wheel의 vba_extract.py 한 파일만 정상 pip `--target` 위치로 인정하고, 현재 설치의 Python shebang과 원본 전체 본문 hash를 확인한다. 다른 `.data` 항목·본문 변경·외부 Python 경로·누락은 계속 거부한다. 최종 제품 지문접두492999…에서 신규20통과다. 관련216통과는 초기lambda 구성으로 구분한다. 지정 범위 독립 검토에서 중요 지적 없음. 근거: `.qa/affiliate-p1-20261020/csv-xlsxwriter-target-fix-20261026.md` 및 같은 prefix의 independent-review/pins 기록.
- **ProcessLease 종료 경쟁 상태 수정 완료:** 같은 핸들의 첫 생존 확인 뒤 자식이 자연 종료하면 실제 TerminateProcess가 FALSE/5를 반환하는 독립 결함을 native RED로 재현했다. 실패 직후 같은 핸들의 Wait0이 정확히 종료 상태일 때만 반환하는 제품2줄 보완을 적용했다. 살아 있는 권한 부족 프로세스는 여전히 실패하고 이미지·생성시각·lease·tracking 경계는 유지한다. 이 결함을 a2 첫stop 실패의 원인으로 확정하지 않는다.
- ProcessLease native RED1실패/1통과 → 핸들·이미지·종료·tracking 범위6통과(0.65초), 마지막 시험 EOF LF 정리 후 native2통과(0.19초)다. 단일 desktop 파일70통과(209.60초)는 최종 제품과 같고 시험 EOF LF 보완 전 구성이다. 각 실행은 포함 관계가 있어 합산하지 않으며 전체 r5를 대신하지 않는다. 최종 제품 지문접두2fe13…/시험1a3ce…를 확인했고 독립 검토에서 중요 지적 없음. 근거: `.qa/affiliate-p1-20261020/csv-process-lease-race-fix-20261026.md`와 independent-review/pins 기록.
- **a2 두번째 실제 정상stop은43.937초·PASS, 4개 포트 모두 닫힘이다.** 첫stop30.375초·FAIL(DesktopError)과 원래 a2 전체FAIL은 보존한다. 첫stop 실패의 직접 원인은 아직 미확정이다. 실제 부재를 확인한 saw PID의 process_missing/87은 예상 진단이며 제품 결함으로 분류하지 않는다. 운영/개발 프로세스를 강제 종료하지 않았다.
- QA common import 실패는 별개다. a2 예상 PostgreSQL 차단 실패82.34초 뒤 fresh-resume는PASS206.81초였으나 fresh-seed는0.06초에 ModuleNotFoundError(common)로 실패했다. 제품 `_pth`를 바꾸지 않고 QA fixture의 인접 common 경로를 명시했다. 실제 설치 Python에서 r2 RED(exit3)→r3 GREEN(exit0)을 확인했지만 이는 import 판독이며 a3 전체 인수 결과가 아니다. 영수증: `.qa/affiliate-p1-20261020/embedded-fixture-import-red-green-20261026.json`.
- **다음은 최종8파일 commit/push → 새 r3 매체 build/ZIP/독립 해제 → a3 신규 설치·재개·0014업데이트·실패 처리·전체복구·설치 CSV smoke다. 이 단계들은 아직 확정 대기이며 소스 r5 PASS를 매체 인수/게시 성공으로 확대하지 않는다.** 기존 r2는 manifest 접두dd116…/ZIP1,448,367,241바이트·SHA-256접두4b827…의 포장·독립 해제 기록이다. a1/a2 매체·실패·로그는 보존하며 PR/릴리스도 미게시다. QA 하네스·assembler·문안 준비는 실제 인수 결과가 아니다.
- 100만건 QA900초 job_wait_timeout 성능인수NOT_PASS(제품 범위분석120초와 별도), LTSC17763/물리16GB/관리자SCM/재부팅/운영 인수 미검증, History503/권한metadata4건 직접원인 미확정은 유지한다. 이번 릴리즈 검증에서는 모델가중치를 포함하지 않았으며 추론/SFT/품질향상을 실행·검증하지 않았다. 아래는 당시 이력이며 최신 상태는 이 절을 따른다.

## 2026-10-26 OWNER RIGHTS 수정 후 전체 r4 통과 — 새 a2 인수 대기

- a1은 source4a29319·manifest 지문접두58980…의 매체로 실행했다. `fresh-blocked-postgres`는 계획한 포트 차단에 따른 예상실패(exit1·102.26초)였으나, 다음 `fresh-resume`는 예기치 않은 실패(exit1·5.47초)로 끝났다. a1 패키지·설치 루트·로그·실패 결과를 보존하며 게시하지 않았다.
- install-state의 OWNER RIGHTS SID `S-1-3-4`를 실제 신뢰된 소유자와 연결해 확인하는 참조가 누락돼 허용 ACL을 오판한 원인을 확정했다. 구현2파일을 수정했다. RED3실패/7통과/36제외·6.11초 → GREEN66통과/3건너뜀/기존경고1·29.82초다. 서비스/owner 양성 일부는 metadata fixture이므로 실제 trusted-owner ACL 실행이나 관리자SCM 인수와 혼동하지 않는다.
- 보존된 원래 a1 루트의 실제 read-only 검사만 별도로 PASS(25.8248초)했고 ACL·journal은 바뀌지 않았다. **이 판독 통과는 설치 재개/fresh-resume 성공이 아니다.** 새 설치·업데이트·복구가 완료됐다고 표시하지 않는다.
- **수정 후 전체 서버 r4 실제PASS: exit0·2828통과·14건너뜀·실패0·오류0·기존경고2**, 총2842건. pytest로그2437.42초·JUnit2417.796초·실행기2457.907초이며675소스 변경목록[]이다. OWNER RIGHTS 코드/시험2파일의 수정 지문도 동일하다. 이전 r3의2818통과 기록은 수정 전 별도 이력으로 보존하며 이번 r4 결과로 대체·합산하지 않는다.
- 14건너뜀·기존경고2의 범위는 이전r3와 같다. 전용nativeOS3·root native harness1·명시PG바이너리3·시험DB URL1·실제PG조건4·POSIX비트1·Windows symlink1을 별도native12통과로 대체하지 않는다. UI183개 지문은 불변이며 웹359/52·TypeScript·Vite20.76초와 정확 소스가 같다. 별도native12·합성브라우저 결과는 각 당시 검증 범위로 유지한다.
- **다음은 최종commit/push→v0.1.0-pilot.20261026 새매체**다. `.release/affiliate-p5-csv-r2-20261026-built` → 새 ZIP → 독립해제 `.release/affiliate-p5-csv-r2-20261026` → 새 a2 fixture로 진행한다. 새20261026매체·a2설치/업데이트/복구·설치CSV smoke·PR/사전릴리스는 아직 **NOT_RUN**이다. a2 helper 복사·순수 검증 준비를 실제 인수 성공으로 표시하지 않는다.
- 100만건QA900초 job_wait_timeout 성능인수NOT_PASS(제품범위분석120초와 별도), LTSC17763/물리16GB/관리자SCM/재부팅/운영 인수 미검증, 모델가중치 제외 매체의 별도 검증·추론/SFT/품질향상 미검증, History503/권한metadata4건 직접원인 미확정은 유지한다.
- 이번 갱신은 STATE/AGENTS/PROGRESS/HANDOVER4문서만 다뤘으며 새 파일·제품/시험/UI/공개파일 수정·커밋은 없다. 아래의 이전 통과·실행 중 표기는 당시 기록이며 최신 소스 게이트 상태는 이 절을 따른다.

## 2026-10-26 CSV 최종 전체 r3 통과 — 새 매체·게시 다음

- 최종 전체 서버 r3는 **2818통과·14건너뜀·실패0·오류0·기존경고2**, log2405.20초·JUnit2405.157초·실행기2424.922초로 완료했다. 675소스의 실행 전후 변경목록[]이다.
- 14건너뜀은 전용 native OpenSearch 환경/URL 없음3·root native harness 조건1·명시적PG바이너리경로 없음3·시험DB URL 미지정1·실제PG실행조건 미충족4·POSIX권한비트1·Windows심볼릭링크1이다. 별도 native12통과가 이14건 전체의 실행 성공을 뜻하지 않는다.
- 최종 별도 실제 PG16.15·OpenSearch2.19.6/Nori native r3는12통과/0실패/0건너뜀·시험205.609초·전체245.453초, 정상종료·포트닫힘true다. UI359/52파일·TypeScript·Vite20.76초와 수정 뒤 합성 브라우저v3(이벤트59·탐지15·불투명주소 강한 교차원천 카드 제거·v1/v2보존)는 각 실행 범위로 유지한다.
- r1의2774통과/1실패/13건너뜀/2경고와673소스 불변, r2의추가P2 수정 목적 중단(call passed132관측·실패관측0·673소스불변·NOT_PASS)은 이력으로 보존한다. correlation/story/relation 경계 수정·story/1.0.1, 관련37·최종선별27통과와 독립재검토 기록도 별도다.
- **다음은 최종 소스 커밋→새 모델 제외 매체·독립해제→정확한 매체의 신규설치/0014업데이트/실패/전체복구·설치CSV점검→비공개PR/사전릴리스다. 매체·게시 성공은 아직 표시하지 않는다.** 기존P5후보·main/릴리스·원본/운영자료를 보존한다.
- 100만건QA900초 job_wait_timeout 성능인수NOT_PASS(제품범위분석120초와 별도), LTSC17763/물리16GB/관리자SCM/재부팅/운영인수 미검증, 모델추론/SFT/품질향상 미검증, History503/권한metadata4건 직접원인 미확정은 유지한다. 새 typed 세대 보존을 과거flat 세대의 native 이관/호환 성공으로 확대하지 않는다.
- [CSV 최종 검증](docs/verification/recurring-csv-validation-20261025.md). 아래의 실행 중·미확정 표기는 당시 체크포인트이며 현재 소스 전체 게이트 상태는 이 절을 따른다.

## 2026-10-25 파생 식별 경계 수정·native r3 확인 — 최종 전체 r3 실행 중

- 전체 r2는 합성 브라우저에서 불투명 IP를 강한 교차 원천 동일성으로 취급한 추가 P2를 확인해 소유 세션9146을 중단했다. 중단 전 call passed132건·실패 관측0, 당시673소스 불변이나 **전체 미완료·INTERRUPTED이며 PASS가 아니다.** r1의2774통과/1실패/13건너뜀/2경고 이력도 보존한다.
- correlation·story·relation 세 경계의 소스/시험5파일을 수정하고 story/1.0.1을 기록한다. 관련37통과·85.69초, 최종 정확 범위27통과·12.11초는 별도 실행이다. 독립 지정 범위 재검토에서 미해결 Important 없음. 불투명 표기를 동일 자산의 근거로 승격하지 않으며 정상 IP 분석 경로는 유지한다.
- 최종 실제 PostgreSQL16.15·OpenSearch2.19.6/Nori native r3는 **12통과·0실패·0건너뜀**, 시험205.609초·전체245.453초, 소유 프로세스 정상 종료·포트 닫힘true. 매핑 native r2의6통과(89.266초·전체132.312초)는 별도 이력으로 유지한다. 새 typed 세대 보존을 과거 flat 세대의 native 이관/호환 성공으로 확대하지 않는다.
- 서버 재시작 뒤 실제 합성 UI 재분석 v3는 이벤트59·탐지15건이며 불투명 주소의 강한 교차 원천 카드/연관 결과가 사라졌다. v1·v2는 보존됐다. UI 코드·주 CSV 안내서·공개13파일은 변경하지 않았다. 기존 UI359/52파일·TypeScript·Vite20.76초·r2소스/dist 지문은 그대로다.
- **최종 전체 r3는675소스를 동결해 세션83762·PID21468로 실행 중이며 결과 미확정이다.** 코드·시험·UI·주 CSV guide/공개13파일을 수정하지 않는다. 이 체크포인트는 허용된4문서만 갱신했다. 전체 게이트·새 매체/설치/0014업데이트/실패/전체복구·비공개PR/사전 릴리스 게시를 완료로 표시하지 않는다.
- 필수·추가 헤더의 빈/공백뿐인/점이 든 이름 거부·최대199열·실제 전용파서 확인 경계는 유지한다. 100만건QA900초 job_wait_timeout 성능 인수NOT_PASS(제품범위분석120초와 별도), LTSC17763/물리16GB/관리자SCM/재부팅/운영인수·모델추론/SFT/품질향상 미검증, History503/과거권한metadata4건 원인미확정도 유지한다. 모델가중치 제외 최종매체는 별도 검증한다.
- [CSV 증분 검증](docs/verification/recurring-csv-validation-20261025.md). 아래 체크포인트는 당시 이력이며 최신 상태는 이 절을 따른다.

## 2026-10-25 CSV 매핑 수정·native r2 확인 — 전체 서버 r2 실행 중

- 전체 서버 r1은 **2774통과·1실패·13건너뜀·기존경고2**, pytest2541.09초·실행기2561.86초·exit1로 끝났다. 673소스는 실행 중 바뀌지 않았다. `security_csv` OpenSearch 명시 namespace 누락 실패는 실제 결함으로 보존한다.
- namespace 등록·예약 원천 열의 일관된 object 보존을 수정하고 지정 범위 재검토에서 미해결 중요/치명 지적이 없었다. 필수·추가 헤더 모두 빈/공백뿐인/점이 든 이름은 거부하며 평평한 추가 이름은 최대199열 안에서 지원한다. 일반 CSV fallback을 전용 형식 지원으로 해석하지 않는다.
- 수정 후 실제 PostgreSQL16.15·OpenSearch2.19.6/Nori native r2는 **6통과·0실패·0건너뜀**, 시험89.266초·전체132.312초, stop_complete=true·종료/포트 닫힘 확인이다. 앞선 native4건은 이 namespace/예약 열 수정을 검증한 결과가 아니며 r2와 합산하지 않는다. 새 typed 세대의 보존을 과거 flat 세대의 native 이관/호환 성공으로 확대하지 않는다.
- UI r2는 **359통과/52파일·TypeScript exit0·Vite exit0(20.76초)**. 기존 경고를 유지한다. 저영향 업로드 문구와 guide만 수정했고 정적 문구 단언은 추가하지 않았다. 별도 r2 UI소스/dist/public183파일 지문으로 이전 freeze를 보존했다.
- **전체 서버 r2는 수정된673소스 동결로 실행 중이며 최종 결과 미확정이다.** 현재 코드·UI·시험·CSV guide/공개13파일은 동결 중이다. 이 체크포인트는 허용된 검증/상태 문서만 갱신했다. 소스 최종 통과·새 매체/설치/0014업데이트/실패/전체복구·PR/사전 릴리스 게시를 완료로 표시하지 않는다.
- 100만건은 QA900초 job_wait_timeout으로 성능 인수NOT_PASS이며 제품 범위분석120초 예산과 구분한다. LTSC17763·물리16GB·관리자SCM·재부팅·운영 인수, 모델추론/SFT/품질향상 미검증, History503·과거권한metadata4건 원인미확정은 유지한다. 모델가중치 제외 최종매체는 별도 검증한다.
- [CSV 증분 검증](docs/verification/recurring-csv-validation-20261025.md). 아래 이전 체크포인트의 실행 중·대기 표기는 당시 기록이며 현재 상태는 이 절을 따른다.
## 2026-10-25 CSV 전체 게이트 후속 수정 대기
- p5-csv-backend-full-r1(session12107)는 실행 중이며 test_extension_template_preserves_known_typed_namespaces에서1실패를 확인했다. security_csv 제품 namespace가 OpenSearch 명시적 typed_extensions에 누락된 것이며 정확1건 재현 실패0.29초. 기존 nativeAPI4통과가 이 누락을 검증한 것은 아니다.
- 추가 조사에서 선택 열 source_columns가 단독이면 scalar, csv_format 충돌과 함께면 object가 되는 경계도 발견했다. 일관된 예약 열 보존과 typed namespace를 함께 검증할 계획이다. 원본 CSV·운영인덱스는 건드리지 않는다.
- 현재673소스 동결은 유지하고 나머지 전체 검사에서 다른 실패를 수집한다. csv_format_adapters가 QA-only 패치/회귀 초안을 준비한다. 현전체시험 종료 후 최소수정→독립검토→새native4+mapping시험→새전체회귀를 실행하며 현재 실패를 숨기지 않는다.
- 새매체/PR/릴리스는 아직 미실행. 설치CSV추가smoke QA두파일(실행기ccab19ec…,작업기94cd8a45…)은 순수8검사·독립검토 통과, 실제실행은 mainmediaPASS 후다.

## 2026-10-25 반복 FW·NDR CSV 증분 — 전체 검증 진행
- P5 소스 0925b4d 위에 전용 ko_fw_csv/ko_ndr_csv 파서, 저장된 CSV 자료 준비도와 시나리오 실행 상세, 반복 업로드 안내·합성 예제를 추가했다. 필수 헤더 FW16/NDR19, UTF-8/CP949, 최대199열, 요청행·메서드/경로 요약 구분과 원문 참조를 유지한다.
- 첨부 파일의 목적지는 비식별 예제이며 실제 운영은 정상 IP라는 사용자 설명을 반영했다. 사설/공인 IPv4/IPv6×FW/NDR 8개 합성 회귀를 추가해 관련165통과. 비식별 예제로 운영 목적지 기반 정확도를 주장하지 않는다.
- 독립 검토의 O(N²) 출처수집·CONNECT 검증 문제를 수정하고 최종 범위 검토에서 미해결 중요/치명 지적 없음. 공개 매체 목록 후속 검토는 별도 기록한다.
- 실제 합성 브라우저 정상 MFA→FW12행→서버 재시작→NDR47행 추가→v2 59행·HTTP요청행27/요약20·web_intrusion후보1→v1 12행 유지 확인. 화면7장·실습CSV5개는 공개 허용 목록에 포함. SQLite 개발 저장소이며 LTSC/native 인수와 구분한다.
- 웹359통과/52파일·TypeScript통과, 최종Vite19.34초 통과(2MB chunk 경고 유지). 포장70통과/기존경고1. 새 전체서버 p5-csv-backend-full-r1 세션12107,673파일동결로 실행 중이며 아직 결과를 PASS로 쓰지 않는다.
- 기존 affiliate-p5-built-20261025 매체는 CSV 증분 전 후보로 보존한다. 새출력 affiliate-p5-csv-built-20261025→SAW-0.1.0-pilot.20261025-model-free-win-x64.zip→affiliate-p5-csv-20261025. 아직 새포장/native 설치/릴리스 미실행.
- 다음: 전체회귀·새CSV nativePG/OS→문서/커밋→새모델제외매체/독립해제→새C Temp 설치·0014업데이트·실패·전체복구→새비공개PR/사전릴리스. 기존 main/릴리스·원본Claude·운영계정/자료 보존.
- 100만건 성능NOT_PASS, LTSC17763/물리16GB/관리자SCM/재부팅/운영인수, 모델추론/SFT, History503/과거권한metadata4건 원인미확정은 기존 별도 게이트를 유지한다.
- [반복 CSV 사용법·실제 화면](docs/RECURRING-SECURITY-CSV-GUIDE-20261025.md).

# 2026-10-25 P5 소스 검증 완료 · 릴리스 작업 계속
- 작업본 F:/codex/SAW-Claude-main, codex/affiliate-p0-20261020, P5 기준 부모c8f9747. 최종소스commit은 p5-source-commit-20261025.json과 새매체manifest로 확인한다. 소스커밋 후 새전체매체 인수를 계속한다.
- product지문21a9058bb43da431ada3a1e9326a5a066cec8ba5d2bf9a1acb8b32ce804e1c84,663소스/16웹빌드파일 동일성최종PASS. 전체서버r3 exit0/2628통과/13skip/0실패/2경고,2510.516초. 실행세션84023완료.
- 커밋검사에서 시험파일 끝빈줄2바이트정리. AST동일·실행코드불변·관련9통과. p5-packaging-source-freeze-20261025.json이 포장기준이며 원래전체시험동결은보존한다.
- 13skip: PGURL5·OSURL3·nativePG바이너리3·Windows symlink1·POSIX권한1. 별도native성공기록과 혼합하지 않는다.
- 최종matrix-r3 1천/10만건1·3요청자일치/조회960성공. 100만건QA900초 job_wait_timeout/전체NOT_PASS,1733.8893424초·정리/포트닫힘확인. 10만건Job571.535131초와 이후범위분석39.796초 구분.
- 모델제외매체경로 affiliate-p5-built-20261025→SAW-0.1.0-pilot.20261025-model-free-win-x64.zip→affiliate-p5-20261025. p5-archive-package.py·verifier핀확인완료,실행직전다시검사. 매체QA고정C Temp a1/6개소스핀/사전검사→execute. 아직매체/설치/게시NOT_RUN.
- 새비공개PR/사전릴리스 v0.1.0-pilot.20261025 예정. 원격보존기준 p5-remote-releases-before-20261025.json(기존5릴리스51자산/main보존). 정상단계 재승인대기없음.
- 오프라인HTML실제8장/목차표시PASS: SAW-P5-REPROCESSING-GUIDE-20261025.html,627474바이트/eccb671926f2988c0afad01b8acc3c0d32d0599ea69458091ebf05c390e86138. 안내만제공하는loopback58518/세션85821, 제품서버아님.
- 대상LTSC17763/실제16GB/관리자SCM·재부팅·운영인수·모델추론/SFT 및History503/과거권한metadata4건 원인미확정은유지한다.

## 2026-10-25 P5 소스 검증 완료 · 설치 매체 인수 진행
- 새 자료 세대·이전 분석 근거 보존, 영속 작업 큐, 재처리·취소·정리와 정지 상태 전체 백업을 구현했다. I1–I3와 취소 조회·패턴·SQLite 커서 수정의 독립 검토 및 재검토를 종료했다.
- 최종 전체 서버 2,628통과·13건너뜀·실패/오류0·기존경고2. JUnit2486.955초/실행기2510.516초. 코드663파일·웹빌드16파일 동결값 동일. 웹351·TypeScript·Vite는 동일소스의 최종 실행이며 QA cp949출력오류를 따로 기록했다.
- 실제 PG16.15/OpenSearch2.19.6/Nori 선별50·15·9·10건은 각각 통과·종료 확인이다. 최종 성능matrix-r3의1천/10만건·1/3요청자 네행 공개결과 일치, 조회960성공/오류0. 10만건 적재·자동분석 Job571.535131초와 이후 범위분석39.796초를 구분한다.
- 100만건은PARSING 중 QA900초 대기한도 job_wait_timeout으로 미완료. 전체행렬NOT_PASS. 총1733.8893424초·소유프로세스종료/포트닫힘/정리실패0 확인. 제품범위분석120초 한도와 구분하고 한도를 올려 통과 처리하지 않았다.
- 실제 합성 화면의 재처리·이전v1·통계·PCAP·재시작보존을 유지한다. 실제화면8장 단일HTML은 별도배포용으로 만들고 브라우저 표시·목차 이동을 확인했다.
- 다음: P5커밋→모델제외 전체ZIP 봉인·독립해제검증→새C Temp 합성설치·0014업데이트·실패·전체복구→새비공개PR/사전릴리스. 새매체 인수/게시 아직NOT_RUN. 기존릴리스/main·원본Claude·운영설치/계정/은행자료 보존.
- 이번개발기 Windows11Pro26200/i5-12600/약32GB. LTSC17763·물리16GB·관리자SCM·재부팅·운영인수/모델추론·SFT는 별도이며 History503/과거권한metadata4건 원인은미확정이다.
- [P5 검증](docs/verification/affiliate-p5-validation-20261024.md) · [실제 화면 안내](docs/SAFE-REPROCESSING-GUIDE-20261024.md).

# SAW 현재 상태 — 2026-10-24

## 2026-10-24 최신 재개 지점
- 작업 원본 F:/codex/SAW-Claude-main, 마지막 P4 커밋 c8f9747. P5는 커밋·릴리스 전이다.
- 최종 검토 I1~I3(이전PCAP 정리·권한별룰 한도·검토/지원함 ACL)을 한 묶음으로 수정했고 독립 재검토에서 잔여 지적 없음. 삭제 중 받은함 경계도 보완해 관련27건 통과. 최종 동결 revision2 보고서가 기준이다.
- 실제 PG16.15/OpenSearch2.19.6/Nori50개 통과 후 추가15개도 통과·정상종료. 마지막 받은함 변경9개도 별도 실제 시험을 통과하고 정상 종료했다. 각 실행을 합산해 한 번의 전체 통과로 쓰지 않는다.
- 최신 UI351통과·TypeScript·Vite 통과, 웹 소스159개 동일. QA 출력의 cp949 오류는 빌드 성공 후 발생해 관측된 종료코드·JUnit·소스지문으로 별도 복구 기록했다.
- 전체 서버r1(541.469초),r2(105.812초)는 수정 전 후보 중단으로 보존했다. 최종r3 준비 완료·아직 미실행. 첫 성능 pilot은 QA의 Python 경로 구분 오류로 중단 기록했다. 도구 수정·검토 후 새1천건 pilot은1/3요청자 모두330세션·차단10·후보1 일치 및 정상종료. 10만건matrix는 색인 후 분석 지연을 확인해950.879초에 정상 취소·종료하고 진단으로 보존했다. 1천/1만건 실제 프로파일2건 통과·정상종료로 탐지시간의83.5%/88.4%가 반복 취소SQL 확인에 쓰임을 확인했다. 0.2초 작업별 확인과 탐지기 전후 fresh 검사로 보완했고 집중21·관련145건 및 독립 검토를 통과했다. 구조화 연결의 중복 자유문장 패턴 분석은 보수적 조건으로 보완·검증 중이다. 10만건 분석완료·100만건 실행을 주장하지 않는다.
- 실제 합성 브라우저 재처리·이전v1·통계·PCAP·37패킷 세션 다운로드와 재시작 후3조사·6이력·123원문참조 보존 확인. 사용법 docs/SAFE-REPROCESSING-GUIDE-20261024.md.
- 설치·복구 QA는 지정된 C Temp 새 합성폴더만 사용하도록 독립 검토 완료. 경로/용량/무결성/소유권 검사는 유지하며 아직 폴더 생성·새매체 설치는 하지 않았다.
- 남은 순서: 패턴 보완·검토 → 동일1천/1만건 및 실제matrix 재검증 → 최종 전체서버 → P5커밋/모델제외전체매체 → 신규설치/0014업데이트/실패/복구 → 새 비공개PR·사전릴리스.
- LTSC17763·물리16GB·관리자서비스·재부팅·운영반입, 모델추론/SFT, History503/과거ACL4건 원인 미확정은 별도다.


## 2026-10-24 P5 재처리·복구 통합 진행
- P1–P4 완료 커밋과 검증은 유지하며 P5를 연속 수행한다. 새 P5 릴리스는 아직 없다.
- 저장소 독립 검토의 3개 결함(불확실 쓰기, 재사용 입력 객체, 손상 metadata)을 수정했다. 실제 SQLite/전송계약 시험50통과·native1건너뜀, 수정 재검토3개 모두 해결. 실제 OpenSearch 인수는 별도 진행 대상이다.
- SQL 이력 보존 로직47통과·독립 검토 승인. 큐51통과·독립 검토 승인. 루트 재시작/취소·컨텍스트·0023 추가 schema 통합은 최종 관련21통과·PG2건너뜀(23.85초). 기존 Starlette/httpx 경고는 구분한다.
- 읽기/권한·정확한 분석 세대 연결, 실제 재파싱·PCAP·connector, 관리자 전체/부분 정리를 분리 구현 중이다. 원본/운영 설치·데이터를 수정하지 않는다.
- 기존 전체 복구 규약으로 정지 상태 전체 백업을 추가하고 있다. 합성 파일/실제 복사·복구5통과(25.93초); 기존 업데이트 포함 관련63통과·0건너뜀(177.80초)을 확인했다. 실제 매체·설치·복구 인수는 미완료다.
- 자동 승인 검토 서비스 사용량 한도로 직전 명령 하나가 미실행되었고, 사용자의 재개 지시 후 같은 승인 경로로 다시 실행했다. 승인 검사를 우회하지 않았다.
- 실제 PG16.15/OS2.19.6 r1에서 migration3통과·write-block 요청 직렬화1실패를 확인해 수정했다. r2 정확4통과·0건너뜀(41.141초), 정상 종료·포트 닫힘 확인. 더 넓은 실제 재처리/권한/삭제 통합은 별도 진행한다.
- 재처리 시 새 Job으로 이동하는 화면 연결과 기존 이력 보존 문구를 수정했다. 관련 UI6통과·TypeScript 통과; 실제 브라우저 인수는 아직이다.
- 다음: P/R/D 통합 검토와 남은 상태 계약 수정 → 실제 PG/OpenSearch·성능·브라우저 → 전체시험 → 모델 제외 매체 및 합성 설치/업데이트/복구 → 최종 검토·새 비공개 PR/사전 릴리스.
- 현재 작업은 F:/codex/SAW-Claude-main, 브랜치 codex/affiliate-p0-20261020. 마지막 커밋 c8f9747(P4); P5 변경은 아직 커밋 전이다.


## 2026-10-24 P4 검증 완료 · P5 연속 진행
- 정확한 골든셋/분석/확인 기록과 비실행 변환 프로필, 독립 반출 승인, 원천 권한 재검사, 취소·재시도·철회, holdout 입력→결과→답안 이력을 구현하고 검토했다.
- 최종 전체 서버 2,179통과·8건너뜀·실패0·오류0; JUnit 2276.70초. 웹348통과/51파일·TypeScript·Vite 통과. 건너뜀·경고·이전 실패는 검증 기록에 구분한다.
- 실제 PostgreSQL16.15/OpenSearch2.19.6/Nori: r1 2통과/1실패→0022 버전폭64 수정, r2 59통과/1실패→시험 fixture 격리, r3 6통과/0실패. 최신 서로 다른62개 통과이며 한 번의 전체62통과가 아니다. 소유 프로세스 정상 종료/포트 닫힘 확인.
- 실제 합성 브라우저:21행·7세션 전체 재계산, 일반MFA 독립 승인, ZIP103010바이트/13항목, 철회 후 UI/HTTP 차단. Holdout 입력·결과·답안 화면, NDJSON 표시 수정과 재시작 뒤 고정 이력7종 보존을 확인했다. 모델 실행·품질 향상은 주장하지 않는다.
- 실제 캡처6장 안내와 공개 기록을 명시적인 매체 허용 목록에 넣고 관련73개 회귀를 통과했다(12.56초). 새 전체 매체·설치/업데이트/복구는 P5에서 이어간다.
- 다음 P5: 세대별 저장/안전한 재처리·공정한 영속 큐·실제1k/100k/1M 및1/3요청자 측정·모델 제외 매체·최종 검토·새 비공개 PR/사전 릴리스. 재승인 대기는 없다.
- 원본 Claude·운영 설치/계정/은행 자료·기존 릴리스 보존. LTSC2019/16GB/관리자 서비스·운영 인수와 과거 History503/권한metadata4건 원인 미확정은 별도 유지.

- [P4 검증](docs/verification/affiliate-p4-validation-20261024.md) · [실제 화면 안내](docs/AFFILIATE-GOLDEN-GUIDE-20261023.md).


## 2026-10-23 P3 검증 완료 · P4 연속 진행
- 후속확인 요청·회신·검증의 정확 버전과 불변 다중 보고서, 같은 내용의 HTML/8시트 Excel, 취소·재시도·원천 권한 검사를 구현했다.
- 최종 코드 동결 후 전체 서버2,060통과·6건너뜀·실패0·기존경고2, 2,248.45초. 실제 DB 환경을 별도 지정해야 하는4건, Windows 심볼릭 링크1건, POSIX 권한1건을 건너뛰었다. 이전 실패·중단 이력은 보존한다.
- 최종 웹292통과/48파일·TypeScript·Vite 빌드 통과. 실제 합성 브라우저의 요청→회신→자료 부족 검증→정확 버전 Excel/HTML과 최종 권한 수정 뒤 재시작·다운로드를 확인했다.
- 실제 PostgreSQL16.15/OpenSearch2.19.6/Nori에서13통과, 최종 다운로드 권한·부분 삭제 수정은 별도15통과. 모두0실패/0건너뜀·정상 종료·시험 포트 닫힘을 확인했다.
- 긴 Windows 경로 삭제, 다운로드 중 권한 회수, 부분 증거 삭제 뒤 잔존 내보내기 Job, 조사 이동 후 남는 이전 선택을 실패 재현 뒤 수정했다.
- XlsxWriter3.2.9 실제 wheel/sdist/라이선스를 확인해 배포 입력에 등록했고 내장 Python3.12.10의 오프라인 의존성 설치·한글8시트 생성 smoke를 통과했다. 새 전체 매체 인수는 P5에서 수행한다.
- P4 골든셋/독립 반출→P5 재처리·큐·성능·모델 제외 매체·설치/업데이트/복구·검토·새 비공개 릴리스를 재승인 대기 없이 계속한다.
- 원본 Claude·운영 설치/계정/은행 자료·기존 릴리스 보존. LTSC2019/16GB/관리자 서비스·운영 인수와 과거 History503/권한metadata4건 원인 미확정은 별도로 유지한다.

- [P3 검증](docs/verification/affiliate-p3-validation-20261023.md) · [실제 화면 안내](docs/AFFILIATE-FOLLOWUP-REPORT-GUIDE-20261021.md).

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

아래는 이전 진행 이력이다.

## 2026-10-20 P1–P5 연속 구현 승인 · P1 진행 중
- 사용자가 설계를 승인하고 P1→P5 구현·검증·검토·새 릴리스를 연속 수행하도록 지시했다. 단계별 재승인 대기는 없다.
- [실행 계획](docs/plans/affiliate-soc-implementation-20261020.md), [승인 설계](docs/plans/affiliate-soc-design-20261020.md).
- P1 관계사/장비 맥락, 관측/세션 의미, 원천 ACL을 분리 구현하고 실행 이력·불변 보고서·화면을 통합 중이다.
- 현재 새 기능은 개발 중이며 릴리스·운영 인수 완료가 아니다. 새 시험 결과는 단계별 별도 기록한다.
- 원본/운영 설치·자료·기존 릴리스 보존. 대상 LTSC·16GB·운영 설치 및 실제 자료 반출 승인은 별도다.

아래 P0의 승인 대기 문구는 이력이다.

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

아래는 이전 배포·업데이트 이력이며 새 요구의 구현 완료 기록이 아니다.

## 이전 배포: 최종 ZIP 직접 재검증·게시 완료 · LTSC 운영 인수 별도

- [모델 제외 전체 ZIP](https://github.com/dewdorp/SAW/releases/tag/v0.1.0-pilot.20261019)을 직접 풀어 실제 업데이트·전체 복구를 재실행했다. 실행 코드 추가 변경 없이 source 26f5d1a448668c127383c2e73d47d60d00ed2a28와 설치 ZIP을 유지한다.
- 이번 실제 Windows11 Pro build26200 / Windows PowerShell5.1.26100.9711 / NoAdmin 합성 흐름: 시작48.32초·점검38.21초·업데이트485.55초·복구488.11초 모두 PASS. 실제 WinForms 버튼 이벤트→worker→포함 런타임→PostgreSQL/OpenSearch/HTTPS이다. 물리 마우스 더블클릭·관리자 SCM 서비스·대상 LTSC 인수는 아니다.
- 점검 전후·적용 후·복구 후 계정2·이벤트9·Finding10·증거2·노트1·완료작업2/schema0014 일치. 계정ID·암호hash·권한·MFA·설정·키·TLS·원본 대조 및 같은 계정 로그인 PASS. 새 합성 객체1개 별도 보관·합성 계정 정리·정상 종료28.77초, 세 포트 닫힘/PG PID 부재 PASS.
- 이번 오류 회귀14파일 **618통과·1건너뜀·2기존경고·실패0**, 795.23초. POSIX 권한 비트 시험1건만 건너뛰었고 native Windows ACL 회귀는 실행했다. 기존 전체 서버1733/6skip·웹177/TypeScript PASS는 이전 실행이며 이번 재실행으로 표시하지 않는다. 실행 코드·기존 시험은 변경되지 않았다.
- ZIP **SAW-0.1.0-pilot.20261019-model-free-win-x64.zip**, 1,445,832,542바이트, SHA256 b9d7e0e7d9b3658c17690dcd276b072c03bb3330518431e1eba4e04d56b30cb5. 677항목 직접 해제 및675 payload 검증 PASS. 기존 ZIP·manifest·9자산·tag/main·이전4개 릴리스 보존, 문서3개 추가 후12자산 원격 크기/digest 대조 PASS.
- [최신 그림·사용 안내](docs/UPDATER-RECHECK-20261020.html) · [Markdown 안내](docs/UPDATER-RECHECK-20261020.md) · [직접 실행 검증](docs/verification/updater-release-recheck-20261020.json) · [게시 검증](docs/verification/github-updater-recheck-20261020.json). 실제 화면3장을 원본 그대로 HTML에 내장했고 브라우저3개 로딩과 복구 화면을 확인했다.
- [통합 PR #3](https://github.com/dewdorp/SAW/pull/3), 브랜치 codex/updater-stabilization-20261019. main은 병합하지 않는다. 원본 F:/claude/saw, 운영 C:/SAW·D:/SAW-0.1.0, 운영 계정·자료를 변경하지 않았다.
- 사용: 새 ZIP을 D:/SAW-update-20261019 같은 새 폴더에 해제 → UPDATE-SAW.cmd → 기존 C:/SAW·새 C:/SAW-r-20261019 선택 → 설치 점검 → 중지 동의 후 업데이트. 수동 hash 대조는 없고 자동 검증을 유지한다. 복구는 전체 시점 복구이며 이후 새 자료는 별도 보관한다.
- 남은 인수: 깨끗한 LTSC2019 build17763·실제 관리자/UAC/SCM/LocalSystem/NetworkService·Registry32 서비스·HTTPS443·재부팅·조직TLS/서명/MOTW·물리폐쇄망·저사양 공동부하·운영 승인. [현장 읽기 전용 점검 절차](docs/verification/updater-native-acceptance-20261019.md)를 사용한다. 이번 ZIP으로 빈 폴더 최초 설치는 재실행하지 않았다.
- 과거 후보6 권한 metadata 조회4건과 History503의 정확한 원인은 미확정이다. 후속 성공을 원인 해결로 취급하지 않는다. 게시 설명의 첫 대조는 GitHub의 CRLF 변환으로 실패했으며 내용이 같은 것을 확인한 뒤 줄 끝만 정규화해 재검증했다. 업로드·기존 자산을 덮어쓰지 않았다.
- 합성 시험 설치 .qa/packaging/installed-new2-20261017는 정지/계정 비활성 상태다. 새 복구본 .qa/ur20-final과 보관 설치·기존 모든 시험 이력은 보존한다. 최신 안내 URL: http://127.0.0.1:58369/UPDATER-RECHECK-20261020.html (기존 docs 서버 유지).

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
