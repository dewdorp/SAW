# 업데이트 현장 인수 절차 — 2026-10-19

이 문서는 Windows 10 Enterprise LTSC 2019 x64(build 17763), Windows PowerShell 5.1의 실제 서비스 설치를 현장에서 확인하기 위한 인계 자료다. 개발 PC(build 26200)의 합성 시험을 LTSC·실제 서비스·재부팅 인수 결과로 표시하지 않는다. 이번 개발 작업에서는 운영 C:\SAW, D:\SAW-0.1.0의 서비스나 레지스트리를 변경하지 않았다.

## 일반 사용자의 점검

1. 새 **전체 오프라인 설치 ZIP**을 아직 없는 새 폴더 D:\SAW-update-20261019에 푼다. 기존 C:\SAW와 원래 매체 D:\SAW-0.1.0은 보존한다. GitHub의 Source code ZIP은 설치 매체가 아니다.
2. `UPDATE-SAW.cmd`를 더블클릭하고 기존 설치 폴더를 선택한다.
3. 기존 설치에 배포 기준 기록이 없으면 원래 설치에 사용한 **전체 매체 폴더**를 선택한다. 기준을 모르면 새 매체나 소스 ZIP으로 대신하지 않는다.
4. **설치 점검** 결과와 권장 조치를 확인한다. 이 단계에서는 서비스 중지·업데이트·복구 버튼을 누르지 않는다.

## 관리자의 읽기 전용 증거 수집

새 매체의 `test-update-environment.ps1`은 관리자 인수용 보조 도구다. 선택한 매체 전체를 검증한 뒤 검증된 worker의 `inspect`만 실행한다. 서비스 시작·중지·설치·재등록, 레지스트리 쓰기, 설치 ACL 수리는 수행하지 않는다.

기존에 만든 증거 보관 폴더를 지정한다. 설치·새 매체·원래 매체와 겹치지 않는 로컬 경로여야 한다. 다음은 경로 예시이며 실제 서버에서 임의로 실행한 기록이 아니다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "D:\SAW-update-20261019\test-update-environment.ps1" -InstallRoot "C:\SAW" -BundleDir "D:\SAW-update-20261019" -OriginalMedia "D:\SAW-0.1.0" -EvidenceParent "D:\SAW-evidence"
```

예시의 실행 정책은 이 PowerShell 프로세스에만 적용된다. 전역 실행 정책을 바꾸지 않으며, 조직 정책이나 매체 차단 표시가 실행을 막으면 임의로 우회하지 않는다.

설치된 배포 기준 기록이 이미 있으면 `-OriginalMedia`는 생략할 수 있다. 64비트 Windows PowerShell 5.1의 관리자 창에서 실행한다. 스크립트가 승격이나 서비스 설치를 대신하지 않는다. `EvidenceParent`를 생략하면 사용자 임시 폴더에 새 보호 폴더를 만든다.

새 증거 폴더에는 현재 사용자와 SYSTEM만 허용한 ACL을 적용한다. 이 폴더의 worker 상태·임시 실행 환경과 설치 폴더 **옆**의 유지보수 잠금 파일은 점검 과정에서 생성될 수 있다. 설치 내부의 프로그램·설정·저장소를 변경하는 작업은 수행하지 않는다.

## 기록과 판정

`native-acceptance.json`에는 다음 정보를 기록한다.

- 실제 OS 이름·버전·빌드·구조·제품 유형·SKU, PowerShell 버전, 현재 토큰의 사용자 SID·기본 소유자 SID·관리자 여부.
- `saw`, `saw-postgresql`, `saw-opensearch`의 검사 전후 상태와 PID. 계정은 LocalSystem/NetworkService 여부만 표시하며, 인식하지 못한 계정·실행 명령 원문은 숨긴다.
- Procrun Registry32/Registry64의 존재 여부와 JVM/옵션/작업 경로 값의 자료형. 값 원문은 기록하지 않는다. 경로·옵션 일치 여부는 worker의 검증 결과로 판정한다.
- 프로그램·설정·런타임 파일의 검사 전후 건수와 내용·소유자·DACL을 함께 반영한 전체 지문. 개별 파일 이름, 환경 변수 값, 비밀번호·토큰·레지스트리 값은 보고서에 기록하지 않는다.
- `inspect`의 승인 여부·관리자 요구 여부·안전한 원인 코드. 업데이트·복구·재부팅은 항상 `not_run`으로 구분한다.

기본 파일 비교는 프로그램·설정·런타임 범위다. `data`, `logs`, `run`, `models`, `app/var` 등 실행 중 변경되는 저장소는 기본 비교에서 제외한다. `-FullInventory`를 명시하면 설치 내부 전체 파일을 읽고 지문을 비교하므로 큰 저장소에서는 오래 걸릴 수 있다. 실행 중인 DB·로그의 정상 쓰기 때문에 전후 지문이 달라질 수 있으며, 이 결과만으로 점검 도구가 파일을 변경했다고 단정하지 않는다. 읽기 실패·재분석 지점·변경 중인 파일은 성공으로 건너뛰지 않는다.

종료 코드는 다음처럼 해석한다.

| 코드 | 의미 |
|---|---|
| 0 | Windows 클라이언트(ProductType 1)·Enterprise S/N(SKU 125/126)·10.0.17763·build 17763·PS 5.1·64비트 OS/프로세스·관리자 실행에서 inspect 승인, 서비스 상태/PID와 선택한 파일·ACL 범위의 전후 일치 |
| 2 | 증거는 작성했지만 목표 환경·관리자·점검 결과·전후 일치 조건 중 하나 이상 미충족 |
| 1 | 매체 검증 또는 증거 수집을 끝내지 못함. 설치와 생성된 보호 폴더를 보존 |

보고서의 `inspection_verified`는 **점검에 한정된 결과**다. 대상 판별은 빌드뿐 아니라 클라이언트 제품 유형과 Enterprise S/N SKU를 함께 검사한다. Server 2019·일반 Enterprise/Pro·IoT·평가판은 이 대상 판정에서 통과하지 않는다. OS 이름에 Enterprise LTSC 2019가 표시되는지도 현장에서 대조한다. 다른 OS에서 같은 빌드 번호를 보고하거나 개발 PC에서 점검이 통과한 경우 LTSC 인수 완료로 처리하지 않는다.

제품 유형과 SKU 기준은 Microsoft의 [Win32_OperatingSystem](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem) 및 [GetProductInfo](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getproductinfo) 정의를 따른다. 이 판별은 제품 종류 확인이며 라이선스 활성화·운영 승인 검사를 대신하지 않는다.

## 서비스 구성 확인표

| 서비스 | SCM 계정 | 실행 파일 |
|---|---|---|
| saw | LocalSystem | `<설치>\service\saw-service.exe` |
| saw-postgresql | NT AUTHORITY\NetworkService | `<설치>\service\saw-postgresql.exe` |
| saw-opensearch | LocalSystem | `<설치>\opensearch-2.19.6\bin\opensearch-service-x64.exe //RS//saw-opensearch` |

세 서비스는 독립 프로세스 형식이어야 한다. 앱 의존성은 두 저장소 서비스이며, PostgreSQL에는 추가 의존성을 허용하지 않는다. Procrun의 표준 Tcpip/Afd 의존성은 허용한다. 알 수 없는 계정·경로·의존성은 자동 수정하지 않고 중지 전에 거부한다.

Apache 문서는 64비트 Windows의 Procrun도 설정을 32비트 레지스트리 뷰에 저장한다고 설명한다. 업데이트 검증은 Registry32만 존재, 기존 Registry64만 존재, 두 뷰가 동일한 경우를 허용한다. 어느 한 뷰라도 불완전하거나 경로·옵션이 충돌하면 거부한다. 레지스트리 복사와 서비스 재등록으로 우회하지 않는다. [Apache Procrun Windows Registry Usage](https://commons.apache.org/proper/commons-daemon/procrun.html#Windows_Registry_Usage)

서비스 모드의 PostgreSQL 상태 확인은 관리자 계정의 `pg_ctl status`에만 의존하지 않는다. SCM에서 확인한 WinSW 프로세스와 데이터 디렉터리의 postmaster PID 연결, 보유 프로세스 핸들·생성 시각·다시 읽은 명령 정보를 확인한 뒤 PostgreSQL 준비 상태와 OpenSearch·HTTPS 응답을 함께 검사한다. HTTPS 기본 포트 443도 정상 입력으로 지원한다.

## 별도로 남는 실제 인수

읽기 전용 점검 다음의 업데이트·복구 작업은 현장 담당자가 점검 시간과 전체 복구 공간을 확보하고 승인한 뒤 수행한다. 깨끗한 LTSC 2019의 합성 설치에서 관리자/UAC → 실제 서비스 중지 → 전체 복구본 → 앱 교체 → 서비스 기동 → HTTPS 443 → 같은 계정·MFA·자료 보존 → 전체 시점 복구 → 재부팅 후 기동을 확인한다. 원래 설치의 계정이나 자료를 자동 시험용으로 사용하지 않는다.

전원 강제 중단, 조직 TLS 신뢰, 방화벽, 물리 폐쇄망, 실제 공동 부하, 운영 인수는 각각의 실제 결과를 남긴다. 레지스트리·SCM 합성 fixtures, PowerShell 구문 검사와 개발 PC 시험은 이 인수를 대체하지 않는다.
