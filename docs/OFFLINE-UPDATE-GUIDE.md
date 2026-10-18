# 기존 C:\SAW 업데이트·복구 안내

새 매체에 **UPDATE-SAW.cmd**가 있으면 [더블클릭 업데이트 안내](DOUBLE-CLICK-UPDATE-GUIDE.md)를 먼저 사용하세요. 아래 내용은 기존 명령형 도구를 사용할 때의 참고 절차입니다.

기존 계정과 분석 자료를 유지하려면 **새 매체의 update.ps1**을 사용합니다. 현재 C:\SAW는 그대로 두고, 프로그램을 모두 중지한 뒤 전체 복구본을 만든 다음 앱을 교체합니다. install.ps1을 다시 실행하거나 새 ZIP을 C:\SAW 위에 풀어서 업데이트하지 마세요.

이 안내는 프로그램 전체 버전을 바꿀 때 사용합니다. 탐지 룰·파서 데이터만 바꾸는 일은 [오프라인 콘텐츠 실습](OFFLINE-CONTENT-GUIDE.md)의 화면에서 반입·시험·독립 승인·적용·되돌리기를 사용하세요.

## 먼저 알아둘 점

이 안내는 로그인 가능한 기존 설치의 앱 업데이트용입니다. 설치가 중간에 실패한 상태라면 새 매체의 START-HERE.md에 있는 설치 재개 안내를 먼저 확인합니다.

- **2026-10-17 버전이 정상 실행 중이면**, 10월 18일의 설치기 보완 때문에 급히 업데이트할 필요는 없습니다. 두 매체의 업무 스키마는 0014로 같고, 이번 차이는 설치·검증 도구와 안내 문서 중심입니다.
- 이 업데이트는 기존 서비스 등록·서비스 XML·Java 환경·데이터베이스 설정·접근권한을 새 설치 방식으로 자동 재구성하지 않습니다. 설치 오류를 고치는 작업과 정상 설치의 앱 업데이트는 구분합니다.
- 같은 Python·PostgreSQL·OpenSearch·모델 실행기·의존성 조합의 앱 업데이트만 지원합니다. 런타임 제품 버전 변경, 외부 경로의 데이터, 연결 지점·심볼릭 링크, 실행 중인 설치는 자동 전환하지 않습니다.
- **기존 설치 위치는 C:\SAW로 유지합니다.** 이 절차는 C:에서 D:로 이전하는 기능이 아닙니다. 기존 설정과 서비스에는 절대 경로가 저장되어 있으므로 설치 폴더 이름을 바꾸지 않습니다.

## 1. 폴더와 여유 공간 준비

다음은 예시입니다. 새 ZIP은 별도 폴더에 압축을 풀고, 그 안에 update.ps1과 release-manifest.json이 있는지 확인합니다.

| 용도 | 예시 경로 | 설명 |
|---|---|---|
| 기존 설치 | C:\SAW | 지금 계정과 분석 자료가 들어 있는 곳 |
| 새 매체 | D:\SAW-media-20261018 | 새 ZIP을 압축 해제한 곳 |
| 이번 복구본 | C:\SAW-r-20261018 | 아직 없는 새 폴더 이름을 지정; 도구가 생성 |
| 원래 매체 | D:\SAW-media-old | 설치 이력 파일이 없는 구형 설치에 필요 |

D:가 없으면 새 매체를 C:\SAW-media-20261018에 두어도 됩니다. **매체·설치·복구 폴더는 서로 별개**여야 하고, 다른 폴더의 하위에 중첩하면 안 됩니다. 명령의 예시 D: 경로도 실제 위치로 바꾸세요.

**복구본은 현재 구현상 설치와 같은 드라이브에 만듭니다.** C:\SAW를 업데이트할 때 D:를 복구본 위치로 지정해서 C:의 공간 부족을 우회할 수는 없습니다.

점검 명령은 설치 전체 크기, 새 앱, app/var 보존분, 64MiB의 여유 공간을 합해 적용에 필요한 공간을 계산합니다. 나중에 전체 복구를 하려면 그때도 **설치 전체 크기 + 64MiB**가 추가로 필요합니다. 따라서 점검 통과가 되돌리기 공간까지 보장하지는 않습니다.

예를 들어 C:\SAW 전체가 30GB라면 적용에 약 30GB와 새 앱 등의 공간이 필요합니다. 되돌리기까지 준비하려면 시작 전에 C:에 약 60GB와 새 앱·추가 자료를 위한 여유를 확보하는 편이 좋습니다. 정확한 적용 기준은 다음 점검의 required_free_bytes이며, 모델·원본·색인·기존 백업도 전체 크기에 포함됩니다.

폴더 이름은 짧게 준비하세요. 하위 파일과 임시 복구 경로가 Windows의 지원 길이를 넘으면 복사 전에 거부됩니다. 도구가 긴 경로 레지스트리 설정을 바꾸지는 않습니다.

새 ZIP을 별도 폴더에 풀고 원래 매체도 보관합니다. 사용자가 해시 값을 직접 계산하거나 대조할 필요는 없습니다. update.ps1이 실행 때마다 새 매체의 필수 파일과 무결성을 자동 검증합니다. 검증 오류가 있으면 적용을 중지하고 매체를 확인합니다.

## 2. 작업 저장 후 설치 방식에 맞게 중지

분석가에게 점검 시간을 알리고 업로드·분석 작업을 끝낸 뒤 접속을 멈춥니다. 기존 계정으로 로그인되는지, 대표 조사의 제목·이벤트 수·탐지 수·원문·노트가 보이는지 먼저 확인해 두면 업데이트 뒤 비교하기 쉽습니다. 비밀번호·MFA 비밀키·원문 내용을 점검 문서나 공유 화면에 적지 마세요.

### A. Windows 서비스로 설치한 공동 접속 서버

서버에서 **Windows PowerShell을 관리자 권한으로 실행**합니다. 관리자 계정 로그인만으로는 충분하지 않으며, 창 제목에 관리자 표시가 있어야 합니다.

아래 조회로 세 서비스의 경로가 C:\SAW 아래인지 확인합니다. 서비스가 없거나 다른 설치 경로를 가리키면 중지·시작 명령을 진행하지 말고 설치 방식을 확인하세요.

~~~powershell
Get-CimInstance Win32_Service |
  Where-Object { $_.Name -in @('saw', 'saw-opensearch', 'saw-postgresql') } |
  Select-Object Name, State, PathName
~~~

서비스 창은 Win+R에서 services.msc를 입력해 열 수 있습니다. SAW 웹 서비스, OpenSearch, PostgreSQL을 다음 순서로 정상 중지하고 기다립니다.

~~~powershell
Stop-Service -Name 'saw' -ErrorAction Stop
(Get-Service 'saw').WaitForStatus('Stopped', [TimeSpan]::FromSeconds(180))
Stop-Service -Name 'saw-opensearch' -ErrorAction Stop
(Get-Service 'saw-opensearch').WaitForStatus('Stopped', [TimeSpan]::FromSeconds(180))
Stop-Service -Name 'saw-postgresql' -ErrorAction Stop
(Get-Service 'saw-postgresql').WaitForStatus('Stopped', [TimeSpan]::FromSeconds(180))
Get-Service -Name 'saw', 'saw-opensearch', 'saw-postgresql'
~~~

세 항목 모두 Stopped인지 확인합니다. 중지 실패나 시간 초과가 나면 다음 단계로 넘어가지 않습니다. 점검 중 재부팅이나 외부 감시 프로그램·예약 작업이 서비스를 다시 시작하지 않도록 기존 운영 절차에 따라 관리합니다. 이 안내의 업데이트 도구는 서비스 등록·방화벽 변경을 하지 않습니다.

### B. NoAdmin 사용자 프로세스로 설치한 시험용 PC

처음 설치하고 실행한 **같은 Windows 사용자**로 실행합니다. 아래 명령은 NoAdmin 설치 전용이며, 위 서비스 설치의 제어 명령으로 사용하지 않습니다.

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\SAW\saw-ctl.ps1" stop
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\SAW\saw-ctl.ps1" status
~~~

PostgreSQL·OpenSearch·SAW가 모두 중지로 표시되는지 확인합니다. 중지 출력이 나왔더라도 다음 점검이 실행 중 상태를 발견하면 거부합니다. 강제 종료하거나 잠금 파일을 지워 우회하지 마세요.

## 3. 변경 전 점검

관리자 서비스는 관리자 PowerShell에서, NoAdmin 설치는 같은 설치 사용자로 진행합니다. PowerShell의 현재 위치는 C:\SAW 밖으로 둡니다.

~~~powershell
Set-Location "D:\SAW-media-20261018"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\SAW-media-20261018\update.ps1" -Action plan -InstallRoot "C:\SAW" -BundleDir "D:\SAW-media-20261018"
~~~

화면의 결과 JSON에서 다음을 확인합니다.

| 항목 | 의미 |
|---|---|
| status: ready_stopped | 설치가 중지되어 있고 적용 사전 검사를 통과 |
| snapshot_bytes | 전체 복구본에 들어갈 파일 크기 합계 |
| required_free_bytes | 이번 적용에 필요한 최소 여유 공간 |
| free_bytes | 설치 드라이브의 현재 여유 공간 |
| target_manifest_sha256 | 적용할 새 매체 manifest의 지문 |

이 단계는 계정이나 분석 자료를 교체하지 않습니다. 보호된 임시 실행 폴더는 생성되며 자동 삭제하지 않습니다. 파일 수와 자료 크기에 따라 검사가 오래 걸릴 수 있으므로 같은 명령을 여러 창에서 동시에 실행하지 마세요.

**원래 매체 옵션이 필요한 경우:** C:\SAW\installed-release-manifest.json이 있으면 위 예시처럼 생략할 수 있습니다. 파일이 없는 구형 설치는 정확히 그 설치를 만든 검증된 원래 매체가 필요합니다. 점검 명령과 다음 적용 명령 끝에 아래 옵션을 추가합니다.

~~~powershell
-BaselineBundleDir "D:\SAW-media-old"
~~~

임의의 이전 버전을 원래 매체로 지정하지 않습니다. 원래 매체가 필요한데 없다면 파일을 덮어쓰거나 설치 이력을 직접 만들지 말고 해당 매체를 확보해야 합니다.

권한 오류가 나면 담당 관리자가 실제 서비스 계정에 맞게 기존 권한을 검토합니다. 도구는 기존 권한을 자동 완화하지 않습니다. 로컬 수정 파일·런타임 변경·공간 부족·실행 중 상태가 확인되어도 적용을 거부하므로 원인을 해결한 뒤 다시 점검합니다.

## 4. 복구본을 만들고 새 앱 적용

점검이 통과하고 되돌리기 공간까지 준비되면 실행합니다. 아래 복구 폴더가 이미 있으면 재사용하지 말고 새로운 이름을 정합니다.

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\SAW-media-20261018\update.ps1" -Action apply -InstallRoot "C:\SAW" -BundleDir "D:\SAW-media-20261018" -RecoveryPoint "C:\SAW-r-20261018"
~~~

구형 설치에 원래 매체가 필요했다면 이 명령에도 동일한 -BaselineBundleDir 옵션을 붙입니다.

도구는 전체 중지·경로·기존 파일·런타임·권한·공간을 다시 확인합니다. 그다음 전체 설치의 복구본을 만들고 파일 지문과 접근권한을 확인한 뒤 새 앱으로 교체합니다.

| 보존 대상 | 처리 |
|---|---|
| 계정·비밀번호 해시·MFA·권한·조사·분석 기록 | 기존 PostgreSQL 데이터 유지 |
| 검색용 이벤트·색인 | 기존 OpenSearch 데이터 유지 |
| 원본 로그·PCAP·모델 파일 | 기존 저장 위치의 자료 유지 |
| 앱 설정·비밀키·TLS 인증서 | app/.env, data/saw, 기존 TLS·비밀값 유지; app/var가 있으면 함께 보존 |
| 시작 제어 파일·설치 버전 정보 | 새 saw-ctl.ps1과 installed-release-manifest.json으로 교체 |
| 최초 설치 이력 | 기존 .saw-install-state.json 유지; 수동 편집·삭제하지 않음 |

성공 결과는 **status: applied_stopped_schema_pending**입니다. 뜻은 “앱 적용 완료, 아직 중지 상태, 시작 시 DB 스키마 확인 필요”입니다. 계정을 다시 만들거나 MFA를 다시 등록하라는 뜻이 아닙니다. 이 결과만으로 서비스 정상화나 데이터 확인 완료로 판단하지 않습니다.

중간 오류가 나면 결과와 보호된 복구 폴더를 보존합니다. 같은 복구 폴더로 apply를 다시 실행하거나 C:\SAW를 삭제해 재설치하지 않습니다. 어느 단계까지 진행됐는지 확인한 뒤 복구 여부를 결정합니다.

## 5. 시작하고 기존 계정·분석 자료 확인

### A. 관리자 서비스 설치

서비스 설치에서만 다음 순서로 시작합니다.

~~~powershell
Start-Service -Name 'saw-postgresql' -ErrorAction Stop
(Get-Service 'saw-postgresql').WaitForStatus('Running', [TimeSpan]::FromSeconds(180))
Start-Service -Name 'saw-opensearch' -ErrorAction Stop
(Get-Service 'saw-opensearch').WaitForStatus('Running', [TimeSpan]::FromSeconds(240))
Start-Service -Name 'saw' -ErrorAction Stop
(Get-Service 'saw').WaitForStatus('Running', [TimeSpan]::FromSeconds(180))
Get-Service -Name 'saw', 'saw-opensearch', 'saw-postgresql'
~~~

Running은 Windows 서비스 상태입니다. 검색엔진 준비와 DB 마이그레이션이 끝나 웹 화면이 실제로 열리는지도 확인해야 합니다. 시작이 실패하면 새로 서비스를 등록하거나 계정을 초기화하지 말고 C:\SAW\logs 아래 해당 로그를 보호된 환경에서 확인합니다.

### B. NoAdmin 설치

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\SAW\saw-ctl.ps1" start
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\SAW\saw-ctl.ps1" status
~~~

### 공통 확인

기존 접속 주소로 브라우저를 열고 다음 순서로 확인합니다. 접속 주소와 계정은 기존 값을 사용합니다.

1. 기존 아이디·비밀번호·MFA로 로그인합니다.
2. 업데이트 전 확인해 둔 조사를 열어 이벤트·탐지 건수, 원문, 노트가 유지되는지 비교합니다.
3. 별도 시험 조사에 가상 로그·PCAP을 넣어 처리 완료, 검색, 통계·행위 분석을 확인합니다.
4. 새 시험 노트를 저장하고, 같은 방식으로 전체 종료·시작한 뒤 유지되는지 확인합니다.
5. 확인이 끝난 다음 분석가의 접속과 새 작업을 다시 받습니다.

최신 앱을 처음 시작할 때 필요한 DB 마이그레이션이 실행됩니다. 예를 들어 10월 12일의 스키마0011 설치는 최신0014로 올라갑니다. 10월 17일→18일은 둘 다0014입니다. 오류가 있으면 분석가 접속을 열지 말고 원인과 복구본을 보존합니다.

## 6. 문제가 있을 때 업데이트 직전 시점으로 복구

새 앱이 DB0014를 적용한 뒤 구버전 app만 덮어쓰면 시작하지 못할 수 있습니다. 아래 명령은 **앱·DB·색인·원본·키를 업데이트 직전 시점으로 함께 되돌립니다.** 업데이트 후 만든 기록을 이전 시점에 자동 병합하지는 않습니다. 업데이트 후 추가한 계정이나 비밀번호·MFA·권한 변경도 복구 시점의 상태로 돌아갑니다.

먼저 2단계와 같은 방식으로 전체 중지합니다. 복구할 때도 설치 전체를 임시 복사할 여유 공간이 필요합니다. 그다음 새 매체에서 실행합니다.

~~~powershell
Set-Location "D:\SAW-media-20261018"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\SAW-media-20261018\update.ps1" -Action restore -InstallRoot "C:\SAW" -BundleDir "D:\SAW-media-20261018" -RecoveryPoint "C:\SAW-r-20261018" -ConfirmPointInTimeRecovery
~~~

성공 결과는 **status: restored_stopped**입니다. 아직 정지 상태이므로 5단계의 해당 방식으로 원래 C:\SAW를 시작하고 기존 계정·MFA·조사·색인을 다시 확인합니다.

복구 직전의 최신 설치는 같은 상위 경로의 .saw-k-고유값 폴더에 별도로 보존됩니다. 결과 JSON의 retained_installation에 정확한 경로가 나옵니다. 업데이트 후 만든 기록은 그 안에 남으므로 필요하면 별도 검토·이관합니다. 그 폴더의 설정에는 원래 C:\SAW 절대 경로가 남아 있으므로 **보존 폴더에서 직접 실행하지 않습니다.**

복구본 변조·누락, 실행 중 프로세스, 원래 설치 경로 불일치가 있으면 도구가 진행을 거부합니다. 복구본과 보존 폴더를 자동 삭제하지 않습니다.

## 보관과 검증 범위

복구본에는 계정·DB·색인·원본·모델·비밀키까지 포함됩니다. 접근을 제한한 로컬 경로에 두고 GitHub에 올리거나 분석 자료처럼 공유하지 마세요. 파일 내용·구조와 접근권한 DACL을 보존하지만, Windows 소유자/SACL까지 복제하는 도구는 아닙니다. 복구본·보존 폴더·보호된 임시 Python 폴더의 보관 기간은 조직 정책으로 정하며 자동 삭제하지 않습니다.

기존 실제 합성 설치 전환·복구 결과는 [업데이트 실행 기록](OFFLINE-RELEASE-VALIDATION-2026-10-17.md), 10월 18일 설치기 보완은 [설치기 검증 기록](verification/installer-recovery-2026-10-18.md)에 구분해 기록했습니다. Windows11 사용자 프로세스 시험, 깨끗한 LTSC2019, 관리자 서비스·다중 분석가 인수는 서로 다릅니다. 이 문서의 서비스 명령 예시는 실제 관리자 서비스 업데이트 검증 완료를 뜻하지 않습니다.
