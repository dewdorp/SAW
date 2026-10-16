# 폐쇄망 프로그램 업데이트·복구

이 안내는 프로그램 전체 버전을 바꿀 때 사용합니다. 탐지 룰·파서 데이터만 바꾸는 일은 [오프라인 콘텐츠 실습](OFFLINE-CONTENT-GUIDE.md)의 화면에서 반입·시험·독립 승인·적용·되돌리기를 사용하세요.

## 준비
새 매체와 해당 설치의 기존 매체를 모두 보관합니다. 새 ZIP의 공개 SHA256과 manifest를 확인합니다. 같은 Python/PostgreSQL/OpenSearch/모델 실행기·의존성 조합의 앱 업데이트만 지원합니다. 런타임 변경, 외부 경로의 데이터, 연결 지점/심볼릭 링크, 실행 중인 프로세스는 자동 전환하지 않습니다.

설치·복구본 경로는 짧게 준비합니다. 모든 하위 파일·폴더와 임시 복구 경로가 Windows의 지원 길이를 넘으면 복사 전에 거부합니다. 도구가 긴 경로 레지스트리 설정을 바꾸지 않습니다. 기존 설치는 절대 경로 설정을 사용하므로 폴더 이름을 임의로 바꾸지 마세요.

기존 설치의 앱·키·저장소를 다른 로컬 사용자가 읽거나 바꿀 수 있는 권한이면 점검이 거부됩니다. 담당 관리자가 실제 서비스 계정에 맞게 권한을 정비한 뒤 다시 검사해야 합니다. 업데이트 도구가 기존 권한을 자동으로 변경하지 않습니다. 신규 매체 설치는 처음부터 설치 루트를 보호합니다.

복구본에는 DB·색인·증거·비밀키·계정·모델까지 포함됩니다. 접근을 제한한 로컬 같은 볼륨의 경로를 사용하고 충분한 공간을 확보합니다. 파일 내용·구조와 접근권한 DACL을 보존하며, Windows 소유자/SACL까지 복제하는 도구는 아닙니다. 복구본을 GitHub에 올리거나 분석 자료처럼 공유하지 마세요. 백업 보관 기간은 조직 정책으로 정하며 도구가 기존 복구본을 자동 삭제하지 않습니다.

## 1. 점검과 중지
아래 경로는 예입니다. 실제 반입 폴더와 설치 폴더로 바꿉니다. 새 매체 폴더에서 실행합니다.

작업을 저장하고 업로드·분석이 진행 중이지 않은지 확인합니다. 사용자 프로세스 파일럿은 다음처럼 전체 중지합니다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SAW\saw-ctl.ps1 stop
```

서비스 설치는 관리자가 승인된 유지보수 시간에 SAW·OpenSearch·PostgreSQL을 중지하고 자동 재시작을 막아야 합니다. 업데이트 도구는 관리자 설치·서비스 등록·방화벽 변경을 수행하지 않습니다.

점검 명령도 전체 중지 후 실행합니다. 실행 중이면 변경 없이 거부하며, 필요한 복구 공간과 대상 manifest 지문을 확인합니다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File D:\SAW-media-new\update.ps1 -Action plan -InstallRoot C:\SAW -BundleDir D:\SAW-media-new -BaselineBundleDir D:\SAW-media-old
```


## 2. 복구본 생성과 적용
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File D:\SAW-media-new\update.ps1 -Action apply -InstallRoot C:\SAW -BundleDir D:\SAW-media-new -BaselineBundleDir D:\SAW-media-old -RecoveryPoint C:\SAW-recovery-20261017
```

전체 중지·경로·기존 소스/런타임·공간을 확인하고 전체 설치의 복구본을 보관·해시 검증한 뒤 새 앱을 적용합니다. app/.env와 app/var의 비밀키를 보존합니다. 적용 후에도 정지 상태를 유지하며 DB 마이그레이션은 다음 시작 때 실행됩니다. 적용 receipt만으로 서비스 정상화를 판단하지 마세요.

## 3. 시작과 확인
다음 명령은 사용자 프로세스 설치용입니다. 서비스 설치는 관리자가 기존 승인된 서비스 시작 절차를 사용합니다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SAW\saw-ctl.ps1 start
```

로그인·MFA, 기존 조사 건수·원문·노트, 새 합성 로그/PCAP 처리, 통계/행위 분석을 확인합니다. 프로그램·저장소를 한 번 더 종료·시작한 뒤 결과가 유지되는지 확인합니다. 오류가 있으면 분석가 접속을 열지 말고 원인을 보존합니다.

## 4. 전체 시점 복구
새 버전이 DB0014를 적용한 뒤 구버전 app만 덮어쓰면 시작에 실패할 수 있습니다. 아래 복구는 업데이트 직전 시점으로 전체를 되돌립니다. 업데이트 후 생긴 기록을 자동 병합하지 않습니다. 현재 설치는 별도 retained 경로에 보관하므로 필요한 신규 기록은 별도 검토·이관해야 합니다. 보존 폴더의 실제 이름은 같은 상위 경로의 `.saw-k-<고유값>`이며, 결과 JSON의 `retained_installation` 값을 확인합니다. 그 안의 설정에는 원래 절대 경로가 남아 있으므로 그 폴더에서 직접 기동하지 않습니다.

전체를 중지한 후 새 매체에서 실행합니다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File D:\SAW-media-new\update.ps1 -Action restore -InstallRoot C:\SAW -BundleDir D:\SAW-media-new -RecoveryPoint C:\SAW-recovery-20261017 -ConfirmPointInTimeRecovery
```

복구본 변조·누락, 실행 중 프로세스, 원래 설치 경로 불일치가 있으면 진행하지 않습니다. 복구 후 원래 경로에서 시작해 이전 조사·색인·MFA를 다시 확인합니다. retained 폴더와 복구본은 자동 삭제하지 않습니다.

## 검증 상태
구현·실제 설치 전환 결과는 [별도 실행 기록](OFFLINE-RELEASE-VALIDATION-2026-10-17.md)에 기록합니다. Windows11 사용자 프로세스 시험, 깨끗한 LTSC2019, 관리자 서비스·다중 분석가 인수는 서로 구분합니다.

도구 실행에 쓰는 독립 Python은 보호된 임시 폴더에 남으며 자동 삭제하지 않습니다. 복구본/retained/임시 경로는 결과에 표시됩니다.
