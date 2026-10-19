# 업데이트 상태 파일 소유자 수정안 — 2026-10-19

상태: **소스 수정안. Windows 실행·새 설치 매체 검증 전이며 배포 완료가 아니다.**

## 현장에서 확인한 조건

- 대상: Windows 10 Enterprise LTSC 2019 x64, 더블클릭 업데이트의 **설치 점검 중** `invalid_controller_result`.
- 사용자가 내장 Python에서 `RUNTIME_OK`, `EXIT_CODE=0`을 확인했다. 이는 기본 실행과 확인한 모듈의 로딩 결과다.
- 사용자가 기록 폴더의 `state.json`에 대해 `StateOwnerAllowed=False`, `StateOwnerIsAdministrators=True`를 확인했다.
- `state.json`의 461은 파일 크기로 전달됐으며 JSON 본문이나 전체 ACL을 확인한 결과가 아니다.
- 현재 배포 `v0.1.0-pilot.20261018.1`의 소스는 `4655fbba7cd0d16f42379b14bfcbac147a589925`다. 수정 기준 `main`은 `723e2a677dfc19e2079acbc0c6b604518a8c76aa`이며 관련 실행 코드가 같다.

## 원인과 변경

UI는 작업 기록 폴더의 소유자를 현재 사용자로 지정하지만 PowerShell의 `Write-WorkerState`는 파일 소유자를 지정하지 않고 임시 파일을 만들었다. Windows 토큰의 기본 소유자가 Administrators이면 파일도 해당 그룹 소유가 될 수 있다. Python의 `_state_directory`는 기존 `state.json`에 현재 사용자 또는 SYSTEM 소유자를 요구하므로 이 파일을 거부한다. 이 검사는 최종 결과 기록 전에 수행되어 worker에는 `invalid_controller_result`가 남는다.

수정은 새 상태 파일 생성에 한정한다.

1. `deploy/windows/update-worker.ps1`: PowerShell 5.1/.NET Framework `FileStream`의 `FileSecurity` 생성자를 사용한다. `CreateNew`로 고유 파일을 만들면서 현재 사용자 소유자와 현재 사용자·SYSTEM만 허용하는 보호된 DACL을 지정한다.
2. `saw/devtools/desktop_update.py`: Windows에서는 동일한 소유자·DACL을 지정한 `CreateFileW(CREATE_NEW)`로 파일을 만든다. CRT 파일 설명자로 소유권을 넘긴 후 기존 JSON 기록·flush·fsync·원자 교체를 유지한다. POSIX에서는 생성 시 0600 모드를 지정한다.
3. private owner 허용 목록, 경로·재분석 지점·하드 링크 검사와 매체 검증은 유지한다. 기존 설치·DB·계정·복구본·시스템 기본 소유자 정책의 권한은 변경하지 않는다.

기존 오류 폴더의 `state.json` 소유자를 수동으로 고치는 것만으로는 다음 실행의 새 기록 폴더와 새 파일 생성 문제가 해결되지 않는다. 기존 봉인 매체 안의 스크립트를 직접 덮어쓰면 매체 검증과 불일치한다. 수정 소스로 새 매체를 만들고 검증해야 한다.

## 실제로 실행한 검증

실행 환경은 Linux / Python 3.12.14 / pytest 9.1.1이다. GitHub의 필요한 updater 소스·시험·고정 fixture 파일만 가져온 독립 사본이며 전체 저장소 checkout이나 Windows 개발 환경이 아니다. 모든 자료는 합성 자료다.

| 검사 | 결과 |
|---|---|
| 새 private-state 시험을 원본 Python에 먼저 실행 | 3실패·2통과. 새 파일과 게시 실패 후 임시 파일이 private 접근 검사에서 거절됨 |
| 생성부 수정 후 같은 시험 | 5통과 |
| 기존 updater 시험 사본, 변경 전 | 59통과·79건너뜀·5실패 |
| 같은 시험과 새 시험 6건, 변경 후 | 66통과·80건너뜀·3실패 |
| PowerShell → Python 실제 연결 시험의 Linux 수집 | 1건 수집·Windows 전용으로 건너뜀 |
| 독립 코드 검토 | Windows fixture의 불필요한 선행 문자를 고침. 미해결 코드 결함 지적 없음. Windows 실행 검증 필요 |
| 줄 끝·형식 | PowerShell UTF-8 BOM/CRLF 유지, Python LF 유지, CRLF를 인식한 `git diff --check` 통과 |

변경 후에도 실패한 기존 시험은 다음과 같다. 세 시험 모두 동일 환경의 변경 전 코드에서도 실패했다. 이 결과를 전체 시험 통과로 보고하지 않는다.

- `test_postgresql_process_with_other_data_directory_is_not_owned`: Linux의 ctypes에는 `WinDLL`이 없다.
- `test_health_does_not_accept_postgres_process_without_readiness`: Linux에 Windows `SystemRoot` 환경이 없다.
- `test_tracked_live_process_and_pg_lock_refuse_copy`: Windows 프로세스 추적을 전제로 한 기대 결과가 Linux 실행과 맞지 않는다.

변경 전 추가로 실패했던 `test_apply_and_restore_use_real_backend_and_preserve_private_state`, `test_installed_manifest_supersedes_old_baseline_for_inspect_start_and_apply`는 변경 후 통과했다. POSIX 상태 파일이 반복 점검의 private 접근 조건을 만족하게 된 결과다. 이는 Windows 소유자 문제의 실제 실행 검증을 대신하지 않는다.

첫 넓은 시험은 실행 샌드박스의 소켓 생성 제한 및 누락된 원본 서비스 XML fixture 때문에 실패했다. fixture를 원본 그대로 준비하고 합성 로컬 포트 검사를 허용한 같은 조건에서 위 변경 전·후 결과를 얻었다. 새 시험의 모듈 로딩 순서로 기존 backend 대체가 다른 모듈에 적용된 문제도 시험 코드에서 고쳤다.

## Windows에서 남은 검증

`tests/unit/test_update_state_handoff.py`는 실제 UI 폴더 생성 함수, worker 기록·읽기 함수, Python `_state_directory`·`State.write`를 연결한다. 전체 worker, `run`, 서비스·DB·설치 동작은 호출하지 않는다. 시험이 만드는 빈 합성 경로만 사용하며 기존 개발 Python을 사용하므로 embedded ZIP이 없어도 이 연결 검사는 가능하다.

아래는 **Windows 개발 PC의 저장소 루트**에서 실행할 명령이다. PowerShell 7로 Windows PowerShell 5.1을 대체하지 않는다.

일반 PowerShell 창:

```powershell
$env:SAW_TEST_STATE_TOKEN_OWNER = 'current-user'
& '.\.venv\Scripts\python.exe' -m pytest tests/unit/test_private_update_state.py tests/unit/test_update_state_handoff.py -q -p no:cacheprovider
```

별도로 연 관리자 PowerShell 창에서, 토큰 기본 소유자가 Administrators인 경우:

```powershell
$env:SAW_TEST_STATE_TOKEN_OWNER = 'administrators'
& '.\.venv\Scripts\python.exe' -m pytest tests/unit/test_private_update_state.py tests/unit/test_update_state_handoff.py -q -p no:cacheprovider
```

연결 시험은 선택한 토큰 조건이 맞지 않으면 실패한다. 스스로 권한을 올리거나 컴퓨터 정책을 바꾸지 않는다. 두 조건의 결과를 각각 기록한다.

이어 기존 worker/controller/매체 회귀와 저장소 전체 서버 시험을 실행한다. 실제 배포의 pinned embedded Python 3.12.10, Windows PowerShell 5.1, NTFS, LTSC2019에서 새 매체의 점검·적용·복구 흐름을 합성 설치로 검증한다. 계정·설정·원본·DB 보존과 잘못된 소유자·ACL 거부도 확인한다.

## 배포

이 변경만으로 기존 GitHub ZIP이 갱신되지는 않는다. Windows 검증 후 새 버전의 전체 오프라인 매체를 생성하고 manifest·체크섬을 다시 봉인하여 검증한다. 새 ZIP은 기존 설치 밖에 풀고 최상위 `UPDATE-SAW.cmd`로 점검한다. 기존 릴리스·태그·자산을 덮어쓰지 않는다.

아직 실행하지 않은 것: Windows native 보안 API, 실제 LTSC 설치 점검·업데이트·복구, 전체 저장소 시험, 새 1.4GB 매체 빌드·봉인·게시. 운영 설치를 수정하지 않았다.

## API 근거

- [Windows 객체의 기본 소유자](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object)
- [.NET Framework FileStream의 FileSecurity 생성자](https://learn.microsoft.com/en-us/dotnet/api/system.io.filestream.-ctor?view=netframework-4.8.1)
- [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
