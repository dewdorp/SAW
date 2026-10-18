# 2026-10-18 설치 위치·재실행 보완

신규 설치의 C:/D: 폴더 선택과 같은 경로 재개는 [새 설치 안내](INSTALL-RECOVERY-2026-10-18.md)를 먼저 따른다. 정상 설치본은 재설치하지 않고 검증하며, 기존 드라이브 이전은 별도 작업이다. 아래 과거 설치 흐름에서 신규 설치 전용이라는 설명은 보완 설치 매체에는 적용되지 않는다.

> 최신 모델 제외 매체는 [2026-10-17 설치 안내](OFFLINE-RELEASE-2026-10-17.md)를 먼저 확인하세요. 내장 Python ZIP과 62개 wheel을 사용합니다. install.ps1은 신규 설치, update.ps1은 중지한 기존 설치의 앱 업데이트·전체 시점 복구용입니다. [업데이트 안내](OFFLINE-UPDATE-GUIDE.md)와 [실제 검증 범위](OFFLINE-RELEASE-VALIDATION-2026-10-17.md)를 함께 확인하세요. 서비스 방식 설명은 실제 서비스 인수 완료를 뜻하지 않습니다.

# SAW 설치 설명서 — Windows 폐쇄망 서버

설치 대상: **Windows 10 Enterprise LTSC 2019 x64** (깨끗한 대상 OS 인수는 미완료), **인터넷 차단(폐쇄망)**, 저사양 서버.
설계 근거: [ADR-0016](adr/0016-windows-airgapped-deployment-and-builtin-pcap.md)

---

## 1. 전체 구성

```
분석가 PC (브라우저)
      │  HTTPS 443  (Windows 방화벽: 허용한 대역만)
      ▼
┌──────────────────── SAW 서버 (Windows) ─────────────────────┐
│  saw              SAW 웹 화면 + API (Python, Windows 서비스)    │
│    ├─ saw-postgresql   사용자·사건·지식 DB   (127.0.0.1:5432) │
│    └─ saw-opensearch   로그 검색 엔진        (127.0.0.1:9200) │
│  PCAP 분석: SAW 내장 분석기 (Zeek 불필요)                       │
│  C:\SAW\data  증거 원본·인덱스 / C:\SAW\backup  백업              │
└──────────────────────────────────────────────────────────────┘
```

- 외부에 열리는 포트는 **443 하나**입니다. PostgreSQL·OpenSearch는 서버 내부(127.0.0.1)에서만 접근됩니다.
- Docker, WSL, 인터넷 연결이 **필요 없습니다.**

### 권장 사양

| 항목 | 최소 | 권장 |
|---|---|---|
| CPU | 4코어 | 8코어 |
| 메모리 | 8GB | 16GB 이상 |
| 디스크 | 여유 100GB | 500GB 이상 (로그·PCAP 보관량에 비례) |

메모리별 OpenSearch 힙 설정(`-OpenSearchHeapGB`): 8GB → **1**, 16GB → **2~4**, 32GB → **8**. 메모리의 절반을 넘기면 안 됩니다.
지정하지 않으면 설치 스크립트가 메모리를 보고 정합니다(16GB 미만 1, 16GB 이상 2, 32GB 이상 4 — 브라우저·업무 프로그램 몫을 남김).

### 분석가 PC 한 대에 설치 (서버가 아닌 경우)

분석가가 **자기 PC에서 혼자** 쓰는 경우 `-LocalOnly`로 설치합니다.

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -LocalOnly
```

- SAW가 **127.0.0.1에만** 열립니다. 방화벽 규칙을 만들지 않으며 다른 PC에서는 접속할 수 없습니다. 접속 주소는 `https://localhost/`
- OpenSearch·PostgreSQL 메모리를 PC 메모리에 맞춰 작게 잡습니다.
- 무거운 작업은 **한 번에 하나씩** 처리합니다(`SAW_JOB_WORKERS=1`). 여러 파일을 올리면 차례로 처리되고 화면은 계속 쓸 수 있습니다.

### 관리자 권한이 없는 PC (`-NoAdmin`)

분석가 PC에 관리자 권한이 없으면 **일반 PowerShell**에서 다음처럼 설치합니다. 서비스 등록·방화벽·시스템 폴더를 건드리지 않습니다.

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -NoAdmin -AutoStartAtLogon
```

| 항목 | 동작 |
|---|---|
| 설치 위치 | `%LOCALAPPDATA%\SAW` (예: `C:\Users\홍길동\AppData\Local\SAW`). 폴더 권한은 **현재 사용자와 SYSTEM만** |
| 실행 방식 | 서비스 대신 사용자 프로세스. 시작 메뉴 **SAW → SAW start / SAW stop / SAW status / SAW open** |
| 접속 주소 | `https://localhost:8443/` (127.0.0.1에만 열림) |
| 자동 시작 | `-AutoStartAtLogon`을 주면 로그온할 때 자동 시작. 주지 않으면 재부팅 후 **SAW start**를 눌러야 함 |
| Python | 매체의 Python 3.12.10 embeddable과 고정 wheel을 설치 폴더 안에서 사용합니다. 시스템 Python의 사전 설치가 필요하지 않습니다. |
| 제거 | `uninstall.ps1 -InstallRoot "$env:LOCALAPPDATA\SAW"` (관리자 권한 불필요) |

명령으로 제어하려면:

```powershell
powershell -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\SAW\saw-ctl.ps1" status
```

- 조직 정책이 PowerShell 스크립트 실행을 막으면(그룹 정책 `AllSigned` 등) 설치·실행이 되지 않습니다. 이 경우 보안 담당자에게 서명 또는 예외를 요청하세요.
- 서비스 방식보다 보호 수준이 낮습니다(데이터가 사용자 계정 권한으로 실행·보관). 한 사람이 쓰는 분석 PC 용도로만 권합니다.

### 브라우저

SAW 화면은 **Chrome 또는 Microsoft Edge(최신, Chromium)** 에서 동작합니다. Windows 10 LTSC 2019에는 기본으로 Internet Explorer 11만 있으며, IE로 접속하면 "Chrome으로 접속하세요" 안내만 표시됩니다.

### 대용량 로그 처리 (저사양 PC 기준)

| 항목 | 동작 |
|---|---|
| 저장 크기 | 웹·네트워크·NDR처럼 필드로 나뉘는 로그는 **원본 줄을 인덱스에 넣지 않고** 원본 파일 위치만 저장. 이벤트 상세를 열 때 원본 파일에서 읽어 옴 (`SAW_RAW_STORE=auto`, 기본). 텍스트 로그(분류되지 않는 로그)는 원본 줄을 저장해 검색·패턴 분석에 사용 |
| 압축 | OpenSearch `best_compression`, 단일 노드 복제본 0 |
| 저장 확정 | 기본 설치와 `-LocalOnly`/`-NoAdmin` 모두 `SAW_OPENSEARCH_DURABILITY=request`를 사용합니다. 저장한 묶음의 기록을 확인한 뒤 완료로 처리하며, 저사양을 이유로 자동으로 async로 낮추지 않습니다. |
| 저장 거부·일시 장애 | 검색엔진이 받지 않은 이벤트는 "완료"로 세지 않음. 형식 문제로 거부된 건수는 작업 화면 **처리 범위 › 저장 거부**에 표시. 검색엔진이 잠시 바쁜 경우(429 등)는 작업이 실패로 멈추고 **다시 시도**를 누르면 멈춘 곳부터 이어서 처리 |
| 진행 표시 | 작업 화면에 **바이트 기준 진행률·남은 시간**. 색인이 끝나면 분석 중에도 조사 화면에서 검색 가능 |
| 중단 후 재개 | PC 재부팅·서비스 재시작 시 작업이 자동으로 다시 시작되고, **이미 색인한 이벤트는 다시 넣지 않음** |

참고 측정값 (NDR 메타 CSV 59MB, 10만 행 → 이벤트 6.5만 건, OpenSearch 힙 1GB, 개발 PC):

| 저장소 | 파싱+색인 | 분석 | 합계 | 저장 크기 |
|---|---|---|---|---|
| OpenSearch (운영 구성) | 약 20초 (초당 3,000건) | 12~19초 | **약 35~40초** | 약 20MB |
| SQLite (개발용) | 44초 | 51초 | 95초 | 197MB |

- 600MB 파일은 대략 **5~10분**, 저사양 PC(4코어·HDD)는 그 2배 정도를 예상합니다. 실제 PC에서 한 번 측정해 두세요.
  측정은 실제 조사 데이터와 분리된 임시 공간에서 하고 끝나면 지웁니다(관리자 PowerShell, `C:\SAW\app`에서):
  `C:\SAW\venv\Scripts\python.exe -m saw.devtools.bench_ingest D:\logs\qsearch_meta_result.csv`
  → 이벤트 수, 초당 처리 건수, 분석 시간, **이 PC에서 GB당 예상 시간**을 출력합니다.
- 디스크 예상: 이벤트 100만 건당 OpenSearch 약 0.3GB + **원본 파일 크기만큼**(원본은 증거로 보관).
- **백신 실시간 검사**가 `C:\SAW\data`의 대량 쓰기를 크게 늦출 수 있습니다. 조직 보안 정책이 허용하면 보안 담당자와 협의해 데이터 폴더 예외를 검토하세요(SAW가 자동으로 바꾸지 않습니다).
- 전원 옵션을 "고성능"으로 두고, 처리 중에는 절전 모드로 들어가지 않게 하세요.

---

## 2. 설치 묶음 만들기 (인터넷 PC에서)

> 이미 받은 설치 묶음(`offline-bundle` 폴더)이 있으면 3장으로 넘어가세요.

이 절은 매체 제작자용입니다. 설치 대상에서 실행하지 않습니다. 빌드 PC에서 UI를 미리 빌드하고, provenance.json으로 고정한 실제 의존성 파일과 검증된 정적 CPU 실행기를 준비한 뒤 조립합니다. 조립 스크립트 자체는 내려받기를 수행하지 않습니다.

```bash
powershell -ExecutionPolicy Bypass -File deploy\windows\build-bundle.ps1 -InputDir C:\build-inputs -NativeRuntime C:\llama-runtime -OutDir C:\SAW-media-new
```

다음이 지정한 새 `-OutDir` 폴더에 모입니다. 정확한 파일별 크기는 release-manifest.json에 기록됩니다.

| 폴더/파일 | 내용 | 무결성 확인 |
|---|---|---|
| `opensearch\` | OpenSearch 2.19.6 Windows, 한글 분석기(nori) | 공식 SHA-512 대조 |
| `postgresql\` | PostgreSQL 16.15 Windows 바이너리 | SHA-256 기록 |
| `python\` | Python 3.12.10 embeddable ZIP | 고정 SHA-256 대조 |
| `winsw\` | Windows 서비스 등록 도구 (MIT) | SHA-256 기록 |
| `wheels\` | SAW가 쓰는 Python wheel 62개 | SHA-256 기록 |
| `llm-runtime\` | 고정 llama.cpp CPU 실행기(모델 가중치는 별도) | runtime manifest·SHA-256 대조 |
| `app\` | SAW 프로그램 (웹 화면 빌드 포함) | SHA-256 기록 |
| `install.ps1` 등 | 설치·백업·제거 스크립트 | — |
| `sbom.cdx.json`, `THIRD-PARTY-NOTICES.md` | 구성 요소 목록(SBOM, CycloneDX 1.5)과 라이선스 고지 — 반입 심사용 | — |
| `SHA256SUMS.txt` | 파일과 manifest의 SHA-256 참고 목록 | 공개 값과 별도 대조 |
| `release-manifest.json` | 필수 파일·크기·SHA-256 계약 | 설치 시 전체 파일 자동 대조 |

빌드 결과의 **manifest_sha256(release-manifest.json의 SHA-256)을 반입 기록에 적어두세요.** ZIP의 공개 SHA-256도 함께 보관합니다.
폴더를 회사의 매체 반입 절차(악성코드 검사 등)에 따라 서버로 옮깁니다.

---

## 3. 서버에 설치하기

### 3.1 설치 실행

1. 설치 묶음을 서버에 복사합니다. 예: `D:\saw-bundle`
2. **PowerShell을 관리자 권한으로 실행**합니다.
3. 설치 묶음 폴더에서 실행합니다.

```bash
cd D:\saw-bundle
```

```bash
powershell -ExecutionPolicy Bypass -File .\install.ps1 -HostName saw.corp.local -ExtraNames 10.10.5.20 -AllowFrom 10.20.0.0/16
```

| 옵션 | 의미 | 예 |
|---|---|---|
| `-HostName` | 분석가가 브라우저에 입력할 서버 이름 | `saw.corp.local` |
| `-ExtraNames` | 추가 이름·IP (인증서에 포함) | `10.10.5.20` |
| `-AllowFrom` | 접속을 허용할 분석가 PC 대역 (방화벽) | `10.20.0.0/16` |
| `-OpenSearchHeapGB` | OpenSearch 메모리 (1장 표 참고) | 생략 시 메모리에 맞춰 자동 |
| `-LocalOnly` | 분석가 PC 단독 사용: 127.0.0.1에만 열고 방화벽 규칙 없음 | — |
| `-NoAdmin` | 관리자 권한 없는 PC: 서비스 없이 사용자 프로세스로 실행, `%LOCALAPPDATA%\SAW`에 설치 (`-LocalOnly` 포함) | — |
| `-AutoStartAtLogon` | `-NoAdmin`과 함께: 로그온 시 자동 시작 | — |
| `-CertFile`, `-KeyFile` | 회사에서 발급한 인증서(PEM)가 있을 때 | — |
| `-InstallRoot` | 설치 위치. 공백·`&`·한글 폴더 이름은 사용할 수 있음. `% " ' ; ^ ! # $` 와 백틱은 설정 파일의 뜻을 바꾸므로 설치가 거부됨 | `C:\SAW` (기본) |

설치 시간은 CPU·디스크에 따라 달라집니다. 다음을 자동으로 처리합니다.

1. 설치 묶음 **무결성 검사** (release-manifest.json의 전체 파일·크기·SHA-256 대조, 누락·추가·불일치 시 중단)
2. Python 설치 → 패키지 오프라인 설치
3. PostgreSQL 설치 (암호 자동 생성, 서버 내부 전용)
4. OpenSearch 설치 (불필요한 플러그인 제거, 한글 분석기 설치, 서버 내부 전용)
5. 설정 파일 생성, **HTTPS 인증서** 생성(회사 인증서가 없을 때)
6. **DB 스키마 마이그레이션**(`saw migrate`) 후 **최초 관리자 계정** 생성
7. Windows 서비스 3개 등록·시작, 방화벽 규칙 추가
8. 정상 동작 확인(health check)

마지막에 접속 주소와 최초 관리자 암호 파일 위치가 출력됩니다.

### 3.2 설치되는 것

| 위치 | 내용 | 접근 권한 |
|---|---|---|
| `C:\SAW\app` | SAW 프로그램, 설정(`.env`) | `.env`는 관리자·SYSTEM만 |
| `C:\SAW\data` | 증거 원본, DB, 검색 인덱스 | 관리자·SYSTEM(·DB 서비스 계정)만 |
| `C:\SAW\secrets` | DB 암호, 최초 관리자 암호 | 관리자·SYSTEM만 |
| `C:\SAW\tls` | HTTPS 인증서·개인키 | 관리자·SYSTEM만 |
| `C:\SAW\logs` | 서비스 로그 | 관리자·SYSTEM, `postgresql` 하위 폴더는 Network Service 수정 권한 추가 |
| `C:\SAW\backup` | 백업 | 관리자·SYSTEM만 |

Windows 서비스 (`services.msc`에서 확인):

| 서비스 | 역할 | 시작 |
|---|---|---|
| `saw-postgresql` | DB | 자동 |
| `saw-opensearch` | 로그 검색 | 자동(지연) |
| `saw` | SAW 웹·API | 자동(지연), 위 두 서비스에 의존 |

서비스가 비정상 종료되면 자동으로 재시작합니다.

---

## 4. 설치 후 할 일

### 4.1 최초 관리자 로그인

1. 서버에서 최초 암호 확인 (관리자 PowerShell):
   ```bash
   type C:\SAW\secrets\initial-admin.pw
   ```
2. 브라우저에서 `https://saw.corp.local/` 접속 → ID `admin`과 위 암호로 로그인
3. **QR 코드로 MFA 등록** (인증 앱)
4. 오른쪽 위 **비밀번호** 버튼으로 **암호를 바로 변경**
5. 서버에서 최초 암호 파일 삭제:
   ```bash
   del C:\SAW\secrets\initial-admin.pw
   ```

### 4.2 분석가 계정 만들기

admin으로 로그인 → **Admin** 메뉴 → 사용자 추가 (역할: analyst / senior_analyst / soc_manager / viewer).
초기 암호는 안전한 경로로 전달하고, 사용자는 첫 로그인 때 MFA 등록 후 **비밀번호** 버튼으로 바꿉니다.

> admin 계정은 관리 전용이라 사건 분석 화면이 보이지 않습니다. 분석은 분석가 계정으로 합니다.

### 4.3 인증서 신뢰 설정 (자체 서명 인증서를 쓴 경우)

회사 인증서(`-CertFile`)를 쓰지 않았다면 브라우저에 "안전하지 않음" 경고가 나옵니다.
`C:\SAW\tls\saw.crt` 파일(공개 인증서, 개인키 아님)을 분석가 PC의 **신뢰할 수 있는 루트 인증 기관**에 등록하세요.
여러 대라면 그룹 정책(GPO)으로 배포하는 것이 편합니다.

### 4.4 백업 예약 (권장)

매일 새벽 백업을 예약합니다 (관리자 PowerShell):

```bash
schtasks /Create /TN "SAW Backup" /SC DAILY /ST 02:30 /RU SYSTEM /RL HIGHEST /TR "powershell -NoProfile -ExecutionPolicy Bypass -File C:\SAW\app\deploy\windows\backup.ps1 -KeepDays 14"
```

백업 내용: PostgreSQL 덤프, OpenSearch 스냅샷, 증거 원본 복사본 → `C:\SAW\backup`.
**같은 디스크의 백업은 디스크 고장에 대비가 안 되므로** 주기적으로 별도 매체에 복사하세요.

---

## 5. PCAP 분석

- PCAP / PCAPNG 파일을 업로드하면 **SAW 내장 분석기**가 연결(conn)·DNS·HTTP·TLS(JA3/JA4)를 추출합니다. Zeek 설치가 필요 없습니다.
- 사건 작업대의 이벤트 상세 창에서 **⬇ 세션 PCAP** 버튼으로 해당 세션의 원본 패킷만 따로 받아 Wireshark로 열 수 있습니다 (다운로드는 감사 기록).
- 한계: 연결당 앞부분 64KB만 내용 분석(HTTP 헤더·TLS 핸드셰이크에는 충분), SMB·RDP 등은 연결 정보만 표시.

### IDS 경보를 추가하려면 (선택)

Suricata Windows 버전을 설치하면 IDS 시그니처 경보가 함께 표시됩니다.
- Suricata는 **Npcap**이 필요합니다. Npcap 무료판은 설치 대수 제한(5대)이 있으므로 라이선스를 확인하세요.
- 탐지 규칙(예: ET Open)은 인터넷 PC에서 받아 반입합니다.
- 설치 후 `C:\SAW\app\.env`에 추가하고 `saw` 서비스를 재시작:
  ```
  SAW_SURICATA_PATH=C:\Program Files\Suricata\suricata.exe
  SAW_SURICATA_RULES=C:\SAW\suricata\rules\suricata.rules
  ```

---

## 6. 운영

### 서비스 관리

```bash
powershell -Command "Get-Service saw*"
```

```bash
powershell -Command "Restart-Service saw"
```

### 상태 확인

```bash
curl.exe -sk https://localhost/api/v1/health
```

정상: `{"status":"ok","event_store":"opensearch",...}`

### 로그 위치

| 로그 | 위치 |
|---|---|
| SAW | `C:\SAW\logs\saw\` |
| OpenSearch | `C:\SAW\logs\opensearch\` |
| PostgreSQL | `C:\SAW\logs\postgresql\` |

### 사용자 문제 해결 (서버에서, 관리자 PowerShell)

| 상황 | 명령 |
|---|---|
| MFA 앱 분실 | 웹 Admin 화면 **MFA 재설정**, 또는 아래 명령 |
| 암호 분실 | 웹 Admin 화면 **임시 비밀번호**, 또는 아래 명령 |

```bash
cd C:\SAW\app
```

```bash
C:\SAW\venv\Scripts\python.exe -m saw.cli reset-mfa 사용자ID
```

```bash
C:\SAW\venv\Scripts\python.exe -m saw.cli set-password 사용자ID
```

### 업그레이드

현재 `install.ps1`은 신규 설치 전용이며 기존 설치를 발견하면 중단합니다. 같은 경로에 다시 실행하여 업그레이드하지 마세요.
동일한 고정 런타임 조합의 중지한 설치는 새 매체의 `update.ps1`으로 사전 검사·전체 복구본 생성·앱 교체·명시적 시점 복구를 수행합니다. [업데이트·복구 안내](OFFLINE-UPDATE-GUIDE.md)를 따르세요. 실행 중 자동 업데이트나 런타임/DB 제품 버전 변경은 지원하지 않습니다. 실제 서비스 운영 전환은 별도 인수가 필요합니다.
변경 전에는 `backup.ps1`으로 백업하고 별도 위치의 복원 가능성을 확인하세요. 데이터로 된 룰·파서 변경은 [오프라인 콘텐츠 안내](OFFLINE-CONTENT-GUIDE.md)의 검증·시험·승인·적용 절차를 사용합니다.

### 제거

```bash
powershell -ExecutionPolicy Bypass -File C:\SAW\app\deploy\windows\uninstall.ps1
```

서비스와 방화벽 규칙만 제거하고 데이터는 남깁니다. 데이터까지 지우려면 `-RemoveData`를 붙입니다(확인 입력 필요).

---

## 7. 문제 해결

| 증상 | 원인·조치 |
|---|---|
| 설치 중 `checksum mismatch` | 반입 중 파일 손상. 묶음을 다시 복사하세요. |
| `saw` 서비스가 계속 재시작 | `C:\SAW\logs\saw\` 확인. OpenSearch가 2분 안에 안 뜨면 실패합니다 → `saw-opensearch` 서비스와 `C:\SAW\logs\opensearch` 확인 |
| OpenSearch가 바로 종료 | 로그에서 메모리 부족 여부 확인 → 전체 중지 후 관리자가 `opensearch-2.19.6\config\jvm.options.d\saw-heap.options`의 `-Xms`·`-Xmx`를 같은 값(예: `1g`)으로 조정하고 기존 시작 절차로 재시작. 기존 설치에 install.ps1 재실행 금지 |
| 디스크 부족 경고 후 검색 불가 | 디스크 사용률 95% 초과 시 OpenSearch가 쓰기를 막습니다. 공간 확보 후 `saw-opensearch` 재시작 |
| 브라우저 "안전하지 않음" | 4.3절 인증서 신뢰 설정 |
| 분석가 PC에서 접속 불가 | `-AllowFrom` 대역 확인, 서버에서 `curl.exe -sk https://localhost/api/v1/health` 확인 |

### 알아둘 제약

- Windows 10은 클라이언트 OS라 **동시 접속 기기 수 라이선스 제한**(통상 20대)이 있습니다. 사용자가 많으면 Windows Server 사용을 검토하세요.
- Windows 10 LTSC 2019 보안 지원은 **2029년 1월**에 끝납니다. 그 전에 OS 이전 계획이 필요합니다.
- 백신 실시간 검사가 `C:\SAW\data` 를 검사하면 성능이 크게 떨어질 수 있습니다. 보안 담당자와 협의해 예외 등록을 검토하세요.
