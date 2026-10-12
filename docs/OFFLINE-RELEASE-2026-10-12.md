# 모델을 제외한 폐쇄망 설치 매체 (2026-10-12)

이 배포물은 Windows 10 Enterprise LTSC 2019 x64(build 17763)를 위한 **개발 파일럿 사전 배포본**입니다. 깨끗한 LTSC PC의 운영 인수를 승인한 배포본은 아닙니다. 원본 Claude 작업 폴더와 운영 자료는 포함하지 않습니다.

## 들어 있는 파일

- Python 3.12.10 x64 embeddable 배포 ZIP과 고정 wheel 62개. 대상 PC의 Python 설치나 pip 캐시를 사용하지 않습니다.
- PostgreSQL 16.15-1 공식 바이너리 ZIP.
- OpenSearch 2.19.6, analysis-nori 2.19.6, 번들 Eclipse Temurin JDK 21.0.11+10.
- 빌드된 웹 화면, SAW 실행 소스, 탐지 YAML, 공개 ATT&CK 카탈로그, 명시적으로 표시한 가상 enrichment fixture.
- 내장 PCAP 분석기. Zeek/Suricata 설치를 완료했다는 의미는 아닙니다.
- llama.cpp b11429 / d81235049384534c167caea52b85a694f6103d14 정적 CPU 실행기와 라이선스. 모델 가중치는 없습니다.
- WinSW 2.12.0, 구성요소 고지, Python·UI 라이선스, 해당 Python 배포물과 elkjs/JDK 소스 제공물.

`release-manifest.json`은 전체 파일의 경로·크기·SHA-256을 기록합니다. `SHA256SUMS.txt`의 목록과 공개한 manifest 지문을 함께 보관하세요. 각 파일의 실제 버전·해시는 manifest와 `provenance.json`에 있습니다. 모델·운영 데이터·설치 후 생성되는 계정·비밀값·개발 DB는 제외합니다.

## 반입과 최초 실행

1. GitHub 사전 배포의 ZIP과 checksum/manifest를 함께 내려받습니다. 조직의 매체 검사 절차를 거쳐 폐쇄망에 반입합니다.
2. ZIP을 새 폴더에 풉니다. 배포 페이지에 게시된 ZIP SHA-256과 비교합니다. 프로그램 실행 전에 PowerShell에서 아래 매체 검증을 수행합니다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\verify-bundle.ps1 -BundleDir .
```

3. 이번에 실제 점검한 사용자 프로세스 설치는 아래 형태입니다. 기존 경로를 덮어쓰지 말고 빈 경로를 선택합니다. Python/Node/Git/Docker/DB 사전 설치가 필요 없습니다. 설치 중 내려받거나 소스를 컴파일하지 않습니다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -NoAdmin -InstallRoot C:\SAW-Pilot -Port 8443 -OpenSearchHeapGB 1
```

4. `https://localhost:8443/`로 들어갑니다. 설치 시 생성된 `tls\saw.crt` 인증서를 조직 절차대로 신뢰 설정합니다. 초기 계정은 `admin`이며, 초기 비밀번호는 설치 폴더의 보호된 `secrets\initial-admin.pw` 파일에만 생성됩니다. 화면에서 MFA를 등록하고 비밀번호를 변경합니다. 비밀번호·MFA 값을 GitHub나 문의 글에 붙이지 마세요.
5. 관리자가 분석가 계정을 생성하고 역할을 부여합니다. 분석가 계정으로 로그인하여 새 조사를 만들고 가상 로그 또는 PCAP을 업로드합니다. 처리 완료 후 Story → Evidence → Raw를 확인하고 노트로 분석 결과를 저장합니다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SAW-Pilot\saw-ctl.ps1 status
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SAW-Pilot\saw-ctl.ps1 stop
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SAW-Pilot\saw-ctl.ps1 start
```

`-NoAdmin`은 로컬 점검용이므로 다른 PC에 포트를 열지 않습니다. 여러 분석가가 공동 접속하는 운영 서버 구성은 사내 DNS/TLS·접근 대역·방화벽·서비스 계정 및 서비스 설치 승인이 필요합니다. 이 승인을 실제로 실행한 것으로 보고하지 않습니다.

## 화면을 보며 따라 하기

설치 매체의 `app/docs/USER-MANUAL.md`는 전체 사용 설명서입니다. `app/docs/DETECTION-LIVE-WALKTHROUGH.md`는 실제 화면 6장으로 탐지 목록, 규칙 설명, 변경 사유, NDR 기준, 공격 흐름, 분석 작업대를 설명합니다. 가상 자료 실습은 `app/docs/DEMO-GUIDE.md`를 여세요. 같은 폴더의 `assets` 안에 화면 파일이 함께 들어 있습니다.

## 별도 모델 반입

저장소의 [모델 반입·교체 안내](LOCAL-MODEL-GUIDE.md)를 따릅니다. 설치 매체에서는 `app/docs/LOCAL-MODEL-GUIDE.md` 파일을 여세요. 본체와 모델 매체는 분리됩니다. 모델이 없으면 결정적 로그·PCAP 분석과 기본 설명은 계속 동작합니다. 지원 범위는 검증된 Llama 3 계열 GGUF와 정해진 BASE/Instruct 형식이며 임의의 모델 저장소 코드를 실행하지 않습니다.

모델 관리의 파일 검증, 실제 생성, 한국어/관제 품질 채택은 서로 다른 상태입니다. 이번 CPU 경로는 승인된 합성 조사에만 연결되며 일반 운영 조사에는 자동으로 적용하지 않습니다. 모델 선택이 학습·운영 승인·자동 조치를 뜻하지 않습니다.

## 검증과 남은 범위

- 개발 PC의 실제 매체 설치·PostgreSQL/OpenSearch/TLS 기동·첫 관리자 생성은 실행했습니다. 세부 검증 결과는 배포 보고서와 별도로 기록합니다.
- 깨끗한 LTSC 2019 PC, 인터넷이 물리적으로 차단된 장비, 다중 분석가 운영 서비스 설치·복원은 아직 별도 검증 대상입니다.
- PostgreSQL의 C 런타임은 시스템 DLL을 수집하지 않고, 공식 OpenSearch 배포 ZIP의 JDK에 포함된 파일을 자식 프로세스 PATH에서 그대로 사용합니다. 공식 배포물과 고지를 보존하며 별도 권리 승인을 대신하지 않습니다. 개발 PC에는 시스템 C 런타임도 있으므로 개발기 실행만으로 깨끗한 LTSC의 DLL 로딩을 검증했다고 할 수 없습니다.
- PostgreSQL 서비스의 번들 런타임 경로 구성은 사용자 승인을 받아 코드·구성 파일에 보완했습니다. 관리자 서비스 등록·실행과 방화벽 변경은 수행하지 않았으며 사용자 프로세스 검증을 서비스 인수로 세지 않습니다.
- 신규 설치 전용입니다. 기존 설치에 대한 업그레이드·데이터 이관은 별도 검토 절차가 필요합니다.
