# 모델 제외 폐쇄망 설치 매체 — 2026-10-17

최신 웹 행위 분석·통계·조사 안내·Golden·오프라인 룰/파서 관리가 포함되는 파일럿 매체입니다. 모델 가중치는 별도 반입합니다. 대상은 Windows10 Enterprise LTSC2019 x64 build17763이며, 개발 Windows11의 실행 시험과 대상 OS 인수는 구분합니다.

## 포함 구성과 확인
Python3.12.10 embeddable, 고정 wheel62개, PostgreSQL16.15-1, OpenSearch/nori2.19.6, 번들 JDK21.0.11+10, WinSW2.12.0, llama.cpp b11429 정적 CPU 실행기, 빌드된 UI, 내장 결정적 PCAP 분석기, 탐지YAML, ATT&CK 자료, 라이선스·SBOM·공식 소스 제공물을 포함합니다. 대상에서 Python/Node/Git/Docker를 미리 설치하거나 npm build를 실행할 필요가 없습니다. 설치 중 인터넷 다운로드는 없습니다.

전체 파일의 크기·SHA256과 소스 commit은 release-manifest.json, 실행 파일 출처는 provenance.json에 있습니다. ZIP과 manifest의 공개 SHA256을 별도로 보관하고 대조하세요. 해시는 배포자를 인증하는 전자서명을 대신하지 않습니다.

모델 가중치·학습 데이터·운영 DB·계정/비밀값·브라우저 설치 파일은 포함하지 않습니다. Zeek/Suricata 설치 완료를 주장하지 않으며 내장 PCAP 분석의 지원 범위를 따릅니다. 현대 Chrome/Edge는 조직에서 별도로 준비합니다.

## 신규 설치
1. ZIP과 checksum/manifest를 함께 반입하고 조직의 매체 검사를 받습니다.
2. 새 폴더에 풀고 SHA256을 비교한 뒤 전체 매체를 검사합니다.

```powershell
Get-FileHash .\SAW-0.1.0-pilot.20261017-model-free-win-x64.zip -Algorithm SHA256
Expand-Archive -LiteralPath .\SAW-0.1.0-pilot.20261017-model-free-win-x64.zip -DestinationPath .\SAW-media-20261017
Set-Location .\SAW-media-20261017
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\verify-bundle.ps1 -BundleDir .
```

ZIP·별도 checksum·반입 기록은 압축을 푼 매체 폴더 밖에 보관합니다. 매체 안에 임의 파일을 추가하면 전체 파일 검사에서 거부됩니다.

3. 먼저 로컬 파일럿을 빈 경로에 설치합니다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -NoAdmin -InstallRoot C:\SAW-Pilot -Port 8443 -OpenSearchHeapGB 1
```

4. https://localhost:8443/ 로 접속합니다. 인증서 tls/saw.crt는 조직 절차대로 신뢰합니다. 초기 admin 비밀번호는 설치 폴더의 보호된 secrets/initial-admin.pw에만 생성됩니다. MFA 등록·비밀번호 변경 후 별도 분석가 계정을 만듭니다.
5. app/docs/examples/behavior/case-A.csv 등 합성 자료로 새 조사→업로드→분석→행위 분석→구간 선택→원문→후속확인→보고서를 확인합니다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SAW-Pilot\saw-ctl.ps1 status
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SAW-Pilot\saw-ctl.ps1 stop
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SAW-Pilot\saw-ctl.ps1 start
```

-NoAdmin은 localhost 검증용입니다. 여러 분석가 공동 접속은 조직 DNS/TLS·접속 대역·서비스 계정과 승인된 관리자 설치가 필요합니다. 해당 서버 설치 예시는 매체 INSTALL-WINDOWS.md를 따르며, 이 배포의 사용자 모드 시험을 서비스 인수로 간주하지 않습니다.

## 기존 설치 업데이트
기존 경로에 install.ps1을 다시 실행하지 않습니다. 매체 app/docs/OFFLINE-UPDATE-GUIDE.md를 따라 작업 저장·전체 중지→사전 점검→보호된 복구본→앱 교체→재시작/검증 순서로 진행합니다. DB0014로 바뀐 뒤 예전 프로그램 파일만 덮어쓰면 안 됩니다.

## 화면·룰·파서 실습
아래 문서는 매체 app/docs에 실제 그림·합성 예제와 함께 들어 있습니다.

- BEHAVIOR-ANALYSIS-GUIDE.md: 행위 지표, 원문 근거, 추가 확인, 보고서·Golden.
- STATISTICS-TEMPORAL-GUIDE.md: 출발지/목적지별 통계와 시간 변화 후보.
- OFFLINE-CONTENT-GUIDE.md: 외부에서 룰·파서 작성→반입→예제 시험→다른 사람 승인→적용→되돌리기.
- DETECTION-RULES-HOWTO.md: 기본 탐지와 사용자 Sigma 등록·승인·Export.
- ADMIN-RULES-ANALYTICS-GUIDE.md: 관리자 데이터 정리, 탐지 Export, 로그 통계.
- ASSISTANT-EVIDENCE-GUIDE.md: 선택 근거 설명과 추가 확인. 모델이 없으면 기본 안내 사용.
- MODEL-8B-KOREAN-SECURITY-GUIDE.md, LOCAL-MODEL-GUIDE.md: 별도 모델 후보·다운로드·무결성·반입·등록 범위.
- USER-MANUAL.md: 전체 사용 설명서.

## 검증 범위
이번 매체의 실제 실행 결과는 OFFLINE-RELEASE-VALIDATION-2026-10-17.md와 공개 receipt를 확인합니다. 생성된 파일만으로 실행 성공을 판정하지 않습니다. 깨끗한 LTSC17763, 물리적 인터넷 차단,16GB 무GPU 다중 분석가 부하, 관리자 서비스/방화벽/조직 TLS, 운영 자료 반입·배포 승인은 별도 게이트입니다. 모델 한국어·보안 품질과 SFT는 매체 설치 성공과 별개입니다.
