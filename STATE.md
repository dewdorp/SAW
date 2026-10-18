# SAW 현재 상태 — 2026-10-18

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
