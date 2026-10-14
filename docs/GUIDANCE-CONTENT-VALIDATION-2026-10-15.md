# 조사 안내·Golden·오프라인 콘텐츠 검증 — 2026-10-15

수정 대상은 `F:/codex/SAW-Claude-main`이다. 원본 `F:/claude/saw`와 은행 운영 자료는 수정하거나 시험에 사용하지 않았다. 기존 조사·Evidence·Check·Experience·권한·감사·Sigma 평가기·선언형 ParserSpec을 재사용했다.

## 구현과 데이터 변경

- 기존 조사 안에서 IP의 출발지/목적지/양방향, 탐지, 필터와 시간을 고정해 A–G 안내를 제공한다. 조회 실패·권한 없음·미수집을 0건으로 바꾸지 않는다. 실제 선택 근거와 답변은 기존 Check에 보존하고 종결·Experience 초안으로 이어진다.
- Golden은 Experience 승인과 별도 선택이다. 당시 입력·근거 해시·처리 출처와 평가자 정답을 나누고 작성자/기여자의 자기 채택, 다른 사건 용도 혼합, 승인·근거 상태가 달라진 내보내기를 거부한다. 모델 학습·자동 평가 실행기는 추가하지 않았다.
- 콘텐츠 JSON은 작성 → 무결성/호환성 검사 → 초안 반입 → 양성/정상 예제 → 다른 사람 승인·적용 → 변경 영향 확인 → 독립 되돌리기 흐름이다. 동시 변경·수동 편집·시험 시간 초과를 차단한다. SHA-256은 출처 서명이 아니다.
- 스키마 `0013`에 `kn_golden_family`, `kn_golden_family_member`, `kn_golden_blob`, `kn_golden_version`, `cp_package`, `cp_binding`, `cp_validation`을 추가한다. 기존 테이블이 있으면 보존하며 반복 마이그레이션을 시험했다. 실제 테이블 이름은 마이그레이션과 모델을 기준으로 한다.
- 다음 새 설치 매체 조립에 `guidance_rules.yaml`, 사용 안내와 합성 예제가 누락되지 않도록 명시적 포함 목록을 보완했다. 기존 배포 ZIP은 갱신하지 않았다.

주요 구현: `saw/core/application/guidance.py`, `guidance_rules.yaml`, `saw/knowledge/golden.py`, `golden_models.py`, `saw/content_packages/`, `saw/devtools/content_package.py`, API 라우터, `apps/web/src/pages/ContentPackages.tsx`, `Golden.tsx`, `pages/inv/GuidancePanel.tsx`, `components/Checks.tsx`, `pages/inv/CloseDialog.tsx`.

## 새로 실행한 자동 시험

| 실행 | 최종 결과 |
|---|---|
| 서버 전체 `pytest tests -q -p no:cacheprovider -o addopts=` | **913통과·2건너뜀**, 274.99초, exit 0 |
| 화면 `vitest run --maxWorkers=2 --minWorkers=2` | **162통과·30파일**, 49.77초, exit 0 |
| `tsc --noEmit`, `build` | exit 0, Vite build 24.08초 |
| 마지막 설치 매체 포함 목록 변경 후 `test_release_manifest.py` | 21통과, 3.34초 |
| 변경 Python의 Ruff E9/F, Git 공백 검사 | 통과 |

마지막 설치 매체 변경은 데이터 파일 포함 목록이며 해당 시험을 변경 뒤 다시 실행했다. 서버 전체 시험의 건너뛴 2건을 통과 건수로 세지 않는다.

화면 시험은 컴포넌트 자동 시험이다. 실제 브라우저 조작 성공과 구분한다. 기존 큰 JS chunk 경고와 React Router 미래 옵션 경고는 남아 있다. 과거 History 503와 일시적 Node 종료 문제도 후속 통과만으로 원인 해결 처리하지 않았다.

## 실제 저장소 시험

개발 Windows 11 Pro x64 **build 26200**에서 격리한 PostgreSQL **16.15**와 OpenSearch **2.19.6**을 기동했다. 운영 인스턴스가 아닌 무작위 포트·새 데이터 폴더·합성 데이터로 실행했으며 프로세스 ID·데이터 경로를 확인했다.

- 마이그레이션·Guidance·Golden·콘텐츠 API: **59통과, 614.64초, exit 0**.
- 최종 보완 4건(Experience 당시 종결 보존, 빈 후속확인 2조건, 되돌리기 capability): **4통과, 39.02초, exit 0**. 이 실행도 flush 실패 shard 0 및 두 저장소/세 포트 종료를 확인했다.
- 첫 실행 후 OpenSearch flush 실패 shard 0, 두 저장소 종료와 세 포트 닫힘을 확인했다.

개발기 저장소 검증이며 깨끗한 LTSC 2019, 조직 TLS/RLS/백업 복원 전체 인수로 확대하지 않는다.

## 실제 HTTP 사용자 흐름

별도 앱 `127.0.0.1:57285`에서 인증·MFA·CSRF를 거쳐 실제 HTTP 요청을 실행했다. 합성 전용 SQLite와 로컬 객체 저장소를 사용했다. TestClient의 응답을 실제 네트워크 실행으로 세지 않았다.

| 단계 | 처리 로그 | 파서 버전 | Sigma 일치 | Sigma 버전 |
|---|---:|---:|---:|---:|
| r1 적용 | 3 | 1 | 1 | 1 |
| r2 적용 | 3 | 2 | 2 | 2 |
| r2 새 상태 코드 로그 | 2 | 2 | 1 | 2 |
| 별도 복원 검토자로 r2 되돌림 | 3 | 1 | 1 | 3 |

작성자의 자기 적용과 자기 Golden 승인 요청은 403으로 거부됐다. 최초 작성자가 이전 Sigma 복원을 승인할 수 없는 POST 제약은 유지했고, 이 제약과 화면 capability가 달랐던 문제를 재현·수정했다. 작성자와 적용자 양쪽에 해당하지 않는 제3 검토자가 복원했다.

사례 A에서 만든 Experience를 다른 검토자가 승인하며 Golden `dev`로 채택했다. agent ZIP/JSONL, evaluator JSONL/CSV를 별도로 받아 agent 입력에 종결 정답 문구와 정답 파일이 포함되지 않는지 확인했다. 입력과 정답의 자동 시험도 별도로 수행했다.

앱 프로세스를 종료하고 최신 코드/빌드로 재시작한 후 실제 HTTP로 Check 3건, r2 되돌림 이력, parser v1로 처리한 3건, Golden 채택 상태와 agent 내보내기(11,478 bytes)가 유지됨을 확인했다. 이는 SQLite 앱 재시작 검증이며 운영 PostgreSQL 장애 복원 시험은 아니다.

## 실제 브라우저와 남은 화면 검증

실제 브라우저에서 사례 A의 WAF 120건/118차단/2허용, 같은 조사에서 IP 범위 선택, 허용 원문 2건 선택, 원문 120번째 줄, 후속확인 저장, 종결 초안의 기존 Check 재사용, Experience 검토 요청까지 확인했다. 종결창 실제 캡처는 [사용 안내](GUIDANCE-GOLDEN-GUIDE.md)에 있다. 현재 최종 문구 정리 이전 캡처임을 표시했다.

이후 브라우저 도구가 제공되지 않았고 대체 제공된 Node 실행 도구도 초기화와 단순 실행에서 반복 시간 초과했다. **콘텐츠 화면의 파일 불러오기·승인·되돌리기 및 Golden 채택·내보내기 최종 브라우저 검증과 새 단계별 스크린샷은 미완료**이다. 실제 API 실행이나 자동 UI 시험으로 이 공백을 완료 처리하지 않는다.

[실제 HTTP 합성 검증 요약 JSON](verification/guidance-content-http-2026-10-15.json)을 함께 보존한다. 계정·자격증명·운영 원문은 포함하지 않았다.

## 사용 안내와 남은 게이트

- [외부 작성·반입·적용·되돌리기 실습](OFFLINE-CONTENT-GUIDE.md): r1/r2 JSON, 정상 포함 합성 로그, SHA 목록, 정확한 버튼명과 403/409 처리.
- [기존 조사 → 확인 기록 → 종결 → 경험 → Golden 실습](GUIDANCE-GOLDEN-GUIDE.md).
- 다음: 브라우저 실행 도구 복구 후 합성 전용 계정으로 마지막 화면 흐름을 재실행하고 캡처한다. 기존 사용자 계정이나 운영 데이터로 대신 검증하지 않는다.
- 기존 2026-10-12 설치 매체는 스키마 0013/새 화면을 포함하지 않는다. 새 매체 제작·설치 전환과 깨끗한 LTSC17763·16GB 무GPU 공동 부하 시험이 남는다. 기존 `install.ps1`은 신규 설치용이며 덮어쓰기 업그레이드가 아니다.
- Foundation BASE 지정 모델 유지, 새 모델·SFT·optimizer·adapter·한국어 품질 채택 없음. 운영 데이터 반입/학습·관리자 서비스 설치·운영 배포/모델 교체 승인도 별도다.
