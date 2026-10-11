# 탐지 단계 후속 실제 검증 — 2026-10-12

대상은 새 복사본 `F:\codex\SAW-Claude-main`입니다. 원본·운영 데이터와 분리한 합성 환경에서 실행했습니다. 이후 AI 모델·패키징 변경 검증으로 이 결과를 재사용하지 않습니다.

## 실행 결과

| 검증 | 실제 결과 | 범위 |
|---|---|---|
| 초기 native 전체 | 577 통과, 0 실패, 0 건너뜀, 588.27초 | 시작 revision 8a1342a, PostgreSQL 16.15/OpenSearch 2.19.6/Java 21.0.11 |
| 순서 수정 native 영향 시험 | 13 통과, 16.09초 | tests/unit/test_sequence_order.py + tests/api/test_phase12_anomaly.py |
| 수정 후 전체 SQLite | 587 통과, 1 건너뜀, exit 0 | 환경 갱신으로 중단된 최초 실행은 성공으로 세지 않고 별도 재실행 |
| UI | 21파일 93시험 통과 | 최종 전체 vitest, tsc와 build exit 0 |
| 실제 브라우저 | 로그인/MFA, 규칙 검색·상세·끄기·켜기·재조회, NDR·흐름 조회, 합성 작업대, 시간대 전환·로그아웃 | HTTP API와 실제 빌드 UI. [6장 사용 안내](DETECTION-LIVE-WALKTHROUGH.md) |

native는 Windows 11 Pro x64 10.0.26200/build26200 개발 호스트입니다. PostgreSQL15432/OpenSearch19200의 새 루프백 인스턴스·새 DB·새 인덱스만 사용했습니다. pytest에 운영 저장소를 연결하지 않았습니다. DB 자격증명은 시험 영역의 제한 ACL 아래 보관하며 문서에 포함하지 않습니다.

전체 SQLite의 건너뜀은 PostgreSQL 주소가 필요한 마이그레이션 시험입니다. 이 시험은 앞의 native 전체에서 실행됐습니다. pytest 출력의 성공/건너뜀 표식과 종료코드로 집계했고, 중단 로그와 재실행 로그를 구분해 보존합니다. 기존 Starlette 경고와 UI chunk 크기 경고는 남아 있습니다.

## 실제 발견하고 수정한 두 문제

- **시각 표시:** SQLite가 반환한 시간대 없는 UTC 시각을 브라우저가 현지 시각으로 해석해 작업대 기간에 9시간 오차가 있었습니다. UTC 계약을 적용하고, KST/UTC 전환이 작업대와 개요에 즉시 전달되도록 구독을 연결했습니다. 실제 화면 양방향 전환과 컨텍스트 숨김 상태 보존을 확인했습니다. 커밋 `0a21bed`.
- **탐지 순서:** 동일 합성 로그를 올렸는데 같은 시각 기록의 임의 이벤트 ID 정렬 때문에 SequenceAnomaly가 1건/0건으로 달랐습니다. 같은 원문의 고유 offset/line_no로 기록 순서를 결정하고, 순서가 불명확한 세션은 범위 안내로 남기도록 수정했습니다. 동일 592건 합성 DB 두 개를 읽기 전용으로 재평가해 0건/0건·점수·checks 일치를 확인했습니다. 기록 순서는 인과관계의 증명이 아닙니다. 커밋 `5dc5483`.

브라우저용 저장 결과는 592이벤트·26탐지(시그니처11·흐름3)입니다. 이 저장 결과는 backend 수정 전 생성됐으므로 새 backend 전체 HTTP 생성 검증으로 재사용하지 않습니다. 수정된 backend는 native/SQLite 회귀 및 동일 합성 DB 재평가로 검증했습니다. UI는 최종 빌드로 재확인했습니다.

## 재현 기록과 한계

로컬 로그는 기존 작업공간 `.runtime/claude-main-continuation/`의 `final-sqlite-20261012-rerun.log`, `timezone-toggle-full-vitest.log`, `timezone-toggle-build.log`, 새 복사본 `.qa/infra/isolated-20261011-235727/logs/pytest.log` 및 `pytest-delta.log`에 보관합니다. `.qa`는 Git·배포물에서 제외합니다.

깨끗한 LTSC 2019 빌드17763, 인터넷 없는 신규 설치, TLS·서비스·백업/복원, 16GB에서 OpenSearch+AI 공동 부하, 운영 데이터·운영 모델 채택은 이 검증에 포함되지 않았습니다. Foundation 실제 실행과 한국어 품질도 별도 확인해야 합니다.
