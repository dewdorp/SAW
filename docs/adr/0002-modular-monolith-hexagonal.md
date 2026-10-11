# ADR-0002: 모듈러 모놀리스 + Hexagonal 아키텍처

- 상태: Accepted (Phase 0)
- 날짜: 2026-10-05

## Context
팀 규모 4–5명, 온프레미스 운영. 마이크로서비스는 운영·배포 부담 대비 이점이 적다. 반면 Analyzer를 API(동기 소형)와 Worker(비동기 대량)가 공유해야 한다.

## Decision
- 단일 Python 코드베이스, 프로세스 2종(api, worker).
- `analyzers/ parsers/ detectors/` 는 IO 없는 순수 라이브러리.
- 외부 시스템·OSS·저장소는 Port/Adapter.
- import-linter로 경계 강제, Controller/Task에 비즈니스 로직 금지.

## Consequences
+ 테스트 용이, 재사용, 단순 배포
- 경계가 코드 규율에 의존 → CI 강제 필요
