# ADR-0012: SIEM Connector는 추상화 + Mock 우선

- 상태: Accepted (Phase 0)
- 날짜: 2026-10-05

## Context
Logpresso 실제 API 문서가 없는 상태에서 임의 API 구현은 금지. Internal Context는 Connector가 있어야 완성된다.

## Decision
- `SecurityDataConnector`: search(), get_event(), get_events(), aggregate(), get_context(), health_check().
- 입력은 SAW Query Model, 출력은 CES 이벤트/집계.
- MockLogpressoConnector(Fixture 기반)로 UI·로직 개발.
- 실제 구현은 공식 문서·테스트 계정 확보 후. Read-only 계정 요구.
- 향후: Cloudflare, NDR, EDR, ASM, Firewall.

## Consequences
+ 잘못된 가정 방지
- 실데이터 연동 검증은 Phase 10 이후
