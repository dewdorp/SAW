# ADR-0011: Payload Decode: 자체 결정적 체인 + CyberChef 정적 Deep-link

- 상태: Accepted (Phase 0)
- 날짜: 2026-10-05

## Context
자동 Decode Chain 탐색·감사·테스트가 필요하고, 핵심 경로가 외부 서비스(CyberChef Server, 유지보수 저조)에 의존하면 안 된다.

## Decision
- 핵심 Transform(URL/Base64/Hex/Unicode/HTML/JWT/gzip/deflate/PS Encoded)은 Python 자체 구현, 출력 크기 상한.
- CyberChef 정적 빌드를 내부 호스팅, 동일 Recipe로 'Open in CyberChef' (URL fragment).
- CyberChef Server는 사용하지 않음.

## Consequences
+ 결정성·보안·성능
- 희귀 변환은 CyberChef 수동 사용
