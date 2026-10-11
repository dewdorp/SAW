# ADR-0004: PCAP MVP는 Zeek + Suricata + tshark → OpenSearch (Option A)

- 상태: Accepted (Phase 0)
- 날짜: 2026-10-05

## Context
Packet Parser 직접 구현 금지. Malcolm(전체 채택)은 무겁고 UX·스키마 통제권을 잃는다. Arkime는 Deep-dive에 우수하나 운영 부담이 크다.

## Decision
- MVP: Option A (Zeek+Suricata+tshark, SAW 정규화, SAW 인덱스).
- Phase 6b: Raw Packet 수요 확인 시 Arkime를 Deep-dive 전용으로 추가(Option C), Community ID로 연결.
- Malcolm은 설정·매핑 레퍼런스.

## Consequences
+ 낮은 운영 부담, Story-first UX 통제
- 패킷 수준 Deep-dive는 MVP에서 tshark 세션 추출 다운로드로 제한
비교표: [20 §1](../20-pcap-analysis-design.md)
