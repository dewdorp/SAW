# ADR-0017: Codex 구현 비교 후 채택한 항목과 PCAP 포렌식 확장

- 상태: Accepted
- 날짜: 2026-10-08

## Context
같은 요구로 만들어진 Codex 구현(`F:\codex\SOC Analyst & Threat Hunting Platform`)과 비교했다(코드·Codex 자체 검증 기록 기준, Codex 앱은 실행하지 않음).
SAW가 앞선 영역: Windows 내장 PCAP 분석, OpenSearch 검색·집계 실검증, MFA, 감사 해시 체인, CSP, 서버형 설치.
Codex가 앞선 영역: 스키마 마이그레이션, 공식 ATT&CK 전체 카탈로그, SBOM·라이선스 고지, 작업 멱등성/임대, 근거 유형(claim) 모델, 테스트 밀도, 화면 완성도.
사용자 요청: 좋은 점만 채택, UI/UX 개선, PCAP 분석은 pcap-forensics-analyzer(GitHub, C#)를 참고.

## Decision
채택 (SAW 구조에 맞게 재구현, 코드 복사 없음):
1. **Alembic 마이그레이션** — `saw/storage/migrations`, `saw migrate`, 운영 `SAW_SCHEMA_MODE=migrate`. 기존 create_all DB는 기준선에 stamp.
2. **ATT&CK Enterprise 19.2 공식 카탈로그** — 54MB STIX는 반입하지 않고 해시 고정한 원본에서 compact JSON(697 기법) 생성, 라이선스 동봉.
3. **SBOM(CycloneDX 1.5)·THIRD-PARTY-NOTICES** — 설치 묶음에 포함.
4. **Idempotency-Key + 작업 임대 epoch** — 중복 클릭·재시도·재시작 시 작업 중복/경합 방지.
5. **근거 유형** — 관측(OBSERVED)·계산(DERIVED)·추론(INFERRED)·판정(VERDICT)을 API와 화면 배지로 표시.
6. **UI/UX** — 사이드바·한글 메뉴·페이지 머리말·숫자 타일·배지·로그인 분할 화면 등 Codex 화면 장점.

채택하지 않음: Foundation-Sec-8B 학습 파이프라인(GPU·16GB 모델 필요), Docker/Redis/Celery/S3(운영 OS 제약), 포터블 단독 실행 방식(다중 사용자 서버 아님).

PCAP 포렌식 확장 — pcap-forensics-analyzer의 **탐지 범위를 참고**해 SAW 방식으로 구현.
그 저장소는 **라이선스가 명시되지 않아** 소스 코드를 복사·번역하지 않았다. 참고한 것은 기능 목록과 일반적 임계값 아이디어뿐이다.
구현 범위:
- TCP 재조립, HTTP 본문·압축, 파일 추출(해시·엔트로피·위장)
- 평문 인증(비밀번호 미저장), FTP 데이터 채널, ARP, 중복 프레임 제거
- 탐지기 9종: 웹 공격(응답 성공 징후), 웹셸, 악성코드 유입·익스플로잇 킷 연쇄, 평문/취약 비밀번호, 무차별 대입, ARP 스푸핑, DGA, IP 직접 HTTP, IOC
- 스트림 보기, HTML 보고서, CSV 내보내기

## Consequences
+ 운영 업그레이드 시 스키마 변경 안전, 반입 심사 자료(SBOM) 확보, ATT&CK 표준 정합성, 중복 작업 방지
+ PCAP만으로 침해 흐름(유입→악용→지속→유출)을 근거와 함께 재구성
- 내장 PCAP 분석기는 메모리 상한(방향당 8MB 저장, 전체 384MB) 내에서 동작 — 초대형 캡처는 분할 권장
- 이메일 첨부 추출, SMB/RDP 내용 해석, TLS 복호화는 범위 밖
- Codex 대비 테스트 수는 여전히 적음 → 기능 추가 시 테스트 동반 원칙 유지
