# ADR-0016: Windows 10 LTSC 2019 폐쇄망 배포 — 네이티브 설치 + 내장 PCAP 분석기

- 상태: Accepted
- 날짜: 2026-10-07

## Context
- 운영 서버는 **Windows 10 Enterprise LTSC 2019 x64 (1809, 빌드 17763)**, **폐쇄망**, 사양은 높지 않음.
- 요구: OpenSearch 사용, PCAP 분석.
- 기존 설계(ADR-0001 등)는 Linux + Docker Compose를 전제로 했다. 그러나:
  - WSL2는 빌드 18362 이상 필요 → **불가** (WSL1에서는 dockerd 실행 불가).
  - Docker Desktop은 Windows 10 22H2 이상 필요 → **설치 불가**. (대기업은 유료 구독도 필요)
  - Zeek는 Windows 공식 빌드가 없다.
- SAW 코드는 Windows에서 개발·테스트되어 Linux 전용 의존성이 없다.

## Options
| 옵션 | 장점 | 단점 |
|---|---|---|
| A. Hyper-V Linux VM + Docker | 원래 설계 유지 | 저사양 서버에서 자원 이중 소비, VM 관리·보안 승인 추가 |
| **B. Windows 네이티브 설치** | 추가 가상화 없음, 개발 환경과 동일 | 구성 요소별 Windows 서비스 관리 필요, Zeek 없음 |
| C. 별도 Linux 서버 요청 | 표준 구성 | 조달 일정·비용, 현재 요구와 불일치 |

PCAP:
| 옵션 | 장점 | 단점 |
|---|---|---|
| tshark 필드 추출 | 프로토콜 범위 넓음 | Wireshark 설치(GPL)·버전 차이, 출력 정규화 부담 |
| **내장 순수 Python 분석기** | 의존성 0, 폐쇄망 반입 쉬움, 테스트 가능 | 프로토콜 범위 제한(conn/dns/http/tls), 성능 Zeek 이하 |

## Decision
- **옵션 B (Windows 네이티브)**. 구성:
  - SAW API + 웹(빌드된 정적 파일)을 하나의 HTTPS 서비스로 실행 (Windows 서비스).
  - PostgreSQL (Windows 서비스), **OpenSearch Windows zip (단일 노드, 127.0.0.1 바인딩)** + nori 플러그인.
  - 파일 보관은 NTFS 로컬(`object_store=local`), 작업 처리는 내장 실행기(`job_runner=inprocess`). MinIO·Celery·Valkey는 사용하지 않는다.
- **PCAP은 내장 분석기 `saw.integrations.pcapkit`**:
  - PCAP/PCAPNG → 흐름 → **Zeek 호환 JSON**(conn·dns·http·ssl, JA3/JA4, Community ID). 기존 Zeek 파서·탐지기·ATT&CK 매핑을 그대로 사용.
  - 세션 PCAP 추출도 내장(tshark 불필요), 다운로드는 감사 기록.
  - Zeek가 있으면 Zeek 우선(Linux 호환 유지). **Suricata(Windows MSI)는 선택** — 설치 시 IDS 경보 추가, 규칙은 오프라인 반입.
- 저사양 기본값: OpenSearch heap 1–2GB, 단일 샤드·레플리카 0, 분석 작업 동시 1개.

## Consequences
+ 추가 가상화 없이 현재 서버에서 운영 가능, 개발 PC와 동일 런타임
+ PCAP 분석에 외부 도구가 필요 없어 폐쇄망 반입 대상 감소
- 내장 분석기는 Zeek 대비 프로토콜·정밀도 제한(TCP 재조립은 방향당 앞 64KB, HTTP chunked 본문 미해석, SMB/RDP 등 미지원)
- Windows 10은 클라이언트 OS: 동시 접속 기기 수 라이선스 제한(통상 20) 확인 필요
- LTSC 2019 보안 지원 종료(2029-01) 전 OS 이전 계획 필요
- 관련: ENV-VERIFICATION.md (ENV-01·05·06 대체 경로), 설치 안내 docs/INSTALL-WINDOWS.md
