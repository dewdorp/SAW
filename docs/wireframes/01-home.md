# 01. Home

| 항목 | 내용 |
|---|---|
| Purpose | 분석 시작점. “분석할 데이터를 붙여넣거나 업로드하십시오.” Dashboard 아님 |
| Primary User Action | 붙여넣기(Ctrl+V) → Analyze / 파일 Drop → Upload |
| Layout | 상단 중앙 대형 입력창, 아래 Quick Upload 5종, 하단 3열(Recent Investigations / Active Jobs / Recent Findings) |
| Main Components | Paste Box(실시간 타입 감지 칩), Analyze 버튼, Upload Dropzone, Investigation 선택(옵션: “기존 Investigation에 추가”), 최근 목록 |
| Visualization | 없음 (의도적). Job은 미니 진행 바만 |
| Drill-down Flow | Analyze → [02 Universal]; Upload → Evidence 종류 확인 → [15 Job]; 최근 항목 → [07 Workbench]/[06 Finding] |
| Context Panel | 없음 (입력에 집중). 감지 칩 hover 시 간단 설명 |
| Raw Data Access | 해당 없음 |

```
┌───────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                       │
│                        무엇이든 붙여넣으세요                                            │
│   ┌───────────────────────────────────────────────────────────────────────────────┐   │
│   │ IP / URL / HTTP / Log / Payload / JWT / Hash …                                │   │
│   │ GET /api/customer?id=123 HTTP/1.1                                             │   │
│   │ Host: service.example.com                                                     │   │
│   └───────────────────────────────────────────────────────────────────────────────┘   │
│   감지: [HTTP Request] [IPv4 ×1] [Host] [User-Agent: script]                           │
│   대상: ( ) 새 분석  ( ) INV-20261005-013에 추가 ▾                 [ Analyze  ⏎ ]      │
│                                                                                       │
│   ┌ Drop files here or [Upload Files] ───────────────────────────────────────────┐    │
│   │ [PCAP]  [Web Logs]  [WAF Logs]  [IOC List]  [Security Logs]                   │    │
│   └───────────────────────────────────────────────────────────────────────────────┘   │
├─────────────────────────────┬─────────────────────────────┬───────────────────────────┤
│ RECENT INVESTIGATIONS       │ ACTIVE JOBS                 │ RECENT FINDINGS (mine)    │
│ ▲ INV-…013 API 대량조회  2h │ #1024 Web 38 files ███▌ 78% │ ▲ #1042 API Enumeration   │
│ ■ INV-…011 WAF 우회    1d   │ #1025 PCAP 6.3GB  ██ 31%    │ ■ #1037 Periodic Comm.    │
│ ○ INV-…009 정상 배치    3d   │                             │ ■ #1031 Sensitive File    │
└─────────────────────────────┴─────────────────────────────┴───────────────────────────┘
```
