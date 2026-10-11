# 02. Universal Analyzer

| 항목 | 내용 |
|---|---|
| Purpose | 입력이 무엇인지 자동 인식하고, 무엇을 분석해야 하는지 제시·자동 실행 |
| Primary User Action | 감지 결과 확인 → 추천 분석 결과 열람 → 다음 행동(Investigation 추가, Related Logs, Similar) |
| Layout | 좌: 입력 원문(Span 하이라이트) / 중: 감지 목록 + 추천 분석 / 하: 분석 결과 카드(탭) / 우: Context |
| Main Components | Highlighted Input Viewer, Detection List(신뢰도), Recommended Actions Bar, Result Tabs(HTTP/IOC/Payload/Log), Entity Chips |
| Visualization | 입력 Span 하이라이트(감지 유형별 색+밑줄 패턴), Decode Chain 미니 플로우 |
| Drill-down Flow | 감지 항목 → 해당 Analyzer 전체 화면 [03]/IOC/Payload; Entity Chip → IOC Detail Drawer; [Add to Investigation] → [07] |
| Context Panel | 감지 IOC의 Internal Context 요약, Previous Verdict, Similar Experience(있으면) |
| Raw Data Access | 입력 원문은 항상 좌측에 표시, 제어문자·Bidi 기호화 토글 |

```
┌ UNIVERSAL ANALYSIS ── input 412 B · not saved ── [Add to Investigation ▾] [Copy defanged] ──┐
├ INPUT ──────────────────────────────────┬ DETECTED ──────────────────┬ CONTEXT ────────────┤
│ GET /api/customer?[id]=[123] HTTP/1.1   │ ✓ HTTP Request       0.99  │ 1.2.3.4             │
│ Host: [service.example.com]             │ ✓ IPv4 (XFF, ext)    0.98  │ Internal: First 09-28│
│ User-Agent: [python-httpx/0.27]         │ ✓ Host               0.99  │ WAF 1,203 · FW 8,421│
│ X-Forwarded-For: [1.2.3.4]              │ ✓ User-Agent script  0.95  │ Prev: Attack (10-02)│
│                                         │ ✓ Query Param id     0.99  │─────────────────────│
│                                         │                            │ Similar Exp 2       │
├ RECOMMENDED ────────────────────────────┴────────────────────────────┤ 09-14 API Enum ▲   │
│ [✓ HTTP Analysis] [✓ IOC] [– Payload Decode] [Related Logs] [Similar Case] [Timeline]     │
├ RESULTS: HTTP │ IOC │ Payload ───────────────────────────────────────────────────────────┤
│ Method GET · Path /api/customer · Params 1 (id numeric) · Patterns: none                  │
│ Hints: ● script UA  ● external XFF  ● numeric object id → [Context Required: Enumeration] │
│ [Open full HTTP Analyzer]                                                                 │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```
