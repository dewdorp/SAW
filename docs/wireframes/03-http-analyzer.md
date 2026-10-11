# 03. HTTP Analyzer

| 항목 | 내용 |
|---|---|
| Purpose | 단일 HTTP Request/Response를 구조화하고 Potential Pattern과 근거를 제시 |
| Primary User Action | Pattern 근거 확인 → Decode Chain 확인 → (여러 요청이면) Request Diff 이동 |
| Layout | 상단 요청 요약 바 / 좌: 구조(Headers/Params/Body) / 우: Patterns + Anomalies / 하: Response |
| Main Components | Request Summary, Parameter Table(location·decoded·type), Pattern Card(Evidence/Not-evidence/Confidence), Anomaly List, JWT Panel, Response Panel(text/hex, 렌더 금지) |
| Visualization | 파라미터별 Decode Chain 플로우, Evidence Span 하이라이트 |
| Drill-down Flow | Pattern → Evidence Span → Decode Chain(Payload Analyzer); IP/Host Chip → IOC; [Related Logs] → Investigation 검색; [Compare] → [Request Diff] |
| Context Panel | Host의 Asset Context, 동일 패턴의 Experience/FP 조건 |
| Raw Data Access | Raw 탭: 원문 요청/응답(마스킹), hex 뷰 |

```
┌ HTTP ANALYSIS ─ GET service.example.com /api/customer ─ UA script ─ Resp 403 512B ─ [Compare] [Add to Inv] ┐
├ Overview │ Headers │ Parameters │ Body │ Response │ Raw ──────────────────┬ PATTERNS ───────────────────────┤
│ PARAMETERS                                                             │ ■ Potential SQL Injection  MED  │
│ loc     name     value            decoded         type    flags        │   at json $.q                   │
│ query   id       123              —               num                  │   Evidence:                     │
│ json    $.q      %2527%20OR…      ' OR 1=1--      str     ⛓ 2 steps    │    ' OR 1=1--  (span)           │
│ cookie  sid      ●●●●a91f         —               token   🔒            │    ✓ libinjection s&1c          │
│ header  XFF      1.2.3.4          —               ip      ext·AWS      │    ✓ double URL encoding        │
│                                                                        │   Not evidence:                 │
│ ⛓ $.q DECODE CHAIN                                                      │    ✗ Response 403 (blocked?)    │
│  %2527%20OR%201%3D1--  ─URL─▶  %27 OR 1=1--  ─URL─▶  ' OR 1=1--         │─────────────────────────────────│
│                                                                        │ ANOMALIES                       │
│                                                                        │ ⚠ Content-Length + TE both      │
├ RESPONSE ──────────────────────────────────────────────────────────────┤ ⚠ Duplicate Host header        │
│ 403 Forbidden · text/html · 512 B · body: [text] [hex]  (HTML 렌더하지 않음)│                                 │
└────────────────────────────────────────────────────────────────────────┴─────────────────────────────────┘
```
