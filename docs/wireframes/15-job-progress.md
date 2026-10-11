# 15. Job Progress

설계: [10-job-processing-design](../10-job-processing-design.md)

| 항목 | 내용 |
|---|---|
| Purpose | 대용량 분석 상태를 단계별로 투명하게 보여주고, 문제를 바로 조치 |
| Primary User Action | 진행 확인 → (필요 시) 파서 확인·암호 입력·실패 파일 재시도·취소 → 부분 결과 열기 |
| Layout | 상단 Job 요약 / 단계별 진행 바 / 파일 테이블 / 오류 샘플 / 부분 결과 링크 |
| Main Components | State badge, Stage bars(Upload/Parse/Index/Analyze), 이벤트 카운터(추정 표시), EPS·ETA, Current item, File table(파서·상태·이벤트·오류), WAITING_INPUT 액션 카드, Error samples, Cancel/Retry |
| Visualization | 단계별 진행 바, EPS 스파크라인 |
| Drill-down Flow | 파일 행 → 파서 미리보기(파싱된 5행) / 오류 샘플 → 파서 Override → 재처리; [Open partial overview] → [04] |
| Context Panel | 없음 (Evidence Custody 정보: 업로더·SHA-256) |
| Raw Data Access | 파싱 실패 라인 샘플 원문 (마스킹) |

```
┌ ANALYSIS JOB #1024 ─ INV-20261005-013 ─ Web Logs ─ ● PARSING ─ by 박분석 ─ started 01:02 ── [Cancel] ──────────┐
│ 38 Files · 12.4 GB                                       8,320,131 / ≈10,720,000 events (est.)  31.2k EPS ▁▂▃▅▆ │
│ Upload    ██████████████████████ ✓                                                     ETA ≈ 1m 17s          │
│ Parse     ███████████████████░░░░░ 78%       Current: access.log.18.gz                                       │
│ Index     ██████████░░░░░░░░░░░░░░ 42%                                                                       │
│ Analyze   Waiting                                         [Open partial overview ↗]                           │
├ ⚠ ACTION NEEDED ──────────────────────────────────────────────────────────────────────────────────────────────┤
│ waf_export_0105.log — parser confidence 0.62. Candidates: GenericWaf(<vendor>) 0.62 · KeyValue 0.55            │
│ [Preview] [Use GenericWaf] [Use KeyValue] [Define custom parser]                                               │
├ FILES ────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ file                      size    parser           state      events      errors                             │
│ access.log.1.gz           412MB   nginx_combined   ✓ done     281,203     0                                  │
│ access.log.18.gz          398MB   nginx_combined   ● parsing  201,882     12                                 │
│ waf_export_0105.log       1.1GB   ?                ⏸ waiting  —           —                                  │
│ broken.zip                20MB    —                ✗ failed   —           Possible archive bomb (ratio 1:840)│
├ ERROR SAMPLES (12) ───────────────────────────────────────────────────────────────────────────────────────────┤
│ line 48211: unexpected quote in request field  [show raw]                      [Retry failed files]           │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
States: QUEUED · UPLOADING · PARSING · INDEXING · ANALYZING · COMPLETED · FAILED · CANCELLED (+ WAITING_INPUT)
```
