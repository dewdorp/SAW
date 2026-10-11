# 32. Case & Investigation Design

## 1. 개념 구분

| | Investigation | Case |
|---|---|---|
| 성격 | **분석 작업 공간** (Evidence, 분석 결과, 시각화) | **사건 기록·관리 단위** (판단, 대응, 보고) |
| 수명 | 분석 중심, 종료 시 Verdict | 대응 완료까지, 여러 Investigation 묶음 가능 |
| 내용 | Evidence, Findings, Story, Timeline, Graph, Notes | Findings/Events/Entities 스냅샷, Summary, Response, Experience·Detection 링크 |
| 관계 | 1 Case ↔ N Investigation | |

작은 사건은 “Investigation 종료 → 자동 Case 생성” 옵션으로 단일 흐름.

## 2. Unified Investigation

```
Investigation #20261005-013
Evidence:  PCAP 6.3GB · Web Log 12.8GB · WAF Log 2.1GB · (Connector) SIEM query: src_ip in group g1, 10-04~10-05
```
- Evidence 추가 시 공통 Entity 자동 연결(IP, 도메인, 계정, 자산, community_id).
- **Cross-source Correlation** (CorrelationWorker): 공통 Entity + 시간 윈도우 → `inv.correlation`
```
03:11  WAF   API Access              ─┐ src group g1
03:13  WEB   Mass Requests (21k)      │ same asset 10.10.1.21
03:14  DB    Query Spike +32x         │ Δt 1m (asset 기준 약한 연결)
03:15  PCAP  Outbound 3.2 GB         ─┘ 10.10.1.21 → 185.x.x.x
```
Timeline·Story에서 이 상관 연결을 표시하며, 링크 종류(강: 같은 src/session, 약: 같은 asset + 시간)를 구분.

## 3. Case 필드

`case_id, title, severity, status, assignee, summary, observables, evidence, events, timeline, findings, analysis, response, experience, related_detection, created_at, closed_at`
- events/findings/timeline/story는 **스냅샷**(case_item.snapshot) — Investigation 데이터가 보존기간으로 삭제되어도 Case 기록 유지.
- Evidence 첨부 유형: PCAP, Logs, IOC, File, Screenshot, Document (S3 `saw-knowledge-attach`/원본 참조).

## 4. Investigation 종료 플로우

```
[Close Investigation]
 Final Verdict      ○ Attack  ○ Normal  ○ False Positive  ○ Unknown   (필수)
 Analyst Comment    ___________________________                     (필수)
 Checks Performed   ☑ WAF 차단 여부 확인  ☑ 배치 스케줄 확인  ☐ 계정 소유자 확인 …  (Playbook에서 제안)
 Response           ___________________________  (사람이 수행한 대응 기록)
 Detection Idea     ___________________________
 ☑ Save as SOC Experience (Draft)      ☐ Create Case / Link to CASE-…
 [Close]
```
종료 후: Investigation read-only(재오픈 가능, 감사), Experience Draft 생성, Similar 인덱스 갱신.

## 5. Case 화면 요소

- Header: severity, status, assignee, SLA(선택)
- Summary (Markdown, AI 초안 가능 — 라벨)
- Story 스냅샷, Key Findings, Timeline 발췌, Observables 테이블(defanged, Export)
- Response 로그 (시간·수행자)
- Links: Investigations, Experience, Detection
- History (모든 변경)
- Export: Markdown/PDF/DOCX 보고서 (마스킹 정책 선택, 워터마크)

## 6. 외부 연동

기존 ITSM/SOAR/IRIS가 있으면 Case Export(JSON/Webhook는 Admin 승인 Connector)로 연계 — 양방향 동기화는 P2.

## 7. Notes

- Markdown, 멘션(@user), 링크 칩(`[F-1042]`, `[evt:…]`, `[ip:…]`) 자동 렌더(텍스트 escape 후).
- Timeline에 Note 마커로 표시.
- Revision 보존.
