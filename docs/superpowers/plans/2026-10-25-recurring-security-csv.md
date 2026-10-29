# Recurring Security CSV Implementation Plan
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans task-by-task.
**Goal:** Repeatably ingest the supplied FW/NDR header shapes and explain actual scenario execution and unavailable evidence.
**Architecture:** Strong-header built-in parsers feed existing CES/detectors. Readiness and per-scenario execution details are frozen in existing analysis history; the UI renders those records.
**Tech Stack:** Existing Python/FastAPI/SQLAlchemy, React/TypeScript/Vitest; no new dependency.
**Spec:** docs/superpowers/specs/2026-10-25-recurring-security-csv-design.md

## Global Constraints
- Keep original Claude/operational data untouched; synthetic test and documentation records only.
- Never infer verified counter/time/device semantics, actual IPs from opaque IDs, or ground truth from alert names/200/detected.
- Preserve raw references, masking, pinned generation and ACL/4-eyes contracts; no new DB schema.
- User approved continuous execution and release; no new phase approval gate.
- Preserve existing EOL; run tools explicitly in F:/codex/SAW-Claude-main with escalation and -B.
- Existing P5 sealed build is immutable. New product code requires a fresh final build.

## Review Focus
1. Mixed HTTP/non-HTTP rows and malformed requests must not become invented HTTP events (Task 1).
2. Quoted multiline CP949 records must preserve exact original byte references and unknown fields (Task 1).
3. Multiple devices and opaque destinations must not claim complete sessions/geography/cross-device identity (Task 2).
4. A failed/partial upstream execution or missing steps must not display normal/true-negative (Tasks 2,3).
5. Old retained runs without new detail must remain readable without manufacturing results (Task 3).

### Task 1: Deterministic format adapters
Files: new saw/parsers/security_csv.py, tests/unit/test_security_csv.py; modify saw/parsers/registry.py.
Interfaces: KoFirewallCsvParser id ko_fw_csv; KoNdrCsvParser id ko_ndr_csv; product security_csv. Preserve original unmapped fields in ext.security_csv. Record csv_format as fw/ndr in that namespace.
- [x] Write failing tests for exact headers, reordered/extra columns, wrong/missing/duplicate mandatory headers, CP949/BOM and multiline refs, mixed rows, invalid status, action semantics, opaque destination, attack label only.
- [x] Implement strong-header adapters using CsvParser bounded record handling. Valid NDR HTTP request line -> method+uri+web/http_access, otherwise connection/conn. Map session ID and strict numeric 100..599 response; retain source request/response fields and metadata. Do not map total packets into a direction or assume duration unit.
- [x] Run targeted parser/normalization regressions and record red/green evidence. Parent review complete; source commit remains in Task 4.

### Task 2: Frozen readiness and actual flow execution evidence
Files: new saw/detectors/csv_readiness.py and tests; modify saw/core/application/analysis.py and saw/detectors/scenarios.py with focused tests.
Interfaces: CsvReadiness detector id csv.readiness, report schema csv-readiness/1 in execution.detail, per-format counts/field counts/limitations without raw values; no Finding generated. Existing scenario.flow detail schema scenario-execution/1 contains actual pack fingerprint, per-scenario id/title/status/match_count/steps with eligible finding counts. Rendered match counts use actual matcher output, not inferred attack labels.
- [x] Write failing tests for missing/opaque/multidevice/no-time/unknown-semantic rows, bounded iteration/cancellation, no input, and retained history.
- [x] Add bounded one-pass readiness over matching parser IDs, max 100000 records, explicit coverage complete/partial, no hidden full-corpus claim. Keep raw source values out of report.
- [x] Expose per-scenario actual matcher report from same findings/pack used by _flows. Distinguish matched_candidate, no_chain, insufficient_evidence; never claim TN or success. Record actual scenarios.VERSION. Include failed/partial upstream caveat via existing execution statuses.
- [x] Test actual synthetic parser->store->detectors->flow history, normal rows and missing-response/label-only controls. Parent review complete; source commit remains in Task 4.

### Task 3: Analyst UI and repeatable examples
Files: new focused analysis-history components/tests; minimal modification AnalysisHistoryTab.tsx/UploadModal.tsx; guide and synthetic CSV examples.
Interfaces: consume csv-readiness/1 and scenario-execution/1; no additional writes or endpoints. Missing old detail -> explicit unrecorded, not computed from current data.
- [x] Red/green UI tests for counts, unavailable fields, bounded sample, per-scenario status, missing old data, no raw HTML rendering.
- [x] Show recognizable Korean headers, repeat upload workflow, profile semantics confirmation, analysis-history and evidence links.
- [x] Provide complete same-header synthetic FW/NDR CSV fixtures and guide covering repeated upload vs duplicate records, source device split, detector enabled state, deterministic results vs analyst truth.
- [x] Actual synthetic browser workflow/screenshots; inspect readability and lack of real values.

### Task 4: Validation and release
- [x] Scoped independent review fixes; final backend 2818 passed/14 skipped, web 359 passed, native 12 passed; source frozen unchanged.
- [x] Read-only provided-file parser audit outputs only counts/field names/rule IDs; no content or unlabeled accuracy claim.
- [x] Update STATE/PROGRESS/manual with final source validation outcomes and limitations.
- [ ] Commit/push, fresh model-free build, verified ZIP/extraction, native fresh/update/rollback harness, new private PR/prerelease. Preserve prior main/releases/P5 candidate. Publish only actual verified claims.
