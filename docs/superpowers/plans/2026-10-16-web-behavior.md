# Scoped Behavior Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Existing investigation logs produce reproducible behavior tables/charts and evidence-linked report/Golden inputs.
**Architecture:** Pure bounded calculation -> existing Job -> immutable BehaviorResult -> existing workbench/Check/report/Experience/Golden.
**Tech Stack:** Existing Python/FastAPI/SQLAlchemy/EventStore/React/ECharts; no new product dependencies.
**Spec:** docs/superpowers/specs/2026-10-16-web-behavior-design.md

## Global Constraints
LTSC2019 x64 target, airgap, multiuser/low-memory. No operating data, original Claude edits, external downloads, model changes or automated blocking. English code/comments/commits; Korean UI/docs. Preserve existing EOL. Existing approval and source ACL boundaries. Routine execution delegated by user; product approvals remain human.

## Review Focus
- Missing UA versus logged empty; timestamp ties.
- Multisensor records incorrectly deduplicated; query identity lost.
- Concurrent ingest/deletion/retry producing stale completed results.
- Numeric divergence between view/report/Golden or answer leakage.
- Huge input/output silently reported complete; stale scope in raw navigation.

### Task 1: Measurement and producer field coverage
Owner calculator agent. Files saw/behavior/calculator.py, definitions.py, parser/normalize source provenance helper and focused tests/unit/test_behavior_calculator.py, test_behavior_observation.py. No service/router/UI edits.
Consumes CES events; produces calculate contract exactly in spec.
- [ ] Write failing boundary/threshold/query/static/OPTIONS/missing-UA/dedup tests and run RED.
- [ ] Implement bounded deterministic windows, profile/version, quality/indicators and sample refs; producer metadata.
- [ ] Run new unit and existing parser/normalize tests; report results/limits.

### Task 2: Immutable results, worker and evidence lifecycle
Owner service agent. Files saw/behavior/{models,service,router,worker}.py, behavior Check/close/Experience/Golden integration; tests/api/test_behavior.py. Root owns shared db/migration/router registry/Job recovery wiring.
Consumes calculate/events/provenance; produces spec API and result DTO.
- [ ] Write failing API tests for run/read/version/ACL/tamper/cancel/source change and Behavior Check->Golden separation.
- [ ] Implement Job submission and leased bounded worker, result hashes/source manifests, Check capture and Experience pinned references, Golden allowlist blobs.
- [ ] Test independent approval, stale revisions, missing snapshots, existing Guidance-only Golden regression.
- [ ] Publish wiring instructions to root.

### Task 3: Workbench and printable report
Owner UI agent. Files apps/web/src/pages/inv/BehaviorTab.tsx and test, components/Checks.tsx support; saw/behavior/report.py and tests/unit/test_behavior_report.py. Root owns Workbench tab wiring and existing Briefing link; do not edit backend service.
Consumes result DTO/API spec; produces BehaviorTab and render_report(result_dto, analyst_checks=[]) -> HTML.
- [ ] Write failing UI contract tests for scope/job/metrics/unavailable/raw/compare/record/report and report escaping/numeric equality.
- [ ] Implement Korean visual tab, profile controls, saved versions, time bars/zoom/peaks, measurement table/indicators/limits/notes; reuse RequestEvolution/EventDrawer.
- [ ] Implement escaped A4 HTML9sections with bounded inlineSVG chart/table from exact DTO; separate interpretation.
- [ ] Run focused Vitest/tsc + report tests.

### Task 4: Shared integration and request comparison
Owner root. Files db/router registry,migration0014,container.py,workers/tasks.py,evidence retry branch,Workbench/Briefing links,workbench.py diff scope/mask.
- [ ] Add failing comparison query/masking and behavior retry/recovery tests.
- [ ] Wire registrations/migration and correct Job dispatch without changing other kinds.
- [ ] Fix raw-query comparison collapse, explicit scope and masking; maintain bound limits.
- [ ] Integrate agent outputs; full server/UI tests, tsc/build, review.

### Task 5: Actual synthetic execution and documentation
Owner root with independent reviewer.
- [ ] Generate A–D synthetic logs and run actual upload->scope->behavior->report->Check->Experience->other reviewer Golden/export plus restart.
- [ ] Run actual PG/OpenSearch focused tests on owned instances; compare output values.
- [ ] Render standalone synthetic report, verify pages visually; browser workflow/screenshots only if actual tool works.
- [ ] Document precise source/methodology/profile definitions, actual samples/results/OS and remaining gates; update STATE/HANDOVER/PROGRESS and next-release allowlist.
- [ ] Commit verified implementation and docs; authorized private GitHub push. Do not claim installer/LTSC/browser/LLM acceptance not executed.
