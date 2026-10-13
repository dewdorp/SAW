# Admin Data, Rule Export and Log Analytics Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development and verification-before-completion. The user delegated routine implementation decisions; continue without redundant approvals.

**Goal:** Deliver safe administrator cleanup, inspectable detection rules, useful scoped statistics and explainable peer anomalies, with a truthful 16GB model intake guide.
**Architecture:** Extend existing FastAPI/SQLAlchemy/eventstore/React contracts. Keep deletion lifecycle independent from rule export and statistics. No external ML service or new runtime dependency.
**Tech Stack:** Python3.12, FastAPI, SQLAlchemy, PostgreSQL16/OpenSearch2.19.6, React18/TypeScript.
**Spec:** ../specs/2026-10-14-admin-rules-analytics-design.md

## Global Constraints

- Modify F:\codex\SAW-Claude-main only; original F:\claude\saw remains read-only.
- Windows10 LTSC2019 x64/17763, airgap, noGPU,16-32GB, noDocker/WSL2. Developer tests do not certify target.
- Never use real bank contents/credentials; synthetic tests only. Preserve EOL, Korean UI/docs, English code/comments/commits.
- Preserve audit/revisions/4-eyes, refuse unsupported deletion instead of silently losing evidence.
- Do not change selected model, publish model weights, alter administrator services/firewall, or overwrite existing release media.

## Review Focus

- Deletion racing upload/worker/LLM and partial cross-store failure must remain blocked/retryable (Task1).
- A shared object or legal hold must prevent physical deletion; local paths must reject traversal/reparse (Task1).
- Export cannot silently omit matching conditions or include historical raw samples; file download cannot approve a rule (Task2).
- Statistics denominators, missing values, time filters and topN errors must match drilldown (Task3).
- Sparse or unrelated-service normal traffic must not create an attack claim, and private historical baselines must not leak (Task3).

### Task1: Administrator cleanup (admin agent)

Files: new core/application/data_deletion.py, routers/admin_data.py, deletion model/migration0012; minimum integration in authz/main/investigations/evidence/pipeline/jobs/objectstore/eventstores/llm.service; AdminData.tsx/test and Admin/App links. Own these files; coordinate any overlap.
Interfaces: admin.data.delete; GET /admin/data; POST /admin/data/deletion-preview; POST /admin/data/deletions; GET /admin/data/deletions/{id}; POST /admin/data/deletions/{id}/retry. Body target_type/target_id/reason/confirmation/preview_fingerprint. Preview/result expose counts and retained categories, never raw content.
- [x] RED synthetic API tests: nonadmin403, admin raw-read stays403, legalhold/jobs/uploads/sharedkeys block, stale preview409, case revision retained, evidence bundle/investigation cleanup, cross-store failure/retry, audit chain unchanged.
- [x] Implement persistent delete lifecycle and row-lock barrier including upload/worker/LLM completion boundaries. Fail closed for unsafe references/backends.
- [x] Implement Korean metadata list, impact preview, required ID/reason confirmation, failed/retry status with UI tests.
- [x] Run focused tests and independent review; root runs whole suite before feature commit.

### Task2: Rule export and onboarding (root)

Files: new saw/detection/exporting.py, routers/detection.py; Detections.tsx, DetectionCatalog.tsx, DetectionHelp.tsx/tests; tests/api/test_detection_export.py; docs/DETECTION-RULES-HOWTO.md.
Interfaces: GET /detection-catalog/export?format=json|yaml; GET /detections/export?format=json; existing /detections/{id}/export returns attachment headers with exact native logic. Shipped export schema saw.detection-catalog.v1 contains full inherited match conditions/examples/benign and effective state; custom export schema saw.detection-rules.v1 contains safe current versions only.
- [x] RED matching fields/benign/effective switches/attachment/permission/audit/source-samples exclusion tests.
- [x] Implement bounded exports and safe filenames, no status mutation.
- [x] Add Korean workflow guide, narrow synthetic example/test-input editor, native download, catalog JSON/YAML and current-rule bundle download with error tests.
- [x] Run focused API/UI and final whole suite.

### Task3: Statistics and peer anomalies (analytics agent)

Files: new core/application/statistics.py and detectors/peer_behavior.py, workbench router, analysis.py/anomaly history boundary; StatisticsTab.tsx/test, Workbench.tsx, OverviewTab.tsx; focused API/unit tests. Avoid editing storage adapters owned by Task1; compose time filters or coordinate if essential.
Interfaces: POST /investigations/{inv_id}/statistics as spec. Per-row filter composes with existing filters/time and opens Raw tab. Detector registered once; historical unapproved baseline returns empty.
- [x] RED synthetic statistics: auth/filter/time/missing/topN/cross-evidence same filename/no raw data.
- [x] RED peer: normal20000 plus small anomalous80, normal bulk other service, sparse normal, same source different windows, cap coverage, cross-investigation history denied.
- [x] Implement bounded aggregation+detector and Korean scope/time/table/drilldown UI with tests.
- [x] Run focused tests and independent review; root runs whole suite before feature commit.

### Task4: Model guide and integrated validation (root + model researcher)

Files: docs/MODEL-16GB-KOREAN-GUIDE.md, existing model guide links; STATE/PROGRESS/HANDOVER/manual final updates.
- [x] Record official sources, original/quant revisions, memory estimates versus observed facts, current adapter limits, offline intake/selection guide and synthetic evaluation checklist.
- [x] Review all tasks, run whole backend/UI/tsc/build, real synthetic browser workflows/screenshots and possible dedicated native PG/OS scenarios.
- [x] Update evidence-based progress and commit each verified feature. Preserve immutable oldrelease, do not claim new package until rebuilt/tested.

## Decisions

- Reuse existing independent copy instead of creating another checkout. Starting HEAD043297c clean.
- User delegated routine approvals in the same session. No new model execution or destructive real-data action is inferred.
- First UI attempt did not run tests because worker min/max options conflicted; retry explicitly sets min1/max2. Shell log-path typo likewise did not execute tests. Preserve both as setup failures, not product regressions.

## Execution evidence

See ../../ADMIN-RULES-ANALYTICS-VALIDATION-2026-10-14.md. All code is frozen after full backend805/UI130, TypeScript and build verification. Model guidance is documentation only; target OS acceptance and new release packaging remain separate gates.
