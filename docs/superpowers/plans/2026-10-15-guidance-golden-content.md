# Investigation guidance and offline content implementation plan

Spec: docs/superpowers/specs/2026-10-15-guidance-golden-content-design.md
Baseline: 05fe73b60ce5c2150979234c1a79a7e3c7a20061. Existing isolated branch codex/detection-packs in F:/codex/SAW-Claude-main.

## Global constraints

Keep F:/claude/saw read-only. No real bank data or credentials in outputs. Synthetic data only. Preserve EOL, existing RBAC/audit/4-eyes. Korean UI and docs; English code/comments/commits. No new dependency/download/model/training/production change. No automatic blocking/allowlisting/deployment. Actual native and browser verification must be reported separately from automated tests. Shared files owned by controller. No child commits until controller integration checks.

## Task 1: Guidance backend and capture

Implement saw/core/application/guidance.py and versioned YAML, new API router, Check validated metadata/revisions, structured closure helper/route, explicit WAF action normalization. Own existing checks.py/checks router/investigations router/normalization and tests/api/test_guidance.py. Do not edit experience.py or UI/shared registration. Use exact scope/8 states/A-G contract in spec; captured initial input and actual receipts separate from answers. Confirm failing API tests first, then 120/118/2, filter/time/either, spoofed evidence/receipt denial, prior time invalidity, B/C states, closure reuse. Expose build_closure_draft(s,p,inv_id) and documented capture schema for golden.

## Task 2: Golden backend and existing Knowledge UI

Own saw/knowledge/golden.py, golden_models.py, golden router, existing experience.py and knowledge.py, apps/web/src/pages/Knowledge.tsx plus Golden component/tests. Reuse exact approved Experience revision and contributor checks. Implement separate immutable versions/families/blobs, 4-part rubric, optional existing approval + standalone adoption, input allowlist vs answer separation, source ACL, selected evidence hash/cutoff, split conflicts. Correct Experience draft generation to use Task1 closure helper; no fabricated finding review. No shared main/db/migrations edits. API/UI tests of self/contributor approval, source ACL, existing Experience approval alone, adopted edits/newreview, tamper/missing evidence, no answer leakage, split linkage change, CSV injection and limits. CaseA integrated fixture should use actual guidance API.

## Task 3: Offline data content packages

Own saw/content_packages/ modules/models, API router, apps/web/src/pages/ContentPackages.tsx/tests, package authoring CLI/sample, tests. Can modify detection approval eligibility/auto runner and parser service only where necessary for exact package_fixture validation and atomic transactions. Do not mutate live state on import. Strict JSON<=1MiB<=20items, only Sigma/ParserSpec, positive+benign tests, immutable staging, 4-eyes apply, drift/digest/version recheck, atomic receipt/audit, exact rollback with compensation versions. Provide UI verify/stage/test/apply/history/rollback/export and external authoring guide. Fix INSTALL-WINDOWS incorrect rerun-installer upgrade advice. Controller owns shared navigation/registration/migrations. Tests include staging no-effect, failure atomicity, concurrent/stale apply, rollback drift, replay distinction.

## Task 4: Workbench integration and schema

Controller owns GuidancePanel component/tests + ContextPanel, CloseDialog, CheckDialog frontend, shared main.py/db.py, idempotent0013 migration, navigation, deletion retention hook. Reuse selected entity/finding/investigation filters/time; role selector, evidence links, facts/unknowns/actions, optional responses with followups and 8 states. Read-only preview never marks verified. Save Check payload and refresh only current scope. Closure prefill from real recorded work, editable separate behavior/impact, no six mandatory boxes. Existing Knowledge review displays separate adoption. Add migration/restart integration tests preserving legacy data.

## Task 5: Integrated validation, documentation, publication

Run relevant tests during integration and full isolated Python suite, Vitest, tsc/build, lint; use real isolated PostgreSQL/OpenSearch where available. Run synthetic browser caseA with two separate test actors, exports, pack verify/stage/test/apply/rollback, restart persistence. Capture actual screens. Record exact commands/results and unresolved native/LTSC gates. Update STATE/HANDOVER/PROGRESS/USER-MANUAL and Korean walkthrough, packaged synthetic examples. Review feature diffs independently, fix material findings, final whole-branch review. Commit feature groups after checks and publish authorized private GitHub source; do not imply existing installer ZIP contains this code.
