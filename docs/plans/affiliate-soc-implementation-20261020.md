# Affiliate SOC implementation P1–P5
Approved by the user on 2026-10-20 for continuous implementation, validation, review, and release.
Spec: [approved design](affiliate-soc-design-20261020.md). Acceptance IDs T01–T20: ../verification/affiliate-p0-matrix-20261020.md.

Goal: preserve source context and evidence semantics through deterministic device analysis, governed detection, immutable reports, and approved Golden releases.
Architecture: additive SQLAlchemy/Alembic models, producer-owned CES observation metadata, immutable snapshots, bounded workers, existing FastAPI/React and source ACL.
Tech: Python 3.12, PostgreSQL/SQLite tests, OpenSearch, React/TypeScript, actual XLSX with a pinned offline dependency.

## Global constraints
Use only F:/codex/SAW-Claude-main. Never change F:/claude/saw or operational installs. Synthetic data only. Never read/copy actual bank data or credentials. Python -B, isolated pytest wrapper. Preserve EOL. No downgrade of RBAC, source ACL, four-eyes, provenance, missing/partial/failure semantics. No claims of LTSC/16GB approval from development tests. Models excluded from media. Original releases preserved.
User approval covers feature code, tests, phase commits, new private prerelease and PR; it does not authorize operational installation or actual data export.

## Task P1.1: Context registry
Create saw/source_context/{models,service,router}.py and idempotent migration 0015. Extend only Investigation/Evidence context columns in storage/models.py and investigation API/service. Stable org IDs; versioned device profiles; immutable evidence context snapshot. Unknown/conflicting observed affiliation is not overridden. Context changes affect new ingestion only. Return org context in investigation outputs and scoped filters. Synthetic API/migration tests before implementation.
Interfaces: attach evidence context using source_context.service; producer normalizer consumes a plain validated snapshot. Root integrates workers and UI.

## Task P1.2: Observation and FW interpretation
Create pure saw/observation modules and tests, adapt structured parser to retain true source, directional counters and field-state metadata. Common ConnectionObservation for Zeek and generic connection records. Preserve all raw/hash/id/offset. Session keys include organization/device/network/domain/protocol/session/start/reuse. Start/interim/end cumulative values are not summed; test 0/0,100/900,300/1200 => 3 records,1session,300/1200. Unknown counter semantics remain unknown. FW deterministic scan/deny-to-allow/large transfer/long duration/true connection beacon with explicit limits and evidence. Avoid unbounded input/group memory.

## Task P1.3: Source ACL closure
Fix shared Checks/team/cite/evidence and asset context to require source investigation ACL. No administrator analysis bypass. Do not expose inaccessible source IDs or counts. Test revocation and same-IP different affiliate collisions. Update intentionally permissive old assertions to new approved contract.

## Task P1.4: Runtime integration and UI
Root integrates context upload, common immutable AnalysisRun/detector execution/FindingSnapshot/ReportVersion, current source epoch, failures and partial status. Add relation/device/time/log workflow, optional service, counts/quality and FW evidence report. Tests then integrated P1 server/UI gate, independent review, commit.

## Task P2: Governed detection and device analysis
Single DetectorSpec metadata used by catalog/runtime/editor, immutable policy/version/binding and explicit active pointers. Editing does not disable prior active version. Version-pinned tests with expected match/no-match/unlabeled and correct units/denominators. Numeric forms plus robust JSON draft editing. Implement WAF/IPS/DDoS/NDR device-specific analyses with measured units, missing data, context boundaries and actual thresholds. Separate behavior/impact/enforcement. Review and full phase tests.

## Task P3: Follow-up and immutable reports
Versioned Check-linked requests/replies/verification; nullable owner/due. Freeze exact Check/followup/source/result versions into ReportVersion. Same snapshot drives HTML and eight-sheet XLSX with safe string cells, charts, bounded writing and no external links/macros/formulas from input. Investigation, selected follow-up, authorized multiple investigations entrypoints. Pin XLSX dependency and actual wheel/license for offline media. Browser/API/real workbook verification; review and full phase tests.

## Task P4: Golden and external release governance
Versioned device-aware Golden with separate detection/investigation truth, known-at facts, case-family split and leakage checks. Full recalculation eligibility requires complete verified normalized input manifest. Separate purpose/recipient/artifact-digest export approval excluding contributors. Stable pseudonyms and semantic preservation/revalidation. Versioned nonexecutable model conversion profiles. Bounded export job checks source ACL and approval at start/publication/download; legacy external export returns explicit approval-required. Test revoke/cancel/hash changes, holdout leakage and export archive.

## Task P5: Integration, media and release
Idempotent migrations and generation-safe reprocessing with count/hash/ACL checks before active switch. Rule reanalysis creates a new run without replacing old snapshots. Bounded fair queue and synthetic 1k/100k/1M, 1/3-user measurement. Full backend/frontend, actual synthetic PostgreSQL/OpenSearch/browser. Build model-free complete offline package; new install/0014 upgrade/restart/failure/rollback retains accounts/evidence. Independent whole-branch review and focused re-review, phase commits, new private prerelease and PR with exact assets. LTSC/16GB and operational gates explicitly separate.

## Review focus
Source ACL, immutable snapshots, cumulative counters, unknown vs zero, independent approvals, active version races, report scope equivalence, export answer leakage, bounded processing, and migration/update preservation.
