# Statistics and Temporal Behavior Reinforcement Implementation Plan

> Use subagent-driven-development, test-driven-development and verification-before-completion. Prior user delegation permits routine design/implementation choices without repeated approval.

**Goal:** Strengthen scoped log statistics and explainable same-source temporal anomalies; provide truthful Korean/security ~8B offline candidate guidance.
**Architecture:** Extend existing statistics/grouping and detector interfaces. No new dependencies, database schema, cross-investigation baseline, operational model change or product phase.
**Tech Stack:** Existing Python3.12/FastAPI/SQLite/PostgreSQL/OpenSearch2.19.6/React18.
**Spec:** This document records the bounded design announced in chat for the existing statistics and anomaly flows.

## Global constraints

- Modify F:/codex/SAW-Claude-main, branch codex/detection-packs, base29950d7. Original F:/claude/saw is untouched.
- Target LTSC2019x64 build17763, airgap, noGPU16GB (possibly32GB), shared analysts. Development success is not target acceptance.
- Synthetic tests only; never open/copy bank records, var/secrets/.env. Keep evidence, RBAC, audit, four-eyes and analyst decision boundaries.
- Preserve tracked EOL; Korean UI/docs, English code/comments. No dependencies or model weight downloads and no model selection changes.
- Commits are feature-scoped after verification. Existing10/12 release media remains immutable.
- Existing20 statistics/anomaly baseline tests passed in10.36s, .qa/analytics-round2-baseline.log.

## Design decisions

- Statistics: add source/destination pair, HTTP status and method grouping; count, inbound/outbound sums/known counts, validHTTP100..599 denominator with4xx/5xx/errorcounts; count/byte/error-count sorting. Keep missing distinct from0.
- Use bounded conditional group metrics rather than per-row network calls; <=50groups and existing<=200timelinebuckets. Preserve old group_by defaults and original timestamp string while ordering SQLite timestamps by instant.
- Add a top-group chart and explicitly displayed-statistics-only CSV with current scope/summary; no raw records or hidden extra pages. Defend CSV formulas/quotes/newlines and label partial topN.
- Temporal: same investigation/logsource/canonicalsrc/dstip/dstport,15min windows. Exclude first/last observed group windows; require6immediately preceding windows and>=10events per baseline/candidate. Earliest comparison therefore needs9observed windows.
- Stable baseline counts: MAD/median<=0.25 and max/min<=2. Require>=2distinct observed changes among requestcount,errorratio,bytes/event using peer-style robust thresholds. Do not claim statistical independence.
- Every metric needs>=80% valid coverage in each baseline and candidate window. No zero fill for missingwindows. Partial/capped/invalid/missing/unstable conditions become coverage findings.
- Bounded temporal limits100000events/200series/5000windowgroups/10findings/20samples; aliases<=32. On resource truncation suppress candidates and report incomplete coverage. Exact evidence filters preserve originalIPaliases and candidatewindow.
- Models: official model IDs/revisions/licenses/tokenizers/templates/quant provenance; distinguish Korean support from security expertise and actual SAW compatibility. No model claims from invented performance; no multiGB downloads.

## Review focus

1. Scope, time zone and missing denominators must match raw drilldown on both backends.
2. Metric order/filter aliases must not permit SQL/DSL injection or per-rowquery explosion.
3. CSV must represent displayedtopN+scope safely without spreadsheet formula execution.
4. Temporal candidates must not use future/current observations in baseline or leak otherinvestigations/services; boundary/coverage truthful.
5. Candidate preparation guide must not imply unsupportedarchitecture/template or unverifiedGGUF is deployable.

## Task1: Statistics (statistics_enhancement)

Owned: core/schemas/query.py,storage/eventstore.py,storage/opensearch_store.py,core/application/statistics.py,routers/workbench.py,StatisticsTab.tsx/tests,tests/api/test_statistics.py,newfocusedstoretests.
- [x] RED tests for grouping/pairs/missing/HTTPdenominator/metricordering/mixedoffset/constantcalls/CSV.
- [x] Add backward-compatible metricfilter/value_count+allowlistedorder support and bounded statistics response.
- [x] Add Korean metric UI/chart and safe displayedCSV with drilldown tests.
- [x] FocusedSQLite+actualnativeOpenSearch verification and review.

## Task2: Temporal anomaly (anomaly_temporal)

Owned: newdetectors/temporal_behavior.py,analysis.py registration,newtests/unit/test_temporal_behavior.py,newAPIintegrationtest ifneeded. Do not modify peer_behavior.py orTask1files.
- [x] RED normalburst-only/genuine2signals/missinggaps/partialedges/futureindependence/order/caps/IPv6/exactevidence tests.
- [x] Implement bounded detector and Korean scope/limitation findings.
- [x] Integrationtest real pipeline candidate+evidence,reanalysis cleanup.
- [x] Focused tests and independent review; benchmark syntheticlarge input.

## Task3: Model guidance (model8b_candidates)

Owned: docs/MODEL-8B-KOREAN-SECURITY-GUIDE.md only.
- [x] Official-source comparison of~8B Korean/securitycandidates with clear constraints andpinnedmetadata.
- [x] Download onconnectedPC,verify,model-onlytransfer,actualCLIregistration/selection guidance with unsupportedpaths explicit.
- [x] Korean security syntheticcomparison criteria,memorybudget/currentadapter limits andsource/provenance review.

## Task4: Root integration

- [x] Review tasks; run full backend/UI/TypeScript/build after code freeze.
- [x] Actual isolatednative statistics and temporal tests; syntheticbrowser revisedstatistics+temporal evidence screenshots.
- [x] Update STATE/PROGRESS/manual/modelguide links and actual validation; feature commits created.
- [ ] Final documentation commit and authorized private GitHub push; verify remote SHA.

## Coordination ledger

| Tasks | Shared surface | Resolution |
|---|---|---|
|1/2|group_by caller contract|Task1onlyaddsoptionalargs; Task2keepsiterate/Filtercontext andownfiles.|
|1/3|none|Codeimplementation andofficial-source guide can proceed independently.|
|2/3|none|No modeldependent anomaly logic.|
|1|API/metric/UI|Use responsefields consistently; fullpublicgroup API regression tests required.|
|2|baseline/evidence|Sharedparams samewindow andaliases; nofuturebaseline; boundarycoverage explicit.|
|3|modelguide/runtime|Read actualCLI andvalidate_pack; do not modifyruntime to make guideclaims true.|

Ruling: Reuse existing isolated copy and user-delegated execution; preserve original and selectedmodel. Cost if wrong: reversible code/doc changes, no operational side effects.
Ruling: Run disjoint implementations in parallel per current tool/developer delegation guidance; explicit ownership prevents conflictingedits. Cost if wrong: integration rework caught by finaltests/review.

Final integration: backend830passed/2skipped; UI132passed; TypeScript/build exit0; isolatedPG/OS26API+8unit passed; realHTTP and browser160events/80candidate evidence, CSVdownload verified. Read-only final review found no remaining actionable defect. No new model execution or targetOS acceptance.
