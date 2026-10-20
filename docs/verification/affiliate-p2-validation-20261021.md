# P2 verification — governed detection and device analysis

Current checkpoint: P2 implementation, finite independent review and phase gates passed. P3 starts next; product release and operational acceptance remain separate.

## Implemented scope

- Immutable detection/policy versions, exact selected-unit proof, independent approval, explicit activation/rollback with active-revision conflict checks.
- Stable composite observed-organization/device scope; owner organization is a separate concept.
- Common DetectorSpec for editor/runtime, numeric policy controls and validated JSON drafts.
- WAF/IPS/DDoS/NDR observation analysis with recorded units, prerequisites, coverage and source context; existing FW semantics preserved.
- Exact-version export and immutable historical execution pins. Source access remains required through approval inputs, runtime policies and derived artifacts.

## Actual browser/API observations

Dedicated loopback synthetic server58372; no operational account or data.

- Normal login/MFA and rule editing in actual built UI.
- Nine normalized synthetic connection records: positive window6records and negative window3records; exact v2 proof TP1/TN1/FP0/FN0.
- Initial unsupported source mapping and inclusive time-window fixture issue were recorded, corrected and retested. Earlier attempts are not counted as successes.
- Author approval prevented. A different synthetic reviewer approved and activated exact v2 through the authenticated API.
- Actual browser saved draft v3 while approved v2 and active v2 stayed unchanged, including a post-restart read.
- DDoS policy form displayed numeric/unit/inheritance controls. This observation did not perform a policy write.
- Actual screenshot guide: [P2 use guide](../AFFILIATE-DETECTION-GUIDE-20261021.md).
- Fixed synthetic examples do not establish operational precision/recall or quality improvement.

## Automatic/native evidence

- Final UI:268tests/43files passed,16.08s (one independent QA probe included); TypeScript passed; production build25.57s. No later frontend product edit.
- Native initial:21passed/0failed/0skipped; pytest194.25s, total433.39s. Actual PostgreSQL16.15/OpenSearch2.19.6/Nori, populated0016→0017→0018 upgrade, selected proof→approval→activation→rollback, indexed scopes and source-change/revocation guards.
- Native final:11passed/0failed/0skipped; pytest113.97s, harness114.969s, total163.547s. Final derived-run source, flow/completion, rule-copy and coverage regressions.
- The intermediate fresh native r2 failed with8passed/1failed/2notrun. PostgreSQL rejects DISTINCT on JSON-bearing Detection rows. The lookup was narrowly changed to correlated EXISTS, preserving rule scope, inactive condition, source ACL and bounds. Default affected6tests passed7.95s; fresh actual native r3 then passed all11.
- Native runs verified23,195 reused runtime files against exact public archives and used fresh data/config/generated synthetic credentials. Flush failed_shards0, both processes stopped, owned ports closed, stop_complete=true.
- [Initial native record](affiliate-p2-native-20261021.md) and [final native supplement including failure](affiliate-p2-native-final-20261021.md).
- Full backend r1:1935passed/6skipped/2warnings,1875.95s. Earlier candidate, before final derived-source corrections.
- Full backend r2:1960passed/6skipped/1failed,1770.30s. The sole failure was a missing P2 guide/media allowlist entry. Exact guide+3screens were added; the entire affected media suite then passed67tests in7.70s. The initial full-run failure is preserved, not renamed PASS. It started before the one PostgreSQL-specific query correction. Its result must be reported with the exact post-correction6test and native11test supplement, not described as loading that corrected query.

## Independent review corrections

- Missing method for method-specific signatures and mismatched device-window event IDs no longer count as complete true negatives.
- Device composite scope, policy proof source/contributor closure, active eligibility and approval-reason audit corrected.
- Mixed complete/insufficient device scopes report partial; metric units stay distinct. Missing WAF prerequisites are explicit. DDoS overlap uses ordered window processing.
- Failed integration probes first demonstrated private derived Finding/story disclosure and omitted-rule retirement after a capture budget. Producers now retain lineage; every examined consumer rechecks it. Omitted, unreadable or incompletely evaluated rules retain prior findings.
- Independent probes found story-save source-ledger loss and Golden-list metadata disclosure; both are fixed with permanent regressions.
- Copied rule definitions/exports retain transitive sources. New runs and reports containing retained derived findings also retain original source authority even without the old runtime pin.
- Revocation between capture and successful finish prevents publication; recording failed/cancelled completion remains possible.
- Different completely evaluated partitions settle independently; an incomplete partition of the same rule prevents incorrect global retirement.
- Existing report/run bytes remain unchanged. Legacy content-package approval bridges exact original receipt/version rather than rewriting history.
- Finite review scope is closed. Broad new audits are not used to keep reopening P2.

## Next checkpoint and remaining environment gates

P2 is ready to commit. Continue P3→P4→P5 in the approved order. No new release ZIP, PR or prerelease has been produced yet.

Physical LTSC2019 build17763, administrator services,16GB concurrent qualification, production data and operational acceptance remain separate. Previous intermittent History503 and four older updater permission-metadata failures remain root-cause-unresolved; subsequent successful tests do not close them.
