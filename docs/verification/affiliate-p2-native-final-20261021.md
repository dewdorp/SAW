# P2 final native source-lineage supplement — 2026-10-21

**Final result: 11 passed, 0 failed, 0 skipped**, actual PostgreSQL 16.15 + OpenSearch 2.19.6. This supplements the earlier P2 native21 run with the final derived-source, completion, copying and coverage changes.

Final fixture: .qa/affiliate-p1-20261020/native-p2-20261021-r3
Harness: .qa/affiliate-p1-20261020/run-p2-native-final.py
Public receipt: native-p2-20261021-r3/receipt.json
Redacted output: native-p2-20261021-r3/logs/pytest.log
Public progress: native-p2-20261021-r3/logs/test-progress.jsonl

Exact selection, independently collected as 11:
- tests/api/test_derived_run_lineage.py — 2.
- tests/api/test_sigma_scope_completion.py — 4.
- tests/api/test_detection_source_lineage.py — 5.

## Actual native defect and correction

Fresh r2 first returned 8 passed /1 failed /2 not run because -x stopped after the first failure. The real PostgreSQL error was:
    psycopg.errors.UndefinedFunction: could not identify an equality operator for type json

The compatibility retirement lookup selected DISTINCT across Detection columns including JSON source/deployments. SQLite accepted it; PostgreSQL correctly could not perform whole-row JSON equality.

The correction was limited to that lookup in saw/detection/auto.py: a correlated EXISTS over the target Finding identifiers replaces whole-row DISTINCT. Existing active=None condition, investigation scope, bounded MAX_RULES order, private-source target fence and source ACL checks stay intact.

Failure evidence is preserved at native-p2-20261021-r2/receipt.json and logs/pytest.log. That fixture stopped normally. It is not reported as a successful run.

After correction:
- Default synthetic regression: detection_source_lineage plus explicit inactive-rule retirement = 6 passed in7.95s.
- Fresh r3 actual PG/OpenSearch: all11 passed; pytest113.97s, harness test duration114.969s; full163.547s.

## Covered final behaviors

- A retained derived finding captured into a new run without its original rule pin still requires every private source in history and saved reports.
- Unreadable derived input cannot be captured/published.
- Two different completely evaluated scope/rule combinations both settle.
- One incomplete scope of the same rule prevents global settlement and retirement.
- Actual scenario flow keeps underlying source closure; target-only serialization is denied.
- Revocation after capture prevents successful finish while allowing failure sealing.
- Copying a Finding into a durable rule requires complete source authority before any write.
- The copied rule keeps its source closure; later revocation prevents definition read, edit and legacy replay.
- Omitted active rules beyond capture/evaluation budget and inaccessible inactive rules retain prior findings.
- Coverage does not expose private-derived ATT&CK observation counts.

## Isolation, versions and shutdown

Each r2/r3 run used fresh data/config/log/temp/credentials under its own approved QA root. The retained public runtime was reused read-only only after verifying23,195 files against the exact same three public archives as the earlier native21 receipt. Initial r3 free disk:42,966,327,296bytes.

Only dedicated loopback ports56471/59471/60471 were used; source search found no uses of these ports in tests/deploy/windows and exclusive-bind preflight ran before startup. Hidden user processes only; no installed service, original Claude workspace, operational data or credential file was modified.

Verified final receipt:
- opensearch_flush_failed_shards=0.
- opensearch_stopped=true.
- postgresql_stopped=true.
- ports_closed=true.
- stop_complete=true.
- One existing Starlette TestClient httpx deprecation warning.

This is final native validation of the selected11 functional paths on the current host, not clean LTSC2019/admin-service/TLS/S3/Redis/backup-restore/production/16GiB concurrent-load acceptance. Root's full regression started before the single PostgreSQL-specific query correction; report it together with these exact post-correction regressions, rather than falsely claiming the long full run loaded the corrected query.
