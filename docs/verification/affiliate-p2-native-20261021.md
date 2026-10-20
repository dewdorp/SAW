# P2 native verification — 2026-10-21

Result: **21 passed, 0 failed, 0 skipped**, exit 0. Actual PostgreSQL 16.15 and OpenSearch 2.19.6 were used. Pytest reported 194.25 seconds; the harness measured 195.078 seconds for the test process and 433.39 seconds including verification, startup and shutdown.

Evidence:
- Harness: .qa/affiliate-p1-20261020/run-p2-native.py
- Fresh fixture: .qa/affiliate-p1-20261020/native-p2-20261021-r1
- Public receipt: native-p2-20261021-r1/receipt.json
- Redacted test output: native-p2-20261021-r1/logs/pytest.log
- Per-test public progress: native-p2-20261021-r1/logs/test-progress.jsonl
- Additional populated migration test: .qa/affiliate-p1-20261020/test_p2_native_schema.py

## Actual exercised paths

1. Fresh migration/model consistency through current head.
2. Approved source context → parser normalization → saved firewall analysis.
3. Actual indexed source filtering by organization, device and time; distinguish zero matches, unknown data and empty scope.
4. Scope ACLs, active ingest exclusion, idempotency and immutable old runs.
5. Cancellation, source mutation and ACL revocation during analysis prevent publication; retry and duplicate delivery preserve job/run ownership.
6. Partial/failed execution records and analysis candidates do not rewrite current findings.
7. Selected event-unit truth is separate from investigation verdicts; unlabeled or missing inputs do not become true negatives.
8. Exact selected-proof approval → activation → rollback preserves version identities.
9. Source ACL hides private case definitions and saved proofs.
10. Populated PostgreSQL 0016 → 0017 → 0018 upgrade: valid legacy head admitted, incomplete evidence remains inactive, original two versions preserved, policy/approval/truth tables exist and repeated head upgrade succeeds.

## Isolation and closure

- Dedicated loopback ports: PostgreSQL 56471; OpenSearch HTTP 59471 / transport 60471.
- Fresh PostgreSQL/OpenSearch data, logs, config, temporary directories and generated synthetic credentials stayed inside the fresh fixture. No operational source data or accounts were used.
- Previously retained runtime binaries were reused read-only after 23,195 files were verified against the public PostgreSQL/OpenSearch/nori archives. Previous service data/config/credentials were not reused.
- Hidden user processes only; no Windows service installation or administrator SCM mutation.
- OpenSearch heap 512 MiB; disk watermarks remained enabled at 20/12/6 GiB, with 25 GiB minimum free-space preflight. Actual initial free space was 43,163,193,344 bytes.
- OpenSearch flush failed shards: 0.
- Owned OpenSearch and PostgreSQL processes stopped successfully.
- All three owned ports closed; stop_complete=true.
- One existing dependency warning: Starlette TestClient's httpx deprecation. No test failure or skipped native test.

## Scope limits

This verifies the listed synthetic flows on the current development host with actual PG/OpenSearch user processes. It is not clean LTSC 2019 installation acceptance, administrator service/ACL deployment acceptance, TLS/S3/Redis/restore acceptance, production data acceptance, 16 GiB performance qualification, or a release/operational approval.

Root is independently addressing later derived-read ACL and pinned-Sigma retirement review findings; this receipt records the exact earlier test invocation and must not replace the final full regression after those changes. The full current suite and browser/release gate remain parent-owned.
