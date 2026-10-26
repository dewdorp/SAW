# Pinned dependency update and whole recovery implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans. Existing continuous implementation and release authorization applies; this is an incremental updater repair.

**Goal:** Allow the verified prior 0014 release to update to the current release with its exact XlsxWriter 3.2.9 dependency, and restore the previous accounts, data and runtime together.

**Architecture:** Share one exact runtime transition policy between command and desktop paths. Validate the installed old profile before applying, the complete candidate after applying, and the verified recovery profile after restoring. Add dependencies only after a verified full cold backup; preserve failed attempts and newer data when restoring.

**Tech Stack:** Python 3.12.10, Windows PowerShell 5.1, existing manifest, ACL, maintenance lock and recovery journal.

**Spec:** Existing user requirement: offline double-click update, account/data preservation, full rollback; current release dependency comparison recorded in the private QA receipt.

## Constraints
- Only XlsxWriter 3.2.9 wheel 175315 bytes, SHA-256 9a5db42bc5dff014806c58a20b9eae7322a134abb6fce3c92c181bfb275ec5b3 may be added.
- Requirements transition only ce97ae90f25093ba9f574d41ede60457d8cbd3a2287cd48cdb035d2be15b5f1f to bf75190bc504caaffca54e3a164d4c20d63ebcbc8d50d9a17647893861149c38.
- All other runtime rows and pins remain equal. No network, external install, generic runtime relaxation or automatic recovery that discards later data.
- Do not touch original Claude/operational installations, private source data, old releases or preserved failure fixtures. New native execution uses approved synthetic roots only.

## Review focus
- Extra or changed runtime files: refuse before stopping or mutating.
- Old installation must not require a newly added wheel before application.
- Dependency staging failure: no live runtime mutation; complete snapshot remains usable.
- Publication interruption: full recovery must accept only exact known partial additions and preserve newer state.
- Legacy installation with explicit baseline but no installed manifest: recovery must still derive an authenticated old profile.

## Tasks
- [x] In saw/devtools/offline_update.py and tests/unit/test_offline_update.py, reproduce exact transition rejection and add positive/negative transition tests.
- [x] Implement _runtime_transition(previous,candidate), profiled _installed_runtime, verified staging/publication, marker update and recovery profile derivation. Test unchanged, exact addition, hash/size/pins/removal/extra-file refusal and restore after interruption.
- [x] In saw/devtools/desktop_update.py and tests/unit/test_desktop_update.py, reproduce old/candidate restore profile errors; route inspect/apply/start/restore through the shared policy without weakening existing access or process ownership checks.
- [x] Independently review implementation and run focused tests, then a fresh complete backend suite with immutable source fingerprints. Preserve interrupted r6 as NOT_PASS.
- [ ] Commit tested source, build fresh model-free r4 media, verify ZIP and independent extraction.
- [ ] Run fresh a5 native install, stop/restart, prior0014 update, failure and whole-restore, then installed synthetic CSV scenario/readback tests.
- [ ] Assemble exact public allowlist, create draft PR and private prerelease, verify downloaded asset hashes and preserve main/prior releases. Record real results and separate LTSC/16GB/admin/production limits.
