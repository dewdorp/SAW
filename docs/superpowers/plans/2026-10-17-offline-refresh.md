# Offline release refresh implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Deliver current model-free offline media and tested recovery from a stopped application update.
**Architecture:** Reuse immutable release manifests and existing native runtime. Update only application payload after a protected complete cold snapshot; restore the whole installation explicitly.
**Tech Stack:** Python3.12, PowerShell5.1, PostgreSQL16.15, OpenSearch2.19.6.
**Spec:** docs/superpowers/specs/2026-10-17-offline-refresh-design.md

## Global Constraints
- Original F:/claude/saw and operational bank data stay untouched.
- No model weights, credentials, mutable stores or caches enter public media.
- No actual privileged service install/firewall modification.
- Existing runtime pins unchanged; no source build on target; no internet fetch during install.
- Preserve file EOL; user-facing guidance Korean; code/comments English.
- Cold restore is pre-update point recovery, not lossless merge of post-update changes.

## Review Focus
- Active/unowned process and port detection must refuse mutation.
- Reparse, sibling/path alias, external configured storage and modified source cannot escape verification.
- Copy failure or altered recovery payload cannot produce a completed update/restore receipt.
- Runtime/dependency drift cannot be hidden by application-only copying.
- New DB schema must never be paired with old application during claimed rollback.

### Task 1: Update/recovery boundary
Files: saw/devtools/offline_update.py, deploy/windows/update.ps1, tests/unit/test_offline_update.py.
Consumes: saw.offline-release/1 baseline/new media and a stopped installation.
Produces: explicit plan/apply/restore commands, protected complete recovery tree and non-secret receipt.
- [x] Write/run refusal and recovery tests before implementation (expected missing implementation FAIL).
- [x] Implement checks, complete snapshot and app-only replacement; explicit whole-root recovery preserving failed tree.
- [x] Focused tests pass, independently inspect behavior and run whole server suite before commit.

### Task 2: Complete fresh media
Files: saw/devtools/build_release.py, deploy/windows/install.ps1, tests/unit/test_release_manifest.py, public install/update guides.
Consumes: pinned inputs/native runtime plus Task1 scripts.
Produces: new complete manifest media, installed-source identity and current guide set.
- [x] Test current startup guide and shipped update/runtime identity before changing assembly.
- [x] Build UI and assemble fresh candidate from verified pins.
- [x] Fresh user-mode install, TLS/MFA/log/PCAP/behavior/restart, legacy update/restore/reapply.
Expected: explicit receipts from installed runtime, no developer Python/Node dependency at target.

### Task 3: Seal and publish
Files: validation/STATE/HANDOVER/PROGRESS plus release assets.
Consumes: verified candidate and final source commit.
Produces: ZIP, sha256, receipt, guides and private GitHub prerelease.
- [x] Independent final review and fix important findings with regression tests.
- [x] Full checks; preserve known unresolved History503/model/LTSC gates.
- [x] Seal archive, compare tested executable payload and every ZIP entry hash.
- [x] Publish to existing private repository; verify remote asset digests and source commit.
