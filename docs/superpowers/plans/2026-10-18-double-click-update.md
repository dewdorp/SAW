# Double-click offline update implementation plan

> For agentic workers: use test-driven-development and verification-before-completion. The user has delegated routine design/execution choices; implement continuously in the existing isolated Claude-copy repository. Do not operate the user's installation.

**Goal:** Let an operator update and restore an existing SAW installation by double-clicking a local launcher and using Korean buttons, preserving accounts, MFA, permissions, databases, indexes, original evidence, keys and configuration.

**Architecture:** Windows PowerShell 5.1 WinForms is the local front end, without downloads, Python prerequisites or a new web listener. A worker bootstraps a verified embedded Python outside the installation and invokes a standard-library orchestrator. The orchestrator reuses offline_update's cold-update/recovery contracts and holds the same maintenance lock across validation, stop, mutation, start and health checks.

**Tech stack:** Existing pinned embedded Python 3.12.10, Windows PowerShell 5.1/.NET WinForms, existing offline_update/runtime_health; no new dependency.
**Spec:** Current user instruction and the interface/constraints below.

## Constraints
- Deployment target remains LTSC 2019 x64/build17763, offline, no Docker/WSL; actual Windows11 native tests are recorded separately.
- Existing isolated copy F:/codex/SAW-Claude-main on codex/detection-packs is reused. Original F:/claude/saw and user C:/SAW are never mutated.
- No password reset, account creation, database initialization, automatic deletion, service registration or security weakening.
- No manual hash comparison. Whole-media automatic verification before worker code/runtime execution remains required.
- New media, installation, recovery and worker/status directories are separate; no writes into media.
- UI work does not replace existing CLI. Older manifest/baseline remains supported.
- Update/restore operations preserve partial artifacts on failure; no automatic rollback, destructive cancellation, retry or failure-as-no-change claim.
- Restore requires the operator's point-in-time acknowledgement. Newer records are retained separately, not merged.

## Interface shared by tasks
- Python CLI: app/saw/devtools/desktop_update.py inspect|apply|restore|start --install-root PATH --bundle-dir PATH --state-dir PATH [--baseline-bundle-dir PATH] [--recovery-point PATH] [--maintenance-confirmed] [--confirm-point-in-time-recovery].
- Action inspect is read-only apart from a private status file. apply stops/checks/snapshots/applies/starts. restore stops/restores/starts. start safely restarts a verified installed source after an operator request.
- state.json (atomic, private): schema=saw.desktop-update/1, action, phase, status=working|ready|completed|failed, message (safe Korean UI text), code (safe stable diagnostic), install_root, recovery_point if set, mode=service|noadmin when known, requires_admin, app_url, optional plan/retained_installation, needs_acceptance.
- Exit 0 plus ready (inspect) or completed (mutation) are required for UI success. Missing/invalid/mismatched final result is failure.
- Worker PowerShell: update-worker.ps1 -Action inspect|apply|restore|start -InstallRoot PATH -BundleDir PATH -StateDir PATH [-BaselineBundleDir PATH] [-RecoveryPoint PATH] [-MaintenanceConfirmed] [-ConfirmPointInTimeRecovery].
- StateDir is created with current-user/SYSTEM protection by the UI outside media/install/recovery. The worker validates this and uses it as its current directory. It records bootstrap failures generically without disclosing output.
- Root launcher UPDATE-SAW.cmd starts update-ui.ps1 (WinForms), which consumes update-ui.psm1. Full media remains immutable.
- UI has browse buttons, inspection, update, restore and safe start actions, progress phases/elapsed time, no fake percentages. A maintenance checkbox is required for stop/apply; a separate restore acknowledgement explains account/data rollback. Closing during a worker operation does not terminate it.
- Elevation is explicit and only for service mode. NoAdmin remains the original Windows user.
- Install ownership, service executable/config paths and tracked PID ownership are checked before any stop. Uncertain/foreign process ownership fails closed.
- Healthy completion requires verified TLS API + correct OpenSearch cluster readiness + PostgreSQL readiness, not a mere process/service Running flag. Login/MFA acceptance remains an operator check.

## Review focus
1. A mismatched install/service/PID must not stop another application.
2. Multiple windows or the old CLI must not mutate the same installation concurrently.
3. Interrupted/partial apply and restore must retain usable snapshots and avoid blind restart.
4. Unicode/spaces/metacharacters, directory nesting, reparse points, foreign volumes and insufficient restore headroom must fail safely.
5. Old installed manifests/baselines, private worker status and TLS failure must not be silently bypassed.

## Task 1: orchestration (agent install_independent_review)
Files: saw/devtools/desktop_update.py; tests/unit/test_desktop_update.py.
Tests first: no mutation without acknowledgement; wrong/missing/ambiguous mode; foreign PID/service; same-lock contention; failed stop/flush/plan/apply/start; no false success; safe state without secrets; recovery acknowledgement; whole-root preservation delegated to existing backend.
Implementation: lock once, invoke backend locked cores without acquiring the same lock twice, validate installed source/runtime before stop; bounded safe diagnostics and runtime-health reuse. Do not edit existing engine unless essential and report ownership needs first.
Verification: focused tests and Windows-specific behavioral subprocess tests, then integration by root.

## Task 2: launcher/UI/worker (root)
Files: deploy/windows/UPDATE-SAW.cmd, update-ui.ps1, update-ui.psm1, update-worker.ps1; tests/unit/test_update_ui.py.
Tests first: bootstrap argument and media/state validation, UI action gating, result identity checking and process-completion behavior. Tests invoke real PowerShell functions on synthetic paths.
Implement WinForms UI plus hidden worker; maintain Korean copy and PS5.1 encoding. No target-side source compilation.
Verification: PS5.1 parser, actual form creation/render and available native UI interaction, worker real synthetic inspect/update/restore.

## Task 3: packaging contract (agent update_guide_review)
Files: saw/devtools/build_release.py, release_manifest.py; deploy/windows/verify-bundle.ps1 if needed; tests/unit/test_release_manifest.py.
Tests first: conditional GUI contract required files, old baseline compatibility, root/app copies, missing/tampered GUI.
Add conditional metadata desktop_update_ui=1 (not universal REQUIRED) and exact file copying. No existing sealed media mutations. Root supplies final user guide paths once created.
Verification: focused Python/PowerShell validator tests and actual new candidate assembly by root.

## Task 4: native rehearsal and final review
Run backend suite and web vitest/tsc (no runtime overlap), then new-media Windows11 synthetic update/start/HTTPS-MFA/preservation/restart/restore/preservation. Run an independent security review over the entire diff. Test original fixture only with designated ownership, never operational inputs.
Document fresh results and unresolved LTSC/admin gates; screenshots distinguish real GUI from illustrative guide.

## Task 5: delivery
Update guide, STATE/PROGRESS/HANDOVER. Commit tested code, assemble immutable final full model-free media in a fresh directory; seal against tested candidate executable payload. Publish a separate prerelease e.g. v0.1.0-pilot.20261018.1 with no replacements of existing releases/assets. Verify remote sizes/digests/commit without requiring manual user comparison.

## Ledger
- Start HEAD 9bdb831; clean isolated copy. Existing live updater is offline_update.py, not release_update.py.
- Ruling: retain automatic integrity checks and use a native UI (no web port/CSRF surface/new dependencies). Existing user delegation supplies authorization for routine design decisions.
- Ruling: hold the existing backend maintenance lock in-process and call its already-locked implementation, avoiding parent/child byte-lock self-deadlock.
- Ruling: staging/backup/status stay outside immutable media and installation; all failure artifacts are preserved.
- Task3 complete: conditional media contract;61 tests PASS. Worker bootstrap17 PS5.1 subprocess tests PASS. Web177 PASS, tsc exit0. Native flow not yet run. Core/UI still in progress; full suite and independent review pending.
- Native complete: candidate2 actual Form update 474.55s/restore 406.54s; TLS/MFA/data preservation and later-file retention PASS; synthetic account disabled and native stores stopped. Candidate1 ownership failure was fixed and retained as evidence. Final media/publishing remain next.
