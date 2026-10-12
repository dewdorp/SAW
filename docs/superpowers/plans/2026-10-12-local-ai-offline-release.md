# Local AI and Offline Release Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development for independent components and verification-before-completion before claims or publication. User delegated routine design and implementation choices; do not repeat permission requests already covered by the task.

**Goal:** 별도 반입 모델을 검증·선택해 폐쇄망 SAW에서 CPU로 실행하고, 모델을 제외한 실제 설치 매체를 비공개 GitHub 배포물로 제공한다.

**Architecture:** Claude 기반 새 작업본의 기존 Assistant/권한/감사/API에 모델팩 관리층을 연결한다. 모델팩과 본체 release manifest를 분리하며 본체에는 Python·의존성·빌드 UI·PostgreSQL·OpenSearch·PCAP·native 추론 실행기를 포함한다. Foundation BASE 생성과 운영 답변 채택은 별도 상태다.

**Tech Stack:** Python3.12/FastAPI/SQLAlchemy, React/TypeScript, PostgreSQL16, OpenSearch2.19.6, Windows CPU llama.cpp, PowerShell5.1.

**Spec:** ../../LOCAL-AI-DESIGN.md plus the user's 2026-10-12 addendum recorded in STATE.md.

## Global Constraints

- F:\claude\saw is read-only. Modify F:\codex\SAW-Claude-main only.
- Target: Windows10 Enterprise LTSC2019 x64/build17763, no GPU, 16–32GB RAM, no Internet/WSL2/Docker. Development-host execution is not target certification.
- Foundation-Sec-8B BASE revision9e6bb1f70b402e55bbf68cfd7abf88458daf09b3 remains the initial candidate. No automatic model replacement or model-weight publication.
- No operational data, credentials, secrets, local stores, or models in Git/GitHub/package. Synthetic tests only; no automatic training or response actions.
- Four-eyes approvals and existing Evidence/Finding authorization remain. Activation does not grant production approval or prove quality.
- No target npm build/compiler/network bootstrap. Include actual locked runtime payloads and licenses; identify any missing rights/files precisely.
- Preserve EOL. UI/user docs Korean; code/comments/commit messages English.

## Review Focus

- A model directory can contain traversal, links, unexpected DLLs, or modified weights: reject outside the sealed manifest before execution (Task2).
- Same user may lack another investigation's membership or experience may expire: filter before RAG scoring/prompt construction (Task1).
- BASE output can be malformed, uncited, or hallucinated: reject invalid structure/references and never claim factual quality from syntax (Task1).
- A model switch may fail or overlap an active inference: keep the prior selection, bound concurrency, and audit the actual outcome (Task2/3).
- Installation can run under a fresh path without cached runtimes: verify all media, install/restart using included files, and exclude development state (Task4).

### Task1: Authorized context and honest output (root)

**Files:** saw/llm/service.py, saw/knowledge/similar.py, tests/api/test_ai_context_boundary.py.
**Interfaces:** provider().generate(LLMRequest) remains; response adds output_status, execution_status, claim_support. Context accepts Principal and excludes inaccessible/stale knowledge before scoring.

- [x] RED: private investigation and inaccessible/expired/deprecated Experience never reach a capturing provider; authorized approved generalized Experience does.
- [x] RED: malformed JSON/answer/citations or foreign citation yields an empty rejected answer; valid cited output remains an unverified draft.
- [x] Implement current-source authorization, masking and output validation; selected_provider binding after Task2 without implicit fallback to another LLM.
- [x] Run focused tests, then whole backend regression before commit.

### Task2: Model pack and bounded CPU runtime (cpu_model_integration)

**Files:** saw/llm/model_packs.py, cpu_provider.py, windows_runtime.py, admin model router, config/authz, migration if persisted DB state requires it; focused tests.
**Interfaces:** GET /admin/local-models; POST /validate {pack_id}; POST /activate {pack_id,reason}; POST /deactivate {reason}. selected_provider(settings, session?) returns CPUProvider|None. API exact fields are in the design spec.

- [x] Define strict model/runtime/file manifest and supported BASE/Instruct serialization; tests for paths/hash/template/corruption.
- [x] Implement admin permission and audited atomic selection, real synthetic probe, failed-switch preservation.
- [x] Implement CPU1/time/context/token/memory and Windows process/network containment; never execute model repository code or arbitrary arguments.
- [x] Fresh-verify existing designated Foundation artifacts; run one bounded synthetic inference through the new provider. Record execution separately from output quality.
- [x] Run unit/API failure tests and native smoke; no synthetic replacement model credited as Foundation success.

### Task3: Model management UI (claude_ui_review)

**Files:** apps/web/src/pages/LocalModels.tsx and test; App/Admin/Shell minimum links; Assistant output indicators as needed.
**Interfaces:** Task2 endpoints; ai.models.manage permission. Task1 output_status/execution_status/claim_support.

- [x] RED: unauthorized access, missing runtime/model, validation status, reason-required switch, failure retains previous selection, output rejection.
- [x] Implement Korean view for separate media intake, selected model, limits, actual generation and operational adoption distinction.
- [x] Full vitest/tsc/build and real browser using synthetic data; save screenshots and account cleanup.

### Task4: Model-free real installation media (packaging agent + root)

**Files:** deploy/windows build/install/verify scripts, dependency pins/notices/manifest, tests/unit/test_windows_bundle.py and new packaging tests, installation guide.
**Interfaces:** release manifest lists all payload hashes/versions/size; model inbox optional at install. App functions without models.

- [x] Inventory only public runtime artifacts; verify official source/pins/redistribution terms. Resolve missing payloads within authorized scope.
- [x] Build immutable fresh output with built UI, actual Python/dependencies/PG/OS/PCAP/native AI runtime and no model weights/private state.
- [x] Tests reject missing/hash-invalid payload, unsafe paths, online install steps, absent built UI, accidental model/data inclusion.
- [x] Verify/extract/install to fresh path on development host, first account workflow, synthetic analysis/save/stop/restart; mark clean LTSC target test separately if unavailable.

### Task5: Private GitHub distribution (root)

- [x] Inspect tracked files/history and release payload for private data/credentials/models. Keep only intended source/docs/binaries and notices.
- [x] Create private dewdorp/SAW (or collision-safe explicit new name), push the validated branch, create a versioned prerelease with notes.
- [x] Upload real archive(s), release manifest/checksums, install/model intake guide. Split large media with deterministic reassembly if GitHub limits require it.
- [x] Verify repository visibility, release assets size/digest and download location. Report links, local hashes and unresolved target/quality/approval gates.
## Execution notes (2026-10-12)

Task1–3 complete as implementation/contract/native/browser verification, with Foundation quality not adopted and the real Assistant investigation request failing safely (reason not retained). Actual short native generation succeeded. Follow-up fixed diagnostics are in progress. Task4 uncovered a real restart data-loss bug; release waits for request durability and explicit flush verification. Service runtime environment code was rejected by automatic approval review and awaits the user's specific approval. Source publication and remaining model-free media work continue independently.

The user explicitly approved service code/configuration changes only. Resume the PostgreSQL WinSW/runtime environment implementation and synthetic tests; do not install/register/start Windows services or change the firewall on this host. Prior automatic-review rejection is resolved only for this code scope.

Final development-host verification: backend743 passed/2 skipped in184.95s; UI115 passed plus tsc/build; separate PostgreSQL48 passed. Candidate4 standalone installation, strict TLS, synthetic log/PCAP, restart preservation and isolated restore passed. Final immutable archive and private prerelease publication remain the next steps. This does not certify clean LTSC or multi-user service deployment.

Published private prerelease https://github.com/dewdorp/SAW/releases/tag/v0.1.0-pilot.20261012 from frozen commit f10a375. Eight remote asset sizes and SHA256 digests match local verified files; tag target verified. The archive remains immutable. Remaining target/operational/quality gates are recorded in STATE.md.
