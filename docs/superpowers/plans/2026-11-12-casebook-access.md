# Casebook Access Correction

## Design

The 0.2.5 release contains W01–W60 worked cases, but the sidebar and command
palette omit the casebook route. Investigation links select legacy C examples,
and that detail view hides the W case reader. A successful application update
can therefore leave an analyst using only the earlier examples.

Restore a visible path to the existing worked cases: add the casebook to the
sidebar and command palette, and add an explicit platform-case action on C
detail pages. The action clears only the legacy case selection and preserves
the investigation and any worked-case deep link. Keep the existing C examples
and their evidence references intact.

This is a small navigation correction. Expanding automatic matching from
C007–C011 to W01–W60 requires executable applicability definitions and evidence
scope tests; a navigation correction must not imply that matching is implemented.
The alternative of replacing the C pack would break established references and
would not turn the authored W narratives into executable hunting rules.

## Implementation Plan

**Goal:** Make shipped platform cases reachable after upgrading from 0.2.4.

**Architecture:** Reuse `/casebook` and `PlatformCases`. No schema, source data,
updater, detector, dependency, or authentication changes.

**Tech Stack:** Existing React, React Router, Vitest and Testing Library.

**Base:** `b1d49b97c00ed96abca2553cc7653902177fa007`, whose application code is
identical to release `v0.2.5-pilot.20261111` at `1b7fd8f`.

### Task 1: Restore casebook navigation

- [x] Exercise sidebar navigation and command-palette search to `/casebook`.
- [x] Reproduce C-detail navigation to W60 using the real bundled W index/detail
  and synthetic HTTP responses; assert the return investigation is retained.
- [x] Observe the tests fail because those navigation actions are absent.
- [x] Update `Shell.tsx` and `PracticeCases.tsx`, preserving each file's line endings.
- [x] Run the related casebook tests and TypeScript check; build the web bundle.
- [x] Independently review the diff and record the verified scope below.

## Validation Record

- Before changes: 3 frontend test files / 16 tests passed. Existing React
  asynchronous update warnings were present in the practice-case test suite.
- Navigation regression: 3 added tests failed because the new actions were absent;
  after implementation, all 19 tests in the 3 selected files passed.
- Independent source review found a focus regression after changing a legacy C
  selection. The actual W60 navigation test reproduced it (RED), and a dedicated
  platform action now clears the old list focus target and focuses the page
  heading (GREEN). The ordinary case-list return behavior stays unchanged.
- Final frontend suite: `node node_modules/vitest/vitest.mjs run` — 64 files,
  431 tests passed, zero failed (21.89 seconds).
- Final TypeScript: `node node_modules/typescript/bin/tsc --noEmit` — exit 0.
- Final web build: `node node_modules/vite/bin/vite.js build` — exit 0
  (23.16 seconds). Existing React Router/async-test and large-chunk warnings remain.
- The published manifest lists 60 W details, 1 index, 120 images and 60 generated
  case ZIPs. All 181 authored JSON/image files match the published manifest hashes.
  The full Windows distribution ZIP was not downloaded or independently unpacked.
- Windows LTSC deployment and the user's running installation are outside this
  local validation. A source patch does not update an already installed server.
- No automatic W matching, detector, API, migration or runtime dependency changes
  are part of this correction. Those require the separate hunting design.
