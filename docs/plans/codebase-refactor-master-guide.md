# Codebase Refactor Master Guide

Last updated: 2026-04-30
Owner: platform architecture / Autopilot / Studio / Agent IDE / runtime services
Status: completed on 2026-04-30 with documented baseline test failures

## Purpose

This guide turns the current codebase-shape review into an executable refactor
program.

It addresses the main findings:

- several production source files have become navigational bottlenecks
- shared model and type barrels hide domain boundaries
- some UI files combine controller state, rendering, modal orchestration, and
  data transformation
- large CSS files mix unrelated surfaces behind one import
- some runtime modules have grown into sub-systems but still live behind one
  `mod.rs`
- tests and fixtures contain large, valuable harnesses that should be made more
  reusable without disrupting coverage

The goal is not to make the tree look tidy for its own sake.

The goal is to make the codebase easier to reason about, safer to modify, and
more honest about ownership boundaries while preserving behavior and public
contracts.

## Execution Record: 2026-04-30

The refactor program has been executed end to end against the target state in
this guide.

### Starting inventory

The initial large-file pass used the command in Phase 0. The largest production
bottlenecks included:

| Starting file | Lines | Outcome |
| --- | ---: | --- |
| `apps/autopilot/src/windows/AutopilotShellWindow/AutopilotShellWindow.css` | 6213 | split into owned CSS surfaces behind the original import |
| `crates/api/src/chat/html/mod.rs` | 5261 | split by semantic HTML responsibility |
| `packages/agent-ide/src/WorkflowComposer.tsx` | 5133 | reduced to a compatibility wrapper around controller/view composition |
| `crates/services/src/agentic/runtime/service/step/cognition/history/browser_snapshot.rs` | 4183 | split by browser snapshot helper family |
| `crates/api/src/chat/generation/runtime_materialization/mod.rs` | 4056 | split by artifact generation phase |
| `apps/autopilot/src-tauri/src/models/mod.rs` | 3994 | split into backend contract domain modules |
| `packages/agent-ide/src/WorkflowComposer.css` | 3910 | split into composer CSS surfaces behind the original import |
| `apps/autopilot/src/windows/ChatShellWindow/components/ArtifactHubViews.tsx` | 3907 | split into detail router and owned view files |
| `apps/autopilot/src/types.ts` | 3847 | split into frontend contract domain modules |

### Completed structural changes

- `apps/autopilot/src/types.ts` is now a compatibility barrel over
  `apps/autopilot/src/types/`, with frontend session, plugin, notification,
  local engine, artifact, governance, chat, event, knowledge, voice, and
  generated-contract modules split by domain.
- `apps/autopilot/src-tauri/src/models/mod.rs` is now a compatibility barrel
  over backend model modules for app state, atlas, capabilities, chat, events,
  knowledge, local engine, notifications, plugins, session, session
  compaction, session continuity, and voice while preserving ts-rs exports.
- `crates/api/src/chat/generation/runtime_materialization/mod.rs` is split by
  direct authoring, recovery, deterministic repair, inference, parsing,
  preview, refinement, repair, timeouts, and tests.
- `crates/api/src/chat/html/mod.rs` is split by terminal closure, markup scan,
  view controls, detail regions, sectioning, placeholder detection,
  focusability, and font safety.
- `apps/autopilot/src-tauri/src/kernel/session/mod.rs` is split into history,
  projection, compaction, compaction policy, team memory, rewind, remote, and
  summaries.
- Cognition history browser snapshot and signal helpers are split into smaller
  modules by helper and signal family. The broad file-level dead-code allowance
  in `browser_snapshot.rs` was removed.
- `packages/agent-ide/src/WorkflowComposer.tsx` is a compatibility wrapper over
  `WorkflowComposer/` controller, view, content, type, and support modules.
- `WorkflowNodeBindingEditor.tsx` is split into a thin host plus binding
  sections, local types, and binding option/default helpers.
- `ArtifactHubViews.tsx` is a compatibility barrel over
  `ArtifactHubViews/ArtifactHubDetailView.tsx`, source-control views,
  runtime/governance views, local types, and helpers.
- Large CSS entrypoints were physically split while preserving class names and
  cascade order:
  `AutopilotShellWindow.css`, `WorkflowComposer.css`, `ChatSurface.css`, and
  `packages/workspace-substrate/src/style.css`.
- Additional over-threshold production modules were split to satisfy the final
  inventory:
  `crates/api/src/chat/payload/mod.rs`,
  `crates/api/src/chat/domain_topology/mod.rs`,
  `crates/drivers/src/browser/dom_ops/accessibility.rs`, and
  `crates/types/src/app/consensus/collapse/proofs.rs`.
- Large test and fixture files were split into scenario-family include parts,
  including guardian registry tests, chat direct-author and payload-validation
  tests, guardian majority tests, CLI capabilities and computer-use harnesses,
  validator consensus/finalize tests, cognition history tests, Autopilot
  workflow-project/session-truth tests, and consensus type tests.

### Final inventory

The final large-file pass used the same Phase 0 command. The only file still
over 3000 lines is:

| Final file | Lines | Disposition |
| --- | ---: | --- |
| `scripts/run-agent-model-matrix.mjs` | 3607 | intentional exception: operational benchmark/model-matrix runner, not production source |

The largest remaining production files are under the threshold, including:

| Final production file | Lines |
| --- | ---: |
| `apps/autopilot/src-tauri/src/kernel/capabilities/mod.rs` | 2990 |
| `packages/agent-ide/src/WorkflowComposer/controller.tsx` | 2989 |
| `crates/drivers/src/browser/dom_ops/accessibility/capture.rs` | 2911 |
| `apps/autopilot/src/windows/ChatShellWindow/styles/Chat.css` | 2860 |
| `apps/autopilot/src-tauri/src/project/runtime.rs` | 2797 |

The largest remaining test or fixture file is also under 3000 lines:
`apps/autopilot/src/windows/ChatShellWindow/viewmodels/contentPipeline.test.ts`
at 2964 lines.

### Verification results

| Command | Result | Notes |
| --- | --- | --- |
| `cargo fmt --package autopilot` | pass | backend model/session formatting |
| `cargo test -p autopilot models::` | pass | ts-rs exports and split model modules |
| `cargo test -p autopilot kernel::session::tests` | pass | split session kernel modules |
| `cargo check -p ioi-drivers` | pass | accessibility split compiles |
| `npx tsc -p apps/autopilot/tsconfig.json --noEmit` | pass | substitute for missing workspace typecheck script |
| `npx tsc -p packages/agent-ide/tsconfig.json --noEmit` | pass | substitute for missing workspace typecheck script |
| `npm run build --workspace=apps/autopilot` | pass | includes workspace substrate and Agent IDE prebuilds |
| `npm run build --workspace=@ioi/agent-ide` | pass | WorkflowComposer and binding editor split compile |
| `npm run build --workspace=@ioi/workspace-substrate` | pass | CSS split import paths compile |
| `npm run typecheck` | pass | root typecheck, workspaces with missing scripts skipped by npm |
| `cargo test -p ioi-consensus aft::guardian_majority` | pass | compiled with 0 matching tests |
| `cargo test -p ioi-cli --test benchmark_throughput --no-run` | pass | split benchmark helper compiles; one dead-code warning remains |
| `cargo test -p ioi-cli --test capabilities_suite_e2e --no-run` | pass | split capabilities fixtures compile with existing warnings |
| `cargo test -p ioi-cli --test computer_use_suite_e2e --no-run` | pass | split computer-use workflow backend compiles with existing warnings |
| `npm run typecheck --workspace=apps/autopilot` | script missing | workspace has no `typecheck` script; direct `tsc` passed |
| `npm run typecheck --workspace=@ioi/agent-ide` | script missing | workspace has no `typecheck` script; direct `tsc` passed |
| `cargo test -p ioi-api chat::tests::direct_author` | baseline failures | compiles; 44 passed, 19 failed; existing direct-author expectations fail unchanged by code movement |
| `cargo test -p ioi-api chat::tests::payload_validation` | baseline failures | compiles; 52 passed, 10 failed; existing payload-validation expectations fail unchanged by code movement |
| `cargo test -p ioi-api chat` | baseline failures | compiles; 214 passed, 33 failed, 1 ignored; failures match existing chat expectation drift |
| `cargo test -p autopilot` | baseline failures | 457 passed, 11 failed, 3 ignored; failures are existing chat routing/status, data-count, `/bin/sh` chmod, and loopback-target expectations |
| `cargo test -p ioi-services cognition` | baseline failures | compiles; 195 passed, 37 failed; failures are existing cognition behavior/default expectation drift |
| `cargo test -p ioi-types` | baseline failures | compiles; 155 passed, 6 failed; failures are existing consensus collapse/proof expectations |
| `cargo test -p ioi-validator standard::orchestration::consensus::tests` | baseline compile failures | existing validator tests fail to compile on private-field expectations and an unrelated `AgentState.execution_ledger` initializer |

Generated files under `apps/autopilot/src/generated/autopilot-contracts/` were
updated by ts-rs export tests and were not manually edited.

### Intentional exceptions and residual debt

- `scripts/run-agent-model-matrix.mjs` remains over 3000 lines because it is an
  operational benchmark runner outside the production source target.
- Some broad dead-code allowances outside the split browser snapshot helper
  remain for future focused cleanup where visibility can be narrowed without
  changing behavior.
- The requested workspace-specific npm typecheck commands do not exist. Direct
  package `tsc --noEmit` checks were used to verify the same TypeScript
  surfaces.

## Scope

This guide covers broad refactors across:

- Rust runtime and API modules
- Tauri Autopilot kernel and model surfaces
- TypeScript shared UI and frontend app surfaces
- CSS organization
- test harness and fixture layout
- gradual naming cleanup

It does not define new product behavior. Any user-visible change should be
treated as a separate product or feature PR.

## Starting Findings

The repository already has many good domain directories, especially in the
Rust runtime and Autopilot kernel. The problem is not a lack of folders. The
problem is that a few files still act as "everything at this layer" bins.

The most important production refactor targets are:

| Area | Current bottleneck | Primary issue | First refactor move |
| --- | --- | --- | --- |
| Studio artifact generation | `crates/api/src/chat/generation/runtime_materialization/mod.rs` | inference, direct authoring, deterministic repair, parse/retry policy, timeouts, and refinement in one file | split by execution phase while preserving exports |
| Chat HTML normalization | `crates/api/src/chat/html/mod.rs` | one large HTML repair and semantic-normalization toolkit | split into small semantic repair modules |
| Autopilot backend contracts | `apps/autopilot/src-tauri/src/models/mod.rs` | all app-facing structs, generated TS exports, runtime config, session, notification, plugin, and app state types in one file | split by domain with a compatibility barrel |
| Autopilot frontend types | `apps/autopilot/src/types.ts` | generated contract aliases plus hand-written app types plus re-exports from `@ioi/agent-ide` | split by domain with staged import migration |
| Agent IDE WorkflowComposer | `packages/agent-ide/src/WorkflowComposer.tsx` | one stateful component owns graph state, workflow state, rail state, modal state, callbacks, and render | extract controller hook and major view components |
| Agent IDE Workflow bindings | `packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor.tsx` | one component renders many binding families inline | extract binding-section components |
| Chat artifact hub | `apps/autopilot/src/windows/ChatShellWindow/components/ArtifactHubViews.tsx` | several large view components and a huge props surface in one file | move each view into `components/views` |
| Shell and workspace CSS | `AutopilotShellWindow.css`, `WorkflowComposer.css`, `ChatSurface.css`, `workspace-substrate/src/style.css` | unrelated component styles share one file/import | split physical files first, keep class names stable |
| Session kernel | `apps/autopilot/src-tauri/src/kernel/session/mod.rs` | history, compaction, team memory, remote sessions, rewind, and projection logic in one module | split by session sub-domain |
| Cognition history | `browser_snapshot.rs`, `signals.rs` under cognition history | snapshot parsing, UI target ranking, pending-state signals, success signals, autocomplete/select logic in very large helpers | split by signal family and remove broad dead-code allowances |

The review also found many large test and fixture files. Those are important,
but they should follow production splits rather than lead them unless they are
actively slowing work.

## North Star

The refactored tree should make three things obvious:

1. What domain a file owns.
2. Which exports are stable contracts versus local helpers.
3. Which tests protect the behavior of that domain.

A new contributor should be able to open a feature folder and understand the
local model, controller, view, styles, and tests without scanning thousands of
lines in unrelated surfaces.

## Non-Goals

Do not use this refactor program to:

- rewrite protocols
- change artifact generation behavior
- change UI copy or visual design
- collapse generated types into hand-written types
- rename public contract names just because they are long
- remove compatibility exports before import migration is complete
- move files across crate/package ownership boundaries without an explicit
  dependency reason

## Refactor Principles

### 1. Compatibility first

Large files that are heavily imported should become compatibility barrels before
call sites are migrated.

Example:

- keep `apps/autopilot/src/types.ts`
- move types into `apps/autopilot/src/types/*.ts`
- re-export the same names from `types.ts`
- migrate imports gradually to narrower modules
- delete the barrel only if it becomes clearly unnecessary

### 2. Split by responsibility, not by line count

Line count is a symptom. Split around a stable reason:

- one parser
- one view
- one state controller
- one contract family
- one verification policy
- one CSS surface
- one test scenario family

### 3. Preserve public names during the first pass

Renaming should come after physical splits. This keeps blame, review, test
failures, and import churn easier to understand.

### 4. Avoid mixed refactor and behavior PRs

Mechanical movement and behavior changes should not share a PR unless the
behavior change is required to make the split compile.

### 5. Every split needs a local verification command

Each refactor PR should name the smallest useful verification command, such as:

- `cargo test -p ioi-api chat::tests::direct_author`
- `cargo test -p ioi-services agentic::runtime::service::step::cognition`
- `npm run typecheck --workspace=apps/autopilot`
- `npm run build --workspace=@ioi/agent-ide`

### 6. Remove dead-code allowances only when local visibility is clear

Some current large helper modules use broad `#![allow(dead_code)]`. Treat those
as migration debt. After splitting, replace broad allowances with either:

- narrower visibility
- test-only `pub(crate)` exports
- deletion of truly unused helpers

## Recommended Sequence

### Phase 0: Guardrails and inventory

Objective: make refactors measurable and safe.

Tasks:

- create this guide as the shared plan
- record the current large-file baseline
- decide the first two target areas
- identify affected test commands before moving code
- avoid import path rewrites outside the selected target

Suggested baseline command:

```sh
rg --files -g '!node_modules' -g '!dist' -g '!build' -g '!coverage' \
  -g '!*.lock' -g '!*.json' -g '!*.bin' -g '!docs/**' -g '!outputs/**' \
  -g '!examples/**' |
  rg '\.(rs|ts|tsx|css|mjs)$' |
  rg -v '(^|/)(tests?|__tests__|fixtures?)/|(_test|\.test|tests)\.(rs|ts|tsx)$|/tests\.rs$|/tests/' |
  xargs wc -l |
  sort -nr
```

Acceptance:

- top bottlenecks are known
- each selected target has an owner and verification command
- no behavior changes yet

### Phase 1: Contract barrel splits

Objective: make domain boundaries visible without changing import behavior.

Best first targets:

- `apps/autopilot/src-tauri/src/models/mod.rs`
- `apps/autopilot/src/types.ts`

Acceptance:

- the original import path still works
- generated TS export paths still work
- narrower domain modules exist
- no product behavior changes

### Phase 2: Runtime subsystem splits

Objective: split large Rust modules that already contain clear sub-systems.

Best targets:

- `crates/api/src/chat/generation/runtime_materialization/mod.rs`
- `crates/api/src/chat/html/mod.rs`
- `apps/autopilot/src-tauri/src/kernel/session/mod.rs`
- `crates/services/src/agentic/runtime/service/step/cognition/history/browser_snapshot.rs`
- `crates/services/src/agentic/runtime/service/step/cognition/history/signals.rs`

Acceptance:

- external module exports remain stable
- tests remain in the same crate or move beside their new owner
- helper visibility becomes narrower where possible

### Phase 3: Frontend controller/view splits

Objective: make UI state and rendering easier to change independently.

Best targets:

- `packages/agent-ide/src/WorkflowComposer.tsx`
- `packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor.tsx`
- `apps/autopilot/src/windows/ChatShellWindow/components/ArtifactHubViews.tsx`

Acceptance:

- large stateful components become controller hooks plus view components
- modal orchestration is no longer interleaved with the whole page render
- component-level files have natural names and tests can target their view
  models

### Phase 4: CSS decomposition

Objective: reduce visual blast radius without renaming class contracts.

Best targets:

- `apps/autopilot/src/windows/AutopilotShellWindow/AutopilotShellWindow.css`
- `apps/autopilot/src/windows/ChatShellWindow/styles/ChatSurface.css`
- `apps/autopilot/src/windows/ChatShellWindow/styles/Chat.css`
- `apps/autopilot/src/windows/ChatShellWindow/styles/ArtifactPanel.css`
- `packages/agent-ide/src/WorkflowComposer.css`
- `packages/workspace-substrate/src/style.css`

Acceptance:

- class names remain stable
- import order is explicit
- related styles live beside the owning component or under a named styles
  folder
- screenshots or existing layout tests continue to pass

### Phase 5: Naming cleanup

Objective: remove misleading names after the new structure proves stable.

Only do this after phases 1-4 have reduced churn.

Candidate cleanup:

- replace vague `model`, `types`, or `utils` filenames with domain-specific
  names
- promote repeated prefixes into module names when possible
- remove legacy aliases after imports are migrated
- rename CSS classes only when ownership has become obvious and tests/screens
  can verify the result

Acceptance:

- rename PRs are mostly mechanical
- compatibility aliases are deprecated before removal
- public protocol names are not changed without a migration note

## Target Guide: Studio Artifact Generation

Current bottleneck:

- `crates/api/src/chat/generation/runtime_materialization/mod.rs`

Current responsibilities:

- typed JSON materialization
- direct-author raw-document materialization
- continuation and repair loops
- deterministic local HTML repairs
- inference execution and timeout wrappers
- streamed preview emission
- parse/recovery helpers
- refinement and refinement repair

Suggested destination layout:

```text
crates/api/src/chat/generation/runtime_materialization/
  mod.rs
  direct_author.rs
  direct_author_recovery.rs
  deterministic_html_repair.rs
  inference.rs
  parse.rs
  refinement.rs
  repair.rs
  timeouts.rs
  preview.rs
```

Migration steps:

1. Move timeout and token-budget helpers into `timeouts.rs`.
2. Move `execute_materialization_inference` and
   `await_direct_author_inference_output` into `inference.rs`.
3. Move direct-author recovery payload parsing and merge helpers into
   `direct_author_recovery.rs`.
4. Move local HTML deterministic repair helpers into
   `deterministic_html_repair.rs`.
5. Move raw-document parse candidates into `parse.rs`.
6. Move `refine_chat_artifact_candidate_with_runtime` into `refinement.rs`.
7. Keep `mod.rs` as the public entrypoint and re-export only the functions used
   by `generation/mod.rs`.

Do not change:

- execution strategy semantics
- direct-author fallback behavior
- trace labels
- public materialization function names
- test fixture outputs

Verification:

```sh
cargo test -p ioi-api chat::tests::direct_author
cargo test -p ioi-api chat::tests::payload_validation
```

## Target Guide: Chat HTML Normalization

Current bottleneck:

- `crates/api/src/chat/html/mod.rs`

Current responsibilities:

- terminal closure
- mismatched nesting repair
- panel/control synthesis
- detail-region payloads
- semantic sectioning
- focusability checks
- placeholder detection
- font-family safety

Suggested destination layout:

```text
crates/api/src/chat/html/
  mod.rs
  terminal_closure.rs
  markup_scan.rs
  view_controls.rs
  detail_regions.rs
  sectioning.rs
  focusability.rs
  placeholder_detection.rs
  font_safety.rs
```

Migration steps:

1. Extract low-level tag scanning into `markup_scan.rs`.
2. Extract terminal closure and mismatched nesting repair into
   `terminal_closure.rs`.
3. Extract mapped panels and view control synthesis into `view_controls.rs`.
4. Extract rollover/detail helpers into `detail_regions.rs`.
5. Extract top-level semantic sectioning into `sectioning.rs`.
6. Extract focusable element helpers into `focusability.rs`.
7. Extract placeholder detection and font-family repair last.

Do not change:

- normalized HTML output
- validation failure wording
- renderer contracts

Verification:

```sh
cargo test -p ioi-api chat::tests::payload_validation
cargo test -p ioi-api chat::tests::direct_author
```

## Target Guide: Autopilot Backend Models

Current bottleneck:

- `apps/autopilot/src-tauri/src/models/mod.rs`

Current responsibilities:

- app state
- local engine records
- capability records
- events and artifacts
- knowledge and active context
- chat artifact sessions
- session summaries and compaction
- notifications and interventions
- plugin records
- remote env/server records
- voice request/response contracts

Suggested destination layout:

```text
apps/autopilot/src-tauri/src/models/
  mod.rs
  app_state.rs
  local_engine.rs
  capabilities.rs
  events.rs
  artifacts.rs
  chat.rs
  session.rs
  session_compaction.rs
  team_memory.rs
  notifications.rs
  plugins.rs
  remote_env.rs
  server.rs
  voice.rs
  knowledge.rs
```

Migration rules:

- keep `models/mod.rs` as the barrel
- use `pub use` for every existing public type
- preserve `#[ts(export)]` paths unless the generated contract path is
  explicitly updated and committed
- move tests beside the module they validate when doing so is low-churn

Suggested first PR:

- create `local_engine.rs`, `notifications.rs`, `session_compaction.rs`, and
  `plugins.rs`
- move only type definitions and trivial defaults
- leave `AppState` in `mod.rs` until the rest compiles cleanly

Verification:

```sh
cargo test -p autopilot
npm run typecheck --workspace=apps/autopilot
```

## Target Guide: Autopilot Frontend Types

Current bottleneck:

- `apps/autopilot/src/types.ts`

Current responsibilities:

- generated contract aliases
- app-only chat types
- artifact runtime types
- session and compaction types
- notification types
- plugin types
- local engine types
- re-exports from `@ioi/agent-ide`
- small normalization helpers

Suggested destination layout:

```text
apps/autopilot/src/types/
  index.ts
  agent-ide.ts
  generated.ts
  chat.ts
  chat-artifacts.ts
  artifacts.ts
  session.ts
  session-continuity.ts
  notifications.ts
  plugins.ts
  local-engine.ts
  capabilities.ts
  traces.ts
  atlas.ts
  execution.ts
```

Migration rules:

- preserve `apps/autopilot/src/types.ts` as the compatibility barrel
- make `types/index.ts` the new domain barrel only after import paths are
  stable
- migrate hot surfaces first:
  - `ChatShellWindow`
  - `AutopilotShellWindow`
  - `surfaces/Capabilities`
  - `services/TauriRuntime.ts`
- do not hand-edit generated contracts under
  `apps/autopilot/src/generated/autopilot-contracts`

Import strategy:

```ts
// First pass: still works.
import type { AgentTask } from "../types";

// Later pass: preferred for new code.
import type { AgentTask } from "../types/session";
```

Verification:

```sh
npm run typecheck --workspace=apps/autopilot
npm run build --workspace=apps/autopilot
```

## Target Guide: WorkflowComposer

Current bottleneck:

- `packages/agent-ide/src/WorkflowComposer.tsx`

Current responsibilities:

- graph state setup
- execution state
- workflow project state
- right rail state
- bottom shelf state
- left drawer and node library state
- modal state
- workflow action callbacks
- validation/readiness callbacks
- dogfood and package state
- full JSX render

Suggested destination layout:

```text
packages/agent-ide/src/features/Workflows/composer/
  WorkflowComposer.tsx
  WorkflowComposerContent.tsx
  useWorkflowComposerController.ts
  workflowComposerConstants.ts
  workflowComposerSelection.ts
  WorkflowComposerHeader.tsx
  WorkflowComposerLeftDrawer.tsx
  WorkflowComposerRightRail.tsx
  WorkflowComposerCanvasStage.tsx
  WorkflowComposerModalHost.tsx
```

Migration steps:

1. Move constants and pure helpers out first.
2. Extract `useWorkflowComposerController` while returning the same values used
   by the current JSX.
3. Extract modal rendering into `WorkflowComposerModalHost`.
4. Extract left drawer, right rail, header, and canvas stage.
5. Leave `packages/agent-ide/src/WorkflowComposer.tsx` as a re-export wrapper
   so the package public API stays stable.

State grouping:

- project state
- graph/canvas state
- selection/config state
- validation/readiness state
- run/test state
- package/import/deploy state
- chrome layout state

Verification:

```sh
npm run typecheck --workspace=@ioi/agent-ide
npm run build --workspace=@ioi/agent-ide
```

## Target Guide: Workflow Node Binding Editor

Current bottleneck:

- `packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor.tsx`

Suggested destination layout:

```text
packages/agent-ide/src/features/Workflows/bindings/
  WorkflowNodeBindingEditor.tsx
  BindingSectionHeader.tsx
  SourceBindingSection.tsx
  ModelBindingSection.tsx
  ToolBindingSection.tsx
  OutputBindingSection.tsx
  PolicyBindingSection.tsx
  DryRunBindingSection.tsx
  bindingDefaults.ts
  bindingOptions.ts
```

Migration steps:

1. Move option arrays and default logic into `bindingOptions.ts` and
   `bindingDefaults.ts`.
2. Extract sections one at a time.
3. Keep prop names stable until the parent config modal is simplified.

Verification:

```sh
npm run typecheck --workspace=@ioi/agent-ide
```

## Target Guide: Artifact Hub Views

Current bottleneck:

- `apps/autopilot/src/windows/ChatShellWindow/components/ArtifactHubViews.tsx`

Current responsibilities:

- commit view
- branches view
- server view
- plugins view
- hooks view
- capability inventory view
- detail-view router
- broad props surface

Suggested destination layout:

```text
apps/autopilot/src/windows/ChatShellWindow/components/artifact-hub/
  ArtifactHubDetailView.tsx
  ArtifactHubDetailView.types.ts
  views/
    BranchesView.tsx
    CapabilityInventoryView.tsx
    CommitView.tsx
    HooksView.tsx
    PluginsView.tsx
    ServerView.tsx
  models/
    branchSyncSummary.ts
    commitActions.ts
```

Migration steps:

1. Move prop interface into `ArtifactHubDetailView.types.ts`.
2. Move each view component without changing JSX.
3. Move small pure helpers beside the view that uses them.
4. Keep `ArtifactHubViews.tsx` as a wrapper export until imports are migrated.

Verification:

```sh
npm run typecheck --workspace=apps/autopilot
```

## Target Guide: CSS Decomposition

Current bottlenecks:

- `apps/autopilot/src/windows/AutopilotShellWindow/AutopilotShellWindow.css`
- `apps/autopilot/src/windows/ChatShellWindow/styles/ChatSurface.css`
- `apps/autopilot/src/windows/ChatShellWindow/styles/Chat.css`
- `apps/autopilot/src/windows/ChatShellWindow/styles/ArtifactPanel.css`
- `packages/agent-ide/src/WorkflowComposer.css`
- `packages/workspace-substrate/src/style.css`

Rules:

- split files before renaming classes
- preserve import order
- keep tokens and reset-like rules in one predictable file
- keep component-specific selectors beside component-specific files when
  possible
- avoid moving a selector unless its owner is clear
- after each split, run typecheck/build and a visual smoke path

Suggested Autopilot shell layout:

```text
apps/autopilot/src/windows/AutopilotShellWindow/styles/
  index.css
  tokens.css
  shell.css
  activity-bar.css
  ide-header.css
  nav.css
  utility-pane.css
  workspace-oss.css
  inspector.css
  responsive.css
```

Suggested Chat shell layout:

```text
apps/autopilot/src/windows/ChatShellWindow/styles/
  index.css
  chat.css
  input.css
  conversation.css
  artifact-panel.css
  artifact-hub.css
  evidence.css
  responsive.css
```

Suggested Agent IDE layout:

```text
packages/agent-ide/src/features/Workflows/composer/styles/
  index.css
  composer-shell.css
  toolbar.css
  rails.css
  bottom-shelf.css
  node-library.css
  modals.css
```

Suggested workspace substrate layout:

```text
packages/workspace-substrate/src/styles/
  index.css
  tokens.css
  host.css
  rail.css
  explorer.css
  editor.css
  terminal.css
  notebook.css
  workbench-chrome.css
  responsive.css
```

Verification:

```sh
npm run build --workspace=apps/autopilot
npm run build --workspace=@ioi/agent-ide
npm run build --workspace=@ioi/workspace-substrate
```

For UI-heavy CSS moves, also capture before/after screenshots for:

- Autopilot shell
- Chat shell
- Studio artifact drawer
- Workflow composer
- workspace substrate

## Target Guide: Session Kernel

Current bottleneck:

- `apps/autopilot/src-tauri/src/kernel/session/mod.rs`

Suggested destination layout:

```text
apps/autopilot/src-tauri/src/kernel/session/
  mod.rs
  history.rs
  projection.rs
  compaction.rs
  compaction_policy.rs
  team_memory.rs
  rewind.rs
  remote.rs
  summaries.rs
```

Migration steps:

1. Extract pure summary helpers into `summaries.rs`.
2. Extract compaction record/preview logic into `compaction.rs`.
3. Extract team memory logic into `team_memory.rs`.
4. Extract remote session merge/snapshot logic into `remote.rs`.
5. Extract rewind candidate construction into `rewind.rs`.
6. Keep Tauri command functions exported from `mod.rs`.

Verification:

```sh
cargo test -p autopilot session
```

## Target Guide: Cognition History

Current bottlenecks:

- `crates/services/src/agentic/runtime/service/step/cognition/history/browser_snapshot.rs`
- `crates/services/src/agentic/runtime/service/step/cognition/history/signals.rs`

Suggested destination layout:

```text
crates/services/src/agentic/runtime/service/step/cognition/history/
  browser_snapshot/
    mod.rs
    markup.rs
    priority_targets.rs
    scroll.rs
    navigation.rs
    forms.rs
    autocomplete.rs
    selection.rs
    goal_matching.rs
  signals/
    mod.rs
    success.rs
    pending.rs
    dropdown.rs
    autocomplete.rs
    navigation.rs
    text_entry.rs
    pointer.rs
```

Migration steps:

1. Move low-level string and XML-ish parsing helpers first.
2. Move scroll/navigation helpers next.
3. Move form/select/autocomplete helpers.
4. Move success-signal builders.
5. Move pending-state signal builders.
6. Replace broad `#![allow(dead_code)]` with narrower exports or test-only
   visibility.

Verification:

```sh
cargo test -p ioi-services cognition
cargo test -p ioi-services agentic::runtime::service::step::cognition
```

## Target Guide: Consensus and Guardian Types

Current bottlenecks:

- `crates/types/src/app/guardianized.rs`
- `crates/types/src/app/consensus/collapse/proofs.rs`
- related large consensus test modules

These files are protocol-heavy and should be refactored more conservatively
than UI or application code.

Suggested split for `guardianized.rs`:

```text
crates/types/src/app/guardianized/
  mod.rs
  keys.rs
  committee.rs
  witness.rs
  observers.rs
  asymptote_policy.rs
  effects.rs
  certificates.rs
  hashes.rs
```

Suggested split for `collapse/proofs.rs`:

```text
crates/types/src/app/consensus/collapse/proofs/
  mod.rs
  recursive.rs
  continuity.rs
  bulletin.rs
  custody.rs
  publication_frontier.rs
  canonical_order.rs
  sealing.rs
```

Rules:

- preserve public type and function names
- keep canonical hash/signing bytes unchanged
- prefer pure module moves over naming edits
- run focused consensus tests after every split

Verification:

```sh
cargo test -p ioi-types
cargo test -p ioi-consensus aft::guardian_majority
```

## Target Guide: Test Harnesses and Fixtures

Large tests are not automatically bad. In this repo they often encode protocol
and runtime truth. Refactor them when the split improves reuse or reduces
review risk.

Targets:

- `crates/api/src/chat/tests/direct_author/mod.rs`
- `crates/services/src/guardian_registry/tests.rs`
- `crates/consensus/src/aft/guardian_majority/tests.rs`
- `crates/cli/tests/capabilities_suite/harness/project_fixtures.rs`

Suggested rules:

- split by scenario family, not by arbitrary line ranges
- move common builders into `fixtures.rs` or `support.rs`
- keep test names stable when possible
- do not compress readable inline fixtures into opaque macros
- only introduce helper abstractions when at least three tests share the same
  setup shape

Suggested `direct_author` layout:

```text
crates/api/src/chat/tests/direct_author/
  mod.rs
  support.rs
  raw_document.rs
  local_html.rs
  repair.rs
  streaming.rs
  validation.rs
```

Suggested `guardian_majority` layout:

```text
crates/consensus/src/aft/guardian_majority/tests/
  mod.rs
  support.rs
  asymptote.rs
  canonical_observer.rs
  canonical_order.rs
  nested_guardian.rs
  recovery.rs
```

## Naming Guidelines

### Rust modules

Prefer names that describe the owned concept:

- `compaction.rs`
- `team_memory.rs`
- `runtime_plan.rs`
- `direct_author.rs`
- `view_controls.rs`

Avoid new catch-all modules:

- `helpers.rs`
- `misc.rs`
- `utils.rs`
- `common.rs`

Existing `common.rs` files do not need immediate renaming, but new splits
should aim for clearer names.

### TypeScript files

Prefer:

- `useWorkflowComposerController.ts`
- `ArtifactHubDetailView.types.ts`
- `branchSyncSummary.ts`
- `local-engine.ts`

Avoid:

- `model2.ts`
- `helpers2.ts`
- `newTypes.ts`
- `shared.ts` unless the sharing boundary is genuinely stable

### CSS files

Prefer component or surface ownership:

- `activity-bar.css`
- `artifact-hub.css`
- `workspace-oss.css`
- `node-library.css`

Avoid:

- `extra.css`
- `fixes.css`
- `new.css`
- `overrides.css` unless it is explicitly a third-party override layer

## Import and Export Rules

### Public barrels

Keep stable barrels when they are package or app-level contracts:

- `packages/agent-ide/src/index.ts`
- `packages/agent-ide/src/WorkflowComposer.tsx`
- `apps/autopilot/src/types.ts`
- `apps/autopilot/src-tauri/src/models/mod.rs`
- `crates/api/src/chat/generation/mod.rs`

### Internal imports

New code should import from the narrowest reasonable owner.

Good:

```ts
import type { SessionPluginSnapshot } from "../../../types/plugins";
```

Compatibility-only:

```ts
import type { SessionPluginSnapshot } from "../../../types";
```

### Rust visibility

Prefer:

- private helpers inside the owning module
- `pub(super)` for sibling-only helpers
- `pub(crate)` only when multiple crate modules genuinely use the item
- `pub` only for stable API/contract surfaces

## Verification Matrix

Use the smallest meaningful check for each PR, then expand when touching shared
contracts.

| Refactor target | Minimum checks | Expanded checks |
| --- | --- | --- |
| `ioi-api` chat generation | `cargo test -p ioi-api chat::tests::direct_author` | `cargo test -p ioi-api chat` |
| `ioi-api` HTML/payload | `cargo test -p ioi-api chat::tests::payload_validation` | `cargo test -p ioi-api` |
| Autopilot backend models/session | `cargo test -p autopilot session` | `cargo test -p autopilot` |
| Autopilot frontend types/views/CSS | `npm run typecheck --workspace=apps/autopilot` | `npm run build --workspace=apps/autopilot` |
| Agent IDE WorkflowComposer | `npm run typecheck --workspace=@ioi/agent-ide` | `npm run build --workspace=@ioi/agent-ide` |
| workspace substrate CSS | `npm run build --workspace=@ioi/workspace-substrate` | desktop/web smoke probe |
| cognition history | `cargo test -p ioi-services cognition` | `cargo test -p ioi-services` |
| consensus/guardian types | `cargo test -p ioi-types` | `cargo test -p ioi-consensus aft::guardian_majority` |

## PR Sizing Rules

A good refactor PR should usually:

- touch one target area
- move code without changing behavior
- keep public exports stable
- include a short before/after tree in the PR body
- include exact verification commands
- avoid formatting unrelated files

Avoid PRs that combine:

- Rust and frontend refactors
- CSS splits and JSX restructuring
- public contract renames and behavior edits
- generated file churn and hand-written logic changes

## Review Checklist

Before merging a refactor PR, verify:

- the old import path still works or has an explicit migration note
- no generated file was manually edited
- public function/type names remain stable unless the PR is explicitly a rename
- tests moved with the behavior they cover
- comments still point to correct modules
- broad `allow` attributes did not spread
- no unrelated formatting churn
- verification output was attached

For UI/CSS PRs, also verify:

- class names are unchanged unless explicitly planned
- import order is deterministic
- responsive rules moved with their owning surface
- before/after screenshots or layout probes were captured for visual surfaces

## Risk Register

### Contract drift

Risk: moving Rust models or TS types changes generated contract behavior.

Mitigation:

- keep barrels
- preserve `#[ts(export)]`
- typecheck frontend after backend model moves

### Hidden behavior changes in artifact generation

Risk: changing helper boundaries changes repair order, timeout behavior, trace
labels, or direct-author fallback.

Mitigation:

- move helpers one family at a time
- preserve function bodies on first split
- run direct-author and payload validation tests

### CSS cascade changes

Risk: splitting files changes import order and therefore visual behavior.

Mitigation:

- create `index.css` with explicit old-order imports
- keep selectors unchanged
- visually smoke test shell surfaces

### Over-eager renaming

Risk: mass renames hide real behavior changes and disrupt public contracts.

Mitigation:

- rename only after physical splits
- keep compatibility aliases for one cycle
- batch renames by domain

### Test helper over-abstraction

Risk: large tests become shorter but less readable.

Mitigation:

- extract repeated setup, not assertions
- keep scenario names concrete
- avoid macro-heavy test DSLs

## Suggested First Five PRs

### PR 1: Autopilot TS type domain barrels

Create domain files under `apps/autopilot/src/types/` and re-export from
`apps/autopilot/src/types.ts`. Do not migrate call sites yet except for
obvious type-only internal imports.

Primary verification:

```sh
npm run typecheck --workspace=apps/autopilot
```

### PR 2: Autopilot Rust model domain modules

Split `models/mod.rs` into domain modules for local engine, notifications,
session compaction, plugins, and app state. Keep `pub use` compatibility.

Primary verification:

```sh
cargo test -p autopilot
```

### PR 3: Chat generation runtime materialization split

Move direct-author recovery, timeouts, inference wrappers, parse helpers, and
refinement into sibling modules. Keep public exports in `mod.rs`.

Primary verification:

```sh
cargo test -p ioi-api chat::tests::direct_author
```

### PR 4: WorkflowComposer constants and controller hook

Move constants and pure helpers first, then extract
`useWorkflowComposerController` without changing JSX.

Primary verification:

```sh
npm run build --workspace=@ioi/agent-ide
```

### PR 5: Autopilot shell CSS physical split

Create `AutopilotShellWindow/styles/index.css`, preserve import order, and move
selectors by surface without renaming them.

Primary verification:

```sh
npm run build --workspace=apps/autopilot
```

## When Not To Refactor

Pause a refactor if:

- a feature branch is actively changing the same behavior
- tests are already red for unrelated reasons and no stable baseline exists
- the split requires public protocol renames to compile
- a module is large but locally coherent and rarely edited
- the refactor would require changing generated output without understanding
  the generator path

## Completion Criteria

This refactor program is substantially complete when:

- no production source file over 3k lines remains unless justified as generated,
  data-heavy, or protocol fixture material
- package/app barrels are compatibility layers rather than primary development
  surfaces
- WorkflowComposer and ArtifactHubDetailView are controller/view compositions
  rather than monolithic render functions
- CSS files map to owned surfaces
- Chat artifact generation has visible phase boundaries
- session, plugin, notification, and local engine contracts have separate
  backend and frontend modules
- tests are organized by scenario family and reusable fixtures are discoverable

## Maintenance

Update this guide whenever:

- a listed target is completed
- a new bottleneck appears over repeated PRs
- a compatibility barrel is deprecated or removed
- generated contract paths change
- verification commands change

Keep the document practical. If a section stops helping reviewers decide what
to do next, rewrite it or remove it.
