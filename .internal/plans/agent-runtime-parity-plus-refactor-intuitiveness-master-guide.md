# Agent Runtime Parity Plus Refactor And Intuitiveness Master Guide

Objective: convert the proven Agent Runtime Parity Plus implementation from a campaign-shaped codebase into an intuitive, maintainable, low-regression architecture without changing product behavior or weakening the parity-plus contract.

Target end state:

- The worktree remains clean and synchronized after the refactor leg.
- Runtime behavior remains parity-plus proven.
- Large monoliths are split into named ownership modules with clear boundaries.
- Shared live-GUI proof infrastructure replaces repeated Electron/bridge/CDP boilerplate.
- Product/runtime naming is consistent enough that new contributors can navigate the codebase without reading entire monolith files.
- CLI/TUI adapter hardening remains separately gated unless those surfaces are active product commitments.

Non-goals:

- Do not redesign Agent Studio UI during structural extraction.
- Do not rewrite runtime semantics.
- Do not remove live proof coverage.
- Do not mass-rename first. Rename only after module seams are clear.
- Do not commit generated evidence artifacts under `docs/evidence/`.

## 1. Baseline And Safety Rails

Before editing:

- Confirm `git status --short --branch` is clean.
- Record current `HEAD`.
- Read the final parity-plus verdict and this guide.
- Confirm generated evidence remains ignored.
- Run a fast baseline validation pack, or record why a long proof runner is deferred.

Baseline commands:

```bash
git status --short --branch
git log --oneline --decorate -3
git check-ignore -v docs/evidence/autopilot-agent-runtime-parity-plus/example.json || true
node --check apps/autopilot/openvscode-extension/ioi-workbench/extension.js
node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs
node --test packages/runtime-daemon/src/runtime-thread-control.test.mjs
cargo test -p ioi-services zero_budget_does_not_trip_retry_limit_before_failure_ceiling --lib
cargo test -p ioi-services retry_limit_terminalizes_after_failure_ceiling_even_with_zero_budget --lib
```

Refactor rules:

- Preserve behavior first; improve naming second.
- Move code with tests before changing code.
- Keep public request/response envelopes stable unless an explicit compatibility adapter is added.
- Keep product UI leak audits intact.
- Keep proof scripts runnable after each extraction wave.
- Do not combine broad renames with semantic changes.

## 2. Workstream A: Extract Shared Live GUI Proof Harness

Why first: the live proof scripts repeat Electron launch, bridge server setup, daemon boot, CDP attach, screenshots, cleanup, webview frame lookup, and proof artifact writing. Extracting this reduces future proof drift and makes later refactors cheaper to validate.

Primary files:

- `scripts/lib/workflow-managed-session-reconnect-live-gui-proof.mjs`
- `scripts/lib/workflow-historic-run-gui-replay-proof.mjs`
- `scripts/lib/workflow-stage2-web-repair-loop-live-gui-proof.mjs`
- `scripts/lib/workflow-stage5-stop-cancel-recover-live-gui-proof.mjs`
- `scripts/lib/workflow-stage5-stop-hook-repair-loop-live-gui-proof.mjs`
- `scripts/lib/workflow-stage7-delegation-live-gui-proof.mjs`
- `scripts/lib/workflow-trajectory-reconnect-live-gui-proof.mjs`
- `scripts/lib/workflow-session-brain-live-gui-proof.mjs`
- `scripts/lib/workflow-policy-lease-lifecycle-live-gui-proof.mjs`
- `scripts/lib/workflow-crash-restart-replay-live-gui-proof.mjs`

Target modules:

- `scripts/lib/live-gui-proof-harness/process.mjs`
- `scripts/lib/live-gui-proof-harness/bridge.mjs`
- `scripts/lib/live-gui-proof-harness/electron.mjs`
- `scripts/lib/live-gui-proof-harness/playwright.mjs`
- `scripts/lib/live-gui-proof-harness/screenshots.mjs`
- `scripts/lib/live-gui-proof-harness/cleanup.mjs`
- `scripts/lib/live-gui-proof-harness/proof-output.mjs`
- `scripts/lib/live-gui-proof-harness/index.mjs`

Extraction candidates:

- `timestamp`
- `ensureDir`
- `wait`
- `waitForPredicate`
- `waitForChildExit`
- `listen`
- `closeServer`
- `getFreePort`
- `waitForCdp`
- `sendJson`
- `readRequestBody`
- `queueCommand`
- `requireNewRequest`
- `findFrameWithTestId`
- `screenshot`
- `cleanupProofUserDataProcesses`
- Electron launch environment construction
- Playwright CDP attach and tracing lifecycle

Acceptance:

- At least Stage 8 and Stage 9 proof scripts use the shared harness.
- Existing proof outputs remain schema-compatible.
- No behavior change to proof checks.
- `node --check` passes for every touched proof script and harness module.
- Stage 8 and Stage 9 live GUI proofs pass after extraction.

## 3. Workstream B: Split Agent Studio Workbench Extension

Primary file:

- `apps/autopilot/openvscode-extension/ioi-workbench/extension.js`

Problem:

- The file is too large to reason about locally.
- It mixes command registration, bridge I/O, Studio state projection, panel rendering lifecycle, test hooks, managed session controls, workbench shell integration, runtime event normalization, and product-boundary sanitation.

Target structure:

```text
apps/autopilot/openvscode-extension/ioi-workbench/
  extension.js                         # thin activation/composition root
  bridge/
    client.js
    request-writer.js
    command-poller.js
  commands/
    register-core-commands.js
    register-studio-commands.js
    register-test-hook-commands.js
  studio/
    projection-state.js
    projection-events.js
    projection-replay.js
    projection-managed-sessions.js
    projection-policy.js
    projection-recovery.js
    public-text-sanitizer.js
    panel-lifecycle.js
    test-hooks/
      managed-session-reconnect.js
      parity-plus-events.js
      recovery-panels.js
  workbench/
    shell-integration.js
    target-index.js
```

Extraction order:

1. Move pure helpers first: public text sanitizer, bridge payload helpers, frame/state utilities.
2. Move Studio projection state and event application.
3. Move managed-session test hooks.
4. Move command registration by feature.
5. Leave activation root as dependency wiring and registration only.

Acceptance:

- `extension.js` becomes an activation/composition file, ideally under 2,500 lines.
- No public command ids change.
- Existing static tests still find required command ids, data-testids, and projection behavior.
- Product UI leak wording remains sanitized.
- Stage 8 and Stage 9 live GUI proofs still pass.

Validation:

```bash
node --check apps/autopilot/openvscode-extension/ioi-workbench/extension.js
node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs
node scripts/lib/workflow-managed-session-reconnect-live-gui-proof.mjs
node scripts/lib/workflow-historic-run-gui-replay-proof.mjs
```

## 4. Workstream C: Split Runtime Daemon Composition Root

Primary file:

- `packages/runtime-daemon/src/index.mjs`

Problem:

- It is serving as daemon service root, HTTP bootstrap, thread store, runtime thread control surface, bridge integration, and persistence coordinator.

Target structure:

```text
packages/runtime-daemon/src/
  index.mjs                         # public exports and service composition only
  service/
    runtime-daemon-service.mjs
    daemon-state-dir.mjs
    shutdown.mjs
  threads/
    thread-store.mjs
    thread-control.mjs
    thread-replay.mjs
    managed-session-state.mjs
  http/
    server.mjs
    route-registration.mjs
  bridges/
    runtime-agent-bridge.mjs
    workbench-bridge.mjs
```

Extraction order:

1. Extract pure store/state helpers.
2. Extract managed-session inspect/control state.
3. Extract daemon service lifecycle.
4. Extract route registration glue.
5. Reduce `index.mjs` to public exports and composition.

Acceptance:

- `startRuntimeDaemonService` public API remains compatible.
- Runtime route handler tests pass.
- Managed-session reconnect tests pass.
- Stage 8 live GUI proof still passes.
- `index.mjs` no longer owns feature-level implementation details.

Validation:

```bash
node --check packages/runtime-daemon/src/index.mjs
node --test packages/runtime-daemon/src/runtime-thread-control.test.mjs
node --test packages/runtime-daemon/src/managed-session-inspection.test.mjs
```

## 5. Workstream D: Split Model Mounting

Primary file:

- `packages/runtime-daemon/src/model-mounting.mjs`

Problem:

- Provider registry, native fixture behavior, state machine, route handling, install/mount validation, and product projection are concentrated in one file.

Target structure:

```text
packages/runtime-daemon/src/model-mounting/
  index.mjs
  registry.mjs
  state-machine.mjs
  routes.mjs
  validation.mjs
  projections.mjs
  native-fixtures/
    stage2-web-repair.mjs
    stage5-stop-hook-repair.mjs
    tool-catalogue.mjs
```

Acceptance:

- Existing imports keep working through a compatibility barrel.
- Native fixture tests still pass.
- Agent Studio model setup static tests still pass.
- No product copy regression in model setup views.

Validation:

```bash
node --check packages/runtime-daemon/src/model-mounting.mjs
node --test packages/runtime-daemon/src/model-mounting/native-fixture-stage2-web-repair.test.mjs
node --test packages/runtime-daemon/src/model-mounting/native-fixture-stage5-stop-hook-repair.test.mjs
node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs
```

## 6. Workstream E: Rust Runtime Service Extractions

Primary files:

- `crates/services/src/agentic/runtime/substrate.rs`
- `crates/services/src/agentic/runtime/service/decision_loop/cognition/final_reply.rs`
- `crates/services/src/agentic/runtime/service/tool_execution/processing/phases/execute_tool_phase/tool_outcome.rs`
- `crates/services/src/agentic/runtime/service/tool_execution/processing/phases/finalize_action_processing.rs`
- `crates/services/src/agentic/runtime/service/queue/support/pipeline/facts.rs`
- `crates/services/src/agentic/runtime/execution/filesystem/handler.rs`

Approach:

- Split by runtime responsibility, not line count alone.
- Prefer private submodules before public API changes.
- Keep tests near the behavior they protect.
- Use compatibility re-exports where callers are numerous.

Recommended extraction themes:

- Final reply contract and rejection reasons.
- Tool outcome classification.
- Command failure reply composition.
- File policy observation and boundary enforcement.
- Queue pipeline fact aggregation.
- Substrate transport/session lifecycle.

Acceptance:

- Cargo tests for touched modules pass.
- Retry-limit regression tests pass.
- Existing type names remain understandable.
- No broad import churn unless it removes real ambiguity.

Validation:

```bash
cargo test -p ioi-services zero_budget_does_not_trip_retry_limit_before_failure_ceiling --lib
cargo test -p ioi-services retry_limit_terminalizes_after_failure_ceiling_even_with_zero_budget --lib
cargo test -p ioi-services completion --lib
```

## 7. Workstream F: Naming And Vocabulary Alignment

Do this after the main extractions.

Current naming drift:

- Agent Studio vs Autopilot Studio vs workbench panel.
- Runtime daemon vs daemon runtime vs runtime service.
- Managed session vs browser/computer session vs computer use.
- Trajectory replay vs historic replay vs reconnect replay.
- Product UI vs evidence surface vs tracing surface.

Create a vocabulary table:

```text
Canonical term | Meaning | Allowed aliases | Deprecated aliases | Code owner
```

Candidate canonical terms:

- Agent Studio: product UI surface.
- Runtime Daemon: local daemon process and HTTP API.
- Runtime Thread: durable agent execution thread.
- Managed Session: browser/computer session controlled by runtime.
- Trajectory Replay: replay of durable runtime events.
- Historic Replay: read-only replay sourced from archived evidence.
- Product Projection: sanitized UI-facing state.
- Evidence Surface: proof/tracing artifacts where raw internals may appear.

Rename rules:

- Rename modules and filenames before data fields.
- Rename private helpers before exported APIs.
- Add compatibility aliases for exported APIs.
- Keep test ids stable unless a migration is explicit.
- Do not rename raw tool names in evidence fixtures; sanitize product projection instead.

Acceptance:

- New file/module names map cleanly to vocabulary.
- No product test id churn unless explicitly approved.
- Search results for deprecated aliases are mostly compatibility shims, evidence fixtures, or historical docs.

## 8. Workstream G: CLI/TUI Adapter Gate

Only start this workstream if CLI/TUI surfaces are active product commitments.

If active, require:

- Same typed stream contract as GUI.
- Same product-boundary redaction.
- Same replay cursor semantics.
- Same policy lease visibility.
- Same stop/resume/cancel controls.
- Same managed-session state projection.
- Same trace/evidence linkability.

If inactive:

- Record CLI/TUI as inactive in the refactor report.
- Do not broaden scope.
- Keep existing CLI/TUI files untouched except for compile fixes required by Rust module moves.

## 9. Release Gate For The Refactor Leg

Required final checks:

```bash
git status --short --branch
node --check apps/autopilot/openvscode-extension/ioi-workbench/extension.js
node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs
node --check packages/runtime-daemon/src/index.mjs
node --test packages/runtime-daemon/src/runtime-thread-control.test.mjs
node --test packages/runtime-daemon/src/managed-session-inspection.test.mjs
node --check scripts/lib/workflow-managed-session-reconnect-live-gui-proof.mjs
node --check scripts/lib/workflow-historic-run-gui-replay-proof.mjs
cargo test -p ioi-services zero_budget_does_not_trip_retry_limit_before_failure_ceiling --lib
cargo test -p ioi-services retry_limit_terminalizes_after_failure_ceiling_even_with_zero_budget --lib
git diff --check
```

Required live proof checks before declaring done:

```bash
node scripts/lib/workflow-managed-session-reconnect-live-gui-proof.mjs
node scripts/lib/workflow-historic-run-gui-replay-proof.mjs
```

Optional broader checks when time allows:

```bash
cargo test -p ioi-services completion --lib
node --test packages/runtime-daemon/src/model-mounting/native-fixture-stage2-web-repair.test.mjs
node --test packages/runtime-daemon/src/model-mounting/native-fixture-stage5-stop-hook-repair.test.mjs
```

Final report must include:

- Modules extracted.
- Public APIs preserved or changed.
- Compatibility shims added.
- Naming changes made.
- Commands run.
- Live proof paths generated, if any.
- Product leak audit status.
- CLI/TUI status: inactive, untouched, or hardened.
- Remaining follow-ups.

## 10. Handoff Goal Prompt

Use this prompt to execute the full leg:

```text
/goal Execute the Agent Runtime Parity Plus refactor and intuitiveness leg end-to-end.

Use .internal/plans/agent-runtime-parity-plus-refactor-intuitiveness-master-guide.md as the source of truth.

Target end state:
- Runtime behavior remains parity-plus proven.
- Generated docs/evidence artifacts remain ignored and are not committed.
- Shared live-GUI proof harness exists and Stage 8/Stage 9 proof scripts use it.
- apps/autopilot/openvscode-extension/ioi-workbench/extension.js is reduced to a thin activation/composition root with Studio projection, bridge, commands, test hooks, and workbench integration split into intuitive modules.
- packages/runtime-daemon/src/index.mjs is reduced to service composition/public exports with thread store/control/replay, managed-session state, HTTP bootstrap, and bridge integration split into modules.
- packages/runtime-daemon/src/model-mounting.mjs is split behind compatibility exports into registry, state machine, routes, validation, projections, and native fixture modules.
- Rust runtime hot spots are split by behavioral responsibility without changing public semantics: final reply contract, tool outcome classification, finalize action processing, queue facts, filesystem handler, and substrate lifecycle.
- Naming/vocabulary drift is documented and private/module-level names are aligned where safe. Avoid disruptive exported API/test-id renames unless compatibility shims are included.
- CLI/TUI adapters are either explicitly marked inactive and left alone, or hardened to the same stream/replay/redaction/policy/managed-session contract if active.
- Worktree is clean and synchronized at the end.

Execution constraints:
- Start from a clean worktree.
- Move/extract code before semantic changes.
- Keep product UI redaction and evidence/tracing separation intact.
- Do not commit generated evidence artifacts.
- Preserve command ids, data-testids, and public request/response envelopes unless compatibility is added.
- Commit and push only after validation is complete.

Required validation:
- node --check apps/autopilot/openvscode-extension/ioi-workbench/extension.js
- node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs
- node --check packages/runtime-daemon/src/index.mjs
- node --test packages/runtime-daemon/src/runtime-thread-control.test.mjs
- node --test packages/runtime-daemon/src/managed-session-inspection.test.mjs
- node --check scripts/lib/workflow-managed-session-reconnect-live-gui-proof.mjs
- node --check scripts/lib/workflow-historic-run-gui-replay-proof.mjs
- cargo test -p ioi-services zero_budget_does_not_trip_retry_limit_before_failure_ceiling --lib
- cargo test -p ioi-services retry_limit_terminalizes_after_failure_ceiling_even_with_zero_budget --lib
- git diff --check

Required live proof validation before completion:
- node scripts/lib/workflow-managed-session-reconnect-live-gui-proof.mjs
- node scripts/lib/workflow-historic-run-gui-replay-proof.mjs

Deliverables:
- Refactored modules with compatibility shims where needed.
- Updated or added tests for extracted helpers.
- Refactor report in .internal/plans or internal-docs describing module splits, validation, naming decisions, CLI/TUI status, and remaining follow-ups.
- Clean synchronized worktree with one or more coherent commits pushed to origin/master.
```
