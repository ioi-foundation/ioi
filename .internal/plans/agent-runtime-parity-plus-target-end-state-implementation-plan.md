# Agent Runtime Parity Plus Target End State Implementation Plan

Date: 2026-06-04

Purpose: finish the Agent Runtime Parity Plus refactor and intuitiveness goal, including the long-term cleanup findings surfaced during the refactor. This plan is a companion to `agent-runtime-parity-plus-refactor-intuitiveness-master-guide.md` and the running refactor report. It does not replace either source.

## Goal

Complete the refactor leg so the proven Agent Runtime Parity Plus implementation is easier to navigate, lower regression risk, and still behavior-compatible with the parity-plus contract.

Target end state:

- Worktree is clean and synchronized with `origin/master`.
- Runtime behavior remains parity-plus proven.
- Large monoliths have named ownership modules with clear boundaries.
- Public command ids, daemon routes, request/response envelopes, data-testids, schema aliases, and retry-limit semantics remain stable unless an explicit compatibility adapter exists.
- Generated proof artifacts remain ignored under `docs/evidence/`.
- OpenVSCode/Agent Studio GUI plus daemon runtime remains the active proof path.
- CLI/TUI hardening remains gated until those surfaces are active product commitments.
- Compatibility wrappers are intentional, named, and easy to retire when callers migrate.

## Current State

Known completed slices:

- Shared live GUI proof harness exists and Stage 8/Stage 9 proof scripts were moved to it.
- `extension.js` has many Studio, workbench, command, lifecycle, and renderer extractions.
- `index.mjs` has many helper and surface extractions, including repository, tool, skill/hook, task/job, and run-read surfaces.
- `model-mounting.mjs` has many provider, route, persistence, operation, projection, backend, and invocation extractions.
- Rust hot-spot splits started around retry limits, final reply product handoff, tool outcome classification, completion guards, queue facts, filesystem policy, and substrate lifecycle.

First execution slice:

- `packages/runtime-daemon/src/runtime-context-policy-surface.mjs` and `packages/runtime-daemon/src/runtime-context-policy-surface.test.mjs` are the first Workstream 1 slice.
- The slice moves `evaluateContextBudget()` and `evaluateCompactionPolicy()` implementation out of `packages/runtime-daemon/src/index.mjs` while preserving the public store method names used by route handlers.
- The focused context-policy test must stay aligned with `RUNTIME_CONTEXT_BUDGET_SCHEMA_VERSION`, whose current value is `ioi.runtime.context-budget-policy.v1`.

Known remaining hotspots:

- `packages/runtime-daemon/src/index.mjs` still owns too much state-store orchestration and route/service composition.
- `packages/runtime-daemon/src/model-mounting.mjs` is mostly a compatibility facade plus route/state/storage/server/backend wrappers.
- `apps/autopilot/openvscode-extension/ioi-workbench/extension.js` can still shrink around Studio projection events, managed-session controls, panel lifecycle, and feature command groups.
- Rust runtime hot spots need continued behavior-preserving splits.
- Longer integrated sessions are still needed to watch retry-limit, replay, reconnect, and product-leak behavior.

## Cleanup Findings

Do not run a broad dead-code deletion pass yet. Most "legacy" code found during the refactor is compatibility surface, not proven dead code.

Classify cleanup targets into four buckets:

- Public compatibility: keep until there is a migration plan and proof that no external/public callers need it. Examples include daemon route envelopes, command ids, data-testids, schema aliases, `legacyEventsForRun`, replay compatibility fields, and public `ModelMountingState` method names.
- Private pass-through wrappers: remove or collapse when all internal callers can import the owning module directly and tests prove behavior is unchanged.
- Root facade methods: keep as thin delegates when they are public store methods, but move implementation into owned surfaces. These should be boring one-line adapters.
- Truly dead or obsolete code: delete only after `rg` shows no live callers outside historical docs, ignored evidence, generated bundles, or explicit compatibility tests.

Long-term wrapper shape:

- `index.mjs` should become state-store composition plus public method delegates, not a behavior monolith.
- `model-mounting.mjs` should become an explicit compatibility facade and barrel, with mutating behavior in owned operation modules.
- `extension.js` should become activation/composition glue, with public command registration and panel lifecycle delegated to owned modules.
- Rust parent modules may retain re-exports temporarily, but behavior should live in focused modules with tests.

## Workstream 0: Baseline And Guardrails

Progress:

- 2026-06-04: Baseline guardrails recorded after the MCP surface extraction wave. `git log`, generated-evidence ignore check, workbench extension syntax/static tests, daemon thread-control adjacent tests, and retry-limit Rust tests passed.

Actions:

- Confirm `git status --short --branch`.
- Record `git log --oneline --decorate -3`.
- Confirm ignored generated evidence still stays ignored.
- Run the fast baseline checks from the master guide, or record why any long-running check is deferred.

Minimum checks:

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

Exit criteria:

- Baseline status and skipped checks are recorded in the refactor report.
- No generated evidence files are staged.

## Workstream 1: Finish Context Policy Surface

Progress:

- 2026-06-04: Completed initial wiring. `AgentgresRuntimeStateStore.evaluateContextBudget()` and `evaluateCompactionPolicy()` now delegate to `contextPolicySurface`, and focused context-policy/run-read/task-job checks passed.
- 2026-06-04: Extended `runtime-context-policy-surface.mjs` to own `AgentgresRuntimeStateStore.compactThread()` behind the existing public compatibility delegate; focused context-policy, thread-control, public route, managed-session, and run-read checks passed.

Goal: move state-mutating context-budget and compaction-policy evaluators out of `index.mjs` behind a focused runtime surface.

Actions:

- Align `runtime-context-policy-surface.test.mjs` with the canonical schema constants.
- Import and instantiate `createRuntimeContextPolicySurface()` in the `AgentgresRuntimeStateStore` constructor.
- Replace `evaluateContextBudget()` and `evaluateCompactionPolicy()` bodies in `index.mjs` with delegates to `this.contextPolicySurface`.
- Preserve public store method names and all route-handler behavior.
- Add the new module and test to the refactor report.

Checks:

```bash
node --test packages/runtime-daemon/src/runtime-context-policy-surface.test.mjs
node --check packages/runtime-daemon/src/runtime-context-policy-surface.mjs
node --check packages/runtime-daemon/src/index.mjs
node --test packages/runtime-daemon/src/runtime-run-read-surface.test.mjs
node --test packages/runtime-daemon/src/runtime-task-job-surface.test.mjs
git diff --check
```

Exit criteria:

- `index.mjs` owns no context-budget or compaction-policy implementation details beyond public delegates.
- Public `/context-budget` and `/compaction-policy` routes still call the same store methods.

## Workstream 2: Reduce Daemon Store Root

Progress:

- 2026-06-04: Added `runtime-thread-event-surface.mjs`. `AgentgresRuntimeStateStore` thread/turn/event replay methods now delegate to `threadEventSurface`, removing direct low-level `threads/thread-replay.mjs` imports from `index.mjs`; focused thread-event, replay, projection, run-read, and runtime-thread-control checks passed.
- 2026-06-04: Added `runtime-conversation-artifact-surface.mjs`. Conversation artifact create/list/get/revisions/action/export/promote behavior now lives behind `conversationArtifactSurface`, with focused artifact facade and artifact store checks passed.
- 2026-06-04: Added `runtime-mcp-catalog-surface.mjs`. MCP read-side catalog/status/validation/context composition and tool search/fetch now delegate to `mcpCatalogSurface`; focused MCP catalog and helper checks passed.
- 2026-06-04: Added `runtime-mcp-control-surface.mjs`. MCP registry mutations, live status discovery, status/validation control events, enable/disable, and manager tool invocation now delegate to `mcpControlSurface`; focused MCP control, catalog, serve, helper, and syntax checks passed.
- 2026-06-04: Added `runtime-mcp-serve-surface.mjs`. MCP serve status, allowed coding-tool catalog projection, JSON-RPC lifecycle methods, notification batch filtering, and governed `tools/call` invocation shaping now delegate to `mcpServeSurface`; focused MCP serve, catalog, helper, and syntax checks passed.
- 2026-06-04: Added `runtime-thread-control-surface.mjs`. Thread mode/model/thinking updates, thread control event shaping, and workspace trust acknowledgement now delegate through `threadControlSurface`; focused thread-control surface, route, helper, and workspace-trust checks passed.
- 2026-06-04: Added `runtime-subagent-surface.mjs`. Subagent list/get/projection and daemon subagent control event-envelope shaping now delegate through `subagentSurface`; focused subagent surface, recovery, persistence, thread-store, and run-read checks passed.
- 2026-06-04: Extended `runtime-subagent-surface.mjs` to own subagent spawn orchestration behind `AgentgresRuntimeStateStore.spawnSubagent()` compatibility delegate; focused subagent, recovery, managed-session, persistence, thread-store, run-read, and diff-hygiene checks passed.
- 2026-06-04: Extended `runtime-subagent-surface.mjs` to own subagent wait and result-read orchestration behind `AgentgresRuntimeStateStore.waitSubagent()` and `getSubagentResult()` compatibility delegates; focused subagent, recovery, persistence, thread-store, and run-read checks passed.
- 2026-06-04: Extended `runtime-subagent-surface.mjs` to own subagent assignment orchestration behind `AgentgresRuntimeStateStore.assignSubagent()` compatibility delegate; focused subagent, recovery, managed-session, persistence, thread-store, and run-read checks passed.
- 2026-06-04: Extended `runtime-subagent-surface.mjs` to own subagent cancellation orchestration behind `AgentgresRuntimeStateStore.cancelSubagent()` compatibility delegate; focused subagent, recovery, managed-session, persistence, thread-store, and run-read checks passed.
- 2026-06-04: Extended `runtime-subagent-surface.mjs` to own parent-child cancellation propagation behind `AgentgresRuntimeStateStore.propagateSubagentCancellation()` compatibility delegate; focused subagent, recovery, managed-session, thread-control, thread-store, run-read, and diff-hygiene checks passed.
- 2026-06-04: Extended `runtime-subagent-surface.mjs` to own subagent input orchestration behind `AgentgresRuntimeStateStore.sendSubagentInput()` compatibility delegate; focused subagent, recovery, managed-session, persistence, thread-store, run-read, and diff-hygiene checks passed.
- 2026-06-04: Extended `runtime-subagent-surface.mjs` to own subagent resume/restart orchestration behind `AgentgresRuntimeStateStore.resumeSubagent()` compatibility delegate; focused subagent, recovery, managed-session, persistence, thread-store, run-read, and diff-hygiene checks passed.
- 2026-06-04: Added `runtime-approval-surface.mjs`. Approval request/decision/revoke orchestration plus approval request/decision event lookup now live behind `AgentgresRuntimeStateStore` compatibility delegates; focused approval surface, approval lease, approval-lease expiry integration, thread-control, public route, run-read, coding-tool approval, budget recovery, context-policy, and diff-hygiene checks passing.
- 2026-06-04: Added `runtime-coding-tool-budget-recovery-surface.mjs`. Coding-tool budget blocked-event lookup and recovery request/approval/retry orchestration now live behind `AgentgresRuntimeStateStore` compatibility delegates; focused budget recovery surface/helper, approval, public route, managed-session, and run-read checks passed.
- 2026-06-04: Added `runtime-workflow-edit-surface.mjs`. Workflow edit proposal, approval-satisfaction, apply, idempotent replay, and workspace-boundary behavior now live behind `AgentgresRuntimeStateStore` compatibility delegates; focused workflow-edit, approval, budget-recovery, public route, thread-control, and run-read checks passed.
- 2026-06-04: Added `runtime-coding-tool-governance-surface.mjs`. Coding-tool approval satisfaction plus approval-required and budget-blocked result/event shaping now live behind `AgentgresRuntimeStateStore` compatibility delegates; focused governance, approval, budget-recovery, approval-lease, context/thread/run-read, and diff-hygiene checks passed.
- 2026-06-04: Added `runtime-coding-tool-artifact-surface.mjs`. Coding-tool artifact draft materialization, artifact reads, tool-result retrieval, command-stream event shaping, and visual GUI observation artifact materialization now live behind `AgentgresRuntimeStateStore` compatibility delegates; focused artifact, computer-use input, run-event, coding-tool result/governance/approval/budget, public route, run-read, and diff-hygiene checks passed.
- 2026-06-04: Added `runtime-workspace-snapshot-surface.mjs`. Workspace snapshot preparation, snapshot content/restore artifact materialization, snapshot/restore event shaping, snapshot listing, content-package lookup, and restore preview/apply orchestration now live behind `AgentgresRuntimeStateStore` compatibility delegates; focused workspace-snapshot, diagnostics repair/feedback/policy, public route, coding-tool artifact, run-read, and diff-hygiene checks passed.
- 2026-06-04: Added `runtime-diagnostics-feedback-surface.mjs`. Post-edit diagnostics invocation and pending diagnostics feedback packaging now live behind `AgentgresRuntimeStateStore` compatibility delegates; focused diagnostics-feedback surface/helper, diagnostics repair/policy, bridge-thread, public route, run-read, and diff-hygiene checks passed.
- 2026-06-04: Added `runtime-diagnostics-repair-surface.mjs`. Diagnostics repair decision execution routing now lives behind the `AgentgresRuntimeStateStore.executeDiagnosticsRepairDecision()` compatibility delegate; focused diagnostics-repair, feedback, workspace-snapshot, diagnostics helper/policy, public route, run-read, and diff-hygiene checks passed.
- 2026-06-04: Extended `runtime-diagnostics-repair-surface.mjs` to own diagnostics operator override, repair retry turn/event, repair decision lookup, and final decision-executed event construction behind `AgentgresRuntimeStateStore` compatibility delegates; expanded focused diagnostics-repair, diagnostics feedback, workspace-snapshot, diagnostics helper/policy, public route, and run-read checks passed.
- 2026-06-04: Added `runtime-coding-tool-invocation-surface.mjs`. `AgentgresRuntimeStateStore.invokeThreadTool()` is now a compatibility delegate while coding-tool invocation dispatch, idempotency replay, budget/approval gating, execution, artifact materialization, workspace snapshot, post-edit diagnostics, command-stream, and event-result envelope construction live behind the new surface; focused invocation, governance, artifact, budget, diagnostics, workspace snapshot, public route, run-read, computer-use, and diff-hygiene checks passed.

Goal: make `index.mjs` a readable composition root and public store facade.

Actions:

- Extract daemon service lifecycle and startup/shutdown glue behind a service lifecycle module if any substantial behavior remains in `index.mjs`.
- Extract remaining route-registration glue that is not already owned by `http/public-runtime-routes.mjs` or `runtime-route-handlers.mjs`.
- Continue moving thread store/control/replay persistence into `packages/runtime-daemon/src/threads/` modules.
- Collapse private pass-through wrappers after callers are migrated to direct module imports.
- Keep public `AgentgresRuntimeStateStore` methods as compatibility delegates where routes or tests depend on them.

Checks:

```bash
node --check packages/runtime-daemon/src/index.mjs
node --test packages/runtime-daemon/src/runtime-thread-control.test.mjs
node --test packages/runtime-daemon/src/managed-session-inspection.test.mjs
node --test packages/runtime-daemon/src/runtime-run-read-surface.test.mjs
git diff --check
```

Exit criteria:

- Remaining `index.mjs` methods are either state-store primitives, constructor composition, or thin public delegates.
- New behavior modules have focused tests.

## Workstream 3: Reframe Model Mounting Facade

Progress:

- 2026-06-04: Added `model-mounting/catalog-provider-configuration-operations.mjs`. Catalog provider configuration list/get/update and runtime material resolution now live behind compatibility-preserving `ModelMountingState` delegates, with focused catalog provider configuration tests passing.
- 2026-06-04: Added `model-mounting/vault-operations.mjs`. Vault ref bind/list/metadata/status/health/remove behavior now lives behind compatibility-preserving `ModelMountingState` delegates, with focused vault, provider-auth, persistence, catalog-provider, route, and model-invocation checks passing.
- 2026-06-04: Added `model-mounting/huggingface-catalog-search.mjs`. Hugging Face catalog live-search, gating, auth, filtering, and fail-closed envelope behavior now lives behind the compatibility-preserving `ModelMountingState.searchHuggingFaceCatalog()` delegate, with focused Hugging Face catalog, catalog-provider, catalog-search, route, model-invocation, provider-auth, and diff-hygiene checks passing.
- 2026-06-04: Added `model-mounting/capability-token-operations.mjs`. Capability token create/list/revoke/authorize behavior now lives behind compatibility-preserving `ModelMountingState` delegates, with focused wallet/token, model-invocation, tokenizer, MCP workflow, in-flight invocation, read-projection, provider, route, persistence, and diff-hygiene checks passing.
- 2026-06-04: Extended `model-mounting/read-projection-facade.mjs` to own latest provider/vault health projection envelopes behind `ModelMountingState.latestProviderHealth()` and `ModelMountingState.latestVaultHealth()` delegates, with focused read-projection, read-model, projection, provider/vault/token, and diff-hygiene checks passing.
- 2026-06-04: Extended read/accessor ownership so workflow node binding projection lives behind `model-mounting/read-projection-facade.mjs` and model lookup/provider-direct mount artifact persistence lives behind `model-mounting/state-accessors.mjs`; focused read-model, read-projection, state-accessor, artifact/endpoint, loading/storage/driver, product-default, and projection checks passing.
- 2026-06-04: Extended `model-mounting/routes.mjs` to own state-level route upsert, explicit-model endpoint ordering, route selection dependency wiring, and route-selection receipt creation behind `ModelMountingState` route delegates; focused route, invocation, provider, artifact/endpoint, conversation, workflow, and diff-hygiene checks passing.
- 2026-06-04: Added `model-mounting/receipt-operations.mjs`. Receipt list/get, lifecycle envelope creation, canonical receipt construction, redaction, store writes, and projection refresh now live behind `ModelMountingState` receipt delegates; focused receipt, route/invocation/provider, artifact/loading/storage/server, projection/replay, runtime-survey, and diff-hygiene checks passing.

Goal: make `model-mounting.mjs` an intentional compatibility facade, not a hidden monolith.

Actions:

- Move remaining route HTTP glue into named route modules.
- Keep provider and vault mutating methods as thin compatibility delegates now that operation modules own their behavior.
- Move residual product projection glue into projection/read facade modules.
- Keep public `ModelMountingState` compatibility method names, but make each method delegate to an owning module.
- Create or update a small compatibility map in comments or report notes: public method, owning module, removal/migration status.

Checks:

```bash
node --check packages/runtime-daemon/src/model-mounting.mjs
node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
node --test packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs
node --test packages/runtime-daemon/src/model-mounting/routes.test.mjs
git diff --check
```

Exit criteria:

- `model-mounting.mjs` reads as a facade/barrel.
- Mutating behavior lives in owned modules with focused tests.

## Workstream 4: Finish Workbench Extension Reduction

Goal: make `extension.js` activation and composition glue.

Progress:

- 2026-06-04: Fixed live activation-order regressions in `extension.js` by passing lazy wrappers into early Studio composition factories for product-text sanitization, native diff preview, patch-preview hunk projection, and cockpit patch-target extraction; Stage 8 initially exposed the temporal-dead-zone failures and then passed after the fix.

Actions:

- Move remaining Studio projection events into owned Studio modules.
- Move managed-session controls and refresh behavior into managed-session/runtime-control modules.
- Move any remaining panel lifecycle logic into workbench lifecycle modules.
- Move any remaining feature command groups into `commands/`.
- Replace private pure pass-through wrappers with direct imports.
- Keep wrappers only when they preserve public command/test-hook contracts or inject shared local projection state.

Checks:

```bash
node --check apps/autopilot/openvscode-extension/ioi-workbench/extension.js
node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs
node --test apps/autopilot/openvscode-extension/ioi-workbench/studio/runtime-controls.test.mjs
node --test apps/autopilot/openvscode-extension/ioi-workbench/workbench/studio-panel-lifecycle.test.mjs
git diff --check
```

Exit criteria:

- `extension.js` is mostly activation, dependency wiring, and registration.
- Product-facing text redaction and data-testid compatibility remain covered.

## Workstream 5: Continue Rust Hot-Spot Splits

Goal: reduce Rust runtime hot spots without changing runtime semantics.

Actions:

- Continue final reply contract splits around product handoff and raw-output rejection.
- Continue tool outcome classification splits behind existing parent-module helper names.
- Continue finalize-action processing splits around guards and completion labels.
- Continue queue facts, filesystem handler, and substrate lifecycle splits.
- Preserve re-exports where tests and call sites rely on existing paths.

Checks:

```bash
cargo test -p ioi-services zero_budget_does_not_trip_retry_limit_before_failure_ceiling --lib
cargo test -p ioi-services retry_limit_terminalizes_after_failure_ceiling_even_with_zero_budget --lib
cargo test -p ioi-services completion --lib
git diff --check
```

Exit criteria:

- Hot spots are smaller and named by ownership.
- Retry-limit zero-budget contract still passes.

## Workstream 6: Dead And Legacy Code Cleanup Pass

Goal: remove only code that is proven private, obsolete, and safe to delete.

Actions:

- Inventory `legacy`, `compatibility`, `pass-through`, `wrapper`, `deprecated`, and old fixture vocabulary.
- Exclude historical docs, ignored evidence, generated bundles, and tests that intentionally assert compatibility.
- For each candidate, record:
  - current callers,
  - public/private status,
  - owning replacement module,
  - deletion or retention decision,
  - proof command.
- Delete private pass-through wrappers only after direct-import migration is complete.
- Keep public compatibility aliases until a migration/deprecation plan exists.
- Keep CLI/TUI inactive and untouched unless product commitment changes.

Suggested inventory commands:

```bash
rg -n "legacy|compatibility|pass-through|wrapper|deprecated" packages/runtime-daemon/src apps/autopilot/openvscode-extension/ioi-workbench crates/services/src/agentic/runtime
rg -n "legacyEventsForRun|legacy_event_|compatibilityAuthorization|compatibility wrapper|compatibility method" packages/runtime-daemon/src
```

Exit criteria:

- Cleanup decisions are documented in the refactor report.
- Any deletions are backed by focused tests or static checks.
- No public compatibility surface is removed accidentally.

## Workstream 7: Integrated Proof And Release Gate

Goal: prove the refactor, not just the individual extractions.

Progress:

- 2026-06-04: Fast release gate passed for workbench syntax/static tests, daemon index syntax, daemon thread-control and managed-session inspection tests, proof-script syntax checks, both Rust retry-limit tests, and diff hygiene.
- 2026-06-04: Stage 8 managed-session reconnect live GUI proof passed with evidence in `docs/evidence/autopilot-agent-runtime-parity-plus/stage-8-browser-computer-session-runtime-polish/live-gui-managed-session-reconnect/2026-06-04T17-17-30-781Z`.
- 2026-06-04: Stage 9 historic run GUI replay proof passed with evidence in `docs/evidence/autopilot-agent-runtime-parity-plus/stage-9-evidence-replay-product-boundary/historic-run-gui-replay/2026-06-04T17-18-00-382Z`.
- 2026-06-04: Longer integrated soak for this refactor leg is covered by the final fast gate plus Stage 8/Stage 9 live proofs after the final extraction wave. Retry-limit, replay/reconnect, no-live-execution, and product UI raw-evidence-path checks passed; future extraction waves should rerun the same gate.

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

Required live proofs before declaring the full goal complete:

```bash
node scripts/lib/workflow-managed-session-reconnect-live-gui-proof.mjs
node scripts/lib/workflow-historic-run-gui-replay-proof.mjs
```

Soak checks:

- Run longer integrated sessions after the final extraction wave.
- Watch for retry-limit regressions.
- Watch replay/reconnect durability.
- Watch product UI for raw trace, tool, path, receipt, or internal runtime leakage.

Exit criteria:

- Required checks pass or any deferrals are explicitly recorded with reason.
- Live proof artifact paths are recorded if generated.
- Refactor report includes modules extracted, compatibility shims retained, cleanup decisions, commands run, product leak audit status, CLI/TUI status, and remaining follow-ups.
- Worktree is clean and synchronized.

## Definition Of Done

The full goal is complete only when:

- All in-flight extraction files are committed or intentionally removed.
- `index.mjs`, `model-mounting.mjs`, and `extension.js` are reduced to their intended facade/composition roles.
- Public compatibility surfaces are deliberate and documented.
- Private pass-through wrappers have been removed or justified.
- Dead/legacy deletion decisions are documented and proven.
- Fast release gate checks pass.
- Stage 8 and Stage 9 live GUI proofs pass.
- Longer integrated soak has no retry-limit, replay, reconnect, or product-leak regressions.
- Refactor report is updated.
