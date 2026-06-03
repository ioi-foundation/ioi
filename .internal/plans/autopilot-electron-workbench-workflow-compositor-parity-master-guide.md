# Autopilot Electron Workbench Workflow Compositor Parity Master Guide

Owner: Autopilot Workbench / VS Code fork / `ioi-workbench` / `@ioi/agent-ide` / daemon runtime

Status: fixture-backed compositor parity validated; daemon-backed production adapter remains before live connector action

Created: 2026-05-20

Parent guide:
`.internal/plans/autopilot-ide-first-tauri-retirement-ux-readiness-master-guide.md`

Next guide:
`.internal/plans/autopilot-electron-model-mounting-daemon-runtime-adapter-master-guide.md`

## Executive Verdict

The IDE-first direction is still correct. The Electron/VS Code fork now mounts
the real `@ioi/agent-ide` Workflow Composer through `ioi-workbench`, closing the
specific UX gap where shell readiness had been proven but workflow-compositor
parity had not.

The previous UX-readiness goal proved:

- the VS Code/Electron fork is the canonical shell;
- `ioi-workbench` is installed and controllable;
- retained-query bridge requests, route receipts, screenshots, and fixture
  connector dry-runs can be validated;
- Tauri is absent from the target launch/package path.

Before this guide, that validation did not prove:

- the rich ReactFlow Workflow Composer is visible in the Electron app;
- the workflow rail, node configuration, readiness, replay, receipts, package
  import/export, connector binding, and live-run panels are mounted in the fork;
- the Electron app has UX parity with the Tauri workflow compositor.

This guide closes that visual/behavioral parity gap with explicit fixture-backed
runtime boundaries. It does not claim live daemon-backed connector execution; the
current production classification is `fixture-composer`, with daemon API gaps
listed below as blockers.

## Target End State

Autopilot Workbench in the VS Code/Electron fork should feel like the rich Tauri
Workflow Composer moved into an IDE-grade operator console, not like a plain VS
Code install with a few IOI sidebar panels.

Target shape:

```text
Electron/VS Code fork
  -> canonical Autopilot app shell
  -> built-in ioi-workbench extension
  -> rich Workflow Composer custom editor / workbench view
  -> @ioi/agent-ide WorkflowComposer mounted as real UI
  -> daemon-backed runtime adapter
  -> policy / approvals / receipts / replay projected from daemon
  -> no Tauri dependency
```

Canonical constraints for this guide:

- Electron/VS Code fork remains the canonical Autopilot app shell.
- Tauri must not be revived.
- Validation must prove workflow compositor parity, not only shell launch or
  bridge readiness.

The user-facing test is simple:

> When a user launches the Electron Autopilot app and opens Workflows, they
> should see and operate the rich graph compositor, workflow rail, inspectors,
> readiness panels, run timeline, receipts, replay, and connector binding
> controls they expect from the Tauri-era app, now embedded into the canonical
> IDE-first workbench.

## Current State

Known local state as of 2026-05-20:

- `npm run goal:autopilot-workflow-compositor-parity` passes with preflight
  evidence at
  `docs/evidence/autopilot-workbench-workflow-compositor-parity/2026-05-20T20-25-15-541Z/`.
- `npm run goal:autopilot-workflow-compositor-parity:run` passes with GUI
  evidence at
  `docs/evidence/autopilot-workbench-workflow-compositor-parity/2026-05-20T20-23-54-891Z/`
  and result summary at
  `docs/evidence/autopilot-workbench-workflow-compositor-parity/2026-05-20T20-25-00-369Z/result.json`.
- `npm run goal:autopilot-ux-readiness` passes with parent preflight evidence
  at `docs/evidence/autopilot-ide-first-ux-readiness/2026-05-20T20-25-16-092Z/`.
- `npm run goal:autopilot-ux-readiness:run` passes with canonical shell/control
  evidence at
  `docs/evidence/autopilot-ide-first-ux-readiness/2026-05-20T20-25-57-739Z/result.json`.
- The fork launches as `Autopilot IDE`; `ioi-workbench` responds to bridge
  commands and can open the rich composer with `ioi.workflow.openComposer`.
- `ioi-workbench` bundles the real `WorkflowComposer` from
  `@ioi/agent-ide`, including the ReactFlow canvas, node inspector, readiness
  projection, run timeline, receipts/replay projection, package/evidence
  surfaces, and connector fixture binding controls.
- The current `AgentWorkbenchRuntime` in the fork is an explicit fixture adapter
  that emits typed bridge requests. It does not own durable runtime state, call
  live connectors, mutate files directly, or revive Tauri.
- `apps/autopilot/src` remains legacy React/Tauri shell extraction inventory.
  That path is not canonical and should not be revived as the product shell.
- `apps/autopilot/src-tauri` remains archived at
  `internal-docs/legacy/autopilot-tauri-src/`.

Interpretation:

- The Electron/fork product surface now mounts the rich composer.
- The current status is `fixture-composer`: visual and behavioral parity for
  dry-run/mock workflows is proven, while live daemon-backed workflow APIs remain
  the production blocker.
- The missing work is no longer another substrate debate or compositor mount; it
  is daemon API wiring, production persistence, receipt-backed mutation, and
  live connector policy integration.

## Validation Closeout: 2026-05-20

Validated commands:

- `npm run goal:autopilot-workflow-compositor-parity`
- `npm run goal:autopilot-workflow-compositor-parity:run`
- `npm run goal:autopilot-ux-readiness`
- `npm run goal:autopilot-ux-readiness:run`

Workflow compositor evidence:

- Result:
  `docs/evidence/autopilot-workbench-workflow-compositor-parity/2026-05-20T20-25-00-369Z/result.json`
- Proof:
  `docs/evidence/autopilot-workbench-workflow-compositor-parity/2026-05-20T20-23-54-891Z/workflow-compositor-parity-proof.json`
- Required screenshots:
  `workflow-composer-canvas.png`, `workflow-node-inspector.png`,
  `workflow-readiness-panel.png`, `workflow-run-timeline.png`,
  `workflow-receipts-replay.png`, and
  `workflow-connector-fixture-binding.png`.

Workflows built from scratch through the Electron composer harness:

- Sequential workflow:
  `workflow-from-scratch-sequential.png`
- Branching approval-gated workflow:
  `workflow-from-scratch-branching-approval.png`
- Connector-neutral dry-run workflow with mock capability binding:
  `workflow-from-scratch-connector-fixture.png`
- Workflow-to-code proposal workflow:
  `workflow-from-scratch-code-proposal.png`
- Replay/evidence-focused workflow:
  `workflow-from-scratch-replay-evidence.png`

Validation result:

- Electron/VS Code fork launched and was controlled through automation.
- Workflows opened the real `@ioi/agent-ide` `WorkflowComposer`, not a list-only
  projection.
- Canvas, nodes, edges, inspector, readiness projection, run timeline,
  receipts/replay projection, and connector fixture binding were visible.
- Every screenshot assertion passed.
- `externalAction` remained `false`.
- `tauriUsed` remained `false`.
- No orphan GUI process remained after validation.

Remaining daemon/API blockers:

- Replace the fixture `AgentWorkbenchRuntime` with daemon-backed workflow
  list/load/save contracts.
- Wire daemon preflight/dry-run/run event streams into the composer rail.
- Wire daemon-backed model mounting and live model route invocation through the
  Electron Models mode and Workflow Composer model binding catalog.
- Wire daemon receipts, replay records, approval IDs, and policy decisions into
  the run and evidence panels.
- Wire proposal-first materialization through daemon-settled patch receipts.
- Wire connector capability catalogs and connector dry-run endpoints without
  exposing live connector action to the webview or extension host.

## Non-Negotiable Doctrine

- Do not bring Tauri back.
- Do not treat a workflow list as compositor parity.
- Do not let the VS Code extension host become a runtime authority.
- Do not call connector APIs, mutate files, or settle workflow runs directly
  from the webview.
- Do mount the real compositor UX in the canonical fork.
- Do route runtime work through daemon APIs.
- Do emit receipts for every consequential workflow action.
- Do validate with screenshots that prove the actual graph/canvas/rail UI is
  visible and operable.

## Product Acceptance Bar

The Electron app is not compositor-ready until all of these are true:

1. The first-run Autopilot profile exposes Workflows as a first-class primary
   mode, not a hidden extension panel.
2. Opening Workflows displays the rich `WorkflowComposer` canvas, not only a
   list of workflows.
3. A user can create/open/import a workflow package.
4. A user can add nodes, connect nodes, configure node bindings, and inspect
   readiness.
5. A user can bind model/tool/connector capabilities through operator controls.
6. A user can trigger dry-run/preflight execution through daemon-backed APIs.
7. A user can inspect run timeline, policy gates, approval requests, receipts,
   replay records, artifacts, and evidence.
8. A user can materialize or generate code proposals from a workflow without
   bypassing daemon policy/receipts.
9. The compositor survives reload, workspace reopen, and app relaunch.
10. Automated evidence includes screenshots of the graph canvas, rail panels,
    node inspector, readiness panel, receipts/replay panel, and connector
    fixture binding.

## Architecture Target

### Workbench Shell

Owner: VS Code/Electron fork and `ioi-workbench`.

Responsibilities:

- Register Autopilot Workflows as a primary workbench mode.
- Provide custom editor or full webview view for workflow packages.
- Own layout, menu commands, keybindings, and activity-bar visibility.
- Pass workspace/editor context to the webview.
- Bridge user intent to daemon APIs.
- Render daemon projections.

Must not own:

- durable workflow truth;
- connector secrets;
- policy decisions;
- approval settlement;
- external action execution;
- patch application.

### Composer UI

Owner: `packages/agent-ide`.

Responsibilities:

- Render `WorkflowComposer`.
- Render ReactFlow canvas and node/edge interactions.
- Render workflow rail, readiness, package, evidence, replay, rollback, run,
  settings, and capability-binding panels.
- Provide a typed browser/runtime adapter interface.

Must not own:

- app shell lifecycle;
- daemon supervision;
- connector credentials;
- durable authority.

### Runtime Adapter

Owner: daemon runtime API plus thin workbench bridge.

Responsibilities:

- Implement `AgentWorkbenchRuntime` for the fork.
- Load workflow manifests/packages.
- Persist workflow edits.
- Run dry-runs/preflights.
- Emit run events, receipts, replay records, policy decisions, and approval
  projections.
- Materialize proposal-only workspace changes.

Must not be:

- an in-memory fake for production;
- a Tauri command shim;
- an extension-host executor.

## Master Guide 0: Honesty Gate

Goal:

Make the status language impossible to misread.

Required updates:

- Parent guide must distinguish "canonical shell readiness" from "workflow
  compositor UX parity."
- Evidence summaries must not imply rich Workflow Composer parity until the
  compositor is visible and operable in the Electron app.
- Sprint-readiness reports must say whether the workflow surface is:
  `projection-only`, `fixture-composer`, `daemon-backed composer`, or
  `production composer`.

Definition of done:

- The parent master guide links to this guide.
- The latest readiness report states that the current Electron workflow surface
  is projection-only until this guide passes.

## Master Guide 1: Surface Inventory And Extraction Map

Goal:

Create an explicit map from the rich Tauri-era workflow UX to the Electron
Workbench target.

Inventory source paths:

- `packages/agent-ide/src/WorkflowComposer.tsx`
- `packages/agent-ide/src/WorkflowComposer/`
- `packages/agent-ide/src/features/Workflows/`
- `packages/agent-ide/src/runtime/`
- `apps/autopilot/src/surfaces/Workspace/`
- `apps/autopilot/src/windows/AutopilotShellWindow/`
- `internal-docs/legacy/autopilot-tauri-src/`

Inventory target:

| Existing capability | Source owner | Target owner | Disposition |
| --- | --- | --- | --- |
| ReactFlow graph canvas | `@ioi/agent-ide` | `ioi-workbench` webview/custom editor | Mount |
| Workflow rail | `@ioi/agent-ide` | Composer webview | Mount |
| Node config modal | `@ioi/agent-ide` | Composer webview | Mount |
| Model/tool/connector binding | `@ioi/agent-ide` runtime panels | Composer webview + daemon API | Mount + live-bind |
| Package import/export | `@ioi/agent-ide` | Workbench commands + daemon API | Mount + bridge |
| Run timeline | `@ioi/agent-ide` rail panels | Composer webview + Runs view | Mount + project |
| Evidence/receipts/replay | `@ioi/agent-ide` rail panels | Composer webview + Evidence view | Mount + project |
| Terminal coding loop activation | `@ioi/agent-ide` runtime adapter | Daemon API + controlled terminal | Migrate |
| Computer-use run options | `@ioi/agent-ide` | Daemon/browser provider + workbench projection | Migrate |
| Tauri commands | archived Rust | daemon API or delete | Do not revive |

Definition of done:

- Each rich-composer capability has a source path, target path, bridge contract,
  and validation assertion.
- Anything dependent on Tauri has a delete or daemon-migration decision.

## Master Guide 2: Package The Composer For VS Code Webviews

Goal:

Bundle `@ioi/agent-ide` Workflow Composer as a VS Code webview/custom editor
asset.

Preferred implementation:

- Add a workbench-composer entrypoint under `apps/autopilot/openvscode-extension/ioi-workbench`.
- Bundle `WorkflowComposer` and CSS from `packages/agent-ide`.
- Use a strict VS Code webview CSP.
- Use `acquireVsCodeApi()` only for typed bridge messages.
- Keep extension-host code thin.
- Keep React app state inside the webview, with durable state delegated to the
  daemon/runtime adapter.

Required commands/views:

- `ioi.workflow.openComposer`
- `ioi.workflow.create`
- `ioi.workflow.importPackage`
- `ioi.workflow.openPackage`
- `ioi.workflow.focusNode`
- `ioi.workflow.openRun`
- `ioi.workflow.openReceipt`
- `ioi.workflow.openReplay`
- `ioi.workflow.generateCode`

Definition of done:

- The packaged Electron app includes compositor webview assets.
- The Workflows view or custom editor mounts the actual `WorkflowComposer`.
- The UI can render without relying on `apps/autopilot/src`.

## Master Guide 3: Daemon-Backed Runtime Adapter

Goal:

Replace fixture/in-memory bridge behavior with daemon-backed runtime operations.

Required daemon/workbench contracts:

```http
GET  /v1/workflows
POST /v1/workflows
GET  /v1/workflows/{workflow_id}
PATCH /v1/workflows/{workflow_id}
POST /v1/workflows/{workflow_id}/dry-run
POST /v1/workflows/{workflow_id}/preflight
POST /v1/workflows/{workflow_id}/materialize-proposal
GET  /v1/workflows/{workflow_id}/runs
GET  /v1/runs/{run_id}/events
GET  /v1/runs/{run_id}/receipts
GET  /v1/runs/{run_id}/replay
POST /v1/runs/{run_id}/approve
GET  /v1/capabilities/models
GET  /v1/capabilities/tools
GET  /v1/connectors
POST /v1/connectors/{connector_id}/dry-run
```

Required adapter behavior:

- Load/save workflow documents.
- Normalize runtime-unavailable states.
- Stream run events into rail/timeline panels.
- Bind approvals to daemon approval IDs.
- Bind receipts to daemon receipt IDs.
- Bind replay to daemon replay records.
- Keep connector fixture mode connector-neutral until real connector sprint
  entry.

Definition of done:

- `WorkflowComposer` receives a real `AgentWorkbenchRuntime` adapter for the
  fork.
- Mutating actions round-trip through daemon contracts or fail closed.
- The adapter can switch between fixture and live daemon profiles explicitly.

## Master Guide 4: Workbench UX Integration

Goal:

Make the composer feel native to Autopilot Workbench.

Required UX:

- Autopilot activity bar opens a primary Workflows mode.
- The rich compositor occupies a large editor/workbench area, not a cramped
  sidebar card.
- The workflow rail can dock beside the canvas.
- Runs, policy, receipts, and connections can open as adjacent workbench views.
- Clicking a run/receipt/replay deep link focuses the correct workflow and node.
- Command palette actions target the active workflow context.
- Keyboard shortcuts and context menus are predictable.
- Empty state offers Create, Import, and Open Package actions.
- The first viewport makes Autopilot Workbench feel like Autopilot, not generic
  VS Code.

Definition of done:

- A user can discover and operate the compositor from app launch without knowing
  command IDs.
- The app has a default Autopilot layout/profile that makes Workflows obvious.

## Master Guide 5: Workflow-To-Code And Materialization

Goal:

Preserve the proposal-first workflow-to-code path inside the fork.

Required flow:

1. Select or create workflow.
2. Bind model/tool capabilities.
3. Run preflight.
4. Generate code proposal.
5. Show proposed file tree/diff.
6. Request approval for materialization.
7. Apply through daemon-settled patch/materialization receipt.
8. Open resulting workspace/files in VS Code editors.
9. Store receipt and replay evidence.

Forbidden:

- Direct webview file writes.
- Extension-host patch apply without daemon receipt.
- Tauri command fallback.

Definition of done:

- The fork can perform the same proposal-first workflow-code route as the legacy
  app, with receipts and screenshots.

## Master Guide 6: Connector-Neutral Readiness In The Composer

Goal:

Prove connector sprint readiness from the rich compositor without starting a
real connector sprint.

Required fixture:

- A mock connector capability appears in the node/capability binding UI.
- The user can bind it to a workflow node.
- The composer shows risk class, required approval, and dry-run status.
- Running the node performs fixture dry-run only.
- The daemon/workbench emits approval request, action receipt, verification
  receipt, and replay record identifiers.
- The evidence view can open those receipts.

Definition of done:

- Automated evidence includes a screenshot of the node binding UI with the mock
  connector selected and the receipt/replay panels populated.
- `externalAction` remains false.

## Master Guide 7: Validation Harness

Goal:

The harness must prove the visual compositor, not merely the bridge.

New required validation command:

```bash
npm run goal:autopilot-workflow-compositor-parity
npm run goal:autopilot-workflow-compositor-parity:run
```

Required evidence root:

```text
docs/evidence/autopilot-workbench-workflow-compositor-parity/
```

Required automated assertions:

- Launch canonical Electron app.
- Open Autopilot Workflows mode.
- Assert compositor webview exists.
- Assert ReactFlow canvas selector exists and is non-empty.
- Assert workflow rail exists.
- Assert node inspector/config panel exists.
- Create or open a fixture workflow.
- Add/select/configure a node.
- Bind mock model/tool/connector capability.
- Run dry-run/preflight through daemon or explicit fixture adapter.
- Observe run timeline.
- Observe approval projection.
- Observe receipt/replay projection.
- Capture screenshots:
  - `workflow-composer-canvas.png`
  - `workflow-node-inspector.png`
  - `workflow-readiness-panel.png`
  - `workflow-run-timeline.png`
  - `workflow-receipts-replay.png`
  - `workflow-connector-fixture-binding.png`
- Cleanly close app and verify no orphan fork processes.

Required negative assertions:

- No production Tauri launch.
- No `@tauri-apps/*` package use in the target launch path.
- No extension-host direct file mutation.
- No live external connector action.

Definition of done:

- The harness fails if the Workflows view is only a list/projection.
- The harness passes only when the rich canvas/rail/inspector experience is
  visible and operable in the Electron app.

## Connector Sprint Entry Criteria

The next connector-specific sprint may start only after this guide proves:

- the real `@ioi/agent-ide` `WorkflowComposer` is visible and operable in the
  Electron app;
- workflows can be created through the GUI for sequential, approval-gated,
  connector-neutral fixture, workflow-to-code, and replay/evidence cases;
- the mock connector binding path shows `externalAction: false`;
- readiness, run timeline, receipts/replay, and evidence projections are
  visible from the rich composer;
- every live connector/API gap is listed as a daemon/API blocker rather than
  hidden behind extension-host or webview behavior.

Status as of the 2026-05-20 validation pass:

- Fixture/mock connector-readiness UX is green.
- Real connector-specific work remains blocked on daemon-backed connector
  dry-run/call, approval, receipt, replay, and policy contracts.
- The next sprint entry is therefore daemon-backed connector readiness, not a
  live provider action sprint.
- Live connector action may begin only after the fixture adapter is replaced by
  daemon-backed contracts while preserving the same evidence shape and
  `externalAction: false` dry-run proof.

## Master Guide 8: Migration Phases

### Phase 0: Status Correction

Outcome:

The team understands the current state accurately.

Status: complete.

Tasks:

- Link this guide from the parent IDE-first guide.
- Mark current Electron workflow surface as projection-only.
- Add validation blocker: rich compositor not surfaced in Electron.

Exit gate:

- No status report implies workflow compositor parity.

### Phase 1: Composer Webview Spike

Outcome:

The fork can render `WorkflowComposer` in a webview/custom editor with fixture
data.

Status: complete.

Tasks:

- Create workbench composer entrypoint.
- Bundle `@ioi/agent-ide` composer assets.
- Mount fixture runtime adapter.
- Open via `ioi.workflow.openComposer`.
- Screenshot canvas and rail.

Exit gate:

- Rich canvas visible in Electron app.

### Phase 2: Workbench Integration

Outcome:

The composer behaves like a native Autopilot workbench mode.

Status: fixture-backed complete; production layout/profile polish remains.

Tasks:

- Add default layout/profile.
- Add command palette actions.
- Add custom editor or full editor-area webview.
- Add deep links for workflow/node/run/receipt/replay.
- Add adjacent Runs/Policy/Connections/Evidence views.

Exit gate:

- A user can discover and operate Workflows from first launch.

### Phase 3: Daemon Runtime Adapter

Outcome:

The composer reads and writes through daemon contracts.

Status: blocked on daemon APIs; current adapter is explicit fixture projection.

Tasks:

- Implement workflow list/load/save.
- Implement dry-run/preflight.
- Implement event stream projection.
- Implement approvals/receipts/replay.
- Implement proposal-first materialization.

Exit gate:

- Mutating workflow actions fail closed or settle through daemon receipts.

### Phase 4: Connector-Neutral Composer Readiness

Outcome:

The rich composer proves connector sprint readiness without real connector work.

Status: complete for fixture/mock/dry-run flows.

Tasks:

- Add mock connector capability fixture.
- Bind fixture to node.
- Run fixture dry-run.
- Project approval/receipt/replay.
- Capture evidence screenshots.

Exit gate:

- Connector fixture passes with `externalAction: false`.

### Phase 5: Parity Closeout

Outcome:

The Electron app replaces the Tauri workflow compositor experience.

Status: complete for fixture-backed visual/behavioral parity; production
closeout requires daemon-backed runtime adapter and final legacy React/Tauri
deletion.

Tasks:

- Compare visible UX against legacy Tauri screenshots/evidence.
- Port or delete remaining legacy React/Tauri workflow surfaces.
- Remove any stale docs that imply Tauri UX is the richer canonical path.
- Update parent guide with green parity evidence.

Exit gate:

- Product owner can launch Electron app and see the rich workflow compositor
  without caveats.

## Definition Of Done

This guide is complete only when:

- `WorkflowComposer` is mounted in the Electron/VS Code fork.
- The Workflows surface is visually and functionally rich enough to replace the
  Tauri compositor.
- The composer is operated through `ioi-workbench`, not `apps/autopilot`.
- Runtime actions route through daemon contracts or explicit fixture adapters.
- Validation captures visual evidence of canvas, rail, inspector, readiness,
  run timeline, receipts/replay, and connector fixture binding.
- The parent IDE-first guide links to passing compositor parity evidence.

Completion status:

- Complete for Electron workflow-compositor parity and connector-neutral
  fixture readiness.
- Not complete for production daemon-backed workflow execution or live
  connector action.

## Exact Next Implementation Prompt

```text
Goal: complete the Autopilot Electron Workbench Workflow Compositor Parity
master guide.

Use
.internal/plans/autopilot-electron-workbench-workflow-compositor-parity-master-guide.md
as source of truth.

Mount the real @ioi/agent-ide WorkflowComposer inside the VS Code/Electron fork
through ioi-workbench. Do not revive Tauri. Do not treat the current workflow
list/projection as parity. Add the validation harness that launches the
canonical Electron app, opens Workflows, proves the rich canvas/rail/inspector
UI is visible and operable, exercises a connector-neutral dry-run fixture, and
stores screenshots/logs/proof under
docs/evidence/autopilot-workbench-workflow-compositor-parity/.

Report remaining blockers before any real connector-specific sprint begins.
```
