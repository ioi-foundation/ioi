# OpenVSCode Native Autopilot Contribution Replacement Master Guide

Owner: Autopilot / OpenVSCode fork / Workspace substrate / Chat runtime / Workflow Composer

Status: active / native chat-command-center replacement validated; workflow-to-code loop still active

Created: 2026-05-19

## Executive Verdict

The original unified chat mode was a useful bridge, but it was not the final
substrate shape. Autopilot now installs a managed native OpenVSCode
replacement overlay: upstream Chat is profile-gated, `ioi.chat` is mounted in
the native secondary side bar, the outer shell no longer renders a second chat
pane for managed workbench hosts, and the OpenVSCode command-center getter plus
`CommandCenter` renderer contribution are patched at the workbench bundle level
instead of being hidden with CSS. The remaining work is to make workflow-to-code
and receipt/evidence loops as native as the chat and command-center ownership.

The target is fork-level/native contribution replacement:

> OpenVSCode should treat Autopilot as the native workbench agent contribution.
> Autopilot owns the chat contribution, command routing, context capture,
> workflow materialization, code-generation handoff, inspector target index,
> and receipt/evidence panes from inside the workbench shell, while IOI runtime
> contracts remain the only execution truth.

This is the Antigravity-style objective: the editor substrate should feel as if
the agent workbench is native to it, not adjacent to it.

## Non-Negotiable Doctrine

- No second runtime.
- The OpenVSCode fork/extension is a projection and control adapter, not an
  autonomous agent runtime.
- Daemon/runtime contracts remain source of truth.
- Agentgres records operational truth.
- Wallet authority authorizes power.
- Models propose; runtime settles.
- Policy is not tracing.
- Provider names, connector transports, and plugin mechanics must not become
  workflow semantics.
- Filesystem, Git, terminal, task, browser, and connector actions must remain
  typed, authority-scoped, proposal-first where mutating, and receipted.
- Workflow Composer and OpenVSCode must both compile to the same deterministic
  workflow/autonomous-system manifests.
- OpenVSCode APIs may expose editor state, diagnostics, SCM, tasks, terminals,
  and webview views, but they do not own IOI runtime state.

## Current State

Implemented:

- Autopilot shell renders a shared `OperatorChatPane`.
- The bundled `ioi-workbench` OpenVSCode extension contributes IOI views and
  commands.
- `ioi.chat` is mounted in the OpenVSCode secondary side bar as the managed
  native chat contribution.
- Direct and iframe OpenVSCode hosts no longer receive a second outer shell chat
  pane; non-native preview hosts keep it as a fallback.
- OpenVSCode command center ownership is disabled by an idempotent managed
  workbench JavaScript overlay that rewrites the native titlebar
  command-center getter and replaces the upstream `CommandCenter` renderer with
  an inert native no-op contribution; managed settings/keybindings remain
  safety defaults.
- Live desktop evidence at
  `/tmp/autopilot-openvscode-native-replacement/direct-probe/2026-05-19T13-25-07Z/native-composited-parent.png`
  shows the Autopilot header as the only global command/search owner, one
  native IOI chat view in the OpenVSCode secondary side bar, and no OpenVSCode
  internal command-center search field.
- Native workbench and IOI commands now emit `WorkbenchCommandRouteReceipt`
  bridge requests so runtime/evidence surfaces can distinguish editor-local,
  IOI-runtime, and blocked command routes.
- A parity harness remains available for upstream UX inspection, but normal
  launch no longer depends on CSS hiding for native Chat or command-center
  ownership.
- Workflow Composer can materialize/open a project scaffold through Autopilot
  workspace paths.

Still shallow:

- OpenVSCode command routing is partially bridged into IOI command route
  receipts, but not yet a full native IOI command/action/control bus.
- Workflow-generated code paths are not yet fully mediated by a native
  workbench contribution that can propose edits, show diffs, run checks, expose
  diagnostics, and emit receipts in one loop.
- Inspector target indexing is present, but should move toward native
  workbench target descriptors instead of relying on outer-shell geometry and
  DOM probing alone.

## Target End State

Autopilot should ship a managed OpenVSCode fork/profile where:

- upstream native Chat is disabled or replaced at source/contribution level,
  not hidden with CSS;
- Autopilot contributes the canonical right-side chat view as a native
  workbench view/webview;
- Autopilot command center semantics are native to the workbench while the
  global Autopilot header remains the outer shell command owner;
- editor context, selection, diagnostics, SCM state, tasks, terminals, and file
  tree state flow through typed IOI bridge contracts;
- Workflow Composer can create or open an Autonomous System Package and have
  the workbench contribution materialize code, proposals, diffs, checks, and
  receipts in place;
- a workflow run can write code as composed by emitting a runtime-settled
  plan, proposal, workspace edit, diff artifact, approval receipt, apply
  receipt, verification receipt, and package/run evidence;
- web/computer-use inspectors can target OpenVSCode UX elements through native
  target descriptors before falling back to DOM/AX/coordinates;
- users see one chat UX, one command model, one authority model, and one
  receipt trail.

## Architecture Shape

### Native Workbench Contribution

Create or promote an IOI OpenVSCode contribution with these responsibilities:

- register `ioi.chat` as the canonical workbench chat view;
- register IOI-native title actions in the same row as VS Code chat controls;
- register IOI command palette commands for chat, workflows, runs, receipts,
  policies, project materialization, review, checks, and promotion;
- expose editor/workspace context through a bridge service;
- receive runtime projections from Autopilot/daemon services;
- render `OperatorChatPane` inside a VS Code webview or native-compatible
  view host;
- surface runtime receipts/artifacts/evidence without owning them.

The contribution should be built as a thin workbench adapter:

```text
OpenVSCode contribution
  -> WorkbenchContextSnapshot
  -> IOI Workspace Bridge
  -> Autopilot daemon/runtime
  -> Agentgres / wallet / policy / capabilities
  -> receipts/events/artifacts
  -> OpenVSCode projected views
```

### Fork-Level Product Patches

Use fork/product patches for concerns that should not be runtime CSS:

- disable or remove upstream Chat contribution registration;
- disable upstream command center ownership when Autopilot shell owns it;
- set default right-side view container to IOI Chat when appropriate;
- install IOI workbench extension/profile by default;
- expose stable IDs/data attributes for native workbench chrome;
- keep settings/keybindings as user-level preferences, not suppression hacks.

CSS may still style IOI-owned views. CSS must not be the mechanism that hides
upstream runtime-relevant contributions.

### Runtime Bridge Contracts

Add explicit contracts for native workbench integration:

```text
WorkbenchContextSnapshot
  workspace_root
  active_file
  active_selection
  open_editors
  diagnostics
  scm_state
  terminal_state
  task_state
  visible_view
  inspection_targets

WorkbenchActionProposal
  proposal_id
  source_command
  context_ref
  requested_capability
  authority_scope
  predicted_effect
  requires_approval

WorkbenchEditProposal
  proposal_id
  file_edits
  diff_refs
  diagnostics_before
  expected_postcondition
  approval_profile

WorkbenchApplyReceipt
  proposal_id
  applied_edits
  diagnostics_after
  scm_state_after
  artifact_refs
  receipt_refs

WorkflowCodeGenerationRequest
  workflow_ref
  package_ref
  goal
  bound_model_capability
  bound_tool_capabilities
  target_workspace
  authority_scope
  eval_profile

WorkflowCodeGenerationReceipt
  request_ref
  created_files
  changed_files
  diff_refs
  run_refs
  verification_refs
  promotion_blockers
```

These contracts should be SDK/API consumable and not React-only.

### Workflow-To-Code Loop

The desired happy path:

```text
compose workflow
-> bind model/tool capabilities
-> create Autonomous System Package
-> open package in OpenVSCode substrate
-> run workflow in simulate/proposal mode
-> generate code proposal
-> inspect diff and diagnostics
-> approve/apply
-> run checks/evals
-> inspect receipts
-> package/promote
```

OpenVSCode should make this loop tangible:

- show generated files in explorer;
- open proposed diffs in editor;
- show diagnostics/checks in Problems/terminal/task views;
- expose run/eval receipts in IOI views;
- allow chat to reference editor selections and workflow nodes;
- allow workflow runs to target the current workspace without inventing a
  separate local state store.

## Completion Dashboard

| Slice | Goal | Status | Done when |
| --- | --- | --- | --- |
| Source map | Inventory OpenVSCode fork/profile, extension, product patch, and shell suppression points. | Done / migration map | Every current CSS/settings/keybinding suppression path and extension contribution is mapped to keep/replace/remove. |
| Native contribution contract | Define workbench bridge contracts and command/action/event envelopes. | Done / regression guarded | Contracts exist in source, tests prove they are projection/control contracts and not runtime truth. |
| Fork patch strategy | Decide vendored patch, source fork, or build overlay approach for OpenVSCode. | Done / overlay manifest guarded | Managed OpenVSCode installations write a deterministic native replacement patch manifest, remove legacy CSS suppression, and install profile-level contribution/command ownership defaults. |
| Upstream chat replacement | Remove/disable upstream Chat contribution at source/profile level. | Done / profile gate guarded | Managed profile disables upstream chat/agent/session features, `ioi.chat` owns the secondary side bar, and auxiliary/chat CSS suppression is retired. |
| IOI native chat view | Mount canonical Autopilot chat as a native OpenVSCode view/webview. | Done / native secondary-sidebar route guarded | `ioi.chat` renders the canonical operator chat pane shape in the OpenVSCode secondary side bar, routes composer/actions through bridge requests, and normal unified launch no longer renders a second chat UX. |
| Command center ownership | Remove duplicate OpenVSCode command center and route native commands through Autopilot command model. | Done / native renderer overlay and route receipts guarded | Autopilot header owns global command center through a managed workbench JS overlay that disables the getter and upstream renderer contribution, profile defaults, keybinding guards, and `WorkbenchCommandRouteReceipt` projection. |
| Workbench context bridge | Emit typed editor/workspace/diagnostics/SCM/task snapshots. | Done / context snapshot guarded | Extension publishes `workbench.contextSnapshot` bridge requests for editor, selection, tabs, diagnostics, Git/dirty SCM posture, active/recent tasks, terminal, and view state without creating editor-owned runtime truth. |
| Workflow code generation | Let composed workflows generate code proposals in the open workspace. | In progress / proposal artifact guarded | Native extension can raise `workflow.codeGenerationRequest`; shell routing materializes a proposal-only artifact bundle under `.agents/workflow-code-proposals/*` with request, placeholder diff, verification checklist, and `WorkflowCodeGenerationReceipt` projection before any mutation. |
| Inspector target descriptors | Replace geometry-first probing with native workbench target descriptors. | In progress / native index guarded | Extension publishes `workbench.inspectionTargetIndex` bridge requests for IOI activity, chat pane, composer, explorer, terminal, problems, and active editor range refs. |
| Migration from shell bridge | Retire CSS suppression and outer-shell chat adjacency where native integration is available. | In progress / native-chat path guarded | Direct/iframe OpenVSCode hosts suppress the outer shell-side chat pane, and managed installs remove the legacy stylesheet suppression marker entirely. |
| GUI/e2e validation | Prove the native integration end to end. | In progress / native chat-command-center screenshot guarded | Live clickthrough at `/tmp/autopilot-openvscode-native-replacement/direct-probe/2026-05-19T13-25-07Z` shows one native IOI chat surface and no duplicate OpenVSCode command center; remaining e2e work is workflow-to-code, apply/check receipts, and inspector targeting against live refs. |

## Slice 1 Source Map

This map is the current source of truth for what exists today, why it exists,
and how it should migrate during the native replacement leg.

| Area | File/module | Current role | Disposition | Replacement target |
| --- | --- | --- | --- | --- |
| OpenVSCode download/install | `apps/autopilot/src-tauri/src/workspace_ide.rs` (`OPENVSCODE_VERSION`, `archive_download_url`, `ensure_openvscode_installation`) | Downloads and installs stock OpenVSCode Server `1.109.5` into the Autopilot data dir. | Keep, then wrap with deterministic patch overlay. | Managed OpenVSCode artifact with reproducible product/contribution patches. |
| Legacy runtime CSS suppression cleanup | `apps/autopilot/src-tauri/src/workspace_ide.rs` (`ensure_openvscode_legacy_shell_chrome_patch_removed`, `remove_openvscode_legacy_stylesheet_chrome_patch`) | Removes old Autopilot CSS marker blocks from cached OpenVSCode stylesheets. | Keep as cleanup guard only. | No normal-launch CSS hiding for native Chat or command-center ownership. |
| Native command-center overlay | `apps/autopilot/src-tauri/src/workspace_ide.rs` (`ensure_openvscode_native_workbench_js_patch`, `patch_openvscode_native_workbench_js`) | Rewrites the OpenVSCode titlebar command-center getter from `get ec(){...window.commandCenter...}` to `get ec(){return!1}`, replaces the upstream `CommandCenter` renderer with an inert `data-ioi-native-command-center-disabled` contribution, and marks the bundle with an IOI patch marker. | Keep until source fork carries the same contribution replacement natively. | Autopilot header is the only global command center owner without CSS hiding. |
| User settings suppression | `apps/autopilot/src-tauri/src/workspace_ide.rs` (`ensure_openvscode_user_settings`) | Writes profile settings disabling command center, native navigation controls, layout control, and upstream Chat features while keeping the secondary side bar visible for native IOI Chat. | Keep as managed profile default. | Managed product/profile defaults plus source overlay where upstream Chat/command center are disabled structurally. |
| Keybinding suppression | `apps/autopilot/src-tauri/src/workspace_ide.rs` (`ensure_openvscode_user_keybindings`) | Unbinds quick-open/show-commands shortcuts so Autopilot header owns global command entry. | Keep until native IOI command router is complete. | IOI command router with editor-local commands preserved and Autopilot-global commands routed to receipts. |
| User-config ownership guard | `apps/autopilot/src-tauri/src/workspace_ide.rs` (`openvscode_user_config_owned`) | Forces stale OpenVSCode sessions to relaunch when suppression settings/keybindings are missing. | Replace. | Patch/profile ownership guard that verifies native replacement profile is installed. |
| Bundled extension install | `apps/autopilot/src-tauri/src/workspace_ide.rs` (`ensure_bundled_extension`) | Copies `ioi-workbench` into the managed OpenVSCode extensions dir on every session. | Keep and harden. | Bundled native IOI contribution with chat/context/proposal/target-index bridge. |
| Bridge server | `apps/autopilot/src-tauri/src/workspace_ide.rs` (`spawn_bridge_server`, `/state`, `/requests`, `/commands`) | Lightweight local bridge carrying state projections, UI requests, and queued OpenVSCode commands. | Keep, then type. | Bridge payloads shaped by SDK workbench contracts and runtime receipts. |
| Session launch env | `apps/autopilot/src-tauri/src/workspace_ide.rs` (`ensure_workspace_ide_session`) | Launches OpenVSCode with bridge env vars and isolated data/extensions dirs. | Keep. | Same session lifecycle, plus deterministic native patch validation before launch. |
| Extension manifest | `apps/autopilot/openvscode-extension/ioi-workbench/package.json` | Registers `ioi.chat` in the OpenVSCode secondary side bar, IOI activity views, commands, command palette entries, and editor/explorer context menu commands. | Keep and expand. | Canonical native Autopilot chat contribution and workbench adapter commands. |
| Extension bridge/runtime state | `apps/autopilot/openvscode-extension/ioi-workbench/extension.js` (`defaultBridgeState`, `readBridgeState`, polling, `writeWorkbenchCommandRouteReceipt`) | Pulls shell/daemon projections, executes queued commands, and emits command route receipts. | Keep and expand. | `WorkbenchContextSnapshot`, `WorkbenchCommandRouteReceipt`, and proposal/edit/apply receipts. |
| Extension placeholder chat | `apps/autopilot/openvscode-extension/ioi-workbench/extension.js` (`renderChatView`) | Shows a small runtime summary/callout, not the real operator chat pane. | Replace. | Native IOI Chat webview mounting `OperatorChatPane`-equivalent UI backed by IOI runtime projections. |
| Shell chat pane | `packages/workspace-substrate/src/components/OperatorChatPane.tsx` | Canonical shared React chat pane for shell/full/sidebar/docked mode. | Keep as reference/asset source. | Bundle or project equivalent UX inside native OpenVSCode IOI chat webview. |
| Workspace host dock | `packages/workspace-substrate/src/components/WorkspaceHost.tsx` (`WorkspaceOperatorChatPane`) | Renders shell-side docked chat for non-native substrate preview/fallback surfaces. | Keep only as fallback. | Native OpenVSCode `ioi.chat` view owns the right-side chat in managed workbench. |
| Outer workspace shell reservation | `apps/autopilot/src/surfaces/Workspace/WorkspaceShell.tsx` | Can reserve right-side pixels for shell-rendered operator chat. | Keep only as fallback. | Direct/iframe OpenVSCode hosts use the native secondary-sidebar chat contribution instead of an outer shell pane. |
| Direct webview host | `apps/autopilot/src/surfaces/Workspace/OpenVsCodeDirectSurface.tsx`, `apps/autopilot/src-tauri/src/workspace_direct_webview.rs` | Hosts OpenVSCode as a bounded Tauri child/owned webview and exposes fallback target metadata. | Keep. | Add native target descriptors from the extension before DOM/geometry fallback. |
| Shell command center | `apps/autopilot/src/windows/AutopilotShellWindow/components/ChatIdeHeader.tsx` and `operatorSubstrateModel.ts` | Autopilot-global command/search owner. | Keep. | Remains the only global command center; OpenVSCode commands bridge or stay editor-local. |
| Workflow project materialization | `apps/autopilot/src/windows/AutopilotShellWindow/operatorSubstrateModel.ts`, Workflow Composer surfaces | Creates Autonomous System Package/project scaffold and opens workspace. | Keep and extend. | Workflow-to-code request/receipt path targeting the active OpenVSCode workspace. |
| Parity harness | `scripts/lib/openvscode-chat-parity-audit.mjs` | Temporarily restores native OpenVSCode chat by removing suppression CSS rules for inspection and screenshot capture. | Keep as audit-only. | Reference harness, not normal runtime dependency. |
| Legacy generated evidence | `docs/evidence/**` and `/tmp/autopilot-*` outputs | Stores screenshots/logs from probes. | Do not commit generated outputs. | Keep final evidence outside git or ignored. |

### Migration Rules From The Map

- Replace runtime CSS hiding before declaring native replacement complete.
- Keep profile settings that enforce safety, onboarding, and upstream chat
  feature gates; do not use CSS or keybinding suppression as the primary
  upstream Chat removal mechanism.
- Keep the bridge server, but move payload semantics into typed SDK contracts.
- Treat `ioi-workbench` as the native adapter. It may render IOI views, collect
  workbench context, and route proposals, but it must never settle model/tool
  actions itself.
- Retain the parity harness so the team can inspect upstream OpenVSCode UX, but
  normal desktop launch must not depend on it.

## Slice 2 Native Contribution Contracts

The first SDK contract slice lives in
`packages/agent-sdk/src/workbench-integration.ts` and exports:

- `WorkbenchContextSnapshot`
- `WorkbenchActionProposal`
- `WorkbenchEditProposal`
- `WorkbenchApplyReceipt`
- `WorkflowCodeGenerationRequest`
- `WorkflowCodeGenerationReceipt`
- `WorkbenchInspectionTargetIndex`
- `WorkbenchCommandRouteReceipt`

Every object extends a projection contract with:

```text
schemaVersion = ioi.workbench-integration.v1
runtimeTruthSource = daemon-runtime
projectionOwner = openvscode-workbench-adapter
ownsRuntimeState = false
runtimeRefs = receipt/artifact/authority/manifest/capability refs
```

This makes the OpenVSCode contribution a native control/projection adapter
without giving it an editor-owned runtime truth store.

## Slice 3 Fork/Profile Patch Strategy

Autopilot now writes an idempotent managed patch manifest into each managed
OpenVSCode installation:

```text
<openvscode-install-root>/.ioi-autopilot/managed-openvscode-patch.json
schemaVersion = ioi.openvscode-managed-patch.v1
patchId = openvscode-native-autopilot-contribution-replacement
```

The manifest is the replacement control plane for the OpenVSCode fork/profile
work. It names the target native steps and records the current migration
posture:

- `disable-upstream-chat-contribution`
- `disable-upstream-command-center`
- `install-ioi-workbench-contribution`
- `bridge-workbench-context`
- `export-native-target-index`
- `workflow-code-generation-receipts`

It records command-center ownership as a native workbench overlay:

```text
temporaryCompatibility = false
mechanism = managed-workbench-js-contribution-noop-and-profile-keybinding
patchMarker = IOI Autopilot native workbench command center replacement v1
```

The overlay rewrites the OpenVSCode titlebar command-center getter and the
upstream `CommandCenter` renderer contribution. The getter is forced off and
the renderer is replaced with an inert hidden element marked
`data-ioi-native-command-center-disabled`, so upstream settings cannot resurrect
the duplicate center search field. Editor-local commands and view controls
remain available through menus, keybindings, and IOI route receipts. Runtime
tests guard that the manifest states OpenVSCode does not own IOI runtime state,
upstream Chat is not allowed in the normal launch contract, the JS overlay is
idempotent, the legacy CSS marker is removed, and the patch metadata stays
provider-neutral.

## Slice 4 Upstream Chat Replacement Profile Gate

The managed OpenVSCode profile now disables the upstream chat/agent/session
surface with profile-level feature gates:

```text
chat.disableAIFeatures = true
chat.agent.enabled = false
chat.viewSessions.enabled = false
chat.agentSessionProjection.enabled = false
```

`openvscode_user_config_owned` treats those gates as part of session ownership,
so stale OpenVSCode sessions relaunch if native chat is re-enabled. The managed
patch manifest records this as:

```text
disable-upstream-chat-contribution
status = installed-profile-gate
temporaryCompatibility = false
```

This is a real profile-level replacement step. The auxiliary/chat stylesheet
suppression has been removed because `ioi.chat` now mounts natively inside the
OpenVSCode secondary side bar. The installer also removes the older command
center/chat CSS marker from cached OpenVSCode assets so normal launch does not
depend on stylesheet hiding.

## Slice 5 IOI Native Chat Webview Shell

The `ioi-workbench` OpenVSCode extension now contributes `ioi.chat` to the
OpenVSCode secondary side bar and renders it as an Autopilot-owned operator
chat pane instead of a runtime summary placeholder.

The native view includes:

- `data-operator-chat-pane="native-openvscode"`;
- `data-inspection-target="native-ioi-chat-pane"`;
- canonical empty state copy and suggested actions;
- a compact composer with context, mode, model, tool, and send controls;
- bridge-request routing for suggested actions, context attachment, and prompt
  submit;
- native view title actions for new chat, new-chat options, settings, and more
  actions.

All user actions from this native pane post bridge requests back to the IOI
runtime:

```text
ioi.chat webview -> bridgeRequest -> workspace bridge -> daemon/runtime refs
```

The extension still does not own runtime state. This slice provides a native
workbench contribution shell that replaces upstream chat in normal managed
profiles. The shell no longer renders a second outer chat pane for direct or
iframe OpenVSCode workspaces; non-native preview surfaces retain that fallback.
The next hardening step is to bundle the full shared
`OperatorChatPane` asset or equivalent into this webview so visual parity is
source-shared rather than manually mirrored.

## Slice 5B Command Route Receipts

Native IOI commands and shell-queued OpenVSCode commands now emit
`WorkbenchCommandRouteReceipt` bridge requests:

```text
requestType = workbench.commandRouteReceipt
route = ioi-runtime-action | editor-local | blocked
runtimeTruthSource = daemon-runtime
projectionOwner = openvscode-workbench-adapter
ownsRuntimeState = false
```

This makes command-center ownership auditable without making OpenVSCode a
second runtime. IOI commands such as `chat.submit`,
`workflow.codeGenerationRequest`, `runs.open`, `policy.open`, and
`automation.browser` route to the IOI runtime action path. Bridge-polled
workbench commands such as `workbench.action.splitEditorRight` remain
editor-local and emit editor-local route receipts. Failed command execution
emits a blocked/failed receipt instead of disappearing inside the workbench.

## Slice 6 Native Workbench Context Snapshot Bridge

The `ioi-workbench` extension now builds and publishes native
`WorkbenchContextSnapshot`-shaped bridge requests:

```text
requestType = workbench.contextSnapshot
schemaVersion = ioi.workbench-integration.v1
runtimeTruthSource = daemon-runtime
projectionOwner = openvscode-workbench-adapter
ownsRuntimeState = false
```

The first snapshot payload includes:

- active editor URI, language, dirty state, selection, and selected text;
- open editor/tab labels, URIs, dirty state, active state, and group index;
- diagnostics with URI, message, severity, source, code, and range;
- terminal count and active terminal name;
- visible view summary for IOI chat and active editor state.

The publisher runs on activation, editor changes, selection changes,
diagnostic changes, tab changes, terminal changes, and a low-frequency poll.
It hashes stable snapshot content to avoid flooding the bridge with timestamp
churn. SCM provider detail and task execution receipts are intentionally
marked as follow-up adapter details rather than guessed from the UI.

## Slice 7 Native Inspection Target Index

The `ioi-workbench` extension now publishes native target descriptors through:

```text
requestType = workbench.inspectionTargetIndex
indexId = workbench-target-index:latest
```

The first index includes native-first targets for:

- IOI activity rail / view container;
- native IOI chat view;
- native IOI chat composer;
- Explorer;
- Terminal panel;
- Problems panel;
- active editor range when an editor is active.

Each target uses `vscode-command`, `vscode-view`, `editor-range`,
`data-attribute`, or `aria` locators before allowing fallback. This starts the
shift away from geometry-first browser/computer-use probing and toward native
workbench target refs that can be receipted by the IOI runtime.

## Slice 8 Workflow-To-Code Proposal Artifacts And Shell Routing

The native IOI workbench extension now contributes:

```text
command = ioi.workflow.generateCode
requestType = workflow.codeGenerationRequest
```

The request payload is shaped like `WorkflowCodeGenerationRequest`:

```text
schemaVersion = ioi.workbench-integration.v1
runtimeTruthSource = daemon-runtime
projectionOwner = openvscode-workbench-adapter
ownsRuntimeState = false
proposalOnly = true
authorityScope = workspace.fs.proposal
```

It carries workflow/package refs, bound model/tool capability refs, the active
workspace path, and the requested goal. The extension only proposes and routes
the request; it does not mutate the filesystem or settle model/tool actions.
The shell bridge router now handles this request intentionally instead of
dropping it as an unknown event. Before opening the runtime chat intent, the
router materializes proposal-only workspace artifacts:

```text
.agents/workflow-code-proposals/<workflow-slug>/
  request.json
  proposal.md
  diffs/proposed.patch
  checks/checklist.md
  receipts/workflow-code-generation-receipt.json
```

The receipt uses `schemaVersion = ioi.workbench-integration.v1`,
`runtimeTruthSource = daemon-runtime`, `projectionOwner =
openvscode-workbench-adapter`, `ownsRuntimeState = false`, `status =
proposed`, and an empty `changedFiles` list. The generated diff file is a
placeholder that explicitly says target source files are unchanged until IOI
settles an approved patch.

After writing the proposal artifacts, the router converts the native request
into a runtime chat intent that names the workflow/package, model/tool
capability refs, target workspace, and proposal-only mutation posture:

```text
Generate code from <workflowRef> in <workspace>.
Package: <packageRef>.
Mutation posture: proposal-only.
Produce a bounded proposal, diff artifact, approval/check plan, and receipt trail before any apply.
```

The same router now handles native `chat.submit`,
`workbench.contextSnapshot`, `workbench.inspectionTargetIndex`, and
`workbench.commandRouteReceipt` requests deliberately. Context/target/route
events are currently recorded through bridge metrics and do not create a React
shadow store. The remaining workflow-to-code work is daemon-side generation of
the final patch, native diff editor opening, approval/apply receipts,
task/check receipts, eval receipts, and Workflow Composer activation against
the active OpenVSCode workspace.

## Implementation Order

1. **Inventory current integration points**
   - `apps/autopilot/src-tauri/src/workspace_ide.rs`
   - `apps/autopilot/openvscode-extension/ioi-workbench/*`
   - `apps/autopilot/src/surfaces/Workspace/*`
   - `packages/workspace-substrate/*`
   - `scripts/lib/openvscode-chat-parity-audit.mjs`
   - OpenVSCode vendored install/build paths under the local desktop profile.

2. **Add bridge contracts**
   - Add TypeScript/Rust contract definitions for workbench context snapshots,
     workbench action proposals, edit proposals, apply receipts, and workflow
     code-generation receipts.
   - Add contract tests proving these objects point to runtime refs and do not
     duplicate runtime truth.

3. **Choose the fork/patch mechanism**
   - Prefer deterministic source or build overlay patches.
   - Avoid runtime mutation of installed CSS as the long-term mechanism.
   - Keep a temporary compatibility path while migrating.

4. **Replace upstream chat contribution**
   - Locate upstream Chat contribution registration.
   - Disable/remove it in the managed Autopilot OpenVSCode build/profile.
   - Ensure upstream Chat commands do not leak into the default command palette
     as primary Autopilot semantics.

5. **Mount IOI Chat natively**
   - Promote `ioi.chat` from a placeholder webview to the canonical
     `OperatorChatPane` workbench view.
   - Bundle the chat view assets for the extension/webview.
   - Use `postMessage`/bridge APIs for runtime projections and user actions.
   - Preserve the same action row/order captured from native VS Code chat where
     it improves UX.

6. **Bridge editor/workspace context**
   - Emit active editor, selection, file tree, diagnostics, SCM, task, and
     terminal snapshots.
   - Make chat context picker and workflow composer consume these refs.
   - Add receipts when context is attached to a chat turn or workflow run.

7. **Wire workflow-to-code**
   - Add `Create project from workflow` and `Generate code in workspace` paths
     to call runtime APIs and then project results into OpenVSCode.
   - Use proposal-first edits and native diff editors.
   - Emit apply/check/eval receipts through IOI runtime.

8. **Native inspector targets**
   - Export a native target index from the extension for workbench elements.
   - Prefer native target refs over DOM/AX/coordinate fallback.
   - Include view IDs, command IDs, editor groups, tab IDs, file paths,
     line/column ranges, terminal IDs, problems, run rows, and IOI view IDs.

9. **Retire CSS suppression**
   - Remove long-term stylesheet patch dependency for native Chat and command
     center suppression.
   - Keep audit harness support for reference captures only.
   - Keep feature flag fallback until native contribution validates in dev and
     desktop builds.

10. **Validate e2e**
    - Launch fresh desktop profile.
    - Open workspace.
    - Confirm there is one chat UX and it is the IOI native contribution.
    - Confirm OpenVSCode command center is absent where Autopilot header owns it.
    - Attach current selection to chat.
    - Compose a workflow and materialize a project.
    - Generate code proposal into the workspace.
    - Inspect diff, diagnostics, checks, receipts, and Agentgres run refs.
    - Approve/apply proposal.
    - Run fixture eval.
    - Inspect target descriptors through computer-use/web inspector.

## Validation Requirements

- Static contract tests for bridge objects.
- Extension activation tests where feasible.
- Build validation for OpenVSCode patch overlay.
- Desktop GUI probes for native chat contribution.
- Workflow Composer e2e probe for workflow-to-code.
- Inspector target-index probe.
- Old workflow/project compatibility tests.
- `git diff --check`.
- Generated screenshots/logs stay outside git.

## Explicit Non-Goals

- Do not make the OpenVSCode extension run a separate agent runtime.
- Do not let VS Code Chat own IOI chat semantics.
- Do not fork provider-specific model routing into editor code.
- Do not let workflow state live only in the OpenVSCode webview.
- Do not expand connector surface area before code-generation and edit
  proposal receipts are correct.
- Do not delete the parity harness; keep it as a reference/audit tool.

## Risks

- Fork maintenance may become heavy if product patches are broad.
- Webview bundling can drift from shell `OperatorChatPane` if not shared.
- Native extension APIs can tempt UI-owned state. Guard with contracts/tests.
- Proposal-first code generation needs careful authority and UX design to avoid
  hidden file mutation.
- Inspector target descriptors need stable IDs across OpenVSCode updates.

## Exit Criteria

- Native OpenVSCode chat is replaced by IOI Chat without CSS hiding.
- Autopilot header remains the only global command center owner.
- OpenVSCode contributes IOI views/commands as first-class workbench features.
- Workflow Composer can generate code proposals into the active workspace.
- Diffs, checks, evals, approvals, and receipts are visible in the workbench and
  backed by IOI runtime events.
- Inspector can target OpenVSCode and IOI workbench elements by native refs.
- Normal desktop launch shows one unified chat UX and no split-brain native
  chat surface.
- Targeted tests and GUI e2e probes pass.
