# OpenVSCode Native Autopilot Contribution Replacement Master Guide

Owner: Autopilot / OpenVSCode fork / Workspace substrate / Chat runtime / Workflow Composer

Status: planned / P0 before broad code-workflow expansion

Created: 2026-05-19

## Executive Verdict

The current unified chat mode is a useful bridge, but it is not the final
substrate shape. Autopilot currently renders the canonical `OperatorChatPane`
outside the embedded OpenVSCode workbench and suppresses native OpenVSCode
chat/command chrome with settings, keybindings, and stylesheet patches. That
keeps runtime truth unified, but it is still shell-level integration.

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
- `WorkspaceShell` reserves space for the Autopilot chat pane next to direct
  OpenVSCode.
- The bundled `ioi-workbench` OpenVSCode extension contributes IOI views and
  commands.
- OpenVSCode command center and native auxiliary chat are suppressed with user
  settings/keybindings plus CSS patching.
- A parity harness can temporarily restore the native OpenVSCode chat surface
  for inspection by removing suppression CSS rules from the live page.
- Workflow Composer can materialize/open a project scaffold through Autopilot
  workspace paths.

Still shallow:

- OpenVSCode does not natively host the canonical Autopilot chat contribution.
- Native OpenVSCode chat is hidden rather than removed/replaced at product or
  contribution registration time.
- Autopilot chat is visually adjacent to the workbench rather than structurally
  part of the workbench view container.
- OpenVSCode command routing is partially bridged, but not yet a full native
  IOI command/action/control bus.
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
| Source map | Inventory OpenVSCode fork/profile, extension, product patch, and shell suppression points. | Pending | Every current CSS/settings/keybinding suppression path and extension contribution is mapped to keep/replace/remove. |
| Native contribution contract | Define workbench bridge contracts and command/action/event envelopes. | Pending | Contracts exist in source, tests prove they are projection/control contracts and not runtime truth. |
| Fork patch strategy | Decide vendored patch, source fork, or build overlay approach for OpenVSCode. | Pending | Build process can apply deterministic product/contribution patches without manual CSS surgery. |
| Upstream chat replacement | Remove/disable upstream Chat contribution at source/profile level. | Pending | Native OpenVSCode chat no longer needs CSS hiding; IOI Chat is the only visible chat contribution. |
| IOI native chat view | Mount canonical Autopilot chat as a native OpenVSCode view/webview. | Pending | Right-side workbench chat is `OperatorChatPane` backed by IOI runtime projections. |
| Command center ownership | Remove duplicate OpenVSCode command center and route native commands through Autopilot command model. | Pending | Autopilot header owns global command center; OpenVSCode local commands bridge into IOI command/action receipts. |
| Workbench context bridge | Emit typed editor/workspace/diagnostics/SCM/task snapshots. | Pending | Chat and workflows can reference current file, selection, diagnostics, branch, tasks, and terminal state by stable refs. |
| Workflow code generation | Let composed workflows generate code proposals in the open workspace. | Pending | Prompt-agent/tool-agent/repo-agent workflows can produce proposal-first diffs, checks, and receipts. |
| Inspector target descriptors | Replace geometry-first probing with native workbench target descriptors. | Pending | Inspector can address explorer rows, editor tabs, commands, chat composer, terminal, problems, and IOI views by native target refs. |
| Migration from shell bridge | Retire CSS suppression and outer-shell chat adjacency where native integration is available. | Pending | Normal mode no longer depends on stylesheet patches for chat/command replacement. |
| GUI/e2e validation | Prove the native integration end to end. | Pending | Live clickthrough shows one chat UX, no native split brain, workflow-to-code, receipts, checks, and inspector targeting. |

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
