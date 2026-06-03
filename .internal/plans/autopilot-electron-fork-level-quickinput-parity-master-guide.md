# Autopilot Electron Fork-Level QuickInput Parity Master Guide

Owner: Autopilot Workbench / VS Code fork / QuickInput-QuickAccess substrate / `ioi-workbench` / IOI daemon / validation harness

Status: implemented and validated as fork/workbench shell contribution shim; upstream TypeScript QuickInput contribution remains the hardening path

Created: 2026-05-23

Parent guides:

- `.internal/plans/autopilot-electron-workbench-mode-shell-master-guide.md`
- `.internal/plans/autopilot-electron-agent-studio-tauri-chat-ux-parity-master-guide.md`

Related fork substrate files:

- `ide/vscode/src/vs/platform/quickinput/common/quickInput.ts`
- `ide/vscode/src/vs/platform/quickinput/common/quickAccess.ts`
- `ide/vscode/src/vs/platform/quickinput/browser/quickInput.ts`
- `ide/vscode/src/vs/platform/quickinput/browser/quickInputController.ts`
- `ide/vscode/src/vs/platform/quickinput/browser/quickInputTree.ts`
- `ide/vscode/src/vs/platform/quickinput/browser/quickAccess.ts`
- `ide/vscode/src/vs/platform/quickinput/browser/pickerQuickAccess.ts`
- `ide/vscode/src/vs/workbench/services/quickinput/browser/quickInputService.ts`
- `ide/vscode/src/vs/workbench/contrib/chat/browser/actions/chatContextActions.ts`
- `ide/vscode/src/vs/workbench/contrib/chat/browser/actions/chatActions.ts`
- `ide/vscode/src/vs/workbench/contrib/quickaccess/browser/quickAccess.contribution.ts`
- `ide/vscode/src/vs/workbench/browser/parts/titlebar/commandCenterControl.ts`

Current implementation:

- `apps/autopilot/openvscode-extension/ioi-workbench/extension.js`
- `ide/vscode/extensions/ioi-workbench/extension.js`
- `scripts/lib/autopilot-workbench-shell-patch.mjs`
- `scripts/run-autopilot-fork-quickinput-parity-goal.mjs`

## Executive Verdict

The current Agent Studio `Add Context` and `Tools` pickers are good enough as an
extension-level stopgap, but they are not the right long-term substrate.

Because Autopilot now owns the Electron/VS Code fork, the correct end state is a
fork-level Autopilot QuickInput contribution that uses VS Code's internal
QuickInput, QuickAccess, command-center, and chat-context machinery directly.

The target is not another webview menu and not a clever public extension
`QuickPick` workaround.

The target is:

> Autopilot registers native fork-level QuickInput surfaces for context and tool
> selection, with collapsible parent/child rows, checkbox semantics, command
> center placement, durable focus, keyboard navigation, and exact VS Code
> substrate feel, while IOI daemon remains the authority for tools, policy,
> receipts, approvals, and execution.

This is a shell task, not a runtime task. The fork owns the picker UI. The daemon
owns what the picker is allowed to expose and what selected tools/context mean.

## Why This Matters

The Tauri-era embedded OpenVSCode chat UX felt better in part because its
context and tool menus felt native to the editor substrate:

- `Add Context` opened a QuickInput-like menu close to the composer;
- `Tools` opened a dense, keyboardable tool picker;
- selected tools appeared as checkable/collapsible groups;
- the menu placement and focus behavior felt like VS Code, not a web popup;
- the menu stayed alive while the operator made a decision;
- the surface could express built-in tools, live tools, runtime catalog entries,
  and extension feature groups without turning the composer into a form.

The current Electron implementation moved in the right direction by using native
`vscode.window.createQuickPick`, but the public extension API cannot deliver
full parity:

- no true expandable parent/child tree rows;
- limited control over renderer density and nested checkbox semantics;
- limited command-center anchoring;
- limited custom focus retention and precise lifecycle control;
- limited ability to reuse internal chat context providers exactly as VS Code
  does.

Now that Autopilot owns the fork, those are no longer hard product constraints.
They are implementation tasks.

## Product Thesis

Autopilot should feel like a first-party IDE operator surface, not an extension
that approximates an IDE.

QuickInput is a critical affordance because it is the small, repeated moment
where operators bind authority:

- which files enter context;
- which instructions or problems are attached;
- which symbols are referenced;
- which tools are enabled;
- which model route or workflow target is selected;
- which daemon-owned capability crosses from "available" to "allowed".

That moment deserves native substrate fidelity.

## Target End State

- Electron/VS Code fork remains the canonical Autopilot app shell.
- IOI daemon remains the runtime authority.
- `ioi-workbench` remains projection/request glue, not the owner of durable
  execution state.
- Agent Studio `Add Context` opens a fork-native context picker:
  - command-center/QuickInput placement;
  - close placement to the composer when launched from the composer;
  - rows for `Files & Folders`, `Instructions`, `Problems`, `Symbols`, and
    `Tools`;
  - native keyboard navigation;
  - durable focus;
  - exact VS Code list density and hover/selection feel;
  - typed daemon/bridge request emission on selection.
- Agent Studio `Tools` opens a fork-native tool configuration picker:
  - title `Configure Tools`;
  - collapsible parent/child groups;
  - native checkbox semantics;
  - selected count;
  - `OK` action;
  - built-in tool group;
  - live tool group;
  - runtime catalog group;
  - extension/tool feature group;
  - stable detail descriptions and hover tooltips;
  - daemon policy/readiness projection per tool;
  - no premature hide on click or focus churn.
- Autopilot QuickInput providers are registered as first-class workbench
  contributions or QuickAccess providers inside the fork, not as webview DOM.
- The fork exposes stable internal commands that the extension can invoke:
  - `ioi.quickInput.context.open`;
  - `ioi.quickInput.tools.configure`;
  - `ioi.quickInput.modelRoute.pick`;
  - `ioi.quickInput.workflowTarget.pick`.
- The workbench contribution can source state from:
  - VS Code workspace/editor APIs;
  - internal chat context quick access providers;
  - `ioi-workbench` bridge projections;
  - IOI daemon catalog/readiness projections.
- Selections return typed results through bridge contracts and receipts, not
  direct webview or extension-host execution.
- No Tauri runtime, Tauri app fallback, webview durable runtime, or live
  external connector action is introduced.

## Non-Goals

- Do not revive the Tauri app or Tauri-managed OpenVSCode embedding.
- Do not make the webview own a fake QuickInput implementation.
- Do not depend on screen-coordinate automation as the only proof.
- Do not let QuickInput selections directly execute tools.
- Do not let extension-host state become the tool authority.
- Do not block all Studio work on this task; this is a parity/hardening layer
  over the existing operational chat path.

## Current State

Implemented today:

- Agent Studio has a Tauri-inspired chat layout.
- `Add Context` is positioned at the top of the composer and routes to the
  fork/workbench QuickInput command `ioi.quickInput.context.open`.
- `Tools` routes to the fork/workbench QuickInput command
  `ioi.quickInput.tools.configure`.
- The tested path uses the fork/workbench shell contribution shim injected into
  the Electron/VS Code fork, not a webview DOM menu and not the public extension
  QuickPick fallback.
- The workbench CSP is patched to allow localhost bridge writes from the
  fork-owned picker to the validation/runtime bridge.
- `Add Context` shows Files & Folders, Instructions, Problems, Symbols, and
  Tools rows with keyboard navigation and composer focus restoration.
- `Tools` shows a Configure Tools picker with collapsible parent/child rows,
  checkbox semantics, selected-count updates, OK persistence, keyboard
  navigation, and stable focus.
- Accepted selections emit typed bridge requests:
  - `chat.attachFilesAndFolders`;
  - `chat.toolControls`;
  - `chat.focusComposer`.
- The command paths remain typed and daemon-owned at the boundary.

Known gap:

- The current implementation is a fork/workbench shell contribution shim applied
  to the packaged Electron fork. It proves product-level parity and runtime
  boundaries, but it is not yet a source-native TypeScript contribution compiled
  into `ide/vscode/src/vs/workbench/contrib/...`.
- The longer-term hardening path remains replacing the injected shell shim with
  a source-native workbench contribution that uses VS Code's internal
  `IQuickInputService`, `QuickInputTree`, and QuickAccess providers directly.

## Architecture Shape

### Fork Workbench Contribution

Add an Autopilot QuickInput contribution inside the fork, conceptually:

```text
ide/vscode/src/vs/workbench/contrib/ioiQuickInput/
  browser/ioiQuickInput.contribution.ts
  browser/ioiContextQuickAccess.ts
  browser/ioiToolQuickInput.ts
  browser/ioiQuickInputService.ts
  common/ioiQuickInputTypes.ts
  test/browser/ioiQuickInput.test.ts
```

The exact path can change to match local fork conventions, but the contribution
must live in the workbench/fork layer, not the extension webview.

### Runtime Boundary

```text
Agent Studio composer button
  -> command: ioi.quickInput.tools.configure
  -> fork QuickInput contribution
  -> workbench context snapshot + daemon projection state
  -> user selection
  -> typed bridge request
  -> IOI daemon policy / tool state / receipt authority
  -> projected Studio state update
```

The picker can show tools. It cannot authorize execution alone.

### Provider Inputs

The fork contribution should compose:

- internal workspace context providers from
  `vs/workbench/contrib/chat/browser/actions/chatContextActions`;
- file and folder quick access from the workbench search/anything providers;
- problem/diagnostic state from Problems/markers;
- symbols from workspace and editor symbol providers;
- tool catalog state from daemon projection;
- runtime capability state from daemon projection;
- selected tool state from daemon-owned session/tool policy state.

### Result Contract

Every accepted QuickInput action emits a typed result:

```ts
type AutopilotQuickInputResult =
  | {
      type: "context.attach";
      source: "files" | "instructions" | "problems" | "symbols" | "tools";
      refs: AutopilotContextRef[];
      runtimeAuthority: "daemon-owned";
    }
  | {
      type: "tools.configure";
      selectedToolIds: string[];
      deselectedToolIds: string[];
      sessionScope: "current" | "default-agent";
      runtimeAuthority: "daemon-owned";
    }
  | {
      type: "modelRoute.pick";
      routeId: string;
      runtimeAuthority: "daemon-owned";
    }
  | {
      type: "workflowTarget.pick";
      workflowId: string;
      runtimeAuthority: "daemon-owned";
    };
```

The fork contribution returns results to `ioi-workbench`, which writes bridge
requests for daemon processing.

## UX Contract

### Add Context Picker

It should match the OpenVSCode reference shape:

- launched from the composer `Add Context...` control;
- compact QuickInput panel;
- placeholder: `Search for files and context to add to your request`;
- rows:
  - `Files & Folders...`;
  - `Instructions...`;
  - `Problems...`;
  - `Symbols...`;
  - `Tools...`;
- `Tools...` routes into the Configure Tools picker without closing through a
  jarring intermediate state;
- Escape returns focus to the composer;
- accepted context updates visible Studio chips/state;
- no webview menu appears.

### Configure Tools Picker

It should match the OpenVSCode reference shape:

- title: `Configure Tools`;
- small top toolbar buttons where native substrate provides them;
- filter input;
- selected count pill;
- `OK` action;
- help text:
  `The selected tools will be applied globally for all chat sessions that use the default agent.`
- collapsible tree groups:
  - `Built-In`;
  - `agent`;
  - `execute`;
  - `new`;
  - `read`;
  - `todo`;
  - `vscode`;
  - extension feature groups such as `Mermaid Chat Features`;
  - live/daemon catalog groups as available.
- checkboxes:
  - group checkbox reflects child state;
  - child checkbox toggles individual tool;
  - selected count updates immediately;
  - `OK` persists through daemon/session route.
- keyboard behavior:
  - arrow keys move focus;
  - left/right collapse/expand;
  - space toggles checkbox;
  - Enter accepts focused action when appropriate;
  - Escape closes and returns focus to composer.

## Implementation Plan

### Phase 0: Source Audit

Inventory and document:

- `IQuickInputService`;
- `IQuickAccessRegistry`;
- `QuickAccessController`;
- `QuickInputController`;
- `QuickPick`;
- `QuickInputTree`;
- `PickerQuickAccessProvider`;
- chat context actions and dynamic variables;
- command-center show/hide hooks;
- existing Autopilot packaged shell patch hooks.

Deliverable:

- source audit section added to this guide with exact files/classes selected for
  implementation.

### Phase 1: Contribution Skeleton

Add a fork-level Autopilot QuickInput contribution:

- registers with the workbench contribution registry;
- contributes internal commands:
  - `ioi.quickInput.context.open`;
  - `ioi.quickInput.tools.configure`;
- uses `IQuickInputService` directly;
- can be invoked from command center, command palette, or `ioi-workbench`;
- includes feature flag:
  - `IOI_WORKBENCH_NATIVE_QUICKINPUT=1`;
- safely no-ops/falls back when disabled.

### Phase 2: Add Context Native Picker

Implement native context picker:

- reuse upstream chat context action patterns where possible;
- show the exact top-level context rows;
- route `Files & Folders`, `Problems`, and `Symbols` to native providers;
- route `Instructions` to Autopilot instruction/context generator;
- route `Tools` to the native tools picker;
- return selection to Studio composer state.

### Phase 3: Configure Tools Native Tree

Implement the native tools tree picker:

- extend or adapt `QuickInputTree` only where needed;
- preserve upstream list classes/theme variables;
- add collapsible groups;
- add group/child checkbox behavior;
- add selected count;
- add `OK`;
- add row details/tooltips;
- keep focus stable on click and row toggle;
- prevent the quick input from disappearing during checkbox changes.

### Phase 4: Daemon Projection Binding

Source tool state from daemon-owned projections:

- built-in tools available by default;
- live connector/tool catalog rows gated by daemon readiness;
- policy-blocked tools displayed but disabled with reason;
- selected tool state scoped to session/default agent;
- user acceptance emits daemon bridge request;
- daemon response updates Studio visible state and receipts.

### Phase 5: Command-Center Placement

Ensure picker placement feels native:

- command-center launched pickers use command-center positioning;
- composer-launched pickers anchor as close as VS Code internals allow;
- no extra gap under command center if the command center is the owner;
- no webview overlay duplication;
- no disappearing picker caused by webview losing focus.

### Phase 6: Extension Fallback Demotion

Keep current extension QuickPick path only as a fallback:

- gated behind `IOI_WORKBENCH_NATIVE_QUICKINPUT !== "1"`;
- clearly named as fallback in tests and docs;
- validation must prove the native path when the feature flag is enabled.

### Phase 7: Validation Harness

Add scripts:

- `npm run goal:autopilot-fork-quickinput-parity`
- `npm run goal:autopilot-fork-quickinput-parity:run`

The harness must:

- launch Electron through the existing fork launcher;
- enable `IOI_WORKBENCH_NATIVE_QUICKINPUT=1`;
- open Agent Studio;
- click `Add Context...`;
- verify native QuickInput appears;
- verify exact rows and placement;
- open `Tools...`;
- verify `Configure Tools` tree;
- expand/collapse groups;
- toggle child tools;
- verify selected count;
- click `OK`;
- verify Studio state updated;
- verify daemon/bridge receipt or dry-run proof emitted;
- verify focus returns to composer;
- verify no orphan Electron/daemon processes remain.

## Required Evidence

Store under:

`docs/evidence/autopilot-fork-quickinput-parity/`

Required screenshots:

- `fork-add-context-quickinput.png`
- `fork-add-context-keyboard-navigation.png`
- `fork-configure-tools-tree.png`
- `fork-tools-collapsible-rows.png`
- `fork-tools-checkbox-selected-count.png`
- `fork-composer-focus-restored.png`

Required JSON/log proof:

- `proof.json`
- `preflight.json`
- `shell-patch.json`
- `bridge-requests.json`
- `bridge-commands.json`
- `console-logs.json`
- `playwright-trace.zip`
- `process-cleanup-before-launch.json`
- `process-cleanup-after-run.json`

Proof JSON must include:

```json
{
  "targetForkQuickInputParityAchieved": true,
  "nativeForkContributionUsed": true,
  "extensionQuickPickFallbackUsed": false,
  "addContextNativeQuickInputVisible": true,
  "contextSelectionBridgeRequest": true,
  "configureToolsNativeTreeVisible": true,
  "collapsibleParentChildRowsVerified": true,
  "nativeCheckboxSemanticsVerified": true,
  "selectedCountUpdates": true,
  "keyboardNavigationVerified": true,
  "durableFocusVerified": true,
  "composerFocusRestored": true,
  "toolSelectionBridgeRequest": true,
  "daemonAuthorityPreserved": true,
  "noTauriUsage": true,
  "noLiveExternalConnectorAction": true
}
```

## Validation Update: 2026-05-23

Latest passing evidence:

- `docs/evidence/autopilot-fork-quickinput-parity/2026-05-23T16-13-05-629Z/proof.json`
- `docs/evidence/autopilot-fork-quickinput-parity/2026-05-23T16-13-05-629Z/shell-patch.json`
- `docs/evidence/autopilot-fork-quickinput-parity/2026-05-23T16-13-05-629Z/process-cleanup-after-run.json`

Validated proof:

- `targetForkQuickInputParityAchieved: true`
- `nativeForkContributionUsed: true`
- `extensionQuickPickFallbackUsed: false`
- `addContextNativeQuickInputVisible: true`
- `configureToolsNativeTreeVisible: true`
- `collapsibleParentChildRowsVerified: true`
- `nativeCheckboxSemanticsVerified: true`
- `selectedCountUpdates: true`
- `keyboardNavigationVerified: true`
- `durableFocusVerified: true`
- `composerFocusRestored: true`
- `daemonAuthorityPreserved: true`
- `noTauriUsage: true`
- `noLiveExternalConnectorAction: true`

Validation notes:

- The workbench HTML CSP had to be patched to allow localhost bridge writes from
  the fork/workbench picker path.
- The Tools tree click handler was hardened so group twisties and checkboxes own
  their own click semantics instead of being intercepted by the parent row.
- Composer focus restoration now emits a typed `chat.focusComposer` bridge
  request and a Studio focus projection command, which avoids brittle direct
  parent-to-webview focus handoff.
- Process cleanup proof reports no remaining validation Electron processes.

Interaction follow-up:

- `Add Context` remains composer-adjacent rather than sharing the global Tools
  placement, because it attaches context to the current prompt while Tools
  configures the session capability set.
- A transparent workbench dismissal layer now closes `Add Context` or `Tools`
  on outside click, right click, Escape, or repeated command invocation.
- GUI validation proves `addContextDismissesOnOutsideClick: true`.
- The latest focused GUI run still reports `composerFocusRestored: false`; the
  typed focus route and Studio-side focus retries are present, but actual
  textarea focus after a workbench-hosted picker remains a VS Code webview focus
  hardening item rather than fully green evidence.

## Tests

Minimum commands:

- `npm run goal:autopilot-fork-quickinput-parity`
- `npm run goal:autopilot-fork-quickinput-parity:run`
- `npm run goal:autopilot-agent-studio-tauri-chat-ux-parity`
- `npm run goal:autopilot-agent-studio-operational-chat`
- `npm run goal:autopilot-workbench-mode-shell`
- `node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs`

Recommended fork tests:

- quickinput unit/browser tests for new contribution;
- keyboard navigation tests for tree behavior;
- command registration tests;
- Playwright screenshots for the actual Electron GUI.

## Blockers

Treat any of these as blockers:

- `Add Context` still uses webview DOM menus.
- `Add Context` only uses public extension `QuickPick` while the native feature
  flag is enabled.
- `Tools` lacks collapsible parent/child rows.
- `Tools` lacks native checkbox semantics.
- Selected count does not update.
- Checkbox clicks close the picker.
- Picker disappears on focus churn.
- Keyboard navigation is broken.
- Focus does not return to composer.
- Command-center placement is materially off.
- Webview or extension host directly executes a selected tool.
- Daemon policy/readiness is bypassed.
- Tauri is used or reintroduced.
- Validation only checks static source or final DOM.
- Screenshots/proof JSON are missing.
- Validation leaves orphan processes.

## Acceptance Criteria

This guide is complete only when:

- `targetForkQuickInputParityAchieved: true` is produced by GUI validation.
- The fork-level QuickInput contribution is used in the tested path.
- The extension QuickPick fallback is not used in the tested path.
- Add Context and Configure Tools look and behave materially like the
  OpenVSCode/Tauri reference.
- Collapsible parent/child rows and native checkbox semantics are proven.
- Keyboard navigation and focus durability are proven.
- Runtime authority remains daemon-owned.
- Existing Agent Studio operational chat and chat UX parity proofs still pass.
- Process cleanup proof shows no orphan Electron/daemon processes.

## Connector Sprint Readiness

This guide does not begin connector-specific sprint work.

It improves connector sprint readiness by making the authority-binding moment
native and trustworthy. Connector actions should eventually appear in the Tools
picker as daemon-projected capabilities, but this guide must only validate:

- built-in tools;
- local/runtime catalog projection;
- fixture or dry-run connector capability rows;
- blocked/gated external actions;
- daemon receipt/approval projection.

No live external connector action should be performed.

## Suggested Goal Prompt

```text
/goal

Goal: complete the Autopilot Electron Fork-Level QuickInput Parity master guide end to end.

Use `.internal/plans/autopilot-electron-fork-level-quickinput-parity-master-guide.md` as the source of truth.

Target end state:
- Electron/VS Code fork remains the canonical Autopilot app shell.
- IOI daemon remains the authority for tools, policy, approvals, receipts, replay, and execution.
- Agent Studio Add Context and Tools controls use fork-level VS Code QuickInput/QuickAccess internals, not webview DOM menus or public-extension QuickPick fallback in the tested path.
- Add Context has native command-center/composer-adjacent placement, durable focus, keyboard navigation, and rows for Files & Folders, Instructions, Problems, Symbols, and Tools.
- Tools opens a native Configure Tools picker with collapsible parent/child rows, native checkbox semantics, selected count, OK action, built-in/live/runtime catalog groups, keyboard navigation, and stable focus.
- Selections emit typed bridge requests and daemon-owned receipts/projections.
- Tauri is not revived or used as a fallback.

Complete autonomously:
1. Audit the fork QuickInput/QuickAccess internals and upstream chat context actions.
2. Implement a fork-level Autopilot QuickInput workbench contribution.
3. Register native commands: `ioi.quickInput.context.open`, `ioi.quickInput.tools.configure`, `ioi.quickInput.modelRoute.pick`, and `ioi.quickInput.workflowTarget.pick`.
4. Wire Agent Studio Add Context and Tools buttons to the native fork commands.
5. Implement native Add Context picker parity.
6. Implement native Configure Tools tree picker parity with collapsible groups and checkbox semantics.
7. Preserve daemon runtime authority and typed bridge request boundaries.
8. Keep public extension QuickPick only as an explicitly gated fallback.
9. Add validation scripts:
   - `npm run goal:autopilot-fork-quickinput-parity`
   - `npm run goal:autopilot-fork-quickinput-parity:run`
10. Launch Electron through Playwright/CDP, drive visible controls, capture screenshots/logs/proofs, and clean up processes.
11. Update the guide with implementation status, evidence links, validation results, blockers, and connector sprint readiness.

Run at minimum:
- `npm run goal:autopilot-fork-quickinput-parity`
- `npm run goal:autopilot-fork-quickinput-parity:run`
- `npm run goal:autopilot-agent-studio-tauri-chat-ux-parity`
- `npm run goal:autopilot-agent-studio-operational-chat`
- `npm run goal:autopilot-workbench-mode-shell`
- `node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs`

Required proof:
- `targetForkQuickInputParityAchieved: true`
- Native fork contribution used.
- Extension QuickPick fallback not used.
- Add Context native QuickInput visible.
- Configure Tools native tree visible.
- Collapsible parent/child rows verified.
- Native checkbox semantics verified.
- Selected count updates.
- Keyboard navigation verified.
- Durable focus verified.
- Composer focus restored.
- Daemon authority preserved.
- No Tauri usage.
- No live external connector action.
- No orphan processes.

Do not mark complete until implementation, GUI validation, screenshots, proof JSON, process cleanup proof, and blocker report are all updated.
```
