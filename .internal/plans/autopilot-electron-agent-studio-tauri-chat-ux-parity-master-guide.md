# Autopilot Electron Agent Studio Tauri Chat UX Parity Master Guide

Owner: Autopilot Workbench / Agent Studio / `ioi-workbench` / VS Code fork / IOI daemon / Tauri-era chat UX substrate / validation harness

Status: complete; implemented and validated in Electron GUI on 2026-05-23

Created: 2026-05-22

Completed: 2026-05-23

Parent guide:

- `.internal/plans/autopilot-electron-agent-studio-operational-chat-master-guide.md`

Child follow-up guide:

- `.internal/plans/autopilot-electron-fork-level-quickinput-parity-master-guide.md`

Completion evidence:

- `docs/evidence/autopilot-agent-studio-tauri-chat-ux-parity/2026-05-23T00-19-50-244Z/proof.json`
- `docs/evidence/autopilot-agent-studio-tauri-chat-ux-parity/2026-05-23T00-19-50-244Z/studio-tauri-parity-default.png`
- `docs/evidence/autopilot-agent-studio-tauri-chat-ux-parity/2026-05-23T00-19-50-244Z/studio-session-rail.png`
- `docs/evidence/autopilot-agent-studio-tauri-chat-ux-parity/2026-05-23T00-19-50-244Z/studio-user-bubble.png`
- `docs/evidence/autopilot-agent-studio-tauri-chat-ux-parity/2026-05-23T00-19-50-244Z/studio-assistant-answer-card.png`
- `docs/evidence/autopilot-agent-studio-tauri-chat-ux-parity/2026-05-23T00-19-50-244Z/studio-utility-drawer-expanded.png`
- `docs/evidence/autopilot-agent-studio-operational-chat/2026-05-23T00-21-12-970Z/proof.json`

Reference screenshots:

- `/home/heathledger/Pictures/Screenshot_2026-05-19_12-45-12.png`
- `/home/heathledger/Pictures/Screenshot_2026-05-22_19-38-26.png`

Reference code:

- `packages/workspace-substrate/src/components/OperatorChatPane.tsx`
- `apps/autopilot/src/windows/ChatShellWindow/components/ChatConversationSurface.tsx`
- `apps/autopilot/src/windows/ChatShellWindow/components/ChatInputSection.tsx`
- `apps/autopilot/src/windows/ChatShellWindow/components/ChatInputControls.tsx`
- `apps/autopilot/src/windows/ChatShellWindow/components/ChatConversationSidebar.tsx`
- `apps/autopilot/src/windows/ChatShellWindow/components/ConversationTimeline.tsx`
- `apps/autopilot/src/windows/ChatShellWindow/components/AssistantTurn.tsx`
- `apps/autopilot/src/windows/ChatShellWindow/components/AnswerCard.tsx`
- `apps/autopilot/src/windows/ChatShellWindow/components/ChatArtifactSurface.tsx`
- `apps/autopilot/src/windows/ChatShellWindow/styles/`
- `apps/autopilot/openvscode-extension/ioi-workbench/extension.js`

## Executive Verdict

The previous goal made Agent Studio operational. This guide makes it good.

Electron Agent Studio should adopt the Tauri-era chat UX language while keeping
the Electron/VS Code fork and IOI daemon architecture intact.

The target is not:

- revive Tauri;
- copy the Tauri shell wholesale;
- make a separate desktop app;
- hide daemon authority behind pretty local mock state.

The target is:

> Port the mature Tauri chat ergonomics into Electron Agent Studio: session rail,
> chat-first transcript, compact run/status bars, assistant answer cards,
> right-aligned user bubbles, bottom composer, icon toggle row, context/model/tool
> controls, collapsible artifacts, and calm dark operator styling, all backed by
> daemon-owned sessions, approvals, receipts, replay, patch decisions, terminal
> output, and workflow/model handoffs.

## Why This Matters

The current Electron Studio surface proves runtime path correctness, but it still
looks like an evidence harness. It overexposes runtime panels and underdelivers
the feeling of a polished operator chat.

The Tauri chat screenshot is materially better because:

- the chat itself is the product surface;
- session history is obvious without swallowing the page;
- the transcript has readable rhythm;
- user turns read as user turns;
- assistant work is grouped into compact `Worked for Xs` bars and answers;
- controls are toggleable icons, not bulky proof buttons;
- the composer is bottom-anchored and ergonomic;
- artifacts are available without dominating the default state;
- the whole surface feels like an app people can use for hours.

Agent Studio should keep the operational daemon path from the previous guide, but
visually graduate from validation UI to daily-driver chat.

## Visual Thesis

Dense, black, IDE-native operator chat: the transcript is calm and central, user
and assistant turns have clear rhythm, runtime evidence is collapsed until
useful, and the composer feels like a professional command surface rather than a
form.

## Content Plan

Default Studio screen:

1. Left session rail: sessions, search, new session, artifacts, recent threads.
2. Center transcript: assistant/user turns, compact work bars, answer cards,
   approval cards, inline evidence when active.
3. Bottom composer: prompt textarea plus icon/toggle row.
4. Right drawer: artifacts, tool timeline, receipts, diffs, terminal/test output,
   hidden or collapsed by default unless active.

## Interaction Thesis

- Rail clicks and session selection should feel instant, with no sidebar
  flash-through.
- Runtime details should reveal progressively: compact status bar first,
  expanded details only on click or active gate/error.
- Composer toggles should be small, icon-first, keyboard-friendly, and reflect
  live daemon/model/policy state.

## Target End State

- Electron/VS Code fork remains the canonical Autopilot app shell.
- IOI daemon remains the authority for sessions, models, tools, approvals,
  patches, terminal/test execution, receipts, and replay.
- Agent Studio remains operational and daemon-backed.
- Agent Studio visually adopts the mature Tauri chat UX:
  - session history rail;
  - chat-first center transcript;
  - right-aligned user bubbles;
  - assistant answer blocks;
  - compact run/status bars;
  - bottom composer;
  - `Add Context` control;
  - target/model/tool/mode toggle buttons;
  - send/stop icon button;
  - collapsible artifacts/evidence drawer;
  - polished dark theme spacing and typography.
- The previous proof-heavy right rail becomes a collapsible utility/evidence
  drawer, not default chrome.
- Workflow Composer and Models remain handoff/deep-work surfaces.
- No Tauri runtime, Tauri shell, or Tauri app fallback is revived.
- No webview or extension host durable runtime authority is introduced.
- No live external connector action is performed.

## Current State

Validated from the previous guide:

- Studio opens to `agent-studio-operational-chat`.
- Prompt submission uses `chat.submit`.
- Stop uses `chat.stop`.
- Hunk decisions use `chat.hunkDecision`.
- Workflow handoff uses `workflow.composer.open`.
- Runtime authority stays daemon-owned.
- GUI harness captures screenshots, bridge requests, daemon receipts, daemon
  threads, Playwright trace, and process cleanup.

Still not good enough:

- Center transcript is too sparse and visually unfinished.
- The left rail looks like validation context rather than chat session history.
- The right side always exposes proof panels instead of progressive disclosure.
- Composer controls are text-heavy and not icon/toggle shaped.
- Assistant turns lack the compact `Worked for Xs` status and answer-card rhythm
  from the Tauri chat UX.
- User turns do not yet have the polished right-side bubble treatment.
- Artifacts, receipts, approvals, diffs, and terminal output are present, but too
  prominent by default.

## UX Parity Inventory

### Tauri Chat Patterns To Port

Session rail:

- `Sessions` heading;
- `Codebase chat history` subtitle;
- session search;
- `New Session`;
- `Artifacts` with count badge;
- `Recent` grouping;
- current session row with status;
- lower operator/settings affordances only if they belong inside Studio.

Transcript:

- full-width center surface;
- assistant turns grouped under a compact work/status bar;
- `Worked for Xs` or `Working...` row with done/running/dropdown state;
- answer text below the status bar;
- answer actions such as copy;
- user bubbles right-aligned;
- enough vertical air for long-running conversations.

Composer:

- bottom anchored;
- placeholder like `Describe what to build next`;
- left control row:
  - `Add Context...`;
  - workspace/session target dropdown;
  - model/command dropdown;
  - `Auto` / `Plan` mode dropdown;
  - tools toggle icon;
- right send/stop icon button;
- blocked/credential state footer when needed;
- keyboard support: Enter or configured submit key, Ctrl/Cmd+Enter, Esc stop.

Progressive utility:

- artifact drawer opens only when requested or active;
- receipts/replay collapse into chips or drawer sections;
- approval gates appear inline when required;
- terminal/test output expands from a compact event row;
- diffs surface in the editor plus compact chat hunk controls.

### Tauri Patterns Not To Port Directly

- Tauri shell process/window APIs.
- Tauri-specific drag regions except where reused only as CSS reference.
- The full Tauri app primary nav if it conflicts with Electron/VS Code rail.
- Any Tauri runtime/session ownership.
- Any local-only mock session state that bypasses daemon receipts.

### Electron Studio Patterns To Keep

- daemon-backed `chat.submit`;
- daemon-backed `chat.stop`;
- daemon-backed hunk approval decisions;
- Workflow Composer and Models handoffs;
- Playwright/CDP GUI validation;
- evidence directory shape;
- process cleanup guard;
- no live external connector action.

## Proposed Information Architecture

```text
Agent Studio
  left session rail
    Sessions
    Search sessions
    New session
    Artifacts count
    Recent sessions
  center chat pane
    Chat tab/header
    Transcript
      assistant turn
        compact run bar
        answer card
      user turn bubble
      approval gate card when active
      compact tool/event rows
    Bottom composer
      textarea
      Add Context
      target dropdown
      model dropdown
      mode dropdown
      tools toggle
      send/stop
  right utility drawer
    Artifacts
    Tool timeline
    Receipts/replay
    Inline diff details
    Terminal/test output
```

Default state should show left session rail, center transcript, bottom composer,
and a collapsed utility drawer affordance. It should not show a large proof grid
unless an operator opens it or a gate/error requires attention.

## Implementation Plan

### Phase 0: Source Audit

Tasks:

- inventory `OperatorChatPane`, `ChatConversationSurface`,
  `ChatInputSection`, `ChatInputControls`, `ChatConversationSidebar`,
  `ConversationTimeline`, `AnswerCard`, and related CSS;
- inventory current Studio HTML/CSS in `ioi-workbench/extension.js`;
- map every current Studio test id to the target UX location;
- decide whether to:
  - render a bundled React webview using shared components; or
  - port the mature markup/CSS patterns into the existing extension webview.

Recommendation:

- Short term: port the markup/CSS patterns into the existing extension webview so
  the Electron Studio UX improves quickly without bundling risk.
- Medium term: bundle a shared React chat surface or fork-native contribution
  that reuses `OperatorChatPane` directly to prevent drift.

Done when:

- every target UX element has a source reference and target implementation path.

### Phase 1: Session Rail Parity

Tasks:

- replace the current validation-style left rail with Tauri-style session rail;
- add search sessions input;
- add `New Session`;
- add artifacts row with count badge;
- add recent grouping by date/status;
- render current daemon session status in the row;
- keep context/policy/workflow/model handoffs as compact rail actions or move
  them into composer/drawer if they create noise.

Required test ids:

- `studio-tauri-session-rail`;
- `studio-session-search`;
- `studio-new-session`;
- `studio-artifacts-row`;
- `studio-current-session-row`;
- `studio-recent-sessions`.

Done when:

- the left rail resembles the Tauri chat session history rail;
- it does not read as a proof/control panel.

### Phase 2: Transcript Rhythm And Turn Styling

Tasks:

- make center transcript the visual priority;
- render user turns as right-aligned bubbles;
- render assistant turns as answer blocks;
- add compact run/status bars:
  - `Working...`;
  - `Worked for Xs`;
  - `done`;
  - `approval required`;
  - `stopped`;
  - `failed`;
- add answer action row with copy and optional more menu;
- keep process summaries collapsed unless active.

Required test ids:

- `studio-chat-transcript`;
- `studio-user-bubble`;
- `studio-assistant-answer-card`;
- `studio-run-status-bar`;
- `studio-answer-copy`;
- `studio-process-disclosure-toggle`.

Done when:

- the transcript has the same hierarchy and rhythm as the Tauri screenshot.

### Phase 3: Composer Toggle Row

Tasks:

- replace text-heavy composer toolbar with the Tauri-style control row;
- implement:
  - `Add Context...`;
  - workspace/session target dropdown;
  - model dropdown using daemon route data;
  - `Auto` / `Plan` mode dropdown;
  - tools toggle icon;
  - send/stop icon button;
- keep controls wired to existing daemon-backed bridge request paths;
- add disabled, pending, gated, and credential states;
- add tooltips or accessible labels for icon-only controls.

Required test ids:

- `studio-tauri-composer`;
- `studio-add-context`;
- `studio-target-toggle`;
- `studio-model-toggle`;
- `studio-mode-toggle`;
- `studio-tools-toggle`;
- `studio-send-icon`;
- `studio-stop-icon`;

Done when:

- composer visually matches the Tauri ergonomics and all controls remain typed
  bridge requests.

### Phase 4: Progressive Utility Drawer

Tasks:

- collapse the current proof-heavy right rail into a utility drawer;
- default the drawer closed or narrow unless there is an active approval/error;
- provide drawer tabs/sections:
  - tool timeline;
  - approvals;
  - artifacts;
  - receipts/replay;
  - inline diff;
  - terminal/test output;
- show compact chips in the transcript for receipts/evidence;
- preserve existing proof test ids inside the drawer so validation remains
  robust.

Required test ids:

- `studio-utility-drawer`;
- `studio-utility-toggle`;
- `studio-tool-timeline-collapsed`;
- `studio-receipt-chip`;
- `studio-approval-inline-card`;
- `studio-terminal-output-drawer`;
- `studio-inline-diff-drawer`.

Done when:

- proof/evidence is available but no longer overwhelms the default chat surface.

### Phase 5: Workflow And Model Handoff Polish

Tasks:

- expose Workflow Composer and Models as compact handoff affordances:
  - composer slash/action;
  - session rail quick action;
  - answer/handoff chip after relevant intent;
- avoid large handoff buttons in the default chat chrome;
- keep handoffs typed and daemon/projection safe.

Required test ids:

- `studio-workflow-handoff-chip`;
- `studio-models-handoff-chip`;
- `studio-workflow-handoff`;
- `studio-model-route-picker`.

Done when:

- Studio feels like the entry point and Workflows/Models feel like deep-work
  destinations, not competing default panels.

### Phase 6: Visual Polish

Tasks:

- port relevant spacing, borders, typography, and dark theme from Tauri chat CSS;
- remove thick proof-card borders from default state;
- reduce always-visible accent noise;
- ensure all buttons fit at laptop and desktop widths;
- make scroll anchoring stable while user/assistant turns append;
- add responsive behavior for narrow windows:
  - session rail collapses;
  - drawer overlays or collapses;
  - composer remains reachable.

Done when:

- screenshots look closer to the Tauri chat UX than the current Electron proof UI.

### Phase 7: Validation Harness

Tasks:

- add scripts:
  - `npm run goal:autopilot-agent-studio-tauri-chat-ux-parity`
  - `npm run goal:autopilot-agent-studio-tauri-chat-ux-parity:run`
- launch Electron through Playwright/CDP;
- open Studio from the real rail;
- validate visible controls, not only DOM strings;
- submit a prompt and prove daemon-backed runtime still works;
- click/validate composer toggles;
- open/close utility drawer;
- validate approval, hunk decision, receipt, stop, and workflow handoff still
  work;
- capture screenshots and cleanup evidence.

Done when:

- runtime proof from the previous guide is preserved;
- UX parity proof is visible in screenshots;
- no orphan processes remain.

## Validation Evidence

Evidence directory:

```text
docs/evidence/autopilot-agent-studio-tauri-chat-ux-parity/
```

Required screenshots:

- `studio-tauri-parity-default.png`
- `studio-session-rail.png`
- `studio-chat-turns-run-bars.png`
- `studio-user-bubble.png`
- `studio-assistant-answer-card.png`
- `studio-composer-toggle-row.png`
- `studio-add-context-picker.png`
- `studio-model-mode-tool-toggles.png`
- `studio-utility-drawer-collapsed.png`
- `studio-utility-drawer-expanded.png`
- `studio-approval-inline-card.png`
- `studio-receipt-chip-and-drawer.png`
- `studio-inline-diff-drawer.png`
- `studio-stop-control.png`
- `studio-workflow-handoff-chip.png`
- `studio-responsive-narrow.png`

Required proof JSON:

```json
{
  "schemaVersion": "ioi.autopilot-agent-studio-tauri-chat-ux-parity.proof.v1",
  "targetStudioTauriChatUxParityAchieved": true,
  "runtimeStillDaemonBacked": true,
  "tauriRuntimeUsed": false,
  "studioOpensChatFirst": true,
  "sessionRailMatchesTauriPattern": true,
  "userBubbleVisible": true,
  "assistantAnswerCardVisible": true,
  "compactRunStatusBarVisible": true,
  "composerToggleRowVisible": true,
  "addContextControlVisible": true,
  "modelModeToolControlsVisible": true,
  "utilityDrawerProgressiveDisclosure": true,
  "approvalInlineCardVisible": true,
  "receiptsReplayStillVisible": true,
  "hunkDecisionStillReceipted": true,
  "stopControlStillDaemonBacked": true,
  "workflowHandoffStillTyped": true,
  "noProofPanelDominanceInDefaultState": true,
  "noSidebarFlashThrough": true,
  "noDuplicateTabs": true,
  "noLiveExternalConnectorAction": true,
  "orphanProcesses": []
}
```

Run at minimum:

- `npm run goal:autopilot-agent-studio-tauri-chat-ux-parity`
- `npm run goal:autopilot-agent-studio-tauri-chat-ux-parity:run`
- `npm run goal:autopilot-agent-studio-operational-chat`
- `npm run goal:autopilot-agent-studio-operational-chat:run`
- `node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs`

## Blockers

Treat any of these as blockers:

- Studio regresses to a mock/card launcher.
- Prompt submission no longer uses `chat.submit`.
- Stop no longer uses `chat.stop`.
- Hunk decisions no longer emit daemon receipts.
- User turn does not appear immediately.
- Pending state does not appear within one second.
- Final answer is not visible.
- Session rail is missing or still reads like a validation control panel.
- Composer toggle row is missing.
- `Add Context` control is missing.
- Model/mode/tool controls are decorative only.
- Default state is dominated by proof panels.
- Utility drawer cannot expose tool timeline, receipts, approvals, diffs, and
  terminal/test output.
- Workflow Composer handoff disappears.
- Tauri runtime, Tauri shell, or Tauri app fallback is used.
- Webview or extension host performs durable runtime authority.
- Live external connector action is performed.
- Validation only proves final DOM state.
- Screenshots are missing.
- Validation leaves orphan processes.

## Acceptance Criteria

The guide is complete only when:

- Electron Agent Studio looks and behaves materially closer to the Tauri chat UX
  than to the current proof-heavy Electron Studio surface.
- Runtime authority remains daemon-owned and the previous operational chat proof
  still passes.
- The default state is chat-first:
  - session rail;
  - transcript;
  - bottom composer;
  - compact toggles;
  - collapsed utility/evidence.
- Required screenshots show the Tauri-inspired interaction shape.
- Proof JSON reports `targetStudioTauriChatUxParityAchieved: true`.
- No orphan processes remain.

## Completion Record

Implemented in `apps/autopilot/openvscode-extension/ioi-workbench/extension.js`:

- Studio now renders a Tauri-inspired session rail with session search, new
  session, artifacts, recent/current session state, context shortcuts, and
  Workflow/Models handoff buttons.
- The center surface is chat-first: transcript, right-aligned user bubble,
  assistant answer cards, compact run/status bars, and a bottom-anchored
  composer.
- Composer controls now expose `Add Context`, target/model/mode/tool toggles,
  send icon, and stop control while preserving the daemon-owned request path.
  `Add Context` opens a native VS Code QuickInput picker with the OpenVSCode
  substrate options: Files & Folders, Instructions, Problems, Symbols, and
  Tools.
- The former proof-heavy right rail is a collapsed utility/evidence drawer by
  default, with tool timeline, approvals, receipts/replay, terminal/test output,
  and inline diff controls revealed progressively.
- Runtime routes remain typed and daemon-owned: `chat.submit`, `chat.stop`,
  `chat.hunkDecision`, and `workflow.composer.open`.

Validation added:

- `npm run goal:autopilot-agent-studio-tauri-chat-ux-parity`
- `npm run goal:autopilot-agent-studio-tauri-chat-ux-parity:run`

Validated on 2026-05-23:

- `npm run goal:autopilot-agent-studio-tauri-chat-ux-parity` passed.
- `npm run goal:autopilot-agent-studio-tauri-chat-ux-parity:run` passed.
- `npm run goal:autopilot-agent-studio-operational-chat` passed.
- `npm run goal:autopilot-agent-studio-operational-chat:run` passed.
- `node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs` passed.

Primary proof:

- `docs/evidence/autopilot-agent-studio-tauri-chat-ux-parity/2026-05-23T00-19-50-244Z/proof.json`

Proof highlights:

- `targetStudioTauriChatUxParityAchieved: true`
- `targetStudioOperationalChatAchieved: true`
- `sessionRailVisible: true`
- `rightAlignedUserBubbleVisible: true`
- `assistantAnswerCardVisible: true`
- `compactRunStatusBarVisible: true`
- `bottomComposerVisible: true`
- `utilityEvidenceDrawerProgressive: true`
- `noTauriUsage: true`
- `noWebviewDurableRuntimeAuthority: true`
- `noLiveExternalConnectorAction: true`

Remaining blockers:

- None for this UX parity guide.

Residual product follow-ups outside this goal:

- Replace symbolic button glyphs with final Autopilot icon assets when the icon
  system is settled.
- The `Add Context` and `Tools` picker path has been promoted to the
  fork/workbench QuickInput parity path per
  `.internal/plans/autopilot-electron-fork-level-quickinput-parity-master-guide.md`;
  remaining hardening is replacing the packaged shell shim with a source-native
  TypeScript workbench contribution.
- Continue reducing extension-level webview chrome once the fork-native mode
  shell work lands.
- Let real daemon session metadata populate richer session names and artifact
  counts as the daemon session API matures.

## Connector Sprint Readiness

This guide does not begin connector-specific sprint work.

Connector sprint readiness improves when Studio becomes a polished operator loop
because connector actions will require careful user trust at the moment of
authority handoff.

The connector sprint may use this polished Studio surface only for:

- local daemon-backed model/session execution;
- fixture or dry-run connector capability projection;
- policy and approval rehearsal;
- receipt/replay visibility;
- Workflow Composer handoff.

No live external connector action should be performed by this UX parity goal.

## Suggested Goal Prompt

```text
/goal

Goal: complete the Autopilot Electron Agent Studio Tauri Chat UX Parity master guide end to end.

Use `.internal/plans/autopilot-electron-agent-studio-tauri-chat-ux-parity-master-guide.md` as the source of truth.

Target end state:
- Electron/VS Code fork remains the canonical Autopilot app shell.
- IOI daemon remains the authority for session, model, tool, approval, patch, terminal, receipt, and replay state.
- Agent Studio keeps the daemon-backed operational chat path from the previous guide.
- Agent Studio visually adopts the mature Tauri chat UX: session rail, chat-first transcript, right-aligned user bubbles, assistant answer cards, compact run/status bars, bottom composer, Add Context, model/mode/tool toggle row, send/stop icon controls, and collapsible artifacts/evidence drawer.
- The current proof-heavy right rail becomes progressive utility/evidence disclosure, not default chrome.
- Workflow Composer and Models remain handoff/deep-work surfaces.
- No Tauri runtime, Tauri app fallback, webview durable runtime authority, or live external connector action is introduced.

Complete autonomously:
1. Inventory Tauri-era chat UX components and current Electron Studio HTML/CSS.
2. Port the Tauri chat ergonomics into Electron Agent Studio while preserving daemon-owned runtime semantics.
3. Implement the session rail, transcript rhythm, user bubbles, assistant answer cards, compact run/status bars, bottom composer toggle row, utility drawer, and handoff chips.
4. Preserve typed request routes: `chat.submit`, `chat.stop`, `chat.hunkDecision`, and `workflow.composer.open`.
5. Add validation scripts:
   - `npm run goal:autopilot-agent-studio-tauri-chat-ux-parity`
   - `npm run goal:autopilot-agent-studio-tauri-chat-ux-parity:run`
6. Launch Electron through Playwright/CDP, drive visible controls, capture screenshots/logs/proofs, and clean up processes.
7. Update the guide with implementation status, evidence links, validation results, remaining blockers, and connector sprint readiness.

Run at minimum:
- `npm run goal:autopilot-agent-studio-tauri-chat-ux-parity`
- `npm run goal:autopilot-agent-studio-tauri-chat-ux-parity:run`
- `npm run goal:autopilot-agent-studio-operational-chat`
- `npm run goal:autopilot-agent-studio-operational-chat:run`
- `node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs`

Do not mark complete until `targetStudioTauriChatUxParityAchieved: true` is proven in GUI evidence, the previous daemon-backed operational chat proof still passes, and no blocker remains.
```
