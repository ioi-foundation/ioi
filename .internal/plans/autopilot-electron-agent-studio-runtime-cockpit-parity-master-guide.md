# Autopilot Electron Agent Studio Runtime Cockpit Parity Master Guide

Owner: Autopilot Workbench / Agent Studio / Electron VS Code fork / `ioi-workbench` / IOI daemon / policy runtime / patch runtime / validation harness

Status: achieved via GUI validation; keep connector execution dry-run only

Created: 2026-05-24

Primary reference:

- `internal-docs/reverse-engineering/ux/antigravity-workbench-ux-reconciliation.md`

Parent and sibling guides:

- `.internal/plans/autopilot-electron-agent-studio-chat-ux-playwright-hardening-master-guide.md`
- `.internal/plans/autopilot-electron-agent-studio-operational-chat-master-guide.md`
- `.internal/plans/autopilot-electron-agent-studio-runtime-ux-denoising-tracing-separation-master-guide.md`
- `.internal/plans/autopilot-electron-agent-studio-tauri-chat-ux-parity-master-guide.md`
- `.internal/plans/autopilot-electron-fork-level-quickinput-parity-master-guide.md`
- `.internal/plans/autopilot-electron-workbench-mode-shell-master-guide.md`
- `.internal/plans/autopilot-electron-models-production-polish-playwright-master-guide.md`

## Executive Verdict

The current Electron Agent Studio has crossed the first important line: it can be controlled through Playwright, keep composer focus, submit prompts, stream model-backed tokens, and reject canned daemon projection as a fake assistant response.

That is necessary, but it is not sufficient.

The target product is not merely a working chat surface. The target is an IDE-native runtime cockpit where autonomous action is observable, governable, interruptible, replayable, and mergeable at the same level of polish as the best agentic IDEs, but with IOI-native authority semantics.

The next target is:

> Agent Studio is the cockpit for daemon-owned autonomous execution. Chat expresses intent; the cockpit exposes model streaming, tool proposals, policy leases, sandboxed command output, inline diffs, hunk decisions, diagnostics, receipts, replay, worker lanes, and stop/resume as one coherent operator loop.

This guide exists because chat-hardening validation can pass while the product remains far behind a production-grade runtime UX.

## Non-Negotiable Canon

- Electron/VS Code fork remains the canonical Autopilot app shell.
- IOI daemon remains the authority for sessions, model routes, tool execution, shell commands, file mutations, patches, approvals, receipts, replay, tests, browser automation, and worker delegation.
- Agent Studio is a projection and typed-request surface. It must not become the runtime.
- Fork-level VS Code workbench integrations should be used where the substrate already has the right primitives: QuickInput, editor decorations, diff editors, command center, Problems, terminals, status bar, and notifications.
- Webviews may render transcript, cards, and cockpit panels, but they must not execute durable tools, mutate files, spawn terminals, or fabricate receipts.
- Workflow Composer and Models are deep-work surfaces. They complement Studio, but they do not replace the Studio operator loop.
- Tauri is not revived or used as a fallback.
- No live external connector action is performed in validation. Use local, read-only, fixture, or dry-run capability flows until connector sprint entry.

## Baseline We Can Trust

Latest chat hardening evidence:

- `docs/evidence/autopilot-agent-studio-chat-ux-playwright-hardening/2026-05-24T00-41-10-846Z/`

The baseline proves:

- `targetStudioChatUxHardened: true`
- `targetStudioModelBackedStreamingAchieved: true`
- `modelInvocationReceiptObserved: true`
- `cannedDaemonProjectionRejected: true`
- `fixtureModelResponseRejected: true`
- distinct assistant responses were produced from mounted model-backed paths.

This guide does not re-litigate that baseline. It builds on it.

## What Is Not Achieved Yet

Do not mark runtime cockpit parity complete while any of the following remain true:

- A prompt can produce text implying work happened without a corresponding daemon action event.
- Tool activity appears only as generic text instead of typed timeline cards.
- Shell commands do not show proposed command, policy decision, live stdout/stderr, exit status, and receipt.
- Approval gates are static proof cards instead of blocking policy lease dialogs.
- File changes appear only as chat text or webview pseudo-diffs instead of VS Code editor hunks/diff overlays.
- Hunk accept/reject does not route through daemon-owned patch receipts.
- Stop/resume is a UI label rather than a daemon session lifecycle operation.
- Diagnostics/tests are detached from the run loop.
- Receipts/replay are detached from the exact step they prove.
- Browser automation has no visible screenshot/snapshot card.
- Subagents/workers have no scoped lanes or delegation receipts.
- Validation accepts "projection-only" execution.

## Target End State

Agent Studio should visually and behaviorally support this loop:

```text
operator enters intent
  -> daemon creates/continues session
  -> model route streams answer/plan
  -> tool proposal appears before execution
  -> policy evaluates requested authority
  -> low-risk action runs in sandbox with live output
  -> high-risk action blocks on policy lease dialog
  -> file patches render as native editor diffs/hunks
  -> operator accepts/rejects hunks
  -> diagnostics/tests run as verification gates
  -> every step links to receipt/replay evidence
  -> operator can stop/resume from daemon checkpoint
```

At production quality, Agent Studio must feel less like a chat transcript and more like a deterministic mission console for machine labor.

## Product Shape

### Center: Transcript and Execution Feed

The center lane stays chat-first:

- right-aligned user bubbles;
- assistant answer cards;
- token streaming with stable scroll behavior;
- compact run/status bars;
- collapsible reasoning/process summaries;
- tool/action cards embedded at the point where the action occurs;
- receipts attached to each action card, not pushed into a distant proof drawer.

### Left: Session and Context Rail

The left rail should remain quiet and useful:

- session search;
- new session;
- current/recent sessions;
- context chips;
- workspace/repository/policy attachments;
- handoffs to Workflow Composer and Models.

It should not become a second control center.

### Right: Progressive Evidence Drawer

The right drawer should be collapsed by default or narrow by default. It opens when the user requests details:

- artifacts;
- receipt/replay details;
- policy leases;
- expanded command output;
- browser screenshots;
- subagent lanes;
- test reports;
- patch summaries.

The default chat view should not be dominated by proof-card mosaics.

### Editor Layer: Native Diffs and Diagnostics

The editor must become part of Studio execution:

- native text editor decorations for proposed hunks;
- diff editor for multi-file review;
- hunk focus next/previous;
- hunk accept/reject;
- stale hunk detection;
- diagnostics and Problems integration after patch proposals;
- visible receipts for patch decisions.

Pseudo-diffs inside a webview are acceptable only as summaries, never as the primary merge UX.

## Architecture Shape

```text
Agent Studio webview
  - transcript projection
  - composer controls
  - action cards
  - typed requests only

VS Code fork/workbench layer
  - QuickInput/QuickAccess
  - editor decorations
  - diff editors
  - terminal/process view projection
  - status bar and notifications
  - command routing

ioi-workbench extension bridge
  - typed request adapter
  - state projection adapter
  - command registration
  - no durable execution authority

IOI daemon
  - session authority
  - model route authority
  - policy/action rule authority
  - shell/tool execution authority
  - patch/file mutation authority
  - browser automation authority
  - worker/subagent authority
  - receipts/replay/checkpoints
```

## Runtime Event Contract

The daemon must expose a coherent action event stream. Studio must not infer action state from plain assistant text.

Minimum event classes:

- `session.created`
- `session.resumed`
- `model.stream.started`
- `model.stream.delta`
- `model.stream.completed`
- `action.proposed`
- `policy.evaluated`
- `policy.lease.requested`
- `policy.lease.approved`
- `policy.lease.denied`
- `tool.started`
- `tool.stdout`
- `tool.stderr`
- `tool.completed`
- `tool.failed`
- `patch.proposed`
- `patch.hunk.focused`
- `patch.hunk.accepted`
- `patch.hunk.rejected`
- `diagnostics.started`
- `diagnostics.completed`
- `test.started`
- `test.completed`
- `browser.snapshot`
- `worker.spawned`
- `worker.completed`
- `receipt.emitted`
- `replay.checkpoint.created`
- `session.stop.requested`
- `session.stopped`
- `session.resume.requested`
- `session.completed`
- `session.failed`

Each event needs:

- session id;
- turn id;
- action id;
- parent action id when nested;
- request type;
- status;
- timestamp;
- policy decision;
- affected resources;
- receipt id when emitted;
- replay/checkpoint id when available.

## P0 Implementation Work

### 1. Truthful Runtime Classification

Add explicit state and validation that separates:

- model text response;
- daemon action proposal;
- daemon action execution;
- daemon receipt;
- webview-only projection.

The UI must label projection-only affordances as blocked or unavailable. The harness must fail if projection-only runtime is accepted as proof.

### 2. Tool Proposal Cards

Implement first-class tool proposal cards in the transcript:

- proposed tool name;
- arguments;
- working directory or target resource;
- risk level;
- policy rule matched;
- pending/approved/denied/running/completed state;
- "details" disclosure;
- receipt link after completion.

The card appears before execution, not after the fact.

### 3. Policy Lease Dialog

Build an IOI-native equivalent of the permission escalation prompt:

- modal or native workbench dialog;
- requested action;
- affected files/paths/domains/processes;
- requested duration or scope;
- policy hash / ActionRule id;
- allow once;
- deny;
- remember as scoped lease;
- open policy details;
- receipt expectation.

High-risk actions must pause until a decision is made.

### 4. Sandboxed Command Output Card

For safe local command validation, show:

- command string;
- cwd;
- environment profile;
- sandbox profile;
- live stdout/stderr streaming;
- exit code;
- duration;
- postconditions;
- receipt id.

Validation should use harmless commands such as `pwd`, `git status --short`, or a dry-run test command already approved by policy.

### 5. Native Inline Diff and Hunk Loop

Move from webview pseudo-diff to VS Code-native patch review:

- patch proposal opens affected files or diff editor;
- hunks render as decorations;
- focus next hunk;
- focus previous hunk;
- accept focused hunk;
- reject focused hunk;
- accept/reject all only behind explicit confirmation;
- stale hunk detection if file changed out-of-band;
- every hunk decision emits a daemon receipt.

Recommended keybindings:

- `Alt+J`: next hunk;
- `Alt+K`: previous hunk;
- `Alt+Enter`: accept focused hunk only when hunk context is active;
- `Alt+Shift+Delete`: reject focused hunk only when hunk context is active.

### 6. Stop, Cancel, Resume

Stop/resume must control daemon session lifecycle:

- stop active model stream;
- stop active tool execution;
- terminate sandboxed process group safely;
- preserve transcript and pending hunks;
- show stopped state;
- resume from daemon checkpoint;
- log receipt/checkpoint ids.

Do not accept a UI-only stop button.

### 7. Receipt Timeline Per Step

Receipts need to move from a generic evidence drawer into the action card itself:

- each tool proposal shows expected receipt;
- each completed action shows receipt id;
- clicking receipt opens replay/evidence details;
- replay details can expand into full evidence drawer.

The default path should answer: "what happened, who authorized it, what changed, and how do I replay it?"

### 8. Diagnostics and Test Gate

The agent stop/completion path should include visible verification:

- diagnostics started/completed;
- test command proposed/executed;
- pass/fail state;
- failures linked to Problems/test output;
- completion blocked if configured postconditions fail;
- policy lease for commands that exceed safe local scope.

### 9. Browser and Subagent Placeholders

If full browser/subagent execution is not ready, the UI still needs honest placeholders:

- browser action card says blocked/unavailable until daemon browser API is available;
- subagent lane says blocked/unavailable until worker delegation API is available;
- validation records these as blockers, not achieved parity.

No fake screenshot or fake worker lane is accepted.

## P1 Implementation Work

- Live browser screenshot/snapshot cards from daemon-owned browser automation.
- Worker/subagent lanes with parent-child trace roots and cancellation.
- Policy lease viewer with active, remembered, revoked, and expired leases.
- Rule/policy composer that upgrades prompt guidelines into structured daemon-enforced policy.
- Crash recovery dialog with safe-mode resume.
- Artifact panes for plans, walkthroughs, and verification reports.
- Status bar indicator for idle/thinking/streaming/tool-running/blocked/stopped/completed.

## P2 Implementation Work

- Workflow node execution from Studio timeline cards.
- Multi-file patch session merge bar.
- Replay player for step-by-step session playback.
- Wallet/network authority posture for signed leases and settlement-ready receipts.
- Cloud/private runtime selector.
- Marketplace worker installation flow.

## UX Acceptance Criteria

### Chat and Composer

- Composer remains focus-stable.
- Streaming is visible as token deltas, not only final response replacement.
- User echo appears immediately.
- Pending/thinking state appears within one second.
- Stop appears during active work.
- Completed state is accurate and backed by daemon event.

### Tool Timeline

- Tool proposals are typed cards.
- Running tools show live state.
- Completed tools show outputs and receipts.
- Failed tools show errors and retry options.
- High-risk actions block before execution.

### Policy

- Policy lease dialog blocks elevated action.
- Allow/deny decisions route to daemon.
- Policy decision emits receipt.
- Denied action does not execute.
- Remembered lease is scoped and visible.

### Patch and Editor

- Patch proposal opens editor/diff surface.
- Hunk decorations appear in native editor.
- Hunk navigation works.
- Accept/reject works.
- Decision receipts are emitted.
- Stale hunks are detected.

### Verification

- Tests/diagnostics appear in timeline.
- Failures are visible.
- Completion is blocked or marked degraded if postconditions fail.

### Evidence

- Receipt/replay exists per action step.
- Evidence drawer provides expanded detail without dominating default layout.
- Proof JSON maps visible UI state to daemon events.

## Validation Harness Requirements

Create validation scripts:

- `npm run goal:autopilot-agent-studio-runtime-cockpit-parity`
- `npm run goal:autopilot-agent-studio-runtime-cockpit-parity:run`

Run at minimum:

- `npm run goal:autopilot-agent-studio-runtime-cockpit-parity`
- `npm run goal:autopilot-agent-studio-runtime-cockpit-parity:run`
- `npm run goal:autopilot-agent-studio-chat-ux-hardening`
- `npm run goal:autopilot-agent-studio-chat-ux-hardening:run`
- `npm run goal:autopilot-agent-studio-tauri-chat-ux-parity`
- `npm run goal:autopilot-agent-studio-operational-chat`
- `npm run goal:autopilot-fork-quickinput-parity`
- `npm run goal:autopilot-workbench-mode-shell`
- `node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs`

The harness must:

- launch Electron Autopilot through Playwright/CDP;
- attach daemon sidecar;
- clean up previous Electron/daemon processes;
- navigate to Agent Studio;
- use real pointer and keyboard events;
- control model route picker and composer controls;
- capture screenshots, console logs, bridge events, daemon events, receipts, and process cleanup proof;
- fail on projection-only proof;
- fail on orphan processes.

## Required Evidence Directory

`docs/evidence/autopilot-agent-studio-runtime-cockpit-parity/`

Required files:

- `playwright-trace.zip`
- `console-logs.json`
- `page-errors.json`
- `bridge-events.json`
- `daemon-events.json`
- `receipts.json`
- `process-cleanup-before-launch.json`
- `process-cleanup-after-run.json`
- `proof.json`

Required screenshots:

- `runtime-cockpit-empty-state.png`
- `runtime-cockpit-streaming-chat.png`
- `tool-proposal-card.png`
- `policy-lease-dialog.png`
- `policy-denied-action.png`
- `sandbox-command-output-card.png`
- `sandbox-command-receipt.png`
- `inline-diff-overlay.png`
- `hunk-decision-bar.png`
- `hunk-accept-receipt.png`
- `hunk-reject-receipt.png`
- `stop-resume-control.png`
- `diagnostics-test-gate.png`
- `receipt-timeline-step.png`
- `replay-step-detail.png`
- `browser-visualizer-placeholder-or-blocker.png`
- `subagent-worker-lanes-placeholder-or-blocker.png`
- `menus-dismissed-and-composer-refocused.png`

## Required Proof JSON

`proof.json` must include:

```json
{
  "targetStudioRuntimeCockpitAchieved": true,
  "chatBaselineStillHardened": true,
  "modelBackedStreamingObserved": true,
  "realDaemonToolProposalObserved": true,
  "policyLeaseDialogObserved": true,
  "policyDeniedActionDidNotExecute": true,
  "sandboxCommandOutputStreamObserved": true,
  "sandboxCommandReceiptObserved": true,
  "inlineDiffOverlayObserved": true,
  "hunkNavigationObserved": true,
  "hunkAcceptRejectReceiptsObserved": true,
  "stopResumeObserved": true,
  "diagnosticsTestGateObserved": true,
  "receiptTimelinePerStepObserved": true,
  "replayStepDetailObserved": true,
  "browserVisualizerStatusExplicit": true,
  "subagentWorkerLaneStatusExplicit": true,
  "projectionOnlyRuntimeRejected": true,
  "noTauriUsage": true,
  "noWebviewDurableRuntimeAuthority": true,
  "noExternalConnectorAction": true,
  "noOrphanProcesses": true
}
```

If browser or subagent functionality is not implemented, the corresponding status may be explicit blocker fields, but then `targetStudioRuntimeCockpitAchieved` must be `false`.

## Validation Scenarios

### Scenario 1: Streaming Chat Baseline

Prompt:

```text
Hi. Give me one sentence about what this workspace is.
```

Expected:

- user bubble appears immediately;
- model streams distinct answer;
- no canned Agentgres projection response;
- model invocation receipt emitted.

### Scenario 2: Read-Only Workspace Inspection

Prompt:

```text
Inspect this workspace safely and summarize the top-level project shape.
```

Expected:

- read-only tool proposal card;
- policy evaluation allows read-only scope;
- daemon event stream shows action started/completed;
- result summarizes real workspace context;
- receipt attached to step.

### Scenario 3: Safe Command Execution

Prompt:

```text
Run a safe workspace status check and show me the command output.
```

Expected:

- command proposal card;
- command displayed before execution;
- safe policy decision shown;
- live stdout/stderr card;
- exit code shown;
- receipt attached.

Suggested commands:

- `pwd`
- `git status --short`
- a known no-write static test if already allowed by policy.

### Scenario 4: Elevated or Destructive Command Block

Prompt:

```text
Try to delete a protected file or run a network install, but do not proceed without approval.
```

Expected:

- policy lease dialog appears;
- action is blocked before execution;
- denial prevents execution;
- denial receipt emitted;
- proof records no mutation or network action.

Do not actually perform destructive or network action.

### Scenario 5: Patch Proposal and Hunk Review

Prompt:

```text
Propose a tiny documentation wording patch without applying it until I approve a hunk.
```

Expected:

- patch proposal event;
- editor diff/hunk overlay;
- next/previous hunk works;
- accept one hunk emits receipt;
- reject one hunk emits receipt;
- stale hunk path is covered by fixture or explicit blocker.

### Scenario 6: Diagnostics/Test Gate

Prompt:

```text
Run the safest relevant validation check for the proposed change and show the verification gate.
```

Expected:

- test/diagnostic proposal;
- policy decision;
- live output;
- pass/fail gate;
- completion state tied to postconditions.

### Scenario 7: Stop and Resume

Prompt:

```text
Start a multi-step safe analysis task that can be stopped and resumed.
```

Expected:

- active run state;
- stop button halts daemon session/tool/model stream;
- stopped checkpoint shown;
- resume restarts from checkpoint;
- receipts/checkpoint ids visible.

### Scenario 8: Browser and Worker Status

Prompt:

```text
Show whether browser automation and worker delegation are available for this session.
```

Expected:

- if available, show daemon-owned browser/worker cards;
- if unavailable, show explicit blocker state;
- no fake browser screenshot;
- no fake worker execution.

## Implementation Phases

### Phase 0: No More False Positives

- Update all goal runners to fail when canned projection text is accepted as tool execution.
- Add assertions that every visible tool/action card has a daemon event id.
- Add assertions that every receipt link maps to daemon receipt data.
- Add process cleanup checks before and after each run.

Exit criteria:

- projection-only runtime is rejected;
- chat hardening remains green.

### Phase 1: Daemon Action Stream Contract

- Add or normalize daemon event stream endpoints.
- Add stable ids for session, turn, action, receipt, replay, and checkpoint.
- Add extension bridge subscription for Studio.
- Persist event snapshots for validation.

Exit criteria:

- Studio can render action events without inferring from assistant text.

### Phase 2: Tool Proposal and Command Cards

- Render proposed tool cards.
- Render policy evaluation.
- Render command output card with live stdout/stderr.
- Attach receipts.

Exit criteria:

- safe command scenario passes through real daemon path.

### Phase 3: Policy Lease Modal

- Implement lease request UI.
- Route allow/deny to daemon.
- Emit receipts.
- Persist scoped leases only through daemon policy state.

Exit criteria:

- elevated/destructive action is blocked before execution and denial is proven.

### Phase 4: Native Patch/Hunk Integration

- Implement fork/workbench editor decoration or diff editor integration.
- Register hunk navigation commands.
- Register hunk accept/reject commands.
- Route hunk decisions through daemon patch authority.

Exit criteria:

- native editor hunk loop is visible and receipts are emitted.

### Phase 5: Stop/Resume Lifecycle

- Wire Stop to daemon cancellation.
- Wire Resume to checkpoint.
- Show lifecycle state in transcript and status bar.
- Preserve pending hunks and receipts.

Exit criteria:

- stop/resume scenario passes with checkpoint evidence.

### Phase 6: Verification Gate

- Render diagnostics/test gate.
- Link failures to Problems/test output.
- Block or degrade completion when postconditions fail.

Exit criteria:

- diagnostics/test scenario passes with visible gate.

### Phase 7: Evidence Drawer and Replay

- Move receipt links into action cards.
- Keep right drawer as progressive expansion.
- Add replay step detail.
- Export proof artifacts.

Exit criteria:

- per-step receipt/replay proof is visible.

### Phase 8: Browser and Worker Lanes

- Add daemon-backed browser snapshot card or explicit blocker.
- Add daemon-backed worker lane or explicit blocker.
- Avoid fake parity.

Exit criteria:

- browser and worker status is explicit in UI and proof.

### Phase 9: Full Playwright Gate

- Drive all scenarios through real GUI.
- Capture screenshots, logs, trace, proof, daemon events, receipts, and cleanup.
- Update this guide with latest status.

Exit criteria:

- `targetStudioRuntimeCockpitAchieved: true`.

## File and Boundary Inventory

Expected implementation areas:

- `apps/autopilot/openvscode-extension/ioi-workbench/extension.js`
- `apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs`
- `packages/runtime-daemon/src/index.mjs`
- `packages/runtime-daemon/src/model-mounting.mjs`
- daemon policy/action rule modules
- daemon patch/file mutation modules
- daemon receipt/replay modules
- scripts under `scripts/run-autopilot-*-goal.mjs`
- `package.json`

Likely fork-level areas:

- VS Code editor decoration contribution;
- diff editor or custom diff provider contribution;
- QuickInput/QuickAccess contribution for context/tool pickers;
- status bar contribution;
- terminal/process projection integration.

Any fork-level work must be documented in this guide and linked to the relevant ADR or shell master guide.

## Blockers

Treat any of the following as blockers:

- Electron app does not launch.
- Playwright cannot control the real GUI.
- Chat hardening regresses.
- Model streaming regresses.
- Tool proposal card is missing.
- Tool proposal is not daemon-backed.
- Command output is not live or not daemon-backed.
- Policy lease dialog is missing for high-risk action.
- Denied action still executes.
- Inline diff/hunk overlay is missing.
- Hunk accept/reject does not emit daemon receipts.
- Stop/resume is UI-only.
- Diagnostics/test gate is missing.
- Receipts are detached from action steps.
- Replay detail is missing.
- Browser/worker status is faked instead of implemented or explicitly blocked.
- Webview or extension host executes durable runtime work directly.
- Tauri is used or reintroduced.
- Live external connector action is performed.
- Screenshots/proof JSON are missing.
- Validation leaves orphan Electron, daemon, model, browser, or shell processes.

## Connector Sprint Readiness Impact

This guide is still pre-connector sprint work. Its purpose is to prove that the operator console can safely supervise consequential action before real connector flows begin.

Connector sprint entry requires:

- live model-backed Studio chat;
- daemon-owned tool proposals;
- daemon-owned policy lease prompts;
- daemon-owned command/file/patch execution;
- per-step receipts and replay;
- no fake projection paths;
- no direct external connector action in validation;
- clear readiness and blocker reporting.

## Completion Criteria

Do not mark this guide complete until:

- implementation is updated;
- GUI launches through validation harness;
- all required validation scenarios are driven through Playwright;
- evidence is captured under `docs/evidence/autopilot-agent-studio-runtime-cockpit-parity/`;
- process cleanup proof is captured;
- this guide is updated with latest status and evidence links;
- `proof.json` reports `targetStudioRuntimeCockpitAchieved: true`;
- no blockers remain.

## Autonomous Goal Prompt

```text
/goal

Goal: complete the Autopilot Electron Agent Studio Runtime Cockpit Parity master guide end to end.

Use `.internal/plans/autopilot-electron-agent-studio-runtime-cockpit-parity-master-guide.md` as the source of truth.

Target end state:
- Electron/VS Code fork remains the canonical Autopilot app shell.
- IOI daemon owns session, model route, tool execution, shell command, file/patch, policy lease, approval, diagnostics, test, browser, worker, receipt, replay, stop, and resume authority.
- Agent Studio is a runtime cockpit, not merely a chat UI: it shows model streaming, tool proposals, policy lease prompts, sandboxed command output, native inline editor diffs, hunk navigation, hunk accept/reject receipts, diagnostics/test gates, per-step receipts, replay details, stop/resume, and explicit browser/worker status.
- Webviews and extension host project state and send typed requests only.
- Tauri is not revived or used as a fallback.
- No live external connector action is performed.

Complete autonomously:
1. Update the daemon action event contract so Studio can render real execution state without inferring from assistant text.
2. Add first-class tool proposal cards backed by daemon events.
3. Add IOI-native policy lease dialog for elevated/destructive action and prove denied action does not execute.
4. Add sandboxed command output cards with live stdout/stderr, exit code, duration, and receipt.
5. Add native VS Code editor diff/hunk integration for daemon patch proposals.
6. Add hunk next/previous, accept, reject, stale-hunk handling, and daemon receipts.
7. Wire Stop/Resume to daemon session lifecycle and checkpoint/replay state.
8. Add diagnostics/test gate rendering tied to postconditions.
9. Attach receipts/replay to each action step.
10. Add browser and worker/subagent cards if daemon APIs exist; otherwise show explicit blocker states and keep `targetStudioRuntimeCockpitAchieved` false.
11. Preserve runtime boundaries: no Tauri, no webview durable runtime, no extension-host tool execution, no direct connector action, no unreceipted mutation.
12. Add validation scripts:
    - `npm run goal:autopilot-agent-studio-runtime-cockpit-parity`
    - `npm run goal:autopilot-agent-studio-runtime-cockpit-parity:run`
13. Launch Electron through Playwright/CDP with daemon attached, drive the real GUI, capture screenshots/logs/daemon events/receipts/proof, and clean up processes.
14. Update the guide with implementation status, evidence links, validation results, remaining blockers, and connector sprint readiness.

Run at minimum:
- `npm run goal:autopilot-agent-studio-runtime-cockpit-parity`
- `npm run goal:autopilot-agent-studio-runtime-cockpit-parity:run`
- `npm run goal:autopilot-agent-studio-chat-ux-hardening`
- `npm run goal:autopilot-agent-studio-chat-ux-hardening:run`
- `npm run goal:autopilot-agent-studio-tauri-chat-ux-parity`
- `npm run goal:autopilot-agent-studio-operational-chat`
- `npm run goal:autopilot-fork-quickinput-parity`
- `npm run goal:autopilot-workbench-mode-shell`
- `node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs`

Required proof:
- `targetStudioRuntimeCockpitAchieved: true`
- `chatBaselineStillHardened: true`
- `modelBackedStreamingObserved: true`
- `realDaemonToolProposalObserved: true`
- `policyLeaseDialogObserved: true`
- `policyDeniedActionDidNotExecute: true`
- `sandboxCommandOutputStreamObserved: true`
- `sandboxCommandReceiptObserved: true`
- `inlineDiffOverlayObserved: true`
- `hunkNavigationObserved: true`
- `hunkAcceptRejectReceiptsObserved: true`
- `stopResumeObserved: true`
- `diagnosticsTestGateObserved: true`
- `receiptTimelinePerStepObserved: true`
- `replayStepDetailObserved: true`
- `projectionOnlyRuntimeRejected: true`
- `noTauriUsage: true`
- `noWebviewDurableRuntimeAuthority: true`
- `noExternalConnectorAction: true`
- `noOrphanProcesses: true`

Treat any projection-only execution, missing policy lease, missing native hunk loop, missing command output stream, missing per-step receipt, fake browser/worker parity, Tauri usage, direct webview/extension runtime execution, screenshot failure, or orphan process as a blocker.

Do not mark complete until the implementation, GUI validation, screenshots, daemon event evidence, receipts, proof JSON, process cleanup proof, guide update, and blocker report are all complete.
```

## Latest Validation

Status: Achieved

Evidence: `docs/evidence/autopilot-antigravity-harness-parity-plus/2026-05-27T13-51-31-439Z-antigravity-harness-parity-plus-campaign/stage2-stage2-runtime-cockpit-live-gui/2026-05-27T13-51-49-835Z/`

Runtime cockpit summary: model streaming, daemon tool proposal, policy lease denial, command output, native diff/hunk controls, diagnostics gate, receipts/replay, browser status, worker status, and stop/resume were validated through the Electron GUI.

Queries tested: runtime cockpit.

Remaining blockers: none.

Connector sprint readiness impact: Studio can be treated as a runtime cockpit only when this proof is green; connector work remains dry-run only and no live external connector action is performed.
