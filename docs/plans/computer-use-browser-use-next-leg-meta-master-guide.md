# Computer Use And Browser Use Next Leg Meta Master Guide

Owner: agent runtime / browser driver / GUI driver / Autopilot workflow compositor

Status: draft next-leg guide

Created: 2026-05-14

Primary source:

- `docs/plans/browser-use-master-guide.md`

Companion guides:

- `docs/plans/cua-parity-plus-computer-use-master-guide.md`
- `docs/plans/agent-tool-vocabulary-v2.md`
- `docs/plans/meta-harness-master-guide.md`
- `crates/drivers/src/browser/README.md`
- `crates/drivers/src/gui/README.md`
- `examples/cua-main/README.md`
- `examples/cua-main/blog/trajectory-viewer.md`
- `examples/cua-main/blog/app-use.md`

## Executive Verdict

The next leg should promote `docs/plans/browser-use-master-guide.md` from a
future-track plan into the active computer-use/browser-use sprint.

The framing should be broader than browser automation. The target is a first
class IOI computer-use harness that can operate through browser semantics,
visual GUI control, or sandboxed/hosted computers while preserving one runtime
truth:

- no second runtime;
- no workflow-compositor shadow truth store;
- daemon/runtime contracts first;
- browser, GUI, sandbox, model, workflow, and Autopilot surfaces all consume
  the same observations, target indexes, action proposals, actions, receipts,
  trajectories, policies, artifacts, and manifests.

The immediate move is to turn browser-use into the first concrete lane, then
generalize the same contracts across visual GUI and sandboxed/hosted computer
use.

The first draft of this guide defines the right contract and lifecycle shape.
The SOTA-plus target also needs an explicit behavioral control layer: how the
runtime chooses an environment, perceives the surface, builds affordances,
proposes actions, gates risk, verifies outcomes, repairs failures, hands off to
the user, and learns from trajectories.

## First Step: Promote Browser Use Master Guide

`docs/plans/browser-use-master-guide.md` should become the active next-leg
implementation source of truth.

Promotion means:

- update its status from future-track to active next leg;
- move any stale "later-track" language into historical context;
- align its phases with the current workflow compositor and agent runtime
  doctrine;
- make contract spine work the first implementation phase;
- require every new browser/computer-use behavior to emit deterministic
  manifests, receipts, and evidence;
- route reusable browser/computer-use primitives through canonical runtime
  tool invocations when they are executable from workflows, SDK, CLI, or TUI,
  even when a convenience endpoint also exists;
- keep quick operator diagnostics available from CLI/TUI without requiring
  React Flow, while preserving the same receipts and event kinds used by
  workflows;
- treat Playwright, UI-TARS, OpenAI CUA, Cua, and other tools as adapters or
  references unless explicitly introduced behind a typed IOI contract.

The promoted guide should not become a visual polish backlog. It should define
the canonical lifecycle and contracts for computer-use runs.

## Desired End State

IOI should expose a single computer-use harness family with at least three
lanes. The lanes can be surfaced as workflow configuration modes by default and
as explicit advanced nodes for protocol/debug users.

### Lane 1: Native Browser Use

Purpose:

- web automation;
- authenticated web app inspection;
- form filling;
- browser benchmarks;
- DOM/AX-rich workflows;
- browser-specific evidence and replay.

Shape:

- owned or attached Chromium;
- CDP-first;
- DOM, accessibility tree, selector, BrowserGym id, browser-use state, and page
  metadata aware;
- screenshot and Set-of-Marks fused into the same target index;
- preferred for web tasks where browser semantics are available.

Primary session modes:

- owned hermetic browser;
- attached browser;
- controlled relaunch;
- visual fallback when browser semantics are insufficient.

### Lane 2: Computer Use / Visual GUI

Purpose:

- arbitrary desktop apps;
- canvas apps;
- non-DOM browser surfaces;
- native application workflows;
- fallback when semantic browser control fails;
- user-visible computer-use tasks.

Shape:

- screenshot plus accessibility plus Set-of-Marks;
- coordinate safety and visual drift guards;
- window/app focus and clipboard awareness;
- no raw coordinate action without an observation reference and coordinate
  space id;
- best for apps and surfaces that do not expose stable DOM/AX browser targets.

Primary session modes:

- foreground local desktop;
- background-capable local desktop when the platform supports it;
- app-scoped visual session;
- human-assisted auth or challenge handoff.

### Lane 3: Sandboxed / Hosted Computer

Purpose:

- risky or destructive task isolation;
- reproducible evals;
- training trajectory generation;
- team or hosted workers;
- cloud/local VM and container control;
- mobile or device-lane workflows.

Shape:

- VM, container, mobile device, or hosted browser session;
- same screenshot/action/receipt contract as local computer use;
- explicit lifecycle: provision, observe, act, verify, retain evidence, clean
  up;
- best for evals, external-task agents, team workflows, and tasks that should
  not touch the user's real desktop.

Primary session modes:

- local container or VM;
- cloud container or VM;
- hosted browser;
- mobile/device session;
- bring-your-own image or environment.

## North Star Behavioral Shape

IOI computer use should be a governed, multi-lane runtime harness that can:

- choose the right environment;
- observe it through semantic and visual channels;
- build a target and affordance model;
- propose and validate actions before execution;
- execute only grounded and authorized actions;
- verify outcomes;
- repair failures;
- collaborate with the user at risk boundaries;
- emit replayable trajectories and receipts;
- clean up every leased environment.

All of this must happen through the same runtime event spine and
workflow-composable primitives.

## Shared Runtime Contracts

The three lanes must converge on one set of contracts.

Minimum lifecycle contract spine:

| Contract | Purpose |
| --- | --- |
| `ComputerUseLease` | Owns the authority, environment, lifecycle, consent, profile, app, and cleanup scope for a run. |
| `ComputerControlAdapterContract` | Normalizes native browser, GUI, sandbox, hosted, Playwright, CUA, UI-TARS, and other control backends. |
| `ComputerUseObservationBundle` | Captures screenshot, SoM, DOM, AX, selector maps, tab/app/window state, pending work, redaction, and freshness. |
| `TargetIndex` | Fuses semantic ids, BrowserGym bids, AX nodes, SoM ids, selectors, coordinates, window handles, and drift state. |
| `ComputerAction` | Canonical action language for click, type, key, scroll, drag, hover, select, upload, clipboard, wait, shell, and mobile gestures where allowed. |
| `ActionReceipt` | Records grounding, adapter path, execution result, postcondition, screenshots, and policy decisions. |
| `ComputerUseVerificationReceipt` | Records whether the intended state changed, remained stable, failed, or requires user intervention. |
| `ComputerUseTrajectoryBundle` | Replays observations, model decisions, tool/action calls, verifications, interruptions, and cleanup. |
| `CleanupReceipt` | Records process/profile/sandbox shutdown, artifact retention, and cleanup failures. |

Behavioral contract spine:

| Contract | Purpose |
| --- | --- |
| `ComputerUseRunState` | Live state for goal, subgoal, plan graph, current observation, target index, hypotheses, expected postcondition, blockers, retry budget, risk posture, handoff, and cleanup. |
| `EnvironmentSelectionReceipt` | Records selected lane/session mode, rejected options, reasons, authority, privacy impact, risk posture, and expected cleanup. |
| `AffordanceGraph` | Describes possible actions for each target, preconditions, confidence, expected transitions, risk class, required authority, fallback paths, and invalidation conditions. |
| `ActionProposal` | Captures raw model/provider output, normalized candidate, target reference, confidence, rationale summary, predicted postcondition, risk assessment, and policy decision before execution. |
| `RecoveryPolicy` | Defines allowed repairs for visual drift, target missing, no-effect action, stale observation, modal interruption, auth wall, navigation loop, network stall, crash, sandbox unavailable, policy block, or handoff timeout. |
| `HumanHandoffState` | Records why the user is needed, what action is requested, what the agent must not do, resume condition, post-resume observation, timeout policy, and evidence retention. |
| `InterfacePatternIndex` | Identifies forms, tables, modals, canvas, graphs, editors, terminals, file pickers, sidebars, toolbars, tabsets, warnings, auth walls, iframes, and shadow DOM. |
| `OutcomeContract` | Defines requested outcome, success criteria, acceptable side effects, prohibited side effects, evidence requirements, and rollback or cleanup requirements. |
| `CommitGate` | Separates preparation from consequential external effect with pre-commit summary, user confirmation, final action, and post-commit verification. |
| `ObservationRetentionMode` | Controls prompt-only summaries, local redacted artifacts, local raw artifacts, encrypted local raw artifacts, shareable eval artifacts, or no persistence. |

## Canonical Behavioral Loop

The canonical loop should be explicit in daemon events, trajectory records, and
workflow projection:

```text
classify_intent
-> select_environment
-> acquire_lease
-> observe
-> build_target_index
-> build_affordance_graph
-> plan_next_step
-> propose_action
-> policy/risk_gate
-> execute_action
-> verify_postcondition
-> repair_or_continue
-> commit_or_handoff
-> write_trajectory
-> cleanup
```

The loop prevents IOI from becoming a screenshot-to-click wrapper. It makes the
runtime's perception, plan, risk posture, action choice, verification, and
repair path inspectable and replayable.

### Environment Planner

The environment planner decides:

- owned browser, attached browser, controlled relaunch, visual GUI, local
  desktop, sandbox, hosted computer, or mobile/device;
- foreground vs background where available;
- persistent profile vs temporary profile;
- browser semantics vs visual fallback;
- read-only vs action-capable posture;
- whether the task should be refused, sandboxed, made read-only, or handed to
  the user.

Every decision should produce an `EnvironmentSelectionReceipt`.

### Action Proposal Pipeline

Model/provider outputs must not jump directly to executable actions.

Flow:

```text
raw provider output -> ActionProposal -> policy/risk gate -> ComputerAction
-> ActionReceipt -> ComputerUseVerificationReceipt
```

This is where UI-TARS coordinate tokens, OpenAI computer-use calls, Claude-style
computer tool requests, Gemini-style function calls, local VLM outputs, and
human-authored workflow actions become normalized IOI actions.

### Recovery And Repair

Failures should be classified at runtime, not only during benchmarks:

- perception;
- grounding;
- planning;
- policy;
- execution;
- verification;
- environment.

Allowed recovery actions should be policy-controlled:

- reobserve;
- rebuild target index;
- rebuild affordance graph;
- switch from semantic to visual action;
- switch from browser lane to GUI lane;
- pause for auth or user correction;
- rollback or restore;
- terminate safely;
- escalate to sandbox;
- mark task blocked.

### Outcome And Commit Gates

Preparation and external commitment must be separate.

Examples:

- fill a form, then pause before submit;
- draft a message, then pause before send;
- stage a browser setting, then pause before save;
- prepare a PR, then pause before publish;
- collect files, then pause before upload.

`OutcomeContract` defines success and side-effect bounds. `CommitGate` controls
the final consequential step.

### Trajectory Learning Loop

Trajectories should drive harness improvement:

```text
Trajectory -> failure taxonomy -> harness patch proposal -> shadow replay
-> held-out eval -> promotion receipt
```

Trajectory evidence is for diagnosis and validation. It must not become a
hidden benchmark shortcut.

## Workflow And Autopilot Shape

Default workflow authors should see a small number of primitives:

- Browser Use;
- Computer Use;
- Sandboxed Computer;
- Observation;
- Action;
- Verification;
- Evidence;
- Auth Handoff;
- Cleanup.

Advanced users should be able to expose lower-level runtime nodes:

- Session Lease;
- Browser Discovery;
- Profile Broker;
- CDP Connector;
- GUI Adapter;
- Sandbox Adapter;
- Target Index;
- Drift Guard;
- Model Action Adapter;
- Trajectory Writer.

Autopilot should make every run glass-box visible:

- current lane and session mode;
- active environment, browser, app, tab, or sandbox;
- latest screenshot and SoM overlay;
- DOM/AX/selector target list when available;
- live run state;
- affordance graph summary;
- model decision and parsed action;
- action proposal and policy/risk gate;
- action receipt and postcondition;
- verification state;
- recovery or repair state;
- outcome/commit gate state;
- auth/user-handoff state;
- evidence and trajectory links;
- cleanup state.

## Model Adapter Posture

Computer-use models and providers should be mounted behind IOI contracts.

Examples:

- OpenAI computer-use style outputs become IOI `ActionProposal` entries with
  pending safety checks mapped into IOI approvals before execution.
- UI-TARS coordinate or token outputs become grounded IOI actions only after
  coordinate normalization and observation binding.
- Cua-style computer/sandbox APIs become `ComputerControlAdapterContract`
  implementations or benchmark/eval references.
- Local mounted VLMs can be planning models, grounding models, or composite
  model roles, but they cannot bypass IOI receipts, policy, or target indexes.

This keeps model diversity from creating a second action runtime.

## Sprint Order

### Phase 0: Promote And Normalize The Guide

Deliverables:

- promoted browser-use guide status;
- updated north star around three lanes;
- active completion dashboard;
- explicit doctrine and non-goals;
- links to CUA parity-plus guide and workflow compositor guide.

Acceptance:

- browser-use is clearly the first implementation lane;
- visual GUI and sandboxed/hosted lanes are named as target follow-ons;
- no "later-track" ambiguity remains.

### Phase 1: Contract And Behavioral Spine

Deliverables:

- `ComputerUseLease`;
- `ComputerControlAdapterContract`;
- `ComputerUseObservationBundle`;
- `TargetIndex`;
- `ComputerAction`;
- `ActionReceipt`;
- `ComputerUseVerificationReceipt`;
- `ComputerUseTrajectoryBundle`;
- `CleanupReceipt`;
- `ComputerUseRunState`;
- `EnvironmentSelectionReceipt`;
- `AffordanceGraph`;
- `ActionProposal`;
- `RecoveryPolicy`;
- `HumanHandoffState`;
- `InterfacePatternIndex`;
- `OutcomeContract`;
- `CommitGate`;
- `ObservationRetentionMode`.

Acceptance:

- existing owned browser path can emit the contracts without behavior change;
- existing GUI fallback can map into the same contracts;
- provider/model outputs pass through `ActionProposal` before execution;
- run state, recovery, handoff, outcome, and cleanup are durable enough for
  replay;
- generated manifests are deterministic;
- no React Flow state becomes runtime truth.

Current status: the SDK exposes the contract spine plus executable recovery,
human handoff, outcome, commit-gate, retention, and model-action adapter
helpers. SDK, daemon, saved workflow runs, and React Flow run history now expose
commit-gate evidence through the canonical `computer_use.commit_gate` step.
SDK-local and daemon-backed runs also accept canonical native-browser
observation, target-index, and affordance contracts from mounted executors, or
native `BrowserObservationArtifacts` that compile into the same observation,
target-index, and affordance contracts. RuntimeAgentService bridge turns now
project recent native browser driver artifacts into canonical
`computer_use.observation` and `computer_use.affordance_graph` events for
Autopilot/daemon consumption, and daemon run records now preserve those bridge
events in run inspection plus `computer-use-trace.json` artifacts. When a
bridge emits computer-use events without a full trajectory bundle, the daemon
synthesizes deterministic event-level trajectory entries so the trace remains
replayable. Bridge observation traces also infer lane, session, environment
selection, and lease projection data from the canonical observation bundle
without creating a second runtime owner. When the bridge supplies an
affordance graph but no explicit proposal, the daemon projects a non-executing
`ActionProposal` from the top affordance so policy and UI surfaces can show the
next candidate without pretending an action already ran. Those bridge-derived
proposals synthesize proposal-only outcome and commit gates, requiring
confirmation for possible external effects while keeping `ComputerAction`
execution null; the IDE projection and run-history workbench now preserve that
distinction as typed, non-executed, confirmation-gated harness rows. The same
bridge projection also synthesizes live
`ComputerUseRunState` so inspection surfaces can show the current observation,
target index, blocker, handoff/confirmation state, and cleanup ownership.
The RuntimeAgentService bridge now emits the proposal and commit-gate events
directly from native browser affordances, with daemon-side derivation retained
for older bridge streams that only provide observation and affordance rows.
When the same turn includes `browser__*` tool results, the bridge now emits
canonical action-executed and verification rows so the persisted trace can show
the real browser tool effect instead of only generic tool completion.
Daemon-backed visual and hosted/sandbox lane runs activate through the same
trace spine when a mounted executor supplies those contracts or, for the
sandboxed-hosted lane, when the caller opts into the deterministic local
fixture provider. Those runs preserve adapter contracts, cleanup receipts,
contract-ingest evidence, and trajectory data while missing external hosted
adapters still fail closed. Visual GUI runs can now broker supplied
screenshot/SoM/AX files or read-only local captures through
`ioi.computer_use.visual_gui.observe`, then feed the retained observation refs
into a later visual run. Approved visual GUI action runs can opt into the local
GUI executor only with an approval ref, observation-bound target bounds, the
original screenshot artifact, a preflight screenshot drift check, provider
execution receipt, and required reobserve-after-action evidence; missing local
providers still fail closed. The browser lane now also has a
daemon/SDK read-only discovery receipt for browser process inventory, declared
CDP endpoints, default-profile remote-debugging blockers, and redaction/safety
posture before any attach or relaunch authority is requested. Workflow authors
can add the same capability through an advanced Browser Discovery primitive
that compiles to the runtime tool contract and deterministic discovery
arguments instead of a React Flow-owned browser state. Saved workflow runs now
emit a dedicated `computer_use.browser_discovery` event with browser/CDP/blocker
counts in the same glass-box run-history projection. Direct SDK/daemon
thread-tool invocation of `ioi.computer_use.native_browser` now emits the full
read-only native-browser behavioral loop through canonical `computer_use.*`
events, giving workflows and TUI surfaces a glass-box prompt-through-pipeline
trace; mutating actions remain proposal/commit-gate only until an explicit
approval ref is supplied, at which point the same route emits the approved
`ComputerAction`, `ActionReceipt`, passed verification, and completed commit
gate evidence when a CDP endpoint/websocket is available. The daemon now
contains a narrow CDP-backed executor for approved `click`, `navigate`,
`type_text`, `key_press`, and `upload` actions plus explicit `scroll` actions;
missing browser adapter evidence fails closed with blocked verification and
commit-gate receipts instead of synthetic execution. Explicit CDP endpoints now
infer `attached_cdp` session-mode receipts instead of being projected as owned
hermetic sessions. CLI and TUI operators now have dedicated native-browser,
sandboxed-computer, visual-observe, and visual-action commands over the same
daemon thread-tool route, including approval, target selectors, text/key/scroll
and file payloads, CDP endpoint/websocket, sandbox provider/image/task refs,
local-capture, and opt-in local GUI executor options, so manual validation can
run both the gated and approved prompt pipeline without knowing raw tool ids.
The workflow proof harness now covers the same authoring path for native
browser, sandboxed computer, and visual GUI lanes: mounted model prompt traces
flow into Browser Use or Visual Observation plus Computer Use, then project
environment, observation, target-index/SoM/AX, affordance, proposal, approval,
preflight drift, action, verification, trajectory, and cleanup rows without a
React Flow shadow truth store. A retained tri-lane computer-use scorecard now
rolls those proofs into one promotion gate for lane coverage, prompt-trace
coverage where model nodes are composed, target/affordance/action evidence,
approval/fail-closed posture, and explicit external deferrals for hosted
providers and third-party eval ingestion. The scorecard also carries an
operator summary with per-lane status rows, blocker rows, and exact proof
artifact paths so the retained gate is readable without opening every proof
file.
Sandboxed
Computer authoring presets now default to `local_sandbox` plus `local_fixture`,
giving workflow authors a runnable hosted-style harness trace while concrete
VM/container/mobile providers remain behind explicit adapter, authority,
isolation, and retention policy work.
Future daemon, workflow, and Autopilot policy executors should consume these
helpers rather than defining local policy shapes.

### Phase 2: Environment Planner And Behavioral Loop

Deliverables:

- intent classifier;
- environment planner;
- run state updater;
- affordance graph builder;
- action proposal normalizer;
- policy/risk gate;
- repair dispatcher;
- outcome and commit gate;
- retention policy selector.

Acceptance:

- a run can explain why it chose a lane and session mode;
- every proposed action is auditable before execution;
- common failures produce structured recovery choices;
- sensitive final actions pause behind commit gates.

### Phase 3: Native Browser Lane

Deliverables:

- owned browser lease;
- attach discovery receipt;
- controlled relaunch branch;
- profile broker;
- auth handoff state;
- unified browser observation bundle;
- fused DOM/AX/SoM target index;
- adapter-side Browser Use artifact projection into canonical target indexes
  and affordance graphs;
- receipted browser action executor.

Acceptance:

- browser sessions are lifecycle-managed;
- every material action has postcondition evidence;
- cleanup is automatic and receipted.

### Phase 4: Visual GUI Lane

Deliverables:

- local desktop/app lease;
- screenshot/AX/SoM observation bundle;
- visual target index;
- visual drift guard;
- safe input executor;
- auth/challenge handoff state.

Acceptance:

- visual fallback uses the same action and receipt language;
- coordinate actions require observation grounding;
- private screenshot retention follows policy.

### Phase 5: Sandboxed / Hosted Lane

Deliverables:

- sandbox/hosted lease;
- provision/attach/cleanup lifecycle;
- VM/container/browser/mobile adapter boundaries;
- hosted worker fail-closed behavior;
- retained trajectory/eval bundles.

Acceptance:

- hosted or sandbox unavailable states fail closed unless a mounted provider or
  deterministic local fixture adapter is configured;
- local fixture and provider-backed sandboxed runs are replayable and cleanly
  cleaned up;
- team/worker surfaces use the same runtime events and receipts.

### Phase 6: Glass-Box Workbench

Deliverables:

- Autopilot computer-use run view;
- live screenshot/SoM pane with runtime-derived refs and target overlay
  summaries;
- event/action/verification timeline;
- run state inspector;
- target index inspector;
- affordance graph inspector;
- model action inspector;
- proposal, policy, and commit gate inspector;
- recovery and handoff inspector;
- trajectory replay view;
- evidence export controls.

Acceptance:

- a user can watch a prompt move through the harness;
- failures reveal observation, decision, action, and verification state;
- sensitive artifacts are redacted or locally retained by policy.

### Phase 7: Workflow Projection

Deliverables:

- default Browser Use and Computer Use primitives;
- advanced low-level nodes;
- deterministic manifest compile;
- migration compatibility for stored workflows;
- default harness teaching graph.
- runtime-event projection that turns `computer_use.*` events into
  node-addressed glass-box rows with lane, lease, observation, target,
  affordance, proposal, action, verification, trajectory, cleanup, recovery,
  and fail-closed evidence.
- canonical Browser Use, Computer Use, and Sandboxed Computer creator presets
  that compile to runtime-owned computer-use lane/session metadata rather than
  React Flow state.
- composer Run activation metadata bridge that sends configured lane, session,
  action kind, approval ref, retention, fail-closed, workflow node ids, tool ref,
  and authority scopes to the runtime request.
- saved workflow-run manifest projection that emits the same canonical
  `computer_use.*` runtime-thread trace when invoked outside the React Flow
  controller path, including proposal-only commit-gated traces for mutating
  native-browser actions and approved action/receipt traces when approval refs
  are present.
- sandboxed-computer Run-button proof that exercises the real composer Run
  control, forwards local-fixture sandbox metadata into runtime options, and
  verifies step-addressed glass-box trace projection without React Flow owning
  runtime truth.
- native-browser prompt pipeline proof that composes a mounted model node with
  Browser Use, carries a demo prompt through the model invocation trace, and
  verifies the model-to-browser handoff plus browser observation, proposal,
  action, verification, trajectory, and cleanup rows.

Acceptance:

- React Flow remains a configurable projection;
- every node maps to runtime contracts;
- old workflows continue to load.
- mounted-model prompts launched from a composed workflow carry the selected
  computer-use lane and action kind into the daemon/runtime request.
- Autopilot/run history can rebuild the computer-use prompt-to-action pipeline
  from canonical runtime events without a separate trace store.
- authored single-node computer-use traces remain glass-box visible as
  environment, observation, affordance, proposal, action, verification,
  trajectory, and cleanup steps instead of collapsing into one opaque node.
- composed model plus Browser Use workflows show the prompt, mounted model
  trace, selected browser action path, policy posture, verification, and
  cleanup evidence in one run-history surface.
- SDK and daemon runtime thread events preserve authored workflow graph/node
  ids, tool refs, authority scopes, and observation-retention metadata so the
  glass-box trace lands back on the composed primitive.

### Phase 8: Evals And Meta-Harness

Deliverables:

- replayable trajectory format;
- OSWorld/ScreenSpot/BrowserGym/WorkArena style adapters where feasible;
- retained challenge batteries;
- model adapter regression fixtures;
- SDK action-adapter compiler fixtures for OpenAI-style computer-use outputs,
  UI-TARS coordinate actions, and generic VLM action records, all normalized
  into IOI `ActionProposal` and grounded `ComputerAction` contracts;
- failure-class scorecards from SDK trajectory eval projection.

Acceptance:

- improvements can be evaluated across lanes;
- trajectory evidence supports debugging, not hidden benchmark overfitting.

## Non-Goals

- Replacing the native Rust CDP browser driver with Playwright as the silent
  core browser runtime.
- Treating CUA, UI-TARS, or any provider as the new source of runtime truth.
- Adding a node for every implementation detail in React Flow.
- Allowing screenshot-only coordinate clicks when semantic grounding exists.
- Automating credentials, human challenges, or sensitive account actions
  without explicit user authority.
- Persisting private screenshots by default.

## Completion Criteria

This next leg is complete when:

- the promoted browser-use guide is active and current;
- the three-lane end state is represented in docs and workflow taxonomy;
- owned browser, visual GUI, and sandbox/hosted adapters share the contract
  spine;
- browser actions emit observation refs, target refs, receipts, verifications,
  and cleanup receipts;
- the behavioral loop is explicit in runtime events and trajectories;
- environment selection, action proposal, recovery, handoff, outcome, commit,
  and retention decisions are receipted;
- Autopilot can show a glass-box prompt-to-action-to-verification pipeline;
- React Flow can compose the harness without shadow runtime state;
- generated evidence is ignored or retained only under explicit policy;
- targeted unit, contract, manifest, and GUI validation tests pass;
- remaining external dependencies are documented as narrow deferrals.
