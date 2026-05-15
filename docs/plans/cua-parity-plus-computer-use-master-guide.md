# CUA Parity Plus Computer Use Master Guide

Owner: agent runtime / drivers / sandbox / Autopilot / workflow compositor

Status: draft parity-plus guide

Created: 2026-05-14

Reference implementation:

- `examples/cua-main/README.md`
- `examples/cua-main/blog/trajectory-viewer.md`
- `examples/cua-main/blog/app-use.md`
- `examples/cua-main/blog/bringing-computer-use-to-the-web.md`
- `examples/cua-main/blog/composite-agents.md`
- `examples/cua-main/blog/cua-vlm-router.md`
- `examples/cua-main/blog/training-computer-use-models-trajectories-1.md`

Companion IOI guides:

- `docs/plans/browser-use-master-guide.md`
- `docs/plans/computer-use-browser-use-next-leg-meta-master-guide.md`
- `docs/plans/agent-tool-vocabulary-v2.md`
- `docs/plans/meta-harness-master-guide.md`

## Executive Verdict

CUA is the right parity-plus reference for IOI's next computer-use leg because
it treats computer use as a complete product surface:

- background native computer control;
- sandboxed computers across OS and container shapes;
- browser/device automation;
- trajectory capture and replay;
- benchmark and training data pipelines;
- model/provider routing;
- app-scoped computer sessions;
- cooperative sandbox access for coding agents.

IOI should not copy CUA as a second runtime. IOI should use CUA as a reference
shape and implement parity-plus through IOI's existing runtime doctrine:

- one canonical runtime truth;
- typed leases, observations, target indexes, actions, receipts, trajectories,
  policies, artifacts, and manifests;
- native browser and GUI drivers remain first-class;
- React Flow is an authoring/projection surface;
- every external model or computer backend is an adapter.

Parity-plus means IOI matches the developer and operator affordances that make
CUA useful, then goes beyond them with stronger workflow configurability,
runtime receipts, policy governance, and Autopilot glass-box visibility.

The parity target should not stop at lifecycle contracts. CUA-style systems are
useful because they keep running through perception, action, verification, and
repair loops. IOI's plus layer is to make that behavioral control loop typed,
receipted, workflow-composable, and policy-bound.

## Parity Dimensions

| CUA Shape | IOI Parity Target | IOI Plus Target |
| --- | --- | --- |
| Background computer-use driver | Local GUI adapter can observe, click, type, verify, and retain trajectories without unsafe coordinate drift | Runtime lease and receipts make every action policy-auditable and replayable |
| Sandboxes for Linux, macOS, Windows, Android, containers, VMs, BYOI | `SandboxedComputer` adapter family with provision, observe, act, verify, cleanup | Same contract as browser and local GUI lanes, with workflow nodes and hosted worker fail-closed behavior |
| CuaBot cooperative sandbox for coding agents | IOI coding agents can request computer-use leases through the runtime harness | Autopilot shows run topology, evidence, approvals, and cleanup in one glass-box view |
| Cua-Bench and trajectory export | IOI can emit replayable trajectory bundles for evals | Meta-harness can diagnose failure classes and validate harness candidates across lanes |
| Trajectory Viewer | Autopilot trajectory replay and evidence inspector | Timeline links model decisions, target indexes, policy checks, receipts, and verification deltas |
| App-Use scoped desktops | App-scoped visual sessions with least-privilege window/app visibility | Scopes compile from workflow policy and are visible as authority receipts |
| Web SDK and unified computer API | SDK/CLI/API expose canonical `ComputerUseLease` and `ComputerAction` contracts | Same manifest runs across daemon, workflow, Autopilot, and tests |
| Composite agents and VLM routing | Mounted models can play planner, grounding, verifier, or action-parser roles | Routing decisions, costs, fallbacks, and model roles are receipted and replayable |

## North Star

The IOI computer-use harness should let a user or workflow author say:

```text
Use a browser, desktop app, sandbox, hosted worker, or device to complete this
task. Show me what the agent saw, why it acted, what it clicked or typed, what
changed, what was verified, what artifacts were retained, and what was cleaned
up.
```

The stronger SOTA-plus version is:

```text
Choose the safest usable environment, understand the current interface, infer
what actions are available, propose a grounded action, explain the risk,
execute only after policy approval, verify what changed, repair failures,
handoff to the user at sensitive boundaries, and preserve a replayable
trajectory.
```

The same run should be executable through:

- daemon/runtime API;
- SDK;
- CLI/TUI;
- Autopilot chat;
- React Flow workflow;
- benchmark/eval harness.

## Current IOI Advantages

IOI already has strong pieces that CUA parity can build on:

- Rust CDP browser driver;
- browser-use and BrowserGym observation artifacts;
- DOM, AX, selector, screenshot, and Set-of-Marks grounding;
- GUI screenshot and accessibility capture;
- visual hash guarded clicks;
- normalized browser and screen tool vocabulary;
- runtime event and receipt routing;
- workflow compositor doctrine;
- Autopilot GUI as the natural glass-box workbench.

The gap is packaging. IOI needs a unified computer-use harness lifecycle and
CUA-grade operator affordances.

## Required Contract Spine

CUA parity-plus depends on the contract spine from the meta guide:

- `ComputerUseLease`;
- `ComputerControlAdapterContract`;
- `ComputerUseObservationBundle`;
- `TargetIndex`;
- `ComputerAction`;
- `ActionReceipt`;
- `ComputerUseVerificationReceipt`;
- `ComputerUseTrajectoryBundle`;
- `CleanupReceipt`.

Behavioral extensions:

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

All CUA-inspired features must map to these contracts. No feature should create
an independent action language, trajectory format, policy store, or workflow
truth source.

## Behavioral Control Layer

CUA parity-plus requires a canonical runtime loop:

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

### Live Run State

`ComputerUseRunState` should keep the live state of the run:

- user goal;
- current subgoal;
- plan graph;
- current observation and target index;
- active hypotheses;
- expected postcondition;
- last action;
- verification status;
- blocker state;
- retry budget;
- risk posture;
- user handoff state;
- cleanup state.

This is the durable behavioral memory of a computer-use run. The trajectory
records what happened; run state records what the agent currently believes and
intends.

### Target Index Plus Affordances

`TargetIndex` says what exists. `AffordanceGraph` says what can safely be done
with it.

Affordances should record:

- possible actions;
- action preconditions;
- confidence;
- expected state transitions;
- risk class;
- required authority;
- confirmation requirements;
- fallback action paths;
- invalidation conditions.

### Action Proposal Before Action

Provider/model output should become `ActionProposal`, not immediate
`ComputerAction`.

The proposal records:

- raw model output;
- normalized candidate action;
- target reference;
- model role;
- confidence;
- rationale summary;
- predicted postcondition;
- risk assessment;
- policy decision reference.

Only grounded and authorized proposals become executable `ComputerAction`
entries.

### Recovery And Repair

Runtime failures should use the same failure taxonomy as benchmarks:

- perception;
- grounding;
- planning;
- policy;
- execution;
- verification;
- environment.

`RecoveryPolicy` defines allowed responses:

- reobserve;
- rebuild target index;
- rebuild affordance graph;
- switch semantic/visual lane;
- pause for auth;
- ask the user for correction;
- rollback or restore;
- terminate safely;
- escalate to sandbox;
- mark blocked.

### Handoff, Outcome, Commit, And Retention

Human collaboration should be broader than auth.

`HumanHandoffState` covers login, CAPTCHA or human challenge, password entry,
payment confirmation, account permission changes, sensitive data entry, manual
target selection, and user correction after mis-grounding.

`OutcomeContract` defines success criteria and allowed side effects.
`CommitGate` separates safe preparation from consequential external effects.
`ObservationRetentionMode` controls how much private observation evidence can be
persisted.

### Interface Pattern Understanding

The runtime should detect common UI patterns and route behavior accordingly:

- form;
- table;
- modal;
- canvas;
- graph;
- editor;
- terminal;
- file picker;
- sidebar;
- toolbar;
- tabset;
- warning or toast;
- auth wall;
- iframe;
- shadow DOM.

This lets IOI do better than generic screenshot clicking. Tables, graphs,
modals, editors, and file pickers need different action and verification
strategies.

## Parity-Plus Workstreams

### Workstream 1: Computer Use Lease And Adapter Boundary

Goal: define the common lifecycle for browser, GUI, sandbox, hosted, and device
computer-use sessions.

Deliverables:

- lease schema with lane, environment, authority, consent, owner, lifecycle,
  retention, cleanup, and policy fields;
- adapter trait or interface for observe, act, verify, heartbeat, and cleanup;
- adapter capability descriptors;
- fail-closed unavailable states;
- compatibility mapping for existing browser and GUI drivers.

Acceptance:

- owned browser can run through the lease contract without behavior change;
- GUI fallback can report capabilities through the same contract;
- unavailable sandbox/hosted providers fail closed with explicit receipts.

### Workstream 2: Behavioral Planner, Proposal, And Recovery Loop

Goal: make IOI's runtime behavior as explicit as its lifecycle contracts.

Deliverables:

- `ComputerUseRunState`;
- environment planner;
- `EnvironmentSelectionReceipt`;
- affordance graph builder;
- action proposal normalizer;
- policy/risk gate;
- recovery dispatcher;
- handoff state manager;
- outcome and commit gate;
- observation retention selector.

Acceptance:

- every run can explain its selected environment and rejected alternatives;
- model outputs are proposals before actions;
- recovery choices are structured and policy-controlled;
- sensitive final actions pause behind commit gates;
- trajectory replay includes run state, proposals, risks, repairs, and handoffs.

### Workstream 3: Native Browser Parity

Goal: make IOI's browser lane production-grade as the first concrete
computer-use lane.

Deliverables:

- owned browser lease;
- attached browser discovery;
- controlled relaunch branch;
- profile broker;
- auth handoff;
- unified observation bundle;
- fused target index;
- receipted browser action executor;
- browser cleanup receipt.

Acceptance:

- every material browser action is grounded, verified, and receipted;
- auth walls pause for the user instead of harvesting credentials;
- controlled profiles and scratch artifacts are cleaned or retained by policy.

### Workstream 4: Visual GUI And App-Scoped Sessions

Goal: reach CUA-style arbitrary app control while preserving IOI safety
contracts.

Deliverables:

- local visual computer lease;
- app/window scoped observation;
- accessibility plus screenshot plus SoM bundle;
- visual target index;
- coordinate-space guard;
- drift-aware action executor;
- app-scope policy receipt;
- user handoff for challenges and sensitive flows.

Acceptance:

- visual GUI actions require observation grounding;
- app-scoped runs can limit visible/interactive surfaces when platform support
  exists;
- failures identify whether the block is observation, grounding, authority, or
  platform capability.

### Workstream 5: Sandboxed And Hosted Computers

Goal: match CUA's sandbox value without making sandbox providers runtime truth.

Deliverables:

- sandbox adapter interface;
- local container/VM capability model;
- hosted container/VM capability model;
- browser-only hosted session mode;
- mobile/device session mode where available;
- provision and cleanup receipts;
- artifact retention policy;
- hosted worker job representation.

Acceptance:

- sandbox runs are reproducible and replayable;
- provider outage or missing credentials fails closed;
- team/hosted jobs surface task state, logs, artifacts, and cleanup receipts;
- no hosted provider bypasses IOI approval or policy.

### Workstream 6: Trajectory Recording And Replay

Goal: provide CUA-grade trajectory debugging and training-data affordances.

Deliverables:

- canonical trajectory directory and manifest;
- observation/action/decision/verification timeline;
- screenshot and SoM frames;
- target index snapshots;
- model action parse records;
- policy and approval decisions;
- cleanup receipt;
- Autopilot replay view;
- export filters for evals and training data.

Acceptance:

- every computer-use run can be replayed at the decision/action level;
- private artifacts are redacted or excluded by retention policy;
- users can identify the exact step where a run failed;
- trajectory export is deterministic and schema-versioned.

### Workstream 7: Model Action Adapters And Composite Roles

Goal: support computer-use models without fragmenting the runtime.

Deliverables:

- OpenAI computer-use style action adapter;
- UI-TARS coordinate/token action adapter;
- generic VLM action-parser adapter;
- planner/grounder/verifier role descriptors;
- observer summarizer role descriptor;
- critic/recovery role descriptor;
- policy explainer role descriptor;
- composite model role routing;
- cost, provider, and fallback receipts where applicable;
- deterministic fixture tests for each adapter.

Acceptance:

- provider-specific outputs compile to IOI `ActionProposal` and then approved
  IOI `ComputerAction`;
- coordinate outputs are normalized and observation-bound;
- safety checks map to IOI approval policy;
- mounted local models can run through the same workflow manifests.

### Workstream 8: Co-Op Coding Agent Computer Use

Goal: let IOI coding agents use computer environments as a governed runtime
capability.

Deliverables:

- coding-agent computer-use lease request: started with `computer_use.request_lease`
  in the governed coding-tool pack;
- sandbox/browser/device selection policy: lease manifest records native browser,
  visual GUI, or sandboxed/hosted lane intent before execution;
- shared clipboard and artifact policy: lease manifest fails closed with clipboard
  disabled until explicit approval and redacted trace artifacts by default;
- repo/worktree authority scope: lease manifest records workspace read scope while
  leaving write/mutating authority to explicit approvals and downstream tools;
- run history and evidence projection in Autopilot: coding-tool result receipts
  preserve workflow graph/node ids plus the downstream thread-tool handoff;
- CLI/TUI controls for pause, resume, abort, and cleanup: started through the
  canonical `ioi.computer_use.control` thread tool, emitting governed control,
  handoff, and cleanup receipts on the same runtime event spine.

Acceptance:

- coding agents cannot silently seize host desktop authority;
- sandboxed computer-use is visible and cancellable;
- branch/diff/artifact outputs remain tied to runtime receipts.

### Workstream 9: Benchmarks And Meta-Harness

Goal: make computer-use improvements measurable.

Deliverables:

- benchmark adapter interface;
- OSWorld-style task adapter where feasible;
- ScreenSpot-style grounding adapter where feasible;
- BrowserGym/WorkArena bridge alignment;
- retained validation and challenge batteries;
- failure taxonomy and scorecards;
- trajectory-backed regression fixtures.

Acceptance:

- changes are accepted from held-out validation, not cherry-picked traces;
- failures are categorized by perception, grounding, planning, policy,
  execution, verification, or environment;
- benchmark artifacts are not used as hidden runtime shortcuts.

### Workstream 10: Trajectory-Driven Harness Improvement

Goal: use trajectories to improve the harness without benchmark overfitting.

Deliverables:

- trajectory failure summarizer;
- failure taxonomy aggregation;
- harness patch proposal records;
- shadow replay runner;
- held-out eval promotion gate;
- promotion receipt.

Acceptance:

- trajectories produce actionable harness hypotheses;
- proposed changes are validated on held-out evals;
- accepted improvements have a lineage trail;
- rejected improvements retain failure evidence.

## Autopilot Product Requirements

Autopilot should be the primary glass-box operator surface.

Required views:

- live environment/screen pane;
- SoM and target overlays;
- DOM/AX/selector inspector for browser mode;
- app/window inspector for visual mode;
- timeline of observations, model decisions, actions, verifications, and
  approvals;
- run state inspector;
- affordance graph inspector;
- action proposal and policy gate inspector;
- recovery and handoff inspector;
- outcome and commit gate inspector;
- current lane and session mode badges;
- policy and authority panel;
- trajectory replay;
- cleanup and retained evidence panel;
- export controls.

The experience should feel like watching the harness reason and act through a
real topology, not like reading a flat tool log.

## Workflow Compositor Projection

Default palette primitives:

- Browser Use;
- Computer Use;
- Sandboxed Computer;
- Observe;
- Act;
- Verify;
- Evidence;
- Auth Handoff;
- Cleanup.

Advanced palette primitives:

- Session Lease;
- Control Adapter;
- Browser Discovery;
- Profile Broker;
- CDP Connector;
- GUI Adapter;
- Sandbox Adapter;
- Target Index;
- Affordance Graph;
- Action Proposal;
- Drift Guard;
- Recovery Policy;
- Commit Gate;
- Model Action Adapter;
- Trajectory Writer;
- Benchmark Adapter.

Rules:

- separate nodes only for separate execution boundaries;
- config sections for variants of the same boundary;
- inspectors for receipts, target maps, and low-level protocol details;
- every graph compiles to deterministic runtime/workflow manifests.

## Safety And Governance

Computer-use policy must be stricter than ordinary tool use.

Required guarantees:

- explicit authority before attaching to or relaunching user browsers;
- no credential harvesting;
- no automated human-challenge completion;
- no hidden user-profile copying;
- no private screenshot persistence by default;
- no destructive, billing, admin, or account mutation without approval;
- no raw coordinate actions without observation grounding;
- no hosted provider access without configured trust and budget policy;
- cleanup failures are visible and retained.

## Implementation Order

1. Promote browser-use into the active next-leg guide.
2. Create the lifecycle and behavioral contract spine.
3. Map owned browser into the contract spine.
4. Add environment planner, run state, affordance graph, action proposal,
   recovery, handoff, outcome, commit, and retention contracts.
5. Add trajectory schema and writer for existing browser runs.
6. Add Autopilot trajectory/workbench projection.
7. Add visual GUI lane contract mapping.
8. Add model action adapter fixtures for OpenAI-style and UI-TARS-style
   outputs.
9. Add sandbox/hosted adapter skeleton with deterministic local fixture and
   fail-closed hosted-provider behavior.
10. Add workflow compositor primitives and advanced nodes.
11. Add benchmark/eval adapters and retained regression fixtures.
12. Validate end-to-end through browser, visual GUI, local sandbox fixture, and
    sandbox-unavailable lanes.

## Completion Dashboard

| Area | Target status |
| --- | --- |
| Contract spine | Done / regression guarded |
| Behavioral control loop | Done / regression guarded for current lanes: SDK and daemon lifecycle projection emit select, acquire, observe, affordance, propose, execute, verify, trajectory, and cleanup steps with workflow node ids; RuntimeAgentService bridge traces now carry proposal, commit-gate, executed-action, and verification evidence directly from native browser affordances and browser tool results, then synthesize live `ComputerUseRunState` from that evidence; daemon thread-tool runs now execute approved native-browser click/navigate/type_text/key_press/upload actions plus explicit scroll through CDP when an adapter endpoint is available and fail closed when it is not |
| Environment planner | Done / regression guarded for current lanes, with narrow external deferral: `EnvironmentSelectionReceipt` is SDK/daemon trace-visible, explicit sandbox requests either activate the deterministic local fixture provider or fail closed when no trusted provider is configured, explicit visual requests now fail closed unless mounted contracts, local screenshot/SoM/AX observation refs, explicit local observation file paths, a read-only local visual capture, or an approved observation-bound local GUI executor request is supplied, RuntimeAgentService bridge observations now infer lane/session/lease projection data without selecting a second runtime, daemon native-browser thread-tool runs infer attached-CDP session mode when explicit CDP endpoints are supplied, unbrokered controlled-relaunch requests fail closed with explicit recovery guidance, brokered controlled-relaunch manifests acquire pending handoff leases with operator-visible resume/cleanup evidence before browser authority is used, approved controlled-relaunch runs now launch isolated temporary Chromium profiles with deterministic launch and cleanup receipts, and approved visual GUI actions now require preflight screenshot drift evidence before dispatch; external hosted provider launchers remain deferred to their lane-specific adapter slices |
| Affordance/action proposal pipeline | Done / regression guarded: target index, affordance graph, policy-gated `ActionProposal`, deterministic `PolicyDecisionReceipt`, grounded `ComputerAction`, and `ActionReceipt` are SDK/daemon trace-visible; daemon thread-tool invocation of `ioi.computer_use.native_browser` now emits the full read-only proposal-to-action-receipt loop through canonical runtime events, while requested mutating action kinds emit proposal, policy decision, verification, commit-gate, handoff, trajectory, and cleanup evidence without action execution before approval, then either emit approval-bound `ComputerAction`, CDP-backed `ActionReceipt`, passed verification, completed commit-gate evidence, and post-action observation data when an explicit approval ref plus CDP endpoint/websocket is supplied, or fail closed with blocked policy/verification/commit-gate evidence when no adapter is available; the native browser driver/RuntimeAgentService bridge now projects the top affordance into a non-executing `ActionProposal` plus `CommitGate`, and maps real `browser__*` tool results into `ComputerAction`, `ActionReceipt`, and `ComputerUseVerificationReceipt` rows before daemon persistence, with daemon synthesis retained for older bridge event streams |
| Recovery, handoff, and commit gates | Done / regression guarded for computer-use scope, with future-plus policy-platform deferral: SDK contracts and helpers now generate fail-closed `RecoveryPolicy`, credential-safe `HumanHandoffState`, bounded `OutcomeContract`, external-effect `CommitGate`, and retention checks; SDK, daemon, saved workflow runs, and React Flow run history now expose `computer_use.commit_gate` with outcome and commit-gate evidence; daemon native-browser runs now include deterministic policy decision receipts for read-only, confirmation-required, approved, and adapter-unavailable proposals, and Autopilot exposes those receipts through a policy inspector with decision ref, outcome, authority scope, approval ref, external-effect posture, and fail-closed status; RuntimeAgentService bridge-derived proposals now synthesize proposal-only outcome/commit gates that require confirmation for possible external effects while keeping action execution null, approved CDP-backed native-browser thread-tool/workflow runs now clear handoff state and complete the commit gate with approval plus executor evidence, and approved runs without an adapter fail closed with blocked policy/commit-gate evidence; broader cross-domain policy execution is deferred to the policy-platform leg |
| Native browser parity | Done / regression guarded: owned browser artifacts now project into canonical observation bundles, target indexes, affordance graphs, action proposals, commit gates, action receipts, and verification receipts; SDK-local plus daemon-backed runs can ingest either those canonical contracts or native `BrowserObservationArtifacts` from a mounted executor; RuntimeAgentService bridge turns now emit canonical observation, affordance, proposal, commit-gate, action-executed, and verification events from recent native browser driver artifacts plus browser tool results, and daemon run records persist them into inspection plus `computer-use-trace.json`; daemon/SDK/CLI/TUI browser discovery now emits read-only, redacted process/CDP inventory receipts through both the discovery endpoint and canonical thread-tool spine; the native-browser thread tool now produces read-only executable traces, mutating proposal-only traces, CDP-backed approved click/navigate/type_text/key_press/upload action traces, explicit CDP scroll traces, attached-CDP session receipts, unbrokered controlled-relaunch fail-closed traces, brokered controlled-relaunch pending-handoff lease traces, approved controlled-relaunch process/CDP execution traces with isolated temporary profile cleanup, and approved-without-adapter fail-closed traces from the same runtime spine, with CLI `--action-kind`/`--approval-ref`/`--session-mode controlled_relaunch` launch flags, TUI action-prefix/approval/ref/relaunch parsing, React Flow composer metadata, Autopilot launch workbench evidence, and saved workflow projection covered by regression tests |
| Visual GUI parity | Done / regression guarded for observation broker, local observation, local screen capture, approved local action execution, mounted-contract, and fail-closed behavior, with narrow external deferral: unavailable requests fail closed with recovery policy evidence unless a mounted executor supplies canonical observation/target/affordance contracts, the caller supplies local screenshot/SoM/AX observation refs/files, asks the read-only daemon capture adapter to capture the current screen, or the caller first brokers those files/captures through `ioi.computer_use.visual_gui.observe`. The observe broker forces read-only inspect authority, strips coordinate-action scope, retains supplied files or local captures as governed artifacts without leaking source paths, and returns canonical observation, target-index, affordance, cleanup, retained-evidence, local-capture, and observation-broker receipts that can feed a later `ioi.computer_use.visual_gui` run. Local refs, retained files, and captured screens are compiled into canonical `ObservationBundle`, `TargetIndex`, `AffordanceGraph`, adapter contract, read-only `ComputerAction`, verification, cleanup, retained-evidence refs, and trace artifacts; approved visual GUI action runs can opt into the local executor, which requires an approval ref, observation-bound target bounds, original screenshot artifact, preflight screenshot drift check, provider execution receipt, and reobserve-after-action evidence before any local input dispatch. React Flow exposes Visual Observation as an advanced primitive with capture intent fields and the Computer Use visual lane exposes opt-in local GUI executor config; CLI/TUI expose `visual-gui-observe --capture-screen` plus `visual-gui --local-gui-executor --local-gui-executor-provider auto|fixture`. Platform-specific provider availability remains fail-closed, and hosted/remote visual adapters remain deferred until their authority and cleanup policies are productized |
| Sandboxed/hosted parity | Done / regression guarded for deterministic local fixture, mounted-contract, and fail-closed behavior, with narrow external deferral: unavailable requests fail closed with recovery policy evidence unless a mounted executor supplies canonical observation/target contracts or the caller opts into the local fixture provider, in which case SDK, daemon thread-tool, coding-tool lease handoff, React Flow Sandboxed Computer presets, and saved workflow runs activate the hosted lane and preserve the same trace spine. Local fixture runs emit adapter-contract, observation, target-index, affordance, action, verification, trajectory, cleanup, and `local_sandbox_fixture` contract-ingest evidence without becoming a second runtime; mounted hosted adapter contracts and cleanup receipts are still preserved in trace/result artifacts. Concrete VM/container/mobile hosted provider adapters remain deferred until provider credentials, isolation, authority, and retention policy are available |
| Trajectory replay | Done / regression guarded: `ComputerUseTrajectoryBundle` is emitted as trace data; RuntimeAgentService bridge computer-use traces synthesize deterministic event-level trajectory entries when the bridge emits observation/affordance events without a full trajectory bundle; daemon API and SDK expose direct computer-use trace/trajectory readers so consumers do not need artifact-name coupling; SDK `computerUseTrajectoryEval()` now scores passed, human-boundary, fail-closed, failed, and incomplete traces with failure class/mode and regression-gate evidence |
| Trajectory-driven harness improvement | Done / regression guarded for deterministic replay evidence, with narrow external deferral: SDK and Run helpers now turn trajectory evals into deterministic harness improvement plans with recovery policy, patch proposal records, shadow replay requirements, promotion-gate receipts, residual risks, and no hidden benchmark shortcuts; SDK shadow replay now evaluates replay cases plus held-out cases against comparison gates, hidden-shortcut posture, scores, and promotion status. External held-out task execution is deferred to provider-backed eval adapters |
| Model action adapters | Done / regression guarded for adapter contracts: SDK model-action adapter fixtures normalize OpenAI-style CUA outputs, UI-TARS coordinate strings, and generic VLM action records into IOI `ActionProposal` plus grounded `ComputerAction` objects with policy decision refs, safety-check mapping, and observation-bound coordinates; mounted model routes remain runtime inputs and do not become separate action runtimes |
| Co-op coding agent computer use | Done / regression guarded for lease/control contracts, with narrow external deferral: coding agents can now invoke `computer_use.request_lease` through the governed coding-tool pack to record deterministic computer-use lease request manifests with lane/session/action, repo authority, shared clipboard/artifact policy, approval-before-execution evidence, and a canonical thread-tool handoff shape without silently seizing browser/GUI authority; sandboxed-hosted lease requests can hand off to `ioi.computer_use.sandboxed_hosted` using the deterministic local fixture provider for executable glass-box traces, while non-fixture hosted providers still fail closed until mounted; CLI/TUI operators can now emit `ioi.computer_use.control` pause/resume/abort/cleanup receipts against those leases without bypassing runtime truth; approved local visual GUI execution is available only through the observation-bound executor path, while concrete external sandbox/hosted execution remains deferred to provider-backed adapter deferrals |
| Benchmark/eval harness | Done / regression guarded for deterministic exports and aggregation, with narrow external deferral: SDK and Run helpers now export deterministic redacted computer-use benchmark cases from trace, trajectory eval, improvement plan, promotion gate, evidence refs, and regression gates, with raw artifacts excluded unless a local-private export explicitly asks for them; SDK benchmark suites now aggregate exported cases into deterministic pass/fail-closed/failure counts, average score, regression gates, promotion blockers, raw-artifact posture, and scorecard rates without hidden runtime shortcuts. The Autopilot proof harness now emits a retained tri-lane computer-use scorecard across native browser, visual GUI, and sandboxed-hosted local fixture proofs, with operator-readable lane rows, proof artifact paths, blocker rows, external deferrals, a retained markdown summary artifact, Workflows run-inspector rendering for validation payloads, and gates for lane coverage, prompt traces where model nodes are composed, runtime trace rows, target/affordance/proposal/policy/action/verification/cleanup evidence, approval/fail-closed posture, and no React Flow shadow truth; negative enforcement tests prove each of those required evidence classes blocks promotion when removed or failed. External OSWorld/ScreenSpot-style adapters, concrete hosted providers, and hosted scorecard ingestion are deferred until those eval/providers are selected |
| Autopilot glass-box workbench | Done / regression guarded for retained evidence, with narrow privacy deferral: canonical runtime payloads, `computer-use-trace.json` artifacts, workflow/run-history projection, compact trace rows, and a dedicated computer-use workbench now expose harness lane, lease, controlled-relaunch launch evidence, screenshot/SoM refs, coordinate space, target overlay summaries, proposal, action execution state, verification, outcome, commit gate, handoff, cleanup, policy decision, blocker, and recovery evidence; authored single-node computer-use runs now expand into step-addressed trace rows so observation, affordance, proposal, action, verification, trajectory, and cleanup evidence remain visible together; native-browser and visual-GUI prompt pipeline proofs now show mounted model prompt traces crossing into Browser Use or Visual Observation plus Computer Use environment, observation, affordance, proposal, commit, action, verification, trajectory, and cleanup rows; runtime bridge affordance projections now emit source-side live proposal and commit-gate events for the stream, the UI distinguishes gated proposal-only steps from executed actions, the workbench renders URL/data screenshot refs plus SVG target boxes when bounds are available, and opaque retained evidence refs now project governed run-artifact fetch paths resolved by artifact id, name, or `artifact:` ref; non-retained private screenshot binary preview is intentionally deferred behind explicit retention policy and user consent |
| Workflow compositor projection | Done / regression guarded: React Flow runtime projection maps `computer_use.*` events into glass-box harness nodes with lane/session/lease, observation/target/affordance, browser discovery, sandbox fixture provider evidence, proposal/action, verification, outcome, commit-gate, handoff, cleanup, control, and recovery evidence; palette creator presets now expose Browser Use, Computer Use, and Sandboxed Computer lanes without a second runtime, with Browser Discovery and Visual Observation available in the advanced palette as read-only primitives whose saved/direct runs emit canonical runtime receipts before attach/relaunch or coordinate authority is requested. Sandboxed Computer defaults to `local_sandbox` plus the deterministic `local_fixture` provider so authors can run a hosted-style computer-use trace locally; composer Run forwards the configured lane/session/action-kind/approval-ref/retention plus target/selector/text/CDP endpoint metadata, visual screenshot/SoM/AX observation refs, local-capture intent metadata, opt-in local GUI executor metadata, and sandbox provider/fixture/image/task metadata into the daemon request. Dedicated GUI proofs now verify sandboxed-computer Run-button wiring, a native-browser mounted-model prompt pipeline, and a visual-GUI mounted-model prompt pipeline that composes Visual Observation into Computer Use, and the retained tri-lane scorecard promotes them as one gate covering composer metadata forwarding, local-fixture/native-browser/visual runtime event projection, model trace visibility, model-to-browser/model-to-visual handoff, screenshot/SoM/AX target overlay evidence, policy/approval/verification/cleanup workbench fields, explicit external deferrals, and no React Flow shadow runtime truth. Saved workflow runs and direct SDK/CLI/TUI thread-tool invocation compile Browser/Computer Use tool bindings into canonical runtime-thread traces, including read-only executable, mutating proposal-only, CDP-backed approved, approved-without-adapter fail-closed `ioi.computer_use.native_browser` loops, deterministic local-fixture `ioi.computer_use.sandboxed_hosted` loops, observation-broker `ioi.computer_use.visual_gui.observe` loops with supplied files or read-only local screen capture, local-observation and approved local-executor `ioi.computer_use.visual_gui` loops, and governed `ioi.computer_use.control` pause/resume/abort/cleanup receipts; CLI `agent tools native-browser --action-kind ... --approval-ref ... --selector ... --text ... --cdp-endpoint-url ...`, `agent tools sandboxed-computer --action-kind inspect --sandbox-provider local_fixture --sandbox-image-ref ... --sandbox-task-ref ...`, `agent tools visual-gui-observe --capture-screen --capture-app-name ... --capture-window-title ...` or `--screenshot-path ... --som-path ... --ax-path ...`, `agent tools visual-gui --action-kind click --approval-ref ... --target-ref ... --local-gui-executor --local-gui-executor-provider auto --screenshot-ref ... --som-ref ... --ax-ref ...` or `--screenshot-path ... --som-path ... --ax-path ...`, plus `agent tools computer-use-control --action ... --lease-id ...`, and TUI `/native-browser`, `/sandboxed-computer`, `/visual-gui-observe`, `/visual-gui`, plus `/computer-use pause|resume|abort|cleanup --lease-id ...`, expose those same loops as operator commands; SDK thread streams expose typed `computer_use_*` events, and SDK/daemon/workflow events preserve authored workflow node ids/tool refs/authority scopes for glass-box trace alignment |
| Safety/governance receipts | Done / regression guarded for computer-use scope, with future-plus policy-platform deferral: `computer_use_trace`, failed-closed leases, recovery policy payloads, deterministic proposal policy decision receipts, action, verification, trajectory, control, handoff, and cleanup receipts are projected; broader cross-domain policy execution is deferred to the policy-platform leg |

## Definition Of Done

CUA parity-plus is complete when:

- native browser, visual GUI, and sandboxed/hosted computer-use lanes share the
  same runtime contracts;
- the runtime loop can choose environment, observe, build affordances, propose
  actions, gate risk, execute, verify, repair, hand off, commit, retain
  evidence, and clean up;
- every material action is grounded, receipted, verified, and replayable;
- Autopilot exposes a trajectory/workbench view comparable in clarity to CUA's
  trajectory viewer but richer in runtime receipts and policy state;
- model-specific computer-use outputs are adapters into IOI action proposals
  and approved IOI actions;
- workflows can compose computer-use runs without shadow runtime truth;
- sandbox/hosted providers are available through fail-closed adapters;
- benchmark and trajectory exports support regression and meta-harness work;
- safety rules around credentials, private screenshots, profiles, destructive
  actions, and cleanup are enforced by policy and visible in receipts.
