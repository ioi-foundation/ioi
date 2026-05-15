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

- coding-agent computer-use lease request;
- sandbox/browser/device selection policy;
- shared clipboard and artifact policy;
- repo/worktree authority scope;
- run history and evidence projection in Autopilot;
- CLI/TUI controls for pause, resume, abort, and cleanup.

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
9. Add sandbox/hosted adapter skeleton with fail-closed behavior.
10. Add workflow compositor primitives and advanced nodes.
11. Add benchmark/eval adapters and retained regression fixtures.
12. Validate end-to-end through browser, visual GUI, and sandbox-unavailable
    lanes.

## Completion Dashboard

| Area | Target status |
| --- | --- |
| Contract spine | Done / regression guarded |
| Behavioral control loop | Started: SDK and daemon lifecycle projection emit select, acquire, observe, affordance, propose, execute, verify, trajectory, and cleanup steps with workflow node ids; RuntimeAgentService bridge traces now carry proposal, commit-gate, executed-action, and verification evidence directly from native browser affordances and browser tool results, then synthesize live `ComputerUseRunState` from that evidence; daemon thread-tool runs now execute approved native-browser click/navigate/type_text/key_press/upload actions plus explicit scroll through CDP when an adapter endpoint is available and fail closed when it is not |
| Environment planner | Started: `EnvironmentSelectionReceipt` is SDK/daemon trace-visible, explicit visual/sandbox requests fail closed, RuntimeAgentService bridge observations now infer lane/session/lease projection data without selecting a second runtime, daemon native-browser thread-tool runs infer attached-CDP session mode when explicit CDP endpoints are supplied, and unbrokered controlled-relaunch requests fail closed with explicit recovery guidance; controlled relaunch lease orchestration pending |
| Affordance/action proposal pipeline | Started: target index, affordance graph, policy-gated `ActionProposal`, deterministic `PolicyDecisionReceipt`, grounded `ComputerAction`, and `ActionReceipt` are SDK/daemon trace-visible; daemon thread-tool invocation of `ioi.computer_use.native_browser` now emits the full read-only proposal-to-action-receipt loop through canonical runtime events, while requested mutating action kinds emit proposal, policy decision, verification, commit-gate, handoff, trajectory, and cleanup evidence without action execution before approval, then either emit approval-bound `ComputerAction`, CDP-backed `ActionReceipt`, passed verification, completed commit-gate evidence, and post-action observation data when an explicit approval ref plus CDP endpoint/websocket is supplied, or fail closed with blocked policy/verification/commit-gate evidence when no adapter is available; the native browser driver/RuntimeAgentService bridge now projects the top affordance into a non-executing `ActionProposal` plus `CommitGate`, and maps real `browser__*` tool results into `ComputerAction`, `ActionReceipt`, and `ComputerUseVerificationReceipt` rows before daemon persistence, with daemon synthesis retained for older bridge event streams |
| Recovery, handoff, and commit gates | Started: SDK contracts and helpers now generate fail-closed `RecoveryPolicy`, credential-safe `HumanHandoffState`, bounded `OutcomeContract`, external-effect `CommitGate`, and retention checks; SDK, daemon, saved workflow runs, and React Flow run history now expose `computer_use.commit_gate` with outcome and commit-gate evidence; daemon native-browser runs now include deterministic policy decision receipts for read-only, confirmation-required, approved, and adapter-unavailable proposals; RuntimeAgentService bridge-derived proposals now synthesize proposal-only outcome/commit gates that require confirmation for possible external effects while keeping action execution null, approved CDP-backed native-browser thread-tool/workflow runs now clear handoff state and complete the commit gate with approval plus executor evidence, and approved runs without an adapter fail closed with blocked policy/commit-gate evidence; broader policy executor pending |
| Native browser parity | Started: owned browser artifacts now project into canonical observation bundles, target indexes, affordance graphs, action proposals, commit gates, action receipts, and verification receipts; SDK-local plus daemon-backed runs can ingest either those canonical contracts or native `BrowserObservationArtifacts` from a mounted executor; RuntimeAgentService bridge turns now emit canonical observation, affordance, proposal, commit-gate, action-executed, and verification events from recent native browser driver artifacts plus browser tool results, and daemon run records persist them into inspection plus `computer-use-trace.json`; daemon/SDK/CLI/TUI browser discovery now emits read-only, redacted process/CDP inventory receipts through both the discovery endpoint and canonical thread-tool spine; the native-browser thread tool now produces read-only executable traces, mutating proposal-only traces, CDP-backed approved click/navigate/type_text/key_press/upload action traces, explicit CDP scroll traces, attached-CDP session receipts, controlled-relaunch fail-closed traces, and approved-without-adapter fail-closed traces from the same runtime spine, with CLI `--action-kind`/`--approval-ref`, TUI action-prefix/approval-ref parsing, React Flow composer metadata, and saved workflow projection covered by regression tests; controlled relaunch lease orchestration remains pending |
| Visual GUI parity | Started: unavailable requests fail closed with recovery policy evidence unless a mounted executor supplies canonical observation/target/affordance contracts, in which case daemon-backed runs activate the visual lane and preserve the same trace spine; mounted GUI adapter contracts and cleanup receipts are now preserved in trace/result artifacts; concrete local GUI adapter pending |
| Sandboxed/hosted parity | Started: unavailable requests fail closed with recovery policy evidence unless a mounted executor supplies canonical observation/target contracts, in which case daemon-backed runs activate the hosted lane and preserve the same trace spine; mounted hosted adapter contracts and cleanup receipts are now preserved in trace/result artifacts; concrete hosted adapter pending |
| Trajectory replay | Started: `ComputerUseTrajectoryBundle` is emitted as trace data; RuntimeAgentService bridge computer-use traces synthesize deterministic event-level trajectory entries when the bridge emits observation/affordance events without a full trajectory bundle; daemon API and SDK expose direct computer-use trace/trajectory readers so consumers do not need artifact-name coupling; SDK `computerUseTrajectoryEval()` now scores passed, human-boundary, fail-closed, failed, and incomplete traces with failure class/mode and regression-gate evidence |
| Trajectory-driven harness improvement | Not started |
| Model action adapters | Started: SDK model-action adapter fixtures normalize OpenAI-style CUA outputs, UI-TARS coordinate strings, and generic VLM action records into IOI `ActionProposal` plus grounded `ComputerAction` objects with policy decision refs, safety-check mapping, and observation-bound coordinates |
| Co-op coding agent computer use | Not started |
| Benchmark/eval harness | Not started |
| Autopilot glass-box workbench | Started: canonical runtime payloads, `computer-use-trace.json` artifacts, workflow/run-history projection, compact trace rows, and a dedicated computer-use workbench now expose harness lane, lease, screenshot/SoM refs, coordinate space, target overlay summaries, proposal, action execution state, verification, outcome, commit gate, handoff, cleanup, blocker, and recovery evidence; runtime bridge affordance projections now emit source-side live proposal and commit-gate events for the stream, the UI distinguishes gated proposal-only steps from executed actions, and the workbench renders URL/data screenshot refs plus SVG target boxes when bounds are available; artifact fetch/preview for opaque local evidence refs pending |
| Workflow compositor projection | Started: React Flow runtime projection maps `computer_use.*` events into glass-box harness nodes with lane/session/lease, observation/target/affordance, browser discovery, proposal/action, verification, outcome, commit-gate, handoff, cleanup, and recovery evidence; palette creator presets now expose Browser Use, Computer Use, and Sandboxed Computer lanes without a second runtime, with Browser Discovery available in the advanced palette as a read-only process/CDP inventory primitive whose saved workflow run emits `computer_use.browser_discovery` receipts; composer Run forwards the configured lane/session/action-kind/approval-ref/retention plus target/selector/text/CDP endpoint metadata into the daemon request, saved workflow runs and direct SDK/CLI/TUI thread-tool invocation compile Browser/Computer Use tool bindings into canonical runtime-thread traces, including read-only executable, mutating proposal-only, CDP-backed approved, and approved-without-adapter fail-closed `ioi.computer_use.native_browser` loops; CLI `agent tools native-browser --action-kind ... --approval-ref ... --selector ... --text ... --cdp-endpoint-url ...` and TUI `/native-browser <action> ... --approval-ref ... --selector ... --text ... --cdp-endpoint-url ...` expose that same loop as operator commands, SDK thread streams expose typed `computer_use_*` events, and SDK/daemon/workflow events preserve authored workflow node ids/tool refs/authority scopes for glass-box trace alignment |
| Safety/governance receipts | Started: `computer_use_trace`, failed-closed leases, recovery policy payloads, deterministic proposal policy decision receipts, action, verification, trajectory, and cleanup receipts are projected; broader policy executor pending |

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
