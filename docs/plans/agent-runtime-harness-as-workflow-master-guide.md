# Agent Runtime Harness-As-Workflow Master Guide

Last updated: 2026-05-09
Owner: agent runtime / workflow substrate / Autopilot GUI
Status: next-leg master guide

Companion documents:

- `docs/roadmap.md`
- `docs/plans/autopilot-canvas-runtime-unification-plan.md`
- `docs/plans/meta-harness-master-guide.md`
- `docs/specs/runtime/cursor-sdk-harness-parity-plus-master-guide.md`
- `docs/specs/runtime/harness-change-workflow.md`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-07T12-03-49-923Z/result.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T09-29-56-082Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T09-36-18-437Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T09-51-41-976Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T09-58-25-386Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T10-16-37-486Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T10-23-24-073Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T11-36-07-284Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T11-42-45-444Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T12-22-46-391Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T12-28-29-887Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T13-02-20-661Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T13-08-12-127Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T13-36-28-167Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T13-46-51-381Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T14-18-42-111Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T14-26-30-948Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T15-56-37-565Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T16-03-01-399Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T16-22-36-710Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T16-30-23-659Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T16-55-16-241Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T17-01-20-170Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T17-41-29-444Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T17-47-23-121Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T18-12-02-920Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T18-18-59-682Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T18-37-02-352Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T18-43-28-818Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T19-29-45-194Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T19-36-51-457Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T19-54-02-426Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T20-00-06-942Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T20-27-59-060Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T20-34-19-262Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-09T00-32-20-635Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-09T00-40-30-002Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-09T01-19-51-435Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-09T01-26-16-362Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-09T03-45-10-002Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-09T03-51-29-908Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-09T04-11-07-040Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-09T04-17-19-806Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-09T11-45-40-808Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-09T11-51-57-558Z/dashboard-index.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-09T12-12-40-027Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-09T12-19-21-195Z/dashboard-index.json`
- `docs/evidence/harness-as-workflow-aip-reference/2026-05-06/README.md`

## Executive Verdict

The next leg should be the transition from "the runtime harness is projected
into workflow-shaped components" to "the default live agent runtime is actually
driven by those workflow-addressable components."

Chronologically, this means:

1. Finish componentizing the runtime harness around explicit action frames,
   schemas, policies, receipt bindings, replay envelopes, and UI surfaces.
2. Run the workflow projection in shadow against the live `RuntimeAgentService`
   path until every major runtime decision can be correlated to a graph node.
3. Promote the blessed `Default Agent Harness` workflow from inspectable
   projection to the default runtime orchestration surface.
4. Let users fork the harness only after activation gates prove bindings,
   replay fixtures, tests, slots, policy posture, and receipt mapping are safe.

The focus is not just architectural neatness. The focus is proving one unified
substrate by dogfooding the real agent harness through the same workflow graph
model that users can inspect, test, package, propose changes to, and eventually
fork.

## Strategic Thesis

The roadmap already says the workflow canvas has strong bones and the agent
runtime is the part that must be componentized next. The key line is the
roadmap's current architecture read:

> `RuntimeAgentService` owns session lifecycle, step/resume, pending action
> state, approvals, PII, execution queue, transcript continuity, worker
> templates, and playbooks.

The implication is correct: componentize the harness before expanding
persistent agents, the model router, markets, or long-lived worker autonomy.

The product reason is equally important. A workflow-backed harness gives users
an inspectable mental model for why an agent planned, routed, asked approval,
called a tool, retried, repaired, verified, or stopped. It also creates a real
dogfood loop: the default agent that edits workflows should itself be running
through a workflow-backed harness.

## Latest Validated Checkpoint

As of 2026-05-09, the default live harness activation-id gate, runtime selector
readiness gate, live handoff, default runtime dispatch proof, durable worker
binding authority proof, worker binding registry proof, worker attach lifecycle
timeline, worker session record, runtime-checkpoint worker session
persistence, persisted worker-session launch authority, typed worker
launch/resume/rollback envelopes, durable worker handoff receipts, worker
launch reviewed-import activation invariant binding, rollback handoff
authority, worker handoff node timeline/replay fixture binding, gated
verification/output adapter proof, gated authority/tooling adapter proof, fork
activation handoff timeline proof, fork handoff deep-link proof,
canary/rollback route-state proof, fork package evidence manifest proof,
package evidence activation gate proof, and live package-evidence click-through
proof, package evidence export/import round-trip proof, and user-facing import
review mode proof, live-turn node inspector proof, live-turn node inspector
deep-link restoration proof, and live-vs-shadow comparison deep-link proof have
a green end-to-end checkpoint:

- Full retained Autopilot GUI harness run:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-09T06-00-43-156Z/result.json`
- Runtime P3 validation with required GUI evidence:
  `docs/evidence/agent-runtime-p3-validation/2026-05-09T06-06-54-656Z/dashboard-index.json`

This checkpoint proves the GUI promotion flow can show the activation-id gate,
the fork activation click proof, the selector-owned live-promotion readiness
gate, the default runtime dispatch binding, worker binding authority posture,
worker binding registry status, live handoff, route-stateful deep links,
activation audit links, rollback restore actions, and runtime evidence in one
retained-query evidence bundle. It also proves the blessed default dispatch is
bound to `activation:default-agent-harness:blessed-readonly`, the active worker
binding matches the selector/default-dispatch proof ids and rollback target,
the registry record is bound with no blockers and a matching readiness proof
id, the worker attach/resume/rollback lifecycle is complete, the worker session
record is accepted and `rollback_ready`, that worker session record is visible
with runtime checkpoint keys, `persistedInRuntimeCheckpoint: true`,
`restoredFromPersistedSession: true`, no persistence blockers,
`launchAuthorityReady: true`, `launchAuthoritySource` set to
`persisted_harness_worker_session_record`, empty launch-authority blockers,
`rollbackHandoffReady: true`, empty rollback-handoff blockers, and a rollback
handoff target matching the activation rollback target. It additionally proves
three accepted `workflow.harness.worker-launch-envelope.v1` records for
`launch`, `resume`, and `rollback`, three accepted
`workflow.harness.worker-handoff-receipt.v1` records with handoff statuses
`launched`, `resumed`, and `rollback_handoff_ready`, GUI rail attributes for
launch envelope and handoff receipt counts, and a live GUI check
`workerLaunchHandoffBound: true`. It also proves worker handoff node attempts
and replay fixtures are bound into the dispatch timeline with
`workerHandoffNodeTimelineBound: true`, so launch, resume, and rollback
handoff can be inspected as first-class workflow node attempts. Normal live
agent turns now also produce a retained live-turn node inspector proof:
`harness_live_turn_node_inspector_present: true` and
`harnessLiveTurnNodeInspectorCount: 1` for `retained_harness_dogfooding`. The
sample binds a live `planner` attempt to its workflow node id, action frame,
receipt ref, replay fixture ref, policy decision, input/output hashes, runtime
authority, activation id, harness hash, `workflow-harness-node-attempt-inspector`,
`workflow-selected-node-harness-attempt`, `workflow-run-harness-timeline`, and
the `nodeAttemptId` deep-link parameter. The GUI promotion proof now also
restores that live attempt through
`#harness-workbench?panel=outputs&nodeAttemptId=...`, opens
`workflow-harness-node-attempt-inspector`, and reads back
`data-node-attempt-source-kind=default_runtime_dispatch`, live mode,
`live_ready`, receipt refs, replay fixture ref, policy decision, activation id,
harness hash, input hash, and output hash. Runtime consistency now requires
`harness_live_turn_node_inspector_deep_link_present: true`. The GUI promotion
proof also restores a live-vs-shadow comparison through the same
`nodeAttemptId` route, opens
`workflow-harness-live-shadow-comparison-inspector`, and reads back the live
attempt id, shadow attempt id, workflow node id, `planner` component kind,
`divergence=none`, `blocking=false`, live and shadow receipt refs, live and
shadow replay fixture refs, and matching input/output hashes. Runtime
consistency now also requires `harness_live_shadow_comparison_present: true`.
Normal retained live runtime artifacts now also emit the same comparison
directly from the Rust/orchestrator default dispatch path:
`harnessLiveShadowComparisonCount: 6` for `retained_harness_dogfooding`, with
runtime `planner`, `prompt_assembler`, and `task_state` live attempts and
`model_router`, `model_call`, and `tool_router` gated attempts paired to their
shadow attempts, distinct live/shadow receipt refs, distinct live/shadow
replay fixture refs, and matching input/output hashes. Runtime consistency now
treats `harness_live_shadow_comparison_present` as a cognition plus
routing/model coverage gate, not a single-sample existence check. It further
proves
the fork activation wizard uses the same substrate:
`harnessForkHandoffTimelineBoundCount: 3` and
`harness_fork_handoff_timeline_present: true`, with validated fork activation
carrying a worker session, launch envelopes, handoff receipts, gated
`handoff_bridge` node attempts, replay refs, and rollback target. The fork
activation wizard can also deep-link from its `worker-handoff` gate to the
exact node attempt, handoff receipt, replay fixture, and timeline row that
prove the canary worker handoff. Canary boundaries and rollback drills are
also route-stateful: the GUI can restore the selected canary boundary,
rollback drill, and rollback-restore canary receipt directly from
`#harness-workbench` links. Package/export integrity is now part of the same
evidence contract: fork bundles carry
`workflow.harness.package-evidence-manifest.v1`, receipt refs, replay fixture
refs, rollback-restore refs, worker handoff node attempts, and route-restorable
deep links in `harness-package-evidence.json`; the retained GUI evidence marks
`hasHarnessPackageEvidenceManifest: true`,
`harness_package_evidence_gate_present: true`, and
`harness_package_evidence_gate_click_proof_present: true`. The package-evidence
activation gate now restores in the right rail, shows manifest/category rows,
and deep-links to preserved receipt, replay, worker handoff, and package proof
refs. The GUI proof also exports a validated fork package, imports it into a
fresh root, verifies the imported package-evidence gate remains ready, then
loads an intentionally incomplete imported package state and proves actionable
missing rows plus `harness_package_manifest_incomplete`. Imported packages now
open into a source/import package review surface, return the portable manifest
from the Tauri import API, and expose activation only when package evidence is
green; the retained GUI evidence marks
`harness_package_import_review_mode_present: true`. Reviewed imports also show a
first-class activation handoff with preserved activation id, canary, rollback,
and worker binding routes; the retained GUI evidence marks
`harness_package_import_activation_handoff_present: true`. The retained GUI
proof now commits the reviewed import activation through the real
`Activate reviewed import` button and marks
`harness_package_import_activation_apply_present: true`. That proof is now a
hard default-live promotion invariant: `validateAutopilotGuiHarnessResult`
rejects any claimed passing GUI bundle unless the embedded activation apply
proof shows the click, minted activation id, validated workflow state, worker
binding, rollback/revision binding, audit, refs, and worker-handoff deep-link
restoration.
That invariant is now consumed by the runtime selector, live handoff, and
default runtime dispatch proof as `reviewed_import_activation_apply`; the
selector falls back to canary/legacy if the proof is missing, stale, or blocked,
and the dispatch proof exposes a
`reviewedImportActivationApplyGate` with activation id, worker binding id,
rollback target, proof blockers, and default-dispatch blockers.

### 2026-05-08 Cognition Live Adapter Slice

The current implementation has started the first true component-promotion
slice inside the default dispatch path:

- Rust now treats `planner`, `prompt_assembler`, and `task_state` as
  `live_ready` canonical harness components.
- The shared adapter can invoke those components in `live` mode and still
  blocks later clusters that remain `shadow_ready`.
- The Autopilot default runtime dispatch proof now records
  `cognitionExecutionAdapterMode: workflow_component_adapter_live`,
  canonical adapter results, action frame ids, live-ready component kinds, and
  live node attempts for the cognition triplet.
- The TypeScript harness projection mirrors that readiness split so the GUI
  workbench and runtime proof cannot drift from Rust.
- Focused validation is green for the Rust harness contract, service adapter,
  Autopilot default dispatch store test, TS type check, harness contract
  consistency, shell wiring, and `test:autopilot-gui-harness`.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T09-12-40-928Z/`,
  with the copied workflow proof showing three live cognition adapter results
  and `planner`, `prompt_assembler`, and `task_state` as live-ready.

This is not the full target end state yet. It is the first production-shaped
promotion wedge: the cognition envelope still uses the existing workflow node
executor for the actual envelope execution, but its authority proof now flows
through the canonical harness adapter result instead of only hand-assembled
attempt ids.

### 2026-05-08 Cognition Gate Adapter Slice

The second cognition slice extends the same proof pattern across the remaining
cognition cluster without prematurely promoting those gates to live authority:

- `uncertainty_gate`, `budget_gate`, and `capability_sequencer` now execute as
  staged workflow envelopes during default dispatch proof generation.
- Their canonical adapter invocations run in `gated` mode, keep
  `shadow_ready` readiness, emit node attempts, action frames, receipt refs,
  replay fixture refs, and divergence classifications.
- The default dispatch proof now distinguishes live cognition authority
  (`planner`, `prompt_assembler`, `task_state`) from staged cognition gates
  (`uncertainty_gate`, `budget_gate`, `capability_sequencer`).
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T09-29-56-082Z/`;
  the copied workflow proof shows three live adapter results, three gated
  adapter results, and `gateDivergenceClasses: ["none"]`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T09-36-18-437Z/dashboard-index.json`.

This completes the cognition cluster proof shape while preserving the staged
promotion discipline: only the cognition authority triplet is live-ready; the
uncertainty, budget, and capability gates are proven through gated adapter
records until shadow/gated divergence criteria justify live promotion.

### 2026-05-08 Routing-Model Gate Adapter Slice

The next slice applies the same canonical adapter proof shape to the
`routing_model` cluster:

- `model_router`, `model_call`, and `tool_router` now run as staged default
  dispatch workflow envelopes in `gated` mode.
- Their canonical adapter invocations remain `shadow_ready`, emit action frame
  ids, typed adapter results, attempt ids, receipt refs, replay fixture refs,
  and divergence classifications.
- The default dispatch proof now exposes `routingModelAdapterMode`,
  `routingModelAdapterResults`, `routingModelComponentKinds`,
  `routingModelAttemptIds`, `routingModelReceiptIds`,
  `routingModelReplayFixtureRefs`, and `routingModelDivergenceClasses`.
- The TypeScript harness projection mirrors those fields, and the GUI/P3
  validators now require all three routing-model components to appear with
  `gated` execution, `shadow_ready` readiness, `gated` node-attempt status, and
  zero divergence.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T09-51-41-976Z/`;
  the copied workflow proof contains `routingModelAdapterMode:
workflow_component_adapter_gated` and component kinds `model_router`,
  `model_call`, and `tool_router`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T09-58-25-386Z/dashboard-index.json`.

This promotes routing/model proof visibility without handing over live model or
tool authority yet. The existing runtime path remains the user-visible authority
while the routing-model cluster accumulates retained-query evidence for later
gated-to-live promotion.

### 2026-05-08 Verification-Output Gate Adapter Slice

The latest slice extends the canonical adapter proof through the end-of-turn
verification/output cluster:

- `postcondition_synthesizer`, `verifier`, `completion_gate`,
  `receipt_writer`, `quality_ledger`, and `output_writer` now run as staged
  default dispatch workflow envelopes in `gated` mode.
- Their canonical adapter invocations remain `shadow_ready` and emit typed
  adapter results, action frame ids, node attempts, receipt refs, replay
  fixture refs, and `none` divergence classifications.
- The default dispatch proof now exposes `verificationOutputAdapterMode`,
  `verificationOutputAdapterResults`, `verificationOutputComponentKinds`,
  `verificationOutputAttemptIds`, `verificationOutputReceiptIds`,
  `verificationOutputReplayFixtureRefs`, `verificationOutputDivergenceClasses`,
  and `verificationOutputProof`.
- The TypeScript harness projection and GUI/P3 validators require all six
  verification/output components to appear with `gated` execution,
  `shadow_ready` readiness, `gated` node-attempt status, durable receipt and
  replay refs, and zero divergence.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T10-16-37-486Z/`;
  the promotion workflow artifact contains `verificationOutputAdapterMode:
workflow_component_adapter_gated`, six adapter results, and
  `verificationOutputProof`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T10-23-24-073Z/dashboard-index.json`.

This completes the staged proof shape for the verification/output cluster while
preserving user-visible runtime authority.

### 2026-05-08 Authority-Tooling Gate Adapter Slice

The authority/tooling cluster now uses the same canonical adapter proof shape
as cognition, routing/model, and verification/output:

- `policy_gate`, `approval_gate`, `dry_run_simulator`, `mcp_provider`,
  `mcp_tool_call`, `tool_call`, `connector_call`, and `wallet_capability` now
  run as staged default dispatch workflow envelopes in `gated` mode.
- Their canonical adapter invocations remain `shadow_ready` and emit typed
  adapter results, action frame ids, node attempts, receipt refs, replay
  fixture refs, and `none` divergence classifications.
- The default dispatch proof now exposes `authorityToolingAdapterMode`,
  `authorityToolingAdapterResults`, `authorityToolingComponentKinds`,
  `authorityToolingAttemptIds`, `authorityToolingReceiptIds`,
  `authorityToolingReplayFixtureRefs`, `authorityToolingDivergenceClasses`, and
  `authorityToolingAdapterProof`.
- The adapter proof uses compact catalog refs between MCP-provider, MCP-tool,
  native-tool, and connector envelopes so the proof remains replayable without
  recursively embedding full prior executor payloads.
- The existing live dry-run and read-only authority canaries remain intact as
  supporting proof for policy gates, destructive denial, approval blocking,
  provider catalog, MCP tool catalog, native tool catalog, connector describe,
  and wallet capability dry-run behavior.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T11-36-07-284Z/`;
  the promotion workflow artifact contains `authorityToolingAdapterMode:
workflow_component_adapter_gated`, eight adapter results, and
  `authorityToolingAdapterProof`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T11-42-45-444Z/dashboard-index.json`.

This completes the P0 staged adapter proof across cognition, routing/model,
verification/output, and authority/tooling.

### 2026-05-08 P0 Live Promotion Readiness Slice

The blessed default harness activation now has one activation-level promotion
readiness proof instead of requiring reviewers to infer readiness from many
separate cluster artifacts:

- Rust canonical harness contracts now include
  `HarnessLivePromotionClusterReadiness` and
  `HarnessLivePromotionReadinessProof`, and the default dispatch proof carries
  `live_promotion_readiness_proof`.
- TypeScript graph/runtime contracts mirror this as
  `WorkflowHarnessLivePromotionReadinessProof` and
  `livePromotionReadinessProof` on
  `WorkflowHarnessDefaultRuntimeDispatchProof`.
- The proof aggregates all four P0 clusters: cognition, routing/model,
  verification/output, and authority/tooling. Each cluster exposes target
  `live` mode, current status, component kinds, attempt ids, receipt refs,
  replay fixture refs, action frame ids, divergence classes, blockers,
  rollback target, and promotion decision.
- The activation-level rollup exposes `allClustersReady`,
  `promotionEligible`, `defaultLiveActivationReady`,
  `invalidForkLiveActivationBlocked`, `rollbackAvailable`, activation blockers,
  and the policy decision
  `allow_default_harness_live_promotion_readiness`.
- The Autopilot GUI now shows a live-promotion readiness badge in the workflow
  header and a right-rail readiness panel with per-cluster status, receipt
  count, replay count, divergence counts, rollback posture, and blocker data.
- The retained GUI validator now requires
  `harness_live_promotion_readiness_present` and a concrete
  `harness_live_promotion_readiness` artifact, tied to both runtime evidence
  and the promotion-transition GUI proof.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T12-22-46-391Z/`;
  the promotion workflow artifact contains `livePromotionReadinessProof` with
  all four clusters ready for live activation.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T12-28-29-887Z/dashboard-index.json`.

This turns "all P0 clusters have gated canonical adapter evidence" into "the
GUI and retained evidence explicitly prove gated-to-live readiness for the full
default harness activation, with rollback and divergence classification attached
to every promoted cluster." The next chronological slice should make that proof
drive the actual activation selector/canary path more directly: the selector
should consume the readiness object as its primary gate input, and invalid fork
live activation should be proven through the same object rather than through
parallel validation counters.

### 2026-05-08 Selector-Gated Live Promotion Readiness Slice

The live-promotion readiness proof now gates the runtime selector instead of
only appearing as default-dispatch evidence:

- Rust canonical harness contracts now attach live-promotion readiness fields
  to `HarnessRuntimeSelectorDecision` and `HarnessLiveHandoffProof`.
- TypeScript graph/runtime contracts mirror those fields on
  `WorkflowHarnessRuntimeSelectorDecision` and
  `WorkflowHarnessLiveHandoffProof`: the proof object, ready boolean, blockers,
  and policy decision.
- `makeHarnessRuntimeSelectorDecision` fails closed: a requested
  `blessed_workflow_live_default` selector falls back to canary unless
  `livePromotionReadinessProof` is present, all four required clusters are
  live-ready, rollback is available, invalid fork live activation is blocked,
  policy allows promotion, and there are no readiness blockers.
- `makeBlessedHarnessLiveHandoffProof` no longer transfers default authority
  unless the same readiness proof passes.
- Autopilot runtime evidence now emits
  `harness_selector_live_promotion_readiness_gated` and requires it for
  `harness_selector_default_promoted`, default dispatch acceptance, live
  handoff transfer, and the retained GUI/P3 validation path.
- The Workflows right rail now shows selector-level live-promotion readiness
  with blocker count, rollback posture, cluster count, and policy decision, so
  reviewers can distinguish "dispatch has a proof" from "the selector consumed
  and enforced the proof."
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T13-02-20-661Z/`;
  runtime consistency includes
  `harness_selector_live_promotion_readiness_gated: true`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T13-08-12-127Z/dashboard-index.json`.

This changes the promotion boundary from "visible validation evidence" to
"runtime selector authority." The next chronological slice should bind the
selector-gated proof to durable activation IDs and rollback/canary state at the
worker binding layer, so a default live worker cannot attach unless the
selector-readiness proof, dispatch proof, activation record, and rollback target
all agree.

### 2026-05-08 Worker-Binding Authority Slice

The selector-gated readiness proof now flows into the durable worker binding
instead of stopping at selector and dispatch validation:

- Rust canonical harness contracts now make `HarnessWorkerBinding` carry the
  selector decision id, default dispatch id, rollback target, authority
  readiness, authority blockers, live-promotion readiness proof id, and policy
  decision.
- The Autopilot runtime projection now fails closed unless the selected default
  activation, production default activation, selector decision, live handoff,
  default dispatch proof, activation record, rollback target, invalid-fork gate,
  and worker binding all agree.
- The top-level runtime `HarnessWorkerBinding` mirrors the default runtime
  binding's worker binding, so runtime projections, chat proof extraction, and
  GUI proof extraction read the same durable authority posture.
- The Workflows right rail now shows whether worker binding authority is ready
  or blocked, the live-promotion proof id, proof-id match posture, selector
  readiness, dispatch readiness, and invalid fork blocking.
- The retained GUI validator now requires `workerBindingAuthorityReady`, empty
  worker binding blockers, matching selector/default-dispatch/proof ids,
  invalid fork live activation blocking, dispatch-driven runtime authority, and
  matching nested worker binding fields before accepting the default runtime
  binding.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T13-36-28-167Z/`;
  runtime consistency includes worker binding authority readiness and proof-id
  agreement across selector, live handoff, dispatch, GUI, and chat proof.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T13-46-51-381Z/dashboard-index.json`.

This changes the promotion boundary from "selector authority can choose live"
to "a live worker cannot present as the blessed default unless its binding
identity, rollback target, selector proof, dispatch proof, and runtime evidence
all agree." The next chronological slice should move this from proof-time
gating into the worker launch/bind registry itself: persistent workers should
bind by workflow id, activation id, activation hash, component-version set,
rollback target, and readiness proof id, with canary and rollback records
checked before accepting any live default worker attachment.

### 2026-05-08 Worker-Binding Registry Slice

The worker binding authority proof now has a persistent registry record that
the runtime, GUI, fork activation records, and validation evidence must agree
on before any default live worker binding is accepted:

- Rust canonical harness contracts now define
  `HarnessWorkerBindingRegistryRecord`, `HarnessWorkerBindingStatus`,
  default/bound registry constructors, and
  `validate_harness_worker_binding_registry_record`.
- The default runtime dispatch proof now carries
  `workerBindingRegistryRecord`, including workflow id, activation id,
  activation hash, harness hash, component version set, rollback target,
  readiness proof id, canary result id, policy decision, binding status,
  blockers, and the nested `HarnessWorkerBinding`.
- The Autopilot runtime projection fails closed unless the registry is `bound`,
  has no blockers, references the selector live-promotion readiness proof, and
  carries a nested worker binding for
  `activation:default-agent-harness:blessed-readonly`.
- Fork activation readiness now requires validated canary activation records to
  include a matching registry record, so fork packageability and future worker
  attachment cannot silently skip activation hash, component version set,
  canary result, policy posture, or nested binding identity.
- The Workflows right rail surfaces registry status next to worker binding
  authority and includes registry blockers in the active runtime binding
  blocker rollup.
- The retained GUI validator now requires `workerBindingRegistryBound`,
  `workerBindingRegistryStatus: bound`, empty registry blockers, matching
  readiness proof ids, matching activation/hash identity, and a matching nested
  worker binding before accepting default runtime binding evidence.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T14-18-42-111Z/`;
  the live GUI proof explicitly reports `workerBindingRegistryBound: true`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T14-26-30-948Z/dashboard-index.json`.

This changes the promotion boundary from "a live worker binding proves its
authority fields" to "a live worker binding must be accepted by a durable
activation registry record." The next chronological slice should use this
registry as the worker launch surface: worker attach/resume should resolve by
workflow id, activation id, activation hash, component-version set, rollback
target, readiness proof id, and worker binding status before the worker can
claim live default authority.

### 2026-05-08 Worker-Attach Resolver Slice

The registry is now an operational attach resolver, not just a proof artifact.
The live default worker path must produce a durable worker attach receipt before
the worker can claim blessed workflow authority:

- Rust canonical harness contracts now define
  `HarnessWorkerAttachStatus`, `HarnessWorkerAttachRequest`, and
  `HarnessWorkerAttachReceipt`, plus `resolve_harness_worker_binding`.
- Attach resolution fails closed unless workflow id, activation id, activation
  hash, harness hash, component-version set, rollback target, readiness proof
  id, registry status, canary result, nested live worker binding, and authority
  readiness all match.
- `RuntimeAgentService` now carries the active registry record and latest
  attach receipt; adopting a live registry through
  `with_harness_worker_binding_registry_record` requires an accepted resolver
  receipt.
- The TS harness runtime mirrors the resolver with
  `makeWorkflowHarnessWorkerAttachRequest`,
  `resolveWorkflowHarnessWorkerBinding`, and
  `workflowHarnessWorkerAttachBlockers`.
- Default dispatch proofs, fork activation records, harness metadata, and
  Autopilot runtime evidence now include `workerAttachReceipt`.
- Autopilot evidence also includes an intentionally invalid attach receipt with
  a mismatched activation hash, and validation requires that invalid attach to
  be blocked.
- The Workflows right rail surfaces attach status and attach receipt id beside
  worker authority and registry state.
- Focused validation is green for the Rust attach resolver, Autopilot default
  runtime binding evidence, TS activation contracts, IDE build, harness wiring,
  and the GUI harness contract.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T14-51-20-968Z/`;
  the live GUI proof explicitly reports `workerAttachBound: true`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T14-59-45-397Z/dashboard-index.json`.

This changes the promotion boundary from "a registry record authorizes a live
binding" to "a specific worker attachment must resolve through that registry
and emit a receipt." The next chronological slice should make worker
attach/resume/rollback lifecycle events first-class timeline entries and prove
the `resumed` and `rolled_back` states through retained GUI evidence, alongside
the current valid/invalid attach proof.

### 2026-05-08 Worker-Attach Lifecycle Timeline Slice

Worker attach is now a three-phase lifecycle on the harness timeline, not a
single bound receipt. The live default worker path must prove attach, resume,
and rollback against the same registry-bound identity before the default
runtime binding can be considered matched:

- Rust canonical harness contracts now define
  `HarnessWorkerAttachLifecyclePhase` and
  `HarnessWorkerAttachLifecycleEvent`, plus
  `default_harness_worker_attach_lifecycle_events`.
- The TS harness runtime mirrors the lifecycle with
  `makeWorkflowHarnessWorkerAttachLifecycle` and
  `workflowHarnessWorkerAttachLifecycleComplete`.
- Default runtime dispatch proofs now include
  `workerAttachResumeReceipt`, `workerAttachRollbackReceipt`,
  `workerAttachLifecycle`, lifecycle attempt ids, lifecycle statuses, and a
  complete/incomplete readiness flag.
- Autopilot runtime evidence now rejects a matched default runtime binding
  unless `bound`, `resumed`, and `rolled_back` are all accepted with empty
  blockers and lifecycle attempts are present in `dispatchNodeAttemptIds`.
- The Workflows right rail exposes lifecycle completeness, lifecycle statuses,
  resume receipt id, rollback receipt id, and lifecycle attempt ids as DOM
  evidence on the active runtime binding and default dispatch rows.
- Retained GUI validation now requires `workerAttachLifecycleComplete: true`
  in the live GUI proof, in addition to `workerAttachBound: true`.
- Focused validation is green for Rust canonical lifecycle coverage,
  Autopilot store evidence, TS contract consistency, TS activation contracts,
  IDE build, harness wiring, and the GUI harness contract.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T15-21-32-741Z/`;
  the live GUI proof explicitly reports `workerAttachLifecycleComplete: true`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T15-29-14-667Z/dashboard-index.json`.

This changes the promotion boundary from "a worker can attach to the blessed
registry" to "a worker's attach, resume, and rollback lifecycle is visible as
workflow-node evidence." The next chronological slice should bind these
lifecycle events to an explicit persisted worker session record so the GUI can
show which worker instance is currently running, which instance was resumed,
and which rollback target would receive control if the live activation fails.

### 2026-05-08 Worker Session Record Slice

Worker attach lifecycle events now resolve into a durable session-level record
that the runtime and GUI can use as the worker-instance handle for the blessed
default activation:

- Rust canonical harness contracts now define `HarnessWorkerSessionStatus`,
  `HarnessWorkerSessionRecord`, and
  `default_harness_worker_session_record`, with `rollback_ready` as the
  accepted steady state for the live default session.
- `RuntimeAgentService` now stores the current
  `harness_worker_session_record`, derived from the registry-bound attach,
  resume, and rollback lifecycle.
- The TS harness runtime mirrors the contract with
  `makeWorkflowHarnessWorkerSessionRecord` and
  `workflowHarnessWorkerSessionBlockers`, and the contract consistency test now
  checks the Rust/TS session-status union.
- Default runtime dispatch and Autopilot runtime evidence now carry
  `workerSessionRecord`, `workerSessionRecordId`, `workerSessionStatus`,
  `workerSessionAccepted`, and `workerSessionBlockers`.
- The Workflows right rail exposes the worker session id, current status,
  worker id, rollback target, current attempt id, and blocker state on the
  active runtime binding and default dispatch proof.
- Full retained GUI validation now requires `workerSessionRecordBound: true`
  and proves the accepted session is `rollback_ready`, resumed, rollback
  target ready, linked to the same registry record, and backed by lifecycle
  attempts in the default dispatch.
- Focused validation is green for Rust canonical session coverage, Autopilot
  store evidence, services crate compilation, TS contract consistency, TS
  activation contracts, IDE build, harness wiring, and the GUI harness
  contract.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T15-56-37-565Z/`;
  the live GUI proof explicitly reports `workerSessionRecordBound: true`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T16-03-01-399Z/dashboard-index.json`.

This changes the promotion boundary from "a lifecycle is visible" to "the
current worker instance is a workflow-addressable session record with a known
resume state and rollback target." The next chronological slice should persist
that session record into the runtime checkpoint/worker registry path used for
actual worker launch and resume, so the proof object becomes the operational
source of truth instead of only the validation projection.

### 2026-05-08 Worker Session Runtime Persistence Slice

The worker session record is now persisted through the runtime state path used
by delegated worker launch, worker execution, and resume rather than existing
only as a projection artifact:

- Runtime checkpoint keys now include
  `agent::harness_worker_session::<session id>` and
  `agent::harness_worker_session_record::<session record id>`.
- Rust canonical `HarnessWorkerSessionRecord` now carries `persistence_key`,
  `record_persistence_key`, `persisted_in_runtime_checkpoint`,
  `restored_from_persisted_session`, `runtime_checkpoint_source`, and
  `persistence_blockers`.
- Delegated worker spawn persists the record beside the worker assignment;
  duplicate spawn restores the existing record; worker step execution ensures
  a record exists before the step runs; resume marks an existing record as
  restored and writes it back to both indexes.
- The Autopilot projection, TS harness runtime, GUI rail, and retained GUI
  validator all require and show the persistence fields. The active runtime
  binding rollup and default dispatch row now expose checkpoint keys, persisted
  state, restored state, and checkpoint source as DOM evidence.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T16-22-36-710Z/`;
  all eight retained queries passed, the live GUI proof reports
  `workerSessionRecordBound: true`, and the session record includes both
  checkpoint keys, `persistedInRuntimeCheckpoint: true`,
  `restoredFromPersistedSession: true`, checkpoint source
  `runtime_state_access_harness_worker_session_record`, and empty
  `persistenceBlockers`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T16-30-23-659Z/dashboard-index.json`.

This changes the promotion boundary from "the current worker instance is
workflow-addressable" to "the runtime checkpoint can recover the
workflow-bound worker instance by session id or session-record id." The next
chronological slice should make the persisted session record the authority for
actual live worker launch and rollback handoff: launch should bind by
workflow id, activation id, activation hash, component-version set, rollback
target, worker id, session id, and record id, and rollback should prove it can
route control through that persisted binding rather than through projection
metadata alone.

### 2026-05-08 Worker Session Launch Authority Slice

The persisted `HarnessWorkerSessionRecord` is now the authority surface for
live worker launch admission and rollback handoff proof:

- Rust canonical `HarnessWorkerSessionRecord` carries
  `launch_authority_ready`, `launch_authority_blockers`,
  `launch_authority_source`, `rollback_handoff_ready`,
  `rollback_handoff_blockers`, and `rollback_handoff_target`.
- The runtime services layer stamps launch authority after the record is
  written to both persisted indexes and fails closed for live/bound worker
  launch if workflow id, activation id, activation hash, component-version
  set, rollback target, worker id, assigned session id, record id, readiness
  proof, registry status, persistence keys, or persisted checkpoint state do
  not match.
- Resume now restores the persisted worker session record through the same
  authority stamping path, so rollback handoff must prove a resumed,
  rollback-ready session with bound/resumed/rolled-back lifecycle receipts
  rather than trusting projection metadata.
- A tampered live/bound session record now blocks launch with
  `worker_session_launch_authority_blocked` and a specific mismatch blocker
  such as `worker_session_activation_mismatch`.
- The Autopilot projection, TS harness runtime, right rail, and retained GUI
  validator show and require launch authority and rollback handoff fields on
  active runtime binding and default dispatch rows.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T16-55-16-241Z/`;
  all retained queries passed, `harness_chat_runtime_binding_matches_workflow_activation`
  is true, `harnessDefaultRuntimeBindingMatchedCount` is 5, and the matched
  worker session sample includes `launchAuthorityReady: true`,
  `launchAuthorityBlockers: []`, `launchAuthoritySource` set to
  `persisted_harness_worker_session_record`, `rollbackHandoffReady: true`,
  `rollbackHandoffBlockers: []`, and `rollbackHandoffTarget` set to
  `activation:default-agent-harness:blessed-readonly`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T17-01-20-170Z/dashboard-index.json`.

This changes the promotion boundary from "the runtime checkpoint can recover a
workflow-bound worker instance" to "the live worker launch path is allowed to
proceed only when the recovered persisted session record proves the same
workflow activation, registry binding, version set, session identity,
checkpoint state, and rollback handoff." The next chronological slice should
move from authority admission into process handoff: the actual worker launch,
resume, and rollback executor should accept a typed launch envelope derived
from the persisted session record and emit a durable launch/handoff receipt
that the GUI can inspect per node.

### 2026-05-08 Worker Launch/Handoff Envelope Slice

The persisted worker session record now drives explicit worker launch,
resume, and rollback handoff envelopes instead of remaining only an admission
flag on the dispatch proof:

- Rust canonical types now include `HarnessWorkerLaunchPhase`,
  `HarnessWorkerLaunchEnvelope`, and `HarnessWorkerHandoffReceipt`, with
  canonical builders/resolvers that fail closed when the launch envelope does
  not match the persisted worker session record.
- Runtime service persistence now writes launch envelopes under
  `agent::harness_worker_launch_envelope::<child session>::<phase>` and
  handoff receipts under `agent::harness_worker_handoff_receipt::<receipt id>`
  beside the worker session record.
- Delegated worker launch persists the `launch` envelope/handoff receipt, and
  persisted-session restore emits `resume` and `rollback` envelopes/receipts
  after authority stamping.
- The TypeScript harness runtime mirrors the canonical phase, envelope, and
  handoff receipt shapes and regenerates the envelopes whenever the live GUI
  promotion path replaces the default dispatch's worker session id with the
  actual workflow id.
- The Autopilot default runtime binding and dispatch proof now expose
  `workerLaunchEnvelopes`, `workerHandoffReceipts`,
  `workerLaunchEnvelopeIds`, and `workerHandoffReceiptIds`; binding acceptance
  requires accepted launch/resume/rollback envelopes and handoff statuses
  `launched`, `resumed`, and `rollback_handoff_ready`.
- The Workflows right rail now surfaces launch envelope and handoff receipt
  counts/ids and the rollback handoff receipt status on both active runtime
  binding and default dispatch rows.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T17-41-29-444Z/`;
  all eight retained queries passed,
  `harness_chat_runtime_binding_matches_workflow_activation` is true, and the
  live GUI proof reports `workerLaunchHandoffBound: true`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T17-47-23-121Z/dashboard-index.json`.

This changes the promotion boundary from "a persisted session record can
authorize launch" to "worker launch, resume, and rollback handoff are typed
workflow records with durable receipt evidence." The next chronological slice
should bind those launch/handoff receipts into the node timeline and replay
fixture index so each worker handoff has a per-node attempt, receipt, replay
fixture/ref, and rollback target visible from the GUI inspector.

### 2026-05-08 Worker Handoff Node Timeline Slice

The worker launch/handoff receipts now project into the same node-attempt and
replay fixture substrate used by the rest of the harness graph:

- Rust canonical harness types expose
  `default_harness_node_attempt_for_worker_handoff_receipt`, which converts
  launch, resume, and rollback handoff receipts into `handoff_bridge` node
  attempts with stable attempt ids, receipt refs, replay fixture refs, policy
  capture metadata, and live/blocked status.
- Handoff receipts now retain the launch envelope id in `receipt_refs`, so the
  inspector can traverse from node attempt to handoff receipt to launch
  envelope without relying on projection-only ids.
- The TypeScript harness runtime and Autopilot default dispatch proof now
  expose `workerHandoffNodeAttempts`, `workerHandoffNodeAttemptIds`, and
  `workerHandoffReplayFixtureRefs`, and include those ids in the shared
  dispatch node timeline, receipt id list, and replay fixture index.
- The Workflows right rail shows worker handoff attempt and replay fixture
  counts/ids, adds a handoff timeline readiness stat, and fails the active
  runtime binding if handoff node attempts are missing.
- The retained GUI validator now requires
  `workerHandoffNodeTimelineBound: true`, including launch/resume/rollback
  handoff attempts, matching
  `harness.handoff_bridge` node ids, `handoff_bridge` component kind,
  corresponding handoff receipt refs, replay fixture refs, and inclusion in
  both dispatch and global node attempt indexes.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T18-12-02-920Z/`;
  all eight retained queries passed and the live GUI proof reports both
  `workerLaunchHandoffBound: true` and
  `workerHandoffNodeTimelineBound: true`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T18-18-59-682Z/dashboard-index.json`.

This changes the promotion boundary from "launch and handoff have durable
receipts" to "worker handoff is a first-class timeline component with
receipts, replay fixtures, and GUI activation blockers." The next chronological
slice should thread this same handoff-bridge timeline through fork activation,
canary, and rollback proof so a forked harness can be inspected from activation
id to worker session to launch envelope to handoff attempt to rollback target.

### 2026-05-08 Fork Activation Handoff Timeline Slice

The fork activation path now uses the same worker handoff timeline substrate as
the blessed default runtime proof:

- A successful fork activation mint now creates a canary worker binding,
  worker binding registry record, attach/resume/rollback lifecycle, persisted
  worker session record, launch/resume/rollback launch envelopes, handoff
  receipts, gated `handoff_bridge` node attempts, and replay fixture refs.
- The activation record and harness metadata now expose
  `workerHandoffNodeAttempts`, `workerHandoffNodeAttemptIds`, and
  `workerHandoffReplayFixtureRefs`, alongside the worker session, launch
  envelopes, and handoff receipts.
- The fork activation wizard now includes a `worker-handoff` gate and
  exposes handoff timeline data attributes on the minted/blocked proof row, so
  the GUI can inspect activation id, worker session, launch envelope, handoff
  attempt, replay fixture, and rollback target without switching substrates.
- The runtime artifact validator now requires a validated fork to have the
  handoff timeline bound before counting it as a minted fork activation.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T18-37-02-352Z/`;
  all eight retained queries passed and runtime evidence reports
  `harnessForkHandoffTimelineBoundCount: 3`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T18-43-28-818Z/dashboard-index.json`.

This changes the fork boundary from "the wizard can mint a validated
activation id" to "the wizard proves that a forked harness activation can be
packaged with a canary handoff timeline, replay refs, and rollback evidence."
The next chronological slice should make these fork handoff refs deep-linkable
from the activation wizard into the receipt inspector, replay inspector, and
node timeline so operators can jump directly from a fork activation blocker or
canary proof to the exact handoff attempt that proves or blocks it.

### 2026-05-08 Fork Handoff Deep-Link Slice

The fork activation handoff timeline is now route-stateful and inspectable
from the activation wizard:

- The harness workbench deep-link contract now accepts
  `nodeAttemptId` and `activationGateNodeAttemptId`, so a fork activation gate
  can restore the selected handoff attempt as both a global timeline focus and
  an activation-gate focus.
- The `worker-handoff` activation gate now renders node-attempt reference
  buttons and a compact node timeline with receipt refs, replay fixture refs,
  component kind, status, and duration.
- The receipt and replay inspectors resolve fork activation handoff receipts
  and replay fixtures as `activation_worker_handoff` sources tied to the
  `handoff_bridge` component.
- The activation-id mint click proof now captures minted worker handoff
  receipt ids, node attempt ids, replay fixture refs, a handoff deep link, the
  restored selected-state attributes, and timeline row visibility.
- The retained GUI validator now requires
  `activationGateNodeTimelineDeepLink: true`, plus activation-id proof fields
  showing the worker handoff gate restored the selected attempt and timeline.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T19-29-45-194Z/`;
  all eight retained queries passed, `routeStatefulDeepLinkReplay: true`,
  `coldStartDeepLinkRestore: true`, `activationIdGateClickProof: true`, and
  `activationGateNodeTimelineDeepLink: true`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T19-36-51-457Z/dashboard-index.json`.

This changes fork activation from "the wizard lists handoff evidence" to "the
wizard can carry an operator directly to the exact handoff receipt, replay
fixture, and node-attempt timeline row that proves the activation." The next
chronological slice should use the same route-stateful inspector pattern for
rollback/canary comparison panels and then tighten package export/import around
those evidence refs.

### 2026-05-08 Canary And Rollback Deep-Link Slice

The canary and rollback proof surfaces now use the same route-stateful
inspector pattern as the handoff timeline:

- Canary execution boundaries expose selected boundary id, rollback drill id,
  receipt refs, replay fixture refs, rollback target, canary status, and drill
  status as GUI data attributes.
- The canary activation gate now treats both boundary ids and rollback drill
  ids as evidence refs, so the same gate can restore a boundary-focused view
  or a drill-focused view from a `#harness-workbench` link.
- The rollback-restore activation gate click proof now follows a second deep
  link after the dry run, restoring the exact rollback restore canary id and
  `workflow_restore_canary:*` receipt binding into the gate inspector.
- The retained GUI validator now requires canary boundary and rollback drill
  deep-link cases under `routeStatefulActivationGateReferenceDeepLinks`, plus
  rollback-restore deep-link state on the click proof.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T19-54-02-426Z/`;
  all eight retained queries passed, `routeStatefulActivationGateReferenceDeepLinks:
  true`, `activationGateRollbackRestoreClickProof: true`, and
  `activationGateNodeTimelineDeepLink: true`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T20-00-06-942Z/dashboard-index.json`.

This changes canary and rollback inspection from "status rows are visible" to
"each row is an addressable proof target that can be restored by URL, receipt
ref, replay ref, or evidence ref." The next chronological slice should tighten
package export/import so fork bundles preserve these deep-linkable evidence
refs across file-system movement and activation review.

### 2026-05-08 Fork Package Evidence Manifest Slice

Fork package export/import now preserves the proof graph needed to review or
move a harness fork without losing its activation evidence:

- TypeScript contracts define `WorkflowHarnessPackageEvidenceManifest` and
  attach it to both harness metadata and portable package manifests.
- `makeWorkflowHarnessPackageEvidenceManifest` collects activation id/state,
  rollback target, component version set, receipt refs, replay fixture refs,
  rollback-restore receipt refs, canary boundary ids, rollback drill ids,
  worker handoff attempts, worker handoff receipts, and route-restorable
  `#harness-workbench` deep links.
- Fork creation and activation minting refresh the manifest after activation
  audit records are written, so blocked and validated forks both package their
  latest review state.
- Rust package export writes `harness-package-evidence.json` and records it as
  a `harness_package_manifest` sidecar; package import rehydrates
  `metadata.harness.packageManifest` when moving the workflow to a new root.
- The package summary UI exposes manifest presence, receipt count, replay
  fixture count, and deep-link count as data attributes for GUI validation.
- The retained GUI contract now requires
  `harness_package_evidence_manifest`, and the latest retained run reports
  `hasHarnessPackageEvidenceManifest: true`.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T20-27-59-060Z/`;
  all eight retained queries passed with `harness_package_evidence_manifest`
  backed by `rollback-restore-canary-ui-proof.json`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T20-34-19-262Z/dashboard-index.json`.

This changes package export from "workflow files and sidecars move together"
to "the reviewable activation evidence graph moves with the fork." The next
chronological slice should use the same manifest as an import-time activation
review surface: invalid forks stay blocked with visible missing evidence, while
valid imported forks can prove canary, rollback, receipt coverage, replay
coverage, and worker handoff continuity before minting a new activation id.

### 2026-05-08 Package Evidence Activation Gate Slice

The package evidence manifest is now an activation gate, not just portable
metadata:

- `workflowHarnessPackageEvidenceReview` evaluates imported or validated
  harness forks against manifest schema, receipt refs, replay fixture refs,
  rollback-restore receipt refs, worker handoff attempts, worker handoff
  receipts, and route-restorable deep links.
- Incomplete imported or validated package manifests now create the
  `harness_package_manifest_incomplete` readiness issue, with repair metadata
  that routes operators to the advanced package-evidence review surface.
- `createWorkflowHarnessActivationCandidate` now inserts a `package-evidence`
  gate between receipt coverage and canary, so a fork cannot mint activation
  until its portable evidence graph is complete.
- The activation wizard exposes a `Package evidence` step with evidence refs,
  receipt refs, replay fixture refs, readiness status, and a shared gate
  action that re-runs package continuity checks.
- The retained GUI contract now distinguishes
  `harness_package_evidence_manifest` from `harness_package_evidence_gate`,
  proving both that the manifest moves with the fork and that activation
  review actually checks it.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T21-07-53-552Z/`;
  all eight retained queries passed with
  `harness_package_evidence_manifest_present: true` and
  `harness_package_evidence_gate_present: true`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T21-14-03-098Z/dashboard-index.json`.

This changes package import/review from "the activation evidence graph is
available if someone looks for it" to "the activation path blocks until the
package evidence graph is complete and inspectable." The next chronological
slice should make package evidence review click-through fully live in the GUI:
select the `package-evidence` gate, inspect missing manifest refs, deep-link
to preserved receipt/replay/rollback/handoff proof, and show the same review
state when a package is exported, imported, and activated from a new root.

### 2026-05-08 Package Evidence Click-Through Slice

The package-evidence gate is now live-clickable and reviewable in the GUI:

- The gate inspector renders a dedicated `workflow-harness-package-evidence-review`
  panel when `package-evidence` is selected.
- The review panel exposes category rows for manifest schema, receipts, replay
  fixtures, rollback-restore refs, worker handoff node attempts, worker handoff
  receipts, and preserved package deep links.
- Missing categories render explicit missing-row affordances; present refs render
  buttons that restore the appropriate receipt, replay fixture, node attempt, or
  preserved package deep-link target.
- Package deep links prefer non-activation proof targets first, so the first
  click lands on a meaningful canary/rollback/handoff proof rather than a broad
  activation summary.
- The live GUI probe now creates a package-evidence fork, mints a validated
  activation, selects the `package-evidence` gate, clicks representative
  manifest/receipt/replay/handoff/deep-link refs, and records
  `workflow.harness.package-evidence-gate-click-proof.v1`.
- The retained GUI contract now requires
  `harness_package_evidence_gate_click_proof`, and runtime consistency requires
  `harness_package_evidence_gate_click_proof_present`.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T21-56-57-375Z/`;
  all eight retained queries passed and
  `promotion-transition-live-gui-interaction-proof.json` reports
  `packageEvidenceGateClickProof.passed: true` with zero blockers, 31 receipt
  refs, 30 replay fixture refs, three worker handoff attempts, three worker
  handoff receipts, and 13 package deep links.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T22-03-10-391Z/dashboard-index.json`.

This changes package evidence review from "complete enough to gate activation"
to "operator-clickable proof rows with route-restorable evidence." The next
chronological slice should prove the same review state survives export/import
into a new root and that intentionally incomplete imported packages show
actionable missing-row blockers before activation.

### 2026-05-08 Package Evidence Export/Import Round-Trip Slice

Portable package evidence now survives real GUI-driven export/import:

- The live GUI probe saves a validated harness fork to a scratch `target/` root,
  exports it with the real Tauri `exportWorkflowPackage` API, and imports it into
  a fresh root with the real `importWorkflowPackage` API.
- The imported workflow rehydrates
  `workflow.harness.package-evidence-manifest.v1` into
  `metadata.harness.packageManifest` and remains selectable through the
  `package-evidence` activation gate.
- The imported valid package click proof restores receipt, replay fixture,
  worker handoff node attempt, and preserved package deep-link state from the
  gate inspector.
- The same probe then loads an intentionally incomplete imported package state
  with missing receipts, replay fixtures, rollback-restore refs, handoff
  attempts, handoff receipts, and deep links.
- The incomplete import shows six blocked package evidence rows and activation
  readiness includes `harness_package_manifest_incomplete`.
- The retained GUI contract now requires
  `harness_package_evidence_import_roundtrip`, and runtime consistency requires
  `harness_package_evidence_import_roundtrip_present`.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T22-14-36-970Z/`;
  all eight retained queries passed and
  `promotion-transition-live-gui-interaction-proof.json` reports
  `packageEvidenceImportRoundTripProof.passed: true` with zero blockers.
- The valid imported package proof has 31 receipt refs, 30 replay fixture refs,
  three worker handoff attempts, three worker handoff receipts, and a ready
  package-evidence gate.
- The incomplete imported package proof records missing rows for `receipts`,
  `replay-fixtures`, `rollback-restore`, `worker-handoff-attempts`,
  `worker-handoff-receipts`, and `deep-links`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T22-20-45-009Z/dashboard-index.json`.

This changes portable package evidence from "present in a sidecar" to "proven
portable across real export/import and failure-explainable when incomplete."

### 2026-05-08 Package Import Review Mode Slice

Imported harness fork packages now open into a real review mode instead of
landing as a generic file import:

- `import_workflow_package` returns the imported `WorkflowPortablePackage`
  alongside the loaded workbench bundle, including `manifest.json`, source
  workflow path, file count, portable status, harness package manifest, and the
  imported workflow path.
- The Workflow Composer creates a `workflow.package-import-review.v1` state model
  after import, evaluates activation readiness immediately, and focuses the
  `package-evidence` gate in the right rail.
- The package-evidence inspector renders
  `workflow-harness-package-import-review` with source workflow identity,
  imported workflow identity, package evidence readiness, blocker count, and a
  guarded `workflow-harness-package-import-activate` action.
- The activation action is enabled only for a valid imported package with green
  package evidence and disabled for intentionally incomplete imported package
  evidence.
- The live GUI proof records
  `workflow.harness.package-import-review-proof.v1`; the valid import action has
  `present: true`, `disabled: false`, `evidenceReady: true`, and zero blockers,
  while the incomplete import action has `present: true`, `disabled: true`,
  `evidenceReady: false`, and six blockers.
- The retained GUI contract now requires
  `harness_package_import_review_mode`, and runtime consistency requires
  `harness_package_import_review_mode_present`.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T22-40-31-318Z/`;
  all eight retained queries passed and
  `promotion-transition-live-gui-interaction-proof.json` reports
  `packageImportReviewProof.passed: true`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T22-46-52-663Z/dashboard-index.json`.

This completes the first user-facing package import loop: package evidence is
portable, reviewable, and activation-gated in the GUI.

### 2026-05-08 Reviewed Import Activation Handoff Slice

Imported, reviewed harness packages now show the actual activation handoff that
the user is about to commit:

- `workflow.package-import-review.v1` now carries
  `workflow.package-import-activation-handoff.v1` with candidate id, decision,
  activation id preview, canary status, rollback target, rollback-restore
  status, worker binding preview, gate counts, blocker codes, package-evidence
  readiness, and route targets.
- If a package preserves a validated activation record, import review uses that
  preserved activation identity for the handoff instead of treating the package
  like a never-activated fork. Incomplete package evidence still blocks the
  handoff and leaves activation disabled.
- The package-evidence rail renders
  `workflow-harness-package-import-handoff` with activation, canary, rollback,
  and worker route controls. The valid reviewed import is mintable and the
  intentionally incomplete import remains blocked.
- The retained GUI proof records
  `workflow.harness.package-import-activation-handoff-proof.v1`; the valid
  handoff has `handoffDecision: mintable`, `mintable: true`,
  `disabled: false`, canary `passed`, zero blockers, a rollback target, and a
  worker binding id. Activation, canary, rollback, and worker controls all
  restore route state.
- The retained GUI contract now requires
  `harness_package_import_activation_handoff`, and runtime consistency requires
  `harness_package_import_activation_handoff_present`.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T23-25-12-842Z/`;
  all eight retained queries passed and
  `promotion-transition-live-gui-interaction-proof.json` reports
  `packageImportActivationHandoffProof.passed: true`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T23-31-29-876Z/dashboard-index.json`.

This closes the reviewed-import loop: a portable harness package is not merely
visible and evidence-gated; the GUI now shows the exact activation id, worker
binding, canary, and rollback posture before the user activates it.

### 2026-05-08 Reviewed Import Activation Apply Slice

The reviewed-import flow now proves the final commit click, not only the
pre-activation handoff:

- The package import round-trip probe clicks
  `workflow-harness-package-import-activate` on the valid reviewed import and
  records `workflow.harness.package-import-activation-apply-proof.v1`.
- The proof requires the real activation result from
  `applyWorkflowHarnessActivationCandidate`: `applied: true`, activation id
  equal to the reviewed handoff activation id, workflow activation state
  `validated`, worker binding and activation-record worker binding both pinned
  to the activation id, rollback target preserved, revision and rollback hashes
  present, and latest audit event `activation_minted` / `applied`.
- The proof also requires activation receipt refs, evidence refs, worker
  handoff receipt ids, worker handoff node attempts, and worker handoff replay
  fixture refs to remain connected after activation.
- The worker handoff deep link restores the `worker-handoff` activation gate,
  selects the committed handoff node attempt, and shows the handoff timeline.
- The intentionally incomplete imported package remains disabled after the
  valid import is committed, proving the apply path is still evidence-gated.
- The retained GUI contract now requires
  `harness_package_import_activation_apply`, and runtime consistency requires
  `harness_package_import_activation_apply_present`.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T23-41-17-655Z/`;
  all eight retained queries passed and
  `promotion-transition-live-gui-interaction-proof.json` reports
  `packageImportActivationApplyProof.passed: true`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T23-47-26-390Z/dashboard-index.json`.

This closes the activation side of the package loop: a fork package can be
exported, imported, reviewed, inspected, activated, audited, and traced to the
worker handoff timeline through the GUI.

### 2026-05-09 Reviewed Import Activation Hard Gate Slice

The reviewed-import activation apply proof is no longer only an artifact flag.
It is a contract-level default-live promotion invariant:

- `scripts/lib/autopilot-gui-harness-contract.mjs` now exposes
  `DEFAULT_LIVE_PROMOTION_INVARIANTS` and validates
  `uiAssertions.promotionTransitionLiveGui.packageImportActivationApplyProof`
  directly.
- A passing GUI result must prove the same-session `Activate reviewed import`
  click, mintable handoff action, minted activation id, `validated` workflow
  activation state, matching worker binding ids, preserved rollback target,
  revision and rollback hashes, `activation_minted` / `applied` audit status,
  activation receipt/evidence refs, worker handoff receipts, worker handoff
  node attempts, worker handoff replay fixture refs, and worker-handoff
  deep-link restoration.
- A GUI result that merely claims
  `harness_package_import_activation_apply_present: true` now fails unless the
  embedded proof satisfies the invariant. Runtime P3 and superiority gates
  inherit this because they select passing GUI evidence through
  `validateAutopilotGuiHarnessResult`.
- The promotion-ready baseline is
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T23-54-16-708Z/`;
  all eight retained queries passed and the hard invariant reports clicked,
  applied, `validated`, `activation_minted` / `applied`, and worker-handoff
  timeline restoration.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-09T00-00-38-348Z/dashboard-index.json`.

### 2026-05-09 Selector-Enforced Reviewed Import Invariant Slice

The reviewed-import activation invariant now participates in default-live
runtime selection instead of remaining only a result-level validator check:

- Rust canonical harness contracts now carry default-live invariant ids,
  invariant blockers, reviewed-import proof posture, and reviewed activation id
  on `HarnessRuntimeSelectorDecision`, `HarnessLiveHandoffProof`, and
  `HarnessDefaultRuntimeDispatchProof`.
- TypeScript graph/runtime contracts mirror the same fields, and
  `makeHarnessRuntimeSelectorDecision`, `makeBlessedHarnessLiveHandoffProof`,
  and `makeHarnessDefaultRuntimeDispatchProof` all consume
  `WorkflowHarnessPackageImportActivationApplyProof`.
- If the blessed default selector is requested without a valid same-session
  reviewed-import activation apply proof, the selector fails closed to
  canary/legacy and records `package_import_activation_apply_proof_missing`,
  stale, or structural blockers.
- The default dispatch proof now exposes
  `reviewedImportActivationApplyGate` with invariant id
  `reviewed_import_activation_apply`, proof posture, proof blockers, activation
  id, worker binding activation id, rollback target, and default-dispatch
  blockers.
- Runtime evidence and retained GUI validation now require
  `harness_selector_reviewed_import_activation_apply_invariant` and
  `harness_selector_reviewed_import_activation_apply_invariant_present`, proving
  selector, live handoff, and dispatch all consumed the same invariant before
  accepting the default-live route.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-09T00-32-20-635Z/result.json`;
  the promotion proof reports
  `selectorReviewedImportActivationApplyInvariant: true`,
  `liveHandoffReviewedImportActivationApplyInvariant: true`, and
  `defaultDispatchReviewedImportActivationApplyInvariant: true`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-09T00-40-30-002Z/dashboard-index.json`.

### 2026-05-09 Worker Launch Reviewed Import Invariant Slice

The reviewed-import activation invariant now reaches the persistent worker
launch and handoff boundary. This closes the gap where selector/default
dispatch could be invariant-gated while the worker launch path still accepted
bindings that looked live but inherited projection-only invariant blockers.

- Rust canonical harness contracts and TypeScript graph/runtime contracts now
  carry `requiredInvariantIds` and `invariantBlockers` through worker binding,
  worker binding registry, attach request/receipt, attach lifecycle, worker
  session record, launch envelope, and handoff receipt records.
- Worker sessions now expose `launchAuthorityInvariantIds` and
  `launchAuthorityInvariantBlockers`, so launch/resume/rollback envelopes prove
  the same reviewed-import activation invariant before a persistent worker can
  become launch-authoritative.
- Attach resolution fails closed on missing invariant ids, mismatched registry
  vs request invariants, registry invariant blockers, or nested worker binding
  invariant blockers.
- Default dispatch, runtime selector handoff, Autopilot runtime binding, and
  fork activation handoff all mint worker bindings with
  `reviewed_import_activation_apply` and no invariant blockers only after the
  reviewed import apply proof has passed.
- The live GUI proof now verifies that selector, live handoff, default
  dispatch, active worker binding, worker registry, attach lifecycle, session
  record, launch envelopes, handoff receipts, and node timeline are all bound
  to the same invariant posture.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-09T01-19-51-435Z/result.json`;
  runtime consistency reports
  `harness_worker_launch_reviewed_import_activation_apply_invariant_present:
  true` and `harness_chat_runtime_binding_matches_workflow_activation: true`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-09T01-26-16-362Z/dashboard-index.json`.

### 2026-05-09 Live Turn Node Inspector Deep-Link Slice

The live default harness turn is now inspectable through the same
route-stateful workbench path operators use for receipts, replay fixtures,
activation gates, and worker handoffs:

- The node-attempt inspector resolver now treats default runtime dispatch
  adapter attempts as first-class sources. A live attempt emitted by
  `defaultRuntimeDispatchProof.cognitionExecutionAdapterResults` can be opened
  directly from its `nodeAttemptId` even when it did not originate from the
  latest ad hoc workflow run object.
- The promotion GUI proof now runs
  `runHarnessLiveTurnNodeInspectorDeepLinkProbe`, writes a
  `#harness-workbench?panel=outputs&nodeAttemptId=...&receiptRef=...&replayFixtureRef=...`
  hash, applies the workbench route, and reads
  `workflow-harness-node-attempt-inspector` back from the DOM.
- The retained proof requires the rail to echo the default dispatch attempt id,
  `data-node-attempt-source-kind=default_runtime_dispatch`, workflow node id,
  component id/kind, activation id, harness hash, live execution mode,
  `live_ready` readiness, live status, policy decision, receipt refs, replay
  fixture ref, input hash, and output hash.
- The GUI harness evidence contract now requires
  `harness_live_turn_node_inspector_deep_link` and runtime consistency requires
  `harness_live_turn_node_inspector_deep_link_present`.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-09T04-11-07-040Z/result.json`;
  the promotion proof reports
  `liveTurnNodeInspectorDeepLink: true` for
  `harness.planner:default-dispatch:planner_envelope`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-09T04-17-19-806Z/dashboard-index.json`.

This changes the live-turn node inspector from "runtime artifacts include an
inspectable attempt" to "the actual GUI can restore the live default dispatch
node attempt by URL and prove the rail displays the same receipt, replay,
policy, binding, and hash evidence."

### 2026-05-09 Live Vs Shadow Comparison Deep-Link Slice

The default harness workflow now carries explicit shadow cognition adapter
attempts beside its live cognition adapter attempts and exposes their
comparison as a first-class rail surface:

- `defaultRuntimeDispatchProof` now emits
  `cognitionExecutionShadowAdapterResults`, shadow attempt ids, receipt ids,
  replay fixture refs, action frame ids, divergence classes, and
  `liveShadowComparisons` for the live `planner`, `prompt_assembler`, and
  `task_state` envelopes.
- Each comparison binds the live node attempt to its shadow node attempt with
  `divergence=none`, `blocking=false`, live and shadow receipt refs, live and
  shadow replay fixture refs, and matching input/output hashes.
- The node-attempt inspector resolver now attaches the comparison when a live
  or shadow default-dispatch attempt is selected. The right rail renders
  `workflow-harness-live-shadow-comparison-inspector` with data attributes for
  both attempt ids, the component kind, divergence/blocking state, receipts,
  replay fixtures, and hash comparison.
- The promotion GUI proof now runs
  `runHarnessLiveShadowComparisonDeepLinkProbe`, writes the same
  `#harness-workbench?panel=outputs&nodeAttemptId=...&receiptRef=...&replayFixtureRef=...`
  hash shape, opens the comparison inspector, and proves the rail echoes the
  live/shadow pair.
- The GUI harness evidence contract now requires
  `harness_live_shadow_comparison` and runtime consistency requires
  `harness_live_shadow_comparison_present`.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-09T05-15-35-394Z/result.json`;
  the promotion proof reports `liveShadowComparisonDeepLink: true` for
  `harness.planner:default-dispatch:planner_envelope` paired with
  `harness.planner:default-dispatch:planner_envelope_shadow`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-09T05-22-17-721Z/dashboard-index.json`.

This changes live-vs-shadow from "comparison records may exist somewhere in a
run" to "the GUI can restore a default harness live/shadow pair by URL and
prove the rail displays the same receipt, replay, divergence, and hash
evidence."

### 2026-05-09 Retained Runtime Live Vs Shadow Artifact Slice

The Rust/orchestrator default runtime dispatch now emits live/shadow cognition
adapter comparisons directly in normal retained runtime evidence:

- `runtime_harness_default_runtime_dispatch` invokes a shadow adapter result
  beside each live cognition adapter result for `planner`, `prompt_assembler`,
  and `task_state`.
- The dispatch artifact now carries
  `cognitionExecutionShadowAdapterResults`, shadow attempt ids, receipt ids,
  replay fixture refs, action frame ids, component kinds, divergence classes,
  `liveShadowComparisons`, and live/shadow comparison counts.
- The live-promotion cognition readiness proof now requires the shadow adapter
  lane and includes shadow attempt ids, receipt refs, replay refs, action
  frames, and divergence classes in the cognition cluster rollup.
- A focused Rust test now asserts the default dispatch artifact itself emits
  three non-blocking live/shadow comparisons and three retained shadow adapter
  results with shadow execution mode, receipts, and replay fixtures.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-09T05-28-33-120Z/result.json`.
  Its `runtime-artifacts.json` now reports
  `harnessLiveShadowComparisonCount: 3` for `retained_harness_dogfooding`,
  and `harnessLiveShadowComparisonComponentKinds: ["planner",
  "prompt_assembler", "task_state"]`, proving the retained runtime artifact
  path sees every cognition live attempt paired with its shadow attempt,
  distinct live/shadow receipts, distinct replay fixtures, non-blocking
  `divergence=none`, and matching input/output hashes.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-09T05-36-07-777Z/dashboard-index.json`.

This changes the live/shadow proof from "the GUI promotion fixture can show a
comparison" to "a normal retained dogfooded turn emits every cognition
live/shadow comparison from the runtime dispatch evidence path, and retained
GUI validation fails unless all three cognition pairs are present." The next
chronological slice should apply the same direct runtime evidence pattern to
the next P0 cluster instead of leaving it as proof-fixture-only evidence.

### 2026-05-09 Routing/Model Live Vs Shadow Runtime Slice

The direct runtime comparison pattern now covers the next P0 promotion cluster,
`routing_model`, in addition to cognition:

- `runtime_harness_default_runtime_dispatch` invokes shadow adapter results
  beside the gated `model_router`, `model_call`, and `tool_router` adapter
  results.
- The default dispatch artifact now carries `routingModelShadowAdapterMode`,
  shadow attempt ids, receipt ids, replay fixture refs, adapter results, action
  frame ids, component kinds, and divergence classes.
- The shared `liveShadowComparisons` list now includes six retained pairs:
  `planner`, `prompt_assembler`, `task_state`, `model_router`, `model_call`,
  and `tool_router`.
- The routing/model live-promotion readiness proof now requires the shadow
  lane and includes shadow attempt ids, receipt refs, replay refs, action
  frames, and divergence classes in the routing/model cluster rollup.
- The GUI retained-evidence collector now accepts `live` or `gated` as the
  left side of a live/shadow comparison, because routing/model has not yet
  been promoted fully live but still needs shadow comparison proof before
  promotion.
- Runtime consistency now requires
  `harness_live_shadow_routing_model_pairs_present`, so GUI validation fails
  unless `model_router`, `model_call`, and `tool_router` are all present in the
  retained live/shadow comparison samples.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-09T06-00-43-156Z/result.json`.
  Its `runtime-artifacts.json` reports
  `harnessLiveShadowComparisonCount: 6` and
  `harnessLiveShadowComparisonComponentKinds: ["model_call", "model_router",
  "planner", "prompt_assembler", "task_state", "tool_router"]`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-09T06-06-54-656Z/dashboard-index.json`.

This changes routing/model from "gated adapter results are present" to "each
routing/model adapter has a retained shadow comparison with receipts, replay
fixtures, no blocking divergence, and matching input/output hashes."

### 2026-05-09 Verification/Output Live Vs Shadow Runtime Slice

The direct runtime comparison pattern now covers the full `verification_output`
cluster:

- `runtime_harness_default_runtime_dispatch` invokes shadow adapter results
  beside the gated `postcondition_synthesizer`, `verifier`, `completion_gate`,
  `receipt_writer`, `quality_ledger`, and `output_writer` adapter results.
- The default dispatch artifact now carries
  `verificationOutputShadowAdapterMode`, shadow attempt ids, receipt ids, replay
  fixture refs, adapter results, action frame ids, component kinds, and
  divergence classes.
- The shared `liveShadowComparisons` list now includes twelve retained pairs:
  the cognition trio, the routing/model trio, and all six verification/output
  components.
- The verification/output live-promotion readiness proof now requires both the
  gated adapter lane and the shadow adapter lane, and its cluster rollup includes
  both sets of attempt ids, receipt refs, replay refs, action frame ids, and
  divergence classes.
- The node-attempt inspector and live/shadow comparison rail now include
  `verificationOutputShadowAdapterResults` when resolving default dispatch
  attempts, so deep links can land on the new shadow-backed verification/output
  evidence.
- Runtime consistency now requires
  `harness_live_shadow_verification_output_pairs_present`, so GUI validation
  fails unless `postcondition_synthesizer`, `verifier`, `completion_gate`,
  `receipt_writer`, `quality_ledger`, and `output_writer` are all present in the
  retained live/shadow comparison set.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-09T06-21-39-565Z/result.json`.
  Its evidence assessment reports `harnessLiveShadowComparisonCount: 12` and
  component kinds `["completion_gate", "model_call", "model_router",
  "output_writer", "planner", "postcondition_synthesizer", "prompt_assembler",
  "quality_ledger", "receipt_writer", "task_state", "tool_router", "verifier"]`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-09T06-28-12-256Z/dashboard-index.json`.

This changes verification/output from "gated adapter results are present" to
"each verification/output adapter has a retained shadow comparison with receipts,
replay fixtures, no blocking divergence, and matching input/output hashes."

### 2026-05-09 Authority/Tooling Live Vs Shadow Runtime Slice

The direct runtime comparison pattern now covers the final P0 promotion cluster,
`authority_tooling`:

- `runtime_harness_default_runtime_dispatch` invokes shadow adapter results
  beside the gated `policy_gate`, `approval_gate`, `dry_run_simulator`,
  `mcp_provider`, `mcp_tool_call`, `tool_call`, `connector_call`, and
  `wallet_capability` adapter results.
- The default dispatch artifact now carries
  `authorityToolingShadowAdapterMode`, shadow attempt ids, receipt ids, replay
  fixture refs, adapter results, action frame ids, component kinds, and
  divergence classes.
- The shared `liveShadowComparisons` list now includes twenty retained pairs:
  cognition, routing/model, verification/output, and all eight authority/tooling
  components.
- The authority/tooling live-promotion readiness proof now requires both the
  gated adapter lane and the shadow adapter lane while preserving the existing
  policy gate, approval gate, read-only catalog, destructive denial, wallet
  dry-run, canary, and rollback readiness checks.
- The node-attempt inspector and live/shadow comparison rail now include
  `authorityToolingShadowAdapterResults` when resolving default dispatch
  attempts, so deep links can land on the new shadow-backed authority/tooling
  evidence.
- Runtime consistency now requires
  `harness_live_shadow_authority_tooling_pairs_present`, so GUI validation fails
  unless all eight authority/tooling components are present in the retained
  live/shadow comparison set.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-09T06-38-31-001Z/result.json`.
  Its evidence assessment reports `harnessLiveShadowComparisonCount: 20` and
  component kinds `["approval_gate", "completion_gate", "connector_call",
  "dry_run_simulator", "mcp_provider", "mcp_tool_call", "model_call",
  "model_router", "output_writer", "planner", "policy_gate",
  "postcondition_synthesizer", "prompt_assembler", "quality_ledger",
  "receipt_writer", "task_state", "tool_call", "tool_router", "verifier",
  "wallet_capability"]`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-09T06-45-05-443Z/dashboard-index.json`.

This changes authority/tooling from "gated adapter results and live dry-run
canaries are present" to "every P0 default harness cluster has retained
live/shadow comparison coverage with receipts, replay fixtures, no blocking
divergence, and matching input/output hashes." The next chronological slice
should harden final promotion semantics: prove the default live handoff consumes
the blessed workflow activation with all P0 cluster comparison gates as explicit
preconditions, then exercise rollback from that fully proven state.

### Implemented: Explicit P0 Live/Shadow Promotion Gate

The final-promotion hardening slice now makes the full retained live/shadow
comparison set an explicit promotion gate instead of an inferred cluster
property:

- Rust now has canonical `HarnessLiveShadowComparisonGate` contract state for
  the default live promotion proof. The gate records required component kinds,
  observed component kinds, comparison counts, receipt readiness, replay
  readiness, divergence readiness, blockers, policy decision, and evidence
  refs.
- The required gate component set is the twenty retained P0 live/shadow pairs:
  cognition live kernels, routing/model adapters, verification/output adapters,
  and authority/tooling adapters.
- `HarnessLivePromotionReadinessProof` now carries
  `liveShadowComparisonGate` and `liveShadowComparisonGateReady`, and
  `promotionEligible` / `defaultLiveActivationReady` require the gate to pass.
- The default runtime dispatch emits the same top-level
  `liveShadowComparisonGate` and binds the worker registry/attach path to the
  readiness proof only after the gate is ready.
- Default runtime binding evidence now records selector, handoff, and dispatch
  live/shadow gate readiness, so a missing gate blocks authority binding rather
  than only failing after the fact.
- The TS workflow projection carries the same proof shape and blocker logic, so
  GUI fixture evidence and Rust runtime evidence agree on the promotion
  contract.
- GUI validation now requires
  `harness_live_shadow_comparison_gate_present`, and the proof export preserves
  the top-level gate fields so the workbench evidence path can inspect the same
  precondition the runtime uses.

Full retained GUI validation is green in
`docs/evidence/autopilot-gui-harness-validation/2026-05-09T07-17-00-620Z/result.json`.
That evidence reports the live/shadow comparison gate as ready with
`comparisonCount: 20`, `requiredComparisonCount: 20`, and policy decision
`allow_default_harness_live_shadow_comparison_gate`.

Runtime P3 with required GUI evidence is green at
`docs/evidence/agent-runtime-p3-validation/2026-05-09T07-23-20-833Z/dashboard-index.json`.

This changes final promotion from "the readiness proof says all clusters are
ready" to "the blessed default-live handoff and worker binding consume a
readiness proof that explicitly proves every retained P0 live/shadow comparison
gate before the default workflow activation can drive runtime authority." The
next chronological slice should harden rollback from this exact fully gated
state: force a default-live worker binding rollback drill to reference the same
readiness proof id, gate id, activation id, workflow hash, and rollback target,
then require GUI evidence that the rollback path is visible from the runtime
binding/workbench panel.

### Implemented: Rollback From Exact Gated Default-Live Binding

The rollback hardening slice now proves that the default-live worker rollback
path is not merely available; it is bound to the exact live promotion proof and
P0 live/shadow gate that authorized the default runtime handoff:

- Rust canonical harness contracts now carry rollback proof identity through
  worker binding, registry record, attach request/receipt, attach lifecycle,
  worker session record, launch envelope, and handoff receipt.
- Each rollback-capable artifact records `rollbackReadinessProofId`,
  `rollbackLiveShadowComparisonGateId`,
  `rollbackLiveShadowComparisonGateReady`, `rollbackActivationId`,
  `rollbackHarnessHash`, and `rollbackPolicyDecision`.
- Bound default-live rollback is allowed only when those fields match the same
  live promotion readiness proof, `p0-live-shadow-comparison-gate`, blessed
  default activation id, blessed harness hash, and
  `allow_default_harness_worker_rollback_from_live_shadow_gate`.
- The TypeScript workflow runtime now normalizes supplied worker bindings
  through the registry factory, so older prebuilt binding objects cannot omit
  the live-shadow gate id or rollback policy while their registry claims to be
  bound.
- The promoted GUI workflow now stores the normalized registry worker binding
  as `metadata.workerHarnessBinding`, making the active worker binding, default
  dispatch proof, worker registry, attach lifecycle, session, launch envelopes,
  handoff receipts, and handoff node timeline agree on the same rollback
  identity.
- Retained GUI validation now requires
  `harness_default_runtime_rollback_live_shadow_gate_bound`; this fails unless
  every rollback artifact binds to the same readiness proof, live/shadow gate,
  activation id, harness hash, and rollback policy.

Full retained GUI validation is green in
`docs/evidence/autopilot-gui-harness-validation/2026-05-09T11-16-43-081Z/result.json`.
That bundle reports
`harness_default_runtime_rollback_live_shadow_gate_bound: true`,
`harness_chat_runtime_binding_matches_workflow_activation: true`, and
`harness_promotion_transition_live_gui_interaction_present: true`.

Runtime P3 with required GUI evidence is green at
`docs/evidence/agent-runtime-p3-validation/2026-05-09T11-22-47-210Z/dashboard-index.json`.

This changes rollback from "the live harness has a rollback target" to "the
rollback path proves it can return from the exact fully gated default-live
binding that was selected by the workflow runtime." The next chronological
slice should make that rollback drill more operator-actionable in the GUI:
surface a first-class rollback proof row from the runtime binding/workbench
panel, show the matched readiness proof and live/shadow gate beside it, and
preserve deep links for the rollback target, launch envelope, handoff receipt,
and node timeline attempt.

### Implemented: Operator-Actionable Rollback Proof Workbench

The active runtime binding/workbench panel now turns the rollback drill into an
operator-facing proof surface instead of a hidden validation invariant:

- The active runtime binding row carries selected receipt, replay fixture, and
  node attempt state so deep links can restore the same proof context.
- The panel exposes a first-class rollback proof row with readiness proof id,
  live/shadow gate id and readiness, activation id, harness hash, policy
  decision, rollback target, launch envelope, handoff receipt, node attempt, and
  replay fixture.
- The rollback proof row includes route-stateful links for the rollback target,
  launch envelope, handoff receipt, node attempt, and replay fixture. Each link
  must reopen the workbench with the runtime binding proof still mounted and the
  selected artifact restored.
- GUI validation now requires
  `harness_active_runtime_rollback_proof_workbench` and
  `harness_active_runtime_rollback_proof_workbench_present`; the live GUI proof
  fails if any route-restored rollback proof artifact is missing or detached from
  the active runtime binding.

Full retained GUI validation is green in
`docs/evidence/autopilot-gui-harness-validation/2026-05-09T11-45-40-808Z/result.json`.
That bundle reports all 8 retained queries passing with no missing artifacts,
`activeRuntimeRollbackProofWorkbench: true`, and a passing promotion transition
proof for the rollback target, launch envelope, handoff receipt, node attempt,
and replay fixture cases.

Runtime P3 with required GUI evidence is green at
`docs/evidence/agent-runtime-p3-validation/2026-05-09T11-51-57-558Z/dashboard-index.json`.

This changes rollback from "bound to the exact default-live proof" to "visible,
addressable, and reviewable from the operator workbench." The next chronological
slice should wire that proof row into an execution workbench action: run a
rollback dry-run from the bound proof, show the canary result inline, keep apply
disabled until the proof row remains bound, and require GUI evidence that dry-run
and apply readiness survive route restoration.

### Implemented: Active Runtime Rollback Execution Workbench

The active runtime rollback proof row is now actionable without breaking the
proof discipline that authorized the default-live handoff:

- A dedicated `WorkflowHarnessActiveRuntimeRollbackExecutionProof` records the
  dry-run method, bound readiness proof id, live/shadow gate id, activation id,
  harness hash, rollback target, launch envelope, handoff receipt, node attempt,
  replay fixture, canary result, apply readiness, and route-restored state.
- The active runtime binding panel exposes rollback dry-run and apply controls.
  Dry-run is enabled only when the rollback proof is bound. Apply remains
  disabled until the dry-run passes and the route-restored proof row still binds
  to the same readiness proof, gate, activation, hash, envelope, receipt,
  attempt, and replay fixture.
- The inline row now shows dry-run status, canary result id, canary hash
  verification, apply readiness, and blockers beside the rollback proof.
- GUI validation now requires
  `harness_active_runtime_rollback_execution_workbench` and
  `harness_active_runtime_rollback_execution_workbench_present`. The live GUI
  proof fails unless the same-session workbench opens the active runtime
  rollback proof, clicks dry-run, observes a passing canary, restores the route,
  and verifies apply readiness on the still-bound proof row.

Full retained GUI validation is green in
`docs/evidence/autopilot-gui-harness-validation/2026-05-09T12-12-40-027Z/result.json`.
That bundle reports all 8 retained queries passing, no missing artifacts, and
`activeRuntimeRollbackExecutionWorkbench: true`. The proof records canary
`harness-active-runtime-rollback-canary:default-agent-harness:1778329111261`,
`canaryHashVerified: true`, `applyReadiness: ready`, `applyDisabled: false`,
and `routeRestoreProofBound: true`.

Runtime P3 with required GUI evidence is green at
`docs/evidence/agent-runtime-p3-validation/2026-05-09T12-19-21-195Z/dashboard-index.json`.

This changes rollback from "visible and reviewable" to "dry-runnable, canary
checked, and apply-gated by the restored proof row." The next chronological
slice should carry the same operator discipline into actual rollback execution:
make apply produce a durable rollback execution receipt and audit event for the
default-live binding, keep the operation reversible through the same rollback
target, and prove in GUI evidence that apply cannot run against a stale or
detached proof.

### Implemented: Active Runtime Rollback Apply Proof

The active runtime rollback workbench now carries the apply step past readiness
into durable execution proof:

- A dedicated `WorkflowHarnessActiveRuntimeRollbackApplyProof` records the
  apply execution id, rollback receipt id, audit event id, rollback target,
  readiness proof, live/shadow gate, activation id, harness hash, launch
  envelope, handoff receipt, node attempt, replay fixture, dry-run canary id,
  target/hash verification, stale/detached proof guards, receipt refs, replay
  refs, and blockers.
- The Apply rollback control now calls a guarded runtime helper. It refuses
  missing dry-runs, stale proof ids, detached launch/handoff/node/replay state,
  live-shadow gate mismatch, activation mismatch, hash mismatch, and policy
  mismatch before marking rollback applied.
- The active runtime binding rail shows the apply execution status, execution
  id, rollback receipt id, audit event id, target/hash verification, policy
  decision, and blockers next to the dry-run canary state.
- GUI validation now requires
  `harness_active_runtime_rollback_apply_execution` and
  `harness_active_runtime_rollback_apply_execution_present`. The retained GUI
  proof fails unless the same-session workbench clicks Apply after the bound
  dry-run, records a rollback receipt, records an
  `active_runtime_rollback_applied` audit event, and proves target/hash
  verification.

Full retained GUI validation is green in
`docs/evidence/autopilot-gui-harness-validation/2026-05-09T13-04-57-555Z/result.json`.
That bundle reports all 8 retained queries passing and
`activeRuntimeRollbackApplyExecution: true`. The apply proof records rollback
receipt
`harness-active-runtime-rollback-apply-receipt:default-agent-harness:1778332248215`,
audit event
`harness-activation-audit:default-agent-harness:active_runtime_rollback_applied:1778332248215`,
`rollbackTargetVerified: true`, `hashVerified: true`, and no blockers.

Runtime P3 with required GUI evidence is green at
`docs/evidence/agent-runtime-p3-validation/2026-05-09T13-11-20-740Z/dashboard-index.json`.

This changes rollback from "dry-runnable and apply-gated" to "applied through a
durable, audited, receipt-bearing workbench action." The next chronological
slice should add negative retained GUI proof for stale/detached apply attempts:
mutate the selected proof binding in a controlled fixture, verify Apply is
blocked with explicit blocker codes, and keep the happy path unchanged.

### Implemented: Active Runtime Rollback Negative Apply Guardrail

The apply path now has retained GUI evidence for the two rollback failure
classes that matter most: a proof that was valid during dry-run but no longer
matches the live rollback binding, and a proof graph whose live rollback
dependencies have been removed or orphaned.

- A dedicated `WorkflowHarnessActiveRuntimeRollbackNegativeApplyProof` records
  negative cases, mutation kind, expected blockers, rail-visible blockers,
  runtime blockers, Apply disabled state, apply status, stale/detached flags,
  target/hash verification, rollback receipt id, audit event id, and pass/fail
  state.
- The live GUI probe creates a controlled `stale-hash-node-replay` fixture by
  mutating the rollback harness hash, node attempt id, and replay fixture after
  dry-run. The rail must keep Apply disabled and expose
  `rollback_harness_hash_stale`, `rollback_node_attempt_stale`,
  `rollback_replay_fixture_stale`, and `rollback_apply_hash_not_verified`.
- The same stale fixture is sent through the guarded runtime apply helper. The
  helper must refuse the apply, mark `staleProofBlocked: true`, keep
  `rollbackApplied: false`, and return the same explicit blocker codes.
- The negative suite now adds detached proof fixtures for
  `detached-launch-envelope-missing`, `detached-handoff-receipt-missing`,
  `detached-node-attempt-missing`, `detached-node-attempt-orphaned`, and
  `detached-replay-fixture-missing`. Each fixture keeps the successful dry-run
  proof in place, removes or orphans one live rollback dependency, verifies the
  rail keeps Apply disabled, and requires matching rail/runtime blockers such as
  `rollback_launch_envelope_missing`,
  `rollback_handoff_receipt_missing`, `rollback_node_attempt_missing`,
  `rollback_node_attempt_orphaned`, and `rollback_replay_fixture_missing`.
- GUI validation now requires
  `harness_active_runtime_rollback_negative_apply` and
  `harness_active_runtime_rollback_negative_apply_present` in addition to the
  happy-path apply execution proof.

Full retained GUI validation is green in
`docs/evidence/autopilot-gui-harness-validation/2026-05-09T14-08-26-010Z/result.json`.
That bundle reports all 8 retained queries passing and
`activeRuntimeRollbackNegativeApply: true`. The negative suite records six
passing cases with `applyButtonDisabled: true`, `applyStatus: blocked`,
`rollbackApplied: false`, matching rail-visible blocker codes, matching runtime
blocker codes, and no proof-level blockers. The stale case records
`hashVerified: false`; the detached cases intentionally keep
`hashVerified: true` when the hash is still bound and block solely on missing or
orphaned proof dependencies.

Runtime P3 with required GUI evidence is green at
`docs/evidence/agent-runtime-p3-validation/2026-05-09T14-14-54-279Z/dashboard-index.json`.

This changes rollback from "applied through an audited workbench action" to
"applied only when the dry-run proof is still live-bound, with stale and
detached proof attempts visibly and contractually blocked." The next
chronological slice should move from rollback proof guardrails to import/package
activation replay: prove that a forked harness package cannot activate live
unless its imported workflow hash, activation id, worker binding, rollback
target, replay fixtures, and policy posture all match the reviewed package
manifest.

## Current State

### Roadmap State

`docs/roadmap.md` defines the relevant sequence:

- Phase 1: workflow runtime parity.
- Phase 2: harness componentization.
- Phase 3: harness-as-workflow.

The phrasing is already directionally right, but the next implementation leg
should treat Phase 2 and Phase 3 as one continuous migration:

- first make every live harness kernel an executable component contract;
- then bind those contracts into a blessed workflow graph;
- then dogfood live turns through that graph;
- then allow forked harness activation.

### Code State

The repository already has more than a sketch:

- `packages/agent-ide/src/runtime/harness-workflow.ts` defines
  `DEFAULT_AGENT_HARNESS_COMPONENTS`, `HARNESS_FLOW`,
  `runtimeBindingFor`, `makeDefaultAgentHarnessWorkflow`, and
  `forkDefaultAgentHarnessWorkflow`.
- `crates/types/src/app/harness.rs` defines typed Rust harness component,
  slot, action frame, retry, timeout, approval, receipt, and worker binding
  contracts.
- `crates/services/src/agentic/runtime/harness.rs` explicitly states that the
  current projection does not replace the live executor yet. It lifts existing
  runtime kernels into stable workflow-addressable frames.
- `apps/autopilot/src-tauri/src/project/runtime.rs` executes many workflow node
  kinds through an action vocabulary, including task state, uncertainty,
  probes, budget gates, capability sequences, dry run, semantic impact,
  postconditions, verifiers, drift detection, quality ledgers, handoff, GUI
  validation, model calls, tools, approval gates, and outputs.
- `apps/autopilot/src-tauri/src/kernel/data/commands/local_engine_support.rs`
  already exposes worker workflow records with a default harness workflow id,
  activation id, and harness hash.

That means the missing work is not "invent a harness graph." The missing work
is making the harness graph the live orchestration authority and proving it
with receipts, tests, replay, GUI inspection, and activation gates.

### Autopilot GUI Pass

I ran the Autopilot GUI locally and exercised the Chat and Workflows surfaces.
The GUI launched with:

```bash
AUTOPILOT_LOCAL_GPU_DEV=0 AUTOPILOT_RESET_DATA_ON_BOOT=0 AUTOPILOT_DEV_CLEAN_INSTANCE=0 AUTOPILOT_TAURI_WATCH=0 npm run dev:desktop
```

The Vite surface came up at `http://127.0.0.1:1428`, the native shell opened,
and the Workflows surface was reachable from the left activity bar.

I also ran:

```bash
npm run validate:autopilot-gui-harness
```

That generated:

```text
docs/evidence/autopilot-gui-harness-validation/2026-05-07T12-03-49-923Z/result.json
```

The retained-query validation passed with all 8 retained queries and runtime
evidence.

GUI observations:

- The shell has a clear Workflows entry point.
- The Workflows surface already presents the graph as a real workbench with
  Create, Bind, Run, and Ship control clusters.
- A `Harness` header action opens the read-only `Default Agent Harness` graph.
- The default harness graph shows component nodes and action-kind counts.
- The header exposes a harness binding badge, lifecycle state, read-only state,
  validation status, and blocked activation state.
- The right rail already has Settings, Readiness, Data, Search, graph,
  waveform/run, and validation-style panels.
- The bottom shelf already has Selection Preview, Data Preview, Suggestions,
  Warnings, Fixtures, Checkpoints, Proposal Diff, Test Output, and Run Output.
- Forking is intentionally gated through a `Fork harness` action and readiness
  blockers.

GUI gap:

The GUI has the right surface area for harness orchestration, but live agent
turns are not yet experienced as node-by-node harness executions. The next UX
work should turn node execution, receipts, policy decisions, replay fixtures,
and fork activation into first-class operator affordances rather than hidden
side effects.

## Target End State

The target end state is:

- the blessed default live agent runtime is backed by a workflow activation;
- every important runtime decision maps to a harness component node;
- every component has typed input, output, error, timeout, cancellation, retry,
  policy, approval, capability, receipt, and replay contracts;
- the Autopilot GUI can inspect live harness execution at node level;
- default harness changes happen through bounded workflow proposals;
- forked harnesses are packageable but blocked from activation until tests,
  fixtures, slots, policy, and receipt checks pass;
- persistent workers can declare which harness workflow id, activation id, and
  hash they are using;
- the agent runtime dogfoods the same substrate exposed to users.

This is the proof of unified substrate: the default agent runtime, user-created
workflows, workflow-as-tool calls, worker package manifests, tests, proposals,
receipts, and GUI inspection all speak one graph/action-frame language.

### Workflow-As-Code Source Control End State

The harness workflow should not grow a parallel fake source-control system. It
should be a typed domain control plane over real workflow-as-code artifacts and
the existing editor/source-control substrate.

Right end state:

- Workflow graphs, tests, fixtures, proposals, manifests, package metadata, and
  harness metadata are versioned files.
- Every activation is bound to a workflow path, repo root, branch, proposal id,
  activation id, content hash, worker binding, and rollback target.
- When the workflow is inside a Git repository, the activation also records the
  base commit, activated commit or tree hash, and any branch or compare target.
- Push/activation is a validated workflow-code promotion, not just a metadata
  mutation.
- Rollback restores a prior activation binding and can point back to the
  corresponding workflow revision, commit, or tree.
- VS Code/OpenVSCode-derived substrate owns generic authoring affordances:
  explorer, file search, source control, branch compare, text editing, and
  diff review.
- Autopilot owns workflow-domain affordances: readiness gates, receipts,
  canaries, policy posture, slots, activation ledger, worker binding, runtime
  mode, rollback proof, and fork activation.

This split matters. Git is the right substrate for versioning, diffs, branches,
reviews, and file rollback. The workflow runtime still needs a typed activation
ledger because policy gates, secret slots, worker bindings, receipts, canaries,
and live runtime authority are domain objects that raw Git does not model
safely by itself.

The core binding object should be explicit:

```text
WorkflowRevisionBinding
- workflow_path
- repo_root
- branch
- base_revision
- activated_revision
- workflow_content_hash
- proposal_id
- activation_id
- worker_binding
- rollback_activation_id
- rollback_revision
```

The GUI should make this feel like one coherent flow: edit workflow-as-code,
review a typed proposal diff, validate gates, activate the worker binding, and
retain a one-operation rollback target that is tied to the previous workflow
revision.

## Non-Goals

This leg should not become:

- a broad persistent-agent dashboard expansion;
- a marketplace or worker-store effort;
- a new model registry/router project beyond the harness-facing binding
  contract;
- a prompt-only harness rewrite;
- a GUI redesign detached from runtime contracts;
- unrestricted self-modifying agents;
- user-editable live harness activation without policy, tests, replay, and
  bounded proposal review.

## Non-Negotiable Invariants

### 1. The live runtime remains trustworthy during migration

The workflow-backed harness should start in projection and shadow modes before
it becomes the default executor. Live agent correctness must not depend on a
half-ported graph path.

### 2. No visible node may fake execution

If a node is visible and runnable, runtime validation must either execute it
honestly or block with a concrete reason. "Looks runnable but skips" behavior
is not acceptable for the default harness.

### 3. Runtime decisions need receipt correlation

Planner choices, model routing, tool routing, approval decisions, policy
blocks, retries, repairs, verification results, output writes, and completion
states must be mapped to workflow node ids.

### 4. Forks are packages, not live authority by default

Forking the harness should create an editable package with lineage, tests,
fixtures, slots, proposals, and activation blockers. It must not silently
replace the blessed runtime.

### 5. AI mutation remains proposal-only

The default harness may be analyzed and proposed against by agents, but
AI-authored changes must go through bounded workflow proposals and human or
policy-defined acceptance gates.

### 6. Policy and wallet authority are not graph decorations

Approval rules, wallet capability grants, connector permissions, BYOK key
brokerage, and policy constraints must remain enforced by runtime authority.
The graph exposes and parameterizes them; it does not bypass them.

### 7. Replay captures must be deliberate

Replay fixtures need redaction posture, deterministic envelope flags, input and
output capture semantics, and policy-decision capture semantics. The graph must
not accidentally persist sensitive transcript or connector data.

### 8. Workflow source control is substrate, not decoration

Workflow save, proposal, push, activation, and rollback paths must be able to
bind to workflow-as-code revision state. If a workflow lives in Git, the
activation ledger should preserve the relevant revision identity instead of
only storing a UI-local metadata mutation.

## Component Contract

Every harness component must declare the same minimum contract:

| Field              | Requirement                                                              |
| ------------------ | ------------------------------------------------------------------------ |
| Component id       | Stable id used by TS workflow nodes and Rust action frames.              |
| Kind               | Typed harness component kind, mapped to a workflow node type.            |
| Version            | Component version for compatibility and activation checks.               |
| Kernel ref         | Runtime implementation reference or adapter boundary.                    |
| Input schema       | JSON schema or Rust/TS generated schema for accepted input.              |
| Output schema      | JSON schema or Rust/TS generated schema for produced output.             |
| Error schema       | Typed error classes and retryability semantics.                          |
| Timeout            | Default timeout, override policy, and cancellation behavior.             |
| Retry              | Retry class, max attempts, backoff, idempotency posture.                 |
| Capability scope   | Model, tool, wallet, connector, memory, policy, or evidence scopes.      |
| Approval semantics | Whether approval is never, conditional, required, or resumable.          |
| Receipt binding    | Event and evidence kinds mapped to workflow node ids.                    |
| Replay envelope    | Input/output/policy capture, determinism, redaction, fixture support.    |
| UI representation  | Node title, group, icon, inspector summary, logs, warnings, and actions. |
| Activation checks  | Slot requirements and validation blockers before live use.               |

No component should be considered complete until it has the TS graph contract,
Rust action-frame contract, runtime adapter, receipt mapping, replay behavior,
tests, and UI affordance.

## Component Inventory

The default harness should be decomposed into these live-capable components.
The names below are intentionally close to the current projection so the
migration can be incremental.

| Component                 | Purpose                                                                           | Priority |
| ------------------------- | --------------------------------------------------------------------------------- | -------- |
| Planner                   | Produce next plan step from session state, user request, and capability context.  | P0       |
| Task state                | Maintain objective, facts, uncertainty, stale facts, blockers, and evidence refs. | P0       |
| Uncertainty gate          | Decide ask/retrieve/probe/dry-run/execute/verify/escalate/stop.                   | P0       |
| Budget gate               | Bound reasoning, tool calls, retries, wall time, and verification spend.          | P0       |
| Capability sequencer      | Discover, select, sequence, and retire capabilities.                              | P0       |
| Model router              | Select model binding under model policy and deployment profile.                   | P0       |
| Model call                | Invoke selected model with request/response capture and streaming events.         | P0       |
| Tool router               | Select tool, connector, MCP, workflow-tool, or dry-run path.                      | P0       |
| Policy gate               | Enforce runtime, approval, trust, data, and side-effect policy.                   | P0       |
| Approval gate             | Interrupt, present decision, resume, reject, or edit action.                      | P0       |
| Wallet capability         | Request, check, lease, revoke, and receipt wallet-backed authority.               | P1       |
| MCP provider              | Resolve MCP server, scope, availability, and containment.                         | P1       |
| MCP tool call             | Invoke MCP tool with containment, request/response hashes, and receipts.          | P1       |
| Plugin tool call          | Invoke local/plugin tool through governed binding.                                | P1       |
| Connector call            | Invoke external connector with auth, policy memory, and idempotency.              | P1       |
| Workflow tool call        | Execute child workflow as a typed tool with lineage.                              | P1       |
| Probe runner              | Run cheap bounded validation for a hypothesis.                                    | P1       |
| Dry-run simulator         | Preview side effects and compare mutation risk before execution.                  | P1       |
| Memory read               | Retrieve scoped memory with provenance and staleness posture.                     | P1       |
| Memory write              | Persist memory with policy, summarization, and provenance.                        | P1       |
| Semantic impact analyzer  | Estimate behavioral or code impact before applying changes.                       | P2       |
| Postcondition synthesizer | Generate concrete verification conditions from task intent.                       | P2       |
| Verifier                  | Run tests, checks, assertions, or semantic verification.                          | P0       |
| Drift detector            | Detect state, context, dependency, or output drift.                               | P2       |
| Retry policy              | Bound retries and classify retryable failures.                                    | P0       |
| Repair loop               | Produce fix-up attempts from typed failure state.                                 | P1       |
| Merge judge               | Decide accept/merge/retry/escalate for competing outputs.                         | P2       |
| Quality ledger            | Record score, risks, unresolved issues, and confidence.                           | P1       |
| Handoff bridge            | Package state for another worker or human handoff.                                | P2       |
| GUI harness validator     | Validate GUI surfaces against retained harness scenarios.                         | P2       |
| Completion gate           | Decide done/continue/escalate with stop-condition evidence.                       | P0       |
| Receipt writer            | Persist receipts and node correlations.                                           | P0       |
| Output writer             | Materialize final response, artifact, patch, or external delivery.                | P0       |

P0 components must exist before the default live agent runtime can be driven
by the workflow graph. P1 components are needed for serious dogfood. P2
components can mature after shadow mode starts but before broad fork activation.

## Runtime Architecture

### Layer 1: Live Runtime Kernel

The existing runtime kernel remains the source of actual authority for:

- session lifecycle;
- transcript continuity;
- execution queue;
- approvals and resumability;
- policy enforcement;
- tool and connector execution;
- wallet capability checks;
- PII and redaction;
- receipts;
- output materialization.

During the migration, this layer exports component kernels and event hooks
instead of being replaced wholesale.

### Layer 2: Harness Component Adapter

Each runtime kernel gets a harness adapter that knows how to:

- build a `HarnessActionFrame`;
- validate input and bound slots;
- call the live kernel or simulator;
- emit typed events;
- map receipts to workflow node ids;
- provide replay input/output captures;
- expose activation blockers.

This layer is the bridge between `RuntimeAgentService` and the workflow graph.

### Layer 3: Workflow Activation

A harness workflow activation compiles:

- workflow id;
- activation id;
- harness hash;
- workflow revision binding;
- component versions;
- slot bindings;
- model/tool/approval/memory/output policy;
- tests and replay fixtures;
- production profile;
- activation blockers and warnings.

The default activation is read-only and blessed. Fork activations are blocked
until validation mints a new activation id.

### Layer 4: Runtime Orchestrator

The orchestrator executes the active harness activation. It should support:

- projection mode: render the graph and metadata only;
- shadow mode: run live runtime and graph action frames side by side;
- gated mode: graph drives selected components while live runtime remains
  fallback authority;
- live mode: graph activation is the default runtime control plane.

### Layer 5: GUI and Package Surface

The GUI and package layer expose:

- graph topology;
- node config and slots;
- runtime mode;
- read-only vs fork state;
- activation readiness;
- run timeline;
- node IO;
- receipts;
- replay fixtures;
- proposal diffs;
- export/import packages;
- worker harness bindings.

## Chronological Plan

### Phase 0: Lock The Existing Projection

Goal: preserve the useful existing harness projection while preventing it from
being mistaken for full live orchestration.

Build:

- a short doc string in the GUI that distinguishes projection, shadow, gated,
  and live modes;
- a visible mode badge on harness workflows;
- a runtime capability check that reports which components are projection-only,
  simulated, shadow-ready, or live-ready;
- a generated component inventory diff between TS and Rust contracts;
- a no-regression test for default harness graph rendering, slot binding,
  worker binding, and fork lineage.

Exit criteria:

- The `Default Agent Harness` graph opens as read-only.
- The GUI reports activation state truthfully.
- Component inventory is generated or validated from shared contract data.
- Forking remains blocked from live use.

### Phase 1: Normalize The Action-Frame Contract

Goal: make TS node definitions, Rust validation, Rust execution, SDK events,
and receipt bindings share one action-frame vocabulary.

Build:

- a canonical `HarnessActionFrame` schema with id, kind, labels, ports,
  schemas, slots, policy, approval, timeout, retry, and receipts;
- generated TS types from Rust or generated Rust types from a shared schema;
- validation that every harness component has a node type and every node type
  maps to a valid action kind;
- stable error classes for blocked, unsupported, simulated, policy-blocked,
  approval-required, timeout, retry-exhausted, and receipt-missing cases;
- a fixture format for component-level input/output replay.

Exit criteria:

- No harness component can exist only in TS or only in Rust.
- Runtime validation explains unsupported components before execution.
- Component tests can run without a full chat/session path.

### Phase 2: Extract Live Runtime Kernels Into Components

Goal: convert `RuntimeAgentService` from a monolithic owner of all harness
behavior into an orchestrator over component kernels.

Build:

- planner component adapter;
- task-state component adapter;
- uncertainty gate adapter;
- budget gate adapter;
- model router and model call adapters;
- tool router adapter;
- policy and approval gate adapters;
- verifier adapter;
- retry, repair, completion, receipt, and output adapters;
- basic component registry in Rust with explicit capability scopes;
- component-level unit tests over retained fixtures.

Exit criteria:

- P0 component kernels can be invoked independently.
- Chat/session runtime still behaves the same through the existing path.
- Every P0 component emits a node-correlatable event.

### Phase 3: Receipt Correlation And Replay

Goal: make every live runtime turn inspectable through harness graph nodes.

Build:

- receipt binding from plan/routing/workload/execution/policy events to
  workflow node ids;
- per-node run attempt records with input, output, error, duration, and event
  refs;
- redacted replay fixture capture for P0 and P1 components;
- replay comparison between previous and current component versions;
- GUI node inspector sections for latest input, output, policy decision,
  receipt refs, replay envelope, and warnings.

Exit criteria:

- A live agent turn produces a harness-node timeline.
- Selecting a harness node shows the latest relevant decision and receipt refs.
- Replay fixtures can reproduce component outputs or explain nondeterminism.

### Phase 4: Shadow Harness Execution

Goal: run the workflow activation beside the live runtime until behavior and
events line up.

Build:

- shadow runner that consumes the same session state and proposed actions;
- diffing of live vs graph-selected decisions;
- stop reason, approval, routing, tool, verification, and output comparison;
- shadow evidence bundle written under `docs/evidence` or runtime trace
  storage;
- GUI compare panel for live vs shadow node results;
- failure classification for harmless divergence, policy divergence, missing
  receipt, and behavioral regression.

Exit criteria:

- Retained chat/workflow dogfood runs produce shadow reports.
- The default harness graph explains live runtime decisions without driving
  them yet.
- P0 divergence rate is low enough to begin gated execution.

### Phase 5: Gated Default Harness Execution

Goal: let the workflow activation drive selected low-risk components while the
legacy runtime path remains fallback authority.

Build:

- feature flag for component-by-component graph authority;
- live execution for planner/task-state/uncertainty/budget first;
- then model routing/model call;
- then verifier/retry/completion/output;
- finally policy/approval/tool/router paths after receipts are stable;
- automatic fallback and incident receipts for graph execution failures;
- GUI mode controls for default, shadow, and gated diagnostics.

Exit criteria:

- The default agent runtime can run through graph authority for P0
  non-side-effect components.
- Fallbacks are explicit, receipted, and visible.
- No hidden bypass path is presented as graph success.

### Phase 6: Full Default Live Harness

Goal: promote the blessed default harness workflow activation to the default
runtime control plane.

Build:

- default worker binding to harness workflow id, activation id, and hash;
- workflow revision binding on the blessed activation, including workflow path,
  content hash, and revision identity when Git is available;
- live orchestration through the compiled harness graph;
- node-level streaming events in the GUI;
- durable run records linked to harness node attempts;
- activation hash included in SDK, CLI, GUI, and worker records;
- conformance test proving a standard live chat turn maps to graph nodes.

Exit criteria:

- The default live agent runtime is driven by the blessed harness activation.
- Users can inspect why the harness planned, routed, asked, executed, verified,
  retried, repaired, or stopped.
- Runtime, SDK, CLI, and GUI all report the same harness binding.

### Phase 7: Forkable Harness Activation

Goal: allow advanced users to fork the harness and activate forks safely.

Build:

- fork package export/import with component versions and slot manifests;
- source-control-backed proposal diffs for workflow graph, tests, fixtures,
  manifests, package metadata, and harness metadata;
- activation wizard for tests, fixtures, live bindings, policy, wallet grants,
  replay samples, output contracts, and production profile;
- proposal review for graph/config/metadata/sidecar diffs;
- compatibility checks against the blessed harness version;
- canary and rollback controls;
- worker-level selection of a validated harness activation.

Exit criteria:

- Forking produces an editable package with lineage.
- Activation is blocked until validation passes.
- A persistent worker can point to a forked harness activation by id.
- Rollback to the blessed default harness is one operation and fully receipted.
- Rollback can identify the workflow revision, commit, or tree that produced
  the prior activation.

## GUI Requirements

The current GUI has the foundation. The next leg should add or harden the
following operator affordances.

### Already Present

- Workflows left-nav entry.
- Graph/proposals/executions tabs.
- Create, Bind, Run, Ship header clusters.
- `Harness` button to open the default graph.
- `Fork harness` action.
- Read-only harness badge.
- Harness worker binding badge.
- Harness settings summary with template, activation, components, and slots.
- Fork lineage and activation blocker summaries.
- Readiness checklist.
- Node selection preview.
- Node IO workbench.
- Bottom shelf for suggestions, warnings, fixtures, checkpoints, proposal diff,
  tests, and run output.
- Stable selectors for dogfood automation.

### Required Next

- Runtime mode badge: projection, shadow, gated, live.
- Component readiness badge: projection-only, simulated, shadow-ready,
  live-ready.
- Node execution timeline for live harness turns.
- Node decision explainer for planner, uncertainty, budget, router, policy,
  approval, verifier, retry, and completion gates.
- Receipt refs and replay envelope visible on every harness component node.
- Live vs shadow comparison panel.
- Collapsible and expandable node groups for complex harness phases, with
  typed boundary ports and warning/receipt/status rollups.
- Harness activation wizard for forked graphs.
- Slot binding editor specialized for model, tool, memory, approval, wallet,
  verifier, output, retry, and handoff policies.
- Component diff view between blessed and forked harnesses.
- Canary, rollback, and fallback visibility.
- Worker binding picker that shows workflow id, activation id, hash, mode, and
  validation age.
- Source-control posture that shows workflow path, branch, dirty state,
  proposal id, activation revision, compare target, and rollback revision.
- Dogfood launcher for retained chat queries, workflow scratch probe, and
  harness shadow suites.

### Workflow-As-Code UI Boundary

Use the VS Code/OpenVSCode substrate for generic code-workflow mechanics:

- file explorer for workflow bundle files and sidecars;
- Monaco/source editor for workflow JSON, tests, fixtures, manifests, and
  generated package files;
- source-control view for dirty files, branch state, staging, commit posture,
  and compare target;
- diff editor for proposal review, fork comparison, activation changes, and
  rollback preview;
- search across workflow files, proposals, receipts, fixtures, and manifests.

Keep Autopilot-specific workflow controls in the workflow GUI:

- graph canvas and grouped harness topology;
- activation wizard and readiness gates;
- slot binding, policy posture, canary status, and receipt coverage;
- worker binding picker and activation ledger;
- rollback drill, rollback execution, and rollback proof;
- live/shadow/gated runtime timeline and node-level receipt/replay inspectors.

The design goal is not to turn the workflow GUI into a raw code editor. The
goal is to make workflow-as-code feel native: the generic authoring substrate
handles files and diffs, while the workflow workbench handles runtime meaning.

### UI Primitive Decision Gate

When adding a new workflow GUI element for advanced harness orchestration, use a
short design-context gate before choosing or inventing the component. The goal
is a broad shared interaction vocabulary, not imitation of another product.

Required decision sequence:

1. Check existing IOI/Autopilot primitives first.
2. Review the AIP reference evidence for comparable graph/workbench mechanics:
   `docs/evidence/harness-as-workflow-aip-reference/2026-05-06/README.md`.
3. Prefer the shared vocabulary when it fits: rails, mini maps, tabs, split
   panes, bottom shelves, inspectors, workbench panels, tables, status chips,
   cards, legends, expand/collapse groups, focused-node workbenches, and
   branch/compare banners.
4. State why the chosen primitive fits the operator task: inspection,
   navigation, comparison, activation, rollback, receipt tracing, replay,
   policy review, or output control.
5. Avoid bespoke UI when a familiar primitive already covers the interaction.
6. Preserve IOI semantics and visual language: receipts, activation state,
   policy posture, slots, worker bindings, replay, rollback, runtime modes,
   workflow revision binding, and proposal-only mutation.

This gate should run before implementation decisions for right rails, mini
maps, tabs, split panes, cards, expand/collapse controls, status chips, tables,
workbench panels, activation surfaces, and rollback surfaces.

### Collapsible Harness Groups

Complex harness workflows need a screen-real-estate model that lets users move
between operational altitude and component detail without losing trust. The
default harness should support visual grouping where a cluster can collapse
into one node and expand back into its internal graph.

Recommended default groups:

| Group        | Components                                                                                                        |
| ------------ | ----------------------------------------------------------------------------------------------------------------- |
| Cognition    | Planner, task state, uncertainty gate, budget gate, probe runner.                                                 |
| Routing      | Capability sequencer, model router, tool router.                                                                  |
| Authority    | Policy gate, approval gate, wallet capability.                                                                    |
| Execution    | Model call, MCP provider, MCP tool call, plugin tool call, connector call, workflow tool call, dry-run simulator. |
| State        | Memory read, memory write, drift detector.                                                                        |
| Verification | Semantic impact analyzer, postcondition synthesizer, verifier, quality ledger.                                    |
| Recovery     | Retry policy, repair loop, merge judge.                                                                           |
| Output       | Completion gate, receipt writer, output writer, handoff bridge.                                                   |

Rules:

- Collapse is a visual abstraction, not semantic hiding.
- A collapsed group must expose typed boundary ports, schema summaries, slot
  requirements, and activation state.
- Warnings, blockers, failed tests, approval requirements, side effects,
  receipt gaps, replay gaps, and live/shadow divergence must roll up to the
  collapsed node.
- Clicking a rollup issue should expand the group and focus the exact inner
  node.
- Search, validation, run timelines, proposal diffs, and receipt links must be
  able to address inner nodes even when the group is collapsed.
- Package export should preserve expanded internals, group metadata, and the
  user's preferred collapse state separately from runtime semantics.

This gives the Palantir-style benefit of compact graph altitude while keeping
IOI's stronger runtime guarantees visible.

### Reference Mechanics From AIP Browser Pass

The Palantir AIP pipeline pass is useful because it shows a mature pattern for
managing dense operational graphs without making the canvas carry every
interaction. These are product mechanics to consider for the harness leg, not
visual requirements. The user-provided screenshot evidence is indexed in
`docs/evidence/harness-as-workflow-aip-reference/2026-05-06/README.md`.
The browser-control workflow used to inspect that app is captured separately in
`docs/plans/browser-use-master-guide.md`.

Useful mechanics:

- Right rail as output/control inventory: show produced outputs, deployment or
  mapping status, and output settings without forcing users to open every node.
- Right rail mode strip: keep narrow icon tabs for output inventory, graph
  search, branch/change comparison, deployment posture, runtime/build settings,
  schedules, file tree, tests, and sources.
- Mini graph in the rail: provide a compressed graph overview that stays useful
  when the main canvas is zoomed into an expanded group or detailed workbench.
- Bottom workbench that changes with selection: use the bottom area for
  selection preview, input/output data, transformations, warnings, fixtures,
  checkpoints, proposal diff, tests, and run output.
- Focused node workbench: allow a selected or expanded node/group to take over
  the main work area with a toolbar, `Expand all`, close/apply controls, and
  row-level step inspection.
- Deep-linkable expanded state: the browser URL can represent a focused
  cluster/node path. Harness groups should likewise support durable links to a
  selected component, expanded group, selected replay fixture, or run attempt.
- Expand-all and close controls: make it easy to descend into detail and return
  to the compact graph without losing context.
- Legend with visibility toggles: expose categories, counts, and eye/open
  toggles so large graphs can be filtered by component family or runtime state.
- Read-only and branch posture banners: make permission, fork, branch, compare,
  proposal, saved, and deploy posture visible at the top of the workbench.
- Status rollups on output cards: show mapping completeness, deployment
  posture, validation status, or receipt health in compact cards.
- File-tree navigation beside the graph: expose a dense list of graph objects
  or components so users can navigate by name without panning the canvas.
- Empty-state panels with local actions: schedules, tests, sources, and search
  panels should show clear empty states and relevant local actions instead of
  generic blank rails.
- Row-level status in expanded workbenches: inner steps should show applied,
  previewable, deprecated, warning, blocked, disabled, or upgrade-needed states
  directly on the row.
- Input/output table affordances: previews should expose row count, column
  count, schema/column search, column stats, input sampling, and row-count
  calculation in the same workbench as the selected step.

How this maps to the harness leg:

- The default harness graph needs a right rail that can show worker binding,
  activation, outputs, receipt health, policy posture, and selected-node
  details as separate modes.
- Harness rail modes should include at least: receipts/outputs, search,
  live-vs-shadow changes, activation/deploy posture, runtime settings,
  schedules/triggers, component tree, tests, sources/inputs, policy, and
  capabilities.
- Collapsed harness groups should pair with a mini graph so users can navigate
  the whole runtime while one group is expanded.
- Expanded groups should get a focused workbench with inner-node steps,
  boundary IO, replay fixtures, live/shadow comparison, warnings, and policy
  decisions.
- Expanded harness groups should be URL-addressable by group id, component id,
  run id, replay fixture id, and selected panel so links can jump directly to a
  failing receipt or activation blocker.
- The top bar should make read-only blessed mode, fork lineage, proposal mode,
  activation state, and live/shadow/gated/live runtime mode impossible to miss.
- Output and receipt cards should behave like first-class operational objects,
  not only terminal nodes on the canvas.
- A component tree panel should provide dense navigation over all harness
  components, slots, tests, policy gates, outputs, and receipt writers.
- Tests and schedules/triggers panels should keep their own empty states,
  create actions, and readiness warnings instead of hiding inside global
  settings.
- `Expand all` should exist at group, phase, and selected-node levels, but
  expanded state must remain UI state rather than runtime semantics.
- Graph filters should support component kind, policy side-effect class,
  approval requirement, readiness state, run status, failed receipts, and
  live/shadow divergence.
- The bottom shelf should remain selection-sensitive and should not become a
  generic log dump. It should promote the exact workbench needed for the
  selected graph altitude.
- Component rows in expanded harness workbenches should show run status,
  replay status, deprecation/version warnings, policy blockers, preview/dry-run
  availability, and upgrade/proposal affordances.
- Harness input/output previews should mirror the table mechanics for runtime
  payloads: schema fields, redaction status, sampled fixtures, event counts,
  receipt refs, and replay row/attempt counts.

### UX Principle

The harness graph should feel like an execution workbench, not a diagram. A
user should be able to select a node and answer:

- What input did this component see?
- What policy and slots constrained it?
- What decision did it make?
- What evidence or receipts support that decision?
- What changed from the blessed default?
- Can this node be replayed?
- Did the shadow graph agree with live runtime?
- Is this fork safe to activate?
- If this is a collapsed group, which inner node owns the current status,
  warning, receipt, or blocker?

## Dogfood Plan

### Lane 1: Retained Chat Queries

Run the existing retained GUI harness queries through projection and shadow
mode. Capture:

- harness graph opened;
- active harness binding;
- live turn receipt mapping;
- shadow comparison;
- GUI cleanliness.

### Lane 2: Workflow Scratch Probe

Continue using the workflow scratch GUI dogfood that manually builds primitive
workflows instead of loading hidden templates. Add harness-specific assertions:

- open default harness;
- inspect component counts;
- select P0 components;
- capture node input/output after a run;
- fork harness;
- observe activation blockers;
- export package only after readiness checks.

### Lane 3: Default Agent Runtime Dogfood

Use the normal agent runtime to edit workflow and harness code while it is
itself shadowed by the harness graph. This is the real substrate proof.

Capture:

- agent prompt;
- live runtime events;
- graph action frames;
- divergence summary;
- node-level receipts;
- final response and verification.

### Lane 4: Forked Harness Canary

Create a harmless fork that changes a low-risk policy, such as a verifier
threshold or retry bound. Run retained scenarios in canary mode. Require:

- component diff;
- replay fixture pass;
- no policy regressions;
- canary rollback proof;
- explicit activation id.

### Lane 5: Worker Binding Proof

Bind a persistent worker record to a validated harness activation. The GUI,
runtime, SDK, and CLI should all agree on:

- harness workflow id;
- activation id;
- harness hash;
- validation status;
- component version set;
- policy profile.

## Validation Matrix

| Gate                         | Command or evidence                                                                                                         | Purpose                                                                                     |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| GUI harness retained queries | `npm run validate:autopilot-gui-harness`                                                                                    | Proves retained GUI preflight and clean harness contract.                                   |
| Workflow wiring              | `npm run test -- apps/autopilot/src/windows/AutopilotShellWindow/workflowComposerWiring.test.ts` or existing package script | Proves GUI selectors, harness controls, and workflow surface wiring.                        |
| Runtime P3 contract          | `npm run validate:agent-runtime-p3`                                                                                         | Proves smarter runtime and harness contract lanes.                                          |
| Runtime tests                | `npm run test:agent-runtime-p3`                                                                                             | Exercises agent runtime P3 test surface.                                                    |
| Rust harness tests           | targeted `cargo test` for `agentic::runtime::harness` and `ioi_types::app::harness`                                         | Proves component contracts and receipt mapping.                                             |
| Workflow execution tests     | targeted Tauri/project runtime tests                                                                                        | Proves visible node kinds execute or block honestly.                                        |
| Shadow comparison            | new harness shadow evidence bundle                                                                                          | Proves graph/action-frame decisions match live runtime.                                     |
| Fork activation              | new activation readiness tests                                                                                              | Proves forked harness cannot activate without slots, fixtures, policy, tests, and receipts. |
| Worker binding               | local engine worker support tests                                                                                           | Proves worker records expose harness id, activation id, and hash.                           |

## Acceptance Criteria

This leg is complete when all of the following are true:

- The default harness graph is generated from shared TS/Rust component
  contracts, not duplicated ad hoc lists.
- Every P0 harness component has typed input, output, error, timeout, retry,
  capability, approval, receipt, replay, and UI contracts.
- A normal live agent turn produces a node-level harness timeline.
- Live runtime receipts map to workflow node ids.
- The GUI can show node input, output, policy decision, receipts, and replay
  status for the harness turn.
- Shadow mode compares live runtime decisions against graph action frames.
- Gated mode can safely let selected components be graph-driven.
- Full live mode uses the blessed default harness activation as the default
  runtime control plane.
- Forking the harness creates an editable, packageable workflow with lineage.
- Forked harness activation is blocked until validation, tests, fixtures,
  slots, policy, and receipt mapping pass.
- Persistent workers can declare harness workflow id, activation id, and hash.
- SDK, CLI, GUI, worker records, and runtime traces expose the same harness
  binding.

## Risks And Mitigations

| Risk                                                   | Mitigation                                                                              |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------- |
| Graph path diverges from live runtime semantics.       | Shadow mode with decision diffing before promotion.                                     |
| Component contracts duplicate between TS and Rust.     | Generate one side or validate both from a shared manifest.                              |
| GUI implies forked harnesses are live-ready too early. | Explicit projection/shadow/gated/live badges and activation blockers.                   |
| Replay captures sensitive data.                        | Redaction policy, fixture scopes, deterministic envelope metadata, and opt-in captures. |
| Policy is weakened by graph editability.               | Runtime authority remains final; graph slots parameterize policy but do not bypass it.  |
| Half-supported nodes create false confidence.          | Unsupported/simulated/live readiness states and validation blockers.                    |
| Migration regresses normal chat.                       | Component-by-component gated rollout with fallback receipts.                            |
| Fork activation becomes too hard to understand.        | Activation wizard, actionable blockers, component diff, and canary/rollback controls.   |

## Immediate Work Queue

1. Add a harness execution mode model shared by TS workflow metadata and Rust
   activation records: `projection`, `shadow`, `gated`, `live`.
2. Add a component readiness status model:
   `projection_only`, `simulated`, `shadow_ready`, `live_ready`.
3. Create a shared harness component manifest test that compares TS
   `DEFAULT_AGENT_HARNESS_COMPONENTS` with Rust `default_agent_harness_components`.
4. Add component-level fixtures for P0 components.
5. Add receipt correlation coverage for planner, routing, workload, approval,
   policy, verifier, completion, and output events.
6. Add a shadow runner that consumes live turn state and emits graph decision
   diffs.
7. Extend the GUI node inspector with harness node receipts, live/shadow
   comparison, replay status, and activation blockers.
8. Add collapsible harness groups with typed boundary ports, rollup badges,
   inner-node search/focus, and preserved group metadata.
9. Add deep-linkable expanded harness state for group id, component id, run id,
   replay fixture id, and selected rail/bottom panel.
10. Add harness-specific right rail modes for receipts/outputs, search,
    live-vs-shadow changes, activation posture, runtime settings,
    schedules/triggers, component tree, tests, sources/inputs, policy, and
    capabilities.
11. Add row-level expanded workbench status for component run state, replay
    state, deprecation/version warnings, policy blockers, preview/dry-run
    availability, and upgrade/proposal affordances.
12. Add a fork activation wizard and block live worker binding until activation
    id minting succeeds.
13. Add a retained dogfood run where the default agent edits workflow code while
    the harness graph shadows the turn.
14. Promote gated graph authority one P0 component cluster at a time.

## Recommended First PR Slice

The first implementation slice should be deliberately small:

- introduce `harnessExecutionMode` and `componentRuntimeStatus` fields;
- surface them in the default harness workflow metadata and GUI badges;
- add validation that default harness components exist in both TS and Rust;
- add a read-only GUI note explaining projection vs shadow vs gated vs live;
- extend `validate:autopilot-gui-harness` expectations to capture the mode
  badge.

That slice will not make the harness live-driven yet, but it creates the
language the rest of the migration needs and prevents the current projection
from being over-claimed.

## Open Questions

- Should the canonical component manifest be Rust-first, JSON-schema-first, or
  generated from a small language-neutral manifest?
- Should shadow mode run synchronously inside the live turn, asynchronously
  after the turn, or both depending on latency profile?
- What is the minimum divergence threshold before promoting a component from
  shadow-ready to gated?
- Which policy decisions are allowed to be parameterized by a forked harness,
  and which must remain fixed by the runtime or wallet authority?
- Should forked harness activations be user-local only at first, or can they be
  bound to persistent workers after canary proof?

## Final North Star

The default live agent should be able to say, in the GUI and in receipts:

```text
I ran under harness workflow default-agent-harness,
activation default-agent-harness@v1,
hash <hash>.

Planner chose this step.
Uncertainty gate chose this action.
Budget gate allowed it.
Policy gate constrained it.
Tool/model router selected this binding.
Verifier accepted or rejected it.
Completion gate stopped for this reason.

Every decision is visible as a workflow node.
Every node can be tested, replayed, proposed against, and safely forked.
```

That is the end state: not a workflow skin over an agent, but the agent runtime
proving the workflow substrate by living inside it.
