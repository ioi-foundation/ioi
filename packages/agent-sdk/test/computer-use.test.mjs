import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  Agent,
  COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
  Thread,
  compileComputerUseModelActionAdapter,
  commitGateForComputerAction,
  commitGateRequiresConfirmation,
  computerActionHasExternalEffect,
  computerActionHasGrounding,
  createRuntimeSubstrateClient,
  defaultComputerUseHarnessContract,
  evaluateComputerUseTrajectory,
  exportComputerUseBenchmarkCase,
  humanHandoffForComputerUseBoundary,
  isActionProposalReadyForExecution,
  observationRetentionAllowsRawPersistence,
  outcomeContractForGoal,
  planComputerUseHarnessImprovement,
  recoveryPolicyForComputerUseFailure,
  runComputerUseBenchmarkSuite,
  runComputerUseShadowReplay,
} from "../dist/index.js";
import { createMockRuntimeSubstrateClient } from "../dist/testing.js";
import { startRuntimeDaemonService } from "../../runtime-daemon/src/index.mjs";
import { startFakeNativeBrowserCdpServer } from "../../runtime-daemon/src/native-browser-cdp-test-fixture.mjs";

function tempClient() {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-agent-sdk-computer-use-"));
  return {
    cwd,
    client: createMockRuntimeSubstrateClient({
      cwd,
      checkpointDir: path.join(cwd, ".ioi", "agent-sdk"),
    }),
  };
}

function runtimeBridgeEnvelope({
  eventKind,
  sourceEventKind = eventKind,
  idempotencyKey,
  itemId,
  turnId = "",
  createdAt,
  payload,
  payloadSchemaVersion = "ioi.runtime.event.v1",
  componentKind = null,
  workflowNodeId = null,
  receiptRefs = [],
  artifactRefs = [],
}) {
  return {
    event_kind: eventKind,
    source_event_kind: sourceEventKind,
    idempotency_key: idempotencyKey,
    item_id: itemId,
    turn_id: turnId,
    created_at: createdAt,
    component_kind: componentKind,
    workflow_node_id: workflowNodeId,
    payload_schema_version: payloadSchemaVersion,
    receipt_refs: receiptRefs,
    artifact_refs: artifactRefs,
    payload,
  };
}

const expectedComputerUseEventTypes = [
  "computer_use_environment_selected",
  "computer_use_lease_acquired",
  "computer_use_run_state",
  "computer_use_observation",
  "computer_use_affordance_graph",
  "computer_use_action_proposed",
  "computer_use_action_executed",
  "computer_use_verification",
  "computer_use_commit_gate",
  "computer_use_trajectory_written",
  "computer_use_cleanup",
];

const expectedUnavailableComputerUseEventTypes = [
  "computer_use_environment_selected",
  "computer_use_environment_unavailable",
  "computer_use_run_state",
  "computer_use_verification",
  "computer_use_cleanup",
];

test("computer-use contract projection exposes three lanes and behavioral loop", () => {
  const contract = defaultComputerUseHarnessContract();
  assert.equal(contract.schema_version, COMPUTER_USE_CONTRACT_SCHEMA_VERSION);
  assert.deepEqual(contract.required_lanes, ["native_browser", "visual_gui", "sandboxed_hosted"]);
  assert.ok(contract.required_loop_steps.includes("select_environment"));
  assert.ok(contract.required_loop_steps.includes("build_affordance_graph"));
  assert.ok(contract.required_loop_steps.includes("commit_or_handoff"));
  assert.ok(contract.required_contracts.includes("ActionProposal"));
  assert.ok(contract.required_contracts.includes("ObservationRetentionMode"));
  assert.equal(contract.requires_action_proposal_before_execution, true);
  assert.equal(contract.forbids_shadow_runtime_truth, true);
});

test("computer-use helpers require policy-gated proposals and grounded actions", () => {
  assert.equal(
    isActionProposalReadyForExecution({
      proposal_ref: "proposal:1",
      proposed_by: "model",
      model_role: "grounder",
      normalized_action_candidate: "click",
      target_ref: "target:submit",
      confidence: 92,
      rationale_summary: "submit button",
      predicted_postcondition: "form submitted",
      risk_assessment: "external_effect",
    }),
    false,
  );

  assert.equal(
    isActionProposalReadyForExecution({
      proposal_ref: "proposal:1",
      proposed_by: "model",
      model_role: "grounder",
      normalized_action_candidate: "click",
      target_ref: "target:submit",
      confidence: 92,
      rationale_summary: "submit button",
      predicted_postcondition: "form submitted",
      risk_assessment: "external_effect",
      policy_decision_ref: "policy:approved",
    }),
    true,
  );

  assert.equal(
    computerActionHasGrounding({
      action_ref: "action:1",
      action_kind: "click",
      observation_ref: "obs:1",
      payload_summary: "click submit",
      expected_postcondition: "form submitted",
    }),
    false,
  );

  assert.equal(
    computerActionHasGrounding({
      action_ref: "action:1",
      action_kind: "click",
      observation_ref: "obs:1",
      target_ref: "target:submit",
      payload_summary: "click submit",
      expected_postcondition: "form submitted",
    }),
    true,
  );
});

test("computer-use recovery and handoff helpers fail closed at sensitive boundaries", () => {
  const authPolicy = recoveryPolicyForComputerUseFailure({
    run_id: "run-auth",
    failure_mode: "auth_wall",
    lane: "native_browser",
    retry_budget: 2,
  });
  assert.equal(authPolicy.failure_class, "handoff");
  assert.equal(authPolicy.requires_human_handoff, true);
  assert.equal(authPolicy.fail_closed, true);
  assert.equal(authPolicy.retry_budget_delta, 0);
  assert.ok(authPolicy.allowed_actions.includes("pause_for_auth"));
  assert.ok(authPolicy.disallowed_actions.includes("enter_secret"));
  assert.ok(authPolicy.evidence_required.includes("handoff_state"));

  const driftPolicy = recoveryPolicyForComputerUseFailure({
    run_id: "run-drift",
    failure_mode: "visual_drift",
    retry_budget: 2,
  });
  assert.equal(driftPolicy.failure_class, "perception");
  assert.equal(driftPolicy.fail_closed, false);
  assert.equal(driftPolicy.retry_budget_delta, -1);
  assert.ok(driftPolicy.allowed_actions.includes("rebuild_target_index"));

  const handoff = humanHandoffForComputerUseBoundary({
    run_id: "run-auth",
    reason: "auth_wall",
    requested_user_action: "Sign in inside the browser window.",
  });
  assert.equal(handoff.status, "pending");
  assert.equal(handoff.evidence_retention, "prompt_visible_summary_only");
  assert.ok(handoff.forbidden_agent_actions.includes("enter_secret"));
  assert.equal(observationRetentionAllowsRawPersistence("local_redacted_artifacts"), false);
  assert.equal(observationRetentionAllowsRawPersistence("encrypted_local_raw_artifacts"), true);
});

test("computer-use outcome contracts create commit gates for external effects", () => {
  const action = {
    action_ref: "action-submit",
    action_kind: "click",
    target_ref: "target-submit",
    observation_ref: "obs-submit",
    payload_summary: "click target-submit",
    expected_postcondition: "confirmation screen appears",
    approval_ref: "policy-submit",
  };
  const outcome = outcomeContractForGoal({
    run_id: "run-submit",
    requested_outcome: "Prepare the form for submission.",
    success_criteria: ["The confirmation screen appears."],
    external_effect_policy: "confirmation_required",
  });
  const gate = commitGateForComputerAction({
    run_id: "run-submit",
    action,
    outcome_contract: outcome,
  });
  assert.equal(computerActionHasExternalEffect(action), true);
  assert.equal(gate.status, "pending_confirmation");
  assert.equal(gate.external_effect, true);
  assert.equal(gate.authority_required, "computer_use.external_effect");
  assert.equal(commitGateRequiresConfirmation(gate), true);

  const inspectGate = commitGateForComputerAction({
    run_id: "run-readonly",
    action: {
      action_ref: "action-inspect",
      action_kind: "inspect",
      observation_ref: "obs-readonly",
      payload_summary: "inspect page state",
      expected_postcondition: "page state is summarized",
    },
  });
  assert.equal(inspectGate.status, "not_required");
  assert.equal(inspectGate.external_effect, false);
  assert.equal(commitGateRequiresConfirmation(inspectGate), false);

  const prohibitedGate = commitGateForComputerAction({
    run_id: "run-prohibited",
    action,
    outcome_contract: outcomeContractForGoal({
      run_id: "run-prohibited",
      requested_outcome: "Inspect only.",
      external_effect_policy: "prohibited",
    }),
  });
  assert.equal(prohibitedGate.status, "blocked");
  assert.equal(prohibitedGate.user_confirmation_required, true);
});

test("computer-use trajectory eval projects pass and fail-closed outcomes", () => {
  const passed = evaluateComputerUseTrajectory({
    trace: {
      environmentSelection: {
        receipt_ref: "receipt-env",
        run_id: "run-eval",
        selected_lane: "native_browser",
        selected_session_mode: "owned_hermetic_browser",
      },
      lease: { lane: "native_browser", session_mode: "owned_hermetic_browser" },
      observation: { observation_ref: "observation-eval" },
      targetIndex: { target_index_ref: "target-index-eval" },
      actionProposal: { proposal_ref: "proposal-eval" },
      verification: {
        verification_ref: "verification-eval",
        status: "passed",
      },
      cleanup: { cleanup_ref: "cleanup-eval", status: "completed" },
      trajectory: {
        trajectory_ref: "trajectory-eval",
        run_id: "run-eval",
        entries: [
          { sequence: 1, event_kind: "select_environment" },
          { sequence: 2, event_kind: "observe" },
          { sequence: 3, event_kind: "propose_action" },
          { sequence: 4, event_kind: "verify_postcondition" },
          { sequence: 5, event_kind: "cleanup" },
        ],
      },
    },
  });
  assert.equal(passed.outcome, "passed");
  assert.equal(passed.score, 1);
  assert.equal(passed.failure_class, "unknown");
  assert.deepEqual(passed.missing_regression_gates, []);
  assert.deepEqual(passed.evidence_refs, [
    "receipt-env",
    "observation-eval",
    "target-index-eval",
    "proposal-eval",
    "verification-eval",
    "cleanup-eval",
    "trajectory-eval",
  ]);

  const blockedTrace = {
    environmentSelection: {
      run_id: "run-blocked",
      selected_lane: "sandboxed_hosted",
      selected_session_mode: "hosted_sandbox",
    },
    runState: { blocker_state: "adapter_unavailable" },
    observation: { observation_ref: "observation-blocked" },
    targetIndex: { target_index_ref: "target-index-blocked" },
    actionProposal: { proposal_ref: "proposal-blocked" },
    verification: {
      verification_ref: "verification-blocked",
      status: "blocked",
    },
    cleanup: { cleanup_ref: "cleanup-blocked", status: "not_required" },
    trajectory: {
      trajectory_ref: "trajectory-blocked",
      run_id: "run-blocked",
      entries: [{ sequence: 1, event_kind: "propose_action" }],
    },
  };
  const blocked = evaluateComputerUseTrajectory({ trace: blockedTrace });
  assert.equal(blocked.outcome, "blocked");
  assert.equal(blocked.score, 0.5);
  assert.equal(blocked.failure_class, "environment");
  assert.equal(blocked.failure_mode, "sandbox_unavailable");
  assert.equal(blocked.summary.includes("failed closed"), true);

  const improvementPlan = planComputerUseHarnessImprovement({
    trace: blockedTrace,
    eval: blocked,
  });
  assert.equal(improvementPlan.outcome, "blocked");
  assert.equal(improvementPlan.recovery_policy.failure_mode, "sandbox_unavailable");
  assert.equal(improvementPlan.patch_proposals[0].target_surface, "adapter");
  assert.equal(improvementPlan.shadow_replay.status, "required_before_promotion");
  assert.equal(improvementPlan.promotion_gate.status, "blocked_external_adapter");

  const benchmarkCase = exportComputerUseBenchmarkCase({
    trace: blockedTrace,
    eval: blocked,
    improvement_plan: improvementPlan,
  });
  assert.equal(benchmarkCase.export_mode, "redacted_regression");
  assert.equal(benchmarkCase.manifest.deterministic, true);
  assert.equal(benchmarkCase.manifest.raw_artifacts_included, false);
  assert.equal(benchmarkCase.failure_mode, "sandbox_unavailable");
  assert.equal(benchmarkCase.promotion_gate_ref, improvementPlan.promotion_gate.promotion_ref);

  const passedBenchmarkCase = exportComputerUseBenchmarkCase({
    eval: passed,
  });
  const benchmarkSuite = runComputerUseBenchmarkSuite({
    suite_ref: "suite-computer-use-regression",
    cases: [passedBenchmarkCase, benchmarkCase],
  });
  assert.equal(benchmarkSuite.case_count, 2);
  assert.equal(benchmarkSuite.average_score, 0.75);
  assert.equal(benchmarkSuite.passed_count, 1);
  assert.equal(benchmarkSuite.blocked_count, 1);
  assert.equal(benchmarkSuite.scorecard.pass_rate, 0.5);
  assert.equal(benchmarkSuite.scorecard.fail_closed_rate, 0.5);
  assert.equal(benchmarkSuite.hidden_runtime_shortcuts_forbidden, true);

  const shadowReplay = runComputerUseShadowReplay({
    improvement_plan: improvementPlan,
    replay_cases: [benchmarkCase],
    held_out_cases: [passedBenchmarkCase],
  });
  assert.equal(shadowReplay.status, "passed");
  assert.equal(shadowReplay.replayed_case_count, 1);
  assert.equal(shadowReplay.held_out_case_count, 1);
  assert.equal(shadowReplay.failed_gates.length, 0);
  assert.equal(shadowReplay.scorecard.hidden_runtime_shortcuts_forbidden, true);
});

test("computer-use model adapters normalize OpenAI-style actions into IOI proposals and actions", () => {
  const targetIndex = {
    target_index_ref: "target-index-browser",
    observation_ref: "observation-browser",
    coordinate_space_id: "viewport-browser",
    drift_state: "fresh",
    targets: [
      {
        target_ref: "target-submit",
        label: "Submit",
        role: "button",
        semantic_ids: ["button:submit"],
        selectors: ["button[type=submit]"],
        bounds: { x: 20, y: 10, width: 90, height: 40, coordinate_space_id: "viewport-browser" },
        confidence: 96,
        available_actions: ["click"],
      },
    ],
  };
  const result = compileComputerUseModelActionAdapter({
    adapter_kind: "openai_computer_use",
    run_id: "run-openai",
    observation_ref: "observation-browser",
    target_index: targetIndex,
    raw_model_output: {
      type: "click",
      x: 42,
      y: 28,
      confidence: 0.88,
      rationale: "Click the visible submit button.",
      safety_checks: [{ id: "provider-check", status: "review", summary: "Provider requested confirmation." }],
    },
    proposed_by: "mounted-openai-cua",
  });

  assert.equal(result.action_proposal.target_ref, "target-submit");
  assert.equal(result.action_proposal.policy_decision_ref, "policy_run-openai_openai_computer_use_click");
  assert.equal(result.action_proposal.confidence, 88);
  assert.equal(result.computer_action.action_kind, "click");
  assert.equal(result.computer_action.observation_ref, "observation-browser");
  assert.equal(result.computer_action.coordinate_space_id, "viewport-browser");
  assert.equal(result.computer_action.approval_ref, result.action_proposal.policy_decision_ref);
  assert.equal(result.grounding.grounding_status, "target_ref");
  assert.equal(result.safety_checks[0].status, "requires_approval");
  assert.equal(isActionProposalReadyForExecution(result.action_proposal), true);
  assert.equal(computerActionHasGrounding(result.computer_action), true);
});

test("computer-use model adapters normalize UI-TARS coordinates as observation-bound actions", () => {
  const result = compileComputerUseModelActionAdapter({
    adapter_kind: "ui_tars",
    run_id: "run-ui-tars",
    observation_ref: "observation-screen",
    target_index: {
      target_index_ref: "target-index-screen",
      observation_ref: "observation-screen",
      coordinate_space_id: "screen-1",
      drift_state: "fresh",
      targets: [],
    },
    raw_model_output: "click(128, 256)",
    proposed_by: "local-ui-tars",
    policy_decision_ref: "policy-ui-tars-coordinate-approved",
  });

  assert.equal(result.action_proposal.normalized_action_candidate, "click at (128, 256)");
  assert.equal(result.action_proposal.target_ref, null);
  assert.equal(result.computer_action.coordinate_space_id, "screen-1");
  assert.equal(result.grounding.grounding_status, "coordinate");
  assert.deepEqual(result.grounding.coordinate, { x: 128, y: 256 });
  assert.equal(result.safety_checks[0].status, "requires_approval");
  assert.equal(computerActionHasGrounding(result.computer_action), true);
});

test("browser prompts emit glass-box computer-use trace and runtime events", async () => {
  const { cwd, client } = tempClient();
  const agent = await Agent.create({
    model: { id: "local:auto" },
    local: { cwd },
    substrateClient: client,
  });
  const run = await agent.send("Use the browser to inspect https://example.com and explain next actions.", {
    metadata: { computerUse: true },
  });
  const streamed = [];
  for await (const event of run.stream()) {
    streamed.push(event);
  }
  assert.deepEqual(
    streamed.filter((event) => event.type.startsWith("computer_use_")).map((event) => event.type),
    expectedComputerUseEventTypes,
  );

  const trace = await run.inspect();
  const namedArtifact = await run.artifact("computer-use-trace.json");
  assert.equal(namedArtifact.name, "computer-use-trace.json");
  assert.equal(JSON.parse(namedArtifact.content).observation.url, "https://example.com");
  const environmentEvent = trace.events.find((event) => event.type === "computer_use_environment_selected");
  assert.ok(environmentEvent);
  assert.equal(environmentEvent.data.schema_version, COMPUTER_USE_CONTRACT_SCHEMA_VERSION);
  assert.equal(environmentEvent.data.computer_use_step, "select_environment");
  assert.equal(environmentEvent.data.environment_selection_receipt.selected_lane, "native_browser");
  assert.equal(environmentEvent.data.lease.session_mode, "owned_hermetic_browser");

  const observationEvent = trace.events.find((event) => event.type === "computer_use_observation");
  assert.ok(observationEvent);
  assert.equal(observationEvent.data.observation_bundle.url, "https://example.com");
  assert.equal(observationEvent.data.target_index.targets[0].available_actions.includes("inspect"), true);

  const proposalEvent = trace.events.find((event) => event.type === "computer_use_action_proposed");
  assert.ok(proposalEvent);
  assert.equal(proposalEvent.data.action_proposal.policy_decision_ref.startsWith("policy_"), true);
  assert.equal(proposalEvent.data.policy_gate.outcome, "approved_for_read_only_probe");
  assert.equal(
    proposalEvent.data.policy_decision_receipt.policy_decision_ref,
    proposalEvent.data.action_proposal.policy_decision_ref,
  );
  assert.equal(proposalEvent.data.policy_decision_receipt.outcome, "approved_for_read_only_probe");

  const actionEvent = trace.events.find((event) => event.type === "computer_use_action_executed");
  assert.ok(actionEvent);
  assert.equal(actionEvent.data.computer_action.proposal_ref, proposalEvent.data.action_proposal.proposal_ref);
  assert.equal(actionEvent.data.action_receipt.status, "completed");
  assert.equal(trace.computerUse.action.action_ref, actionEvent.data.computer_action.action_ref);

  const cleanupEvent = trace.events.find((event) => event.type === "computer_use_cleanup");
  assert.ok(cleanupEvent);
  assert.equal(cleanupEvent.data.cleanup_receipt.status, "completed");
  assert.equal(trace.computerUse.cleanup.cleanup_ref, cleanupEvent.data.cleanup_receipt.cleanup_ref);
  const commitGateEvent = trace.events.find((event) => event.type === "computer_use_commit_gate");
  assert.ok(commitGateEvent);
  assert.equal(commitGateEvent.data.computer_use_step, "commit_or_handoff");
  assert.equal(commitGateEvent.data.commit_gate.status, "not_required");
  assert.equal(trace.computerUse.commitGate.commit_gate_ref, commitGateEvent.data.commit_gate.commit_gate_ref);
  assert.equal(trace.computerUse.outcomeContract.external_effect_policy, "confirmation_required");

  const thread = await agent.thread();
  const runtimeEvents = [];
  for await (const event of thread.events()) {
    runtimeEvents.push(event);
  }
  const runtimeComputerEvents = runtimeEvents.filter((event) => event.eventKind.startsWith("computer_use."));
  assert.equal(runtimeComputerEvents.length, expectedComputerUseEventTypes.length);
  assert.equal(runtimeComputerEvents[0].payloadSchemaVersion, COMPUTER_USE_CONTRACT_SCHEMA_VERSION);
  assert.equal(runtimeComputerEvents[0].componentKind, "computer_use_harness");
  assert.equal(runtimeComputerEvents[0].workflowNodeId, "computer-use.select-environment");
  assert.equal(runtimeComputerEvents[0].payload.computer_use_step, "select_environment");
  assert.equal(runtimeComputerEvents[0].payload.computer_use_lane, "native_browser");
  assert.equal(
    trace.receipts.some((receipt) => receipt.kind === "computer_use_trace"),
    true,
  );
});

test("workflow-authored computer-use metadata round-trips through SDK trace events", async () => {
  const { cwd, client } = tempClient();
  const agent = await Agent.create({
    model: { id: "local:auto" },
    local: { cwd },
    substrateClient: client,
  });
  const run = await agent.send("Use the browser to inspect https://example.com.", {
    metadata: {
      computerUse: true,
      workflowGraphId: "workflow.browser-use-demo",
      workflowNodeId: "browser-use-node",
      workflowNodeIds: ["browser-use-node"],
      toolRef: "ioi.computer_use.native_browser",
      authorityScopes: ["computer_use.native_browser.read"],
      observationRetentionMode: "prompt_visible_summary_only",
      failClosedWhenUnavailable: true,
    },
  });
  const trace = await run.inspect();
  const environmentEvent = trace.events.find((event) => event.type === "computer_use_environment_selected");
  assert.ok(environmentEvent);
  assert.equal(environmentEvent.data.workflowGraphId, "workflow.browser-use-demo");
  assert.equal(environmentEvent.data.workflowNodeId, "browser-use-node");
  assert.deepEqual(environmentEvent.data.workflowNodeIds, ["browser-use-node"]);
  assert.equal(environmentEvent.data.toolRef, "ioi.computer_use.native_browser");
  assert.deepEqual(environmentEvent.data.authorityScopes, ["computer_use.native_browser.read"]);
  assert.equal(trace.computerUse.observation.retention_mode, "prompt_visible_summary_only");

  const thread = await agent.thread();
  const runtimeEvents = [];
  for await (const event of thread.events()) {
    runtimeEvents.push(event);
  }
  const runtimeComputerEvent = runtimeEvents.find((event) =>
    event.eventKind.startsWith("computer_use."),
  );
  assert.ok(runtimeComputerEvent);
  assert.equal(runtimeComputerEvent.workflowGraphId, "workflow.browser-use-demo");
  assert.equal(runtimeComputerEvent.workflowNodeId, "browser-use-node");
  assert.equal(runtimeComputerEvent.payload.workflowNodeId, "browser-use-node");
  assert.equal(runtimeComputerEvent.payload.observation_retention_mode, "prompt_visible_summary_only");
});

test("SDK local traces ingest canonical computer-use observation contracts", async () => {
  const { cwd, client } = tempClient();
  const agent = await Agent.create({
    model: { id: "local:auto" },
    local: { cwd },
    substrateClient: client,
  });
  const run = await agent.send("Use the browser to inspect https://local-live.example.test.", {
    metadata: {
      computerUse: true,
      computerUseObservationBundle: {
        observation_ref: "observation-sdk-live",
        url: "https://local-live.example.test/app",
        title: "SDK Live App",
        target_index_ref: "target-index-sdk-live",
        detected_patterns: ["table"],
      },
      computerUseTargetIndex: {
        target_index_ref: "target-index-sdk-live",
        observation_ref: "observation-sdk-live",
        coordinate_space_id: "viewport-sdk-live",
        drift_state: "fresh",
        targets: [
          {
            target_ref: "target-sdk-live-table",
            label: "Accounts table",
            role: "table",
            semantic_ids: ["table:accounts"],
            selectors: ["[data-testid=accounts-table]"],
            confidence: 95,
            available_actions: ["inspect"],
          },
        ],
      },
      computerUseAffordanceGraph: {
        graph_ref: "affordance-sdk-live",
        target_index_ref: "target-index-sdk-live",
        observation_ref: "observation-sdk-live",
        affordances: [
          {
            target_ref: "target-sdk-live-table",
            possible_action: "inspect",
            action_preconditions: ["fresh_observation"],
            confidence: 95,
            expected_state_transition: "Table state is summarized.",
            risk_class: "read_only",
            required_authority: "computer_use.native_browser.read",
            confirmation_required: false,
            fallback_action_paths: ["reobserve"],
            invalidation_conditions: ["navigation"],
          },
        ],
      },
    },
  });
  const trace = await run.inspect();
  assert.equal(trace.computerUse.observation.observation_ref, "observation-sdk-live");
  assert.equal(trace.computerUse.observation.url, "https://local-live.example.test/app");
  assert.equal(trace.computerUse.targetIndex.targets[0].target_ref, "target-sdk-live-table");
  assert.equal(trace.computerUse.affordanceGraph.graph_ref, "affordance-sdk-live");
  assert.equal(trace.computerUse.actionProposal.target_ref, "target-sdk-live-table");

  const observationEvent = trace.events.find((event) => event.type === "computer_use_observation");
  assert.ok(observationEvent);
  assert.equal(observationEvent.data.computer_use_contract_ingest, "canonical_runtime_contract");
});

test("SDK local traces project browser observation artifacts into canonical targets", async () => {
  const { cwd, client } = tempClient();
  const agent = await Agent.create({
    model: { id: "local:auto" },
    local: { cwd },
    substrateClient: client,
  });
  const run = await agent.send("Use the browser to inspect the mounted app.", {
    metadata: {
      computerUse: true,
      computerUseBrowserObservationArtifacts: {
        url: "https://artifact.example.test/app",
        page_title: "Artifact App",
        browser_use_selector_map_text:
          "[42] <button name=Submit target_id=target-submit />\n" +
          "[43] <input name=Search placeholder=Search target_id=target-search />",
        browsergym_dom_text: '<button id="submit">Submit</button><input placeholder="Search" />',
        browsergym_axtree_text: "button Submit\ntextbox Search",
        browsergym_focused_bid: "bid-submit",
      },
    },
  });
  const trace = await run.inspect();
  assert.equal(trace.computerUse.observation.url, "https://artifact.example.test/app");
  assert.equal(trace.computerUse.observation.title, "Artifact App");
  assert.equal(trace.computerUse.observation.dom_ref.endsWith(":browsergym_dom"), true);
  assert.equal(trace.computerUse.observation.selector_map_ref.endsWith(":selector_map"), true);
  assert.equal(trace.computerUse.observation.detected_patterns.includes("form"), true);

  const [button, input] = trace.computerUse.targetIndex.targets;
  assert.equal(button.target_ref.endsWith(":target-submit"), true);
  assert.equal(button.label, "Submit");
  assert.equal(button.role, "button");
  assert.equal(button.available_actions.includes("click"), true);
  assert.equal(input.label, "Search");
  assert.equal(input.available_actions.includes("type_text"), true);
  assert.equal(
    trace.computerUse.affordanceGraph.affordances.some((affordance) =>
      affordance.target_ref === button.target_ref &&
        affordance.possible_action === "click" &&
        affordance.confirmation_required === true &&
        affordance.risk_class === "possible_external_effect",
    ),
    true,
  );
  assert.equal(trace.computerUse.actionProposal.target_ref, button.target_ref);

  const observationEvent = trace.events.find((event) => event.type === "computer_use_observation");
  assert.ok(observationEvent);
  assert.equal(observationEvent.data.computer_use_contract_ingest, "browser_observation_artifacts");
  assert.equal(observationEvent.data.target_index.targets.length, 2);
});

test("runtime daemon emits canonical computer-use events for browser prompts", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const run = await agent.send("Use the browser to inspect https://example.com and explain next actions.", {
      metadata: { computerUse: true },
    });
    const trace = await run.inspect();
    assert.deepEqual(
      trace.events.filter((event) => event.type.startsWith("computer_use_")).map((event) => event.type),
      expectedComputerUseEventTypes,
    );
    assert.equal(trace.computerUse.environmentSelection.selected_lane, "native_browser");
    assert.equal(trace.computerUse.observation.url, "https://example.com");
    assert.equal(trace.computerUse.actionProposal.policy_decision_ref.startsWith("policy_"), true);
    assert.equal(trace.computerUse.policyDecision.policy_decision_ref, trace.computerUse.actionProposal.policy_decision_ref);
    assert.equal(trace.computerUse.policyDecision.outcome, "approved_for_read_only_probe");
    assert.equal(trace.computerUse.policyDecision.external_effect, false);
    assert.equal(trace.computerUse.actionReceipt.status, "completed");
    assert.equal(trace.computerUse.verification.action_ref, trace.computerUse.action.action_ref);
    assert.equal(trace.computerUse.commitGate.status, "not_required");
    assert.equal(trace.computerUse.outcomeContract.evidence_required.includes("computer_use_trace"), true);
    assert.equal(trace.computerUse.trajectory.entries.some((entry) => entry.event_kind === "execute_action"), true);
    assert.equal(trace.computerUse.trajectory.entries.some((entry) => entry.event_kind === "commit_or_handoff"), true);
    assert.equal(trace.computerUse.cleanup.status, "completed");
    assert.equal(
      trace.receipts.some((receipt) => receipt.kind === "computer_use_trace"),
      true,
    );
    assert.equal((await run.computerUseTrace()).observation.url, "https://example.com");
    assert.equal(
      (await run.computerUseTrajectory()).entries.some((entry) => entry.event_kind === "execute_action"),
      true,
    );
    const trajectoryEval = await run.computerUseTrajectoryEval();
    assert.equal(trajectoryEval.outcome, "passed");
    assert.equal(trajectoryEval.score, 1);
    assert.equal(trajectoryEval.lane, "native_browser");
    assert.equal(trajectoryEval.missing_regression_gates.length, 0);
    const improvementPlan = await run.computerUseHarnessImprovementPlan();
    assert.equal(improvementPlan.outcome, "passed");
    assert.equal(improvementPlan.patch_proposals.length, 0);
    assert.equal(improvementPlan.promotion_gate.status, "not_required");
    const benchmarkCase = await run.computerUseBenchmarkCase();
    assert.equal(benchmarkCase.outcome, "passed");
    assert.equal(benchmarkCase.export_mode, "redacted_regression");
    assert.equal(benchmarkCase.manifest.hidden_runtime_shortcuts_forbidden, true);

    const thread = await agent.thread();
    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const runtimeComputerEvents = runtimeEvents.filter((event) => event.eventKind.startsWith("computer_use."));
    assert.equal(runtimeComputerEvents.length, expectedComputerUseEventTypes.length);
    assert.equal(runtimeComputerEvents[0].payloadSchemaVersion, COMPUTER_USE_CONTRACT_SCHEMA_VERSION);
    assert.equal(runtimeComputerEvents[0].componentKind, "computer_use_harness");
    assert.equal(runtimeComputerEvents[0].workflowNodeId, "computer-use.select-environment");
    assert.equal(runtimeComputerEvents[0].payload.computer_use_step, "select_environment");
    assert.equal(runtimeComputerEvents[0].payload.computer_use_lane, "native_browser");
    assert.ok((await run.artifacts()).some((artifact) => artifact.name === "computer-use-trace.json"));
  } finally {
    await daemon.close();
  }
});

test("runtime daemon exposes read-only browser discovery receipts", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-browser-discovery-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-browser-discovery-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const report = await client.discoverComputerUseBrowsers({ probe: false });
    assert.equal(report.schema_version, "ioi.computer-use.browser-discovery.v1");
    assert.equal(report.object, "ioi.computer_use.browser_discovery_report");
    assert.equal(report.safety.read_only, true);
    assert.equal(report.safety.mutated_browser_state, false);
    assert.equal(report.safety.copied_profiles, false);
    assert.equal(report.safety.copied_credentials, false);
    assert.equal(report.safety.raw_profile_paths_redacted, true);
    assert.equal(report.safety.raw_command_lines_redacted, true);
    assert.equal(report.safety.cdp_probe_enabled, false);
    assert.ok(Array.isArray(report.browser_processes));
    assert.ok(Array.isArray(report.cdp_endpoints));
    assert.ok(Array.isArray(report.recommended_next_steps));
    assert.equal(JSON.stringify(report).includes(process.env.HOME ?? "__no_home__"), false);
  } finally {
    await daemon.close();
  }
});

test("runtime daemon invokes browser discovery through thread tool spine", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-browser-discovery-tool-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-browser-discovery-tool-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const thread = await agent.thread();
    const result = await client.invokeThreadTool(thread.id, "ioi.computer_use.browser_discovery", {
      source: "react_flow",
      workflowGraphId: "workflow.browser-discovery-tool",
      workflowNodeId: "browser-discovery-tool",
      input: {
        includeTabs: false,
        revealTabTitles: false,
      },
    });
    assert.equal(result.status, "completed");
    assert.equal(result.object, "ioi.runtime_computer_use_browser_discovery_result");
    assert.equal(result.tool_pack, "computer_use");
    assert.equal(result.tool_name, "ioi.computer_use.browser_discovery");
    assert.equal(result.workflow_node_id, "browser-discovery-tool");
    assert.equal(result.event.event_kind, "computer_use.browser_discovery");
    assert.equal(result.event.component_kind, "computer_use_harness");
    assert.equal(result.result.object, "ioi.computer_use.browser_discovery_report");
    assert.equal(result.result.safety.read_only, true);

    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const discovery = runtimeEvents.find((event) => event.type === "computer_use_browser_discovery");
    assert.ok(discovery);
    assert.equal(discovery.workflowNodeId, "browser-discovery-tool");
    assert.equal(
      discovery.payload.browser_discovery_report.object,
      "ioi.computer_use.browser_discovery_report",
    );
  } finally {
    await daemon.close();
  }
});

test("runtime daemon records coding-agent computer-use lease requests", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-coding-lease-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-coding-lease-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const thread = await agent.thread();
    const result = await client.invokeThreadTool(thread.id, "computer_use.request_lease", {
      source: "runtime_agent",
      workflowGraphId: "workflow.coop-coding-computer-use",
      workflowNodeId: "coding-agent-computer-use-lease",
      input: {
        prompt: "Open the local preview and click the refresh button.",
        lane: "native_browser",
        actionKind: "click",
        url: "https://example.com",
        targetRef: "target-refresh",
      },
    });

    assert.equal(result.status, "completed");
    assert.equal(result.result.object, "ioi.coding_agent_computer_use_lease_request");
    assert.equal(result.result.leaseRequest.lane, "native_browser");
    assert.equal(result.result.leaseRequest.authorityScope, "computer_use.native_browser.act");
    assert.equal(result.result.approvalRequiredBeforeExecution, true);
    assert.equal(result.result.threadTool.toolName, "ioi.computer_use.native_browser");
    assert.equal(result.result.threadTool.input.actionKind, "click");

    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const requestEvent = runtimeEvents.find((event) => event.type === "tool_completed");
    assert.ok(requestEvent);
    assert.equal(requestEvent.workflowNodeId, "coding-agent-computer-use-lease");
    assert.equal(requestEvent.payload.result.requestRef, result.result.requestRef);
  } finally {
    await daemon.close();
  }
});

test("runtime daemon invokes native browser loop through thread tool spine", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-native-browser-tool-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-native-browser-tool-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const thread = await agent.thread();
    const result = await client.invokeThreadTool(thread.id, "ioi.computer_use.native_browser", {
      source: "react_flow",
      workflowGraphId: "workflow.native-browser-tool",
      workflowNodeId: "native-browser-tool",
      input: {
        prompt: "Inspect https://example.com without external side effects.",
        url: "https://example.com",
        observationRetentionMode: "prompt_visible_summary_only",
      },
    });
    assert.equal(result.status, "completed");
    assert.equal(result.object, "ioi.runtime_computer_use_native_browser_result");
    assert.equal(result.tool_pack, "computer_use");
    assert.equal(result.tool_name, "ioi.computer_use.native_browser");
    assert.equal(result.workflow_graph_id, "workflow.native-browser-tool");
    assert.equal(result.workflow_node_id, "native-browser-tool");
    assert.equal(result.event_count, expectedComputerUseEventTypes.length);
    assert.equal(result.result.environmentSelection.selected_lane, "native_browser");
    assert.equal(result.result.lease.lane, "native_browser");
    assert.equal(result.result.lease.authority_scope, "computer_use.native_browser.read");
    assert.equal(result.result.observation.retention_mode, "prompt_visible_summary_only");
    assert.equal(result.result.action.action_kind, "inspect");
    assert.equal(result.result.policyDecision.outcome, "approved_for_read_only_probe");
    assert.equal(result.result.policyDecision.fail_closed, false);
    assert.equal(result.result.actionReceipt.status, "completed");
    assert.equal(result.result.commitGate.status, "not_required");

    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const computerEvents = runtimeEvents.filter((event) => event.eventKind.startsWith("computer_use."));
    assert.deepEqual(computerEvents.map((event) => event.type), expectedComputerUseEventTypes);
    assert.equal(computerEvents[0].workflowGraphId, "workflow.native-browser-tool");
    assert.equal(computerEvents[0].workflowNodeId, "native-browser-tool");
    assert.equal(computerEvents[0].componentKind, "computer_use_harness");
    assert.equal(computerEvents[0].payload.tool_ref, "ioi.computer_use.native_browser");
    assert.equal(computerEvents[5].type, "computer_use_action_proposed");
    assert.equal(computerEvents[5].payload.action_proposal.target_ref, result.result.action.target_ref);
    assert.equal(computerEvents[5].payload.policy_decision_receipt.outcome, "approved_for_read_only_probe");
    assert.equal(
      computerEvents[5].payload.policy_decision_receipt.policy_decision_ref,
      computerEvents[5].payload.action_proposal.policy_decision_ref,
    );
    assert.equal(computerEvents[6].type, "computer_use_action_executed");
    assert.equal(computerEvents[6].payload.action_receipt.status, "completed");
  } finally {
    await daemon.close();
  }
});

test("runtime daemon gates mutating native browser actions before execution", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-native-browser-gate-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-native-browser-gate-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const thread = await agent.thread();
    const result = await client.invokeThreadTool(thread.id, "ioi.computer_use.native_browser", {
      source: "react_flow",
      workflowGraphId: "workflow.native-browser-gated-tool",
      workflowNodeId: "native-browser-gated-tool",
      input: {
        prompt: "Click the submit button at https://example.com.",
        url: "https://example.com",
        actionKind: "click",
        targetRef: "target-submit",
        observationRetentionMode: "prompt_visible_summary_only",
      },
    });

    assert.equal(result.status, "completed");
    assert.equal(result.result.lease.authority_scope, "computer_use.native_browser.act");
    assert.equal(result.result.actionProposal.normalized_action_candidate, "click target-submit");
    assert.equal(result.result.actionProposal.risk_assessment, "possible_external_effect");
    assert.equal(result.result.policyDecision.outcome, "requires_confirmation_before_execution");
    assert.equal(result.result.policyDecision.fail_closed, true);
    assert.equal(result.result.policyDecision.external_effect, true);
    assert.equal(result.result.action, null);
    assert.equal(result.result.actionReceipt, null);
    assert.equal(result.result.verification.status, "requires_human");
    assert.equal(result.result.commitGate.status, "pending_confirmation");
    assert.equal(result.result.commitGate.final_action_ref, null);
    assert.equal(result.event_count, expectedComputerUseEventTypes.length - 1);

    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const computerEvents = runtimeEvents.filter((event) => event.eventKind.startsWith("computer_use."));
    assert.equal(computerEvents.some((event) => event.type === "computer_use_action_executed"), false);
    const proposalEvent = computerEvents.find((event) => event.type === "computer_use_action_proposed");
    assert.equal(proposalEvent.payload.policy_gate.outcome, "requires_confirmation_before_execution");
    assert.equal(proposalEvent.payload.policy_decision_receipt.outcome, "requires_confirmation_before_execution");
    assert.equal(proposalEvent.payload.policy_decision_receipt.fail_closed, true);
    const commitEvent = computerEvents.find((event) => event.type === "computer_use_commit_gate");
    assert.ok(commitEvent);
    assert.equal(commitEvent.payload.commit_gate.status, "pending_confirmation");
    assert.equal(commitEvent.payload.human_handoff_state.reason, "mutating_browser_action_requires_confirmation");
  } finally {
    await daemon.close();
  }
});

test("runtime daemon resumes approved mutating native browser actions through action receipts", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-native-browser-approved-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-native-browser-approved-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  const cdp = await startFakeNativeBrowserCdpServer();
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const thread = await agent.thread();
    const result = await client.invokeThreadTool(thread.id, "ioi.computer_use.native_browser", {
      source: "react_flow",
      workflowGraphId: "workflow.native-browser-approved-tool",
      workflowNodeId: "native-browser-approved-tool",
      input: {
        prompt: "Click the submit button at https://example.com.",
        url: "https://example.com",
        actionKind: "click",
        targetRef: "#submit",
        selector: "#submit",
        cdpEndpointUrl: cdp.endpointUrl,
        approvalRef: "approval-browser-click",
        observationRetentionMode: "prompt_visible_summary_only",
      },
    });

    assert.equal(result.status, "completed");
    assert.equal(result.result.action.action_kind, "click");
    assert.equal(result.result.action.target_ref, "#submit");
    assert.equal(result.result.action.approval_ref, "approval-browser-click");
    assert.equal(result.result.actionReceipt.status, "completed");
    assert.equal(result.result.actionReceipt.adapter_id, "ioi.native_browser.cdp");
    assert.equal(result.result.verification.status, "passed");
    assert.equal(result.result.policyDecision.outcome, "approved_after_confirmation");
    assert.equal(result.result.policyDecision.fail_closed, false);
    assert.equal(result.result.policyDecision.approval_ref, "approval-browser-click");
    assert.equal(result.result.commitGate.status, "completed");
    assert.equal(result.result.commitGate.final_action_ref, result.result.action.action_ref);
    assert.equal(result.event_count, expectedComputerUseEventTypes.length);
    assert.deepEqual(cdp.state.clicks, ["#submit"]);

    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const computerEvents = runtimeEvents.filter((event) => event.eventKind.startsWith("computer_use."));
    assert.equal(computerEvents.some((event) => event.type === "computer_use_action_executed"), true);
    const environmentEvent = computerEvents.find((event) => event.type === "computer_use_environment_selected");
    assert.equal(environmentEvent.payload.environment_selection_receipt.selected_session_mode, "attached_cdp");
    assert.equal(environmentEvent.payload.lease.session_mode, "attached_cdp");
    const proposalEvent = computerEvents.find((event) => event.type === "computer_use_action_proposed");
    assert.equal(proposalEvent.payload.policy_gate.outcome, "approved_after_confirmation");
    assert.equal(proposalEvent.payload.policy_gate.approval_ref, "approval-browser-click");
    assert.equal(proposalEvent.payload.policy_gate.executor_status, "completed");
    assert.equal(proposalEvent.payload.policy_decision_receipt.outcome, "approved_after_confirmation");
    assert.equal(proposalEvent.payload.policy_decision_receipt.fail_closed, false);
    const actionEvent = computerEvents.find((event) => event.type === "computer_use_action_executed");
    assert.equal(actionEvent.payload.native_browser_execution_result.status, "completed");
    const commitEvent = computerEvents.find((event) => event.type === "computer_use_commit_gate");
    assert.ok(commitEvent);
    assert.equal(commitEvent.payload.commit_gate.status, "completed");
    assert.equal(commitEvent.payload.human_handoff_state, null);
  } finally {
    await cdp.close();
    await daemon.close();
  }
});

test("runtime daemon fails closed when approved native browser action has no CDP adapter", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-native-browser-approved-blocked-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-native-browser-approved-blocked-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const thread = await agent.thread();
    const result = await client.invokeThreadTool(thread.id, "ioi.computer_use.native_browser", {
      source: "react_flow",
      workflowGraphId: "workflow.native-browser-approved-blocked-tool",
      workflowNodeId: "native-browser-approved-blocked-tool",
      input: {
        prompt: "Click the submit button at https://example.com.",
        url: "https://example.com",
        actionKind: "click",
        targetRef: "#submit",
        approvalRef: "approval-browser-click",
        observationRetentionMode: "prompt_visible_summary_only",
      },
    });

    assert.equal(result.status, "completed");
    assert.equal(result.result.action, null);
    assert.equal(result.result.actionReceipt, null);
    assert.equal(result.result.verification.status, "blocked");
    assert.equal(result.result.policyDecision.outcome, "blocked_executor_unavailable");
    assert.equal(result.result.policyDecision.fail_closed, true);
    assert.equal(result.result.policyDecision.approval_ref, "approval-browser-click");
    assert.equal(result.result.commitGate.status, "blocked");
    assert.equal(result.result.commitGate.user_confirmation_required, false);
    assert.equal(result.event_count, expectedComputerUseEventTypes.length - 1);

    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const computerEvents = runtimeEvents.filter((event) => event.eventKind.startsWith("computer_use."));
    assert.equal(computerEvents.some((event) => event.type === "computer_use_action_executed"), false);
    const proposalEvent = computerEvents.find((event) => event.type === "computer_use_action_proposed");
    assert.equal(proposalEvent.payload.policy_gate.outcome, "blocked_executor_unavailable");
    assert.equal(proposalEvent.payload.policy_gate.executor_status, "unavailable");
    assert.equal(proposalEvent.payload.policy_decision_receipt.outcome, "blocked_executor_unavailable");
    assert.equal(proposalEvent.payload.policy_decision_receipt.fail_closed, true);
    const verificationEvent = computerEvents.find((event) => event.type === "computer_use_verification");
    assert.equal(verificationEvent.payload.verification_receipt.status, "blocked");
    assert.equal(verificationEvent.payload.native_browser_execution_result.status, "unavailable");
    const commitEvent = computerEvents.find((event) => event.type === "computer_use_commit_gate");
    assert.ok(commitEvent);
    assert.equal(commitEvent.payload.commit_gate.status, "blocked");
    assert.equal(commitEvent.payload.human_handoff_state, null);
  } finally {
    await daemon.close();
  }
});

test("runtime daemon executes approved native browser type_text through CDP", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-native-browser-type-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-native-browser-type-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  const cdp = await startFakeNativeBrowserCdpServer();
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const thread = await agent.thread();
    const result = await client.invokeThreadTool(thread.id, "ioi.computer_use.native_browser", {
      source: "react_flow",
      workflowGraphId: "workflow.native-browser-type-tool",
      workflowNodeId: "native-browser-type-tool",
      input: {
        prompt: "Type text into the search field at https://example.com.",
        url: "https://example.com",
        actionKind: "type_text",
        targetRef: "#input",
        selector: "#input",
        text: "hello IOI",
        cdpEndpointUrl: cdp.endpointUrl,
        approvalRef: "approval-browser-type",
        observationRetentionMode: "prompt_visible_summary_only",
      },
    });

    assert.equal(result.status, "completed");
    assert.equal(result.result.action.action_kind, "type_text");
    assert.equal(result.result.action.target_ref, "#input");
    assert.equal(result.result.actionReceipt.adapter_id, "ioi.native_browser.cdp");
    assert.equal(result.result.verification.status, "passed");
    assert.equal(result.result.commitGate.status, "completed");
    assert.deepEqual(cdp.state.typed, [{ selector: "#input", text: "hello IOI" }]);

    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const actionEvent = runtimeEvents.find((event) => event.type === "computer_use_action_executed");
    assert.equal(actionEvent.payload.native_browser_execution_result.action_result.action, "type_text");
    assert.equal(actionEvent.payload.native_browser_execution_result.status, "completed");
  } finally {
    await cdp.close();
    await daemon.close();
  }
});

test("runtime daemon executes approved native browser key_press through CDP", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-native-browser-key-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-native-browser-key-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  const cdp = await startFakeNativeBrowserCdpServer();
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const thread = await agent.thread();
    const result = await client.invokeThreadTool(thread.id, "ioi.computer_use.native_browser", {
      source: "react_flow",
      workflowGraphId: "workflow.native-browser-key-tool",
      workflowNodeId: "native-browser-key-tool",
      input: {
        prompt: "Press Enter in the browser at https://example.com.",
        url: "https://example.com",
        actionKind: "key_press",
        key: "Enter",
        cdpEndpointUrl: cdp.endpointUrl,
        approvalRef: "approval-browser-key",
        observationRetentionMode: "prompt_visible_summary_only",
      },
    });

    assert.equal(result.status, "completed");
    assert.equal(result.result.action.action_kind, "key_press");
    assert.equal(result.result.action.approval_ref, "approval-browser-key");
    assert.equal(result.result.actionReceipt.adapter_id, "ioi.native_browser.cdp");
    assert.equal(result.result.verification.status, "passed");
    assert.equal(result.result.commitGate.status, "completed");
    assert.deepEqual(cdp.state.keys, [{ key: "Enter", code: "Enter", text: "" }]);

    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const actionEvent = runtimeEvents.find((event) => event.type === "computer_use_action_executed");
    assert.equal(actionEvent.payload.native_browser_execution_result.action_result.action, "key_press");
    assert.equal(actionEvent.payload.native_browser_execution_result.status, "completed");
  } finally {
    await cdp.close();
    await daemon.close();
  }
});

test("runtime daemon executes explicit native browser scroll through CDP", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-native-browser-scroll-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-native-browser-scroll-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  const cdp = await startFakeNativeBrowserCdpServer();
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const thread = await agent.thread();
    const result = await client.invokeThreadTool(thread.id, "ioi.computer_use.native_browser", {
      source: "react_flow",
      workflowGraphId: "workflow.native-browser-scroll-tool",
      workflowNodeId: "native-browser-scroll-tool",
      input: {
        prompt: "Scroll down in the browser at https://example.com.",
        url: "https://example.com",
        actionKind: "scroll",
        scrollY: 420,
        cdpEndpointUrl: cdp.endpointUrl,
        observationRetentionMode: "prompt_visible_summary_only",
      },
    });

    assert.equal(result.status, "completed");
    assert.equal(result.result.action.action_kind, "scroll");
    assert.equal(result.result.action.approval_ref, null);
    assert.equal(result.result.actionReceipt.adapter_id, "ioi.native_browser.cdp");
    assert.equal(result.result.verification.status, "passed");
    assert.equal(result.result.commitGate.status, "completed");
    assert.deepEqual(cdp.state.scrolls, [{ selector: null, deltaX: 0, deltaY: 420 }]);

    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const actionEvent = runtimeEvents.find((event) => event.type === "computer_use_action_executed");
    assert.equal(actionEvent.payload.native_browser_execution_result.action_result.action, "scroll");
    assert.equal(actionEvent.payload.native_browser_execution_result.status, "completed");
  } finally {
    await cdp.close();
    await daemon.close();
  }
});

test("runtime daemon executes approved native browser upload through CDP", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-native-browser-upload-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-native-browser-upload-state-"));
  const uploadPath = path.join(cwd, "fixture.txt");
  fs.writeFileSync(uploadPath, "upload me", "utf8");
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  const cdp = await startFakeNativeBrowserCdpServer();
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const thread = await agent.thread();
    const result = await client.invokeThreadTool(thread.id, "ioi.computer_use.native_browser", {
      source: "react_flow",
      workflowGraphId: "workflow.native-browser-upload-tool",
      workflowNodeId: "native-browser-upload-tool",
      input: {
        prompt: "Upload a fixture file at https://example.com.",
        url: "https://example.com",
        actionKind: "upload",
        targetRef: "#file",
        selector: "#file",
        filePath: uploadPath,
        cdpEndpointUrl: cdp.endpointUrl,
        approvalRef: "approval-browser-upload",
        observationRetentionMode: "prompt_visible_summary_only",
      },
    });

    assert.equal(result.status, "completed");
    assert.equal(result.result.action.action_kind, "upload");
    assert.equal(result.result.action.target_ref, "#file");
    assert.equal(result.result.action.approval_ref, "approval-browser-upload");
    assert.equal(result.result.actionReceipt.adapter_id, "ioi.native_browser.cdp");
    assert.equal(result.result.verification.status, "passed");
    assert.equal(result.result.commitGate.status, "completed");
    assert.deepEqual(cdp.state.uploads, [{ nodeId: 2, files: [uploadPath] }]);

    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const actionEvent = runtimeEvents.find((event) => event.type === "computer_use_action_executed");
    assert.equal(actionEvent.payload.native_browser_execution_result.action_result.action, "upload");
    assert.equal(actionEvent.payload.native_browser_execution_result.status, "completed");
  } finally {
    await cdp.close();
    await daemon.close();
  }
});

test("runtime daemon fails closed for unbrokered controlled relaunch requests", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-controlled-relaunch-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-controlled-relaunch-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const thread = await agent.thread();
    const result = await client.invokeThreadTool(thread.id, "ioi.computer_use.native_browser", {
      source: "react_flow",
      workflowGraphId: "workflow.native-browser-controlled-relaunch",
      workflowNodeId: "native-browser-controlled-relaunch",
      input: {
        prompt: "Continue this task by controlled relaunching Chrome.",
        actionKind: "inspect",
        sessionMode: "controlled_relaunch",
        observationRetentionMode: "prompt_visible_summary_only",
      },
    });

    assert.equal(result.status, "completed");
    assert.equal(result.result.lease.status, "failed_closed");
    assert.equal(result.result.lease.session_mode, "controlled_relaunch");
    assert.equal(result.result.runState.blocker_state, "controlled_relaunch_broker_unavailable");
    assert.equal(result.result.verification.status, "blocked");
    assert.equal(result.result.action, null);
    assert.equal(result.event_count, 5);

    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const environmentEvent = runtimeEvents.find((event) => event.type === "computer_use_environment_selected");
    assert.equal(environmentEvent.payload.environment_selection_receipt.selected_session_mode, "controlled_relaunch");
    const unavailableEvent = runtimeEvents.find((event) => event.type === "computer_use_environment_unavailable");
    assert.equal(unavailableEvent.payload.recovery_policy.allowed_actions.includes("use_attached_cdp"), true);
  } finally {
    await daemon.close();
  }
});

test("runtime daemon brokers controlled relaunch leases before browser authority is used", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-controlled-relaunch-broker-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-controlled-relaunch-broker-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const thread = await agent.thread();
    const result = await client.invokeThreadTool(thread.id, "ioi.computer_use.native_browser", {
      source: "react_flow",
      workflowGraphId: "workflow.native-browser-controlled-relaunch-broker",
      workflowNodeId: "native-browser-controlled-relaunch-broker",
      input: {
        prompt: "Continue this task by controlled relaunching Chrome.",
        actionKind: "inspect",
        sessionMode: "controlled_relaunch",
        observationRetentionMode: "prompt_visible_summary_only",
        controlledRelaunchBrokerRef: "broker_controlled_relaunch_test",
        controlledRelaunchLaunchPlanRef: "launch_plan_controlled_relaunch_test",
        controlledRelaunchProfileDirRef: "profile_controlled_relaunch_test",
        url: "https://example.com",
      },
    });

    assert.equal(result.status, "completed");
    assert.equal(result.result.environmentSelection.selected_session_mode, "controlled_relaunch");
    assert.equal(result.result.environmentSelection.risk_posture, "controlled_relaunch_handoff_required");
    assert.equal(result.result.lease.status, "handoff_pending");
    assert.equal(result.result.lease.authority_scope, "computer_use.native_browser.controlled_relaunch");
    assert.equal(result.result.runState.blocker_state, "controlled_relaunch_handoff_pending");
    assert.equal(result.result.verification.status, "requires_human");
    assert.equal(result.result.commitGate.status, "pending_confirmation");
    assert.equal(result.result.adapterContract.adapter_id, "ioi.native_browser.controlled_relaunch_broker");
    assert.equal(result.result.observation, null);
    assert.equal(result.result.action, null);
    assert.equal(result.event_count, 7);

    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const computerEvents = runtimeEvents.filter((event) => event.eventKind.startsWith("computer_use."));
    assert.equal(computerEvents.some((event) => event.type === "computer_use_observation"), false);
    assert.equal(computerEvents.some((event) => event.type === "computer_use_action_executed"), false);
    const leaseEvent = computerEvents.find((event) => event.type === "computer_use_lease_acquired");
    assert.equal(leaseEvent.payload.controlled_relaunch_broker.broker_ref, "broker_controlled_relaunch_test");
    const handoffEvent = computerEvents.find((event) => event.type === "computer_use_commit_gate");
    assert.equal(
      handoffEvent.payload.human_handoff_state.reason,
      "controlled_relaunch_requires_operator_visible_browser_start",
    );
    assert.equal(
      handoffEvent.payload.human_handoff_state.forbidden_agent_actions.includes("harvest_credentials"),
      true,
    );
  } finally {
    await daemon.close();
  }
});

test("runtime daemon emits computer-use pause resume abort cleanup control receipts", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-control-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-control-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const thread = await agent.thread();
    const pause = await client.invokeThreadTool(thread.id, "ioi.computer_use.control", {
      source: "tui",
      workflowGraphId: "workflow.computer-use-control",
      workflowNodeId: "computer-use-control",
      input: {
        controlAction: "pause",
        leaseId: "lease_controlled_relaunch_test",
        handoffRef: "handoff_controlled_relaunch_test",
        reason: "operator wants to inspect the controlled relaunch handoff",
      },
    });
    const resume = await client.invokeThreadTool(thread.id, "ioi.computer_use.control", {
      source: "tui",
      workflowGraphId: "workflow.computer-use-control",
      workflowNodeId: "computer-use-control",
      input: {
        controlAction: "resume",
        leaseId: "lease_controlled_relaunch_test",
        handoffRef: "handoff_controlled_relaunch_test",
        resumeObservationRef: "observation_after_relaunch",
        cdpEndpointUrl: "http://127.0.0.1:9222",
      },
    });
    const abort = await client.invokeThreadTool(thread.id, "ioi.computer_use.control", {
      source: "cli",
      workflowGraphId: "workflow.computer-use-control",
      workflowNodeId: "computer-use-control",
      input: {
        controlAction: "abort",
        leaseId: "lease_controlled_relaunch_test",
        reason: "operator aborted the relaunch",
      },
    });
    const cleanup = await client.invokeThreadTool(thread.id, "ioi.computer_use.control", {
      source: "cli",
      workflowGraphId: "workflow.computer-use-control",
      workflowNodeId: "computer-use-control",
      input: {
        controlAction: "cleanup",
        leaseId: "lease_controlled_relaunch_test",
      },
    });

    assert.equal(pause.status, "completed");
    assert.equal(pause.result.controlReceipt.status, "paused");
    assert.equal(pause.result.humanHandoffState.status, "pending");
    assert.equal(resume.result.controlReceipt.status, "resumed");
    assert.equal(resume.result.humanHandoffState.observation_after_resume_ref, "observation_after_relaunch");
    assert.equal(abort.status, "canceled");
    assert.equal(abort.result.controlReceipt.status, "aborted");
    assert.equal(abort.result.cleanup.status, "completed_after_abort");
    assert.equal(cleanup.result.controlReceipt.status, "cleanup_completed");
    assert.equal(cleanup.result.cleanup.status, "completed");

    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const controlEvents = runtimeEvents.filter((event) => event.type === "computer_use_control");
    assert.deepEqual(
      controlEvents.map((event) => event.payload.control_receipt.action),
      ["pause", "resume", "abort", "cleanup"],
    );
    assert.equal(controlEvents[0].workflowNodeId, "computer-use-control");
    assert.equal(controlEvents[0].payload.control_receipt.lease_id, "lease_controlled_relaunch_test");
    assert.ok(controlEvents[2].receiptRefs.includes(abort.result.cleanup.cleanup_ref));
  } finally {
    await daemon.close();
  }
});

test("runtime daemon preserves workflow-authored computer-use node metadata", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-workflow-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-workflow-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const run = await agent.send("Use the browser to inspect https://example.com.", {
      metadata: {
        computerUse: true,
        workflowGraphId: "workflow.browser-use-demo",
        workflowNodeId: "browser-use-node",
        workflowNodeIds: ["browser-use-node"],
        toolRef: "ioi.computer_use.native_browser",
        authorityScopes: ["computer_use.native_browser.read"],
        observationRetentionMode: "prompt_visible_summary_only",
        failClosedWhenUnavailable: true,
      },
    });
    const trace = await run.inspect();
    const environmentEvent = trace.events.find((event) => event.type === "computer_use_environment_selected");
    assert.ok(environmentEvent);
    assert.equal(environmentEvent.data.workflowGraphId, "workflow.browser-use-demo");
    assert.equal(environmentEvent.data.workflowNodeId, "browser-use-node");
    assert.equal(environmentEvent.data.observation_retention_mode, "prompt_visible_summary_only");
    assert.equal(trace.computerUse.lease.retention_mode, "prompt_visible_summary_only");

    const thread = await agent.thread();
    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const runtimeComputerEvent = runtimeEvents.find((event) =>
      event.eventKind.startsWith("computer_use."),
    );
    assert.ok(runtimeComputerEvent);
    assert.equal(runtimeComputerEvent.workflowGraphId, "workflow.browser-use-demo");
    assert.equal(runtimeComputerEvent.workflowNodeId, "browser-use-node");
    assert.equal(runtimeComputerEvent.payload.workflow_node_id, "browser-use-node");
    assert.deepEqual(runtimeComputerEvent.payload.authority_scopes, ["computer_use.native_browser.read"]);
  } finally {
    await daemon.close();
  }
});

test("runtime daemon ingests canonical computer-use observation contracts", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-live-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-live-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const run = await agent.send("Use the browser to inspect https://live.example.test.", {
      metadata: {
        computerUse: true,
        computerUseObservationBundle: {
          observation_ref: "observation-live-browser",
          lease_id: "ignored-by-daemon",
          lane: "native_browser",
          session_mode: "owned_hermetic_browser",
          url: "https://live.example.test/dashboard",
          title: "Live Dashboard",
          target_index_ref: "target-index-live-browser",
          retention_mode: "local_redacted_artifacts",
          detected_patterns: ["table", "toolbar"],
        },
        computerUseTargetIndex: {
          target_index_ref: "target-index-live-browser",
          observation_ref: "observation-live-browser",
          coordinate_space_id: "viewport-live-browser",
          drift_state: "fresh",
          targets: [
            {
              target_ref: "target-live-refresh",
              label: "Refresh",
              role: "button",
              semantic_ids: ["button:refresh"],
              selectors: ["button[data-testid=refresh]"],
              confidence: 97,
              available_actions: ["inspect", "click"],
            },
          ],
        },
        computerUseAffordanceGraph: {
          graph_ref: "affordance-live-browser",
          target_index_ref: "target-index-live-browser",
          observation_ref: "observation-live-browser",
          affordances: [
            {
              target_ref: "target-live-refresh",
              possible_action: "inspect",
              action_preconditions: ["fresh_observation"],
              confidence: 96,
              expected_state_transition: "Refresh button can be inspected without side effects.",
              risk_class: "read_only",
              required_authority: "computer_use.native_browser.read",
              confirmation_required: false,
              fallback_action_paths: ["reobserve"],
              invalidation_conditions: ["navigation"],
            },
          ],
        },
      },
    });
    const trace = await run.inspect();
    assert.equal(trace.computerUse.observation.observation_ref, "observation-live-browser");
    assert.equal(trace.computerUse.observation.url, "https://live.example.test/dashboard");
    assert.equal(trace.computerUse.targetIndex.targets[0].target_ref, "target-live-refresh");
    assert.equal(trace.computerUse.affordanceGraph.graph_ref, "affordance-live-browser");
    assert.equal(trace.computerUse.actionProposal.target_ref, "target-live-refresh");

    const thread = await agent.thread();
    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const observationEvent = runtimeEvents.find((event) => event.eventKind === "computer_use.observation");
    assert.ok(observationEvent);
    assert.equal(observationEvent.payload.computer_use_contract_ingest, "canonical_runtime_contract");
    assert.equal(observationEvent.payload.computer_use_observation_ref, "observation-live-browser");
  } finally {
    await daemon.close();
  }
});

test("runtime daemon projects browser observation artifacts into canonical computer-use targets", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-artifacts-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-artifacts-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const run = await agent.send("Use the browser to inspect the mounted app.", {
      metadata: {
        computerUse: true,
        computerUseBrowserObservationArtifacts: {
          url: "https://artifact.example.test/app",
          page_title: "Artifact App",
          browser_use_selector_map_text:
            "[42] <button name=Submit target_id=target-submit />\n" +
            "[43] <input name=Search placeholder=Search target_id=target-search />",
          browsergym_dom_text: '<button id="submit">Submit</button><input placeholder="Search" />',
          browsergym_axtree_text: "button Submit\ntextbox Search",
          browsergym_focused_bid: "bid-submit",
        },
      },
    });
    const trace = await run.inspect();
    assert.equal(trace.computerUse.observation.url, "https://artifact.example.test/app");
    assert.equal(trace.computerUse.observation.title, "Artifact App");
    assert.equal(trace.computerUse.observation.dom_ref.endsWith(":browsergym_dom"), true);
    assert.equal(trace.computerUse.observation.selector_map_ref.endsWith(":selector_map"), true);

    const [button, input] = trace.computerUse.targetIndex.targets;
    assert.equal(button.target_ref.endsWith(":target-submit"), true);
    assert.equal(button.label, "Submit");
    assert.equal(button.role, "button");
    assert.equal(button.available_actions.includes("click"), true);
    assert.equal(input.label, "Search");
    assert.equal(input.available_actions.includes("type_text"), true);
    assert.equal(trace.computerUse.actionProposal.target_ref, button.target_ref);
    assert.equal(
      trace.computerUse.affordanceGraph.affordances.some((affordance) =>
        affordance.target_ref === button.target_ref &&
          affordance.possible_action === "click" &&
          affordance.confirmation_required === true,
      ),
      true,
    );

    const thread = await agent.thread();
    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const observationEvent = runtimeEvents.find((event) => event.eventKind === "computer_use.observation");
    assert.ok(observationEvent);
    assert.equal(observationEvent.payload.computer_use_contract_ingest, "browser_observation_artifacts");
    assert.equal(observationEvent.payload.target_index.targets.length, 2);
  } finally {
    await daemon.close();
  }
});

test("runtime service bridge computer-use events persist as run trace artifacts", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-bridge-computer-use-artifacts-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-bridge-computer-use-artifacts-state-"));
  const bridgeAdapter = {
    bridgeId: "test-runtime-service-computer-use-bridge",
    async startThread(input) {
      const createdAt = new Date().toISOString();
      return {
        session_id: "session_bridge_computer_use",
        status: "active",
        updated_at: createdAt,
        events: [
          runtimeBridgeEnvelope({
            eventKind: "thread.started",
            idempotencyKey: `thread:${input.threadId}:started`,
            itemId: `${input.threadId}:item:started`,
            createdAt,
            payload: { event_kind: "ThreadStarted", status: "active" },
          }),
        ],
      };
    },
    async submitTurn(input) {
      const createdAt = new Date().toISOString();
      const turnId = "turn_bridge_computer_use";
      const runId = "run_bridge_computer_use";
      return {
        turn_id: turnId,
        run_id: runId,
        status: "completed",
        result: "The bridge observed the mounted browser surface and indexed the Submit button.",
        created_at: createdAt,
        updated_at: createdAt,
        stop_reason: "runtime_bridge_completed",
        events: [
          runtimeBridgeEnvelope({
            eventKind: "turn.started",
            idempotencyKey: `${turnId}:started`,
            itemId: `${turnId}:item:started`,
            turnId,
            createdAt,
            payload: { event_kind: "TurnStarted", prompt: input.request.prompt },
          }),
          runtimeBridgeEnvelope({
            eventKind: "computer_use.observation",
            sourceEventKind: "ComputerUse.Observation",
            idempotencyKey: `${turnId}:computer-use:observation`,
            itemId: `${turnId}:item:computer-use-observation`,
            turnId,
            createdAt,
            payloadSchemaVersion: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
            componentKind: "computer_use_harness",
            workflowNodeId: "computer-use.observe",
            receiptRefs: ["receipt_bridge_computer_use_trace"],
            artifactRefs: ["computer-use-trace.json"],
            payload: {
              schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
              event_kind: "ComputerUse.Observation",
              computer_use_step: "observe",
              computer_use_contract_ingest: "browser_observation_artifacts",
              observation_bundle: {
                observation_ref: "observation-bridge-browser",
                lease_id: "lease-bridge-browser",
                lane: "native_browser",
                session_mode: "owned_hermetic_browser",
                url: "https://bridge.example.test/app",
                title: "Bridge App",
                target_index_ref: "target-index-bridge-browser",
                retention_mode: "local_redacted_artifacts",
                detected_patterns: ["form", "toolbar"],
              },
              target_index: {
                target_index_ref: "target-index-bridge-browser",
                observation_ref: "observation-bridge-browser",
                coordinate_space_id: "viewport-bridge-browser",
                drift_state: "fresh",
                targets: [
                  {
                    target_ref: "target-bridge-submit",
                    label: "Submit",
                    role: "button",
                    confidence: 98,
                    available_actions: ["click", "inspect"],
                  },
                ],
              },
            },
          }),
          runtimeBridgeEnvelope({
            eventKind: "computer_use.affordance_graph",
            sourceEventKind: "ComputerUse.AffordanceGraph",
            idempotencyKey: `${turnId}:computer-use:affordance-graph`,
            itemId: `${turnId}:item:computer-use-affordance-graph`,
            turnId,
            createdAt,
            payloadSchemaVersion: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
            componentKind: "computer_use_harness",
            workflowNodeId: "computer-use.affordance-graph",
            receiptRefs: ["receipt_bridge_computer_use_trace"],
            artifactRefs: ["computer-use-trace.json"],
            payload: {
              schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
              event_kind: "ComputerUse.AffordanceGraph",
              computer_use_step: "build_affordance_graph",
              computer_use_affordance_graph_ref: "affordance-bridge-browser",
              computer_use_target_index_ref: "target-index-bridge-browser",
              affordance_graph: {
                graph_ref: "affordance-bridge-browser",
                target_index_ref: "target-index-bridge-browser",
                observation_ref: "observation-bridge-browser",
                affordances: [
                  {
                    target_ref: "target-bridge-submit",
                    possible_action: "click",
                    confidence: 93,
                    risk_class: "external_effect_possible",
                    confirmation_required: true,
                  },
                ],
              },
            },
          }),
          runtimeBridgeEnvelope({
            eventKind: "turn.completed",
            sourceEventKind: "TurnCompleted",
            idempotencyKey: `${turnId}:completed`,
            itemId: `${turnId}:item:completed`,
            turnId,
            createdAt,
            payload: { event_kind: "TurnCompleted", stop_reason: "runtime_bridge_completed" },
          }),
        ],
      };
    },
  };
  const daemon = await startRuntimeDaemonService({ cwd, stateDir, runtimeBridge: bridgeAdapter });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const thread = await Thread.create({
      local: { cwd },
      model: { id: "local:auto" },
      runtimeProfile: "runtime_service",
      substrateClient: client,
    });
    const turn = await thread.send("Use the browser to inspect the bridge-mounted app.", {
      metadata: { computerUse: true },
    });
    const trace = await client.inspectRun(turn.runId);
    const directComputerUseTrace = await client.getRunComputerUseTrace(turn.runId);
    const directTrajectory = await client.getRunComputerUseTrajectory(turn.runId);
    assert.equal(trace.source, "runtime_service");
    assert.deepEqual(
      trace.events.filter((event) => event.type.startsWith("computer_use_")).map((event) => event.type),
      [
        "computer_use_observation",
        "computer_use_affordance_graph",
        "computer_use_action_proposed",
        "computer_use_commit_gate",
      ],
    );
    const turnEvents = [];
    for await (const event of turn.events()) {
      turnEvents.push(event);
    }
    assert.deepEqual(
      turnEvents.filter((event) => event.eventKind.startsWith("computer_use.")).map((event) => event.type),
      [
        "computer_use_observation",
        "computer_use_affordance_graph",
        "computer_use_action_proposed",
        "computer_use_commit_gate",
      ],
    );
    assert.equal(trace.computerUse.environmentSelection.selected_lane, "native_browser");
    assert.equal(trace.computerUse.environmentSelection.selected_session_mode, "owned_hermetic_browser");
    assert.equal(trace.computerUse.lease.lease_id, "lease-bridge-browser");
    assert.equal(trace.computerUse.lease.cleanup_required, false);
    assert.equal(trace.computerUse.runState.current_observation_ref, "observation-bridge-browser");
    assert.equal(trace.computerUse.runState.verification_status, "requires_human");
    assert.equal(trace.computerUse.runState.blocker_state, "commit_gate_requires_confirmation");
    assert.equal(trace.computerUse.observation.url, "https://bridge.example.test/app");
    assert.equal(trace.computerUse.targetIndex.targets[0].target_ref, "target-bridge-submit");
    assert.equal(trace.computerUse.affordanceGraph.affordances[0].possible_action, "click");
    assert.equal(trace.computerUse.actionProposal.target_ref, "target-bridge-submit");
    assert.equal(trace.computerUse.actionProposal.confirmation_required, true);
    assert.equal(trace.computerUse.action, null);
    assert.equal(trace.computerUse.outcomeContract.external_effect_policy, "confirmation_required");
    assert.equal(trace.computerUse.commitGate.status, "requires_confirmation_before_execution");
    assert.equal(trace.computerUse.commitGate.final_action_ref, null);
    assert.equal(directComputerUseTrace.commitGate.status, "requires_confirmation_before_execution");
    assert.equal(directTrajectory.entries.at(-1).event_kind, "commit_or_handoff");
    assert.deepEqual(
      trace.computerUse.trajectory.entries.map((entry) => entry.event_kind),
      ["observe", "build_affordance_graph", "propose_action", "commit_or_handoff"],
    );
    assert.equal(trace.computerUse.contractIngest, "browser_observation_artifacts");
    assert.equal(trace.receipts.some((receipt) => receipt.kind === "computer_use_trace"), true);

    const artifacts = await client.listArtifacts(turn.runId);
    const computerUseArtifact = artifacts.find((artifact) => artifact.name === "computer-use-trace.json");
    assert.ok(computerUseArtifact);
    const namedComputerUseArtifact = await client.downloadArtifact(turn.runId, "computer-use-trace.json");
    assert.equal(namedComputerUseArtifact.id, computerUseArtifact.id);
    const artifactTrace = JSON.parse(computerUseArtifact.content);
    assert.equal(artifactTrace.environmentSelection.selected_lane, "native_browser");
    assert.equal(artifactTrace.lease.authority_scope, "computer_use.native_browser.read");
    assert.equal(artifactTrace.runState.cleanup_state, "external_runtime_owned");
    assert.equal(artifactTrace.observation.url, "https://bridge.example.test/app");
    assert.equal(artifactTrace.targetIndex.targets[0].label, "Submit");
    assert.equal(artifactTrace.affordanceGraph.graph_ref, "affordance-bridge-browser");
    assert.equal(artifactTrace.actionProposal.risk_assessment, "external_effect_possible");
    assert.equal(artifactTrace.commitGate.user_confirmation_required, true);
    assert.equal(artifactTrace.trajectory.trajectory_ref, "trajectory_run_bridge_computer_use_runtime_bridge");
  } finally {
    await daemon.close();
  }
});

test("runtime daemon activates mounted visual computer-use contracts instead of failing closed", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-visual-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-visual-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const run = await agent.send("Use the visual desktop to inspect the canvas app.", {
      metadata: {
        computerUse: true,
        computerUseLane: "visual_gui",
        computerUseSessionMode: "foreground_desktop",
        computerUseAdapterContract: {
          adapter_id: "ioi.visual_gui.test_adapter",
          lane: "visual_gui",
          supported_session_modes: ["foreground_desktop"],
          capabilities: ["observe.screenshot", "observe.som", "verify.postcondition", "cleanup"],
          emits_observation_bundle: true,
          emits_action_receipts: true,
          emits_cleanup_receipts: true,
          fail_closed_when_unavailable: true,
        },
        computerUseCleanupReceipt: {
          cleanup_ref: "cleanup-visual-mounted",
          status: "completed",
          closed_process_refs: ["window:canvas-app"],
          deleted_profile_refs: [],
          retained_artifact_refs: ["computer-use-trace.json", "artifact:visual:screenshot-redacted"],
          warnings: [],
        },
        computerUseObservationBundle: {
          observation_ref: "observation-visual-mounted",
          lane: "visual_gui",
          session_mode: "foreground_desktop",
          app_name: "Canvas App",
          window_title: "Canvas App - Mounted",
          screenshot_ref: "artifact:visual:screenshot-redacted",
          som_ref: "artifact:visual:som",
          target_index_ref: "target-index-visual-mounted",
          detected_patterns: ["canvas", "toolbar"],
        },
        computerUseTargetIndex: {
          target_index_ref: "target-index-visual-mounted",
          observation_ref: "observation-visual-mounted",
          coordinate_space_id: "screen-visual-1",
          drift_state: "fresh",
          targets: [
            {
              target_ref: "target-visual-canvas",
              label: "Main canvas",
              role: "canvas",
              semantic_ids: ["som:1"],
              selectors: [],
              som_id: 1,
              confidence: 89,
              available_actions: ["inspect"],
            },
          ],
        },
      },
    });
    const trace = await run.inspect();
    assert.deepEqual(
      trace.events.filter((event) => event.type.startsWith("computer_use_")).map((event) => event.type),
      expectedComputerUseEventTypes,
    );
    assert.equal(trace.computerUse.environmentSelection.selected_lane, "visual_gui");
    assert.equal(trace.computerUse.lease.status, "active");
    assert.equal(trace.computerUse.observation.app_name, "Canvas App");
    assert.equal(trace.computerUse.actionProposal.target_ref, "target-visual-canvas");
    assert.equal(trace.computerUse.adapterContract.adapter_id, "ioi.visual_gui.test_adapter");
    assert.equal(trace.computerUse.cleanup.status, "completed");
    assert.equal(trace.computerUse.cleanup.cleanup_ref, "cleanup-visual-mounted");
    assert.deepEqual(trace.computerUse.cleanup.closed_process_refs, ["window:canvas-app"]);

    const thread = await agent.thread();
    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    assert.equal(
      runtimeEvents.some((event) => event.eventKind === "computer_use.environment_unavailable"),
      false,
    );
    const selected = runtimeEvents.find((event) => event.eventKind === "computer_use.environment_selected");
    assert.ok(selected);
    assert.equal(selected.payload.computer_use_lane, "visual_gui");
    assert.equal(selected.payload.computer_use_contract_ingest, "canonical_runtime_contract");
    const leaseEvent = runtimeEvents.find((event) => event.eventKind === "computer_use.lease_acquired");
    assert.ok(leaseEvent);
    assert.equal(leaseEvent.payload.adapter_contract.adapter_id, "ioi.visual_gui.test_adapter");
    const cleanupEvent = runtimeEvents.find((event) => event.eventKind === "computer_use.cleanup");
    assert.ok(cleanupEvent);
    assert.equal(cleanupEvent.payload.cleanup_receipt.cleanup_ref, "cleanup-visual-mounted");
  } finally {
    await daemon.close();
  }
});

test("runtime daemon activates mounted sandboxed computer-use contracts instead of failing closed", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-hosted-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-hosted-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const run = await agent.send("Use a hosted computer to inspect the isolated app.", {
      metadata: {
        computerUse: true,
        computerUseLane: "sandboxed_hosted",
        computerUseSessionMode: "hosted_sandbox",
        computerUseAdapterContract: {
          adapter_id: "ioi.sandboxed_hosted.test_adapter",
          lane: "sandboxed_hosted",
          supported_session_modes: ["hosted_sandbox"],
          capabilities: ["provision", "observe.screenshot", "verify.postcondition", "cleanup"],
          emits_observation_bundle: true,
          emits_action_receipts: true,
          emits_cleanup_receipts: true,
          fail_closed_when_unavailable: true,
        },
        computerUseCleanupReceipt: {
          cleanup_ref: "cleanup-hosted-mounted",
          status: "completed",
          closed_process_refs: ["sandbox:hosted-session"],
          deleted_profile_refs: ["image-layer:ephemeral"],
          retained_artifact_refs: ["computer-use-trace.json", "artifact:hosted:screenshot-redacted"],
          warnings: [],
        },
        computerUseObservationBundle: {
          observation_ref: "observation-hosted-mounted",
          lane: "sandboxed_hosted",
          session_mode: "hosted_sandbox",
          app_name: "Hosted Browser",
          window_title: "Hosted session",
          screenshot_ref: "artifact:hosted:screenshot-redacted",
          target_index_ref: "target-index-hosted-mounted",
          detected_patterns: ["form"],
        },
        computerUseTargetIndex: {
          target_index_ref: "target-index-hosted-mounted",
          observation_ref: "observation-hosted-mounted",
          coordinate_space_id: "hosted-screen-1",
          drift_state: "fresh",
          targets: [
            {
              target_ref: "target-hosted-form",
              label: "Hosted form",
              role: "form",
              semantic_ids: ["hosted:form"],
              selectors: [],
              confidence: 91,
              available_actions: ["inspect"],
            },
          ],
        },
      },
    });
    const trace = await run.inspect();
    assert.equal(trace.computerUse.environmentSelection.selected_lane, "sandboxed_hosted");
    assert.equal(trace.computerUse.lease.status, "active");
    assert.equal(trace.computerUse.observation.app_name, "Hosted Browser");
    assert.equal(trace.computerUse.actionProposal.target_ref, "target-hosted-form");
    assert.equal(trace.computerUse.adapterContract.adapter_id, "ioi.sandboxed_hosted.test_adapter");
    assert.equal(trace.computerUse.cleanup.cleanup_ref, "cleanup-hosted-mounted");
    assert.deepEqual(trace.computerUse.cleanup.deleted_profile_refs, ["image-layer:ephemeral"]);
    assert.equal(
      trace.events.some((event) => event.type === "computer_use_environment_unavailable"),
      false,
    );
  } finally {
    await daemon.close();
  }
});

test("requested unavailable computer-use lanes fail closed with visible recovery policy", async () => {
  const { cwd, client } = tempClient();
  const agent = await Agent.create({
    model: { id: "local:auto" },
    local: { cwd },
    substrateClient: client,
  });
  const run = await agent.send("Use a hosted computer to inspect the target app.", {
    metadata: {
      computerUse: true,
      computerUseLane: "sandboxed_hosted",
      computerUseSessionMode: "hosted_sandbox",
    },
  });
  const trace = await run.inspect();
  assert.deepEqual(
    trace.events.filter((event) => event.type.startsWith("computer_use_")).map((event) => event.type),
    expectedUnavailableComputerUseEventTypes,
  );
  assert.equal(trace.computerUse.environmentSelection.selected_lane, "sandboxed_hosted");
  assert.equal(trace.computerUse.lease.status, "failed_closed");
  assert.equal(trace.computerUse.verification.status, "blocked");
  assert.equal(trace.computerUse.action, null);
  assert.equal(trace.computerUse.cleanup.status, "not_required");
  const unavailableEvent = trace.events.find((event) => event.type === "computer_use_environment_unavailable");
  assert.ok(unavailableEvent);
  assert.equal(unavailableEvent.data.recovery_policy.failure_class, "environment");

  const thread = await agent.thread();
  const runtimeEvents = [];
  for await (const event of thread.events()) {
    runtimeEvents.push(event);
  }
  const blocked = runtimeEvents.find((event) => event.eventKind === "computer_use.environment_unavailable");
  assert.ok(blocked);
  assert.equal(blocked.status, "blocked");
  assert.equal(blocked.payload.computer_use_lane, "sandboxed_hosted");
});

test("runtime daemon fails closed when requested computer-use lane is unavailable", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-unavailable-cwd-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-computer-use-unavailable-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({
      model: { id: "local:auto" },
      local: { cwd },
      substrateClient: client,
    });
    const run = await agent.send("Use the visual desktop to inspect the app.", {
      metadata: {
        computerUse: true,
        computer_use_lane: "visual_gui",
        computer_use_session_mode: "foreground_desktop",
      },
    });
    const trace = await run.inspect();
    assert.deepEqual(
      trace.events.filter((event) => event.type.startsWith("computer_use_")).map((event) => event.type),
      expectedUnavailableComputerUseEventTypes,
    );
    assert.equal(trace.computerUse.environmentSelection.selected_lane, "visual_gui");
    assert.equal(trace.computerUse.lease.status, "failed_closed");
    assert.equal(trace.computerUse.actionProposal, null);
    assert.equal(trace.computerUse.cleanup.status, "not_required");

    const thread = await agent.thread();
    const runtimeEvents = [];
    for await (const event of thread.events()) {
      runtimeEvents.push(event);
    }
    const blocked = runtimeEvents.find((event) => event.eventKind === "computer_use.environment_unavailable");
    assert.ok(blocked);
    assert.equal(blocked.status, "blocked");
    assert.equal(blocked.workflowNodeId, "computer-use.environment-unavailable");
  } finally {
    await daemon.close();
  }
});
