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
  humanHandoffForComputerUseBoundary,
  isActionProposalReadyForExecution,
  observationRetentionAllowsRawPersistence,
  outcomeContractForGoal,
  recoveryPolicyForComputerUseFailure,
} from "../dist/index.js";
import { createMockRuntimeSubstrateClient } from "../dist/testing.js";
import { startRuntimeDaemonService } from "../../runtime-daemon/src/index.mjs";

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
    assert.equal(trace.computerUse.cleanup.status, "completed");

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
