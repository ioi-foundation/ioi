import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  Agent,
  COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
  compileComputerUseModelActionAdapter,
  computerActionHasGrounding,
  createRuntimeSubstrateClient,
  defaultComputerUseHarnessContract,
  isActionProposalReadyForExecution,
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

const expectedComputerUseEventTypes = [
  "computer_use_environment_selected",
  "computer_use_lease_acquired",
  "computer_use_run_state",
  "computer_use_observation",
  "computer_use_affordance_graph",
  "computer_use_action_proposed",
  "computer_use_action_executed",
  "computer_use_verification",
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
    assert.equal(trace.computerUse.trajectory.entries.some((entry) => entry.event_kind === "execute_action"), true);
    assert.equal(trace.computerUse.cleanup.status, "completed");
    assert.equal(
      trace.receipts.some((receipt) => receipt.kind === "computer_use_trace"),
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
