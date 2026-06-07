import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeInvocationResultProjections } from "./runtime-invocation-results.mjs";

function createProjections() {
  return createRuntimeInvocationResultProjections({
    CODING_TOOL_PACK_ID: "coding",
    CODING_TOOL_RESULT_SCHEMA_VERSION: "ioi.runtime.coding-tool-result.v1",
    objectRecord: (value) => value && typeof value === "object" && !Array.isArray(value) ? value : null,
    optionalString: (value) => typeof value === "string" ? value.trim() || null : null,
    safeId: (value) => String(value || "unknown").replace(/[^a-z0-9]+/gi, "_").replace(/^_+|_+$/g, "").toLowerCase() || "unknown",
    uniqueStrings: (values = []) => [...new Set((Array.isArray(values) ? values : []).map((value) => String(value)).filter(Boolean))],
  });
}

test("coding tool invocation result uses canonical replay and workspace snapshot fields", () => {
  const projections = createProjections();
  const event = {
    status: "completed",
    tool_call_id: "event_call",
    thread_id: "thread_1",
    turn_id: "turn_1",
    workspace_root: "/workspace",
    receipt_refs: ["receipt_1"],
    artifact_refs: ["artifact_1"],
    rollback_refs: ["rollback_1"],
    payload_summary: {
      tool_name: "file__write",
      result: { workspace_snapshot: { snapshotId: "snap_1" } },
    },
  };
  const result = projections.codingToolInvocationResultFromEvent(event, {
    tool_id: "fallback_tool",
    agent: { cwd: "/agent" },
  });

  assert.equal(result.schema_version, "ioi.runtime.coding-tool-result.v1");
  assert.equal(result.tool_pack, "coding");
  assert.equal(result.tool_name, "file__write");
  assert.equal(result.tool_call_id, "event_call");
  assert.equal(result.workspace_root, "/agent");
  assert.equal(result.idempotent_replay, true);
  assert.deepEqual(result.workspace_snapshot, { snapshotId: "snap_1" });
  for (const field of [
    "idempotentReplay",
    "workspaceSnapshot",
    "workspaceSnapshotEvent",
    "autoDiagnostics",
  ]) {
    assert.equal(Object.hasOwn(result, field), false);
  }
  assert.equal(result.error, null);
});

test("single-event invocation results ignore retired camelCase context aliases", () => {
  const projections = createProjections();
  const baseEvent = {
    status: "completed",
    workspace_root: "/workspace",
    receipt_refs: [],
    artifact_refs: [],
    rollback_refs: [],
    payload_summary: {},
  };
  const context = {
    tool_id: "tool.canonical",
    toolId: "tool.retired",
    tool_call_id: "call_canonical",
    toolCallId: "call_retired",
    thread_id: "thread_canonical",
    threadId: "thread_retired",
    turn_id: "turn_canonical",
    turnId: "turn_retired",
    workflow_graph_id: "graph_canonical",
    workflowGraphId: "graph_retired",
    workflow_node_id: "node_canonical",
    workflowNodeId: "node_retired",
  };

  const coding = projections.codingToolInvocationResultFromEvent(baseEvent, context);
  assert.equal(coding.tool_name, "tool.canonical");
  assert.equal(coding.tool_call_id, "call_canonical");
  assert.equal(coding.thread_id, "thread_canonical");
  assert.equal(coding.turn_id, "turn_canonical");
  assert.equal(coding.workflow_graph_id, "graph_canonical");
  assert.equal(coding.workflow_node_id, "node_canonical");

  const browserDiscovery = projections.computerUseBrowserDiscoveryInvocationResultFromEvent(
    baseEvent,
    context,
  );
  assert.equal(browserDiscovery.tool_name, "tool.canonical");
  assert.equal(browserDiscovery.tool_call_id, "call_canonical");
  assert.equal(browserDiscovery.thread_id, "thread_canonical");
  assert.equal(browserDiscovery.turn_id, "turn_canonical");
  assert.equal(browserDiscovery.workflow_graph_id, "graph_canonical");
  assert.equal(browserDiscovery.workflow_node_id, "node_canonical");

  const control = projections.computerUseControlInvocationResultFromEvent(
    {
      ...baseEvent,
      payload_summary: {
        control_receipt: { control_ref: "control_1" },
      },
    },
    context,
  );
  assert.equal(control.tool_name, "tool.canonical");
  assert.equal(control.tool_call_id, "call_canonical");
  assert.equal(control.thread_id, "thread_canonical");
  assert.equal(control.turn_id, "turn_canonical");
  assert.equal(control.workflow_graph_id, "graph_canonical");
  assert.equal(control.workflow_node_id, "node_canonical");
});

test("computer-use browser discovery result normalizes object records", () => {
  const projections = createProjections();
  const event = {
    status: "completed",
    tool_call_id: "call_1",
    thread_id: "thread_1",
    payload_summary: {
      tool_ref: "computer_use__browser_discovery",
      browser_discovery_report: { browsers: ["chromium"] },
    },
  };
  const result = projections.computerUseBrowserDiscoveryInvocationResultFromEvent(event);

  assert.equal(result.object, "ioi.runtime_computer_use_browser_discovery_result");
  assert.equal(result.tool_pack, "computer_use");
  assert.deepEqual(result.result, { browsers: ["chromium"] });
  assert.equal(result.shell_fallback_used, false);
});

test("computer-use control result uses canonical control, handoff, and cleanup fields", () => {
  const projections = createProjections();
  const event = {
    status: "completed",
    payload_summary: {
      toolRef: "computer_use__control",
      control_receipt: { control_ref: "control_1" },
      controlReceipt: { control_ref: "retired_control_alias" },
      human_handoff_state: "returned",
      humanHandoffState: "retired_handoff_alias",
      cleanup_receipt: { cleanup_ref: "cleanup_1" },
      cleanupReceipt: { cleanup_ref: "retired_cleanup_alias" },
    },
  };
  const result = projections.computerUseControlInvocationResultFromEvent(event, {
    thread_id: "thread_1",
    turn_id: "turn_1",
  });

  assert.equal(result.thread_id, "thread_1");
  assert.equal(result.turn_id, "turn_1");
  assert.deepEqual(result.result.control_receipt, { control_ref: "control_1" });
  assert.equal(result.result.human_handoff_state, "returned");
  assert.deepEqual(result.result.cleanup_receipt, { cleanup_ref: "cleanup_1" });
  assert.equal(Object.hasOwn(result, "idempotentReplay"), false);
  for (const field of [
    "controlReceipt",
    "humanHandoffState",
    "cleanup",
  ]) {
    assert.equal(Object.hasOwn(result.result, field), false);
  }
  assert.equal(result.error, null);
});

test("native browser invocation result sorts events and merges payload/projection records", () => {
  const projections = createProjections();
  const result = projections.computerUseNativeBrowserInvocationResultFromEvents([
    {
      seq: 3,
      event_id: "event_3",
      status: "completed",
      receipt_refs: ["receipt_b", "receipt_a"],
      artifact_refs: ["artifact_b"],
      rollback_refs: ["rollback_1"],
      payload_summary: {
        verification_receipt: { verified: true },
        verificationReceipt: { verified: "retired_alias" },
      },
    },
    {
      seq: 1,
      event_id: "event_1",
      status: "completed",
      tool_call_id: "call_1",
      thread_id: "thread_1",
      turn_id: "turn_1",
      workspace_root: "/workspace",
      receipt_refs: ["receipt_a"],
      artifact_refs: ["artifact_a"],
      payload_summary: {
        computer_use_lane: "visual gui",
        computerUseLane: "sandboxed hosted",
        tool_ref: "computer_use__visual_gui",
        toolRef: "computer_use__retired_alias",
        workflow_graph_id: "graph_1",
        workflowGraphId: "graph_retired_alias",
        workflow_node_id: "node_1",
        workflowNodeId: "node_retired_alias",
        environment_selection_receipt: { env: "local" },
        environmentSelectionReceipt: { env: "retired_alias" },
        observation_bundle: { screen: "seen" },
        observationBundle: { screen: "retired_alias" },
      },
    },
    {
      seq: 2,
      event_id: "event_2",
      status: "failed",
      payload_summary: {
        computer_action: { action: "click" },
        computerAction: { action: "retired_alias" },
        cleanup_receipt: { cleanup_ref: "cleanup_1" },
        cleanupReceipt: { cleanup_ref: "retired_alias" },
      },
    },
  ], {
    agent: { cwd: "/agent" },
    tool_id: "computer_use__canonical_context",
    toolId: "computer_use__retired_context",
    tool_call_id: "call_canonical_context",
    toolCallId: "call_retired_context",
    thread_id: "thread_canonical_context",
    threadId: "thread_retired_context",
    turn_id: "turn_canonical_context",
    turnId: "turn_retired_context",
    workflow_graph_id: "graph_canonical_context",
    workflowGraphId: "graph_retired_context",
    workflow_node_id: "node_canonical_context",
    workflowNodeId: "node_retired_context",
    computer_use_lane: "visual_gui",
    computerUseLane: "sandboxed_hosted",
    projection: {
      lease: { lease_ref: "lease_1" },
      targetIndex: { target: "button" },
    },
  });

  assert.equal(result.schema_version, "ioi.runtime.computer-use-visual-gui-result.v1");
  assert.equal(result.object, "ioi.runtime_computer_use_visual_gui_result");
  assert.equal(result.status, "failed");
  assert.equal(result.tool_name, "computer_use__canonical_context");
  assert.equal(result.tool_call_id, "call_canonical_context");
  assert.equal(result.thread_id, "thread_canonical_context");
  assert.equal(result.turn_id, "turn_canonical_context");
  assert.equal(result.workflow_graph_id, "graph_canonical_context");
  assert.equal(result.workflow_node_id, "node_canonical_context");
  assert.deepEqual(result.event_refs, ["event_1", "event_2", "event_3"]);
  assert.deepEqual(result.receipt_refs, ["receipt_a", "receipt_b"]);
  assert.deepEqual(result.artifact_refs, ["artifact_a", "artifact_b"]);
  assert.deepEqual(result.rollback_refs, ["rollback_1"]);
  assert.deepEqual(result.result.environmentSelection, { env: "local" });
  assert.deepEqual(result.result.lease, { lease_ref: "lease_1" });
  assert.deepEqual(result.result.targetIndex, { target: "button" });
  assert.deepEqual(result.result.action, { action: "click" });
  assert.deepEqual(result.result.verification, { verified: true });
  assert.deepEqual(result.result.cleanup, { cleanup_ref: "cleanup_1" });
  assert.equal(Object.hasOwn(result, "idempotentReplay"), false);
});
