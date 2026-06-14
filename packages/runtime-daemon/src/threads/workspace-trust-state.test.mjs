import assert from "node:assert/strict";
import test from "node:test";

import { createWorkspaceTrustState } from "./workspace-trust-state.mjs";

function runtimeError({ message, code, status, details }) {
  const error = new Error(message);
  error.code = code;
  error.status = status;
  error.details = details;
  return error;
}

function createHarness({ planner } = {}) {
  const calls = [];
  const events = [
    {
      event_id: "evt_workspace_trust_warning_1",
      event_stream_id: "stream_thread_a",
      thread_id: "thread_a",
      event_kind: "workspace.trust_warning",
      workflow_node_id: "runtime.thread-mode.workspace-trust",
      payload_summary: {
        warning_id: "workspace_trust_warning_1",
        mode: "yolo",
        approval_mode: "never_prompt",
        severity: "high",
      },
      receipt_refs: ["receipt_workspace_trust_warning_1"],
      policy_decision_refs: ["policy_workspace_trust_warning_1"],
      state_root_after: "sha256:warning",
      projection_watermark: "runtime-events:stream_thread_a:1",
      resulting_head: "agentgres://runtime-events/stream_thread_a/head/1",
      seq: 1,
    },
  ];
  const state = createWorkspaceTrustState({
    contextPolicyCore: planner
      ? {
        planWorkspaceTrustControlStateUpdate(request = {}) {
          calls.push({ type: "planner", request });
          return planner(request);
        },
      }
      : null,
    eventStreamIdForThread: (threadId) => `stream_${threadId}`,
    nowIso: () => "2026-06-04T12:00:00.000Z",
    runtimeError,
  });
  const store = {
    agentForThread(threadId) {
      calls.push({ type: "agentForThread", threadId });
      return { id: "agent_a", cwd: "/workspace" };
    },
    appendRuntimeEvent(event) {
      calls.push({ type: "appendRuntimeEvent", event });
      const admitted = {
        ...event,
        seq: events.length + 1,
        state_root_after: `sha256:${events.length + 1}`,
        projection_watermark: `runtime-events:${event.event_stream_id}:${events.length + 1}`,
      };
      events.push(admitted);
      return admitted;
    },
    latestRuntimeEventSeq(eventStreamId) {
      calls.push({ type: "latestRuntimeEventSeq", eventStreamId });
      return events.filter((event) => event.event_stream_id === eventStreamId).at(-1)?.seq ?? 0;
    },
    runtimeEventsForStream(eventStreamId, cursor) {
      calls.push({ type: "runtimeEventsForStream", eventStreamId, cursor });
      return events.filter((event) => event.event_stream_id === eventStreamId);
    },
  };
  return { calls, events, state, store };
}

function rustWarningPlan(request) {
  return {
    source: "rust_workspace_trust_control_state_update_command",
    backend: "rust_policy",
    status: "planned",
    operation_kind: "workspace_trust.warning",
    thread_id: request.thread_id,
    event_stream_id: request.event_stream_id,
    warning_id: "workspace_trust_warning_2",
    workspace_trust_warning: {
      schema_version: "ioi.runtime.workspace-trust-warning.v1",
      warning_id: "workspace_trust_warning_2",
      mode: request.controls.mode,
      approval_mode: request.controls.approval_mode,
      receipt_refs: ["receipt_workspace_trust_warning_2"],
    },
    event: {
      event_id: "evt_workspace_trust_warning_2",
      event_stream_id: request.event_stream_id,
      thread_id: request.thread_id,
      event_kind: "workspace.trust_warning",
      payload_schema_version: "ioi.runtime.workspace-trust-warning.v1",
      payload_summary: {
        warning_id: "workspace_trust_warning_2",
      },
      receipt_refs: ["receipt_workspace_trust_warning_2"],
      policy_decision_refs: ["policy_workspace_trust_warning_2"],
    },
  };
}

function rustAckPlan(request) {
  assert.equal(request.events.length, 1);
  assert.equal(request.events[0].event_kind, "workspace.trust_warning");
  return {
    source: "rust_workspace_trust_control_state_update_command",
    backend: "rust_policy",
    status: "planned",
    operation_kind: "workspace_trust.acknowledge",
    thread_id: request.thread_id,
    event_stream_id: request.event_stream_id,
    warning_id: request.warning_id,
    source_event_id: request.source_event_id,
    workspace_trust_acknowledgement: {
      schema_version: "ioi.runtime.workspace-trust-acknowledgement.v1",
      warning_id: request.warning_id,
      source_event_id: request.source_event_id,
      status: "acknowledged",
      receipt_refs: ["receipt_workspace_trust_ack_1"],
    },
    event: {
      event_id: "evt_workspace_trust_ack_1",
      event_stream_id: request.event_stream_id,
      thread_id: request.thread_id,
      event_kind: "workspace.trust_acknowledged",
      payload_schema_version: "ioi.runtime.workspace-trust-acknowledgement.v1",
      payload_summary: {
        warning_id: request.warning_id,
        source_event_id: request.source_event_id,
      },
      receipt_refs: ["receipt_workspace_trust_ack_1"],
      policy_decision_refs: ["policy_workspace_trust_ack_1"],
    },
  };
}

test("workspace trust warning uses Rust planner and Rust event admission", () => {
  const { calls, events, state, store } = createHarness({ planner: rustWarningPlan });

  const result = state.appendWorkspaceTrustWarningEvent(store, {
    agent: { id: "agent_a", cwd: "/workspace" },
    threadId: "thread_a",
    controls: { mode: "yolo", approval_mode: "never_prompt" },
    request: {
      source: "react_flow",
      actor: "operator_1",
      workflow_graph_id: "graph_1",
      workspace_trust_workflow_node_id: "runtime.thread-mode.workspace-trust",
    },
    modeEvent: { event_id: "evt_thread_mode" },
    now: "2026-06-04T12:00:00.000Z",
  });

  assert.equal(result.workspace_trust_warning.warning_id, "workspace_trust_warning_2");
  assert.equal(result.workspace_trust_warning_event.event_kind, "workspace.trust_warning");
  assert.equal(result.workspace_trust_warning_event.seq, 2);
  assert.equal(events.length, 2);
  assert.deepEqual(calls.map((call) => call.type), [
    "latestRuntimeEventSeq",
    "planner",
    "appendRuntimeEvent",
  ]);
  assert.equal(calls[1].request.operation_kind, "workspace_trust.warning");
  assert.equal(calls[1].request.source_event_id, "evt_thread_mode");
  assert.equal(calls[2].event.receipt_refs[0], "receipt_workspace_trust_warning_2");
});

test("workspace trust acknowledgement replays warning truth before Rust planning", () => {
  const { calls, events, state, store } = createHarness({ planner: rustAckPlan });

  const result = state.acknowledgeWorkspaceTrustWarning(
    store,
    "thread_a",
    "workspace_trust_warning_1",
    {
      source_event_id: "evt_workspace_trust_warning_1",
      source: "react_flow",
      actor: "operator_1",
      workflow_graph_id: "graph_1",
      workflow_node_id: "runtime.thread-mode.workspace-trust",
      reason: "operator reviewed warning",
    },
  );

  assert.equal(
    result.workspace_trust_acknowledgement.warning_id,
    "workspace_trust_warning_1",
  );
  assert.equal(result.workspace_trust_acknowledgement_event.event_kind, "workspace.trust_acknowledged");
  assert.equal(result.workspace_trust_acknowledgement_event.seq, 2);
  assert.equal(events.length, 2);
  assert.deepEqual(calls.map((call) => call.type), [
    "agentForThread",
    "runtimeEventsForStream",
    "latestRuntimeEventSeq",
    "planner",
    "appendRuntimeEvent",
  ]);
  assert.equal(calls[3].request.operation_kind, "workspace_trust.acknowledge");
  assert.equal(calls[3].request.events[0].event_id, "evt_workspace_trust_warning_1");
});

test("workspace trust controls fail closed before lookup when Rust planner is missing", () => {
  const { calls, state, store } = createHarness();

  assert.throws(
    () => state.acknowledgeWorkspaceTrustWarning(store, "thread_a", "workspace_trust_warning_1", {
      source_event_id: "evt_workspace_trust_warning_1",
    }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_workspace_trust_control_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.workspace_trust_control");
      assert.equal(error.details.operation, "workspace_trust_control");
      assert.equal(error.details.thread_id, "thread_a");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_workspace_trust_control_rust_planner_required",
        "runtime_workspace_trust_event_admission_rust_required",
        "runtime_workspace_trust_replay_rust_required",
        "agentgres_workspace_trust_truth_required",
      ]);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("workspace trust rejects Rust projection mismatches before event admission", () => {
  const { calls, state, store } = createHarness({
    planner: () => ({
      operation_kind: "workspace_trust.acknowledge",
      event: {
        thread_id: "thread_a",
        event_kind: "workspace.trust_warning",
        receipt_refs: ["receipt_wrong"],
      },
    }),
  });

  assert.throws(
    () => state.acknowledgeWorkspaceTrustWarning(store, "thread_a", "workspace_trust_warning_1", {
      source_event_id: "evt_workspace_trust_warning_1",
    }),
    (error) => {
      assert.equal(error.status, 502);
      assert.equal(error.code, "workspace_trust_rust_event_projection_invalid");
      return true;
    },
  );

  assert.deepEqual(calls.map((call) => call.type), [
    "agentForThread",
    "runtimeEventsForStream",
    "latestRuntimeEventSeq",
    "planner",
  ]);
});
