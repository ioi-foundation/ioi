import assert from "node:assert/strict";
import test from "node:test";

import { createWorkspaceTrustState } from "./workspace-trust-state.mjs";

function createHarness() {
  const calls = [];
  const agent = { id: "agent_a", cwd: "/workspace" };
  const events = [];
  const state = createWorkspaceTrustState({
    eventStreamIdForThread: (threadId) => `stream_${threadId}`,
    fixtureProfileForAgent: () => "fixture.test",
    optionalString: (value) => (typeof value === "string" && value ? value : undefined),
    operatorControlSource: (source) => source ?? "operator",
    runtimeError: ({ message, code, status, details }) => {
      const error = new Error(message);
      error.code = code;
      error.status = status;
      error.details = details;
      return error;
    },
    runtimeSessionIdForAgent: (record) => `session_${record.id}`,
    safeId: (value) => String(value).replace(/[^a-z0-9]+/gi, "_"),
    workspaceTrustAcknowledgementSchemaVersion: "trust.ack.v1",
    workspaceTrustWarningRecordForMode: ({ controls, threadId, workflowNodeId }) => ({
      warning_id: "warning_1",
      mode: controls.mode,
      approval_mode: controls.approvalMode,
      severity: "warning",
      thread_id: threadId,
      workflow_node_id: workflowNodeId,
      workspace_root_hash: "workspace_hash",
      branch_policy_status: "unknown",
      warning_reasons: ["review_mode"],
    }),
    workspaceTrustWarningSchemaVersion: "trust.warning.v1",
  });
  const store = {
    agentForThread(threadId) {
      calls.push({ type: "agentForThread", threadId });
      return agent;
    },
    appendRuntimeEvent(event) {
      const record = {
        ...event,
        event_id: event.event_id ?? `event_${events.length + 1}`,
      };
      events.push(record);
      calls.push({ type: "appendRuntimeEvent", event: record });
      return record;
    },
    runtimeEventStream() {
      return { events };
    },
    threadForAgent(record) {
      calls.push({ type: "threadForAgent", agentId: record.id });
      return { thread_id: "thread_a", agent_id: record.id, latest_seq: events.length };
    },
  };
  return { agent, calls, events, state, store };
}

function assertNoRetiredDetailAliases(details) {
  for (const key of [
    "rustCoreBoundary",
    "operationKind",
    "requestedOperation",
    "requestedControlKind",
    "threadId",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(details, key), false);
  }
}

function assertWorkspaceTrustRustCoreRequired(
  error,
  { operation, controlKind, threadId = "thread_a" } = {},
) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_workspace_trust_control_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.workspace_trust_control");
  assert.equal(error.details.operation, "workspace_trust_control");
  assert.equal(error.details.operation_kind, "workspace_trust_control");
  assert.equal(error.details.requested_operation, operation);
  assert.equal(error.details.requested_control_kind, controlKind);
  assert.equal(error.details.thread_id, threadId);
  assert.deepEqual(error.details.evidence_refs, [
    "runtime_workspace_trust_control_js_facade_retired",
    "runtime_workspace_trust_warning_js_facade_retired",
    "runtime_workspace_trust_acknowledgement_js_facade_retired",
    "runtime_workspace_trust_event_append_js_retired",
    "rust_daemon_core_workspace_trust_control_required",
    "agentgres_workspace_trust_truth_required",
  ]);
  assertNoRetiredDetailAliases(error.details);
}

test("workspace trust warning facade fails closed before JS event append", () => {
  const { agent, calls, events, state, store } = createHarness();

  assert.throws(
    () => state.appendWorkspaceTrustWarningEvent(store, {
      agent,
      threadId: "thread_a",
      controls: { mode: "review", approvalMode: "auto_review" },
      request: {
        workflowNodeId: "runtime.mode.retired",
        workspaceTrustWorkflowNodeId: "runtime.workspace-trust.retired",
        trustWarningWorkflowNodeId: "runtime.trust-warning.retired",
      },
      source: "test",
      requestedBy: "operator",
      workflowGraphId: "graph",
      modeEvent: { workflow_node_id: "runtime.mode.canonical-event" },
      now: "2026-06-04T00:00:00.000Z",
    }),
    (error) => {
      assertWorkspaceTrustRustCoreRequired(error, {
        operation: "warning",
        controlKind: "workspace_trust_warning",
      });
      return true;
    },
  );

  assert.deepEqual(calls, []);
  assert.deepEqual(events, []);
});

test("workspace trust acknowledgement facade fails closed before lookup or append", () => {
  const { calls, events, state, store } = createHarness();

  assert.throws(
    () => state.acknowledgeWorkspaceTrustWarning(store, "thread_a", "warning_1", {
      sourceEventId: "warning_event_retired",
      workflowGraphId: "graph_retired",
      workflowNodeId: "runtime.thread-mode.workspace-trust",
      idempotencyKey: "idem-retired",
    }),
    (error) => {
      assertWorkspaceTrustRustCoreRequired(error, {
        operation: "acknowledge",
        controlKind: "workspace_trust_acknowledgement",
      });
      return true;
    },
  );

  assert.deepEqual(calls, []);
  assert.deepEqual(events, []);
});
