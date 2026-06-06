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

test("workspace trust state emits warnings only for trust-sensitive modes", () => {
  const { agent, events, state, store } = createHarness();

  assert.equal(
    state.appendWorkspaceTrustWarningEvent(store, {
      agent,
      threadId: "thread_a",
      controls: { mode: "ask", approvalMode: "default" },
      request: {},
      source: "test",
      requestedBy: "operator",
      workflowGraphId: "graph",
      now: "2026-06-04T00:00:00.000Z",
    }),
    null,
  );

  const event = state.appendWorkspaceTrustWarningEvent(store, {
    agent,
    threadId: "thread_a",
    controls: { mode: "review", approvalMode: "auto_review" },
    request: { workflow_node_id: "runtime.mode" },
    source: "test",
    requestedBy: "operator",
    workflowGraphId: "graph",
    now: "2026-06-04T00:00:00.000Z",
  });

  assert.equal(events.length, 1);
  assert.equal(event.event_kind, "workspace.trust_warning");
  assert.equal(event.payload_schema_version, "trust.warning.v1");
  assert.equal(event.workflow_node_id, "runtime.mode.workspace-trust");
  assert.equal(event.fixture_profile, "fixture.test");
});

test("workspace trust acknowledgement validates warning id and missing warnings", () => {
  const { state, store } = createHarness();

  assert.throws(
    () => state.acknowledgeWorkspaceTrustWarning(store, "thread_a", "", {}),
    (error) => error.code === "workspace_trust_warning_id_required",
  );
  assert.throws(
    () => state.acknowledgeWorkspaceTrustWarning(store, "thread_a", "missing", {}),
    (error) => error.code === "workspace_trust_warning_not_found",
  );
});

test("workspace trust acknowledgement records a daemon-owned acknowledgement event", () => {
  const { agent, state, store } = createHarness();
  const warning = state.appendWorkspaceTrustWarningEvent(store, {
    agent,
    threadId: "thread_a",
    controls: { mode: "yolo", approvalMode: "full_access" },
    request: {},
    source: "test",
    requestedBy: "operator",
    workflowGraphId: "graph",
    now: "2026-06-04T00:00:00.000Z",
  });

  const result = state.acknowledgeWorkspaceTrustWarning(store, "thread_a", warning.event_id, {
    source: "ack_source",
    actor: "heath",
    reason: "Reviewed local workspace trust.",
  });

  assert.equal(result.event.event_kind, "workspace.trust_acknowledged");
  assert.equal(result.event.payload_schema_version, "trust.ack.v1");
  assert.equal(result.workspace_trust_acknowledgement.warning_id, warning.event_id);
  assert.equal(result.workspace_trust_acknowledgement.acknowledged_by, "heath");
  assert.equal(result.workspace_trust_acknowledgement.command_executed, false);
  assert.equal(result.workspace_trust_acknowledgement.session_id, "session_agent_a");
  assert.equal(Object.hasOwn(result, "workspaceTrustAcknowledgement"), false);
  assert.equal(Object.hasOwn(result, "workspaceTrustAcknowledgementEvent"), false);
  assert.equal(Object.hasOwn(result.workspace_trust_acknowledgement, "schemaVersion"), false);
  assert.equal(Object.hasOwn(result.workspace_trust_acknowledgement, "warningId"), false);
  assert.equal(Object.hasOwn(result.workspace_trust_acknowledgement, "sourceEventId"), false);
  assert.equal(Object.hasOwn(result.workspace_trust_acknowledgement, "acknowledgedBy"), false);
  assert.equal(Object.hasOwn(result.workspace_trust_acknowledgement, "daemonEnforced"), false);
});

test("workspace trust acknowledgement rejects retired request aliases", () => {
  const { agent, state, store } = createHarness();
  const warning = state.appendWorkspaceTrustWarningEvent(store, {
    agent,
    threadId: "thread_a",
    controls: { mode: "yolo", approvalMode: "full_access" },
    request: {},
    source: "test",
    requestedBy: "operator",
    workflowGraphId: "graph",
    now: "2026-06-04T00:00:00.000Z",
  });

  assert.throws(
    () =>
      state.acknowledgeWorkspaceTrustWarning(store, "thread_a", warning.event_id, {
        sourceEventId: warning.event_id,
        workflowGraphId: "graph",
        workflowNodeId: "runtime.thread-mode.workspace-trust",
        idempotencyKey: "idem-retired",
      }),
    (error) =>
      error.code === "workspace_trust_acknowledgement_request_aliases_retired" &&
      error.details.thread_id === "thread_a" &&
      error.details.retired_aliases.includes("sourceEventId") &&
      error.details.retired_aliases.includes("workflowGraphId") &&
      error.details.retired_aliases.includes("workflowNodeId") &&
      error.details.retired_aliases.includes("idempotencyKey") &&
      Object.hasOwn(error.details, "threadId") === false,
  );
});
