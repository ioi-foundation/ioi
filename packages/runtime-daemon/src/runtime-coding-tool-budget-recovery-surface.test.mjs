import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeCodingToolBudgetRecoverySurface } from "./runtime-coding-tool-budget-recovery-surface.mjs";

function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}

function notFound(message, details) {
  const error = new Error(message);
  error.status = 404;
  error.details = details;
  return error;
}

function codingToolBudgetRecoveryStateUpdateForRequest(request = {}) {
  const control = {
    control: "coding_tool_budget_recovery",
    action: "retry_approved",
    approvalId: request.approval_id,
    status: "completed",
    source: request.source,
    eventId: request.event_id,
    seq: request.seq,
    receiptRefs: request.receipt_refs,
    policyDecisionRefs: request.policy_decision_refs,
    createdAt: request.created_at,
  };
  const run = request.run ?? {};
  return {
    status: "planned",
    operation_kind: "workflow.run.retry_completed",
    updated_at: request.created_at,
    operator_control: control,
    run: {
      ...run,
      updatedAt: request.created_at,
      trace: {
        ...run.trace,
        operatorControls: appendOperatorControlForTest(run.trace?.operatorControls, control),
      },
      operatorControls: appendOperatorControlForTest(run.operatorControls, control),
    },
  };
}

function appendOperatorControlForTest(value, control) {
  const entries = Array.isArray(value) ? [...value] : [];
  if (!entries.some((entry) => entry?.eventId === control.eventId)) {
    entries.push(control);
  }
  return entries;
}

function createSurface({ calls = [], budgetRecoveryStateUpdate = null } = {}) {
  return createRuntimeCodingToolBudgetRecoverySurface({
    approvalReasonForDecisionEvent(event) {
      return event?.payload_summary?.reason ?? "approval_not_satisfied";
    },
    contextPolicyRunner: {
      planCodingToolBudgetRecoveryStateUpdate(request) {
        calls.push({ name: "planCodingToolBudgetRecoveryStateUpdate", request });
        return budgetRecoveryStateUpdate ?? codingToolBudgetRecoveryStateUpdateForRequest(request);
      },
    },
    notFound,
    runtimeError,
  });
}

function createBlockedEvent(overrides = {}) {
  return {
    event_id: "event_budget_blocked",
    seq: 1,
    thread_id: "thread_alpha",
    turn_id: "turn_alpha",
    event_kind: "workflow.run.coding_tool",
    source_event_kind: "WorkflowRunCodingToolBudgetPreflightBlocked",
    status: "blocked",
    component_kind: "coding_tool",
    workflow_graph_id: "graph_alpha",
    workflow_node_id: "node_budget",
    approval_id: "approval_budget",
    receipt_refs: ["receipt_blocked"],
    policy_decision_refs: ["policy_blocked"],
    payload_summary: {
      reason: "workflow_run_coding_tool_budget_preflight_blocked",
      approval_id: "approval_budget",
      target_node_ids: ["node_budget"],
      recovery_policy: {
        retryLimit: 1,
      },
    },
    ...overrides,
  };
}

function createStore({ initialEvents = [createBlockedEvent()] } = {}) {
  const events = [...initialEvents];
  const writes = [];
  const calls = [];
  const agent = {
    id: "agent_alpha",
    cwd: "/workspace/project",
    fixtureProfile: "fixture.local",
  };
  const run = {
    id: "run_alpha",
    agentId: agent.id,
    status: "blocked",
    trace: {},
  };

  return {
    agents: new Map([[agent.id, agent]]),
    runs: new Map([[run.id, run]]),
    events,
    writes,
    calls,
    getAgent(agentId) {
      const record = this.agents.get(agentId);
      if (!record) throw notFound(`Agent not found: ${agentId}`, { agentId });
      return record;
    },
    getRun(runId) {
      const record = this.runs.get(runId);
      if (!record) throw notFound(`Run not found: ${runId}`, { runId });
      return record;
    },
    projectThreadEvents(inputAgent) {
      calls.push({ name: "projectThreadEvents", agentId: inputAgent.id });
      return events;
    },
    runtimeEventsForTurn(turnId) {
      return events.filter((event) => event.turn_id === turnId);
    },
    runtimeEventStream() {
      return { events };
    },
    appendRuntimeEvent(record) {
      const event = {
        ...record,
        event_id: `event_${events.length + 1}`,
        seq: events.length + 1,
        payload_summary: record.payload,
      };
      events.push(event);
      return event;
    },
    requestThreadApproval(threadId, request = {}) {
      calls.push({ name: "requestThreadApproval", threadId, request });
      const event = this.appendRuntimeEvent({
        event_stream_id: `${threadId}:events`,
        thread_id: threadId,
        turn_id: request.turnId,
        event_kind: "approval.required",
        status: "waiting_for_approval",
        approval_id: request.approvalId,
        payload: {
          approval_id: request.approvalId,
          approvalManifest: request.approvalManifest,
        },
        receipt_refs: ["receipt_approval_request"],
        policy_decision_refs: ["policy_approval_request"],
      });
      return {
        approval_id: request.approvalId,
        event_id: event.event_id,
        receipt_refs: event.receipt_refs,
        policy_decision_refs: event.policy_decision_refs,
      };
    },
    decideThreadApproval(threadId, approvalId, request = {}) {
      calls.push({ name: "decideThreadApproval", threadId, approvalId, request });
      const decisionKind = request.decision === "approve" ? "approval.approved" : "approval.rejected";
      const event = this.appendRuntimeEvent({
        event_stream_id: `${threadId}:events`,
        thread_id: threadId,
        turn_id: request.turnId,
        event_kind: decisionKind,
        status: request.decision === "approve" ? "approved" : "rejected",
        approval_id: approvalId,
        payload: {
          decision: request.decision,
          reason: request.decision === "approve" ? "approved" : "rejected_by_operator",
        },
        receipt_refs: [`receipt_${request.decision}`],
        policy_decision_refs: [`policy_${request.decision}`],
      });
      return {
        approval_id: approvalId,
        event_id: event.event_id,
        receipt_refs: event.receipt_refs,
        policy_decision_refs: event.policy_decision_refs,
      };
    },
    latestApprovalRequestEvent(threadId, approvalId) {
      return events
        .filter(
          (event) =>
            event.thread_id === threadId &&
            event.approval_id === approvalId &&
            event.event_kind === "approval.required",
        )
        .at(-1) ?? null;
    },
    latestApprovalDecisionEvent(threadId, approvalId) {
      return events
        .filter(
          (event) =>
            event.thread_id === threadId &&
            event.approval_id === approvalId &&
            (event.event_kind === "approval.approved" || event.event_kind === "approval.rejected"),
        )
        .at(-1) ?? null;
    },
    writeRun(record, operationKind) {
      writes.push({ record, operationKind });
    },
  };
}

test("budget recovery surface finds the latest blocked coding-tool event", () => {
  const surface = createSurface();
  const older = createBlockedEvent({ event_id: "event_old", seq: 1 });
  const newer = createBlockedEvent({
    event_id: "event_new",
    seq: 2,
    payload_summary: {
      reason: "coding_tool_budget_exceeded",
      approval_id: "approval_new",
    },
  });
  const store = createStore({
    initialEvents: [
      older,
      { event_id: "event_noise", seq: 3, turn_id: "turn_alpha", event_kind: "runtime.progress" },
      newer,
    ],
  });

  assert.equal(surface.latestCodingToolBudgetBlockedEventForRun(store, "run_alpha"), newer);
  assert.equal(surface.latestCodingToolBudgetBlockedEventForRun(store, "run_alpha", "event_old"), older);
  assert.deepEqual(store.calls, [{ name: "projectThreadEvents", agentId: "agent_alpha" }, { name: "projectThreadEvents", agentId: "agent_alpha" }]);
});

test("budget recovery surface requests approval with stable manifest and refs", () => {
  const surface = createSurface();
  const store = createStore();

  const result = surface.codingToolBudgetRecoveryForRun(store, "run_alpha", {
    action: "request_approval",
    source: "runtime_auto",
    actor: "operator-one",
  });

  assert.equal(result.status, "waiting_for_approval");
  assert.equal(result.approvalId, "approval_budget");
  assert.equal(result.event.event_kind, "approval.required");
  assert.deepEqual(result.targetNodeIds, ["node_budget"]);
  assert.deepEqual(result.receiptRefs, [
    "receipt_blocked",
    "receipt_run_alpha_coding_tool_budget_recovery_request_approval_approval_budget",
    "receipt_approval_request",
  ]);
  const request = store.calls.find((call) => call.name === "requestThreadApproval").request;
  assert.equal(request.action, "workflow_run.coding_budget_recovery");
  assert.equal(request.approvalManifest.schemaVersion, "ioi.workflow.coding-tool-budget-recovery.v1");
  assert.equal(request.approvalManifest.recoveryPolicy.retryLimit, 1);
  assert.equal(request.approvalManifest.workflowNodeId, "node_budget");
});

test("budget recovery surface blocks retry until approval is requested and approved", () => {
  const surface = createSurface();
  const store = createStore();

  const missingApproval = surface.codingToolBudgetRecoveryForRun(store, "run_alpha", {
    action: "retry_approved",
  });
  assert.equal(missingApproval.status, "blocked");
  assert.equal(missingApproval.reason, "approval_request_missing");

  surface.codingToolBudgetRecoveryForRun(store, "run_alpha", { action: "request_approval" });
  const missingDecision = surface.codingToolBudgetRecoveryForRun(store, "run_alpha", {
    action: "retry_approved",
  });
  assert.equal(missingDecision.status, "blocked");
  assert.equal(missingDecision.reason, "approval_decision_missing");

  const rejected = surface.codingToolBudgetRecoveryForRun(store, "run_alpha", {
    action: "reject_override",
  });
  assert.equal(rejected.status, "rejected");

  const blockedByDecision = surface.codingToolBudgetRecoveryForRun(store, "run_alpha", {
    action: "retry_approved",
  });
  assert.equal(blockedByDecision.status, "blocked");
  assert.equal(blockedByDecision.reason, "rejected_by_operator");
});

test("budget recovery surface records approved retry and enforces retry limit", () => {
  const calls = [];
  const surface = createSurface({ calls });
  const store = createStore();

  surface.codingToolBudgetRecoveryForRun(store, "run_alpha", { action: "request_approval" });
  const approved = surface.codingToolBudgetRecoveryForRun(store, "run_alpha", {
    action: "approve_override",
  });
  assert.equal(approved.status, "approved");

  const retry = surface.codingToolBudgetRecoveryForRun(store, "run_alpha", {
    action: "retry_approved",
    source: "runtime_auto",
  });
  assert.equal(retry.status, "completed");
  assert.equal(retry.event.event_kind, "workflow.run.retry_completed");
  assert.equal(retry.event.payload_summary.retryCount, 1);
  assert.equal(retry.event.fixture_profile, "fixture.local");
  assert.equal(
    calls.find((call) => call.name === "planCodingToolBudgetRecoveryStateUpdate").request.event_id,
    retry.event.event_id,
  );
  assert.equal(store.runs.get("run_alpha").operatorControls[0].action, "retry_approved");
  assert.equal(store.writes[0].operationKind, "workflow.run.retry_completed");

  const limit = surface.codingToolBudgetRecoveryForRun(store, "run_alpha", {
    action: "retry_approved",
  });
  assert.equal(limit.status, "blocked");
  assert.equal(limit.reason, "retry_limit_exceeded");
  assert.equal(store.events.filter((event) => event.event_kind === "workflow.run.retry_completed").length, 1);
});

test("budget recovery surface fails closed without Rust-planned retry run", () => {
  const calls = [];
  const surface = createSurface({
    calls,
    budgetRecoveryStateUpdate: {
      status: "planned",
      operation_kind: "workflow.run.retry_completed",
      run: null,
    },
  });
  const store = createStore();

  surface.codingToolBudgetRecoveryForRun(store, "run_alpha", { action: "request_approval" });
  surface.codingToolBudgetRecoveryForRun(store, "run_alpha", { action: "approve_override" });

  assert.throws(
    () =>
      surface.codingToolBudgetRecoveryForRun(store, "run_alpha", {
        action: "retry_approved",
        source: "runtime_auto",
      }),
    (error) => error.code === "coding_tool_budget_recovery_state_update_planner_invalid",
  );
  assert.equal(store.writes.length, 0);
  assert.equal(
    calls.find((call) => call.name === "planCodingToolBudgetRecoveryStateUpdate").request.event_id,
    "event_4",
  );
});

test("budget recovery surface preserves the run/thread compatibility boundary", () => {
  const surface = createSurface();
  const store = createStore();

  assert.throws(
    () => surface.codingToolBudgetRecoveryForRun(store, "run_alpha", { threadId: "thread_other" }),
    (error) => error.status === 404 && error.details.threadId === "thread_other",
  );
});
