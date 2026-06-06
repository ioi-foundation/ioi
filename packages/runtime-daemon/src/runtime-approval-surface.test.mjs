import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeApprovalLease } from "./runtime-approval-lease.mjs";
import { createRuntimeApprovalSurface } from "./runtime-approval-surface.mjs";
import {
  doctorHash,
  normalizeArray,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

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

function approvalRequestStateUpdateForRequest(request = {}) {
  const control = {
    control: "approval_request",
    approvalId: request.approval_id,
    status: "waiting_for_approval",
    source: request.source,
    reason: request.reason,
    eventId: request.event_id,
    seq: request.seq,
    receiptRefs: request.receipt_refs,
    policyDecisionRefs: request.policy_decision_refs,
    createdAt: request.created_at,
  };
  const run = request.run ?? {};
  if (request.target_kind === "agent") {
    return {
      status: "planned",
      operation_kind: "approval.required",
      target_kind: "agent",
      updated_at: request.created_at,
      operator_control: control,
      run: null,
      agent: {
        ...request.agent,
        updatedAt: request.created_at,
      },
    };
  }
  return {
    status: "planned",
    operation_kind: "approval.required",
    target_kind: "run",
    updated_at: request.created_at,
    operator_control: control,
    run: {
      ...run,
      status: run.status === "queued" || run.status === "running" ? "blocked" : run.status,
      updatedAt: request.created_at,
      turnStatus: "waiting_for_approval",
      trace: {
        ...run.trace,
        operatorControls: appendOperatorControlForTest(run.trace?.operatorControls, control),
        approvalRequests: appendOperatorControlForTest(run.trace?.approvalRequests, control),
      },
      operatorControls: appendOperatorControlForTest(run.operatorControls, control),
      approvalRequests: appendOperatorControlForTest(run.approvalRequests, control),
    },
  };
}

function approvalDecisionStateUpdateForRequest(request = {}) {
  const control = {
    control: "approval_decision",
    approvalId: request.approval_id,
    leaseId: request.lease_id,
    leaseStatus: request.lease_status,
    decision: request.decision,
    status: request.status,
    source: request.source,
    reason: request.reason,
    eventId: request.event_id,
    seq: request.seq,
    receiptRefs: request.receipt_refs,
    policyDecisionRefs: request.policy_decision_refs,
    createdAt: request.created_at,
  };
  const run = request.run ?? {};
  if (request.target_kind === "agent") {
    return {
      status: "planned",
      operation_kind: `approval.${request.decision}`,
      target_kind: "agent",
      updated_at: request.created_at,
      operator_control: control,
      run: null,
      agent: {
        ...request.agent,
        updatedAt: request.created_at,
      },
    };
  }
  return {
    status: "planned",
    operation_kind: `approval.${request.decision}`,
    target_kind: "run",
    updated_at: request.created_at,
    operator_control: control,
    run: {
      ...run,
      updatedAt: request.created_at,
      turnStatus: request.decision === "reject" ? "waiting_for_input" : run.turnStatus,
      trace: {
        ...run.trace,
        operatorControls: appendOperatorControlForTest(run.trace?.operatorControls, control),
        approvalDecisions: appendOperatorControlForTest(run.trace?.approvalDecisions, control),
      },
      operatorControls: appendOperatorControlForTest(run.operatorControls, control),
      approvalDecisions: appendOperatorControlForTest(run.approvalDecisions, control),
    },
  };
}

function approvalRevokeStateUpdateForRequest(request = {}) {
  const control = {
    control: "approval_revoke",
    approvalId: request.approval_id,
    leaseId: request.lease_id,
    leaseStatus: "revoked",
    decision: "revoke",
    status: "revoked",
    source: request.source,
    reason: request.reason,
    eventId: request.event_id,
    seq: request.seq,
    receiptRefs: request.receipt_refs,
    policyDecisionRefs: request.policy_decision_refs,
    createdAt: request.created_at,
  };
  const run = request.run ?? {};
  if (request.target_kind === "agent") {
    return {
      status: "planned",
      operation_kind: "approval.revoke",
      target_kind: "agent",
      updated_at: request.created_at,
      operator_control: control,
      run: null,
      agent: {
        ...request.agent,
        updatedAt: request.created_at,
      },
    };
  }
  const traceWithDecision = appendOperatorControlForTest(run.trace?.approvalDecisions, control);
  const decisions = appendOperatorControlForTest(run.approvalDecisions, control);
  return {
    status: "planned",
    operation_kind: "approval.revoke",
    target_kind: "run",
    updated_at: request.created_at,
    operator_control: control,
    run: {
      ...run,
      updatedAt: request.created_at,
      turnStatus: "waiting_for_input",
      trace: {
        ...run.trace,
        operatorControls: appendOperatorControlForTest(run.trace?.operatorControls, control),
        approvalDecisions: traceWithDecision,
        approvalRevocations: appendOperatorControlForTest(run.trace?.approvalRevocations, control),
      },
      operatorControls: appendOperatorControlForTest(run.operatorControls, control),
      approvalDecisions: decisions,
      approvalRevocations: appendOperatorControlForTest(run.approvalRevocations, control),
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

function createSurface({
  calls = [],
  approvalRequestStateUpdate = null,
  approvalDecisionStateUpdate = null,
  approvalRevokeStateUpdate = null,
} = {}) {
  const lease = createRuntimeApprovalLease({
    doctorHash,
    normalizeArray,
    optionalString,
    runtimeError,
    safeId,
    uniqueStrings,
  });
  return createRuntimeApprovalSurface({
    ...lease,
    approvalStateRunner: {
      planApprovalRequestStateUpdate(request) {
        calls.push({ name: "planApprovalRequestStateUpdate", request });
        return approvalRequestStateUpdate ?? approvalRequestStateUpdateForRequest(request);
      },
      planApprovalDecisionStateUpdate(request) {
        calls.push({ name: "planApprovalDecisionStateUpdate", request });
        return approvalDecisionStateUpdate ?? approvalDecisionStateUpdateForRequest(request);
      },
      planApprovalRevokeStateUpdate(request) {
        calls.push({ name: "planApprovalRevokeStateUpdate", request });
        return approvalRevokeStateUpdate ?? approvalRevokeStateUpdateForRequest(request);
      },
    },
    notFound,
    runtimeError,
  });
}

function createStore() {
  const events = [];
  const writes = [];
  const agent = {
    id: "agent_alpha",
    cwd: "/workspace/project",
    fixtureProfile: "fixture.local",
  };
  const run = {
    id: "run_alpha",
    agentId: agent.id,
    status: "running",
    turnStatus: "running",
    trace: {},
  };
  return {
    agents: new Map([[agent.id, agent]]),
    runs: new Map([[run.id, run]]),
    events,
    writes,
    agentForThread(threadId) {
      assert.equal(threadId, "thread_alpha");
      return this.agents.get(agent.id);
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
    getRun(runId) {
      const record = this.runs.get(runId);
      if (!record) throw notFound(`Run not found: ${runId}`, { runId });
      return record;
    },
    listRuns(agentId) {
      return [...this.runs.values()].filter((candidate) => candidate.agentId === agentId);
    },
    runtimeEventStream() {
      return { events };
    },
    threadForAgent(record) {
      return { thread_id: "thread_alpha", agent_id: record.id };
    },
    turnForRun(record) {
      return { turn_id: "turn_alpha", run_id: record.id, status: record.turnStatus };
    },
    writeAgent(record, operationKind) {
      writes.push({ type: "agent", operationKind, record });
    },
    writeRun(record, operationKind) {
      writes.push({ type: "run", operationKind, record });
    },
  };
}

test("approval surface requests approval and blocks the active turn", () => {
  const calls = [];
  const surface = createSurface({ calls });
  const store = createStore();

  const result = surface.requestThreadApproval(store, "thread_alpha", {
    approval_id: "approval-one",
    source: "runtime_auto",
    reason: "Need permission",
    ttl_ms: 60000,
    approval_manifest: { toolId: "file.write" },
    pressure: 0.7,
    pressure_status: "warning",
  });

  assert.equal(result.approval_id, "approval-one");
  assert.equal(result.approval_required, true);
  assert.equal(result.status, "waiting_for_approval");
  assert.equal(store.events[0].event_kind, "approval.required");
  assert.equal(store.events[0].payload_summary.approvalLease.status, "pending");
  assert.equal(store.events[0].payload_summary.approvalManifest.toolId, "file.write");
  assert.equal(store.events[0].payload_summary.pressure, 0.7);
  assert.equal(store.runs.get("run_alpha").status, "blocked");
  assert.equal(store.runs.get("run_alpha").turnStatus, "waiting_for_approval");
  assert.equal(store.runs.get("run_alpha").approvalRequests[0].approvalId, "approval-one");
  assert.equal(
    calls.find((call) => call.name === "planApprovalRequestStateUpdate").request.event_id,
    "event_1",
  );
  assert.equal(surface.latestApprovalRequestEvent(store, "thread_alpha", "approval-one"), store.events[0]);
});

test("approval surface records approval decisions with active leases", () => {
  const calls = [];
  const surface = createSurface({ calls });
  const store = createStore();
  surface.requestThreadApproval(store, "thread_alpha", {
    approval_id: "approval-one",
    reason: "Need permission",
  });

  const result = surface.decideThreadApproval(store, "thread_alpha", "approval-one", {
    decision: "approve",
    reason: "Looks good",
  });

  assert.equal(result.decision, "approve");
  assert.equal(result.lease_status, "active");
  assert.equal(result.approval_lease.status, "active");
  assert.equal(store.events[1].event_kind, "approval.approved");
  assert.equal(store.events[1].payload_summary.approvalRequestEventId, "event_1");
  assert.equal(store.runs.get("run_alpha").approvalDecisions[0].decision, "approve");
  assert.equal(
    calls.find((call) => call.name === "planApprovalDecisionStateUpdate").request.event_id,
    "event_2",
  );
  assert.equal(surface.latestApprovalDecisionEvent(store, "thread_alpha", "approval-one"), store.events[1]);
});

test("approval surface revokes approval leases and records prior decisions", () => {
  const calls = [];
  const surface = createSurface({ calls });
  const store = createStore();
  surface.requestThreadApproval(store, "thread_alpha", {
    approval_id: "approval-one",
    reason: "Need permission",
  });
  surface.decideThreadApproval(store, "thread_alpha", "approval-one", { decision: "approve" });

  const result = surface.revokeThreadApproval(store, "thread_alpha", "approval-one", {
    reason: "Changed my mind",
  });

  assert.equal(result.decision, "revoke");
  assert.equal(result.lease_status, "revoked");
  assert.equal(result.approval_lease.approvalDecisionEventId, "event_2");
  assert.equal(store.events[2].event_kind, "approval.revoked");
  assert.equal(store.events[2].payload_summary.approvalDecisionEventId, "event_2");
  assert.equal(store.runs.get("run_alpha").turnStatus, "waiting_for_input");
  assert.equal(store.runs.get("run_alpha").approvalRevocations[0].decision, "revoke");
  assert.equal(
    calls.find((call) => call.name === "planApprovalRevokeStateUpdate").request.event_id,
    "event_3",
  );
  assert.equal(surface.latestApprovalDecisionEvent(store, "thread_alpha", "approval-one"), store.events[2]);
});

test("approval surface routes runless agent approval updates through Rust planner", () => {
  const calls = [];
  const surface = createSurface({ calls });
  const store = createStore();
  store.runs.clear();

  const requestResult = surface.requestThreadApproval(store, "thread_alpha", {
    approval_id: "approval-one",
    reason: "Need permission",
  });
  const requestCall = calls.find((call) => call.name === "planApprovalRequestStateUpdate");
  assert.equal(requestCall.request.target_kind, "agent");
  assert.equal(requestCall.request.run, null);
  assert.equal(requestCall.request.agent.id, "agent_alpha");
  assert.equal(requestResult.agent_id, "agent_alpha");
  assert.equal(store.writes[0].type, "agent");
  assert.equal(store.writes[0].operationKind, "approval.required");
  assert.equal(store.agents.get("agent_alpha").updatedAt, store.events[0].created_at);

  const decisionResult = surface.decideThreadApproval(store, "thread_alpha", "approval-one", {
    decision: "approve",
    reason: "Looks good",
  });
  const decisionCall = calls.find((call) => call.name === "planApprovalDecisionStateUpdate");
  assert.equal(decisionCall.request.target_kind, "agent");
  assert.equal(decisionCall.request.run, null);
  assert.equal(decisionCall.request.agent.id, "agent_alpha");
  assert.equal(decisionResult.agent_id, "agent_alpha");
  assert.equal(store.writes[1].type, "agent");
  assert.equal(store.writes[1].operationKind, "approval.approve");
  assert.equal(store.agents.get("agent_alpha").updatedAt, store.events[1].created_at);

  const revokeResult = surface.revokeThreadApproval(store, "thread_alpha", "approval-one", {
    reason: "Changed my mind",
  });
  const revokeCall = calls.find((call) => call.name === "planApprovalRevokeStateUpdate");
  assert.equal(revokeCall.request.target_kind, "agent");
  assert.equal(revokeCall.request.run, null);
  assert.equal(revokeCall.request.agent.id, "agent_alpha");
  assert.equal(revokeResult.agent_id, "agent_alpha");
  assert.equal(store.writes[2].type, "agent");
  assert.equal(store.writes[2].operationKind, "approval.revoke");
  assert.equal(store.agents.get("agent_alpha").updatedAt, store.events[2].created_at);
});

test("approval surface ignores retired request identity aliases", () => {
  const surface = createSurface();
  const store = createStore();

  surface.requestThreadApproval(store, "thread_alpha", {
    approval_id: "approval-one",
    reason: "Need permission",
    turnId: "turn_retired",
    workflowGraphId: "graph_retired",
    workflowNodeId: "node_retired",
    idempotencyKey: "approval_request_idempotency_retired",
    receiptRefs: ["receipt_retired"],
  });

  assert.equal(store.events[0].turn_id, "turn_alpha");
  assert.equal(store.events[0].workflow_graph_id, null);
  assert.match(store.events[0].workflow_node_id, /^runtime\.approval\./);
  assert.equal(store.events[0].workflow_node_id.includes("node_retired"), false);
  assert.equal(store.events[0].idempotency_key, "thread:thread_alpha:approval.required:approval-one");
  assert.equal(store.events[0].receipt_refs.includes("receipt_retired"), false);

  surface.decideThreadApproval(store, "thread_alpha", "approval-one", {
    decision: "approve",
    turnId: "turn_retired",
    workflowGraphId: "graph_decision_retired",
    workflowNodeId: "node_decision_retired",
    idempotencyKey: "approval_decision_idempotency_retired",
  });

  assert.equal(store.events[1].turn_id, "turn_alpha");
  assert.equal(store.events[1].workflow_graph_id, null);
  assert.match(store.events[1].workflow_node_id, /^runtime\.approval\./);
  assert.equal(store.events[1].workflow_node_id.includes("node_decision_retired"), false);
  assert.match(store.events[1].idempotency_key, /^thread:thread_alpha:approval\.approve:approval-one:/);

  surface.revokeThreadApproval(store, "thread_alpha", "approval-one", {
    turnId: "turn_retired",
    workflowGraphId: "graph_revoke_retired",
    workflowNodeId: "node_revoke_retired",
    idempotencyKey: "approval_revoke_idempotency_retired",
  });

  assert.equal(store.events[2].turn_id, "turn_alpha");
  assert.equal(store.events[2].workflow_graph_id, null);
  assert.equal(store.events[2].workflow_node_id, store.events[0].workflow_node_id);
  assert.equal(store.events[2].workflow_node_id.includes("node_revoke_retired"), false);
  assert.match(store.events[2].idempotency_key, /^thread:thread_alpha:approval\.revoke:approval-one:/);
});

test("approval surface accepts canonical idempotency keys", () => {
  const surface = createSurface();
  const store = createStore();

  surface.requestThreadApproval(store, "thread_alpha", {
    approval_id: "approval-one",
    reason: "Need permission",
    idempotency_key: "approval_request_idempotency_canonical",
  });
  surface.decideThreadApproval(store, "thread_alpha", "approval-one", {
    decision: "approve",
    idempotency_key: "approval_decision_idempotency_canonical",
  });
  surface.revokeThreadApproval(store, "thread_alpha", "approval-one", {
    idempotency_key: "approval_revoke_idempotency_canonical",
  });

  assert.equal(store.events[0].idempotency_key, "approval_request_idempotency_canonical");
  assert.equal(store.events[1].idempotency_key, "approval_decision_idempotency_canonical");
  assert.equal(store.events[2].idempotency_key, "approval_revoke_idempotency_canonical");
});

test("approval surface fails closed without Rust-planned run approval updates", () => {
  const requestSurface = createSurface({
    approvalRequestStateUpdate: {
      status: "planned",
      operation_kind: "approval.required",
      target_kind: "run",
      run: null,
    },
  });
  const requestStore = createStore();

  assert.throws(
    () =>
      requestSurface.requestThreadApproval(requestStore, "thread_alpha", {
        approval_id: "approval-one",
        reason: "Need permission",
      }),
    (error) => error.code === "approval_run_state_update_planner_invalid",
  );
  assert.equal(requestStore.writes.length, 0);

  const decisionSurface = createSurface({
    approvalDecisionStateUpdate: {
      status: "planned",
      operation_kind: "approval.approve",
      target_kind: "run",
      run: null,
    },
  });
  const decisionStore = createStore();
  decisionSurface.requestThreadApproval(decisionStore, "thread_alpha", {
    approval_id: "approval-one",
    reason: "Need permission",
  });

  assert.throws(
    () =>
      decisionSurface.decideThreadApproval(decisionStore, "thread_alpha", "approval-one", {
        decision: "approve",
      }),
    (error) => error.code === "approval_run_state_update_planner_invalid",
  );
  assert.equal(decisionStore.writes.length, 1);

  const revokeSurface = createSurface({
    approvalRevokeStateUpdate: {
      status: "planned",
      operation_kind: "approval.revoke",
      target_kind: "run",
      run: null,
    },
  });
  const revokeStore = createStore();
  revokeSurface.requestThreadApproval(revokeStore, "thread_alpha", {
    approval_id: "approval-one",
    reason: "Need permission",
  });
  revokeSurface.decideThreadApproval(revokeStore, "thread_alpha", "approval-one", {
    decision: "approve",
  });

  assert.throws(
    () => revokeSurface.revokeThreadApproval(revokeStore, "thread_alpha", "approval-one", {}),
    (error) => error.code === "approval_run_state_update_planner_invalid",
  );
  assert.equal(revokeStore.writes.length, 2);
});

test("approval surface fails closed without Rust-planned operation kinds", () => {
  const requestSurface = createSurface({
    approvalRequestStateUpdate: {
      ...approvalRequestStateUpdateForRequest({
        run: createStore().runs.get("run_alpha"),
        event_id: "event_missing_request_kind",
      }),
      operation_kind: null,
    },
  });
  const requestStore = createStore();

  assert.throws(
    () =>
      requestSurface.requestThreadApproval(requestStore, "thread_alpha", {
        approval_id: "approval-one",
        reason: "Need permission",
      }),
    (error) => {
      assert.equal(error.code, "approval_state_update_operation_kind_missing");
      assert.equal(error.details.operationKind, "approval.required");
      assert.equal(error.details.targetKind, "run");
      return true;
    },
  );
  assert.equal(requestStore.writes.length, 0);
  assert.equal(requestStore.runs.get("run_alpha").status, "running");

  const decisionSurface = createSurface({
    approvalDecisionStateUpdate: {
      ...approvalDecisionStateUpdateForRequest({
        run: createStore().runs.get("run_alpha"),
        approval_id: "approval-one",
        decision: "approve",
        status: "approved",
        event_id: "event_missing_decision_kind",
      }),
      operation_kind: null,
    },
  });
  const decisionStore = createStore();
  decisionSurface.requestThreadApproval(decisionStore, "thread_alpha", {
    approval_id: "approval-one",
    reason: "Need permission",
  });

  assert.throws(
    () =>
      decisionSurface.decideThreadApproval(decisionStore, "thread_alpha", "approval-one", {
        decision: "approve",
      }),
    (error) => {
      assert.equal(error.code, "approval_state_update_operation_kind_missing");
      assert.equal(error.details.operationKind, "approval.approve");
      assert.equal(error.details.targetKind, "run");
      return true;
    },
  );
  assert.equal(decisionStore.writes.length, 1);

  const revokeSurface = createSurface({
    approvalRevokeStateUpdate: {
      ...approvalRevokeStateUpdateForRequest({
        run: createStore().runs.get("run_alpha"),
        approval_id: "approval-one",
        event_id: "event_missing_revoke_kind",
      }),
      operation_kind: null,
    },
  });
  const revokeStore = createStore();
  revokeSurface.requestThreadApproval(revokeStore, "thread_alpha", {
    approval_id: "approval-one",
    reason: "Need permission",
  });
  revokeSurface.decideThreadApproval(revokeStore, "thread_alpha", "approval-one", {
    decision: "approve",
  });

  assert.throws(
    () => revokeSurface.revokeThreadApproval(revokeStore, "thread_alpha", "approval-one", {}),
    (error) => {
      assert.equal(error.code, "approval_state_update_operation_kind_missing");
      assert.equal(error.details.operationKind, "approval.revoke");
      assert.equal(error.details.targetKind, "run");
      return true;
    },
  );
  assert.equal(revokeStore.writes.length, 2);

  const agentSurface = createSurface({
    approvalRequestStateUpdate: {
      ...approvalRequestStateUpdateForRequest({
        target_kind: "agent",
        agent: createStore().agents.get("agent_alpha"),
        event_id: "event_missing_agent_request_kind",
      }),
      operation_kind: null,
    },
  });
  const agentStore = createStore();
  agentStore.runs.clear();

  assert.throws(
    () =>
      agentSurface.requestThreadApproval(agentStore, "thread_alpha", {
        approval_id: "approval-one",
        reason: "Need permission",
      }),
    (error) => {
      assert.equal(error.code, "approval_state_update_operation_kind_missing");
      assert.equal(error.details.operationKind, "approval.required");
      assert.equal(error.details.targetKind, "agent");
      return true;
    },
  );
  assert.equal(agentStore.writes.length, 0);
  assert.equal(agentStore.agents.get("agent_alpha").updatedAt, undefined);
});

test("approval surface fails closed for missing approval ids and requests", () => {
  const surface = createSurface();
  const store = createStore();

  assert.throws(
    () => surface.decideThreadApproval(store, "thread_alpha", null, { decision: "approve" }),
    (error) => error.status === 400 && error.code === "approval_id_required",
  );
  assert.throws(
    () => surface.revokeThreadApproval(store, "thread_alpha", "missing", {}),
    (error) => error.status === 404 && error.details.approvalId === "missing",
  );
});
