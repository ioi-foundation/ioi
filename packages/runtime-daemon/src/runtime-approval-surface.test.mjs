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
  return {
    status: "planned",
    operation_kind: "approval.required",
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
  return {
    status: "planned",
    operation_kind: `approval.${request.decision}`,
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

function appendOperatorControlForTest(value, control) {
  const entries = Array.isArray(value) ? [...value] : [];
  if (!entries.some((entry) => entry?.eventId === control.eventId)) {
    entries.push(control);
  }
  return entries;
}

function createSurface({ calls = [] } = {}) {
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
        return approvalRequestStateUpdateForRequest(request);
      },
      planApprovalDecisionStateUpdate(request) {
        calls.push({ name: "planApprovalDecisionStateUpdate", request });
        return approvalDecisionStateUpdateForRequest(request);
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
  const surface = createSurface();
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
  assert.equal(surface.latestApprovalDecisionEvent(store, "thread_alpha", "approval-one"), store.events[2]);
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
