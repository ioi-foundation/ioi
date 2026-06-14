import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeApprovalSurface } from "./runtime-approval-surface.mjs";

function assertNoRetiredApprovalControlAliases(value) {
  for (const alias of [
    "approvalId",
    "eventId",
    "createdAt",
    "receiptRefs",
    "policyDecisionRefs",
    "runId",
    "targetKind",
    "includeResolved",
  ]) {
    assert.equal(Object.hasOwn(value ?? {}, alias), false, `${alias} alias must be absent`);
    if (value?.operator_control) {
      assert.equal(
        Object.hasOwn(value.operator_control, alias),
        false,
        `${alias} operator-control alias must be absent`,
      );
    }
  }
}

function assertRustReplayStateUpdateRequest(value) {
  assert.equal(value.state_dir, "/runtime-state");
  assert.equal(Object.hasOwn(value ?? {}, "run"), false);
  assert.equal(Object.hasOwn(value ?? {}, "agent"), false);
}

function createStore({ approvalStateCore = null } = {}) {
  const run = {
    id: "run_alpha",
    agentId: "agent_alpha",
    createdAt: "2026-06-06T04:00:00.000Z",
    status: "running",
    turnStatus: "running",
    trace: {},
  };
  const agent = {
    id: "agent_alpha",
    threadId: "thread_alpha",
    status: "running",
  };
  const writes = [];
  const store = {
    stateDir: "/runtime-state",
    runtimeEventStreams: new Map(),
    agents: new Map([["agent_alpha", agent]]),
    runs: new Map([["run_alpha", run]]),
    agentForThread() {
      throw new Error("approval control must not read JS agent truth");
    },
    getRun() {
      throw new Error("approval control must not read JS run truth");
    },
    listRuns() {
      throw new Error("approval control must not list JS run truth");
    },
    writeRun(updated, operationKind) {
      writes.push({ type: "run", operationKind, updated });
      this.runs.set(updated.id, updated);
      return {
        source: "rust_agentgres_runtime_run_state_commit_command",
        commit_hash: `commit_${operationKind}`,
      };
    },
    writeAgent(updated, operationKind) {
      writes.push({ type: "agent", operationKind, updated });
      this.agents.set(updated.id, updated);
      return {
        source: "rust_agentgres_runtime_agent_state_commit_command",
        commit_hash: `commit_${operationKind}`,
      };
    },
    appendRuntimeEvent() {
      throw new Error("approval control must not append runtime events in JS");
    },
  };
  const surface = createRuntimeApprovalSurface({
    approvalDecisionForRequest(value) {
      return value === "reject" || value === "rejected" ? "reject" : "approve";
    },
    approvalStateCore,
    nowIso() {
      return "2026-06-06T04:35:00.000Z";
    },
    runtimeError({ status, code, message, details }) {
      const error = new Error(message);
      error.status = status;
      error.code = code;
      error.details = details;
      return error;
    },
  });
  return { store, surface, writes };
}

function rustRunRecord(operationKind, request, control = {}) {
  const run = {
    id: request.run_id ?? "run_alpha",
    agentId: "agent_alpha",
    createdAt: "2026-06-06T04:00:00.000Z",
    status: "running",
    turnStatus: "running",
    trace: {},
  };
  return {
    source: "rust_approval_control_api",
    backend: "rust_authority",
    record: {
      object: "ioi.runtime_approval_control",
      status: "planned",
      operation_kind: operationKind,
      target_kind: "run",
      thread_id: request.thread_id,
      run_id: request.run_id ?? run.id,
      updated_at: request.created_at,
      operator_control: {
        control: control.control,
        approval_id: request.approval_id,
        event_id: request.event_id,
        seq: request.seq,
        receipt_refs: request.receipt_refs,
        policy_decision_refs: request.policy_decision_refs,
        authority: request.authority_record ?? null,
        authority_hash: request.authority_hash ?? null,
        authority_grant_refs: request.authority_grant_refs ?? [],
        authority_receipt_refs: request.authority_receipt_refs ?? [],
        created_at: request.created_at,
      },
      run: {
        ...run,
        status: control.run_status ?? run.status,
        turnStatus: control.turn_status ?? run.turnStatus,
        trace: {
          ...run.trace,
          [control.trace_key]: [
            {
              approval_id: request.approval_id,
              event_id: request.event_id,
            },
          ],
        },
      },
    },
  };
}

function approvalAuthorityResult(decision = "approve") {
  return {
    source: "rust_approval_decision_authority_protocol",
    backend: "rust_authority",
    status: "authorized",
    operation_kind: "approval.decision.authority",
    thread_id: "thread_alpha",
    approval_id: "approval_alpha",
    decision,
    target_kind: "run",
    run_id: "run_alpha",
    actor_ref: "operator://local/heath",
    wallet_network_grant_refs: ["wallet.network://grant/approval/approval_alpha"],
    authority_receipt_refs: ["receipt://wallet.network/approval/approval_alpha"],
    policy_decision_refs: ["policy_wallet_approval"],
    direct_truth_write_allowed: false,
    authority_hash: `sha256:approval-authority-${decision}`,
    authority: {
      schema_version: "ioi.runtime.approval-decision-authority.v1",
      object: "ioi.runtime_approval_decision_authority",
      status: "authorized",
      operation_kind: "approval.decision.authority",
      thread_id: "thread_alpha",
      approval_id: "approval_alpha",
      decision,
      wallet_network_grant_refs: ["wallet.network://grant/approval/approval_alpha"],
      authority_receipt_refs: ["receipt://wallet.network/approval/approval_alpha"],
      policy_decision_refs: ["policy_wallet_approval"],
      direct_truth_write_allowed: false,
      authority_hash: `sha256:approval-authority-${decision}`,
    },
  };
}

test("requestThreadApproval public surface calls Rust approval authority and commits Rust run projection", () => {
  const calls = [];
  const { store, surface, writes } = createStore({
    approvalStateCore: {
      planApprovalRequestStateUpdate(request) {
        calls.push({ method: "planApprovalRequestStateUpdate", request });
        return rustRunRecord("approval.required", request, {
          control: "approval_request",
          run_status: "blocked",
          turn_status: "waiting_for_approval",
          trace_key: "approvalRequests",
        });
      },
    },
  });

  const result = surface.requestThreadApproval(store, "thread_alpha", {
    approval_id: "approval_alpha",
    event_id: "event_approval",
    seq: 3,
    created_at: "2026-06-06T04:30:00.000Z",
    reason: "Need permission",
    receipt_refs: ["receipt_approval"],
    policy_decision_refs: ["policy_approval"],
    approvalId: "approval_retired",
    eventId: "event_retired",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "planApprovalRequestStateUpdate");
  assert.equal(calls[0].request.thread_id, "thread_alpha");
  assert.equal(calls[0].request.run_id, null);
  assert.equal(calls[0].request.target_kind, "run");
  assertRustReplayStateUpdateRequest(calls[0].request);
  assert.equal(calls[0].request.approval_id, "approval_alpha");
  assert.deepEqual(calls[0].request.receipt_refs, ["receipt_approval"]);
  assertNoRetiredApprovalControlAliases(calls[0].request);
  assert.equal(result.operation_kind, "approval.required");
  assert.equal(result.run.status, "blocked");
  assert.equal(result.run.trace.approvalRequests[0].event_id, "event_approval");
  assert.equal(result.commit.source, "rust_agentgres_runtime_run_state_commit_command");
  assert.deepEqual(writes.map((write) => write.operationKind), ["approval.required"]);
  assert.equal(store.runtimeEventStreams.size, 0);
});

test("decideThreadApproval public surface calls Rust authority with canonical decision fields", () => {
  const calls = [];
  const { store, surface, writes } = createStore({
    approvalStateCore: {
      authorizeApprovalDecision(request) {
        calls.push({ method: "authorizeApprovalDecision", request });
        return approvalAuthorityResult(request.decision);
      },
      planApprovalDecisionStateUpdate(request) {
        calls.push({ method: "planApprovalDecisionStateUpdate", request });
        return rustRunRecord("approval.approve", request, {
          control: "approval_decision",
          trace_key: "approvalDecisions",
        });
      },
    },
  });

  const result = surface.decideThreadApproval(store, "thread_alpha", "approval_alpha", {
    decision: "approve",
    event_id: "event_decision",
    seq: 4,
    created_at: "2026-06-06T04:35:00.000Z",
    lease_id: "lease_alpha",
    receipt_refs: ["receipt_js_caller_must_not_authorize"],
    authority_grant_refs: ["wallet.network://grant/approval/approval_alpha"],
    authority_receipt_refs: ["receipt://wallet.network/approval/approval_alpha"],
    policy_decision_refs: ["policy_decision"],
    status: "reject",
    action: "reject",
  });

  assert.equal(calls.length, 2);
  assert.equal(calls[0].method, "authorizeApprovalDecision");
  assert.equal(calls[0].request.decision, "approve");
  assert.equal(Object.hasOwn(calls[0].request, "run"), false);
  assert.equal(Object.hasOwn(calls[0].request, "agent"), false);
  assert.deepEqual(calls[0].request.authority_grant_refs, [
    "wallet.network://grant/approval/approval_alpha",
  ]);
  assert.deepEqual(calls[0].request.authority_receipt_refs, [
    "receipt://wallet.network/approval/approval_alpha",
  ]);
  assert.equal(calls[1].method, "planApprovalDecisionStateUpdate");
  assert.equal(calls[1].request.decision, "approve");
  assert.equal(calls[1].request.status, "approved");
  assert.equal(calls[1].request.lease_status, "active");
  assert.equal(calls[1].request.lease_id, "lease_alpha");
  assert.equal(calls[1].request.run_id, null);
  assertRustReplayStateUpdateRequest(calls[1].request);
  assert.deepEqual(calls[1].request.receipt_refs, [
    "receipt://wallet.network/approval/approval_alpha",
  ]);
  assert.equal(calls[1].request.authority_hash, "sha256:approval-authority-approve");
  assertNoRetiredApprovalControlAliases(calls[1].request);
  assert.equal(result.operation_kind, "approval.approve");
  assert.equal(result.run.trace.approvalDecisions[0].event_id, "event_decision");
  assert.equal(result.operator_control.authority_hash, "sha256:approval-authority-approve");
  assert.deepEqual(writes.map((write) => write.operationKind), ["approval.approve"]);
  assert.equal(store.runtimeEventStreams.size, 0);
});

test("approval decision facade fails closed before state update without Rust wallet.network authority", () => {
  const calls = [];
  const { store, surface, writes } = createStore({
    approvalStateCore: {
      authorizeApprovalDecision(request) {
        calls.push({ method: "authorizeApprovalDecision", request });
        const error = new Error("wallet.network approval authority is required");
        error.code = "approval_decision_authority_invalid";
        error.status = 502;
        throw error;
      },
      planApprovalDecisionStateUpdate() {
        calls.push({ method: "planApprovalDecisionStateUpdate" });
        throw new Error("state update must not run without wallet.network authority");
      },
    },
  });

  assert.throws(
    () => surface.decideThreadApproval(store, "thread_alpha", "approval_alpha", {
      decision: "approve",
      event_id: "event_decision",
      seq: 4,
      created_at: "2026-06-06T04:35:00.000Z",
      authority_grant_refs: [],
      authority_receipt_refs: [],
    }),
    (error) => {
      assert.equal(error.code, "approval_decision_authority_invalid");
      return true;
    },
  );
  assert.deepEqual(calls.map((call) => call.method), ["authorizeApprovalDecision"]);
  assert.deepEqual(writes, []);
  assert.equal(store.runtimeEventStreams.size, 0);
});

test("revokeThreadApproval public surface calls Rust authority and commits Rust projection", () => {
  const calls = [];
  const { store, surface, writes } = createStore({
    approvalStateCore: {
      authorizeApprovalDecision(request) {
        calls.push({ method: "authorizeApprovalDecision", request });
        return approvalAuthorityResult(request.decision);
      },
      planApprovalRevokeStateUpdate(request) {
        calls.push({ method: "planApprovalRevokeStateUpdate", request });
        return rustRunRecord("approval.revoke", request, {
          control: "approval_revoke",
          turn_status: "waiting_for_input",
          trace_key: "approvalRevocations",
        });
      },
    },
  });

  const result = surface.revokeThreadApproval(store, "thread_alpha", "approval_alpha", {
    event_id: "event_revoke",
    seq: 5,
    created_at: "2026-06-06T04:40:00.000Z",
    lease_id: "lease_alpha",
    receipt_refs: ["receipt_js_caller_must_not_authorize"],
    authority_grant_refs: ["wallet.network://grant/approval/approval_alpha"],
    authority_receipt_refs: ["receipt://wallet.network/approval/approval_alpha"],
    policy_decision_refs: ["policy_revoke"],
    approvalId: "approval_retired",
  });

  assert.equal(calls.length, 2);
  assert.equal(calls[0].method, "authorizeApprovalDecision");
  assert.equal(calls[0].request.decision, "revoke");
  assert.equal(Object.hasOwn(calls[0].request, "run"), false);
  assert.equal(Object.hasOwn(calls[0].request, "agent"), false);
  assert.equal(calls[1].method, "planApprovalRevokeStateUpdate");
  assert.equal(calls[1].request.approval_id, "approval_alpha");
  assert.equal(calls[1].request.lease_id, "lease_alpha");
  assert.equal(calls[1].request.run_id, null);
  assertRustReplayStateUpdateRequest(calls[1].request);
  assert.deepEqual(calls[1].request.receipt_refs, [
    "receipt://wallet.network/approval/approval_alpha",
  ]);
  assert.equal(calls[1].request.authority_hash, "sha256:approval-authority-revoke");
  assertNoRetiredApprovalControlAliases(calls[1].request);
  assert.equal(result.operation_kind, "approval.revoke");
  assert.equal(result.run.turnStatus, "waiting_for_input");
  assert.equal(result.run.trace.approvalRevocations[0].event_id, "event_revoke");
  assert.equal(result.operator_control.authority_hash, "sha256:approval-authority-revoke");
  assert.deepEqual(writes.map((write) => write.operationKind), ["approval.revoke"]);
  assert.equal(store.runtimeEventStreams.size, 0);
});

test("listThreadApprovals public read calls Rust approval queue projection", () => {
  const calls = [];
  const { store, surface, writes } = createStore({
    approvalStateCore: {
      projectApprovalQueue(request) {
        calls.push({ method: "projectApprovalQueue", request });
        return {
          source: "rust_approval_queue_projection_protocol",
          backend: "rust_authority",
          status: "projected",
          operation_kind: "approval.queue_projection",
          thread_id: request.thread_id,
          approvals: [
            {
              schema_version: "ioi.runtime.approval-queue-entry.v1",
              thread_id: request.thread_id,
              approval_id: "approval_alpha",
              status: "pending",
              decision: null,
              request_event_id: "event_approval",
            },
          ],
          pending_count: 1,
          resolved_count: 0,
          expected_head: request.expected_head,
          state_root_before: request.state_root_before,
        };
      },
    },
  });

  const result = surface.listThreadApprovals(store, "thread_alpha", {
    include_resolved: "true",
    includeResolved: "retired",
    expected_head: "agentgres://head/before",
    state_root_before: "state://root/before",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "projectApprovalQueue");
  assert.equal(calls[0].request.thread_id, "thread_alpha");
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(Object.hasOwn(calls[0].request, "agent"), false);
  assert.equal(Object.hasOwn(calls[0].request, "run"), false);
  assert.equal(Object.hasOwn(calls[0].request, "runs"), false);
  assert.equal(calls[0].request.include_resolved, true);
  assertNoRetiredApprovalControlAliases(calls[0].request);
  assert.equal(result.operation_kind, "approval.queue_projection");
  assert.equal(result.approvals[0].approval_id, "approval_alpha");
  assert.equal(result.pending_count, 1);
  assert.equal(result.expected_head, "agentgres://head/before");
  assert.deepEqual(writes, []);
  assert.equal(store.runtimeEventStreams.size, 0);
});

test("approval control surface remains fail-closed without Rust approval authority core", () => {
  const { store, surface } = createStore();
  assert.throws(
    () => surface.requestThreadApproval(store, "thread_alpha", {
      approval_id: "approval_alpha",
      event_id: "event_approval",
      seq: 3,
      created_at: "2026-06-06T04:30:00.000Z",
    }),
    (error) => {
      assert.equal(error.code, "runtime_approval_control_rust_core_required");
      assert.equal(error.status, 501);
      assert.equal(error.details.rust_core_boundary, "runtime.approval_control");
      assert.equal(error.details.operation, "approval_request");
      assert.equal(error.details.approval_id, "approval_alpha");
      assertNoRetiredApprovalControlAliases(error.details);
      return true;
    },
  );
  assert.equal(store.runtimeEventStreams.size, 0);
});

test("approval queue read surface remains fail-closed without Rust approval authority core", () => {
  const { store, surface } = createStore();
  assert.throws(
    () => surface.listThreadApprovals(store, "thread_alpha", {
      include_resolved: "true",
    }),
    (error) => {
      assert.equal(error.code, "runtime_approval_control_rust_core_required");
      assert.equal(error.status, 501);
      assert.equal(error.details.rust_core_boundary, "runtime.approval_control");
      assert.equal(error.details.operation, "approval_queue_projection");
      assert.equal(error.details.operation_kind, "approval.queue_projection");
      assert.equal(error.details.thread_id, "thread_alpha");
      assertNoRetiredApprovalControlAliases(error.details);
      return true;
    },
  );
  assert.equal(store.runtimeEventStreams.size, 0);
});

test("approval queue readback is Rust projection only on the JS approval surface", () => {
  const { surface } = createStore({
    approvalStateCore: {
      projectApprovalQueue() {
        return {
          status: "projected",
          operation_kind: "approval.queue_projection",
          thread_id: "thread_alpha",
          approvals: [],
          pending_count: 0,
          resolved_count: 0,
        };
      },
    },
  });
  assert.equal(typeof surface.listThreadApprovals, "function");
  assert.equal(Object.hasOwn(surface, "approvalQueueForThread"), false);
  assert.equal(surface.approvalQueueForThread, undefined);
  assert.equal(Object.hasOwn(surface, "pendingApprovalsForThread"), false);
  assert.equal(surface.pendingApprovalsForThread, undefined);
});

test("approval decision readback facade is retired from the JS approval surface", () => {
  const { surface } = createStore();
  assert.equal(Object.hasOwn(surface, "latestApprovalRequestEvent"), false);
  assert.equal(surface.latestApprovalRequestEvent, undefined);
  assert.equal(Object.hasOwn(surface, "latestApprovalDecisionEvent"), false);
  assert.equal(surface.latestApprovalDecisionEvent, undefined);
});
