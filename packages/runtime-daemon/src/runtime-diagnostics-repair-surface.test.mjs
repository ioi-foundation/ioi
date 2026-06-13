import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeDiagnosticsRepairSurface } from "./runtime-diagnostics-repair-surface.mjs";

function runtimeError(input) {
  const error = new Error(input.message);
  error.status = input.status;
  error.code = input.code;
  error.details = input.details;
  return error;
}

function assertNoRetiredDiagnosticsRepairDetailAliases(details) {
  for (const key of [
    "rustCoreBoundary",
    "operationKind",
    "threadId",
    "decisionId",
    "gateEventId",
    "snapshotId",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(details ?? {}, key), false, `${key} detail alias must be absent`);
  }
}

function harness() {
  const calls = [];
  const store = {
    stateDir: "/tmp/runtime-diagnostics-repair-state",
    agentForThread(threadId) {
      calls.push({ name: "agentForThread", threadId });
      throw new Error("Diagnostics repair facade must not look up agents in JS.");
    },
    getRun(runId) {
      calls.push({ name: "getRun", runId });
      throw new Error("Diagnostics repair facade must not look up runs in JS.");
    },
    createRun(agentId, request) {
      calls.push({ name: "createRun", agentId, request });
      throw new Error("Diagnostics repair facade must not create retry runs in JS.");
    },
    appendRuntimeEvent(event) {
      calls.push({ name: "appendRuntimeEvent", event });
      throw new Error("Diagnostics repair facade must not append JS runtime events.");
    },
    writeRun(run, reason) {
      calls.push({ name: "writeRun", run, reason });
      throw new Error("Diagnostics repair facade must not persist run state in JS.");
    },
    resolveDiagnosticsRepairDecision(threadId, decisionRef, request) {
      calls.push({ name: "resolveDiagnosticsRepairDecision", threadId, decisionRef, request });
      throw new Error("Diagnostics repair facade must not resolve accepted repair truth in JS.");
    },
    executeDiagnosticsOperatorOverride(threadId, request) {
      calls.push({ name: "executeDiagnosticsOperatorOverride", threadId, request });
      throw new Error("Diagnostics repair facade must not execute operator override in JS.");
    },
    createDiagnosticsRepairRetryTurn(threadId, request) {
      calls.push({ name: "createDiagnosticsRepairRetryTurn", threadId, request });
      throw new Error("Diagnostics repair facade must not create retry turns in JS.");
    },
  };
  return {
    calls,
    store,
    surface: createRuntimeDiagnosticsRepairSurface({ runtimeError }),
  };
}

function diagnosticsRepairControlRunner({ operationKind = "diagnostics.repair_decision.execute" } = {}) {
  const requests = [];
  const retryRunRequests = [];
  const controlStatus = operationKind === "diagnostics.repair_decision.executed"
    ? "executed"
    : operationKind === "diagnostics.repair_retry.created"
      ? "created"
      : operationKind === "diagnostics.operator_override.event"
        ? "overridden"
        : "accepted";
  return {
    requests,
    retryRunRequests,
    planRuntimeDiagnosticsRepairRetryRun(request) {
      retryRunRequests.push(request);
      const retryRequest = request.request ?? {};
      return {
        source: "rust_runtime_diagnostics_repair_retry_run_command",
        backend: "rust_policy",
        status: "planned",
        operation: "diagnostics_repair_retry_run_create",
        operation_kind: "diagnostics.repair_retry.run_create",
        thread_id: request.thread_id,
        agent_id: request.agent_id,
        decision_id: request.decision_id,
        run_request: {
          mode: "send",
          prompt: retryRequest.prompt ?? `Retry diagnostics repair for ${request.decision_id}.`,
          options: {
            ...(retryRequest.options ?? {}),
            diagnostics_repair: {
              action: "repair_retry",
              decision_id: request.decision_id,
              gate_event_id: request.gate_event_id ?? null,
              snapshot_id: request.snapshot_id ?? null,
            },
          },
          diagnostics_feedback: {
            mode: "repair_retry",
            decision_id: request.decision_id,
            gate_event_id: request.gate_event_id ?? null,
            snapshot_id: request.snapshot_id ?? null,
          },
        },
        retry_event_request: {
          decision_id: request.decision_id,
          gate_event_id: request.gate_event_id ?? null,
          snapshot_id: request.snapshot_id ?? null,
          action: "repair_retry",
          target_run_id: request.target_run_id ?? null,
          summary: retryRequest.summary ?? "Diagnostics repair retry turn created.",
          receipt_refs: retryRequest.receipt_refs ?? [],
          policy_decision_refs: retryRequest.policy_decision_refs ?? [],
        },
        receipt_refs: request.receipt_refs ?? [],
        policy_decision_refs: request.policy_decision_refs ?? [],
        evidence_refs: request.evidence_refs ?? [],
      };
    },
    planRuntimeDiagnosticsRepairControl(request) {
      requests.push(request);
      return {
        operation: request.operation,
        operation_kind: request.operation_kind,
        thread_id: request.thread_id,
        decision_id: request.decision_id,
        control_status: controlStatus,
        event: {
          event_id: `event_${request.decision_id}`,
          event_stream_id: request.event_stream_id,
          thread_id: request.thread_id,
          event_kind: request.operation_kind,
          status: controlStatus,
          payload: {
            ...(request.request ?? {}),
            decision_id: request.decision_id,
            gate_event_id: request.gate_event_id ?? null,
            snapshot_id: request.snapshot_id ?? null,
          },
          receipt_refs: ["receipt_alpha"],
          policy_decision_refs: ["policy_alpha"],
          evidence_refs: request.evidence_refs,
        },
        receipt_refs: ["receipt_alpha"],
        policy_decision_refs: ["policy_alpha"],
        evidence_refs: request.evidence_refs,
      };
    },
  };
}

function diagnosticsRepairProjectionRunner() {
  const requests = [];
  return {
    requests,
    projectRuntimeDiagnosticsRepairProjection(request) {
      assert.equal(Object.hasOwn(request, "projection"), false);
      assert.equal(Object.hasOwn(request, "decision"), false);
      assert.equal(Object.hasOwn(request, "decisions"), false);
      assert.equal(Object.hasOwn(request, "repair_decisions"), false);
      requests.push(request);
      return {
        source: "rust_runtime_diagnostics_repair_projection_command",
        backend: "rust_policy",
        status: "projected",
        operation: request.operation,
        operation_kind: request.operation_kind,
        projection_kind: request.projection_kind,
        thread_id: request.thread_id,
        decision_id: request.decision_id,
        gate_id: request.gate_id,
        projection: {
          schema_version: "ioi.runtime.diagnostics_repair_decision.v1",
          object: "ioi.runtime_diagnostics_repair_decision",
          decision_id: request.decision_id,
          thread_id: request.thread_id,
          gate_id: request.gate_id,
          action: "restore_apply",
          status: "accepted",
        },
        record_count: 1,
        receipt_refs: ["receipt_runtime_diagnostics_repair_projection_decision"],
        evidence_refs: request.evidence_refs,
      };
    },
  };
}

function diagnosticsOperatorOverrideStateUpdateRunner() {
  const requests = [];
  return {
    requests,
    planDiagnosticsOperatorOverrideStateUpdate(request) {
      requests.push(request);
      const operatorRequest = request.operator_override_request ?? {};
      const approvalRequired =
        operatorRequest.operator_override_requires_approval ??
        request.decision?.requires_approval ??
        request.repair_policy?.operator_override_requires_approval ??
        true;
      const textApproval = String(
        operatorRequest.operator_override_approval ??
          operatorRequest.approval ??
          operatorRequest.approval_decision ??
          operatorRequest.policy_decision ??
          "",
      ).toLowerCase();
      const booleanApproval = operatorRequest.operator_override_approved === true;
      const approvalSatisfied =
        !approvalRequired ||
        booleanApproval ||
        ["approve", "approved", "allow", "allowed", "accept", "accepted", "confirm", "confirmed", "override"].includes(textApproval);
      const approvalSource = !approvalRequired
        ? "workflow_policy"
        : booleanApproval
          ? "boolean_confirmation"
          : approvalSatisfied
            ? textApproval
            : "missing";
      const walletGrantRefs = request.authority_grant_refs ?? [];
      const authorityReceiptRefs = request.authority_receipt_refs ?? [];
      const policyDecisionRefs = request.policy_decision_refs ?? [];
      const authorityHash = walletGrantRefs.length > 0
        ? "sha256:diagnostics-operator-override-authority"
        : null;
      if (approvalRequired && (!authorityHash || authorityReceiptRefs.length === 0)) {
        const error = new Error("wallet.network diagnostics operator override authority required");
        error.code = "diagnostics_operator_override_authority_required";
        throw error;
      }
      return {
        status: "planned",
        operation_kind: "diagnostics.operator_override.event",
        operator_control: {
          control: "diagnostics_operator_override",
          decision_id: request.decision_id,
          event_id: request.event_id,
          approval_required: approvalRequired,
          approval_satisfied: approvalSatisfied,
          approval_source: approvalSource,
          authority: {
            object: "ioi.runtime_diagnostics_operator_override_authority",
            wallet_network_grant_refs: walletGrantRefs,
            authority_receipt_refs: authorityReceiptRefs,
            policy_decision_refs: policyDecisionRefs,
            authority_hash: authorityHash,
            direct_truth_write_allowed: false,
          },
          authority_hash: authorityHash,
          wallet_network_grant_refs: walletGrantRefs,
          authority_receipt_refs: authorityReceiptRefs,
          policy_decision_refs: policyDecisionRefs,
          direct_truth_write_allowed: false,
        },
        run: {
          ...request.run,
          status: "completed",
          updatedAt: request.created_at,
          diagnosticsBlockingGate: {
            ...(request.run.diagnosticsBlockingGate ?? {}),
            status: "overridden",
            continuation_allowed: true,
            approval_required: approvalRequired,
            approval_satisfied: approvalSatisfied,
            authority_hash: authorityHash,
          },
          trace: {
            ...(request.run.trace ?? {}),
            operatorControls: [{
              control: "diagnostics_operator_override",
              decision_id: request.decision_id,
              event_id: request.event_id,
              approval_required: approvalRequired,
              approval_satisfied: approvalSatisfied,
              approval_source: approvalSource,
            }],
          },
        },
      };
    },
  };
}

test("diagnostics repair decision execution uses Rust planning and runtime event admission", () => {
  const appended = [];
  const runner = diagnosticsRepairControlRunner();
  const store = {
    appendRuntimeEvent(event) {
      appended.push(event);
      return { admitted: true, event };
    },
  };
  const surface = createRuntimeDiagnosticsRepairSurface({
    runtimeError,
    diagnosticsRepairRunner: runner,
  });

  const result = surface.executeDiagnosticsRepairDecision(store, "thread_alpha", null, {
    decision_id: "decision_alpha",
    gate_event_id: "event_gate",
    snapshot_id: "snapshot_alpha",
    receipt_refs: ["receipt_request"],
    policy_decision_refs: ["policy_request"],
  });

  assert.equal(result.admitted, true);
  assert.equal(appended[0].event_kind, "diagnostics.repair_decision.execute");
  assert.equal(appended[0].payload.decision_id, "decision_alpha");
  assert.deepEqual(runner.requests, [{
    operation: "diagnostics_repair_decision_execution",
    operation_kind: "diagnostics.repair_decision.execute",
    thread_id: "thread_alpha",
    event_stream_id: "thread_alpha:events",
    turn_id: null,
    decision_id: "decision_alpha",
    gate_event_id: "event_gate",
    gate_id: null,
    snapshot_id: "snapshot_alpha",
    workspace_root: null,
    source: null,
    status: null,
    request: {
      decision_id: "decision_alpha",
      gate_event_id: "event_gate",
      snapshot_id: "snapshot_alpha",
      receipt_refs: ["receipt_request"],
      policy_decision_refs: ["policy_request"],
    },
    receipt_refs: ["receipt_request"],
    policy_decision_refs: ["policy_request"],
    evidence_refs: [
      "runtime_diagnostics_repair_decision_execution_rust_owned",
      "runtime_diagnostics_repair_control_event_rust_owned",
      "agentgres_runtime_thread_event_truth_required",
    ],
  }]);
});

test("diagnostics repair decision execution fails closed before event append without Rust planning", () => {
  const { calls, store, surface } = harness();

  assert.throws(
    () =>
      surface.executeDiagnosticsRepairDecision(store, "thread_alpha", null, {
        decisionId: "decision_retired",
        decision_id: "decision_alpha",
        action: "restore_apply",
        snapshotId: "snapshot_retired",
        idempotencyKey: "idempotency_retired",
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_diagnostics_repair_control_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.diagnostics_repair");
      assert.equal(error.details.operation, "diagnostics_repair_decision_execution");
      assert.equal(error.details.operation_kind, "diagnostics.repair_decision.execute");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.decision_id, "decision_alpha");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_diagnostics_repair_decision_execution_rust_owned",
        "runtime_diagnostics_repair_control_event_rust_owned",
        "agentgres_runtime_thread_event_truth_required",
      ]);
      assertNoRetiredDiagnosticsRepairDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("diagnostics operator override uses Rust state update and run-state admission", () => {
  const runner = diagnosticsOperatorOverrideStateUpdateRunner();
  const calls = [];
  const store = {
    getRun(runId) {
      calls.push({ name: "getRun", runId });
      return {
        id: runId,
        agentId: "agent_alpha",
        status: "blocked",
        diagnosticsBlockingGate: { status: "blocked" },
        trace: {},
      };
    },
    writeRun(run, operationKind) {
      calls.push({ name: "writeRun", run, operationKind });
      return {
        source: "rust_agentgres_runtime_run_state_commit_command",
        operation_kind: operationKind,
        receipt_refs: ["receipt_run_state"],
        policy_decision_refs: ["policy_operator_override"],
      };
    },
  };
  const surface = createRuntimeDiagnosticsRepairSurface({
    runtimeError,
    diagnosticsRepairRunner: runner,
  });

  const result = surface.executeDiagnosticsOperatorOverride(store, "thread_alpha", {
    request: {
      run_id: "run_blocked",
      event_id: "event_override",
      seq: 12,
      created_at: "2026-06-12T15:30:00.000Z",
      decision_id: "decision_override",
      gate_event_id: "event_gate",
      snapshot_id: "snapshot_alpha",
      operator_override_approval: "override",
      authority_grant_refs: ["wallet.network://grant/diagnostics/operator-override"],
      authority_receipt_refs: ["receipt://wallet.network/diagnostics/operator-override"],
      policy_decision_refs: ["policy_diagnostics_operator_override"],
      source: "agent_studio",
    },
    gateEvent: { event_id: "event_gate" },
    decision: { decision_id: "decision_override", requires_approval: true },
    snapshotId: "snapshot_alpha",
  });

  assert.equal(result.object, "ioi.runtime_diagnostics_operator_override");
  assert.equal(result.status, "completed");
  assert.equal(result.operation_kind, "diagnostics.operator_override.event");
  assert.equal(result.run.status, "completed");
  assert.equal(result.run.diagnosticsBlockingGate.status, "overridden");
  assert.equal(result.continuation_allowed, true);
  assert.equal(result.commit.source, "rust_agentgres_runtime_run_state_commit_command");
  assert.deepEqual(result.receipt_refs, ["receipt_run_state"]);
  assert.deepEqual(runner.requests, [{
    thread_id: "thread_alpha",
    run_id: "run_blocked",
    run: {
      id: "run_blocked",
      agentId: "agent_alpha",
      status: "blocked",
      diagnosticsBlockingGate: { status: "blocked" },
      trace: {},
    },
    event_id: "event_override",
    seq: 12,
    created_at: "2026-06-12T15:30:00.000Z",
    decision_id: "decision_override",
    gate_event_id: "event_gate",
    source: "agent_studio",
    operator_override_request: {
      run_id: "run_blocked",
      event_id: "event_override",
      seq: 12,
      created_at: "2026-06-12T15:30:00.000Z",
      decision_id: "decision_override",
      gate_event_id: "event_gate",
      snapshot_id: "snapshot_alpha",
      operator_override_approval: "override",
      authority_grant_refs: ["wallet.network://grant/diagnostics/operator-override"],
      authority_receipt_refs: ["receipt://wallet.network/diagnostics/operator-override"],
      policy_decision_refs: ["policy_diagnostics_operator_override"],
      source: "agent_studio",
    },
    decision: { decision_id: "decision_override", requires_approval: true },
    repair_policy: {},
    authority_grant_refs: ["wallet.network://grant/diagnostics/operator-override"],
    authority_receipt_refs: ["receipt://wallet.network/diagnostics/operator-override"],
    policy_decision_refs: ["policy_diagnostics_operator_override"],
    authority_context: {},
    snapshot_id: "snapshot_alpha",
  }]);
  assert.equal(calls[0].name, "getRun");
  assert.equal(calls[1].name, "writeRun");
  assert.equal(calls[1].operationKind, "diagnostics.operator_override.event");
  for (const field of [
    "schemaVersion",
    "threadId",
    "runId",
    "decisionId",
    "overrideStatus",
    "continuationAllowed",
    "receiptRefs",
    "policyDecisionRefs",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(result, field), false);
  }
});

test("diagnostics operator override fails closed before run lookup without Rust state update", () => {
  const { calls, store, surface } = harness();

  assert.throws(
    () =>
      surface.executeDiagnosticsOperatorOverride(store, "thread_alpha", {
        request: {
          decisionId: "decision_retired",
          decision_id: "decision_override",
          gateEventId: "event_retired",
          gate_event_id: "event_gate",
          snapshotId: "snapshot_retired",
          snapshot_id: "snapshot_alpha",
        },
        gateEvent: { event_id: "event_gate" },
        decision: { decision_id: "decision_override" },
        snapshotId: "snapshot_alpha",
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_diagnostics_repair_rust_core_required");
      assert.equal(error.details.operation, "diagnostics_operator_override_execution");
      assert.equal(error.details.operation_kind, "diagnostics.operator_override.execute");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.decision_id, "decision_override");
      assert.equal(error.details.gate_event_id, "event_gate");
      assert.equal(error.details.snapshot_id, "snapshot_alpha");
      assert.deepEqual(error.details.evidence_refs, [
        "diagnostics_operator_override_state_update_rust_owned",
        "rust_daemon_core_operator_override_state_required",
        "agentgres_operator_override_state_truth_required",
        "rust_agentgres_runtime_run_state_commit",
      ]);
      assertNoRetiredDiagnosticsRepairDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("diagnostics repair retry uses Rust retry-run planning, run creation, and event admission", () => {
  const appended = [];
  const runner = diagnosticsRepairControlRunner({
    operationKind: "diagnostics.repair_retry.created",
  });
  const runCreates = [];
  const store = {
    agentForThread(threadId) {
      assert.equal(threadId, "thread_alpha");
      return { id: "agent_alpha" };
    },
    agentRunLifecycleSurface: {
      createRun(state, agentId, request) {
        assert.equal(state, store);
        runCreates.push({ agentId, request });
        return { id: "run_retry", turn_id: "turn_retry", agentId };
      },
    },
    appendRuntimeEvent(event) {
      appended.push(event);
      return { ...event, admitted: true };
    },
  };
  const surface = createRuntimeDiagnosticsRepairSurface({
    runtimeError,
    diagnosticsRepairRunner: runner,
  });

  const result = surface.createDiagnosticsRepairRetryTurn(store, "thread_alpha", {
    request: {
      decision_id: "decision_retry",
      prompt: "Retry the diagnostics repair.",
      target_run_id: "run_blocked",
      summary: "Retry queued.",
      receipt_refs: ["receipt_retry_request"],
      policy_decision_refs: ["policy_retry_request"],
    },
    gateEvent: { event_id: "event_gate" },
    decision: { decision_id: "decision_retry" },
    snapshotId: "snapshot_alpha",
  });

  assert.equal(result.object, "ioi.runtime_diagnostics_repair_retry");
  assert.equal(result.status, "created");
  assert.equal(result.turn_id, "turn_retry");
  assert.equal(result.request_id, "run_retry");
  assert.equal(result.event.admitted, true);
  assert.equal(appended[0].event_kind, "diagnostics.repair_retry.created");
  assert.equal(appended[0].payload.retry_run_id, "run_retry");
  assert.deepEqual(runner.retryRunRequests, [{
    operation: "diagnostics_repair_retry_run_create",
    operation_kind: "diagnostics.repair_retry.run_create",
    thread_id: "thread_alpha",
    agent_id: "agent_alpha",
    decision_id: "decision_retry",
    gate_event_id: "event_gate",
    snapshot_id: "snapshot_alpha",
    target_run_id: "run_blocked",
    request: {
      decision_id: "decision_retry",
      prompt: "Retry the diagnostics repair.",
      target_run_id: "run_blocked",
      summary: "Retry queued.",
      receipt_refs: ["receipt_retry_request"],
      policy_decision_refs: ["policy_retry_request"],
    },
    receipt_refs: ["receipt_retry_request"],
    policy_decision_refs: ["policy_retry_request"],
    evidence_refs: [
      "runtime_diagnostics_repair_retry_run_request_rust_owned",
      "diagnostics_repair_retry_run_create_rust_owned",
      "runtime_run_create_js_facade_retired",
      "agentgres_run_create_state_truth_required",
    ],
  }]);
  assert.deepEqual(runCreates, [{
    agentId: "agent_alpha",
    request: {
      mode: "send",
      prompt: "Retry the diagnostics repair.",
      options: {
        diagnostics_repair: {
          action: "repair_retry",
          decision_id: "decision_retry",
          gate_event_id: "event_gate",
          snapshot_id: "snapshot_alpha",
        },
      },
      diagnostics_feedback: {
        mode: "repair_retry",
        decision_id: "decision_retry",
        gate_event_id: "event_gate",
        snapshot_id: "snapshot_alpha",
      },
    },
  }]);
  assert.deepEqual(runner.requests, [{
    operation: "diagnostics_repair_retry_event_append",
    operation_kind: "diagnostics.repair_retry.created",
    thread_id: "thread_alpha",
    event_stream_id: "thread_alpha:events",
    turn_id: null,
    decision_id: "decision_retry",
    gate_event_id: "event_gate",
    gate_id: null,
    snapshot_id: "snapshot_alpha",
    workspace_root: null,
    source: null,
    status: null,
    request: {
      decision_id: "decision_retry",
      gate_event_id: "event_gate",
      snapshot_id: "snapshot_alpha",
      action: "repair_retry",
      retry_turn_id: "turn_retry",
      retry_request_id: "run_retry",
      retry_run_id: "run_retry",
      target_run_id: "run_blocked",
      summary: "Retry queued.",
      receipt_refs: ["receipt_retry_request"],
      policy_decision_refs: ["policy_retry_request"],
    },
    receipt_refs: ["receipt_retry_request"],
    policy_decision_refs: ["policy_retry_request"],
    evidence_refs: [
      "runtime_diagnostics_repair_retry_event_rust_owned",
      "runtime_diagnostics_repair_control_event_rust_owned",
      "agentgres_runtime_thread_event_truth_required",
    ],
  }]);
});

test("diagnostics repair retry fails closed before JS lookup without Rust retry-run planning", () => {
  const { calls, store, surface } = harness();

  assert.throws(
    () =>
      surface.createDiagnosticsRepairRetryTurn(store, "thread_alpha", {
        request: { decision_id: "decision_retry", repairRetryIdempotencyKey: "retry_retired" },
        gateEvent: { event_id: "event_gate" },
        decision: { decision_id: "decision_retry" },
        snapshotId: "snapshot_alpha",
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_diagnostics_repair_retry_run_rust_core_required");
      assert.equal(error.details.operation, "diagnostics_repair_retry_run_create");
      assert.equal(error.details.operation_kind, "diagnostics.repair_retry.run_create");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.decision_id, "decision_retry");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_diagnostics_repair_retry_run_request_rust_owned",
        "diagnostics_repair_retry_run_create_rust_owned",
        "runtime_run_create_js_facade_retired",
        "agentgres_run_create_state_truth_required",
      ]);
      assertNoRetiredDiagnosticsRepairDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("diagnostics repair decision executed event uses Rust planning and runtime event admission", () => {
  const appended = [];
  const runner = diagnosticsRepairControlRunner({
    operationKind: "diagnostics.repair_decision.executed",
  });
  const store = {
    appendRuntimeEvent(event) {
      appended.push(event);
      return { admitted: true, event };
    },
  };
  const surface = createRuntimeDiagnosticsRepairSurface({
    runtimeError,
    diagnosticsRepairRunner: runner,
  });

  const result = surface.appendDiagnosticsRepairDecisionExecutedEvent(store, {
    threadId: "thread_alpha",
    gateEvent: { event_id: "event_gate" },
    decision: { decision_id: "decision_alpha" },
    action: "restore_apply",
    snapshotId: "snapshot_alpha",
  });

  assert.equal(result.admitted, true);
  assert.equal(appended[0].event_kind, "diagnostics.repair_decision.executed");
  assert.equal(appended[0].payload.decision_id, "decision_alpha");
  assert.deepEqual(runner.requests, [{
    operation: "diagnostics_repair_decision_event_append",
    operation_kind: "diagnostics.repair_decision.executed",
    thread_id: "thread_alpha",
    event_stream_id: "thread_alpha:events",
    turn_id: null,
    decision_id: "decision_alpha",
    gate_event_id: "event_gate",
    gate_id: null,
    snapshot_id: "snapshot_alpha",
    workspace_root: null,
    source: null,
    status: null,
    request: {
      decision_id: "decision_alpha",
      gate_event_id: "event_gate",
      snapshot_id: "snapshot_alpha",
      action: "restore_apply",
    },
    receipt_refs: [],
    policy_decision_refs: [],
    evidence_refs: [
      "runtime_diagnostics_repair_decision_event_rust_owned",
      "runtime_diagnostics_repair_control_event_rust_owned",
      "agentgres_runtime_thread_event_truth_required",
    ],
  }]);
});

test("diagnostics repair retry event append uses Rust planning and runtime event admission", () => {
  const appended = [];
  const runner = diagnosticsRepairControlRunner({
    operationKind: "diagnostics.repair_retry.created",
  });
  const store = {
    appendRuntimeEvent(event) {
      appended.push(event);
      return { admitted: true, event };
    },
  };
  const surface = createRuntimeDiagnosticsRepairSurface({
    runtimeError,
    diagnosticsRepairRunner: runner,
  });

  const result = surface.appendDiagnosticsRepairRetryTurnEvent(store, {
    threadId: "thread_alpha",
    gateEvent: { event_id: "event_gate" },
    decision: { decision_id: "decision_retry" },
    snapshotId: "snapshot_alpha",
  });

  assert.equal(result.admitted, true);
  assert.equal(appended[0].event_kind, "diagnostics.repair_retry.created");
  assert.equal(appended[0].payload.decision_id, "decision_retry");
  assert.deepEqual(runner.requests[0].evidence_refs, [
    "runtime_diagnostics_repair_retry_event_rust_owned",
    "runtime_diagnostics_repair_control_event_rust_owned",
    "agentgres_runtime_thread_event_truth_required",
  ]);
});

test("diagnostics operator override event append uses Rust planning and runtime event admission", () => {
  const appended = [];
  const runner = diagnosticsRepairControlRunner({
    operationKind: "diagnostics.operator_override.event",
  });
  const store = {
    appendRuntimeEvent(event) {
      appended.push(event);
      return { admitted: true, event };
    },
  };
  const surface = createRuntimeDiagnosticsRepairSurface({
    runtimeError,
    diagnosticsRepairRunner: runner,
  });

  const result = surface.appendDiagnosticsOperatorOverrideEvent(store, {
    threadId: "thread_alpha",
    gateEvent: {
      event_id: "event_gate",
      payload: {
        approval_id: "approval_override",
        authority_grant_refs: ["wallet.network://grant/diagnostics/operator-override"],
      },
    },
    decision: {
      decision_id: "decision_override",
      authority_receipt_refs: ["receipt://wallet.network/diagnostics/operator-override"],
      policy_decision_refs: ["policy_diagnostics_operator_override"],
    },
    snapshotId: "snapshot_alpha",
  });

  assert.equal(result.admitted, true);
  assert.equal(appended[0].event_kind, "diagnostics.operator_override.event");
  assert.equal(appended[0].status, "overridden");
  assert.equal(appended[0].payload.decision_id, "decision_override");
  assert.deepEqual(runner.requests[0], {
    operation: "diagnostics_operator_override_event_append",
    operation_kind: "diagnostics.operator_override.event",
    thread_id: "thread_alpha",
    event_stream_id: "thread_alpha:events",
    turn_id: null,
    decision_id: "decision_override",
    gate_event_id: "event_gate",
    gate_id: null,
    snapshot_id: "snapshot_alpha",
    workspace_root: null,
    source: null,
    status: null,
    request: {
      decision_id: "decision_override",
      gate_event_id: "event_gate",
      snapshot_id: "snapshot_alpha",
      action: "operator_override",
      approval_id: "approval_override",
      authority_grant_refs: ["wallet.network://grant/diagnostics/operator-override"],
      authority_receipt_refs: ["receipt://wallet.network/diagnostics/operator-override"],
      policy_decision_refs: ["policy_diagnostics_operator_override"],
    },
    receipt_refs: [],
    policy_decision_refs: ["policy_diagnostics_operator_override"],
    evidence_refs: [
      "runtime_diagnostics_operator_override_event_rust_owned",
      "runtime_diagnostics_repair_control_event_rust_owned",
      "agentgres_runtime_thread_event_truth_required",
    ],
  });
});

test("diagnostics operator override event append fails closed before JS runtime event append without Rust planning", () => {
  const { calls, store, surface } = harness();

  assert.throws(
    () =>
      surface.appendDiagnosticsOperatorOverrideEvent(store, {
        threadId: "thread_alpha",
        gateEvent: { event_id: "event_gate" },
        decision: { decision_id: "decision_override" },
        snapshotId: "snapshot_alpha",
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_diagnostics_repair_control_rust_core_required");
      assert.equal(error.details.operation, "diagnostics_operator_override_event_append");
      assert.equal(error.details.operation_kind, "diagnostics.operator_override.event");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.decision_id, "decision_override");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_diagnostics_operator_override_event_rust_owned",
        "runtime_diagnostics_repair_control_event_rust_owned",
        "agentgres_runtime_thread_event_truth_required",
      ]);
      assertNoRetiredDiagnosticsRepairDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("diagnostics repair decision resolver uses Rust state replay projection without JS candidate transport", () => {
  const runner = diagnosticsRepairProjectionRunner();
  const { calls, store } = harness();
  store.contextPolicyRunner = runner;
  const surface = createRuntimeDiagnosticsRepairSurface({ runtimeError });

  const result = surface.resolveDiagnosticsRepairDecision(store, "thread_alpha", "decision_alpha", {
    gate_id: "gate_alpha",
  });

  assert.equal(result.object, "ioi.runtime_diagnostics_repair_decision_resolution");
  assert.equal(result.status, "projected");
  assert.equal(result.decision.decision_id, "decision_alpha");
  assert.equal(result.decision.action, "restore_apply");
  assert.deepEqual(result.receipt_refs, ["receipt_runtime_diagnostics_repair_projection_decision"]);
  assert.deepEqual(result.evidence_refs, [
    "runtime_diagnostics_repair_decision_projection_rust_owned",
    "rust_daemon_core_diagnostics_repair_projection_required",
    "rust_daemon_core_diagnostics_repair_replay_required",
    "agentgres_diagnostics_repair_projection_truth_required",
  ]);
  assert.deepEqual(runner.requests, [{
    operation: "runtime_diagnostics_repair_projection",
    operation_kind: "runtime.diagnostics_repair_projection.decision",
    projection_kind: "decision",
    thread_id: "thread_alpha",
    decision_id: "decision_alpha",
    gate_id: "gate_alpha",
    state_dir: store.stateDir,
    evidence_refs: [
      "runtime_diagnostics_repair_decision_projection_rust_owned",
      "rust_daemon_core_diagnostics_repair_projection_required",
      "rust_daemon_core_diagnostics_repair_replay_required",
      "agentgres_diagnostics_repair_projection_truth_required",
    ],
  }]);
  assert.equal(runner.requests[0].state_dir, store.stateDir);
  assert.equal(Object.hasOwn(runner.requests[0], "projection"), false);
  assert.deepEqual(calls, []);
});

test("diagnostics repair decision resolver rejects retired JS candidate transport", () => {
  const runner = diagnosticsRepairProjectionRunner();
  const { calls, store } = harness();
  store.contextPolicyRunner = runner;
  const surface = createRuntimeDiagnosticsRepairSurface({ runtimeError });

  assert.throws(
    () =>
      surface.resolveDiagnosticsRepairDecision(store, "thread_alpha", "decision_alpha", {
        gate_id: "gate_alpha",
        projection: {
          decisions: [{
            decision_id: "decision_alpha",
            thread_id: "thread_alpha",
            gate_id: "gate_alpha",
          }],
        },
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(
        error.code,
        "runtime_diagnostics_repair_projection_candidate_transport_retired",
      );
      assert.deepEqual(error.details.retired_inputs, ["projection"]);
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_diagnostics_repair_decision_projection_rust_owned",
        "rust_daemon_core_diagnostics_repair_projection_required",
        "rust_daemon_core_diagnostics_repair_replay_required",
        "agentgres_diagnostics_repair_projection_truth_required",
      ]);
      return true;
    },
  );

  assert.deepEqual(runner.requests, []);
  assert.deepEqual(calls, []);
});

test("diagnostics repair decision resolver fails closed before JS projection reads without Rust projection", () => {
  const { calls, store, surface } = harness();

  assert.throws(
    () =>
      surface.resolveDiagnosticsRepairDecision(store, "thread_alpha", "decision_alpha", {
        gateId: "gate_retired",
        gate_id: "gate_alpha",
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_diagnostics_repair_rust_core_required");
      assert.equal(error.details.operation, "diagnostics_repair_decision_projection");
      assert.equal(error.details.operation_kind, "runtime.diagnostics_repair_projection.decision");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.decision_id, "decision_alpha");
      assert.equal(error.details.gate_id, "gate_alpha");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_diagnostics_repair_decision_projection_rust_owned",
        "rust_daemon_core_diagnostics_repair_projection_required",
        "rust_daemon_core_diagnostics_repair_replay_required",
        "agentgres_diagnostics_repair_projection_truth_required",
      ]);
      assertNoRetiredDiagnosticsRepairDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("diagnostics repair turn helpers remain non-authoritative null projections", () => {
  const { surface } = harness();

  assert.equal(surface.turnForOperatorOverrideEvent(), null);
  assert.equal(surface.turnForRepairRetryEvent(), null);
}
);
