import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeDiagnosticsRepairSurface } from "./runtime-diagnostics-repair-surface.mjs";

function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}

function diagnosticsOperatorOverrideStateUpdateForRequest(request = {}) {
  const control = {
    control: "diagnostics_operator_override",
    source: request.source,
    decisionId: request.decision_id,
    gateEventId: request.gate_event_id,
    approvalRequired: request.approval_required,
    approvalSatisfied: request.approval_satisfied,
    approvalSource: request.approval_source,
    snapshotId: request.snapshot_id,
    eventId: request.event_id,
    seq: request.seq,
    createdAt: request.created_at,
  };
  const run = request.run ?? {};
  const updatedDiagnosticsBlockingGate = run.diagnosticsBlockingGate
    ? {
        ...run.diagnosticsBlockingGate,
        status: "overridden",
        decision: "operator_override",
        continuationAllowed: true,
        continuation_allowed: true,
        approvalRequired: request.approval_required,
        approval_required: request.approval_required,
        approvalSatisfied: request.approval_satisfied,
        approval_satisfied: request.approval_satisfied,
        operatorOverrideEventId: request.event_id,
        operator_override_event_id: request.event_id,
      }
    : null;
  const updated = {
    ...run,
    status: "completed",
    updatedAt: request.created_at,
    result: "Operator override granted; blocking diagnostics gate marked continuation-allowed.",
    trace: {
      ...run.trace,
      ...(updatedDiagnosticsBlockingGate ? { diagnosticsBlockingGate: updatedDiagnosticsBlockingGate } : {}),
      stopCondition: {
        ...(run.trace?.stopCondition ?? {}),
        reason: "operator_override_granted",
        evidenceSufficient: true,
        rationale: "Operator override granted continuation despite blocking diagnostics.",
      },
      operatorControls: appendOperatorControlForTest(run.trace?.operatorControls, control),
    },
    operatorControls: appendOperatorControlForTest(run.operatorControls, control),
  };
  delete updated.turnStatus;
  if (updatedDiagnosticsBlockingGate) {
    updated.diagnosticsBlockingGate = updatedDiagnosticsBlockingGate;
  }
  return {
    status: "planned",
    operation_kind: "diagnostics.operator_override.event",
    updated_at: request.created_at,
    operator_control: control,
    run: updated,
  };
}

function appendOperatorControlForTest(value, control) {
  const entries = Array.isArray(value) ? [...value] : [];
  if (!entries.some((entry) => entry?.eventId === control.eventId)) {
    entries.push(control);
  }
  return entries;
}

function createSurface({ calls = [], diagnosticsOperatorOverrideStateUpdate = null } = {}) {
  return createRuntimeDiagnosticsRepairSurface({
    contextPolicyRunner: {
      planDiagnosticsOperatorOverrideStateUpdate(request) {
        calls.push({ name: "planDiagnosticsOperatorOverrideStateUpdate", request });
        return diagnosticsOperatorOverrideStateUpdate ?? diagnosticsOperatorOverrideStateUpdateForRequest(request);
      },
    },
    diagnosticsOperatorOverrideApprovalForRequest(request = {}) {
      const required = request.operatorOverrideRequiresApproval !== false;
      const satisfied = !required || request.confirm === true || request.operatorOverrideApproved === true;
      return {
        required,
        satisfied,
        source: required ? (satisfied ? "boolean_confirmation" : "missing") : "workflow_policy",
      };
    },
    diagnosticsOperatorOverrideApprovalKey(approval = {}) {
      if (!approval.required) return "approval_not_required";
      return approval.satisfied ? `approval_${approval.source}` : "approval_required";
    },
    diagnosticsOperatorOverrideResultFromEvent({ threadId, event, turn = null } = {}) {
      const payload = event?.payload_summary ?? {};
      return {
        thread_id: threadId,
        status: event?.status ?? "completed",
        approval_required: Boolean(payload.approval_required),
        approval_satisfied: Boolean(payload.approval_satisfied),
        continuation_allowed: Boolean(payload.continuation_allowed),
        turn,
        event,
      };
    },
    diagnosticsRepairApplyApprovalKey: () => "approval-key",
    diagnosticsRepairExecutionStatus: (result) => result.status ?? "completed",
    diagnosticsRepairRetryFeedback: () => ({
      mode: "repair_retry",
      diagnostic_status: "failed",
      diagnostic_count: 2,
      rollback_refs: ["snapshot_feedback"],
    }),
    diagnosticsRepairRetryResultFromEvent({ threadId, event, turn = null, run = null } = {}) {
      return {
        thread_id: threadId,
        status: event?.status ?? "completed",
        turn_id: turn?.turn_id ?? null,
        request_id: turn?.request_id ?? run?.id ?? null,
        repair_turn: turn,
        event,
        run,
      };
    },
    runtimeError,
  });
}

function createStore({
  action = "restore_apply",
  status = "available",
  snapshotRefs = ["snapshot_alpha"],
  decisionOverrides = {},
  repairPolicyOverrides = {},
  gatePayloadSummary = null,
} = {}) {
  const calls = [];
  const gateEvent = {
    event_id: "event_gate",
    workflow_graph_id: "graph_gate",
    payload_summary: gatePayloadSummary ?? { workspace_snapshot_refs: snapshotRefs },
  };
  const decision = {
    decision_id: "decision_alpha",
    action,
    status,
    workspace_snapshot_refs: snapshotRefs,
    restore_conflict_policy: "allow_override",
    ...decisionOverrides,
  };
  const repairPolicy = {
    policy_id: "policy_alpha",
    workspace_snapshot_refs: snapshotRefs,
    restore_conflict_policy: "clean_preview_only",
    ...repairPolicyOverrides,
  };
  return {
    calls,
    agentForThread(threadId) {
      calls.push({ name: "agentForThread", threadId });
      return { id: "agent_alpha" };
    },
    resolveDiagnosticsRepairDecision(threadId, target, request) {
      calls.push({ name: "resolve", threadId, target, request });
      return { gateEvent, decision, repairPolicy };
    },
    applyWorkspaceSnapshotRestore(threadId, snapshotId, request) {
      calls.push({ name: "apply", threadId, snapshotId, request });
      return { status: "completed", event: { event_id: "event_apply" } };
    },
    previewWorkspaceSnapshotRestore(threadId, snapshotId, request) {
      calls.push({ name: "preview", threadId, snapshotId, request });
      return { status: "completed", event: { event_id: "event_preview" } };
    },
    createDiagnosticsRepairRetryTurn(threadId, input) {
      calls.push({ name: "retry", threadId, input });
      return { status: "completed", repair_turn: { turn_id: "turn_repair" }, event: { event_id: "event_retry" } };
    },
    executeDiagnosticsOperatorOverride(threadId, input) {
      calls.push({ name: "override", threadId, input });
      return { status: "completed", event: { event_id: "event_override" } };
    },
    appendDiagnosticsRepairDecisionExecutedEvent(input) {
      calls.push({ name: "append", input });
      return {
        event_id: "event_executed",
        receipt_refs: ["receipt_executed"],
        artifact_refs: ["artifact_executed"],
        policy_decision_refs: ["policy_executed"],
        rollback_refs: ["snapshot_alpha"],
      };
    },
  };
}

test("diagnostics repair surface routes restore apply with canonical request fields", () => {
  const surface = createSurface();
  const store = createStore();

  const result = surface.executeDiagnosticsRepairDecision(store, "thread_alpha", "decision_alpha", {
    confirm: true,
    allow_conflicts: true,
  });

  assert.equal(result.action, "restore_apply");
  assert.equal(result.status, "completed");
  assert.deepEqual(result.receipt_refs, ["receipt_executed"]);
  for (const field of [
    "schemaVersion",
    "threadId",
    "decisionId",
    "gateEventId",
    "policyId",
    "snapshotId",
    "workflowGraphId",
    "workflowNodeId",
    "repairPolicy",
    "repairRetry",
    "repairTurn",
    "repairRetryEvent",
    "operatorOverride",
    "operatorOverrideEvent",
    "restorePreview",
    "restoreApply",
    "restorePreviewEvent",
    "restoreApplyEvent",
    "receiptRefs",
    "artifactRefs",
    "policyDecisionRefs",
    "rollbackRefs",
  ]) {
    assert.equal(Object.hasOwn(result, field), false);
  }
  const apply = store.calls.find((call) => call.name === "apply");
  assert.equal(apply.snapshotId, "snapshot_alpha");
  assert.equal(apply.request.workflow_node_id, "runtime.lsp-diagnostics.repair.restore-apply");
  assert.equal(apply.request.idempotency_key, "thread:thread_alpha:diagnostics-repair-apply:decision_alpha:snapshot_alpha:approval-key");
  assert.equal(Object.hasOwn(apply.request, "restoreConflictPolicy"), false);
  assert.equal(Object.hasOwn(apply.request, "allowConflicts"), false);
  assert.equal(Object.hasOwn(apply.request, "approvalGranted"), false);
  assert.equal(apply.request.restore_conflict_policy, "allow_override");
  assert.equal(apply.request.allow_conflicts, true);
});

test("diagnostics repair decision execution ignores retired request decision alias", () => {
  const surface = createSurface();
  const store = createStore();

  assert.throws(
    () => surface.executeDiagnosticsRepairDecision(store, "thread_alpha", null, { decisionId: "decision_alias" }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "diagnostics_repair_decision_required");
      assert.deepEqual(error.details, { thread_id: "thread_alpha" });
      assert.equal(Object.hasOwn(error.details, "threadId"), false);
      assert.equal(store.calls.some((call) => call.name === "resolve"), false);
      return true;
    },
  );
});

test("diagnostics repair decision execution ignores retired snapshot ref aliases", () => {
  const surface = createSurface();
  const store = createStore({
    gatePayloadSummary: {},
    decisionOverrides: {
      workspace_snapshot_refs: [],
      workspaceSnapshotRefs: ["snapshot_alias"],
    },
    repairPolicyOverrides: {
      workspace_snapshot_refs: [],
      workspaceSnapshotRefs: ["snapshot_policy_alias"],
    },
  });

  assert.throws(
    () => surface.executeDiagnosticsRepairDecision(store, "thread_alpha", "decision_alpha", { confirm: true }),
    (error) => {
      assert.equal(error.status, 409);
      assert.equal(error.code, "diagnostics_repair_snapshot_required");
      assert.deepEqual(error.details, {
        thread_id: "thread_alpha",
        decision_ref: "decision_alpha",
        action: "restore_apply",
      });
      for (const key of ["threadId", "decisionRef"]) {
        assert.equal(Object.hasOwn(error.details, key), false);
      }
      assert.equal(store.calls.some((call) => call.name === "apply"), false);
      return true;
    },
  );
});

test("diagnostics repair decision execution ignores retired decision and policy id aliases", () => {
  const surface = createSurface();
  const store = createStore({
    action: "operator_override",
    decisionOverrides: {
      decision_id: undefined,
      decisionId: "decision_alias",
    },
    repairPolicyOverrides: {
      policy_id: undefined,
      policyId: "policy_alias",
    },
  });

  const result = surface.executeDiagnosticsRepairDecision(store, "thread_alpha", "decision_alpha", {
    confirm: true,
  });

  assert.equal(result.decision_id, "decision_alpha");
  assert.equal(result.policy_id, null);
});

test("diagnostics repair restore rejects retired request aliases before workspace restore call", () => {
  for (const action of ["restore_preview", "restore_apply"]) {
    const surface = createSurface();
    const store = createStore({ action });
    const retiredRequest = {
      snapshotId: "snapshot_alias",
      workflowGraphId: "graph_alias",
      workflowNodeId: "node_alias",
      restorePreviewIdempotencyKey: "preview_idempotency_alias",
      restoreApplyIdempotencyKey: "apply_idempotency_alias",
      approvalDecision: "approved",
      policyDecision: "allow",
      confirmRestoreApply: true,
      applyConfirmed: true,
      approvalGranted: true,
      allowConflicts: true,
      overrideConflicts: true,
      restoreConflictPolicy: "allow_override",
      conflictPolicy: "override_conflicts",
    };

    assert.throws(
      () => surface.executeDiagnosticsRepairDecision(store, "thread_alpha", "decision_alpha", retiredRequest),
      (error) => {
        assert.equal(error.status, 400);
        assert.equal(error.code, "diagnostics_repair_restore_request_aliases_retired");
        assert.deepEqual(error.details.retired_aliases, [
          "snapshotId",
          "workflowGraphId",
          "workflowNodeId",
          "restorePreviewIdempotencyKey",
          "restoreApplyIdempotencyKey",
          "approvalDecision",
          "policyDecision",
          "confirmRestoreApply",
          "applyConfirmed",
          "approvalGranted",
          "allowConflicts",
          "overrideConflicts",
          "restoreConflictPolicy",
          "conflictPolicy",
        ]);
        assert.deepEqual(error.details.canonical_fields, [
          "snapshot_id",
          "workflow_graph_id",
          "workflow_node_id",
          "restore_preview_idempotency_key",
          "restore_apply_idempotency_key",
          "approval_decision",
          "policy_decision",
          "confirm_restore_apply",
          "apply_confirmed",
          "approval_granted",
          "allow_conflicts",
          "override_conflicts",
          "restore_conflict_policy",
          "conflict_policy",
        ]);
        return true;
      },
    );
    assert.equal(
      store.calls.some((call) => call.name === "preview" || call.name === "apply"),
      false,
      "workspace restore call must not run for retired diagnostics repair restore request aliases",
    );
  }
});

test("diagnostics repair surface routes retry, override, and preview actions", () => {
  for (const [action, expectedCall] of [
    ["repair_retry", "retry"],
    ["operator_override", "override"],
    ["restore_preview", "preview"],
  ]) {
    const surface = createSurface();
    const store = createStore({ action });
    const result = surface.executeDiagnosticsRepairDecision(store, "thread_alpha", "decision_alpha", {});
    assert.equal(result.action, action);
    assert.ok(store.calls.some((call) => call.name === expectedCall));
  }
});

test("diagnostics repair surface fails closed for invalid or unavailable decisions", () => {
  const surface = createSurface();

  assert.throws(
    () => surface.executeDiagnosticsRepairDecision(createStore(), "thread_alpha", "", {}),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "diagnostics_repair_decision_required");
      assert.deepEqual(error.details, { thread_id: "thread_alpha" });
      assert.equal(Object.hasOwn(error.details, "threadId"), false);
      return true;
    },
  );
  assert.throws(
    () => surface.executeDiagnosticsRepairDecision(createStore({ action: "delete_everything" }), "thread_alpha", "decision_alpha", {}),
    (error) => {
      assert.equal(error.status, 409);
      assert.equal(error.code, "diagnostics_repair_decision_action_unimplemented");
      assert.deepEqual(error.details, {
        thread_id: "thread_alpha",
        decision_ref: "decision_alpha",
        action: "delete_everything",
        supported_actions: ["repair_retry", "restore_preview", "restore_apply", "operator_override"],
      });
      for (const key of ["threadId", "decisionRef", "supportedActions"]) {
        assert.equal(Object.hasOwn(error.details, key), false);
      }
      return true;
    },
  );
  assert.throws(
    () => surface.executeDiagnosticsRepairDecision(createStore({ status: "used" }), "thread_alpha", "decision_alpha", {}),
    (error) => {
      assert.equal(error.status, 409);
      assert.equal(error.code, "diagnostics_repair_decision_unavailable");
      assert.deepEqual(error.details, {
        thread_id: "thread_alpha",
        decision_ref: "decision_alpha",
        action: "restore_apply",
        status: "used",
      });
      for (const key of ["threadId", "decisionRef"]) {
        assert.equal(Object.hasOwn(error.details, key), false);
      }
      return true;
    },
  );
  assert.throws(
    () =>
      surface.executeDiagnosticsRepairDecision(
        createStore({ action: "restore_preview", snapshotRefs: [] }),
        "thread_alpha",
        "decision_alpha",
        {},
      ),
    (error) => {
      assert.equal(error.status, 409);
      assert.equal(error.code, "diagnostics_repair_snapshot_required");
      assert.deepEqual(error.details, {
        thread_id: "thread_alpha",
        decision_ref: "decision_alpha",
        action: "restore_preview",
      });
      for (const key of ["threadId", "decisionRef"]) {
        assert.equal(Object.hasOwn(error.details, key), false);
      }
      return true;
    },
  );
});

test("diagnostics repair surface executes operator override and updates the blocked turn", () => {
  const calls = [];
  const surface = createSurface({ calls });
  const events = [];
  const idempotency = new Map();
  const run = {
    id: "run_blocked",
    agentId: "agent_alpha",
    status: "blocked",
    turnStatus: "waiting_for_input",
    diagnosticsBlockingGate: { status: "blocked" },
    trace: { stopCondition: { reason: "lsp_diagnostics_blocked" } },
    operatorControls: [],
  };
  const store = {
    runs: new Map([[run.id, run]]),
    writes: [],
    agentForThread() {
      return { id: "agent_alpha", cwd: "/tmp/workspace" };
    },
    runtimeEventStream() {
      return { idempotency };
    },
    getRun(runId) {
      return this.runs.get(runId);
    },
    writeRun(updated, reason) {
      this.writes.push({ updated, reason });
    },
    turnForRun(updated) {
      return { turn_id: "turn_blocked", status: updated.status };
    },
    appendDiagnosticsOperatorOverrideEvent(input) {
      return surface.appendDiagnosticsOperatorOverrideEvent(this, input);
    },
    appendRuntimeEvent(event) {
      const stored = {
        ...event,
        event_id: `event_${events.length + 1}`,
        seq: events.length + 1,
        created_at: "2026-06-04T14:00:00.000Z",
      };
      events.push(stored);
      idempotency.set(event.idempotency_key, stored);
      return stored;
    },
  };

  const result = surface.executeDiagnosticsOperatorOverride(store, "thread_alpha", {
    request: { confirm: true, source: "runtime_auto" },
    gateEvent: {
      event_id: "event_gate",
      turn_id: "turn_blocked",
      workspace_root: "/tmp/workspace",
      payload_summary: { turn_id: "turn_blocked", gate_id: "gate_alpha" },
    },
    decision: { decision_id: "decision_override" },
    repairPolicy: { policy_id: "policy_alpha" },
    snapshotId: "snapshot_alpha",
    workflowGraphId: "graph_alpha",
  });

  assert.equal(result.status, "completed");
  assert.equal(result.continuation_allowed, true);
  assert.equal(store.runs.get("run_blocked").diagnosticsBlockingGate.status, "overridden");
  assert.equal(store.writes[0].reason, "diagnostics.operator_override.event");
  assert.equal(events[0].event_stream_id, "thread_alpha:events");
  assert.equal(events[0].payload_summary.approval_satisfied, true);
  assert.equal(events[0].payload_summary.continuation_allowed, true);
  assert.equal(
    calls.find((call) => call.name === "planDiagnosticsOperatorOverrideStateUpdate").request.event_id,
    "event_1",
  );
});

test("diagnostics repair operator override turn lookup exposes canonical not-found details", () => {
  const calls = [];
  const surface = createSurface({ calls });
  const idempotency = new Map();
  const run = {
    id: "run_blocked",
    agentId: "agent_beta",
    status: "blocked",
    turnStatus: "waiting_for_input",
    diagnosticsBlockingGate: { status: "blocked" },
    trace: { stopCondition: { reason: "lsp_diagnostics_blocked" } },
    operatorControls: [],
  };
  const store = {
    runs: new Map([[run.id, run]]),
    agentForThread() {
      return { id: "agent_alpha", cwd: "/tmp/workspace" };
    },
    runtimeEventStream() {
      return { idempotency };
    },
    getRun(runId) {
      return this.runs.get(runId);
    },
  };

  assert.throws(
    () =>
      surface.executeDiagnosticsOperatorOverride(store, "thread_alpha", {
        request: { confirm: true, source: "runtime_auto" },
        gateEvent: {
          event_id: "event_gate",
          turn_id: "turn_blocked",
          workspace_root: "/tmp/workspace",
          payload_summary: { turn_id: "turn_blocked", gate_id: "gate_alpha" },
        },
        decision: { decision_id: "decision_override" },
        repairPolicy: { policy_id: "policy_alpha" },
        snapshotId: "snapshot_alpha",
        workflowGraphId: "graph_alpha",
      }),
    (error) => {
      assert.equal(error.status, 404);
      assert.deepEqual(error.details, {
        thread_id: "thread_alpha",
        turn_id: "turn_blocked",
        run_id: "run_blocked",
      });
      for (const key of ["threadId", "turnId", "runId"]) {
        assert.equal(Object.hasOwn(error.details, key), false);
      }
      return true;
    },
  );
  assert.equal(calls.length, 0);
});

test("diagnostics repair surface fails closed without Rust-planned override run", () => {
  const calls = [];
  const surface = createSurface({
    calls,
    diagnosticsOperatorOverrideStateUpdate: {
      status: "planned",
      operation_kind: "diagnostics.operator_override.event",
      run: null,
    },
  });
  const run = {
    id: "run_blocked",
    agentId: "agent_alpha",
    status: "blocked",
    turnStatus: "waiting_for_input",
    diagnosticsBlockingGate: { status: "blocked" },
    trace: { stopCondition: { reason: "lsp_diagnostics_blocked" } },
    operatorControls: [],
  };
  const events = [];
  const idempotency = new Map();
  const writes = [];
  const store = {
    runs: new Map([[run.id, run]]),
    agentForThread() {
      return { id: "agent_alpha", cwd: "/tmp/workspace" };
    },
    runtimeEventStream() {
      return { idempotency };
    },
    getRun(runId) {
      return this.runs.get(runId);
    },
    writeRun(updated, reason) {
      writes.push({ updated, reason });
    },
    appendDiagnosticsOperatorOverrideEvent(input) {
      return surface.appendDiagnosticsOperatorOverrideEvent(this, input);
    },
    appendRuntimeEvent(event) {
      const stored = {
        ...event,
        event_id: `event_${events.length + 1}`,
        seq: events.length + 1,
        created_at: "2026-06-04T14:00:00.000Z",
      };
      events.push(stored);
      idempotency.set(event.idempotency_key, stored);
      return stored;
    },
  };

  assert.throws(
    () =>
      surface.executeDiagnosticsOperatorOverride(store, "thread_alpha", {
        request: { confirm: true, source: "runtime_auto" },
        gateEvent: {
          event_id: "event_gate",
          turn_id: "turn_blocked",
          workspace_root: "/tmp/workspace",
          payload_summary: { turn_id: "turn_blocked", gate_id: "gate_alpha" },
        },
        decision: { decision_id: "decision_override" },
        repairPolicy: { policy_id: "policy_alpha" },
        snapshotId: "snapshot_alpha",
        workflowGraphId: "graph_alpha",
      }),
    (error) => {
      assert.equal(error.code, "diagnostics_operator_override_state_update_planner_invalid");
      assert.deepEqual(error.details, { thread_id: "thread_alpha", run_id: "run_blocked" });
      for (const key of ["threadId", "runId"]) {
        assert.equal(Object.hasOwn(error.details, key), false);
      }
      return true;
    },
  );
  assert.equal(writes.length, 0);
  assert.equal(
    calls.find((call) => call.name === "planDiagnosticsOperatorOverrideStateUpdate").request.event_id,
    "event_1",
  );
});

test("diagnostics repair surface fails closed without Rust-planned override operation kind", () => {
  const calls = [];
  const run = {
    id: "run_blocked",
    agentId: "agent_alpha",
    status: "blocked",
    turnStatus: "waiting_for_input",
    diagnosticsBlockingGate: { status: "blocked" },
    trace: { stopCondition: { reason: "lsp_diagnostics_blocked" } },
    operatorControls: [],
  };
  const surface = createSurface({
    calls,
    diagnosticsOperatorOverrideStateUpdate: {
      status: "planned",
      run: diagnosticsOperatorOverrideStateUpdateForRequest({
        run,
        created_at: "2026-06-04T14:00:00.000Z",
        event_id: "event_1",
      }).run,
    },
  });
  const events = [];
  const idempotency = new Map();
  const writes = [];
  const store = {
    runs: new Map([[run.id, run]]),
    agentForThread() {
      return { id: "agent_alpha", cwd: "/tmp/workspace" };
    },
    runtimeEventStream() {
      return { idempotency };
    },
    getRun(runId) {
      return this.runs.get(runId);
    },
    writeRun(updated, reason) {
      writes.push({ updated, reason });
    },
    appendDiagnosticsOperatorOverrideEvent(input) {
      return surface.appendDiagnosticsOperatorOverrideEvent(this, input);
    },
    appendRuntimeEvent(event) {
      const stored = {
        ...event,
        event_id: `event_${events.length + 1}`,
        seq: events.length + 1,
        created_at: "2026-06-04T14:00:00.000Z",
      };
      events.push(stored);
      idempotency.set(event.idempotency_key, stored);
      return stored;
    },
  };

  assert.throws(
    () =>
      surface.executeDiagnosticsOperatorOverride(store, "thread_alpha", {
        request: { confirm: true, source: "runtime_auto" },
        gateEvent: {
          event_id: "event_gate",
          turn_id: "turn_blocked",
          workspace_root: "/tmp/workspace",
          payload_summary: { turn_id: "turn_blocked", gate_id: "gate_alpha" },
        },
        decision: { decision_id: "decision_override" },
        repairPolicy: { policy_id: "policy_alpha" },
        snapshotId: "snapshot_alpha",
        workflowGraphId: "graph_alpha",
      }),
    (error) => {
      assert.equal(error.code, "diagnostics_operator_override_state_update_operation_kind_missing");
      assert.equal(error.details.operation_kind, "diagnostics.operator_override.event");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.run_id, "run_blocked");
      for (const key of ["threadId", "runId", "operationKind"]) {
        assert.equal(Object.hasOwn(error.details, key), false);
      }
      return true;
    },
  );
  assert.equal(writes.length, 0);
  assert.equal(store.runs.get("run_blocked").diagnosticsBlockingGate.status, "blocked");
});

test("diagnostics repair surface creates retry turns with injected diagnostics feedback", () => {
  const surface = createSurface();
  const events = [];
  const idempotency = new Map();
  const createRunCalls = [];
  const store = {
    agentForThread() {
      return { id: "agent_alpha", cwd: "/tmp/workspace" };
    },
    runtimeEventStream() {
      return { idempotency };
    },
    createRun(agentId, request) {
      createRunCalls.push({ agentId, request });
      return { id: "run_repair", artifacts: [{ id: "artifact_alpha" }] };
    },
    turnForRun() {
      return { turn_id: "turn_repair", request_id: "request_repair", status: "queued" };
    },
    appendDiagnosticsRepairRetryTurnEvent(input) {
      return surface.appendDiagnosticsRepairRetryTurnEvent(this, input);
    },
    appendRuntimeEvent(event) {
      const stored = {
        ...event,
        event_id: `event_${events.length + 1}`,
        seq: events.length + 1,
        created_at: "2026-06-04T14:00:00.000Z",
      };
      events.push(stored);
      idempotency.set(event.idempotency_key, stored);
      return stored;
    },
  };

  const result = surface.createDiagnosticsRepairRetryTurn(store, "thread_alpha", {
    request: { message: "Try the fix again" },
    gateEvent: {
      event_id: "event_gate",
      workspace_root: "/tmp/workspace",
      payload_summary: { gate_id: "gate_alpha" },
    },
    decision: { decision_id: "decision_retry" },
    repairPolicy: { policy_id: "policy_alpha" },
    snapshotId: "snapshot_alpha",
    workflowGraphId: "graph_alpha",
  });

  assert.equal(result.turn_id, "turn_repair");
  assert.equal(createRunCalls[0].agentId, "agent_alpha");
  assert.equal(createRunCalls[0].request.prompt, "Try the fix again");
  assert.equal(createRunCalls[0].request.options.diagnostics_mode, "skip");
  assert.equal(Object.hasOwn(createRunCalls[0].request.options, "diagnosticsMode"), false);
  assert.equal(createRunCalls[0].request.diagnostics_feedback.mode, "repair_retry");
  assert.equal(Object.hasOwn(createRunCalls[0].request, "diagnosticsFeedback"), false);
  assert.equal(events[0].payload_summary.retry_turn_id, "turn_repair");
  assert.deepEqual(events[0].artifact_refs, ["artifact_alpha"]);
});

test("diagnostics repair helper events ignore retired operator override aliases", () => {
  const surface = createSurface();
  const events = [];
  const store = {
    agentForThread() {
      return { id: "agent_alpha", cwd: "/tmp/workspace" };
    },
    appendRuntimeEvent(event) {
      const stored = {
        ...event,
        event_id: `event_${events.length + 1}`,
        seq: events.length + 1,
        created_at: "2026-06-04T14:00:00.000Z",
      };
      events.push(stored);
      return stored;
    },
  };

  const event = surface.appendDiagnosticsOperatorOverrideEvent(store, {
    threadId: "thread_alpha",
    gateEvent: {
      event_id: "event_gate",
      payload_summary: {
        gate_id: "gate_alpha",
        rollbackRefs: ["snapshot_gate_alias"],
      },
    },
    decision: {
      decision_id: "decision_override",
      rollbackRefs: ["snapshot_decision_alias"],
    },
    repairPolicy: {
      policyId: "policy_alias",
      rollbackRefs: ["snapshot_policy_alias"],
    },
    approval: { required: true, satisfied: true, source: "boolean_confirmation" },
    status: "completed",
    snapshotId: null,
    workflowNodeId: "runtime.lsp-diagnostics.operator-override",
  });

  assert.equal(event.payload_summary.policy_id, null);
  assert.deepEqual(event.rollback_refs, []);
  assert.deepEqual(event.policy_decision_refs, [
    "decision_override",
    "policy_lsp_diagnostics_operator_override_approval_satisfied",
    "policy_lsp_diagnostics_operator_override_continuation_allowed",
  ]);
});

test("diagnostics repair helper events ignore retired retry aliases", () => {
  const surface = createSurface();
  const events = [];
  const store = {
    agentForThread() {
      return { id: "agent_alpha", cwd: "/tmp/workspace" };
    },
    appendRuntimeEvent(event) {
      const stored = {
        ...event,
        event_id: `event_${events.length + 1}`,
        seq: events.length + 1,
        created_at: "2026-06-04T14:00:00.000Z",
      };
      events.push(stored);
      return stored;
    },
  };

  const event = surface.appendDiagnosticsRepairRetryTurnEvent(store, {
    threadId: "thread_alpha",
    gateEvent: { event_id: "event_gate" },
    decision: {
      decision_id: "decision_retry",
      rollbackRefs: ["snapshot_decision_alias"],
    },
    repairPolicy: {
      policyId: "policy_alias",
      rollbackRefs: ["snapshot_policy_alias"],
    },
    diagnosticsFeedback: {
      diagnosticStatus: "failed",
      diagnosticCount: 2,
      rollbackRefs: ["snapshot_feedback_alias"],
    },
    run: { id: "run_repair", artifacts: [] },
    turn: { turn_id: "turn_repair", request_id: "request_repair", status: "queued" },
    snapshotId: null,
    workflowNodeId: "runtime.lsp-diagnostics.repair-retry",
  });

  assert.equal(event.payload_summary.policy_id, null);
  assert.equal(event.payload_summary.diagnostic_status, null);
  assert.equal(event.payload_summary.diagnostic_count, null);
  assert.deepEqual(event.rollback_refs, []);
  assert.deepEqual(event.policy_decision_refs, ["decision_retry"]);
});

test("diagnostics repair surface resolves decisions from the latest matching gate event", () => {
  const surface = createSurface();
  const store = {
    projected: false,
    agentForThread() {
      return { id: "agent_alpha" };
    },
    projectThreadEvents() {
      this.projected = true;
    },
    runtimeEventsForStream() {
      return [
        {
          seq: 1,
          event_kind: "policy.blocked",
          component_kind: "lsp_diagnostics_gate",
          payload_summary: {
            gate_id: "gate_alpha",
            repair_policy: {
              policy_id: "policy_old",
              decisions: [{ decision_id: "decision_old", action: "repair_retry" }],
            },
          },
        },
        {
          seq: 2,
          event_kind: "policy.blocked",
          component_kind: "lsp_diagnostics_gate",
          payload_summary: {
            gate_id: "gate_alpha",
            repair_policy: {
              policy_id: "policy_new",
              decisions: [{ decision_id: "decision_preview", action: "restore_preview" }],
            },
          },
        },
      ];
    },
  };

  const result = surface.resolveDiagnosticsRepairDecision(store, "thread_alpha", "restore_preview", {
    gate_id: "gate_alpha",
  });

  assert.equal(store.projected, true);
  assert.equal(result.repairPolicy.policy_id, "policy_new");
  assert.equal(result.decision.decision_id, "decision_preview");
});

test("diagnostics repair resolver ignores retired gate and decision aliases", () => {
  const surface = createSurface();
  const store = {
    agentForThread() {
      return { id: "agent_alpha" };
    },
    projectThreadEvents() {
      this.projected = true;
    },
    runtimeEventsForStream() {
      return [
        {
          seq: 1,
          event_kind: "policy.blocked",
          component_kind: "lsp_diagnostics_gate",
          payload_summary: {
            gateId: "gate_alias",
            repairPolicy: {
              policy_id: "policy_alias",
              decisions: [{ decision_id: "decision_alias", action: "restore_preview" }],
            },
          },
        },
        {
          seq: 2,
          event_kind: "policy.blocked",
          component_kind: "lsp_diagnostics_gate",
          payload_summary: {
            gate_id: "gate_alpha",
            repair_policy: {
              policy_id: "policy_alpha",
            },
            repairDecisions: [{ decision_id: "decision_retired", action: "repair_retry" }],
          },
        },
        {
          seq: 3,
          event_kind: "policy.blocked",
          component_kind: "lsp_diagnostics_gate",
          payload_summary: {
            gate_id: "gate_beta",
            repair_policy: {
              policy_id: "policy_beta",
              decisions: [{ decisionId: "decision_retired", action: "operator_override" }],
            },
          },
        },
      ];
    },
  };

  assert.throws(
    () => surface.resolveDiagnosticsRepairDecision(store, "thread_alpha", "decision_alias", { gateId: "gate_alias" }),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.code, "not_found");
      return true;
    },
  );
  assert.throws(
    () =>
      surface.resolveDiagnosticsRepairDecision(store, "thread_alpha", "repair_retry", {
        gate_id: "gate_alpha",
        decisionAction: "repair_retry",
      }),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.code, "not_found");
      return true;
    },
  );
  assert.throws(
    () => surface.resolveDiagnosticsRepairDecision(store, "thread_alpha", "decision_retired", { gate_id: "gate_beta" }),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.code, "not_found");
      return true;
    },
  );
  assert.equal(store.projected, true);
});

test("diagnostics repair surface appends final execution events with action aliases", () => {
  const surface = createSurface();
  const events = [];
  const store = {
    appendRuntimeEvent(event) {
      const stored = {
        ...event,
        event_id: `event_${events.length + 1}`,
        seq: events.length + 1,
        created_at: "2026-06-04T14:00:00.000Z",
      };
      events.push(stored);
      return stored;
    },
  };

  const event = surface.appendDiagnosticsRepairDecisionExecutedEvent(store, {
    threadId: "thread_alpha",
    request: { confirm: true },
    gateEvent: { event_id: "event_gate", turn_id: "turn_blocked", payload_summary: { gate_id: "gate_alpha" } },
    decision: { decision_id: "decision_override" },
    repairPolicy: { policy_id: "policy_alpha" },
    action: "operator_override",
    snapshotId: "snapshot_alpha",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "runtime.lsp-diagnostics.operator-override",
    executionResult: {
      status: "completed",
      event: { event_id: "event_override" },
      approval_required: true,
      approval_satisfied: true,
      continuation_allowed: true,
      policy_decision_refs: ["policy_override"],
      rollback_refs: ["snapshot_alpha"],
    },
  });

  assert.equal(event.event_stream_id, "thread_alpha:events");
  assert.equal(event.workflow_node_id, "runtime.lsp-diagnostics.operator-override.decision");
  assert.equal(event.payload_summary.operator_override_event_id, "event_override");
  assert.equal(event.payload_summary.operator_override_approval_satisfied, true);
  assert.deepEqual(event.payload_summary.rollback_refs, ["snapshot_alpha"]);
});

test("diagnostics repair final execution events ignore retired decision metadata aliases", () => {
  const surface = createSurface();
  const events = [];
  const store = {
    appendRuntimeEvent(event) {
      const stored = {
        ...event,
        event_id: `event_${events.length + 1}`,
        seq: events.length + 1,
        created_at: "2026-06-04T14:00:00.000Z",
      };
      events.push(stored);
      return stored;
    },
  };

  const event = surface.appendDiagnosticsRepairDecisionExecutedEvent(store, {
    threadId: "thread_alpha",
    request: { idempotencyKey: "idempotency_alias" },
    gateEvent: { event_id: "event_gate", turn_id: "turn_blocked", payload_summary: { gate_id: "gate_alpha" } },
    decision: { decisionId: "decision_alias" },
    repairPolicy: { policyId: "policy_alias" },
    action: "restore_preview",
    snapshotId: "snapshot_alpha",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "runtime.lsp-diagnostics.restore-preview",
    executionResult: {
      status: "completed",
      event: { event_id: "event_preview" },
    },
  });

  assert.notEqual(event.idempotency_key, "idempotency_alias");
  assert.equal(event.payload_summary.decision_id, "restore_preview");
  assert.equal(event.payload_summary.policy_id, null);
  assert.deepEqual(event.policy_decision_refs, ["restore_preview"]);
});

test("diagnostics repair final execution events ignore retired execution result aliases", () => {
  const surface = createSurface();
  const events = [];
  const store = {
    appendRuntimeEvent(event) {
      const stored = {
        ...event,
        event_id: `event_${events.length + 1}`,
        seq: events.length + 1,
        created_at: "2026-06-04T14:00:00.000Z",
      };
      events.push(stored);
      return stored;
    },
  };

  const event = surface.appendDiagnosticsRepairDecisionExecutedEvent(store, {
    threadId: "thread_alpha",
    request: { confirm: true },
    gateEvent: { event_id: "event_gate", turn_id: "turn_blocked", payload_summary: { gate_id: "gate_alpha" } },
    decision: { decision_id: "decision_retry" },
    repairPolicy: { policy_id: "policy_alpha" },
    action: "repair_retry",
    snapshotId: "snapshot_alpha",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "runtime.lsp-diagnostics.repair-retry",
    executionResult: {
      status: "completed",
      event: { event_id: "event_retry" },
      repairTurn: { turn_id: "turn_alias", request_id: "request_alias" },
      approvalSatisfied: true,
      artifactRefs: ["artifact_alias"],
      policyDecisionRefs: ["policy_alias"],
      rollback_refs: ["snapshot_alpha"],
      rollbackRefs: ["snapshot_alias"],
    },
  });

  assert.equal(event.payload_summary.repair_retry_event_id, "event_retry");
  assert.equal(event.payload_summary.repair_retry_turn_id, null);
  assert.equal(event.payload_summary.repair_retry_request_id, null);
  assert.equal(event.payload_summary.approval_satisfied, null);
  assert.deepEqual(event.artifact_refs, []);
  assert.deepEqual(event.policy_decision_refs, ["decision_retry", "policy_alpha"]);
  assert.deepEqual(event.rollback_refs, ["snapshot_alpha"]);
});
