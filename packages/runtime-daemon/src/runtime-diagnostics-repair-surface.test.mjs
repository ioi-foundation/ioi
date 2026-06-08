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

test("diagnostics repair decision execution facade fails closed before JS lookup, event append, or persistence", () => {
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
      assert.equal(error.code, "runtime_diagnostics_repair_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.diagnostics_repair");
      assert.equal(error.details.operation, "diagnostics_repair_decision_execution");
      assert.equal(error.details.operation_kind, "diagnostics.repair_decision.execute");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.decision_id, "decision_alpha");
      assert.deepEqual(error.details.evidence_refs, [
        "diagnostics_repair_decision_execution_js_facade_retired",
        "rust_daemon_core_diagnostics_repair_admission_required",
        "agentgres_diagnostics_repair_state_truth_required",
      ]);
      assertNoRetiredDiagnosticsRepairDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("diagnostics operator override facade fails closed before Rust planner invocation or JS run writes", () => {
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
        "diagnostics_operator_override_js_facade_retired",
        "rust_daemon_core_operator_override_state_required",
        "agentgres_operator_override_state_truth_required",
      ]);
      assertNoRetiredDiagnosticsRepairDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("diagnostics repair retry facade fails closed before JS createRun or retry event append", () => {
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
      assert.equal(error.code, "runtime_diagnostics_repair_rust_core_required");
      assert.equal(error.details.operation, "diagnostics_repair_retry_turn_creation");
      assert.equal(error.details.operation_kind, "diagnostics.repair_retry.create");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.decision_id, "decision_retry");
      assert.equal(error.details.gate_event_id, "event_gate");
      assert.equal(error.details.snapshot_id, "snapshot_alpha");
      assert.deepEqual(error.details.evidence_refs, [
        "diagnostics_repair_retry_js_create_run_facade_retired",
        "rust_daemon_core_repair_retry_run_admission_required",
        "agentgres_repair_retry_state_truth_required",
      ]);
      assertNoRetiredDiagnosticsRepairDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("diagnostics repair event append helpers fail closed before JS runtime event append", () => {
  for (const [name, call, operation, operationKind] of [
    [
      "appendDiagnosticsOperatorOverrideEvent",
      (surface, store) =>
        surface.appendDiagnosticsOperatorOverrideEvent(store, {
          threadId: "thread_alpha",
          gateEvent: { event_id: "event_gate" },
          decision: { decision_id: "decision_override" },
          snapshotId: "snapshot_alpha",
        }),
      "diagnostics_operator_override_event_append",
      "diagnostics.operator_override.event",
    ],
    [
      "appendDiagnosticsRepairRetryTurnEvent",
      (surface, store) =>
        surface.appendDiagnosticsRepairRetryTurnEvent(store, {
          threadId: "thread_alpha",
          gateEvent: { event_id: "event_gate" },
          decision: { decision_id: "decision_retry" },
          snapshotId: "snapshot_alpha",
        }),
      "diagnostics_repair_retry_event_append",
      "diagnostics.repair_retry.created",
    ],
    [
      "appendDiagnosticsRepairDecisionExecutedEvent",
      (surface, store) =>
        surface.appendDiagnosticsRepairDecisionExecutedEvent(store, {
          threadId: "thread_alpha",
          gateEvent: { event_id: "event_gate" },
          decision: { decision_id: "decision_alpha" },
          action: "restore_apply",
          snapshotId: "snapshot_alpha",
        }),
      "diagnostics_repair_decision_event_append",
      "diagnostics.repair_decision.executed",
    ],
  ]) {
    const { calls, store, surface } = harness();
    assert.throws(
      () => call(surface, store),
      (error) => {
        assert.equal(error.status, 501, name);
        assert.equal(error.code, "runtime_diagnostics_repair_rust_core_required");
        assert.equal(error.details.operation, operation);
        assert.equal(error.details.operation_kind, operationKind);
        assert.equal(error.details.thread_id, "thread_alpha");
        assert.equal(error.details.gate_event_id, "event_gate");
        assert.equal(error.details.snapshot_id, "snapshot_alpha");
        assertNoRetiredDiagnosticsRepairDetailAliases(error.details);
        return true;
      },
    );
    assert.deepEqual(calls, []);
  }
});

test("diagnostics repair decision resolver facade fails closed before JS projection reads", () => {
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
      assert.equal(error.details.operation, "diagnostics_repair_decision_resolution");
      assert.equal(error.details.operation_kind, "diagnostics.repair_decision.resolve");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.decision_id, "decision_alpha");
      assert.equal(error.details.gate_id, "gate_alpha");
      assert.deepEqual(error.details.evidence_refs, [
        "diagnostics_repair_decision_resolution_js_projection_retired",
        "rust_daemon_core_diagnostics_repair_projection_required",
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
