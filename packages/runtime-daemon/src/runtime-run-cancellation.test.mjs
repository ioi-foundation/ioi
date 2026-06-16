import assert from "node:assert/strict";
import test from "node:test";

import { cancelRun } from "./runtime-run-cancellation.mjs";

function fakeState(run) {
  const writes = [];
  const runnerCalls = [];
  return {
    runs: new Map([[run.id, run]]),
    runnerCalls,
    writes,
    nowIso() {
      return "2026-06-06T04:45:00.000Z";
    },
    getRun(runId) {
      return this.runs.get(runId);
    },
    writeRun(updated, operation) {
      writes.push({ operation, run: updated });
    },
  };
}

function runFixture(overrides = {}) {
  return {
    id: "run_cancel_one",
    agentId: "agent_one",
    status: "running",
    objective: "Cancel this run",
    mode: "send",
    createdAt: "2026-06-04T00:00:00.000Z",
    updatedAt: "2026-06-04T00:00:01.000Z",
    events: [{ id: "event_1", type: "delta", data: { text: "partial" } }],
    trace: { events: [], receipts: [], qualityLedger: {} },
    receipts: [],
    artifacts: [],
    ...overrides,
  };
}

function canceledRunProjection(request, overrides = {}) {
  const runtimeTask = { taskId: "task_run_cancel_one", status: "canceled" };
  const runtimeJob = { jobId: "job_run_cancel_one", status: "canceled" };
  const runtimeChecklist = {
    checklistId: "checklist_run_cancel_one",
    status: "canceled",
  };
  return {
    source: "rust_run_cancel_state_update_api",
    backend: "rust_policy",
    status: "planned",
    operation_kind: "run.cancel",
    updated_at: request.canceled_at,
    stop_condition: { reason: "operator_cancel", evidenceSufficient: true },
    runtime_task: runtimeTask,
    runtime_job: runtimeJob,
    runtime_checklist: runtimeChecklist,
    run: {
      ...request.run,
      status: "canceled",
      updatedAt: request.canceled_at,
      events: [
        ...request.run.events,
        { type: "runtime_task", data: runtimeTask },
        { type: "runtime_checklist", data: runtimeChecklist },
        { type: "job_canceled", data: runtimeJob },
        { type: "canceled", data: { reason: "operator_cancel" } },
      ],
      receipts: [{ id: "receipt_run_cancel_one_runtime_checklist" }],
      artifacts: [{ id: "artifact_run_cancel_one_runtime_checklist" }],
      runtimeTask,
      runtimeJob,
      runtimeChecklist,
    },
    ...overrides,
  };
}

test("cancelRun facade commits only explicit Rust-planned cancellation through Agentgres writeRun", () => {
  const run = runFixture();
  const state = fakeState(run);
  const contextPolicyCore = {
    planRunCancelStateUpdate(request) {
      state.runnerCalls.push(request);
      return canceledRunProjection(request);
    },
    planRunCancelAdmissionRequired() {
      throw new Error("Positive run cancellation must not ask for admission-required refusal.");
    },
  };

  const result = cancelRun(state, run.id, { contextPolicyCore });

  assert.equal(state.runnerCalls.length, 1);
  assert.deepEqual(state.runnerCalls[0], {
    run_id: run.id,
    run,
    canceled_at: "2026-06-06T04:45:00.000Z",
  });
  assert.equal(result.id, run.id);
  assert.equal(result.status, "canceled");
  assert.equal(result.updatedAt, "2026-06-06T04:45:00.000Z");
  assert.deepEqual(state.writes, [{ operation: "run.cancel", run: result }]);
  assert.equal(state.runs.get(run.id), run);
  assert.equal(result.events.at(-2).type, "job_canceled");
  assert.equal(result.events.at(-1).type, "canceled");
});

test("cancelRun facade fails closed when Rust state planner is missing", () => {
  const run = {
    id: "run_cancel_one",
    agentId: "agent_one",
    status: "running",
    objective: "Cancel this run",
    mode: "send",
    createdAt: "2026-06-04T00:00:00.000Z",
    updatedAt: "2026-06-04T00:00:01.000Z",
    events: [{ id: "event_1", type: "delta", data: { text: "partial" } }],
    trace: { events: [], receipts: [], qualityLedger: {} },
    receipts: [],
    artifacts: [],
  };
  const state = fakeState(run);

  assert.throws(
    () => cancelRun(state, run.id),
    (error) => {
      assert.equal(error.code, "runtime_run_cancel_rust_core_required");
      assert.equal(error.status, 501);
      assert.equal(error.details.rust_core_boundary, "runtime.run_cancel");
      assert.equal(error.details.operation, "run_cancel");
      assert.equal(error.details.operation_kind, "run.cancel");
      assert.equal(error.details.run_id, run.id);
      assert.equal(error.details.run_status, "running");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_run_cancel_js_facade_retired",
        "rust_daemon_core_run_cancel_required",
        "agentgres_run_cancel_state_truth_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "runId"), false);
      assert.equal(Object.hasOwn(error.details, "runStatus"), false);
      return true;
    },
  );

  assert.equal(state.runs.get(run.id), run);
  assert.deepEqual(state.writes, []);
});

test("cancelRun ignores retired admission-required fallback when state planner is absent", () => {
  const run = runFixture();
  const state = fakeState(run);
  const contextPolicyCore = {
    planRunCancelAdmissionRequired() {
      assert.fail("Retired run-cancel admission-required fallback must not be invoked.");
    },
  };

  assert.throws(
    () => cancelRun(state, run.id, { contextPolicyCore }),
    (error) => {
      assert.equal(error.code, "runtime_run_cancel_rust_core_required");
      assert.equal(error.status, 501);
      assert.equal(error.details.rust_core_boundary, "runtime.run_cancel");
      assert.equal(error.details.operation, "run_cancel");
      assert.equal(error.details.operation_kind, "run.cancel");
      assert.equal(error.details.run_id, run.id);
      assert.equal(error.details.run_status, "running");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_run_cancel_js_facade_retired",
        "rust_daemon_core_run_cancel_required",
        "agentgres_run_cancel_state_truth_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "runId"), false);
      assert.equal(Object.hasOwn(error.details, "runStatus"), false);
      return true;
    },
  );

  assert.equal(state.runs.get(run.id), run);
  assert.deepEqual(state.writes, []);
});

test("cancelRun missing-run failure remains canonical and does not write", () => {
  const run = {
    id: "run_existing",
    status: "running",
  };
  const state = fakeState(run);

  assert.throws(
    () => cancelRun(state, "run_missing"),
    (error) => {
      assert.equal(error.code, "runtime_run_cancel_rust_core_required");
      assert.equal(error.status, 501);
      assert.equal(error.details.run_id, "run_missing");
      assert.equal(error.details.run_status, null);
      assert.equal(Object.hasOwn(error.details, "runId"), false);
      return true;
    },
  );

  assert.equal(state.runs.get(run.id), run);
  assert.deepEqual(state.writes, []);
});

test("cancelRun rejects Rust state update without canceled run projection", () => {
  const run = runFixture();
  const state = fakeState(run);
  const contextPolicyCore = {
    planRunCancelStateUpdate(request) {
      return canceledRunProjection(request, {
        run: { ...request.run, status: "running" },
      });
    },
  };

  assert.throws(
    () => cancelRun(state, run.id, { contextPolicyCore }),
    (error) => {
      assert.equal(error.code, "run_cancel_state_update_projection_incomplete");
      assert.equal(error.status, 502);
      assert.equal(error.details.rust_core_boundary, "runtime.run_cancel");
      assert.equal(error.details.run_id, run.id);
      assert.equal(error.details.actual_run_status, "running");
      return true;
    },
  );
  assert.deepEqual(state.writes, []);
});

test("cancelRun rejects Rust state update with wrong operation kind", () => {
  const run = runFixture();
  const state = fakeState(run);
  const contextPolicyCore = {
    planRunCancelStateUpdate(request) {
      return canceledRunProjection(request, {
        operation_kind: "run.create",
      });
    },
  };

  assert.throws(
    () => cancelRun(state, run.id, { contextPolicyCore }),
    (error) => {
      assert.equal(error.code, "run_cancel_state_update_operation_kind_mismatch");
      assert.equal(error.status, 502);
      assert.equal(error.details.expected_operation_kind, "run.cancel");
      assert.equal(error.details.actual_operation_kind, "run.create");
      return true;
    },
  );
  assert.deepEqual(state.writes, []);
});
