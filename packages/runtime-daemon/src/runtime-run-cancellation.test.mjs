import assert from "node:assert/strict";
import test from "node:test";

import { cancelRun } from "./runtime-run-cancellation.mjs";

function fakeState(run) {
  const writes = [];
  return {
    runs: new Map([[run.id, run]]),
    writes,
    getRun(runId) {
      return this.runs.get(runId);
    },
    writeRun(updated, operation) {
      writes.push({ operation, run: updated });
    },
  };
}

test("cancelRun facade fails closed before Rust planning or JS persistence", () => {
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
