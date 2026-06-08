import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

function assertNoRetiredOperatorTurnControlDetailAliases(details) {
  for (const key of [
    "rustCoreBoundary",
    "operationKind",
    "threadId",
    "turnId",
    "requestedAction",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(details ?? {}, key), false, `${key} detail alias must be absent`);
  }
}

function createStore() {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-operator-control-facade-"));
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    contextPolicyRunner: {
      planOperatorInterruptStateUpdate() {
        throw new Error("JS operator interrupt facade must not invoke the Rust planner bridge.");
      },
      planOperatorSteerStateUpdate() {
        throw new Error("JS operator steer facade must not invoke the Rust planner bridge.");
      },
    },
    runtimeBridge: {
      async controlThread() {
        throw new Error("JS operator interrupt facade must not control the runtime bridge directly.");
      },
    },
  });
  return { stateDir, store };
}

test("interruptTurn facade fails closed before runtime bridge, event append, Rust planning, or JS persistence", async () => {
  const { stateDir, store } = createStore();
  try {
    await assert.rejects(
      () => store.interruptTurn("thread_one", "turn_one", {
        runtime_control_action: "cancel",
        controlAction: "cancel",
        workflowGraphId: "graph_retired",
      }),
      (error) => {
        assert.equal(error.code, "runtime_operator_turn_control_rust_core_required");
        assert.equal(error.status, 501);
        assert.equal(error.details.rust_core_boundary, "runtime.operator_turn_control");
        assert.equal(error.details.operation, "operator_interrupt");
        assert.equal(error.details.operation_kind, "turn.interrupt");
        assert.equal(error.details.thread_id, "thread_one");
        assert.equal(error.details.turn_id, "turn_one");
        assert.equal(error.details.requested_action, "cancel");
        assert.deepEqual(error.details.evidence_refs, [
          "operator_interrupt_js_facade_retired",
          "rust_daemon_core_operator_interrupt_required",
          "agentgres_operator_interrupt_state_truth_required",
        ]);
        assertNoRetiredOperatorTurnControlDetailAliases(error.details);
        return true;
      },
    );

    assert.equal(store.runtimeEventStreams.size, 0);
    assert.equal(store.runs.size, 0);
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("steerTurn facade fails closed before agent/run lookup, event append, Rust planning, or JS persistence", () => {
  const { stateDir, store } = createStore();
  try {
    assert.throws(
      () => store.steerTurn("thread_one", "turn_one", {
        guidance: "focus on Rust admission",
        idempotencyKey: "operator_steer_idempotency_retired",
      }),
      (error) => {
        assert.equal(error.code, "runtime_operator_turn_control_rust_core_required");
        assert.equal(error.status, 501);
        assert.equal(error.details.rust_core_boundary, "runtime.operator_turn_control");
        assert.equal(error.details.operation, "operator_steer");
        assert.equal(error.details.operation_kind, "turn.steer");
        assert.equal(error.details.thread_id, "thread_one");
        assert.equal(error.details.turn_id, "turn_one");
        assert.deepEqual(error.details.evidence_refs, [
          "operator_steer_js_facade_retired",
          "rust_daemon_core_operator_steer_required",
          "agentgres_operator_steer_state_truth_required",
        ]);
        assertNoRetiredOperatorTurnControlDetailAliases(error.details);
        return true;
      },
    );

    assert.equal(store.runtimeEventStreams.size, 0);
    assert.equal(store.runs.size, 0);
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});
