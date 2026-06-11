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
  const admissionRequiredCalls = [];
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    modelMountAdmissionRunner: {
      planReadProjection(request) {
        return {
          source: "rust_model_mount_read_projection_command",
          backend: "rust_model_mount_read_projection",
          projection_kind: request.projection_kind,
          projection: { source: "agentgres_model_mounting_projection" },
          evidence_refs: [
            "rust_daemon_core_model_mount_projection",
            "agentgres_model_mount_read_truth",
            "model_mount_js_read_projection_authoring_retired",
          ],
        };
      },
    },
    contextPolicyRunner: {
      planOperatorTurnControlAdmissionRequired(request) {
        admissionRequiredCalls.push(request);
        const evidenceRefs = request.operation === "operator_interrupt"
          ? [
              "operator_interrupt_js_facade_retired",
              "rust_daemon_core_operator_interrupt_required",
              "agentgres_operator_interrupt_state_truth_required",
            ]
          : [
              "operator_steer_js_facade_retired",
              "rust_daemon_core_operator_steer_required",
              "agentgres_operator_steer_state_truth_required",
            ];
        return {
          source: "rust_operator_turn_control_admission_required_command",
          backend: "rust_policy",
          record: {
            status: "rust_core_required",
            status_code: 501,
            code: "runtime_operator_turn_control_rust_core_required",
            message:
              "Operator turn control requires direct Rust daemon-core state admission and persistence.",
            details: {
              rust_core_boundary: "runtime.operator_turn_control",
              operation: request.operation,
              operation_kind: request.operation_kind,
              thread_id: request.thread_id,
              turn_id: request.turn_id,
              requested_action: request.requested_action ?? null,
              evidence_refs: evidenceRefs,
            },
          },
        };
      },
      planOperatorInterruptStateUpdate() {
        throw new Error("JS operator interrupt facade must not invoke the Rust state-update bridge.");
      },
      planOperatorSteerStateUpdate() {
        throw new Error("JS operator steer facade must not invoke the Rust state-update bridge.");
      },
    },
    runtimeBridge: {
      async controlThread() {
        throw new Error("JS operator interrupt facade must not control the runtime bridge directly.");
      },
    },
  });
  return { admissionRequiredCalls, stateDir, store };
}

test("interruptTurn facade uses Rust admission-required planner before runtime bridge, event append, state update planning, or JS persistence", async () => {
  const { admissionRequiredCalls, stateDir, store } = createStore();
  try {
    assert.equal(typeof store.interruptTurn, "undefined");
    await assert.rejects(
      () => store.threadTurnSurface.interruptTurn(store, "thread_one", "turn_one", {
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

    assert.equal(admissionRequiredCalls.length, 1);
    assert.deepEqual(admissionRequiredCalls[0], {
      operation: "operator_interrupt",
      operation_kind: "turn.interrupt",
      thread_id: "thread_one",
      turn_id: "turn_one",
      requested_action: "cancel",
      evidence_refs: [
        "operator_interrupt_js_facade_retired",
        "rust_daemon_core_operator_interrupt_required",
        "agentgres_operator_interrupt_state_truth_required",
      ],
    });
    assert.equal(store.runtimeEventStreams.size, 0);
    assert.equal(store.runs.size, 0);
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("steerTurn facade uses Rust admission-required planner before agent/run lookup, event append, state update planning, or JS persistence", () => {
  const { admissionRequiredCalls, stateDir, store } = createStore();
  try {
    assert.equal(typeof store.steerTurn, "undefined");
    assert.throws(
      () => store.threadTurnSurface.steerTurn(store, "thread_one", "turn_one", {
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

    assert.equal(admissionRequiredCalls.length, 1);
    assert.deepEqual(admissionRequiredCalls[0], {
      operation: "operator_steer",
      operation_kind: "turn.steer",
      thread_id: "thread_one",
      turn_id: "turn_one",
      requested_action: null,
      evidence_refs: [
        "operator_steer_js_facade_retired",
        "rust_daemon_core_operator_steer_required",
        "agentgres_operator_steer_state_truth_required",
      ],
    });
    assert.equal(store.runtimeEventStreams.size, 0);
    assert.equal(store.runs.size, 0);
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});
