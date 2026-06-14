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
  const plannerCalls = [];
  const runtimeBridgeCalls = [];
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    modelMountCore: {
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
    contextPolicyCore: {
      planOperatorInterruptStateUpdate(request) {
        plannerCalls.push({ method: "planOperatorInterruptStateUpdate", request });
        return {
          source: "rust_operator_interrupt_state_update_command",
          backend: "rust_policy",
          status: "planned",
          operation_kind: "turn.interrupt",
          updated_at: request.created_at,
          operator_control: {
            control: "interrupt",
            source: request.source,
            reason: request.reason,
            event_id: request.event_id,
            seq: request.seq,
            created_at: request.created_at,
          },
          stop_condition: {
            reason: "operator_interrupt",
          },
          run: {
            ...request.run,
            status: "canceled",
            turnStatus: "interrupted",
            updatedAt: request.created_at,
            trace: {
              ...(request.run.trace ?? {}),
              operatorControls: [{
                control: "interrupt",
                event_id: request.event_id,
              }],
            },
          },
        };
      },
      planOperatorSteerStateUpdate(request) {
        plannerCalls.push({ method: "planOperatorSteerStateUpdate", request });
        return {
          source: "rust_operator_steer_state_update_command",
          backend: "rust_policy",
          status: "planned",
          operation_kind: "turn.steer",
          updated_at: request.created_at,
          operator_control: {
            control: "steer",
            source: request.source,
            guidance: request.guidance,
            event_id: request.event_id,
            seq: request.seq,
            created_at: request.created_at,
          },
          run: {
            ...request.run,
            updatedAt: request.created_at,
            trace: {
              ...(request.run.trace ?? {}),
              operatorControls: [{
                control: "steer",
                event_id: request.event_id,
              }],
            },
          },
        };
      },
    },
    runtimeBridge: {
      async controlThread() {
        runtimeBridgeCalls.push({ method: "controlThread" });
        throw new Error("Operator control must not use runtime bridge direct control.");
      },
    },
  });
  store.agents.set("agent_one", {
    id: "agent_one",
    status: "active",
    runtime: "local",
    cwd: stateDir,
    createdAt: "2026-06-13T11:59:00.000Z",
    updatedAt: "2026-06-13T12:00:00.000Z",
    runtimeControls: { mode: "agent", approval_mode: "suggest" },
  });
  store.runs.set("run_one", {
    id: "run_one",
    agentId: "agent_one",
    status: "running",
    turnStatus: "running",
    createdAt: "2026-06-13T12:00:00.000Z",
    updatedAt: "2026-06-13T12:01:00.000Z",
    trace: {},
  });
  store.writeRun = (run, operationKind) => {
    plannerCalls.push({ method: "writeRun", run, operationKind });
    store.runs.set(run.id, run);
    return {
      source: "rust_agentgres_runtime_run_state_commit_protocol",
      operation_kind: operationKind,
      receipt_refs: [`receipt://${operationKind}/${run.id}`],
      policy_decision_refs: [`policy://${operationKind}/${run.id}`],
    };
  };
  return { plannerCalls, runtimeBridgeCalls, stateDir, store };
}

test("interruptTurn facade uses Rust state-update planning before Agentgres run persistence", async () => {
  const { plannerCalls, runtimeBridgeCalls, stateDir, store } = createStore();
  try {
    assert.equal(typeof store.interruptTurn, "undefined");
    const result = await store.threadTurnSurface.interruptTurn(store, "thread_one", "turn_one", {
      runtime_control_action: "cancel",
      controlAction: "cancel",
      workflowGraphId: "graph_retired",
      created_at: "2026-06-13T12:02:00.000Z",
    });

    assert.equal(result.status, "completed");
    assert.equal(result.operation, "operator_interrupt");
    assert.equal(result.operation_kind, "turn.interrupt");
    assert.equal(result.run.status, "canceled");
    assert.equal(result.run.turnStatus, "interrupted");
    assert.equal(result.operator_control.reason, "cancel");
    assert.equal(result.evidence_refs.includes("rust_daemon_core_operator_interrupt_state_update"), true);
    assert.equal(plannerCalls.length, 2);
    assert.equal(plannerCalls[0].method, "planOperatorInterruptStateUpdate");
    assert.equal(plannerCalls[0].request.thread_id, "thread_one");
    assert.equal(plannerCalls[0].request.turn_id, "turn_one");
    assert.equal(plannerCalls[0].request.run_id, "run_one");
    assert.equal(plannerCalls[0].request.reason, "cancel");
    assertNoRetiredOperatorTurnControlDetailAliases(plannerCalls[0].request);
    assert.equal(plannerCalls[1].method, "writeRun");
    assert.equal(plannerCalls[1].operationKind, "turn.interrupt");
    assert.equal(store.runs.get("run_one").turnStatus, "interrupted");
    assert.equal(store.runs.get("run_one").trace.operatorControls[0].control, "interrupt");
    assert.deepEqual(runtimeBridgeCalls, []);
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("steerTurn facade uses Rust state-update planning before Agentgres run persistence", () => {
  const { plannerCalls, runtimeBridgeCalls, stateDir, store } = createStore();
  try {
    assert.equal(typeof store.steerTurn, "undefined");
    const result = store.threadTurnSurface.steerTurn(store, "thread_one", "turn_one", {
      guidance: "focus on Rust admission",
      idempotencyKey: "operator_steer_idempotency_retired",
      createdAt: "2026-06-13T12:03:00.000Z",
    });

    assert.equal(result.status, "completed");
    assert.equal(result.operation, "operator_steer");
    assert.equal(result.operation_kind, "turn.steer");
    assert.equal(result.operator_control.guidance, "focus on Rust admission");
    assert.equal(result.evidence_refs.includes("rust_daemon_core_operator_steer_state_update"), true);
    assert.equal(plannerCalls.length, 2);
    assert.equal(plannerCalls[0].method, "planOperatorSteerStateUpdate");
    assert.equal(plannerCalls[0].request.thread_id, "thread_one");
    assert.equal(plannerCalls[0].request.turn_id, "turn_one");
    assert.equal(plannerCalls[0].request.run_id, "run_one");
    assert.equal(plannerCalls[0].request.guidance, "focus on Rust admission");
    assertNoRetiredOperatorTurnControlDetailAliases(plannerCalls[0].request);
    assert.equal(plannerCalls[1].method, "writeRun");
    assert.equal(plannerCalls[1].operationKind, "turn.steer");
    assert.equal(store.runs.get("run_one").trace.operatorControls[0].control, "steer");
    assert.deepEqual(runtimeBridgeCalls, []);
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});
