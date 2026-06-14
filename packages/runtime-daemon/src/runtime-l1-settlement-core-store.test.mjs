import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

function modelMountCore() {
  return {
    planReadProjection(request) {
      return {
        source: "rust_model_mount_read_projection_command",
        backend: "rust_model_mount_read_projection",
        projection_kind: request.projection_kind,
        projection: {
          source: "agentgres_model_mounting_projection",
        },
        evidence_refs: [
          "rust_daemon_core_model_mount_projection",
          "agentgres_model_mount_read_truth",
          "model_mount_js_read_projection_authoring_retired",
        ],
      };
    },
  };
}

test("runtime store mounts L1 settlement core from options", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-l1-settlement-core-store-"));
  const l1SettlementCore = { admitAttempt() {} };
  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      l1SettlementCore,
      modelMountCore: modelMountCore(),
    });
    try {
      assert.equal(store.l1SettlementCore, l1SettlementCore);
      assert.equal(Object.hasOwn(store, "l1SettlementRunner"), false);
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("runtime store wires L1 settlement to typed Rust governed-admission API", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-l1-settlement-typed-core-store-"));
  const calls = [];
  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      cwd: stateDir,
      modelMountCore: modelMountCore(),
      daemonCoreInvoker(request) {
        throw new Error(`generic command invoker must not run for L1 settlement: ${request?.operation}`);
      },
      daemonCoreGovernedAdmissionApi: {
        admitL1SettlementAttempt(attempt, context) {
          calls.push({ attempt, context });
          return {
            schema_version: "ioi.runtime.l1_settlement_admission.v1",
            source: "rust_l1_settlement_guard_protocol",
            backend: "l1_settlement_guard",
            thread_id: context.thread_id,
            agent_id: context.agent_id,
            settlement_ref: attempt.settlement_ref,
            settlement_admitted: true,
          };
        },
      },
    });
    try {
      const result = store.l1SettlementCore.admitAttempt(
        {
          settlement_ref: "l1://settlement/store-typed-api",
          domain_ref: "domain://store-typed-api",
          trigger_refs: ["l1-trigger://store-typed-api"],
          receipt_refs: ["receipt://store-typed-api"],
        },
        {
          thread_id: "thread_l1_store",
          agent_id: "agent_l1_store",
        },
      );

      assert.equal(result.source, "rust_l1_settlement_guard_protocol");
      assert.equal(calls.length, 1);
      assert.equal(calls[0].attempt.settlement_ref, "l1://settlement/store-typed-api");
      assert.deepEqual(calls[0].context, {
        thread_id: "thread_l1_store",
        agent_id: "agent_l1_store",
      });
      assert.equal(Object.hasOwn(calls[0], "operation"), false);
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});
