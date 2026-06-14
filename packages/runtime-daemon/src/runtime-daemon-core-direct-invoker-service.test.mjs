import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

test("daemon-level typed APIs feed migrated daemon-core surfaces", () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-daemon-core-direct-"));
  const calls = [];
  const governedAdmissionCalls = [];
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    modelMountCore: {
      planReadProjection(request) {
        const projection = {
          schemaVersion: request.schema_version,
          source: "agentgres_model_mounting_projection",
        };
        return {
          source: "rust_model_mount_read_projection_command",
          backend: "rust_model_mount_read_projection",
          projection_kind: request.projection_kind,
          evidence_refs: [
            "rust_daemon_core_model_mount_projection",
            "agentgres_model_mount_read_truth",
            "model_mount_js_read_projection_authoring_retired",
          ],
          projection,
        };
      },
    },
    daemonCoreInvoker(request) {
      calls.push(request);
      throw new Error(
        `generic command invoker must not run migrated L1 settlement: ${request?.operation}`,
      );
    },
    daemonCoreGovernedAdmissionApi: {
      admitL1SettlementAttempt(attempt, context) {
        governedAdmissionCalls.push({ attempt, context });
        return {
          source: "direct_governed_admission_api",
          backend: "l1_settlement_guard",
          thread_id: context.thread_id,
          agent_id: context.agent_id,
          settlement_admitted: true,
          record: {
            settlement_ref: attempt.settlement_ref,
            trigger_refs: attempt.trigger_refs,
            receipt_refs: attempt.receipt_refs,
          },
        };
      },
    },
  });

  const result = store.l1SettlementCore.admitAttempt(
    {
      settlement_ref: "settlement://direct",
      trigger_refs: ["trigger://direct"],
    },
    {
      thread_id: "thread_direct",
      agent_id: "agent_direct",
    },
  );

  assert.equal(calls.length, 0);
  assert.equal(governedAdmissionCalls.length, 1);
  assert.deepEqual(governedAdmissionCalls[0].context, {
    thread_id: "thread_direct",
    agent_id: "agent_direct",
  });
  assert.equal(Object.hasOwn(governedAdmissionCalls[0], "operation"), false);
  assert.equal(result.source, "direct_governed_admission_api");
  assert.equal(result.settlement_admitted, true);
  assert.equal(Object.hasOwn(result, "settlement_ref"), false);
  assert.equal(result.record.settlement_ref, "settlement://direct");
});
