import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

test("daemon-level direct invoker feeds default daemon-core runners", () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-daemon-core-direct-"));
  const calls = [];
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    modelMountAdmissionRunner: {
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
      return {
        source: "direct_daemon_core_api",
        backend: request.backend,
        settlement_admitted: true,
        record: {
          settlement_ref: "settlement://direct",
          trigger_refs: ["trigger://direct"],
          receipt_refs: ["receipt://direct"],
        },
      };
    },
  });

  const result = store.l1SettlementRunner.admitAttempt(
    {
      settlement_ref: "settlement://direct",
      trigger_refs: ["trigger://direct"],
    },
    {
      thread_id: "thread_direct",
      agent_id: "agent_direct",
    },
  );

  assert.equal(calls.length, 1);
  assert.equal(calls[0].operation, "admit_l1_settlement_attempt");
  assert.equal(calls[0].schema_version, "ioi.runtime.daemon_core.command.v1");
  assert.equal(calls[0].thread_id, "thread_direct");
  assert.equal(result.source, "direct_daemon_core_api");
  assert.equal(result.settlement_admitted, true);
  assert.equal(result.settlement_ref, "settlement://direct");
});
