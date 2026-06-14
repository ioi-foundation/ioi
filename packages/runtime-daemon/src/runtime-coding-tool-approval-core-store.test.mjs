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

test("runtime store mounts coding tool approval core from options", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-coding-tool-approval-core-store-"));
  const codingToolApprovalCore = {
    planApprovalManifest() {
      throw new Error("not invoked in constructor test");
    },
  };

  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      cwd: stateDir,
      modelMountCore: modelMountCore(),
      codingToolApprovalCore,
    });
    try {
      assert.equal(store.codingToolApprovalCore, codingToolApprovalCore);
      assert.equal(Object.hasOwn(store, "codingToolApprovalRunner"), false);
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("runtime store wires approval cores to typed Rust approval API", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-approval-core-api-store-"));
  const calls = [];

  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      cwd: stateDir,
      modelMountCore: modelMountCore(),
      daemonCoreInvoker(request) {
        throw new Error(`generic command invoker must not run approval APIs: ${request?.operation}`);
      },
      daemonCoreApprovalApi: {
        planCodingToolApprovalManifest(request) {
          calls.push({ method: "planCodingToolApprovalManifest", request });
          return {
            schema_version: "ioi.runtime.coding-tool-approval-result.v1",
            approval_required: true,
            manifest: {
              schema_version: "ioi.runtime.coding-tool-approval-manifest.v1",
              tool_id: request.tool_id,
            },
          };
        },
        projectApprovalQueue(request) {
          calls.push({ method: "projectApprovalQueue", request });
          return {
            status: "projected",
            operation_kind: "approval.queue_projection",
            thread_id: request.thread_id,
            approvals: [],
            pending_count: 0,
            resolved_count: 0,
          };
        },
      },
    });
    try {
      const approvalPlan = store.codingToolApprovalCore.planApprovalManifest({
        thread_id: "thread_store",
        tool_id: "file.apply_patch",
        tool_call_id: "call_store",
      });
      const approvalQueue = store.approvalStateCore.projectApprovalQueue({
        thread_id: "thread_store",
        state_dir: stateDir,
      });

      assert.equal(approvalPlan.approval_required, true);
      assert.equal(approvalQueue.operation_kind, "approval.queue_projection");
      assert.deepEqual(calls.map((call) => call.method), [
        "planCodingToolApprovalManifest",
        "projectApprovalQueue",
      ]);
      for (const call of calls) {
        assert.equal(Object.hasOwn(call.request, "operation"), false);
        assert.equal(Object.hasOwn(call.request, "backend"), false);
      }
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});
