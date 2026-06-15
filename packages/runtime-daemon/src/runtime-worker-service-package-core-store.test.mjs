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
        source: "rust_daemon_core.model_mount.read_projection",
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

test("runtime store mounts worker/service package core from options", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-worker-service-package-core-store-"));
  const workerServicePackageCore = {
    admitInvocation() {
      throw new Error("not invoked in constructor test");
    },
  };

  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      cwd: stateDir,
      modelMountCore: modelMountCore(),
      workerServicePackageCore,
    });
    try {
      assert.equal(store.workerServicePackageCore, workerServicePackageCore);
      assert.equal(Object.hasOwn(store, "workerServicePackageRunner"), false);
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("runtime store wires worker/service package to typed Rust package API", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-worker-service-package-typed-core-store-"));
  const calls = [];
  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      cwd: stateDir,
      modelMountCore: modelMountCore(),
      daemonCoreWorkerServiceApi: {
        admitWorkerServicePackageInvocation(request, context) {
          calls.push({ request, context });
          return {
            schema_version: "ioi.runtime.worker_service_package_admission.v1",
            source: "rust_worker_service_package_invocation_protocol",
            backend: "rust_package_invocation",
            thread_id: context.thread_id,
            agent_id: context.agent_id,
            invocation_id: request.invocation.invocation_id,
          };
        },
      },
    });
    try {
      const result = store.workerServicePackageCore.admitInvocation(
        {
          package_kind: "worker_package",
          package_ref: "worker://store-typed-api",
          manifest_ref: "module://worker/store-typed-api@1",
          invocation: {
            invocation_id: "invocation://worker-service-package/store-typed-api",
          },
          result: {
            receipt_refs: ["receipt://worker-service-package/store-typed-api"],
          },
        },
        {
          thread_id: "thread_worker_store",
          agent_id: "agent_worker_store",
        },
      );

      assert.equal(result.source, "rust_worker_service_package_invocation_protocol");
      assert.equal(calls.length, 1);
      assert.equal(
        calls[0].request.invocation.invocation_id,
        "invocation://worker-service-package/store-typed-api",
      );
      assert.deepEqual(calls[0].context, {
        thread_id: "thread_worker_store",
        agent_id: "agent_worker_store",
      });
      assert.equal(Object.hasOwn(calls[0], "operation"), false);
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});
