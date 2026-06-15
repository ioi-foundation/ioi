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

test("runtime store mounts workspace restore core from options", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-workspace-restore-core-store-"));
  const workspaceRestoreCore = {
    captureSnapshotFiles() {
      throw new Error("not invoked in constructor test");
    },
  };

  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      cwd: stateDir,
      modelMountCore: modelMountCore(),
      workspaceRestoreCore,
    });
    try {
      assert.equal(store.workspaceRestoreCore, workspaceRestoreCore);
      assert.equal(Object.hasOwn(store, "workspaceRestoreRunner"), false);
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("runtime store wires workspace restore core to typed Rust workspace API", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-workspace-restore-core-typed-store-"));
  const calls = [];

  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      cwd: stateDir,
      modelMountCore: modelMountCore(),
      daemonCoreWorkspaceRestoreApi: {
        projectWorkspaceSnapshotList(request) {
          calls.push(request);
          return {
            source: "rust_workspace_snapshot_projection_protocol",
            backend: "rust_workspace_restore",
            projection_kind: "workspace_snapshot.list",
            projection: { snapshots: [] },
          };
        },
      },
    });
    try {
      const result = store.workspaceRestoreCore.projectWorkspaceSnapshotList({
        thread_id: "thread_alpha",
      });

      assert.equal(result.source, "rust_workspace_snapshot_projection_protocol");
      assert.equal(calls.length, 1);
      assert.equal(calls[0].request.thread_id, "thread_alpha");
      assert.equal(Object.hasOwn(calls[0], "operation"), false);
      assert.equal(Object.hasOwn(calls[0], "backend"), false);
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});
