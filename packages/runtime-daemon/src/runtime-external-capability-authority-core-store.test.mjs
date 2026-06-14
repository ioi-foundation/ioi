import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

function modelMountAdmissionRunner() {
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

test("runtime store mounts external capability authority core from options", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-external-capability-authority-core-store-"));
  const externalCapabilityAuthorityCore = {
    authorizeExit() {
      throw new Error("not invoked in constructor test");
    },
  };

  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      externalCapabilityAuthorityCore,
      modelMountAdmissionRunner: modelMountAdmissionRunner(),
    });
    try {
      assert.equal(store.externalCapabilityAuthorityCore, externalCapabilityAuthorityCore);
      assert.equal(Object.hasOwn(store, "externalCapabilityAuthorityRunner"), false);
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});
