import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

test("runtime store mounts worker/service package runner from options", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-worker-service-package-store-"));
  const workerServicePackageRunner = {
    admitInvocation() {
      throw new Error("not invoked in constructor test");
    },
  };

  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      cwd: stateDir,
      workerServicePackageRunner,
    });

    assert.equal(store.workerServicePackageRunner, workerServicePackageRunner);
    store.close();
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});
