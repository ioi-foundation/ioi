import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

test("runtime store mounts external capability authority runner from options", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-external-capability-authority-store-"));
  const externalCapabilityAuthorityRunner = {
    authorizeExit() {
      throw new Error("not invoked in constructor test");
    },
  };

  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      externalCapabilityAuthorityRunner,
    });
    try {
      assert.equal(store.externalCapabilityAuthorityRunner, externalCapabilityAuthorityRunner);
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});
