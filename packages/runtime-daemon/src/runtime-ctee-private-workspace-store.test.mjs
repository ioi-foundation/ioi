import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

test("runtime store mounts cTEE private workspace runner from options", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-ctee-private-workspace-store-"));
  const cteePrivateWorkspaceRunner = { executeAction() {} };
  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      cteePrivateWorkspaceRunner,
    });
    try {
      assert.equal(store.cteePrivateWorkspaceRunner, cteePrivateWorkspaceRunner);
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});
