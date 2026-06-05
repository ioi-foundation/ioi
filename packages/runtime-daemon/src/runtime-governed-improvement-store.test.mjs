import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

test("runtime store mounts governed improvement runner from options", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-governed-improvement-store-"));
  const governedImprovementRunner = {
    admitProposal() {
      throw new Error("not invoked in constructor test");
    },
  };

  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      cwd: stateDir,
      governedImprovementRunner,
    });

    assert.equal(store.governedImprovementRunner, governedImprovementRunner);
    store.close();
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});
