import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

test("runtime store mounts L1 settlement runner from options", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-l1-settlement-store-"));
  const l1SettlementRunner = { admitAttempt() {} };
  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      l1SettlementRunner,
    });
    try {
      assert.equal(store.l1SettlementRunner, l1SettlementRunner);
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});
