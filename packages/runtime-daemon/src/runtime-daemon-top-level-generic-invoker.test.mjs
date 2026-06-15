import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";
import { startRuntimeDaemonServiceWithStore } from "./service/runtime-daemon-service.mjs";

test("runtime daemon startup rejects daemon-wide generic invoker option", async () => {
  await assert.rejects(
    () =>
      startRuntimeDaemonServiceWithStore({
        options: { daemonCoreInvoker() {} },
        StateStore: class UnusedStateStore {},
        handleRequest() {},
        writeError() {},
      }),
    /daemonCoreInvoker is retired/,
  );
});

test("runtime daemon store rejects daemon-wide generic invoker option", () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-daemon-state-"));
  assert.throws(
    () => new AgentgresRuntimeStateStore(stateDir, { daemonCoreInvoker() {} }),
    /daemonCoreInvoker is retired/,
  );
});
