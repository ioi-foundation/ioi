import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createRuntimeAgentServiceCommandAdapter } from "./runtime-agent-service-adapter.mjs";

test("RuntimeAgentService command adapter bridge calls inherit current process env", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-adapter-env-"));
  const bridgeScript = path.join(tempDir, "bridge-env-probe.mjs");
  fs.writeFileSync(
    bridgeScript,
    `
import fs from "node:fs";

const request = JSON.parse(fs.readFileSync(0, "utf8"));
console.log(JSON.stringify({
  ok: true,
  result: {
    bridge_id: request.bridge_id,
    source: "runtime_service",
    operation: request.operation,
    dynamic_env: process.env.IOI_RUNTIME_ADAPTER_DYNAMIC_ENV ?? null,
  },
}));
`,
  );

  const previous = process.env.IOI_RUNTIME_ADAPTER_DYNAMIC_ENV;
  const adapter = createRuntimeAgentServiceCommandAdapter({
    command: process.execPath,
    args: [bridgeScript],
    bridgeId: "dynamic-env-test",
  });

  try {
    process.env.IOI_RUNTIME_ADAPTER_DYNAMIC_ENV = "set-after-adapter-construction";
    const result = await adapter.startThread({ threadId: "thread_dynamic_env" });
    assert.equal(result.bridge_id, "dynamic-env-test");
    assert.equal(result.operation, "start_thread");
    assert.equal(result.dynamic_env, "set-after-adapter-construction");
  } finally {
    if (previous === undefined) {
      delete process.env.IOI_RUNTIME_ADAPTER_DYNAMIC_ENV;
    } else {
      process.env.IOI_RUNTIME_ADAPTER_DYNAMIC_ENV = previous;
    }
  }
});
