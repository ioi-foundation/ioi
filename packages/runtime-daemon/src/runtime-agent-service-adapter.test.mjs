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

test("RuntimeAgentService command adapter projects streaming runtime event lines separately from final result", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-adapter-stream-"));
  const bridgeScript = path.join(tempDir, "bridge-stream-probe.mjs");
  fs.writeFileSync(
    bridgeScript,
    `
console.log(JSON.stringify({
  type: "runtime_event",
  event: {
    event_stream_id: "thread_stream:events",
    thread_id: "thread_stream",
    turn_id: "turn_stream",
    event_kind: "tool.completed",
    payload: { tool_name: "file__read" }
  }
}));
console.log(JSON.stringify({
  ok: true,
  result: {
    bridge_id: "stream-test",
    source: "runtime_service",
    turn_id: "turn_stream",
    events: []
  }
}));
`,
  );

  const adapter = createRuntimeAgentServiceCommandAdapter({
    command: process.execPath,
    args: [bridgeScript],
    bridgeId: "stream-test",
  });
  const events = [];
  const result = await adapter.submitTurn(
    { threadId: "thread_stream" },
    { onRuntimeEvent: (event) => events.push(event) },
  );

  assert.equal(result.bridge_id, "stream-test");
  assert.equal(result.turn_id, "turn_stream");
  assert.deepEqual(events.map((event) => event.event_kind), ["tool.completed"]);
  assert.equal(events[0].payload.tool_name, "file__read");
});

test("RuntimeAgentService command adapter ignores retired bridgeId result alias", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-adapter-bridge-alias-"));
  const bridgeScript = path.join(tempDir, "bridge-alias-probe.mjs");
  fs.writeFileSync(
    bridgeScript,
    `
console.log(JSON.stringify({
  ok: true,
  result: {
    bridgeId: "retired-bridge-result",
    source: "runtime_service",
    turn_id: "turn_alias"
  }
}));
`,
  );

  const adapter = createRuntimeAgentServiceCommandAdapter({
    command: process.execPath,
    args: [bridgeScript],
    bridgeId: "canonical-adapter-bridge",
  });
  const result = await adapter.submitTurn({ thread_id: "thread_alias" });

  assert.equal(result.bridge_id, "canonical-adapter-bridge");
  assert.equal(Object.hasOwn(result, "bridgeId"), false);
  assert.equal(result.turn_id, "turn_alias");
});

test("RuntimeAgentService command adapter treats runtime event streaming as timeout activity", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-adapter-activity-"));
  const bridgeScript = path.join(tempDir, "bridge-activity-probe.mjs");
  fs.writeFileSync(
    bridgeScript,
    `
import { setTimeout as delay } from "node:timers/promises";

await delay(70);
console.log(JSON.stringify({
  type: "runtime_event",
  event: {
    event_stream_id: "thread_activity:events",
    thread_id: "thread_activity",
    turn_id: "turn_activity",
    event_kind: "answer.delta",
    payload: { delta: "still streaming" }
  }
}));
await delay(70);
console.log(JSON.stringify({
  ok: true,
  result: {
    bridge_id: "activity-timeout-test",
    source: "runtime_service",
    turn_id: "turn_activity",
    events: [{ event_kind: "turn.started" }],
    status: "completed"
  }
}));
`,
  );

  const adapter = createRuntimeAgentServiceCommandAdapter({
    command: process.execPath,
    args: [bridgeScript],
    bridgeId: "activity-timeout-test",
    timeoutMs: 100,
  });
  const events = [];
  const result = await adapter.submitTurn(
    { threadId: "thread_activity" },
    { onRuntimeEvent: (event) => events.push(event) },
  );

  assert.equal(result.bridge_id, "activity-timeout-test");
  assert.equal(result.turn_id, "turn_activity");
  assert.deepEqual(events.map((event) => event.event_kind), ["answer.delta"]);
});

test("RuntimeAgentService command adapter supports managed session inspect and control operations", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-adapter-managed-session-"));
  const bridgeScript = path.join(tempDir, "bridge-managed-session-probe.mjs");
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
    input: request.input,
  },
}));
`,
  );

  const adapter = createRuntimeAgentServiceCommandAdapter({
    command: process.execPath,
    args: [bridgeScript],
    bridgeId: "managed-session-test",
  });

  const inspection = await adapter.inspectThread({
    threadId: "thread_managed",
    sessionId: "session_managed",
  });
  assert.equal(inspection.operation, "inspect_thread");
  assert.equal(inspection.input.threadId, "thread_managed");

  const control = await adapter.controlThread({
    threadId: "thread_managed",
    sessionId: "session_managed",
    managedSessionId: "sandbox_browser:one",
    action: "take_over_session",
  });
  assert.equal(control.operation, "control_thread");
  assert.equal(control.input.managedSessionId, "sandbox_browser:one");
  assert.equal(control.input.action, "take_over_session");
});
