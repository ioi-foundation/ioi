import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  RuntimeAgentServiceCommandAdapterError,
  createRuntimeAgentServiceCommandAdapter,
  createRuntimeAgentServiceCommandAdapterFromEnv,
} from "./runtime-agent-service-adapter.mjs";

function writeExecutableBridgeScript(file, source) {
  fs.writeFileSync(file, `#!/usr/bin/env node\n${source}`);
  fs.chmodSync(file, 0o755);
}

test("RuntimeAgentService command adapter bridge calls inherit current process env", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-adapter-env-"));
  const bridgeScript = path.join(tempDir, "bridge-env-probe.mjs");
  writeExecutableBridgeScript(
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
    command: bridgeScript,
    bridgeId: "dynamic-env-test",
  });

  try {
    process.env.IOI_RUNTIME_ADAPTER_DYNAMIC_ENV = "set-after-adapter-construction";
    const result = await adapter.startThread({ thread_id: "thread_dynamic_env" });
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
  writeExecutableBridgeScript(
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
    command: bridgeScript,
    bridgeId: "stream-test",
  });
  const events = [];
  const result = await adapter.submitTurn(
    { thread_id: "thread_stream" },
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
  writeExecutableBridgeScript(
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
    command: bridgeScript,
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
  writeExecutableBridgeScript(
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
    command: bridgeScript,
    bridgeId: "activity-timeout-test",
    timeoutMs: 100,
  });
  const events = [];
  const result = await adapter.submitTurn(
    { thread_id: "thread_activity" },
    { onRuntimeEvent: (event) => events.push(event) },
  );

  assert.equal(result.bridge_id, "activity-timeout-test");
  assert.equal(result.turn_id, "turn_activity");
  assert.deepEqual(events.map((event) => event.event_kind), ["answer.delta"]);
});

test("RuntimeAgentService command adapter supports managed session inspect and control operations", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-adapter-managed-session-"));
  const bridgeScript = path.join(tempDir, "bridge-managed-session-probe.mjs");
  writeExecutableBridgeScript(
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
    command: bridgeScript,
    bridgeId: "managed-session-test",
  });

  const inspection = await adapter.inspectThread({
    thread_id: "thread_managed",
    session_id: "session_managed",
  });
  assert.equal(inspection.operation, "inspect_thread");
  assert.equal(inspection.input.thread_id, "thread_managed");

  const control = await adapter.controlThread({
    thread_id: "thread_managed",
    session_id: "session_managed",
    managed_session_id: "sandbox_browser:one",
    action: "take_over_session",
  });
  assert.equal(control.operation, "control_thread");
  assert.equal(control.input.managed_session_id, "sandbox_browser:one");
  assert.equal(control.input.action, "take_over_session");
});

test("RuntimeAgentService command adapter input aliases fail closed before transport", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-adapter-input-alias-"));
  const bridgeScript = path.join(tempDir, "bridge-input-alias-probe.mjs");
  writeExecutableBridgeScript(
    bridgeScript,
    `
throw new Error("bridge command should not be spawned for retired input aliases");
`,
  );

  const adapter = createRuntimeAgentServiceCommandAdapter({
    command: bridgeScript,
    bridgeId: "input-alias-test",
  });

  await assert.rejects(
    () => adapter.startThread({ threadId: "thread_retired" }),
    (error) =>
      error instanceof RuntimeAgentServiceCommandAdapterError &&
      error.code === "runtime_agent_service_bridge_input_aliases_retired" &&
      error.details?.retired_aliases?.includes("threadId"),
  );
  await assert.rejects(
    () => adapter.submitTurn({ thread_id: "thread_ok", sessionId: "session_retired" }),
    (error) =>
      error instanceof RuntimeAgentServiceCommandAdapterError &&
      error.code === "runtime_agent_service_bridge_input_aliases_retired" &&
      error.details?.retired_aliases?.includes("sessionId"),
  );
  await assert.rejects(
    () => adapter.inspectThread({ session_id: "session_ok", managedSessionsOnly: true }),
    (error) =>
      error instanceof RuntimeAgentServiceCommandAdapterError &&
      error.code === "runtime_agent_service_bridge_input_aliases_retired" &&
      error.details?.retired_aliases?.includes("managedSessionsOnly"),
  );
  await assert.rejects(
    () => adapter.controlThread({ session_id: "session_ok", action: "take_over_session", managedSessionId: "managed_retired" }),
    (error) =>
      error instanceof RuntimeAgentServiceCommandAdapterError &&
      error.code === "runtime_agent_service_bridge_input_aliases_retired" &&
      error.details?.retired_aliases?.includes("managedSessionId"),
  );
});

test("RuntimeAgentService command adapter bridge args env fails closed", () => {
  assert.throws(
    () =>
      createRuntimeAgentServiceCommandAdapterFromEnv({
        IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND: "ioi-runtime-bridge",
        IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS: "--json",
      }),
    (error) =>
      error instanceof RuntimeAgentServiceCommandAdapterError &&
      error.code === "runtime_agent_service_bridge_args_retired",
  );

  assert.throws(
    () =>
      createRuntimeAgentServiceCommandAdapterFromEnv({
        IOI_RUNTIME_BRIDGE_COMMAND: "ioi-runtime-bridge",
        IOI_RUNTIME_BRIDGE_ARGS: '["--json"]',
      }),
    (error) =>
      error instanceof RuntimeAgentServiceCommandAdapterError &&
      error.code === "runtime_agent_service_bridge_args_retired",
  );
});

test("RuntimeAgentService command adapter bridge args constructor option fails closed", () => {
  assert.throws(
    () =>
      createRuntimeAgentServiceCommandAdapter({
        command: "ioi-runtime-bridge",
        args: ["--json"],
      }),
    (error) =>
      error instanceof RuntimeAgentServiceCommandAdapterError &&
      error.code === "runtime_agent_service_bridge_args_retired",
  );
});
