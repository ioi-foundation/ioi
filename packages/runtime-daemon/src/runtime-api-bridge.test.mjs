import assert from "node:assert/strict";
import test from "node:test";

import {
  RuntimeApiBridgeUnavailableError,
  createRuntimeApiBridge,
  isFixtureRuntimeProfile,
  isRuntimeServiceProfile,
  normalizeRuntimeProfile,
  runtimeProfileForRequest,
} from "./runtime-api-bridge.mjs";

test("runtime profile request normalization accepts canonical profile fields", () => {
  assert.equal(runtimeProfileForRequest({ runtime_profile: "runtime" }), "runtime_service");
  assert.equal(runtimeProfileForRequest({}, { runtime_profile: "live" }), "runtime_service");
  assert.equal(runtimeProfileForRequest({ runtime_profile: "fixture" }), "fixture");
  assert.equal(normalizeRuntimeProfile("agentgres_fixture"), "fixture");
  assert.equal(isRuntimeServiceProfile("production"), true);
  assert.equal(isFixtureRuntimeProfile("local_daemon_agentgres_projection"), true);
});

test("runtime profile request normalization ignores retired camelCase aliases", () => {
  assert.equal(runtimeProfileForRequest({ runtimeProfile: "runtime" }), "fixture");
  assert.equal(runtimeProfileForRequest({}, { runtimeProfile: "runtime" }), "fixture");
  assert.equal(
    runtimeProfileForRequest(
      { runtimeProfile: "runtime" },
      { runtime_profile: "fixture" },
    ),
    "fixture",
  );
});

test("RuntimeApiBridge no longer auto-configures command transport from env", async () => {
  const previousCommand = process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND;
  const previousLegacyCommand = process.env.IOI_RUNTIME_BRIDGE_COMMAND;

  try {
    process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = "ioi-runtime-bridge";
    process.env.IOI_RUNTIME_BRIDGE_COMMAND = "legacy-ioi-runtime-bridge";

    const bridge = createRuntimeApiBridge();
    assert.equal(bridge.canStartThread, false);
    assert.equal(bridge.canSubmitTurn, false);
    assert.equal(bridge.canInspectThread, false);
    assert.equal(bridge.canControlThread, false);
    await assert.rejects(
      () => bridge.startThread({ thread_id: "thread_no_env_transport" }),
      (error) =>
        error instanceof RuntimeApiBridgeUnavailableError &&
        error.details?.operation === "start_thread",
    );
  } finally {
    if (previousCommand === undefined) {
      delete process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND;
    } else {
      process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = previousCommand;
    }
    if (previousLegacyCommand === undefined) {
      delete process.env.IOI_RUNTIME_BRIDGE_COMMAND;
    } else {
      process.env.IOI_RUNTIME_BRIDGE_COMMAND = previousLegacyCommand;
    }
  }
});
