import assert from "node:assert/strict";
import test from "node:test";

import {
  FixtureModelProviderDriver,
  NativeLocalModelProviderDriver,
} from "./provider-local-drivers.mjs";

function fakeNativeState() {
  const logs = [];
  const processRecord = {
    id: "backend_process_native",
    backendId: "backend.autopilot.native-local.fixture",
    pidHash: "pid-hash",
    argsHash: "args-hash",
    evidenceRefs: ["fake_process"],
  };
  return {
    logs,
    getModel(modelId) {
      return {
        id: "artifact.native",
        modelId,
        sizeBytes: 42,
        capabilities: ["chat", "responses", "embeddings"],
      };
    },
    ensureBackendProcess(backendId) {
      assert.equal(backendId, "backend.autopilot.native-local.fixture");
      return processRecord;
    },
    backendProcessForBackend(backendId) {
      assert.equal(backendId, "backend.autopilot.native-local.fixture");
      return processRecord;
    },
    backendProcessSnapshot(record) {
      return record ? { id: record.id, evidenceRefs: record.evidenceRefs } : null;
    },
    loadedInstanceForEndpoint() {
      return { loadOptions: { idleTtlSeconds: 900 } };
    },
    writeBackendLog(endpointId, event) {
      logs.push({ endpointId, ...event });
    },
  };
}

test("local provider drivers fail closed for retired direct non-stream invoke", async () => {
  const fixture = new FixtureModelProviderDriver();
  await assert.rejects(
    () =>
      fixture.invoke({
        kind: "chat.completions",
        input: { messages: [{ role: "user", content: "hello" }] },
        endpoint: {
          modelId: "local:auto",
          apiFormat: "ioi_fixture",
        },
      }),
    (error) => error.code === "model_mount_local_provider_direct_invoke_retired",
  );

  const state = fakeNativeState();
  const native = new NativeLocalModelProviderDriver();
  await assert.rejects(
    () =>
      native.invoke({
        kind: "responses",
        input: { input: [{ role: "user", content: "hello" }] },
        endpoint: {
          id: "endpoint.native",
          modelId: "autopilot:native-fixture",
        },
        state,
      }),
    (error) => error.code === "model_mount_local_provider_direct_invoke_retired",
  );
  assert.equal(state.logs.length, 0);
});

test("native-local provider driver keeps load control and retires direct stream production", async () => {
  const state = fakeNativeState();
  const driver = new NativeLocalModelProviderDriver();
  const endpoint = {
    id: "endpoint.native",
    modelId: "autopilot:native-fixture",
    loadPolicy: { mode: "on_demand" },
  };

  const load = await driver.load({ state, endpoint, body: { idle_ttl_seconds: 120 } });
  assert.equal(load.status, "loaded");
  assert.equal(load.backend, "autopilot.native_local.fixture");
  assert.ok(load.evidenceRefs.includes("deterministic_native_local_fixture"));
  assert.equal(state.logs.at(-1).event, "load");

  await assert.rejects(
    () =>
      driver.streamInvoke({
        kind: "chat.completions",
        input: { messages: [{ role: "user", content: "summarize repo state" }] },
        endpoint,
        state,
      }),
    (error) => error.code === "model_mount_local_provider_direct_stream_retired",
  );
  assert.equal(state.logs.at(-1).event, "load");
});
