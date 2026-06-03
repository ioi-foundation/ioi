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

async function readStreamText(stream) {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let text = "";
  for (;;) {
    const next = await reader.read();
    if (next.done) break;
    text += decoder.decode(next.value, { stream: true });
  }
  text += decoder.decode();
  return text;
}

test("fixture provider driver invokes deterministic fixture output", async () => {
  const driver = new FixtureModelProviderDriver();
  const result = await driver.invoke({
    kind: "chat.completions",
    input: { messages: [{ role: "user", content: "hello" }] },
    endpoint: {
      modelId: "local:auto",
      apiFormat: "ioi_fixture",
    },
  });

  assert.equal(result.backend, "ioi_fixture");
  assert.equal(result.backendId, "backend.fixture");
  assert.equal(typeof result.outputText, "string");
  assert.ok(result.outputText.length > 0);
  assert.ok(result.tokenCount);
});

test("native-local provider driver records load and stream lifecycle", async () => {
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

  const stream = await driver.streamInvoke({
    kind: "chat.completions",
    input: { messages: [{ role: "user", content: "summarize repo state" }] },
    endpoint,
    state,
  });
  assert.equal(stream.streamFormat, "ioi_jsonl");
  assert.ok(stream.backendEvidenceRefs.includes("autopilot_native_local_provider_native_stream"));

  const text = await readStreamText(stream.stream);
  assert.match(text, /"delta":/);
  assert.match(text, /"done":true/);

  const previousDelay = process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS;
  try {
    process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS = "25";
    const abortable = await driver.streamInvoke({
      kind: "chat.completions",
      input: { messages: [{ role: "user", content: "abortable stream" }] },
      endpoint,
      state,
    });
    abortable.abort();
  } finally {
    if (previousDelay === undefined) {
      delete process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS;
    } else {
      process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS = previousDelay;
    }
  }
  assert.equal(state.logs.at(-1).event, "stream_abort");
});
