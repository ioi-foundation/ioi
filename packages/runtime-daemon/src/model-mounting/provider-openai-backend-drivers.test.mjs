import assert from "node:assert/strict";
import test from "node:test";

import {
  LlamaCppModelProviderDriver,
  VllmModelProviderDriver,
} from "./provider-openai-backend-drivers.mjs";

function fakeState(backends = {}) {
  const processes = [];
  return {
    processes,
    backend(backendId) {
      return backends[backendId] ?? { id: backendId, binaryPath: null, baseUrl: null };
    },
    ensureBackendProcess(backendId, details = {}) {
      const record = {
        id: `process.${backendId}.${processes.length + 1}`,
        backendId,
        reason: details.reason,
        evidenceRefs: [`${backendId}.process`],
      };
      processes.push(record);
      return record;
    },
    stopBackendProcess(backend, details = {}) {
      return {
        id: `stopped.${backend.id}`,
        backendId: backend.id,
        reason: details.reason,
        evidenceRefs: [`${backend.id}.stopped`],
      };
    },
    backendProcessForBackend(backendId) {
      return processes.find((process) => process.backendId === backendId) ?? null;
    },
    backendProcessSnapshot(record) {
      return record ? { id: record.id, reason: record.reason, evidenceRefs: record.evidenceRefs } : null;
    },
    listInstances() {
      return [
        {
          id: "instance.loaded",
          providerId: "provider.vllm",
          modelId: "repo/model",
          status: "loaded",
        },
      ];
    },
  };
}

test("vLLM backend driver promotes configured backend and records supervised load/unload", async () => {
  const state = fakeState({
    "backend.vllm": {
      id: "backend.vllm",
      binaryPath: "/usr/bin/vllm",
      baseUrl: "http://127.0.0.1:8000/v1",
    },
  });
  const provider = { id: "provider.vllm", kind: "vllm", status: "blocked" };
  const endpoint = { id: "endpoint.vllm", modelId: "repo/model", loadPolicy: { mode: "on_demand" } };
  const driver = new VllmModelProviderDriver({ state });

  const effective = driver.providerWithBackendBaseUrl(provider);
  assert.equal(effective.status, "configured");
  assert.equal(effective.baseUrl, "http://127.0.0.1:8000/v1");

  const load = await driver.load({ state, provider, endpoint });
  assert.equal(load.status, "loaded");
  assert.equal(load.backend, "vllm");
  assert.equal(load.backendId, "backend.vllm");
  assert.ok(load.evidenceRefs.includes("vllm_process_supervisor"));
  assert.equal(state.processes.at(-1).reason, "vllm_model_load");

  const loaded = await driver.listLoaded({ state, provider });
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0].backend, "vllm");
  assert.equal(loaded[0].backendProcess.id, "process.backend.vllm.1");

  const unload = await driver.unload({ state, provider, endpoint });
  assert.equal(unload.status, "unloaded");
  assert.ok(unload.evidenceRefs.includes("clean_backend_stop"));
  assert.equal(unload.process.reason, "vllm_model_unload");
});

test("llama.cpp backend driver records supervised load/unload evidence", async () => {
  const state = fakeState({
    "backend.llama-cpp": {
      id: "backend.llama-cpp",
      binaryPath: "/usr/bin/llama-server",
      baseUrl: "http://127.0.0.1:8080/v1",
    },
  });
  const provider = { id: "provider.llama-cpp", kind: "llama_cpp", status: "configured" };
  const endpoint = { id: "endpoint.llama", modelId: "repo/gguf", loadPolicy: { mode: "on_demand" } };
  const driver = new LlamaCppModelProviderDriver({ state });

  const effective = driver.providerWithBackendBaseUrl(provider);
  assert.equal(effective.baseUrl, "http://127.0.0.1:8080/v1");

  const load = await driver.load({ state, provider, endpoint, body: { idle_ttl_seconds: 90 } });
  assert.equal(load.status, "loaded");
  assert.equal(load.backend, "llama_cpp");
  assert.ok(load.evidenceRefs.includes("llama_cpp_process_supervisor"));
  assert.equal(load.process.reason, "llama_cpp_model_load");

  const unload = await driver.unload({ state, provider, endpoint });
  assert.equal(unload.status, "unloaded");
  assert.equal(unload.backendId, "backend.llama-cpp");
  assert.ok(unload.evidenceRefs.includes("clean_backend_stop"));
  assert.equal(unload.process.reason, "llama_cpp_model_unload");
});
