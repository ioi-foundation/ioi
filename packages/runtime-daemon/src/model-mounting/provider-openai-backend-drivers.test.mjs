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
        loadOptions: details.loadOptions,
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
  };
}

test("vLLM backend driver fails before JS process supervision without provider projection shims", async () => {
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

  assert.equal(Object.hasOwn(driver, "state"), false);
  assert.equal(Object.hasOwn(Object.getPrototypeOf(driver), "providerWithBackendBaseUrl"), false);

  await assert.rejects(
    () =>
      driver.load({
        state,
        provider,
        endpoint,
        body: {
          load_options: { context_length: 4096, model_path: "/models/vllm" },
          loadOptions: { context_length: 9999 },
          contextLength: 8888,
          modelPath: "/models/retired",
        },
      }),
    (error) =>
      error.code === "model_mount_backend_process_supervisor_retired" &&
      error.details.operation_kind === "model_mount.provider_lifecycle.vllm_load" &&
      error.details.provider_id === "provider.vllm",
  );
  assert.deepEqual(state.processes, []);

  await assert.rejects(
    () => driver.listLoaded({ state, provider }),
    (error) =>
      error.code === "model_mount_provider_http_transport_retired" &&
      error.details.operation_kind === "model_mount.provider_inventory.vllm_loaded",
  );

  await assert.rejects(
    () => driver.unload({ state, provider, endpoint }),
    (error) =>
      error.code === "model_mount_backend_process_supervisor_retired" &&
      error.details.operation_kind === "model_mount.provider_lifecycle.vllm_unload",
  );
  assert.deepEqual(state.processes, []);
});

test("vLLM backend driver fails closed for retired JS invocation before process staging", async () => {
  const state = fakeState({
    "backend.vllm": {
      id: "backend.vllm",
      binaryPath: "/usr/bin/vllm",
      baseUrl: "http://127.0.0.1:8000/v1",
    },
  });
  const provider = { id: "provider.vllm", kind: "vllm", status: "blocked" };
  const endpoint = { id: "endpoint.vllm", modelId: "repo/model", backendId: "backend.vllm" };
  const driver = new VllmModelProviderDriver({ state });

  await assert.rejects(
    () => driver.invoke({ state, provider, endpoint, body: { input: "hello" }, input: "hello" }),
    (error) =>
      error.code === "model_mount_provider_js_invocation_retired" &&
      error.details.provider_kind === "vllm" &&
      error.details.stream === false,
  );
  await assert.rejects(
    () => driver.streamInvoke({ state, provider, endpoint, body: { input: "hello" } }),
    (error) =>
      error.code === "model_mount_provider_js_invocation_retired" &&
      error.details.provider_kind === "vllm" &&
      error.details.stream === true,
  );
  assert.equal(driver.supportsStream("responses"), false);
  assert.deepEqual(state.processes, []);
});

test("llama.cpp backend driver fails before JS process supervision", async () => {
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

  assert.equal(Object.hasOwn(driver, "state"), false);
  assert.equal(Object.hasOwn(Object.getPrototypeOf(driver), "providerWithBackendBaseUrl"), false);

  await assert.rejects(
    () =>
      driver.load({
        state,
        provider,
        endpoint,
        body: {
          ttl_seconds: 90,
          loadOptions: { context_length: 9999 },
          contextLength: 8888,
          modelPath: "/models/retired",
        },
      }),
    (error) =>
      error.code === "model_mount_backend_process_supervisor_retired" &&
      error.details.operation_kind === "model_mount.provider_lifecycle.llama_cpp_load" &&
      error.details.provider_id === "provider.llama-cpp",
  );
  await assert.rejects(
    () => driver.listLoaded({ state, provider }),
    (error) =>
      error.code === "model_mount_provider_http_transport_retired" &&
      error.details.operation_kind === "model_mount.provider_inventory.llama_cpp_loaded",
  );
  await assert.rejects(
    () => driver.unload({ state, provider, endpoint }),
    (error) =>
      error.code === "model_mount_backend_process_supervisor_retired" &&
      error.details.operation_kind === "model_mount.provider_lifecycle.llama_cpp_unload",
  );
  assert.deepEqual(state.processes, []);
});

test("llama.cpp backend driver fails closed for retired JS invocation before process staging", async () => {
  const state = fakeState({
    "backend.llama-cpp": {
      id: "backend.llama-cpp",
      binaryPath: "/usr/bin/llama-server",
      baseUrl: "http://127.0.0.1:8080/v1",
    },
  });
  const provider = { id: "provider.llama-cpp", kind: "llama_cpp", status: "configured" };
  const endpoint = { id: "endpoint.llama", modelId: "repo/gguf", backendId: "backend.llama-cpp" };
  const driver = new LlamaCppModelProviderDriver({ state });

  await assert.rejects(
    () => driver.invoke({ state, provider, endpoint, body: { input: "hello" }, input: "hello" }),
    (error) =>
      error.code === "model_mount_provider_js_invocation_retired" &&
      error.details.provider_kind === "llama_cpp" &&
      error.details.stream === false,
  );
  await assert.rejects(
    () => driver.streamInvoke({ state, provider, endpoint, body: { input: "hello" } }),
    (error) =>
      error.code === "model_mount_provider_js_invocation_retired" &&
      error.details.provider_kind === "llama_cpp" &&
      error.details.stream === true,
  );
  assert.equal(driver.supportsStream("responses"), false);
  assert.deepEqual(state.processes, []);
});
