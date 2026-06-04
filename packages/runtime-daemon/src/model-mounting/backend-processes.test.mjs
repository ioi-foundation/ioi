import assert from "node:assert/strict";
import test from "node:test";

import {
  backend,
  backendProcessArgs,
  backendProcessSnapshot,
  backendProcessSpawnArgs,
  backendSupportsSupervision,
} from "./backend-processes.mjs";

function fakeState() {
  return {
    backendRegistry() {
      return [
        { id: "backend.llama", kind: "llama_cpp", baseUrl: "http://127.0.0.1:8091/v1" },
        { id: "backend.vllm", kind: "vllm", baseUrl: "http://0.0.0.0:8092/v1" },
        { id: "backend.ollama", kind: "ollama", baseUrl: "http://127.0.0.1:11434" },
        { id: "backend.native", kind: "native_local" },
        { id: "backend.custom", kind: "custom_backend" },
      ];
    },
    runtimeDefaultLoadOptions(backendId) {
      return {
        "backend.llama": { contextLength: 4096, parallel: 2, gpu: "auto", identifier: "llama profile" },
        "backend.native": { contextLength: 2048, parallel: 1, gpu: "off" },
        "backend.vllm": { contextLength: 8192, parallel: 4 },
      }[backendId] ?? {};
    },
  };
}

const deps = {
  backendBindAddress(baseUrl) {
    const url = new URL(baseUrl);
    return { host: url.hostname, port: url.port };
  },
  llamaCppGpuLayersArg(value) {
    return value === "auto" ? "-1" : String(value);
  },
  notFound(message, details) {
    const error = new Error(message);
    error.status = 404;
    error.details = details;
    return error;
  },
  stableHash(value) {
    return `hash_${String(value).replace(/[^a-z0-9]+/gi, "_")}`;
  },
};

test("backend lookup returns registry records and maps missing ids through notFound", () => {
  const state = fakeState();

  assert.equal(backend(state, "backend.llama", deps).kind, "llama_cpp");
  assert.throws(
    () => backend(state, "backend.missing", deps),
    (error) => error.status === 404 && error.details.backendId === "backend.missing",
  );
});

test("backend process snapshot defaults not-started state and normalizes optional fields", () => {
  assert.deepEqual(backendProcessSnapshot(null), {
    status: "not_started",
    processStatus: "not_started",
    evidenceRefs: ["supervisor_process_not_started"],
  });

  const snapshot = backendProcessSnapshot({
    id: "process_a",
    backendId: "backend.llama",
    backendKind: "llama_cpp",
    status: "started",
    spawned: true,
    stale: true,
    evidenceRefs: ["started"],
  });

  assert.equal(snapshot.processStatus, "started");
  assert.equal(snapshot.pidTracked, "process_ref_hash");
  assert.equal(snapshot.spawned, true);
  assert.equal(snapshot.stale, true);
  assert.deepEqual(snapshot.argsRedacted, []);
  assert.deepEqual(snapshot.evidenceRefs, ["started"]);
});

test("backend process public args redact artifact paths and include default load options", () => {
  const state = fakeState();

  const args = backendProcessArgs(
    state,
    { id: "backend.llama", kind: "llama_cpp" },
    { endpoint: { artifactPath: "/models/private/model.gguf", modelId: "model-a" } },
    deps,
  );

  assert.deepEqual(args, [
    "llama-server",
    "--model",
    "artifact:hash__models_pri",
    "--ctx-size",
    "4096",
    "--parallel",
    "2",
    "--gpu-layers",
    "-1",
    "--identifier",
    "hash_llama_p",
  ]);
});

test("backend process public args support native-local and vLLM provider vocabularies", () => {
  const state = fakeState();

  assert.deepEqual(backendProcessArgs(state, { id: "backend.native", kind: "native_local" }, {}, deps), [
    "ioi-native-local-fixture",
    "--model",
    "runtime-engine-profile",
    "--context",
    "2048",
    "--parallel",
    "1",
    "--gpu",
    "off",
  ]);

  assert.deepEqual(
    backendProcessArgs(
      state,
      { id: "backend.vllm", kind: "vllm" },
      { loadOptions: { dtype: "float16", gpuMemoryUtilization: 0.7 } },
      deps,
    ),
    [
      "vllm",
      "serve",
      "runtime-engine-profile",
      "--max-model-len",
      "8192",
      "--tensor-parallel-size",
      "4",
      "--dtype",
      "float16",
      "--gpu-memory-utilization",
      "0.7",
    ],
  );
});

test("backend process spawn args keep supervised raw paths and bind addresses", () => {
  const state = fakeState();

  assert.deepEqual(backendProcessSpawnArgs(state, { id: "backend.ollama", kind: "ollama" }, {}, deps), ["serve"]);
  assert.deepEqual(
    backendProcessSpawnArgs(
      state,
      { id: "backend.vllm", kind: "vllm", baseUrl: "http://0.0.0.0:8092/v1" },
      { loadOptions: { modelPath: "/models/raw/vllm", maxModelLen: 16384, tensorParallelSize: 2, dtype: "bfloat16" } },
      deps,
    ),
    [
      "serve",
      "/models/raw/vllm",
      "--host",
      "0.0.0.0",
      "--port",
      "8092",
      "--max-model-len",
      "16384",
      "--tensor-parallel-size",
      "2",
      "--dtype",
      "bfloat16",
    ],
  );
  assert.deepEqual(
    backendProcessSpawnArgs(
      state,
      { id: "backend.llama", kind: "llama_cpp", baseUrl: "http://127.0.0.1:8091/v1" },
      { endpoint: { artifactPath: "/models/raw/llama.gguf" }, loadOptions: { embeddings: true } },
      deps,
    ),
    [
      "--model",
      "/models/raw/llama.gguf",
      "--ctx-size",
      "4096",
      "--parallel",
      "2",
      "--n-gpu-layers",
      "-1",
      "--embedding",
      "--host",
      "127.0.0.1",
      "--port",
      "8091",
    ],
  );
});

test("backend process spawn args fall back to public args for unsupported backend kinds", () => {
  const state = fakeState();

  assert.deepEqual(
    backendProcessSpawnArgs(state, { id: "backend.custom", kind: "custom_backend" }, {}, deps),
    ["--model", "runtime-engine-profile"],
  );
});

test("backend supervision predicate is limited to runtime-manageable backends", () => {
  assert.equal(backendSupportsSupervision({ kind: "llama_cpp" }), true);
  assert.equal(backendSupportsSupervision({ kind: "ollama" }), true);
  assert.equal(backendSupportsSupervision({ kind: "vllm" }), true);
  assert.equal(backendSupportsSupervision({ kind: "native_local" }), true);
  assert.equal(backendSupportsSupervision({ kind: "hosted_openai" }), false);
});
