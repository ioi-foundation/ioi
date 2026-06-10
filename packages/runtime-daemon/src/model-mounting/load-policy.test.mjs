import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalLoadOptionsInput,
  expiresAt,
  hasExplicitTtlOption,
  normalizeLoadOptions,
  normalizeLoadPolicy,
  normalizeRuntimeEngineDefaultLoadOptions,
} from "./load-policy.mjs";

test("load policy normalization preserves string idle eviction semantics", () => {
  assert.deepEqual(normalizeLoadPolicy("idle_evict"), {
    mode: "idle_evict",
    idleTtlSeconds: 900,
    autoEvict: true,
  });
  assert.deepEqual(normalizeLoadPolicy("always_loaded"), {
    mode: "always_loaded",
    idleTtlSeconds: 900,
    autoEvict: false,
  });
});

test("load policy normalization accepts snake and camel ttl aliases", () => {
  assert.deepEqual(normalizeLoadPolicy({
    mode: "on_demand",
    idle_ttl_seconds: "45",
    auto_evict: false,
    memoryPressureEvict: false,
  }), {
    mode: "on_demand",
    idleTtlSeconds: 45,
    autoEvict: false,
    memoryPressureEvict: false,
  });
});

test("load option normalization keeps canonical route fields stable", () => {
  assert.deepEqual(normalizeLoadOptions({
    estimate_only: "1",
    gpu_offload: "auto",
    context_length: "8192",
    parallelism: "2",
    ttl_seconds: "30",
    instance_identifier: "chat-a",
    model_path: "/models/qwen.gguf",
    dtype: "q4",
    tensor_parallel_size: "1",
    gpu_memory_utilization: "0.7",
    max_model_len: "4096",
  }), {
    estimateOnly: true,
    gpu: "auto",
    contextLength: 8192,
    parallel: 2,
    ttlSeconds: 30,
    identifier: "chat-a",
    modelPath: "/models/qwen.gguf",
    model: null,
    dtype: "q4",
    tensorParallelSize: 1,
    gpuMemoryUtilization: 0.7,
    maxModelLen: 4096,
    estimate_only: true,
    context_length: 8192,
    ttl_seconds: 30,
    model_path: "/models/qwen.gguf",
    tensor_parallel_size: 1,
    gpu_memory_utilization: 0.7,
    max_model_len: 4096,
  });
});

test("canonical load option input strips retired request aliases before provider normalization", () => {
  assert.deepEqual(canonicalLoadOptionsInput({
    loadOptions: {
      context_length: 9999,
      estimateOnly: true,
      gpuOffload: "retired",
    },
    estimateOnly: true,
    gpuOffload: "retired",
    contextLength: 8888,
    modelPath: "/retired/model.gguf",
    embedding: true,
    load_options: {
      context_length: 4096,
      model_path: "/models/qwen.gguf",
      embeddings: true,
    },
  }), {
    context_length: 4096,
    model_path: "/models/qwen.gguf",
    embeddings: true,
  });
  assert.deepEqual(canonicalLoadOptionsInput({
    contextLength: 8888,
    maxModelLen: 7777,
    tensorParallelSize: 8,
    gpuMemoryUtilization: 0.99,
    estimateOnly: true,
    gpuOffload: "retired",
    modelPath: "/retired/model.gguf",
    embedding: true,
  }), {});
});

test("load option normalization ignores retired load-option camelCase aliases", () => {
  assert.deepEqual(normalizeLoadOptions({
    estimateOnly: true,
    gpuOffload: "auto",
    contextLength: "8192",
    ttlSeconds: "30",
    idleTtlSeconds: "45",
    instanceIdentifier: "instance.retired",
    modelPath: "/models/retired.gguf",
    tensorParallelSize: "8",
    gpuMemoryUtilization: "0.99",
    maxModelLen: "7777",
  }), {
    estimateOnly: false,
    gpu: null,
    contextLength: null,
    parallel: null,
    ttlSeconds: null,
    identifier: null,
    modelPath: null,
    model: null,
    dtype: null,
    tensorParallelSize: null,
    gpuMemoryUtilization: null,
    maxModelLen: null,
    estimate_only: false,
    context_length: null,
    ttl_seconds: null,
    model_path: null,
    tensor_parallel_size: null,
    gpu_memory_utilization: null,
    max_model_len: null,
  });
});

test("runtime engine defaults include only explicit normalized values", () => {
  assert.deepEqual(normalizeRuntimeEngineDefaultLoadOptions({
    gpu: "auto",
    context_length: "4096",
    parallel: "",
    ttl: "120",
    identifier: "engine-default",
  }), {
    gpu: "auto",
    contextLength: 4096,
    context_length: 4096,
    ttlSeconds: 120,
    ttl_seconds: 120,
    identifier: "engine-default",
  });
});

test("ttl helpers detect explicit ttl and calculate evict time", () => {
  assert.equal(hasExplicitTtlOption({ ttl_seconds: 60 }), true);
  assert.equal(hasExplicitTtlOption({ idle_ttl_seconds: 60 }), true);
  assert.equal(hasExplicitTtlOption({ ttlSeconds: 60 }), false);
  assert.equal(hasExplicitTtlOption({ idleTtlSeconds: 60 }), false);
  assert.equal(hasExplicitTtlOption({ gpu: "auto" }), false);
  assert.equal(
    expiresAt("2026-06-03T00:00:00.000Z", { mode: "on_demand", autoEvict: true, idleTtlSeconds: 60 }),
    "2026-06-03T00:01:00.000Z",
  );
  assert.equal(
    expiresAt("2026-06-03T00:00:00.000Z", { mode: "always_loaded", autoEvict: false, idleTtlSeconds: 60 }),
    null,
  );
});
