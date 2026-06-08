import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function withModelState(fn) {
  const state = new ModelMountingState({
    stateDir: mkdtempSync(join(tmpdir(), "ioi-model-state-")),
    cwd: process.cwd(),
    homeDir: process.env.HOME,
  });
  try {
    return fn(state);
  } finally {
    state.close();
  }
}

test("product model defaults do not seed fixture or local:auto models", () => {
  withModelState((state) => {
    const allModelIds = state.listArtifacts().map((artifact) => artifact.modelId);
    const productModelIds = state.listProductArtifacts().map((artifact) => artifact.modelId);
    const endpointModelIds = state.listEndpoints().map((endpoint) => endpoint.modelId);
    const runtimeModelIds = state.runtimeModelCatalogList().map((model) => model.id);
    const openAiModelIds = state.openAiModelList().data.map((model) => model.id);

    for (const ids of [allModelIds, productModelIds, endpointModelIds, runtimeModelIds, openAiModelIds]) {
      assert.equal(ids.includes("local:auto"), false);
      assert.equal(ids.some((id) => String(id || "").includes("fixture")), false);
      assert.equal(ids.some((id) => String(id || "").includes("autopilot:native-fixture")), false);
    }
  });
});

test("backend process planning is delegated to Rust model_mount", () => {
  const calls = [];
  const state = new ModelMountingState({
    stateDir: mkdtempSync(join(tmpdir(), "ioi-model-state-")),
    cwd: process.cwd(),
    homeDir: process.env.HOME,
    modelMountAdmissionRunner: {
      planBackendProcess(request) {
        calls.push(request);
        return {
          public_args: ["llama-server", "--model", "artifact:rust-plan"],
          spawn_args: ["--model", "/models/private/model.gguf"],
          supports_supervision: true,
          spawn_status: "spawn_ready",
        };
      },
    },
  });

  try {
    const backend = {
      id: "backend.llama",
      kind: "llama_cpp",
      baseUrl: "http://127.0.0.1:8091/v1",
      binaryPath: "/bin/llama-server",
    };
    const options = {
      endpoint: { modelId: "model.local", artifactPath: "/models/private/model.gguf" },
      loadOptions: {
        context_length: 4096,
        contextLength: 9999,
        max_model_len: 8192,
        maxModelLen: 7777,
        parallel: 2,
        tensor_parallel_size: 1,
        tensorParallelSize: 8,
        gpu: "auto",
        gpu_memory_utilization: 0.7,
        gpuMemoryUtilization: 0.99,
        identifier: "llama profile",
        model_path: "/models/canonical.gguf",
        modelPath: "/models/retired.gguf",
        embeddings: true,
        embedding: false,
      },
    };

    assert.deepEqual(state.backendProcessArgs(backend, options), ["llama-server", "--model", "artifact:rust-plan"]);
    assert.deepEqual(state.backendProcessSpawnArgs(backend, options), ["--model", "/models/private/model.gguf"]);
    assert.equal(state.backendSupportsSupervision(backend), true);
    assert.equal(calls[0].schema_version, "ioi.model_mount.backend_process_plan.v1");
    assert.equal(calls[0].backend_ref, "backend.llama");
    assert.equal(calls[0].backend_kind, "llama_cpp");
    assert.equal(calls[0].artifact_path, "/models/private/model.gguf");
    assert.equal(calls[0].binary_configured, true);
    assert.equal(calls[0].load_options.context_length, 4096);
    assert.equal(calls[0].load_options.max_model_len, 8192);
    assert.equal(calls[0].load_options.tensor_parallel_size, 1);
    assert.equal(calls[0].load_options.gpu_memory_utilization, 0.7);
    assert.equal(calls[0].load_options.model_path, "/models/canonical.gguf");
    assert.equal(calls[0].load_options.embeddings, true);
    assert.equal(Object.hasOwn(calls[0], "backendRef"), false);
    assert.equal(Object.hasOwn(calls[0].load_options, "contextLength"), false);
    assert.equal(Object.hasOwn(calls[0].load_options, "maxModelLen"), false);
    assert.equal(Object.hasOwn(calls[0].load_options, "tensorParallelSize"), false);
    assert.equal(Object.hasOwn(calls[0].load_options, "gpuMemoryUtilization"), false);
    assert.equal(Object.hasOwn(calls[0].load_options, "modelPath"), false);
    assert.equal(Object.hasOwn(calls[0].load_options, "embedding"), false);

    state.backendProcessArgs({ id: "backend.alias-poison", kind: "llama_cpp" }, {
      loadOptions: {
        contextLength: 1234,
        maxModelLen: 2345,
        tensorParallelSize: 3,
        gpuMemoryUtilization: 0.42,
        modelPath: "/models/alias-only.gguf",
        embedding: true,
      },
    });
    const aliasOnlyCall = calls.at(-1);
    assert.equal(aliasOnlyCall.load_options.context_length, null);
    assert.equal(aliasOnlyCall.load_options.max_model_len, null);
    assert.equal(aliasOnlyCall.load_options.tensor_parallel_size, null);
    assert.equal(aliasOnlyCall.load_options.gpu_memory_utilization, null);
    assert.equal(aliasOnlyCall.load_options.model_path, null);
    assert.equal(aliasOnlyCall.load_options.embeddings, false);
  } finally {
    state.close();
  }
});

test("accepted receipt head planning is delegated to Rust model_mount", () => {
  const calls = [];
  const state = new ModelMountingState({
    stateDir: mkdtempSync(join(tmpdir(), "ioi-model-state-")),
    cwd: process.cwd(),
    homeDir: process.env.HOME,
    modelMountAdmissionRunner: {
      planAcceptedReceiptHead(request) {
        calls.push(request);
        return {
          sequence: request.sequence,
          head_ref: `agentgres://model-mounting/accepted-receipts/head/${request.sequence}`,
          state_root: `sha256:rust-head-${request.sequence}`,
          projection_watermark: `model-mounting-accepted-receipts:${request.sequence}`,
          head_hash: `sha256:head-${request.sequence}`,
          evidence_refs: ["rust_model_mount_accepted_receipt_head"],
        };
      },
    },
  });

  try {
    const head = state.agentgresModelMountingHead();

    assert.equal(calls.length, 1);
    assert.equal(calls[0].schema_version, "ioi.model_mount.accepted_receipt_head.v1");
    assert.equal(calls[0].sequence, 0);
    assert.equal(head.sequence, 0);
    assert.equal(head.head_ref, "agentgres://model-mounting/accepted-receipts/head/0");
    assert.equal(head.state_root, "sha256:rust-head-0");
    assert.equal(head.projection_watermark, "model-mounting-accepted-receipts:0");
    assert.equal(head.head_hash, "sha256:head-0");
  } finally {
    state.close();
  }
});
