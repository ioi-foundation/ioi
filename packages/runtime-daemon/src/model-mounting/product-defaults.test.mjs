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
        contextLength: 4096,
        parallel: 2,
        gpu: "auto",
        identifier: "llama profile",
        embeddings: true,
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
    assert.equal(calls[0].load_options.embeddings, true);
    assert.equal(Object.hasOwn(calls[0], "backendRef"), false);
    assert.equal(Object.hasOwn(calls[0].load_options, "contextLength"), false);
  } finally {
    state.close();
  }
});
