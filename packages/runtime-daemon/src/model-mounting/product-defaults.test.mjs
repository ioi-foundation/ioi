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
