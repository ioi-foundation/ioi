import test from "node:test";
import assert from "node:assert/strict";

import {
  chooseAvailableOllamaRuntime,
  chooseAvailableOllamaRuntimeForRenderer,
  chooseAvailableOllamaRuntimeForProofLane,
} from "./runtime";

test("chooseAvailableOllamaRuntime prefers qwen 7b production and qwen 14b acceptance", () => {
  const runtime = chooseAvailableOllamaRuntime([
    "qwen2.5:14b",
    "qwen2.5:7b",
    "llama3.2:3b",
  ]);

  assert.ok(runtime);
  assert.equal(runtime.productionModel, "qwen2.5:7b");
  assert.equal(runtime.acceptanceModel, "qwen2.5:14b");
});

test("chooseAvailableOllamaRuntime falls back to a distinct acceptance model when possible", () => {
  const runtime = chooseAvailableOllamaRuntime(["llama3.2:3b", "qwen2.5:7b"]);

  assert.ok(runtime);
  assert.equal(runtime.productionModel, "qwen2.5:7b");
  assert.equal(runtime.acceptanceModel, "llama3.2:3b");
});

test("chooseAvailableOllamaRuntimeForRenderer keeps the high-fidelity lane for markdown by default", () => {
  const runtime = chooseAvailableOllamaRuntimeForRenderer("markdown", [
    "qwen2.5:14b",
    "qwen2.5:7b",
    "llama3.2:3b",
  ]);

  assert.ok(runtime);
  assert.equal(runtime.productionModel, "qwen2.5:7b");
  assert.equal(runtime.acceptanceModel, "qwen2.5:14b");
});

test("chooseAvailableOllamaRuntimeForRenderer opts into the fast distinct lane for markdown", () => {
  process.env.STUDIO_ARTIFACT_CORPUS_USE_FAST_DOC_LANE = "1";
  try {
    const runtime = chooseAvailableOllamaRuntimeForRenderer("markdown", [
      "qwen2.5:14b",
      "qwen2.5:7b",
      "llama3.2:3b",
    ]);

    assert.ok(runtime);
    assert.equal(runtime.productionModel, "llama3.2:3b");
    assert.equal(runtime.acceptanceModel, "qwen2.5:7b");
  } finally {
    delete process.env.STUDIO_ARTIFACT_CORPUS_USE_FAST_DOC_LANE;
  }
});

test("chooseAvailableOllamaRuntimeForRenderer keeps the high-fidelity lane for html", () => {
  const runtime = chooseAvailableOllamaRuntimeForRenderer("html_iframe", [
    "qwen2.5:14b",
    "qwen2.5:7b",
    "llama3.2:3b",
  ]);

  assert.ok(runtime);
  assert.equal(runtime.productionModel, "qwen2.5:7b");
  assert.equal(runtime.acceptanceModel, "qwen2.5:14b");
});

test("chooseAvailableOllamaRuntime returns null when no models are available", () => {
  assert.equal(chooseAvailableOllamaRuntime([]), null);
});

test("chooseAvailableOllamaRuntimeForProofLane uses a faster truthful contract lane for html", () => {
  const runtime = chooseAvailableOllamaRuntimeForProofLane(
    "html_iframe",
    "contract",
    ["qwen2.5:14b", "qwen2.5:7b", "llama3.2:3b"],
  );

  assert.ok(runtime);
  assert.equal(runtime.productionModel, "qwen2.5:7b");
  assert.equal(runtime.acceptanceModel, "qwen2.5:7b");
});

test("chooseAvailableOllamaRuntimeForProofLane keeps the contract markdown lane on qwen 7b by default", () => {
  const runtime = chooseAvailableOllamaRuntimeForProofLane(
    "markdown",
    "contract",
    ["qwen2.5:14b", "qwen2.5:7b", "llama3.2:3b"],
  );

  assert.ok(runtime);
  assert.equal(runtime.productionModel, "qwen2.5:7b");
  assert.equal(runtime.acceptanceModel, "qwen2.5:7b");
});

test("chooseAvailableOllamaRuntimeForProofLane opts into a distinct fast contract markdown lane", () => {
  process.env.STUDIO_ARTIFACT_CORPUS_USE_FAST_DOC_LANE = "1";
  try {
    const runtime = chooseAvailableOllamaRuntimeForProofLane(
      "markdown",
      "contract",
      ["qwen2.5:14b", "qwen2.5:7b", "llama3.2:3b"],
    );

    assert.ok(runtime);
    assert.equal(runtime.productionModel, "llama3.2:3b");
    assert.equal(runtime.acceptanceModel, "qwen2.5:7b");
  } finally {
    delete process.env.STUDIO_ARTIFACT_CORPUS_USE_FAST_DOC_LANE;
  }
});

test("chooseAvailableOllamaRuntimeForProofLane keeps contract html on qwen 7b", () => {
  const runtime = chooseAvailableOllamaRuntimeForProofLane(
    "html_iframe",
    "contract",
    ["qwen2.5:14b", "qwen2.5:7b", "llama3.2:3b"],
  );

  assert.ok(runtime);
  assert.equal(runtime.productionModel, "qwen2.5:7b");
  assert.equal(runtime.acceptanceModel, "qwen2.5:7b");
});
