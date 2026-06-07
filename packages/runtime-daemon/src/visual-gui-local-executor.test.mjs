import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  executeLocalVisualGuiAction,
  visualGuiLocalExecutorRequested,
} from "./visual-gui-local-executor.mjs";

const fixturePngBase64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAIAAAADCAIAAADZ5rWJAAAAFElEQVR42mP8z8AARLJgwi+Q5gIAWUMGAf2v7z8AAAAASUVORK5CYII=";

test("visual GUI local executor request detector accepts canonical fields", () => {
  const request = { actionKind: "click", approvalRef: "approval_visual_gui" };

  assert.equal(visualGuiLocalExecutorRequested({
    ...request,
    input: { local_gui_executor: true },
  }), true);
  assert.equal(visualGuiLocalExecutorRequested({
    ...request,
    input: { execute_local_gui: true },
  }), true);
  assert.equal(visualGuiLocalExecutorRequested({
    ...request,
    input: { visual_gui_local_executor: true },
  }), true);
  assert.equal(visualGuiLocalExecutorRequested({
    ...request,
    input: { visual_gui_executor: "fixture" },
  }), true);
  assert.equal(visualGuiLocalExecutorRequested({
    ...request,
    input: { executor_mode: "local_gui" },
  }), true);
  assert.equal(visualGuiLocalExecutorRequested({
    ...request,
    input: { local_gui_executor_provider: "fixture" },
  }), true);
});

test("visual GUI local executor request detector ignores retired request aliases", () => {
  const request = { actionKind: "click", approvalRef: "approval_visual_gui" };

  for (const input of [
    { localGuiExecutor: true },
    { executeLocalGui: true },
    { visualGuiLocalExecutor: true },
    { visualGuiExecutor: "fixture" },
    { executorMode: "local_gui" },
    { localGuiExecutorProvider: "fixture" },
  ]) {
    assert.equal(visualGuiLocalExecutorRequested({ ...request, input }), false);
  }
});

test("visual GUI local executor request detector stays fail-closed without approval", () => {
  assert.equal(visualGuiLocalExecutorRequested({
    actionKind: "click",
    input: { local_gui_executor: true },
  }), false);
});

test("visual GUI local executor grounds only canonical visual target fields", async () => {
  const canonical = await executeLocalVisualGuiAction({
    actionKind: "click",
    approvalRef: "approval_visual_gui",
    input: {
      screenshot_ref: "artifact_screenshot_one",
      target_ref: "target_one",
      visual_targets: [visualTarget("target_one")],
    },
    artifactResolver(ref) {
      assert.equal(ref, "artifact_screenshot_one");
      return null;
    },
  });
  assert.equal(canonical.status, "blocked");
  assert.equal(canonical.error_class, "verification");
  assert.equal(canonical.target_ref, "target_one");
  assert.deepEqual(canonical.evidence_refs, []);

  for (const input of [
    {
      targetRef: "target_legacy",
      visual_targets: [visualTarget("target_legacy")],
    },
    {
      target_ref: "target_legacy",
      visualTargets: [visualTarget("target_legacy")],
    },
    {
      target_ref: "target_legacy",
      visual_targets: [visualTarget("target_legacy", {
        target_ref: undefined,
        targetRef: "target_legacy",
      })],
    },
    {
      target_ref: "target_legacy",
      visual_targets: [visualTarget("target_legacy", {
        available_actions: ["type_text"],
        availableActions: ["click"],
      })],
    },
    {
      target_ref: "target_legacy",
      visual_targets: [visualTarget("target_legacy", { coordinateSpaceId: "screen" })],
    },
  ]) {
    const result = await executeLocalVisualGuiAction({
      actionKind: "click",
      approvalRef: "approval_visual_gui",
      input,
      artifactResolver() {
        assert.fail("retired visual target aliases must not reach artifact resolution");
      },
    });
    assert.equal(result.status, "blocked");
    assert.equal(result.error_class, "grounding");
  }
});

test("visual GUI local executor screenshot resolution ignores retired aliases", async () => {
  let resolvedRef = null;
  const canonical = await executeLocalVisualGuiAction({
    actionKind: "click",
    approvalRef: "approval_visual_gui",
    input: {
      screenshot_ref: "artifact_screenshot_one",
      target_ref: "target_one",
      visual_targets: [visualTarget("target_one")],
    },
    artifactResolver(ref) {
      resolvedRef = ref;
      return null;
    },
  });
  assert.equal(canonical.status, "blocked");
  assert.equal(canonical.error_class, "verification");
  assert.equal(resolvedRef, "artifact_screenshot_one");

  for (const input of [
    {
      screenshotRef: "artifact_legacy",
      target_ref: "target_one",
      visual_targets: [visualTarget("target_one")],
    },
    {
      computerUseObservationBundle: { screenshot_ref: "artifact_legacy" },
      target_ref: "target_one",
      visual_targets: [visualTarget("target_one")],
    },
  ]) {
    let resolverCalled = false;
    const result = await executeLocalVisualGuiAction({
      actionKind: "click",
      approvalRef: "approval_visual_gui",
      input,
      artifactResolver() {
        resolverCalled = true;
        return { content: "unexpected" };
      },
    });
    assert.equal(result.status, "blocked");
    assert.equal(result.error_class, "verification");
    assert.equal(resolverCalled, false);
    assert.deepEqual(result.evidence_refs, []);
  }
});

test("visual GUI local executor action payloads use canonical fields only", async () => {
  await withFixtureExecution(async (captureDir) => {
    for (const { actionKind, inputPatch, expectedAction } of [
      {
        actionKind: "type_text",
        inputPatch: { input_text: "ship it" },
        expectedAction: "type_text",
      },
      {
        actionKind: "key_press",
        inputPatch: { key_text: "Enter" },
        expectedAction: "key_press",
      },
      {
        actionKind: "scroll",
        inputPatch: { scroll_y: 240, scroll_x: 0 },
        expectedAction: "scroll",
      },
    ]) {
      const result = await executeLocalVisualGuiAction({
        actionKind,
        approvalRef: "approval_visual_gui",
        input: fixtureExecutionInput(actionKind, inputPatch),
        captureDir,
        artifactResolver: screenshotArtifactResolver,
      });
      assert.equal(result.status, "completed");
      assert.equal(result.execution_receipt.action, expectedAction);
      assert.deepEqual(result.execution_receipt.target_point, { x: 60, y: 40 });
      assert.equal(Object.hasOwn(result.execution_receipt, "targetPoint"), false);
    }
  });
});

test("visual GUI local executor completion uses canonical observation_ref only", async () => {
  await withFixtureExecution(async (captureDir) => {
    const canonical = await executeLocalVisualGuiAction({
      actionKind: "click",
      approvalRef: "approval_visual_gui",
      input: fixtureExecutionInput("click", {
        observation_ref: "observation_canonical",
      }),
      captureDir,
      artifactResolver: screenshotArtifactResolver,
    });
    assert.equal(canonical.status, "completed");
    assert.equal(canonical.observation_ref, "observation_canonical");

    const retiredAlias = await executeLocalVisualGuiAction({
      actionKind: "click",
      approvalRef: "approval_visual_gui",
      input: fixtureExecutionInput("click", {
        observationRef: "observation_retired",
      }),
      captureDir,
      artifactResolver: screenshotArtifactResolver,
    });
    assert.equal(retiredAlias.status, "completed");
    assert.equal(retiredAlias.observation_ref, null);
  });
});

test("visual GUI local executor action payloads ignore retired aliases", async () => {
  await withFixtureExecution(async (captureDir) => {
    for (const { actionKind, inputPatch } of [
      {
        actionKind: "type_text",
        inputPatch: { text: "legacy text" },
      },
      {
        actionKind: "type_text",
        inputPatch: { value: "legacy value" },
      },
      {
        actionKind: "type_text",
        inputPatch: { inputText: "legacy input" },
      },
      {
        actionKind: "key_press",
        inputPatch: { key: "Enter" },
      },
      {
        actionKind: "key_press",
        inputPatch: { keyText: "Enter" },
      },
      {
        actionKind: "scroll",
        inputPatch: { scrollY: 240 },
      },
      {
        actionKind: "scroll",
        inputPatch: { scrollX: 24 },
      },
      {
        actionKind: "scroll",
        inputPatch: { dy: 240, dx: 0 },
      },
    ]) {
      const result = await executeLocalVisualGuiAction({
        actionKind,
        approvalRef: "approval_visual_gui",
        input: fixtureExecutionInput(actionKind, inputPatch),
        captureDir,
        artifactResolver: screenshotArtifactResolver,
      });
      assert.equal(result.status, "blocked");
      assert.equal(result.error_class, "invalid_action_payload");
    }
  });
});

function visualTarget(targetRef, overrides = {}) {
  return {
    target_ref: targetRef,
    label: "Run button",
    role: "button",
    bounds: {
      coordinate_space_id: "screen",
      x: 10,
      y: 20,
      width: 100,
      height: 40,
      ...(overrides.coordinateSpaceId ? {
        coordinate_space_id: undefined,
        coordinateSpaceId: overrides.coordinateSpaceId,
      } : null),
    },
    available_actions: ["click"],
    ...overrides,
  };
}

function fixtureExecutionInput(actionKind, inputPatch = {}) {
  return {
    screenshot_ref: "artifact_screenshot_one",
    target_ref: "target_one",
    visual_targets: [visualTarget("target_one", { available_actions: [actionKind] })],
    local_gui_executor_provider: "fixture",
    capture_fixture_png_base64: fixturePngBase64,
    ...inputPatch,
  };
}

function screenshotArtifactResolver(ref) {
  assert.equal(ref, "artifact_screenshot_one");
  return { content: fixturePngBase64 };
}

async function withFixtureExecution(callback) {
  const previousCaptureFixture = process.env.IOI_RUNTIME_ENABLE_VISUAL_CAPTURE_FIXTURE;
  const previousExecutorFixture = process.env.IOI_RUNTIME_ENABLE_VISUAL_EXECUTOR_FIXTURE;
  const captureDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-visual-executor-test-"));
  process.env.IOI_RUNTIME_ENABLE_VISUAL_CAPTURE_FIXTURE = "1";
  process.env.IOI_RUNTIME_ENABLE_VISUAL_EXECUTOR_FIXTURE = "1";
  try {
    await callback(captureDir);
  } finally {
    restoreEnv("IOI_RUNTIME_ENABLE_VISUAL_CAPTURE_FIXTURE", previousCaptureFixture);
    restoreEnv("IOI_RUNTIME_ENABLE_VISUAL_EXECUTOR_FIXTURE", previousExecutorFixture);
    fs.rmSync(captureDir, { recursive: true, force: true });
  }
}

function restoreEnv(name, value) {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}
