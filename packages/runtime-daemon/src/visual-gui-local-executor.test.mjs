import test from "node:test";
import assert from "node:assert/strict";

import {
  executeLocalVisualGuiAction,
  visualGuiLocalExecutorRequested,
} from "./visual-gui-local-executor.mjs";

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
