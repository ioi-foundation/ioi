import test from "node:test";
import assert from "node:assert/strict";

import {
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
