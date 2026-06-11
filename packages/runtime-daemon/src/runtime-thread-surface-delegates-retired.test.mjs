import assert from "node:assert/strict";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

test("daemon store thread turn and control pass-through delegates are retired", () => {
  const prototype = AgentgresRuntimeStateStore.prototype;
  for (const method of [
    "resumeThread",
    "createTurn",
    "interruptTurn",
    "steerTurn",
    "updateThreadRuntimeControls",
    "appendThreadRuntimeControlEvent",
    "inspectManagedSessionsForThread",
    "inspectWorkspaceChangeReviewsForThread",
    "controlWorkspaceChangeForThread",
    "controlManagedSessionForThread",
    "forkThread",
    "cancelRun",
    "applyThreadMcpServerMutation",
    "mcpStatusWithLiveDiscovery",
    "appendThreadMcpControlEvent",
    "mcpServersForContext",
  ]) {
    assert.equal(Object.hasOwn(prototype, method), false, `${method} must not be a store delegate`);
    assert.equal(typeof prototype[method], "undefined", `${method} must be absent from the store`);
  }
});
