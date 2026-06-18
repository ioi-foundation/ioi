import { createRequire } from "node:module";
import test from "node:test";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
const {
  buildWorkbenchCommandRouteReceipt,
  createWorkspaceBridge,
  isRuntimeActionRequestType,
} = require("./workspace-bridge.js");

test("workspace bridge receipts keep command route envelope stable", () => {
  const receipt = buildWorkbenchCommandRouteReceipt({
    commandId: "ioi.code.open",
    route: "ioi-runtime-action",
    context: { source: "test" },
  });

  assert.equal(receipt.schemaVersion, "ioi.code-editor-adapter.v1");
  assert.equal(receipt.runtimeTruthSource, "daemon-runtime");
  assert.equal(receipt.projectionOwner, "hypervisor-code-editor-adapter");
  assert.equal(receipt.ownsRuntimeState, false);
  assert.equal(receipt.commandId, "ioi.code.open");
  assert.equal(receipt.route, "ioi-runtime-action");
  assert.match(receipt.contextRef, /^code-editor-context:[a-f0-9]{16}$/);
  assert.deepEqual(receipt.runtimeRefs, {
    receiptRefs: [],
    artifactRefs: [],
    authorityRefs: [],
    manifestRefs: [],
    capabilityRefs: [],
  });
});

test("workspace bridge identifies runtime action request families", () => {
  assert.equal(isRuntimeActionRequestType("commandCenter.open"), false);
  assert.equal(isRuntimeActionRequestType("code.open"), true);
  assert.equal(isRuntimeActionRequestType("chat.submit"), false);
  assert.equal(isRuntimeActionRequestType("workflow.open"), false);
  assert.equal(isRuntimeActionRequestType("workbench.contextSnapshot"), false);
});

test("workspace bridge default state keeps daemon runtime authority", async () => {
  const bridge = createWorkspaceBridge({
    bridgeUrl: () => null,
    readDaemonModelSnapshot: async () => ({
      configured: false,
      endpoint: null,
      status: "not_configured",
      error: null,
      snapshot: null,
    }),
    workspaceSummary: () => ({ name: "repo", path: "/workspace/repo" }),
    vscode: { commands: { executeCommand: async () => undefined } },
    modelSnapshotTimeoutMs: 5,
    refreshStateTimeoutMs: 5,
  });

  const originalError = console.error;
  console.error = () => undefined;
  let state;
  try {
    state = await bridge.readBridgeState();
  } finally {
    console.error = originalError;
  }
  assert.equal(state.authoritativeRuntime, true);
  assert.equal(state.workspace.path, "/workspace/repo");
  assert.equal(state.modelMountingStatus.status, "not_configured");
});
