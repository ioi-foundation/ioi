import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioPanelLifecycle } = require("./studio-panel-lifecycle.js");

function createHarness() {
  const calls = [];
  const bridgeRequests = [];
  const commands = [];
  const disposeHandlers = [];
  const messageHandlers = [];
  const outputLines = [];
  const panels = [];
  const visibility = [];
  let studioPanel = null;
  const context = { extensionUri: { path: "/extension" } };
  const output = { appendLine: (line) => outputLines.push(line) };
  const vscode = {
    ViewColumn: { One: "one" },
    Uri: {
      joinPath: (...parts) => ({ path: parts.map((part) => part.path || part).join("/") }),
    },
    commands: {
      executeCommand: async (command, payload) => {
        commands.push({ command, payload });
      },
    },
    window: {
      createWebviewPanel(viewType, title, column, options) {
        const panel = {
          viewType,
          title,
          column,
          options,
          iconPath: null,
          revealed: [],
          webview: {
            onDidReceiveMessage(handler) {
              messageHandlers.push(handler);
            },
          },
          reveal(targetColumn) {
            this.revealed.push(targetColumn);
          },
          onDidDispose(handler) {
            disposeHandlers.push(handler);
          },
        };
        panels.push(panel);
        return panel;
      },
    },
  };
  const lifecycle = createStudioPanelLifecycle({
    applyStudioAgentModeSelection: (payload) => calls.push({ type: "agentMode", payload }),
    applyStudioPermissionModeSelection: async (payload) => calls.push({ type: "permissionMode", payload }),
    buildWorkspaceActionContext: (source) => ({ source }),
    focusStudioPanelComposer: async () => calls.push({ type: "focus" }),
    getStudioPanel: () => studioPanel,
    handleStudioArtifactAction: async (payload) => calls.push({ type: "artifact", payload }),
    handleStudioHunkDecision: async (decision, payload) => calls.push({ type: "hunk", decision, payload }),
    handleStudioManagedSessionControl: async (payload) => calls.push({ type: "managed", payload }),
    navigateStudioHunk: async (direction) => calls.push({ type: "navigate", direction }),
    readBridgeState: async () => ({ bridge: "state" }),
    refreshStudioPanelHtml: async () => calls.push({ type: "refresh" }),
    registerModePanelVisibilityProjection: (panel, modeId) => visibility.push({ panel, modeId }),
    resetStudioPanelRenderState: () => calls.push({ type: "resetRender" }),
    resumeStudioTurn: async () => calls.push({ type: "resume" }),
    setStudioPanel: (panel) => {
      studioPanel = panel;
    },
    startNewStudioSession: (reason) => calls.push({ type: "newSession", reason }),
    stopStudioTurn: async () => calls.push({ type: "stop" }),
    submitStudioPrompt: async (payload) => calls.push({ type: "submit", payload }),
    updateStudioPanelHtml: (state, options) => calls.push({ type: "updateHtml", state, options }),
    vscode,
    writeBridgeRequest: async (requestType, payload, contextSnapshot) => {
      bridgeRequests.push({ requestType, payload, contextSnapshot });
    },
  });
  return {
    bridgeRequests,
    calls,
    commands,
    context,
    disposeHandlers,
    lifecycle,
    messageHandlers,
    output,
    outputLines,
    panels,
    visibility,
    get studioPanel() {
      return studioPanel;
    },
  };
}

test("studio panel lifecycle creates, reuses, and disposes the panel", async () => {
  const harness = createHarness();

  const first = await harness.lifecycle.openStudioPanel(harness.context, harness.output);
  const second = await harness.lifecycle.openStudioPanel(harness.context, harness.output);

  assert.equal(first, second);
  assert.equal(harness.panels.length, 1);
  assert.equal(first.iconPath.path, "/extension/media/ioi-studio.svg");
  assert.deepEqual(second.revealed, ["one"]);
  assert.equal(harness.visibility[0].modeId, "studio");
  assert.deepEqual(
    harness.calls.filter((call) => call.type === "updateHtml").map((call) => call.options),
    [{ force: true }, { force: true }],
  );
  assert.deepEqual(harness.outputLines, [
    "Opened Agent Studio webview.",
    "Opened Agent Studio webview.",
  ]);

  harness.disposeHandlers[0]();
  assert.equal(harness.studioPanel, null);
  assert.equal(harness.calls.at(-1).type, "resetRender");
});

test("studio panel lifecycle routes direct webview actions", async () => {
  const harness = createHarness();
  await harness.lifecycle.openStudioPanel(harness.context, harness.output);
  const handler = harness.messageHandlers[0];

  await handler({ type: "studioSubmit", payload: { prompt: "hi" } });
  await handler({ type: "studioHunkDecision", decision: "accept", payload: { hunk: 1 } });
  await handler({ type: "studioArtifactAction", payload: { artifactId: "a1" } });
  await handler({ type: "studioManagedSessionControl", payload: { sessionId: "s1" } });
  await handler({ type: "studioHunkNavigate", direction: "previous" });
  await handler({ type: "studioStop" });
  await handler({ type: "studioResume" });
  await handler({ type: "studioOperationalProof", proof: { ok: true } });

  assert.deepEqual(harness.calls.slice(1), [
    { type: "submit", payload: { prompt: "hi" } },
    { type: "hunk", decision: "accept", payload: { hunk: 1 } },
    { type: "artifact", payload: { artifactId: "a1" } },
    { type: "managed", payload: { sessionId: "s1" } },
    { type: "navigate", direction: "previous" },
    { type: "stop" },
    { type: "resume" },
  ]);
  assert.equal(harness.outputLines.at(-1), '[ioi-studio] operational proof: {"ok":true}');
});

test("studio panel lifecycle routes bridge requests and commands", async () => {
  const harness = createHarness();
  await harness.lifecycle.openStudioPanel(harness.context, harness.output);
  const handler = harness.messageHandlers[0];

  await handler({ type: "bridgeRequest", requestType: "chat.agentMode.select", payload: { executionMode: "agent" } });
  await handler({ type: "bridgeRequest", requestType: "chat.permissionMode.select", payload: { permissionMode: "auto-review" } });
  await handler({ type: "bridgeRequest", requestType: "chat.newSession", payload: { bridgeRequestAlreadyWritten: true } });
  await handler({ type: "command", command: "ioi.test", payload: { id: 1 } });

  assert.deepEqual(harness.bridgeRequests, [
    {
      requestType: "chat.agentMode.select",
      payload: { executionMode: "agent" },
      contextSnapshot: { source: "studio-panel-webview" },
    },
    {
      requestType: "chat.permissionMode.select",
      payload: { permissionMode: "auto-review" },
      contextSnapshot: { source: "studio-panel-webview" },
    },
  ]);
  assert.deepEqual(harness.calls.filter((call) => call.type !== "updateHtml"), [
    { type: "agentMode", payload: { executionMode: "agent" } },
    { type: "refresh" },
    { type: "focus" },
    { type: "permissionMode", payload: { permissionMode: "auto-review" } },
    { type: "refresh" },
    { type: "focus" },
    { type: "newSession", reason: "Operator started a fresh Studio chat session." },
    { type: "refresh" },
    { type: "focus" },
  ]);
  assert.deepEqual(harness.commands, [{ command: "ioi.test", payload: { id: 1 } }]);
});
