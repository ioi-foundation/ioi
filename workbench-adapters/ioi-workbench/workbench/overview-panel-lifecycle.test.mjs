import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createOverviewPanelLifecycle } = require("./overview-panel-lifecycle.js");

function createHarness({ failBridge = false } = {}) {
  const bridgeRequests = [];
  const calls = [];
  const commands = [];
  const disposeHandlers = [];
  const messageHandlers = [];
  const outputLines = [];
  const panels = [];
  const visibility = [];
  let overviewPanel = null;
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
  const lifecycle = createOverviewPanelLifecycle({
    applyStudioAgentModeSelection: (payload) => calls.push({ type: "agentMode", payload }),
    applyStudioPermissionModeSelection: async (payload) => calls.push({ type: "permissionMode", payload }),
    buildWorkspaceActionContext: (source) => ({ source }),
    focusStudioPanelComposer: async () => calls.push({ type: "focus" }),
    getOverviewPanel: () => overviewPanel,
    readBridgeState: async () => ({ bridge: "state" }),
    refreshStudioPanelHtml: async () => calls.push({ type: "refresh" }),
    registerModePanelVisibilityProjection: (panel, modeId) => visibility.push({ panel, modeId }),
    resetOverviewPanelRenderState: () => calls.push({ type: "resetRender" }),
    setOverviewPanel: (panel) => {
      overviewPanel = panel;
    },
    updateOverviewPanelHtml: (state) => calls.push({ type: "updateHtml", state }),
    vscode,
    writeBridgeRequest: async (requestType, payload, contextSnapshot) => {
      if (failBridge) {
        throw new Error("bridge unavailable");
      }
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
    get overviewPanel() {
      return overviewPanel;
    },
  };
}

test("overview panel lifecycle creates, reuses, and disposes the panel", async () => {
  const harness = createHarness();

  const first = await harness.lifecycle.openOverviewPanel(harness.context, harness.output);
  const second = await harness.lifecycle.openOverviewPanel(harness.context, harness.output);

  assert.equal(first, second);
  assert.equal(harness.panels.length, 1);
  assert.equal(first.iconPath.path, "/extension/media/ioi-activity.svg");
  assert.deepEqual(second.revealed, ["one"]);
  assert.equal(harness.visibility[0].modeId, "home");
  assert.deepEqual(
    harness.calls.filter((call) => call.type === "updateHtml"),
    [
      { type: "updateHtml", state: { bridge: "state" } },
      { type: "updateHtml", state: { bridge: "state" } },
    ],
  );
  assert.deepEqual(harness.outputLines, [
    "Opened Hypervisor Overview webview.",
    "Opened Hypervisor Overview webview.",
  ]);

  harness.disposeHandlers[0]();
  assert.equal(harness.overviewPanel, null);
  assert.equal(harness.calls.at(-1).type, "resetRender");
});

test("overview panel lifecycle routes bridge requests and commands", async () => {
  const harness = createHarness();
  await harness.lifecycle.openOverviewPanel(harness.context, harness.output);
  const handler = harness.messageHandlers[0];

  await handler({ type: "bridgeRequest", requestType: "chat.agentMode.select", payload: { executionMode: "agent" } });
  await handler({ type: "bridgeRequest", requestType: "chat.permissionMode.select", payload: { permissionMode: "auto-review" } });
  await handler({ type: "bridgeRequest", requestType: "overview.refresh", payload: { bridgeRequestAlreadyWritten: true } });
  await handler({ type: "command", command: "ioi.test", payload: { id: 1 } });

  assert.deepEqual(harness.bridgeRequests, [
    {
      requestType: "chat.agentMode.select",
      payload: { executionMode: "agent" },
      contextSnapshot: { source: "overview-panel-webview" },
    },
    {
      requestType: "chat.permissionMode.select",
      payload: { permissionMode: "auto-review" },
      contextSnapshot: { source: "overview-panel-webview" },
    },
  ]);
  assert.deepEqual(harness.calls.filter((call) => call.type !== "updateHtml"), [
    { type: "agentMode", payload: { executionMode: "agent" } },
    { type: "refresh" },
    { type: "focus" },
    { type: "permissionMode", payload: { permissionMode: "auto-review" } },
    { type: "refresh" },
    { type: "focus" },
  ]);
  assert.deepEqual(harness.commands, [{ command: "ioi.test", payload: { id: 1 } }]);
});

test("overview panel lifecycle logs bridge request failures", async () => {
  const harness = createHarness({ failBridge: true });

  await harness.lifecycle.routeOverviewPanelMessage(
    { type: "bridgeRequest", requestType: "overview.refresh", payload: {} },
    harness.output,
  );

  assert.equal(harness.outputLines[0], "[ioi-overview] bridge request unavailable: bridge unavailable");
});
