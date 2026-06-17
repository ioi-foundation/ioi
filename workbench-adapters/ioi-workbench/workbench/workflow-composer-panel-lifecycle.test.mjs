import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createWorkflowComposerPanelLifecycle } = require("./workflow-composer-panel-lifecycle.js");

function createHarness() {
  const bridgeRequests = [];
  const commands = [];
  const visibility = [];
  const outputLines = [];
  const timers = [];
  const messageHandlers = [];
  const disposeHandlers = [];
  const postedMessages = [];
  const panels = [];
  const context = { extensionUri: { path: "/extension" }, subscriptions: [] };
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
          revealed: [],
          webview: {
            html: "",
            onDidReceiveMessage(handler) {
              messageHandlers.push(handler);
            },
            postMessage(message) {
              postedMessages.push(message);
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
  const lifecycle = createWorkflowComposerPanelLifecycle({
    buildWorkspaceActionContext: (source) => ({ source }),
    registerModePanelVisibilityProjection: (panel, modeId) => visibility.push({ panel, modeId }),
    setTimeoutFn: (callback, delayMs) => {
      timers.push({ callback, delayMs });
    },
    vscode,
    workflowComposerHtml: () => "<html>workflow</html>",
    writeBridgeRequest: async (requestType, payload, contextSnapshot) => {
      bridgeRequests.push({ requestType, payload, contextSnapshot });
    },
  });
  return {
    bridgeRequests,
    commands,
    context,
    disposeHandlers,
    lifecycle,
    messageHandlers,
    output,
    outputLines,
    panels,
    postedMessages,
    timers,
    visibility,
  };
}

test("workflow composer lifecycle creates, reuses, and disposes the panel", () => {
  const harness = createHarness();

  const first = harness.lifecycle.openWorkflowComposerPanel(harness.context, harness.output);
  const second = harness.lifecycle.openWorkflowComposerPanel(harness.context, harness.output);
  assert.equal(first, second);
  assert.equal(harness.panels.length, 1);
  assert.deepEqual(second.revealed, ["one"]);
  assert.equal(first.webview.html, "<html>workflow</html>");
  assert.equal(harness.visibility[0].modeId, "workflows");
  assert.deepEqual(harness.outputLines, [
    "Opened Hypervisor Workflow Composer webview.",
    "Opened Hypervisor Workflow Composer webview.",
  ]);

  harness.disposeHandlers[0]();
  assert.equal(harness.lifecycle.getWorkflowComposerPanel(), null);
});

test("workflow composer lifecycle routes webview messages through bridge and commands", async () => {
  const harness = createHarness();
  harness.lifecycle.openWorkflowComposerPanel(harness.context, harness.output);
  const handler = harness.messageHandlers[0];

  await handler({ type: "bridgeRequest", requestType: "workflow.test", payload: { ok: true } });
  await handler({ type: "workflowCompositorProof", proof: { proof: true } });
  await handler({ type: "workflowCompositorError", error: { message: "client failed" } });
  await handler({ type: "command", command: "ioi.test", payload: { id: 1 } });

  assert.deepEqual(harness.bridgeRequests, [
    { requestType: "workflow.test", payload: { ok: true }, contextSnapshot: { source: "workflow-composer-webview" } },
    { requestType: "workflowCompositor.proof", payload: { proof: true }, contextSnapshot: { source: "workflow-composer-webview" } },
    { requestType: "workflowCompositor.error", payload: { message: "client failed" }, contextSnapshot: { source: "workflow-composer-webview" } },
  ]);
  assert.deepEqual(harness.commands, [{ command: "ioi.test", payload: { id: 1 } }]);
  assert.equal(harness.outputLines.at(-1), "[workflow-composer] client failed");
});

test("workflow composer lifecycle schedules scenario and capture phase messages", () => {
  const harness = createHarness();

  harness.lifecycle.openWorkflowComposerPanel(harness.context, harness.output, {
    scenarioId: "scenario-one",
    phase: "validate",
  });
  harness.lifecycle.openWorkflowComposerPanel(harness.context, harness.output, {
    capturePhase: true,
    phase: "inspect",
  });
  assert.deepEqual(harness.timers.map((timer) => timer.delayMs), [750, 750]);

  harness.timers.forEach((timer) => timer.callback());
  assert.deepEqual(harness.postedMessages, [
    {
      type: "ioi.workflow.compositor.runScenario",
      scenarioId: "scenario-one",
      phase: "validate",
    },
    {
      type: "ioi.workflow.compositor.capturePhase",
      phase: "inspect",
    },
  ]);
});
