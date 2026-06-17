import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const {
  createPersistentModePanels,
  defaultModelsViewDefinition,
} = require("./persistent-mode-panels.js");

function createFakeVscode() {
  const commands = [];
  const panels = [];
  const vscode = {
    ViewColumn: { One: 1 },
    Uri: {
      joinPath: (...parts) => ({ joined: parts }),
    },
    commands: {
      executeCommand: async (...args) => {
        commands.push(args);
      },
    },
    window: {
      createWebviewPanel: (...args) => {
        let messageHandler = null;
        let disposeHandler = null;
        const panel = {
          args,
          iconPath: null,
          revealed: [],
          webview: {
            html: "",
            posted: [],
            onDidReceiveMessage(callback) {
              messageHandler = callback;
            },
            postMessage(message) {
              this.posted.push(message);
            },
          },
          reveal(column) {
            this.revealed.push(column);
          },
          onDidDispose(callback) {
            disposeHandler = callback;
          },
          emitMessage(message) {
            return messageHandler(message);
          },
          dispose() {
            disposeHandler?.();
          },
        };
        panels.push(panel);
        return panel;
      },
    },
  };
  return { commands, panels, vscode };
}

function createManager(overrides = {}) {
  const fake = overrides.fake || createFakeVscode();
  const bridgeRequests = [];
  const visibility = [];
  const outputLines = [];
  const timers = [];
  const states = [{ label: "initial" }];
  const manager = createPersistentModePanels({
    HYPERVISOR_MODE_BY_ID: {
      code: {
        id: "code",
        title: "Code",
        panelViewType: "ioi.code.panel",
        panelViewId: "ioi.codeActivity",
      },
      runs: {
        id: "runs",
        title: "Runs",
        panelViewType: "ioi.runs.panel",
        panelViewId: "ioi.runs",
      },
    },
    VIEW_DEFINITIONS: [
      { id: "ioi.models", title: "Models", eyebrow: "Models", description: "Models", actions: [] },
      { id: "ioi.runs", title: "Runs", eyebrow: "Runs", description: "Runs", actions: [] },
    ],
    buildWorkspaceActionContext: (source) => ({ source }),
    codeModePanelHtml: (state) => `<code-mode>${state.label}</code-mode>`,
    readBridgeState: async () => states[states.length - 1],
    registerModePanelVisibilityProjection: (panel, modeId) => {
      visibility.push({ panel, modeId });
    },
    renderHtml: (definition, state) => `<main data-view="${definition.id}">${state.label}</main>`,
    setTimeoutFn: (callback, delayMs) => {
      timers.push({ callback, delayMs });
    },
    vscode: fake.vscode,
    writeBridgeRequest: async (...args) => {
      bridgeRequests.push(args);
    },
    ...overrides,
  });
  return {
    bridgeRequests,
    fake,
    manager,
    output: { appendLine: (line) => outputLines.push(line) },
    outputLines,
    states,
    timers,
    visibility,
  };
}

test("default model view definition keeps daemon model fallback copy", () => {
  assert.deepEqual(defaultModelsViewDefinition([]), {
    id: "ioi.models",
    title: "Models",
    eyebrow: "Daemon model runtime",
    description: "Daemon-backed model mounting.",
    actions: [],
  });
  assert.equal(defaultModelsViewDefinition([{ id: "ioi.models", title: "Custom" }]).title, "Custom");
});

test("models panel opens, renders, forwards bridge/proof/command messages, and captures phase", async () => {
  const { bridgeRequests, fake, manager, output, outputLines, timers, visibility } = createManager();
  const context = { extensionUri: "/extension" };

  const panel = await manager.openModelsPanel(context, output, { phase: "model-library" });

  assert.equal(fake.panels.length, 1);
  assert.equal(panel.args[0], "ioi.models");
  assert.equal(panel.webview.html, '<main data-view="ioi.models">initial</main>');
  assert.deepEqual(visibility.map((entry) => entry.modeId), ["models"]);
  assert.equal(timers[0].delayMs, 700);
  timers[0].callback();
  assert.deepEqual(panel.webview.posted, [{ type: "ioi.models.capturePhase", phase: "model-library" }]);
  assert.deepEqual(outputLines, ["Opened Hypervisor Models webview."]);

  await panel.emitMessage({ type: "bridgeRequest", requestType: "models.open", payload: { phase: "library" } });
  await panel.emitMessage({ type: "modelsModeProof", proof: { ok: true } });
  await panel.emitMessage({ type: "command", command: "ioi.models.searchCatalog", payload: { query: "qwen" } });

  assert.deepEqual(bridgeRequests, [
    ["models.open", { phase: "library" }, { source: "models-panel-webview" }],
    ["modelsMode.proof", { ok: true }, { source: "models-panel-webview" }],
  ]);
  assert.deepEqual(fake.commands, [["ioi.models.searchCatalog", { query: "qwen" }]]);

  const reopened = await manager.openModelsPanel(context, output);
  assert.equal(reopened, panel);
  assert.deepEqual(panel.revealed, [1]);
});

test("generic mode panels render, refresh, and drop disposed panels", async () => {
  const { bridgeRequests, fake, manager, output, states, visibility } = createManager();
  const context = { extensionUri: "/extension" };

  const panel = await manager.openGenericModePanel(context, output, "runs");
  assert.equal(panel.args[0], "ioi.runs.panel");
  assert.equal(panel.webview.html, '<main data-view="ioi.runs">initial</main>');
  assert.deepEqual(visibility.map((entry) => entry.modeId), ["runs"]);

  await panel.emitMessage({ type: "bridgeRequest", requestType: "runs.open", payload: { id: "run.1" } });
  await panel.emitMessage({ type: "command", command: "ioi.runs.refresh", payload: { source: "test" } });
  assert.deepEqual(bridgeRequests, [
    ["runs.open", { id: "run.1" }, { source: "runs-mode-webview" }],
  ]);
  assert.deepEqual(fake.commands, [["ioi.runs.refresh", { source: "test" }]]);

  states.push({ label: "updated" });
  manager.refreshPersistentModePanels(states.at(-1));
  assert.equal(panel.webview.html, '<main data-view="ioi.runs">updated</main>');

  panel.dispose();
  states.push({ label: "after-dispose" });
  manager.refreshPersistentModePanels(states.at(-1));
  assert.equal(panel.webview.html, '<main data-view="ioi.runs">updated</main>');
});

test("generic code mode delegates to the code-mode panel renderer", () => {
  const { manager } = createManager();
  assert.equal(manager.renderModePanelHtml("code", { label: "ready" }), "<code-mode>ready</code-mode>");
});

test("unknown generic modes fail closed", async () => {
  const { manager, output } = createManager();
  await assert.rejects(
    () => manager.openGenericModePanel({ extensionUri: "/extension" }, output, "missing"),
    /Unknown Hypervisor mode: missing/,
  );
});
