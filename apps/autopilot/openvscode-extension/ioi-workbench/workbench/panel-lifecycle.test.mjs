import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createWorkbenchPanelLifecycle } = require("./panel-lifecycle.js");

function createFakeVscode() {
  const commands = [];
  const updates = [];
  return {
    commands,
    updates,
    vscode: {
      ConfigurationTarget: { Global: "global" },
      commands: {
        executeCommand: async (...args) => {
          commands.push(args);
        },
      },
      workspace: {
        getConfiguration(section) {
          return {
            update: async (...args) => {
              updates.push([section, ...args]);
            },
          };
        },
      },
    },
  };
}

function createLifecycle(overrides = {}) {
  const fake = overrides.fake || createFakeVscode();
  const bridgeRequests = [];
  const timers = [];
  const intervals = [];
  const disposedIntervals = [];
  const errors = [];
  const lifecycle = createWorkbenchPanelLifecycle({
    AUTOPILOT_MODE_BY_ID: {
      studio: { command: "ioi.studio.open", phase: "studio" },
      home: { command: "ioi.overview.open", phase: "overview" },
    },
    AUTOPILOT_MODE_BY_VIEW_ID: {
      "ioi.studio": { command: "ioi.studio.open", phase: "studio" },
    },
    MODE_VISIBILITY_REQUEST_TYPES: {
      studio: "studio.open",
      home: "overview.open",
    },
    buildWorkspaceActionContext: (source) => ({ source }),
    clearIntervalFn: (handle) => {
      disposedIntervals.push(handle);
    },
    consoleRef: {
      error: (...args) => errors.push(args),
    },
    renderHtml: (definition, state) => `<main data-view="${definition.id}">${state.label}</main>`,
    setIntervalFn: (callback, delayMs) => {
      const handle = { callback, delayMs };
      intervals.push(handle);
      return handle;
    },
    setTimeoutFn: (callback, delayMs) => {
      timers.push({ callback, delayMs });
    },
    vscode: fake.vscode,
    workspaceSummary: () => ({ path: "/workspace" }),
    writeBridgeRequest: async (...args) => {
      bridgeRequests.push(args);
    },
    ...overrides,
  });
  return { bridgeRequests, disposedIntervals, errors, fake, intervals, lifecycle, timers };
}

test("visibility projection writes daemon-owned mode envelope and throttles repeats", async () => {
  const originalNow = Date.now;
  let now = 1_000;
  Date.now = () => now;
  try {
    const { bridgeRequests, lifecycle } = createLifecycle();

    assert.equal(lifecycle.writeModeVisibilityProjection("studio", null), true);
    assert.equal(lifecycle.writeModeVisibilityProjection("studio", null), false);
    now += 500;
    assert.equal(lifecycle.writeModeVisibilityProjection("studio", null, "manual"), true);

    await Promise.resolve();
    assert.deepEqual(bridgeRequests, [
      [
        "studio.open",
        {
          workspaceRoot: "/workspace",
          sourceCommand: "ioi.studio.open",
          source: "panel-visible",
          phase: "studio",
          runtimeAuthority: "daemon-owned",
          projectionOwner: "openvscode-workbench-adapter",
          ownsRuntimeState: false,
        },
        { source: "studio-panel-visible" },
      ],
      [
        "studio.open",
        {
          workspaceRoot: "/workspace",
          sourceCommand: "ioi.studio.open",
          source: "manual",
          phase: "studio",
          runtimeAuthority: "daemon-owned",
          projectionOwner: "openvscode-workbench-adapter",
          ownsRuntimeState: false,
        },
        { source: "studio-manual" },
      ],
    ]);
  } finally {
    Date.now = originalNow;
  }
});

test("panel visibility registration disposes its view-state listener", () => {
  const { lifecycle } = createLifecycle();
  let viewHandler = null;
  let disposeHandler = null;
  let disposed = false;
  const panel = {
    onDidChangeViewState(callback) {
      viewHandler = callback;
      return {
        dispose() {
          disposed = true;
        },
      };
    },
    onDidDispose(callback) {
      disposeHandler = callback;
    },
  };

  lifecycle.registerModePanelVisibilityProjection(panel, "studio", null);
  assert.equal(typeof viewHandler, "function");
  assert.equal(typeof disposeHandler, "function");
  disposeHandler();
  assert.equal(disposed, true);
});

test("workbench appearance sync applies changed themes once", async () => {
  const { fake, lifecycle } = createLifecycle();

  assert.equal(await lifecycle.syncWorkbenchAppearance({ appearance: { openVsCodeColorTheme: " Dark+ " } }), true);
  assert.equal(await lifecycle.syncWorkbenchAppearance({ appearance: { openVsCodeColorTheme: "Dark+" } }), false);
  assert.equal(await lifecycle.syncWorkbenchAppearance({ appearance: { openVsCodeColorTheme: "Light+" } }), true);

  assert.deepEqual(fake.updates, [
    ["workbench", "colorTheme", "Dark+", "global"],
    ["workbench", "colorTheme", "Light+", "global"],
  ]);
});

test("bridge-state watcher polls and disposes using injected timers", () => {
  const { disposedIntervals, intervals, lifecycle } = createLifecycle();
  let polls = 0;

  const disposable = lifecycle.watchBridgeState(() => {
    polls += 1;
  });

  assert.equal(intervals.length, 1);
  assert.equal(intervals[0].delayMs, 2_000);
  intervals[0].callback();
  assert.equal(polls, 1);
  disposable.dispose();
  assert.deepEqual(disposedIntervals, [intervals[0]]);
});

test("view provider renders, forwards webview messages, and auto-opens primary surface", async () => {
  const originalNow = Date.now;
  Date.now = () => 10_000;
  try {
    const { bridgeRequests, fake, lifecycle, timers } = createLifecycle();
    let messageHandler = null;
    let visibilityHandler = null;
    let disposeHandler = null;
    const view = {
      visible: true,
      webview: {
        html: "",
        options: null,
        onDidReceiveMessage(callback) {
          messageHandler = callback;
        },
      },
      onDidChangeVisibility(callback) {
        visibilityHandler = callback;
        return { dispose() {} };
      },
      onDidDispose(callback) {
        disposeHandler = callback;
      },
    };
    const provider = new lifecycle.IOIViewProvider(
      { id: "ioi.studio" },
      async () => ({ label: "ready" }),
    );

    provider.resolveWebviewView(view);
    await provider.render();

    assert.deepEqual(view.webview.options, { enableScripts: true, enableForms: true });
    assert.equal(view.webview.html, '<main data-view="ioi.studio">ready</main>');
    assert.equal(timers[0].delayMs, 0);
    timers[0].callback();
    await Promise.resolve();
    await Promise.resolve();
    assert.deepEqual(fake.commands[0], ["ioi.studio.open", { source: "activitybar", phase: "studio" }]);

    await messageHandler({ type: "bridgeRequest", requestType: "chat.submit", payload: { prompt: "hi" } });
    await messageHandler({ type: "command", command: "ioi.models.open", payload: { phase: "library" } });
    assert.deepEqual(bridgeRequests[0], [
      "chat.submit",
      { prompt: "hi" },
      { source: "ioi.chat" },
    ]);
    assert.deepEqual(fake.commands.at(-1), ["ioi.models.open", { phase: "library" }]);

    assert.equal(typeof visibilityHandler, "function");
    assert.equal(typeof disposeHandler, "function");
    disposeHandler();
    assert.equal(provider.webviewView, null);
  } finally {
    Date.now = originalNow;
  }
});
