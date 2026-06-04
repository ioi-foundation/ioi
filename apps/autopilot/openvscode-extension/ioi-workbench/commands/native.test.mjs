import assert from "node:assert/strict";
import { test } from "node:test";
import nativeCommands from "./native.js";

const { createNativeCommandRegistrar, pickString } = nativeCommands;

test("pickString accepts strings and keyed object values", () => {
  assert.equal(pickString("direct", "phase"), "direct");
  assert.equal(pickString({ phase: "chat" }, "phase"), "chat");
  assert.equal(pickString({ phase: 3 }, "phase"), null);
  assert.equal(pickString(null, "phase"), null);
});

test("native command registrar composes command groups with shared dependencies", async () => {
  const calls = [];
  const disposable = (name) => ({ dispose() {}, name });
  const registrar = (name) => (options) => {
    calls.push({ name, options });
    return [disposable(name)];
  };
  const context = { subscriptions: [] };
  const outputLines = [];
  const statusMessages = [];
  const enteredModes = [];
  const opened = [];
  const registrarUnderTest = createNativeCommandRegistrar({
    createModelDaemonActions: (options) => {
      calls.push({ name: "modelDaemonActions", options });
      return {
        pickPayloadString: () => "payload",
        runDaemonModelCatalogDownload: () => "download",
        runDaemonModelCatalogProviderConfig: () => "provider-config",
        runDaemonModelCatalogSearch: () => "catalog-search",
        runDaemonModelWorkbenchAction: () => "workbench-action",
      };
    },
    registerChatCommands: registrar("chat"),
    registerMigrationCommands: registrar("migration"),
    registerModelCommands: registrar("models"),
    registerNavigationCommands: registrar("navigation"),
    registerQuickInputCommands: registrar("quickInput"),
    registerRuntimeSurfaceCommands: registrar("runtimeSurface"),
    registerStudioModeControlCommands: registrar("studioMode"),
    registerStudioQuickInputCommands: registrar("studioQuickInput"),
    registerStudioTestHookCommands: registrar("studioTestHooks"),
    registerWorkflowCommands: registrar("workflow"),
  });
  const deps = {
    context,
    output: { appendLine: (line) => outputLines.push(line) },
    vscode: {
      window: {
        setStatusBarMessage: (message, timeoutMs) => {
          statusMessages.push({ message, timeoutMs });
          return disposable("status");
        },
      },
    },
    daemonEndpoint: () => "http://daemon",
    daemonToken: () => "token",
    requestJson: () => undefined,
    ensureStudioDiffProvider: (receivedContext) => {
      assert.equal(receivedContext, context);
      calls.push({ name: "diffProvider" });
    },
    buildWorkspaceActionContext: () => ({ source: "test" }),
    writeBridgeRequest: () => undefined,
    workspaceSummary: () => ({ path: "/workspace" }),
    studioRuntimeProjection: { mode: "agent" },
    studioPermissionModeOptions: [{ id: "default" }],
    studioExecutionModeLabel: () => "Agent",
    studioPermissionModeLabel: () => "Default",
    applyStudioAgentModeSelection: () => undefined,
    applyStudioPermissionModeSelection: () => undefined,
    refreshStudioPanelHtml: () => undefined,
    focusStudioPanelComposer: () => undefined,
    autopilotModeById: { home: { id: "home" } },
    getLastAutopilotModeBeforeCode: () => "studio",
    getStudioPanel: () => null,
    enterAutopilotMode: (modeId, output) => {
      enteredModes.push({ modeId, output });
    },
    openOverviewPanel: () => opened.push("overview"),
    openStudioPanel: () => opened.push("studio"),
    openGenericModePanel: (modeId) => opened.push(modeId),
    closePrimarySidebarAfterActivityLaunch: () => undefined,
    applyStudioAgentTurnEvents: () => undefined,
    firstArray: (value) => (Array.isArray(value) ? value : []),
    stringValue: (value) => String(value ?? ""),
    normalizeReceiptRefs: () => [],
    refreshStudioReplayStepsFromProjection: () => undefined,
    exerciseStudioPolicyLeaseLifecycle: () => undefined,
    exerciseStudioSessionBrainLifecycle: () => undefined,
    exerciseStudioTrajectoryReplayReconnect: () => undefined,
    exerciseStudioManagedSessionReconnect: () => undefined,
    exerciseStudioStage2WebRepairLoop: () => undefined,
    exerciseStudioStage5StopHookRepairLoop: () => undefined,
    exerciseStudioStage5StopCancelRecoverLifecycle: () => undefined,
    exerciseStudioStage7DelegationLifecycle: () => undefined,
    readBridgeState: () => ({}),
    studioContextQuickPickItems: () => [],
    studioToolQuickPickItems: () => [],
    startNewStudioSession: () => undefined,
    openWorkflowComposerPanel: () => opened.push("workflow"),
    buildRuntimeRefs: () => ({}),
    openModelsPanel: () => opened.push("models"),
    getActiveTraceTarget: () => null,
    setActiveTraceTarget: () => undefined,
  };

  registrarUnderTest(deps);

  assert.deepEqual(calls.map((call) => call.name), [
    "diffProvider",
    "modelDaemonActions",
    "migration",
    "quickInput",
    "studioMode",
    "navigation",
    "studioTestHooks",
    "studioQuickInput",
    "chat",
    "workflow",
    "models",
    "runtimeSurface",
  ]);
  assert.equal(context.subscriptions.length, 8);
  assert.deepEqual(outputLines, ["Registered IOI runtime bridge commands."]);

  const navigationCall = calls.find((call) => call.name === "navigation");
  navigationCall.options.status("Opened.");
  navigationCall.options.enterStudio();
  navigationCall.options.openGenericModePanel("runs");
  assert.deepEqual(statusMessages, [{ message: "$(symbol-keyword) Opened.", timeoutMs: 3000 }]);
  assert.deepEqual(enteredModes, [{ modeId: "studio", output: deps.output }]);
  assert.deepEqual(opened, ["runs"]);

  const modelsCall = calls.find((call) => call.name === "models");
  assert.equal(modelsCall.options.pickPayloadString(), "payload");
  assert.equal(modelsCall.options.runDaemonModelCatalogSearch(), "catalog-search");
  assert.equal(modelsCall.options.daemonEndpoint(), "http://daemon");
});
