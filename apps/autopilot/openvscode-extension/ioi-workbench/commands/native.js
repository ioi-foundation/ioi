"use strict";

const crypto = require("crypto");
const { registerChatCommands } = require("./chat");
const { registerMigrationCommands } = require("./migration");
const { createModelDaemonActions } = require("./model-daemon-actions");
const { registerModelCommands } = require("./models");
const { registerNavigationCommands } = require("./navigation");
const { registerQuickInputCommands } = require("./quick-input");
const { registerRuntimeSurfaceCommands } = require("./runtime-surfaces");
const { registerStudioModeControlCommands } = require("./studio-mode-controls");
const { registerStudioQuickInputCommands } = require("./studio-quick-input");
const { registerStudioTestHookCommands } = require("./studio-test-hooks");
const { registerWorkflowCommands } = require("./workflow");

function pickString(value, key) {
  if (typeof value === "string") {
    return value;
  }
  if (value && typeof value === "object" && typeof value[key] === "string") {
    return value[key];
  }
  return null;
}

function createNativeCommandRegistrar(registrars = {}) {
  const commandRegistrars = {
    createModelDaemonActions,
    registerChatCommands,
    registerMigrationCommands,
    registerModelCommands,
    registerNavigationCommands,
    registerQuickInputCommands,
    registerRuntimeSurfaceCommands,
    registerStudioModeControlCommands,
    registerStudioQuickInputCommands,
    registerStudioTestHookCommands,
    registerWorkflowCommands,
    ...registrars,
  };

  return function registerNativeCommands({
    context,
    output,
    vscode,
    daemonEndpoint,
    daemonToken,
    requestJson,
    ensureStudioDiffProvider,
    buildWorkspaceActionContext,
    writeBridgeRequest,
    workspaceSummary,
    studioRuntimeProjection,
    studioPermissionModeOptions,
    studioExecutionModeLabel,
    studioPermissionModeLabel,
    applyStudioAgentModeSelection,
    applyStudioPermissionModeSelection,
    refreshStudioPanelHtml,
    focusStudioPanelComposer,
    autopilotModeById,
    getLastAutopilotModeBeforeCode,
    getStudioPanel,
    enterAutopilotMode,
    openOverviewPanel,
    openStudioPanel,
    openGenericModePanel,
    closePrimarySidebarAfterActivityLaunch,
    applyStudioAgentTurnEvents,
    firstArray,
    stringValue,
    normalizeReceiptRefs,
    refreshStudioReplayStepsFromProjection,
    exerciseStudioPolicyLeaseLifecycle,
    exerciseStudioSessionBrainLifecycle,
    exerciseStudioTrajectoryReplayReconnect,
    exerciseStudioManagedSessionReconnect,
    exerciseStudioStage2WebRepairLoop,
    exerciseStudioStage5StopHookRepairLoop,
    exerciseStudioStage5StopCancelRecoverLifecycle,
    exerciseStudioStage7DelegationLifecycle,
    readBridgeState,
    studioContextQuickPickItems,
    studioToolQuickPickItems,
    startNewStudioSession,
    openWorkflowComposerPanel,
    buildRuntimeRefs,
    openModelsPanel,
    getActiveTraceTarget,
    setActiveTraceTarget,
  }) {
    ensureStudioDiffProvider(context);
    const status = (message) =>
      vscode.window.setStatusBarMessage(`$(symbol-keyword) ${message}`, 3000);
    const {
      pickPayloadString,
      runDaemonModelCatalogDownload,
      runDaemonModelCatalogProviderConfig,
      runDaemonModelCatalogSearch,
      runDaemonModelWorkbenchAction,
    } = commandRegistrars.createModelDaemonActions({
      daemonEndpoint,
      daemonToken,
      requestJson,
    });

    commandRegistrars.registerMigrationCommands({
      context,
      output,
      vscode,
      buildWorkspaceActionContext,
      writeBridgeRequest,
      workspaceSummary,
      status,
    });
    commandRegistrars.registerQuickInputCommands({
      context,
      output,
      vscode,
      buildWorkspaceActionContext,
      writeBridgeRequest,
      status,
    });

    context.subscriptions.push(
      ...commandRegistrars.registerStudioModeControlCommands({
        vscode,
        output,
        status,
        buildWorkspaceActionContext,
        writeBridgeRequest,
        studioRuntimeProjection,
        studioPermissionModeOptions,
        studioExecutionModeLabel,
        studioPermissionModeLabel,
        applyStudioAgentModeSelection,
        applyStudioPermissionModeSelection,
        refreshStudioPanelHtml,
        focusStudioPanelComposer,
      }),
      ...commandRegistrars.registerNavigationCommands({
        vscode,
        output,
        status,
        buildWorkspaceActionContext,
        writeBridgeRequest,
        workspaceSummary,
        pickString,
        autopilotModeById,
        getLastAutopilotModeBeforeCode,
        getStudioPanel,
        enterHome: () => enterAutopilotMode("home", output),
        enterStudio: () => enterAutopilotMode("studio", output),
        enterCode: () => enterAutopilotMode("code", output),
        enterMode: (modeId) => enterAutopilotMode(modeId, output),
        openOverviewPanel,
        openStudioPanel,
        openGenericModePanel,
        closePrimarySidebarAfterActivityLaunch,
      }),
      ...commandRegistrars.registerStudioTestHookCommands({
        vscode,
        output,
        status,
        enterStudio: () => enterAutopilotMode("studio", output),
        openStudioPanel,
        refreshStudioPanelHtml,
        buildWorkspaceActionContext,
        writeBridgeRequest,
        applyStudioAgentTurnEvents,
        firstArray,
        stringValue,
        normalizeReceiptRefs,
        studioRuntimeProjection,
        refreshStudioReplayStepsFromProjection,
        exerciseStudioPolicyLeaseLifecycle,
        exerciseStudioSessionBrainLifecycle,
        exerciseStudioTrajectoryReplayReconnect,
        exerciseStudioManagedSessionReconnect,
        exerciseStudioStage2WebRepairLoop,
        exerciseStudioStage5StopHookRepairLoop,
        exerciseStudioStage5StopCancelRecoverLifecycle,
        exerciseStudioStage7DelegationLifecycle,
      }),
      ...commandRegistrars.registerStudioQuickInputCommands({
        vscode,
        output,
        status,
        buildWorkspaceActionContext,
        writeBridgeRequest,
        readBridgeState,
        studioContextQuickPickItems,
        studioToolQuickPickItems,
      }),
      ...commandRegistrars.registerChatCommands({
        vscode,
        output,
        status,
        buildWorkspaceActionContext,
        writeBridgeRequest,
        workspaceSummary,
        pickString,
        getStudioPanel,
        startNewStudioSession,
        refreshStudioPanelHtml,
        focusStudioPanelComposer,
      }),
      ...commandRegistrars.registerWorkflowCommands({
        crypto,
        vscode,
        status,
        buildWorkspaceActionContext,
        writeBridgeRequest,
        workspaceSummary,
        pickString,
        enterWorkflows: () => enterAutopilotMode("workflows", output),
        openWorkflowComposerPanel,
        closePrimarySidebarAfterActivityLaunch,
        buildRuntimeRefs,
      }),
      ...commandRegistrars.registerModelCommands({
        vscode,
        status,
        buildWorkspaceActionContext,
        writeBridgeRequest,
        workspaceSummary,
        pickString,
        pickPayloadString,
        daemonEndpoint,
        enterModels: () => enterAutopilotMode("models", output),
        enterWorkflows: () => enterAutopilotMode("workflows", output),
        openModelsPanel,
        openWorkflowComposerPanel,
        closePrimarySidebarAfterActivityLaunch,
        runDaemonModelWorkbenchAction,
        runDaemonModelCatalogSearch,
        runDaemonModelCatalogProviderConfig,
        runDaemonModelCatalogDownload,
      }),
      ...commandRegistrars.registerRuntimeSurfaceCommands({
        vscode,
        output,
        status,
        buildWorkspaceActionContext,
        writeBridgeRequest,
        workspaceSummary,
        pickString,
        getActiveTraceTarget,
        setActiveTraceTarget,
        enterRuns: () => enterAutopilotMode("runs", output),
        enterPolicy: () => enterAutopilotMode("policy", output),
        enterConnectors: () => enterAutopilotMode("connectors", output),
        openGenericModePanel,
        closePrimarySidebarAfterActivityLaunch,
      }),
    );

    output.appendLine("Registered IOI runtime bridge commands.");
  };
}

module.exports = {
  createNativeCommandRegistrar,
  pickString,
};
