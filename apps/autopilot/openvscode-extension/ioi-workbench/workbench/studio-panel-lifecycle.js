"use strict";

function createStudioPanelLifecycle({
  applyStudioAgentModeSelection,
  applyStudioPermissionModeSelection,
  buildWorkspaceActionContext,
  focusStudioPanelComposer,
  getStudioPanel,
  handleStudioArtifactAction,
  handleStudioHunkDecision,
  handleStudioManagedSessionControl,
  navigateStudioHunk,
  readBridgeState,
  refreshStudioPanelHtml,
  registerModePanelVisibilityProjection,
  resetStudioPanelRenderState,
  resumeStudioTurn,
  setStudioPanel,
  startNewStudioSession,
  stopStudioTurn,
  submitStudioPrompt,
  updateStudioPanelHtml,
  vscode,
  writeBridgeRequest,
}) {
  async function routeStudioBridgeRequest(message, output) {
    if (message.requestType === "chat.agentMode.select") {
      applyStudioAgentModeSelection(message.payload || {});
      await refreshStudioPanelHtml(output);
      await focusStudioPanelComposer();
    }
    if (message.requestType === "chat.permissionMode.select") {
      await applyStudioPermissionModeSelection(message.payload || {}, output);
      await refreshStudioPanelHtml(output);
      await focusStudioPanelComposer();
    }
    if (message.requestType === "chat.newSession") {
      startNewStudioSession("Operator started a fresh Studio chat session.");
      await refreshStudioPanelHtml(output);
      await focusStudioPanelComposer();
    }
    if (!message.payload?.bridgeRequestAlreadyWritten) {
      await writeBridgeRequest(
        message.requestType,
        message.payload || {},
        buildWorkspaceActionContext("studio-panel-webview"),
      ).catch((error) => {
        output.appendLine(
          `[ioi-studio] bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
    }
  }

  async function routeStudioPanelMessage(message, output) {
    if (message?.type === "studioSubmit") {
      await submitStudioPrompt(message.payload || {}, output);
      return;
    }
    if (message?.type === "studioHunkDecision") {
      await handleStudioHunkDecision(message.decision, message.payload || {}, output);
      return;
    }
    if (message?.type === "studioArtifactAction") {
      await handleStudioArtifactAction(message.payload || {}, output);
      return;
    }
    if (message?.type === "studioManagedSessionControl") {
      await handleStudioManagedSessionControl(message.payload || {}, output);
      return;
    }
    if (message?.type === "studioHunkNavigate") {
      await navigateStudioHunk(message.direction || "next", output);
      return;
    }
    if (message?.type === "studioStop") {
      await stopStudioTurn(output);
      return;
    }
    if (message?.type === "studioResume") {
      await resumeStudioTurn(output);
      return;
    }
    if (message?.type === "studioOperationalProof") {
      output.appendLine(`[ioi-studio] operational proof: ${JSON.stringify(message.proof || {})}`);
      return;
    }
    if (
      message?.type === "bridgeRequest" &&
      typeof message.requestType === "string"
    ) {
      await routeStudioBridgeRequest(message, output);
      return;
    }
    if (message?.type !== "command" || typeof message.command !== "string") {
      return;
    }
    await vscode.commands.executeCommand(message.command, message.payload);
  }

  async function openStudioPanel(context, output) {
    const state = await readBridgeState();
    let studioPanel = getStudioPanel();
    if (studioPanel) {
      studioPanel.reveal(vscode.ViewColumn.One);
    } else {
      studioPanel = vscode.window.createWebviewPanel(
        "ioi.studio",
        "Agent Studio",
        vscode.ViewColumn.One,
        {
          enableScripts: true,
          retainContextWhenHidden: true,
        },
      );
      setStudioPanel(studioPanel);
      studioPanel.iconPath = vscode.Uri.joinPath(
        context.extensionUri,
        "media",
        "ioi-studio.svg",
      );
      studioPanel.webview.onDidReceiveMessage(async (message) => {
        await routeStudioPanelMessage(message, output);
      });
      registerModePanelVisibilityProjection(studioPanel, "studio", output);
      studioPanel.onDidDispose(() => {
        setStudioPanel(null);
        resetStudioPanelRenderState();
      });
    }
    updateStudioPanelHtml(state, { force: true });
    output.appendLine("Opened Agent Studio webview.");
    return studioPanel;
  }

  return {
    openStudioPanel,
    routeStudioPanelMessage,
  };
}

module.exports = {
  createStudioPanelLifecycle,
};
