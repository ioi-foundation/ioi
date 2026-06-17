"use strict";

function createOverviewPanelLifecycle({
  applyStudioAgentModeSelection,
  applyStudioPermissionModeSelection,
  buildWorkspaceActionContext,
  focusStudioPanelComposer,
  getOverviewPanel,
  readBridgeState,
  refreshStudioPanelHtml,
  registerModePanelVisibilityProjection,
  resetOverviewPanelRenderState,
  setOverviewPanel,
  updateOverviewPanelHtml,
  vscode,
  writeBridgeRequest,
}) {
  async function routeOverviewBridgeRequest(message, output) {
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
    if (!message.payload?.bridgeRequestAlreadyWritten) {
      await writeBridgeRequest(
        message.requestType,
        message.payload || {},
        buildWorkspaceActionContext("overview-panel-webview"),
      ).catch((error) => {
        output.appendLine(
          `[ioi-overview] bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
    }
  }

  async function routeOverviewPanelMessage(message, output) {
    if (
      message?.type === "bridgeRequest" &&
      typeof message.requestType === "string"
    ) {
      await routeOverviewBridgeRequest(message, output);
      return;
    }
    if (message?.type !== "command" || typeof message.command !== "string") {
      return;
    }
    await vscode.commands.executeCommand(message.command, message.payload);
  }

  async function openOverviewPanel(context, output) {
    const state = await readBridgeState();
    let overviewPanel = getOverviewPanel();
    if (overviewPanel) {
      overviewPanel.reveal(vscode.ViewColumn.One);
    } else {
      overviewPanel = vscode.window.createWebviewPanel(
        "ioi.overview",
        "Hypervisor Overview",
        vscode.ViewColumn.One,
        {
          enableScripts: true,
          retainContextWhenHidden: true,
        },
      );
      setOverviewPanel(overviewPanel);
      overviewPanel.iconPath = vscode.Uri.joinPath(
        context.extensionUri,
        "media",
        "ioi-activity.svg",
      );
      overviewPanel.webview.onDidReceiveMessage(async (message) => {
        await routeOverviewPanelMessage(message, output);
      });
      registerModePanelVisibilityProjection(overviewPanel, "home", output);
      overviewPanel.onDidDispose(() => {
        setOverviewPanel(null);
        resetOverviewPanelRenderState();
      });
    }
    updateOverviewPanelHtml(state);
    output.appendLine("Opened Hypervisor Overview webview.");
    return overviewPanel;
  }

  return {
    openOverviewPanel,
    routeOverviewPanelMessage,
  };
}

module.exports = {
  createOverviewPanelLifecycle,
};
