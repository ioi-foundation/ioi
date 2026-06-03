"use strict";

function registerChatCommands({
  vscode,
  status,
  buildWorkspaceActionContext,
  writeBridgeRequest,
  workspaceSummary,
  pickString,
  getStudioPanel = () => null,
  startNewStudioSession,
  refreshStudioPanelHtml,
  focusStudioPanelComposer,
  output,
}) {
  return [
    vscode.commands.registerCommand("ioi.chat.new", async () => {
      const context = buildWorkspaceActionContext("ioi.chat");
      if (getStudioPanel()) {
        startNewStudioSession("Operator started a fresh Studio chat session.");
        await refreshStudioPanelHtml(output);
        await focusStudioPanelComposer();
      }
      await writeBridgeRequest("chat.new", {
        workspaceRoot: workspaceSummary().path,
      }, context);
      status("Queued new IOI Chat thread.");
    }),
    vscode.commands.registerCommand("ioi.chat.newOptions", async () => {
      const context = buildWorkspaceActionContext("ioi.chat");
      await writeBridgeRequest("chat.newOptions", {
        workspaceRoot: workspaceSummary().path,
        options: ["new-chat", "new-window", "new-workspace-chat"],
      }, context);
      status("Queued IOI Chat new-thread options.");
    }),
    vscode.commands.registerCommand("ioi.chat.openSettings", async () => {
      const context = buildWorkspaceActionContext("ioi.chat");
      await writeBridgeRequest("settings.open", {
        surface: "chat",
        workspaceRoot: workspaceSummary().path,
      }, context);
      status("Queued IOI Chat settings.");
    }),
    vscode.commands.registerCommand("ioi.chat.focusComposer", async () => {
      const context = buildWorkspaceActionContext("ioi.chat");
      const studioPanel = getStudioPanel();
      if (studioPanel) {
        studioPanel.reveal(vscode.ViewColumn.One);
        await studioPanel.webview.postMessage({
          source: "ioi-studio-control",
          type: "focusComposer",
        });
      }
      await writeBridgeRequest("chat.focusComposer", {
        workspaceRoot: workspaceSummary().path,
      }, context);
      status("Queued IOI Chat composer focus.");
    }),
    vscode.commands.registerCommand("ioi.chat.submit", async (payload = {}) => {
      const prompt =
        pickString(payload, "prompt") ||
        pickString(payload, "query") ||
        pickString(payload, "initialQuery");
      if (!prompt) {
        vscode.window.showWarningMessage("No IOI Chat prompt was provided.");
        return;
      }
      const context = buildWorkspaceActionContext("ioi.chat");
      await writeBridgeRequest("chat.submit", {
        prompt,
        workspaceRoot: workspaceSummary().path,
        mode: pickString(payload, "mode"),
        model: pickString(payload, "model"),
      }, context);
      status("Queued IOI Chat request.");
    }),
    vscode.commands.registerCommand("ioi.chat.moreActions", async () => {
      const context = buildWorkspaceActionContext("ioi.chat");
      await writeBridgeRequest("chat.moreActions", {
        workspaceRoot: workspaceSummary().path,
        actions: [
          "review-current-file",
          "explain-selection",
          "open-runs",
          "open-policy",
        ],
      }, context);
      status("Queued IOI Chat action menu.");
    }),
    vscode.commands.registerCommand("ioi.chat.explainSelection", async (uri) => {
      const context = buildWorkspaceActionContext("editor", uri);
      const payloadFilePath = pickString(uri, "filePath");
      const payloadSelectedText = pickString(uri, "selectedText");
      if (payloadFilePath) {
        context.filePath = payloadFilePath;
      }
      await writeBridgeRequest("chat.explainSelection", {
        filePath: context.filePath,
        selectedText: payloadSelectedText ?? context.selection?.selectedText ?? null,
      }, context);
      status("Queued IOI Chat selection review.");
    }),
    vscode.commands.registerCommand("ioi.chat.reviewFile", async (uri) => {
      const payloadFilePath = pickString(uri, "filePath");
      const context = buildWorkspaceActionContext(
        uri && !payloadFilePath ? "explorer" : "editor",
        uri,
      );
      if (payloadFilePath) {
        context.filePath = payloadFilePath;
      }
      await writeBridgeRequest("chat.reviewFile", {
        filePath: context.filePath,
      }, context);
      status("Queued IOI Chat file review.");
    }),
    vscode.commands.registerCommand("ioi.artifacts.review", async (payload) => {
      const context = {
        ...buildWorkspaceActionContext("workbench-view"),
        artifactId: pickString(payload, "artifactId"),
        evidenceThreadId: pickString(payload, "evidenceThreadId"),
        connectorId: pickString(payload, "connectorId"),
      };
      await writeBridgeRequest(
        "chat.reviewArtifact",
        {
          artifactId: context.artifactId,
          evidenceThreadId: context.evidenceThreadId,
          connectorId: context.connectorId,
        },
        context,
      );
      status("Queued IOI Chat artifact review.");
    }),
  ];
}

module.exports = {
  registerChatCommands,
};
