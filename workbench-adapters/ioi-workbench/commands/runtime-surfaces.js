"use strict";

function registerRuntimeSurfaceCommands({
  vscode,
  output,
  status,
  buildWorkspaceActionContext,
  writeBridgeRequest,
  workspaceSummary,
  pickString,
  getActiveTraceTarget,
  setActiveTraceTarget,
  enterRuns,
  enterPolicy,
  enterConnectors,
  openGenericModePanel,
  closePrimarySidebarAfterActivityLaunch,
}) {
  return [
    vscode.commands.registerCommand("ioi.runs.refresh", async (payload = {}) => {
      const actionContext = buildWorkspaceActionContext("workbench-view");
      if (payload?.traceTarget && typeof payload.traceTarget === "object") {
        setActiveTraceTarget({
          ...payload.traceTarget,
          openedAt: new Date().toISOString(),
        });
      }
      const traceTarget = getActiveTraceTarget();
      await writeBridgeRequest("runs.open", {
        workspaceRoot: workspaceSummary().path,
        traceTarget,
      }, actionContext).catch((error) => {
        output.appendLine(
          `[ioi-runs] bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
      await enterRuns();
      await openGenericModePanel("runs");
      closePrimarySidebarAfterActivityLaunch();
      status(traceTarget ? "Queued IOI tracing surface." : "Queued IOI runs surface.");
    }),
    vscode.commands.registerCommand("ioi.runs.review", async (payload) => {
      const context = {
        ...buildWorkspaceActionContext("workbench-view"),
        runId: pickString(payload, "runId"),
        artifactId: pickString(payload, "artifactId"),
        evidenceThreadId: pickString(payload, "evidenceThreadId"),
      };
      await writeBridgeRequest(
        "chat.reviewRun",
        {
          runId: context.runId,
          artifactId: context.artifactId,
          evidenceThreadId: context.evidenceThreadId,
        },
        context,
      );
      status("Queued IOI Chat run review.");
    }),
    vscode.commands.registerCommand("ioi.policy.open", async () => {
      const actionContext = buildWorkspaceActionContext("workbench-view");
      await enterPolicy();
      await openGenericModePanel("policy");
      await writeBridgeRequest("policy.open", {
        workspaceRoot: workspaceSummary().path,
      }, actionContext);
      closePrimarySidebarAfterActivityLaunch();
      status("Queued IOI policy surface.");
    }),
    vscode.commands.registerCommand("ioi.artifacts.openEvidence", async (payload) => {
      const sessionId = pickString(payload, "sessionId");
      if (!sessionId) {
        vscode.window.showWarningMessage("No evidence session is available for this artifact.");
        return;
      }
      const context = {
        ...buildWorkspaceActionContext("workbench-view"),
        evidenceThreadId: sessionId,
      };
      await writeBridgeRequest("evidence.open", {
        sessionId,
      }, context);
      status("Queued IOI evidence session.");
    }),
    vscode.commands.registerCommand("ioi.artifacts.openPolicy", async (payload) => {
      const connectorId = pickString(payload, "connectorId");
      const context = {
        ...buildWorkspaceActionContext("workbench-view"),
        connectorId,
      };
      await writeBridgeRequest("policy.open", {
        workspaceRoot: workspaceSummary().path,
        connectorId,
      }, context);
      status("Queued artifact policy context.");
    }),
    vscode.commands.registerCommand("ioi.chatSession.openArtifact", async (payload) => {
      const artifactId = pickString(payload, "artifactId");
      if (!artifactId) {
        vscode.window.showWarningMessage("No artifact target is available for Chat Session.");
        return;
      }
      const context = {
        ...buildWorkspaceActionContext("workbench-view"),
        artifactId,
      };
      await writeBridgeRequest("chatSession.openArtifact", {
        artifactId,
      }, context);
      status("Queued Chat Session artifact drill-in.");
    }),
    vscode.commands.registerCommand("ioi.connections.inspect", async () => {
      const actionContext = buildWorkspaceActionContext("workbench-view");
      await enterConnectors();
      await openGenericModePanel("connectors");
      await writeBridgeRequest("connections.open", {
        workspaceRoot: workspaceSummary().path,
      }, actionContext);
      closePrimarySidebarAfterActivityLaunch();
      status("Queued IOI connections surface.");
    }),
    vscode.commands.registerCommand("ioi.connections.openConnector", async (payload) => {
      const connectorId = pickString(payload, "connectorId");
      if (!connectorId) {
        vscode.window.showWarningMessage("No connector target is available for this workspace item.");
        return;
      }
      await enterConnectors();
      await openGenericModePanel("connectors");
      const actionContext = {
        ...buildWorkspaceActionContext("workbench-view"),
        connectorId,
      };
      await writeBridgeRequest("connections.open", {
        workspaceRoot: workspaceSummary().path,
        connectorId,
      }, actionContext);
      status("Queued IOI connector overview.");
    }),
    vscode.commands.registerCommand("ioi.automation.browser", async (uri) => {
      const context = buildWorkspaceActionContext(uri ? "explorer" : "editor", uri);
      await writeBridgeRequest("automation.browser", {
        workspaceRoot: workspaceSummary().path,
        filePath: context.filePath,
        selectedText: context.selection?.selectedText ?? null,
      }, context);
      status("Queued governed browser/computer-use.");
    }),
  ];
}

module.exports = {
  registerRuntimeSurfaceCommands,
};
