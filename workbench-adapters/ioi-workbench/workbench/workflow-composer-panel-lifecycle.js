"use strict";

function createWorkflowComposerPanelLifecycle({
  buildWorkspaceActionContext,
  registerModePanelVisibilityProjection,
  setTimeoutFn = setTimeout,
  vscode,
  workflowComposerHtml,
  writeBridgeRequest,
}) {
  let workflowComposerPanel = null;

  function getWorkflowComposerPanel() {
    return workflowComposerPanel;
  }

  function openWorkflowComposerPanel(context, output, options = {}) {
    if (workflowComposerPanel) {
      workflowComposerPanel.reveal(vscode.ViewColumn.One);
    } else {
      workflowComposerPanel = vscode.window.createWebviewPanel(
        "ioi.workflowComposer",
        "Autopilot Workflow Composer",
        vscode.ViewColumn.One,
        {
          enableScripts: true,
          retainContextWhenHidden: true,
          localResourceRoots: [
            vscode.Uri.joinPath(context.extensionUri, "media"),
          ],
        },
      );
      workflowComposerPanel.iconPath = vscode.Uri.joinPath(
        context.extensionUri,
        "media",
        "ioi-activity.svg",
      );
      workflowComposerPanel.webview.html = workflowComposerHtml(
        context,
        workflowComposerPanel.webview,
      );
      workflowComposerPanel.webview.onDidReceiveMessage(async (message) => {
        if (
          message?.type === "bridgeRequest" &&
          typeof message.requestType === "string"
        ) {
          await writeBridgeRequest(
            message.requestType,
            message.payload || {},
            buildWorkspaceActionContext("workflow-composer-webview"),
          );
          return;
        }
        if (message?.type === "workflowCompositorProof" && message.proof) {
          await writeBridgeRequest(
            "workflowCompositor.proof",
            message.proof,
            buildWorkspaceActionContext("workflow-composer-webview"),
          );
          return;
        }
        if (message?.type === "workflowCompositorError" && message.error) {
          output.appendLine(
            `[workflow-composer] ${message.error.message || "unknown webview error"}`,
          );
          await writeBridgeRequest(
            "workflowCompositor.error",
            message.error,
            buildWorkspaceActionContext("workflow-composer-webview"),
          );
          return;
        }
        if (message?.type === "command" && typeof message.command === "string") {
          await vscode.commands.executeCommand(message.command, message.payload);
        }
      });
      registerModePanelVisibilityProjection(workflowComposerPanel, "workflows", output);
      workflowComposerPanel.onDidDispose(() => {
        workflowComposerPanel = null;
      });
    }

    const scenarioId =
      typeof options.scenarioId === "string" ? options.scenarioId : null;
    const phase = typeof options.phase === "string" ? options.phase : "canvas";
    if (scenarioId) {
      setTimeoutFn(() => {
        workflowComposerPanel?.webview.postMessage({
          type: "ioi.workflow.compositor.runScenario",
          scenarioId,
          phase,
        });
      }, 750);
    } else if (options.capturePhase) {
      setTimeoutFn(() => {
        workflowComposerPanel?.webview.postMessage({
          type: "ioi.workflow.compositor.capturePhase",
          phase,
        });
      }, 750);
    }

    output.appendLine("Opened Hypervisor Workflow Composer webview.");
    return workflowComposerPanel;
  }

  return {
    getWorkflowComposerPanel,
    openWorkflowComposerPanel,
  };
}

module.exports = {
  createWorkflowComposerPanelLifecycle,
};
