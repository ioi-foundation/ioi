"use strict";

function defaultModelsViewDefinition(viewDefinitions = []) {
  return viewDefinitions.find((definition) => definition.id === "ioi.models") || {
    id: "ioi.models",
    title: "Models",
    eyebrow: "Daemon model runtime",
    description: "Daemon-backed model mounting.",
    actions: [],
  };
}

function createPersistentModePanels({
  HYPERVISOR_MODE_BY_ID,
  VIEW_DEFINITIONS,
  buildWorkspaceActionContext,
  codeModePanelHtml,
  readBridgeState,
  registerModePanelVisibilityProjection,
  renderHtml,
  setTimeoutFn = setTimeout,
  vscode,
  writeBridgeRequest,
}) {
  let modelsPanel = null;
  const genericModePanels = new Map();

  function getModelsPanel() {
    return modelsPanel;
  }

  function renderModePanelHtml(modeId, state) {
    if (modeId === "code") {
      return codeModePanelHtml(state);
    }
    const mode = HYPERVISOR_MODE_BY_ID[modeId];
    const viewId = mode?.panelViewId;
    const viewDefinition =
      VIEW_DEFINITIONS.find((definition) => definition.id === viewId) || {
        id: viewId || `ioi.${modeId}`,
        title: mode?.title || "Hypervisor",
        eyebrow: "Hypervisor mode",
        description: "Persistent Hypervisor Workbench mode.",
        actions: [],
      };
    return renderHtml(viewDefinition, state);
  }

  async function openModelsPanel(context, output, options = {}) {
    const modelsViewDefinition = defaultModelsViewDefinition(VIEW_DEFINITIONS);
    const state = await readBridgeState();
    if (modelsPanel) {
      modelsPanel.reveal(vscode.ViewColumn.One);
    } else {
      modelsPanel = vscode.window.createWebviewPanel(
        "ioi.models",
        "Hypervisor Models",
        vscode.ViewColumn.One,
        {
          enableScripts: true,
          retainContextWhenHidden: true,
        },
      );
      modelsPanel.iconPath = vscode.Uri.joinPath(
        context.extensionUri,
        "media",
        "ioi-activity.svg",
      );
      modelsPanel.webview.onDidReceiveMessage(async (message) => {
        if (
          message?.type === "bridgeRequest" &&
          typeof message.requestType === "string"
        ) {
          await writeBridgeRequest(
            message.requestType,
            message.payload || {},
            buildWorkspaceActionContext("models-panel-webview"),
          );
          return;
        }
        if (message?.type === "modelsModeProof" && message.proof) {
          await writeBridgeRequest(
            "modelsMode.proof",
            message.proof,
            buildWorkspaceActionContext("models-panel-webview"),
          );
          return;
        }
        if (message?.type === "modelsModeProof" && message.proof) {
          await writeBridgeRequest(
            "modelsMode.proof",
            message.proof,
            buildWorkspaceActionContext("ioi.models"),
          );
          return;
        }
        if (message?.type !== "command" || typeof message.command !== "string") {
          return;
        }
        await vscode.commands.executeCommand(message.command, message.payload);
      });
      registerModePanelVisibilityProjection(modelsPanel, "models", output);
      modelsPanel.onDidDispose(() => {
        modelsPanel = null;
      });
    }
    modelsPanel.webview.html = renderHtml(modelsViewDefinition, state);
    const phase = typeof options.phase === "string" ? options.phase : null;
    if (phase) {
      setTimeoutFn(() => {
        modelsPanel?.webview.postMessage({
          type: "ioi.models.capturePhase",
          phase,
        });
      }, 700);
    }
    output.appendLine("Opened Hypervisor Models webview.");
    return modelsPanel;
  }

  async function openGenericModePanel(context, output, modeId) {
    const mode = HYPERVISOR_MODE_BY_ID[modeId];
    if (!mode) {
      throw new Error(`Unknown Hypervisor mode: ${modeId}`);
    }
    const state = await readBridgeState();
    let panel = genericModePanels.get(modeId);
    if (panel) {
      panel.reveal(vscode.ViewColumn.One);
    } else {
      panel = vscode.window.createWebviewPanel(
        mode.panelViewType,
        `Hypervisor `,
        vscode.ViewColumn.One,
        {
          enableScripts: true,
          retainContextWhenHidden: true,
        },
      );
      panel.iconPath = vscode.Uri.joinPath(
        context.extensionUri,
        "media",
        "ioi-activity.svg",
      );
      panel.webview.onDidReceiveMessage(async (message) => {
        if (
          message?.type === "bridgeRequest" &&
          typeof message.requestType === "string"
        ) {
          await writeBridgeRequest(
            message.requestType,
            message.payload || {},
            buildWorkspaceActionContext(`${modeId}-mode-webview`),
          );
          return;
        }
        if (message?.type !== "command" || typeof message.command !== "string") {
          return;
        }
        await vscode.commands.executeCommand(message.command, message.payload);
      });
      registerModePanelVisibilityProjection(panel, modeId, output);
      panel.onDidDispose(() => {
        genericModePanels.delete(modeId);
      });
      genericModePanels.set(modeId, panel);
    }
    panel.webview.html = renderModePanelHtml(modeId, state);
    output.appendLine(`Opened Hypervisor ${mode.title} mode webview.`);
    return panel;
  }

  function refreshPersistentModePanels(state) {
    if (modelsPanel) {
      modelsPanel.webview.html = renderHtml(defaultModelsViewDefinition(VIEW_DEFINITIONS), state);
    }
    for (const [modeId, panel] of genericModePanels) {
      panel.webview.html = renderModePanelHtml(modeId, state);
    }
  }

  return {
    getModelsPanel,
    openGenericModePanel,
    openModelsPanel,
    refreshPersistentModePanels,
    renderModePanelHtml,
  };
}

module.exports = {
  createPersistentModePanels,
  defaultModelsViewDefinition,
};
