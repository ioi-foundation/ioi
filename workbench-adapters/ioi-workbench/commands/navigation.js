"use strict";

function registerNavigationCommands({
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
  enterHome,
  enterStudio,
  enterCode,
  enterMode,
  openOverviewPanel,
  openStudioPanel,
  openGenericModePanel,
  closePrimarySidebarAfterActivityLaunch,
}) {
  return [
    vscode.commands.registerCommand("ioi.overview.open", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("overview");
      await enterHome();
      await openOverviewPanel();
      await writeBridgeRequest("overview.open", {
        workspaceRoot: workspaceSummary().path,
        sourceCommand: "ioi.overview.open",
        phase: pickString(payload, "phase") || "home",
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
      }, contextSnapshot).catch((error) => {
        output.appendLine(
          `[ioi-overview] bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
      closePrimarySidebarAfterActivityLaunch();
      status("Opened Autopilot Overview.");
    }),
    vscode.commands.registerCommand("ioi.commandCenter.open", async (options = {}) => {
      const initialQuery =
        options && typeof options.initialQuery === "string"
          ? options.initialQuery
          : "";
      const mode =
        options && typeof options.mode === "string" && options.mode === "tools"
          ? "tools"
          : undefined;
      const context = buildWorkspaceActionContext("command-center.autopilot-header");
      await writeBridgeRequest("commandCenter.open", {
        workspaceRoot: workspaceSummary().path,
        sourceCommand: "ioi.commandCenter.open",
        initialQuery,
        ...(mode ? { mode } : {}),
      }, context);
      status("Opening Autopilot command center.");
    }),
    vscode.commands.registerCommand("ioi.code.open", async () => {
      const contextSnapshot = buildWorkspaceActionContext("code-mode");
      await enterCode();
      await openGenericModePanel("code");
      await writeBridgeRequest("code.open", {
        workspaceRoot: workspaceSummary().path,
        sourceCommand: "ioi.code.open",
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
        vscodeSubstrateVisible: true,
      }, contextSnapshot).catch((error) => {
        output.appendLine(
          `[ioi-code] bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
      await vscode.commands.executeCommand("workbench.view.explorer").catch(() => undefined);
      status("Opened Code mode.");
    }),
    vscode.commands.registerCommand("ioi.autopilot.back", async () => {
      const lastMode = getLastAutopilotModeBeforeCode();
      const targetMode = lastMode && lastMode !== "code" ? lastMode : "home";
      const target = autopilotModeById[targetMode] || autopilotModeById.home;
      await enterMode(target.id);
      await vscode.commands.executeCommand(target.command, {
        source: "code-back",
        phase: target.phase,
      });
      closePrimarySidebarAfterActivityLaunch();
      status(`Returned to Autopilot ${target.title}.`);
    }),
    vscode.commands.registerCommand("ioi.studio.open", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("studio");
      await enterStudio();
      await openStudioPanel();
      await writeBridgeRequest("studio.open", {
        workspaceRoot: workspaceSummary().path,
        sourceCommand: "ioi.studio.open",
        phase: pickString(payload, "phase") || "chat",
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
      }, contextSnapshot).catch((error) => {
        output.appendLine(
          `[ioi-studio] bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
      closePrimarySidebarAfterActivityLaunch();
      status("Opened Agent Studio.");
    }),
    vscode.commands.registerCommand("ioi.studio.agentBuilder", async () => {
      const contextSnapshot = buildWorkspaceActionContext("agent-builder");
      await enterStudio();
      await openStudioPanel();
      await writeBridgeRequest("studio.agentBuilder.open", {
        workspaceRoot: workspaceSummary().path,
        sourceCommand: "ioi.studio.agentBuilder",
        preview: true,
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
      }, contextSnapshot).catch((error) => {
        output.appendLine(
          `[ioi-studio] agent builder bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
      status("Opened Agent Builder preview.");
    }),
    vscode.commands.registerCommand("ioi.studio.focusComposer", async () => {
      const studioPanel = getStudioPanel();
      if (studioPanel) {
        studioPanel.reveal(vscode.ViewColumn.One);
        await studioPanel.webview.postMessage({
          source: "ioi-studio-control",
          type: "focusComposer",
        });
      }
      status("Focused Agent Studio composer.");
    }),
  ];
}

module.exports = {
  registerNavigationCommands,
};
