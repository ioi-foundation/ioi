"use strict";

function registerStudioModeControlCommands({
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
}) {
  return [
    vscode.commands.registerCommand("ioi.quickInput.permissionMode.pick", async (payload = {}) => {
      const options = studioPermissionModeOptions(payload.approvalMode || studioRuntimeProjection.approvalMode).map((item) => ({
        label: item.label,
        description: item.description,
        picked: item.picked,
        approvalMode: item.id,
      }));
      const picked = await vscode.window.showQuickPick(options, {
        placeHolder: "Choose Agent permissions",
        ignoreFocusOut: true,
      });
      if (!picked) {
        return;
      }
      const mapping = await applyStudioPermissionModeSelection({ approvalMode: picked.approvalMode }, output);
      await writeBridgeRequest("chat.permissionMode.select", {
        selectionId: picked.approvalMode,
        approvalMode: mapping.approvalMode,
        approval_mode: mapping.approvalMode,
        threadMode: mapping.threadMode,
        thread_mode: mapping.threadMode,
        label: picked.label,
        daemonMapping: mapping,
        source: "agent-studio-permissions-menu",
        runtimeAuthority: "daemon-owned",
        projectionOwner: "ioi-workbench-agent-studio",
      }, buildWorkspaceActionContext("agent-studio-permissions-menu")).catch((error) => {
        output.appendLine(
          `[ioi-studio] bridge permission mode route unavailable: ${error?.message || String(error)}`,
        );
      });
      await refreshStudioPanelHtml();
      await focusStudioPanelComposer();
      status(`Agent permissions set to ${picked.label}.`);
    }),
    vscode.commands.registerCommand("ioi.studio.applyAgentMode", async (payload = {}) => {
      const applied = applyStudioAgentModeSelection(payload);
      await refreshStudioPanelHtml();
      await focusStudioPanelComposer();
      status(`Agent Studio mode set to ${studioExecutionModeLabel(applied.executionMode)}.`);
    }),
    vscode.commands.registerCommand("ioi.studio.applyPermissionMode", async (payload = {}) => {
      const mapping = await applyStudioPermissionModeSelection(payload, output);
      await refreshStudioPanelHtml();
      await focusStudioPanelComposer();
      status(`Agent Studio permissions set to ${studioPermissionModeLabel(mapping.approvalMode)}.`);
    }),
  ];
}

module.exports = {
  registerStudioModeControlCommands,
};
