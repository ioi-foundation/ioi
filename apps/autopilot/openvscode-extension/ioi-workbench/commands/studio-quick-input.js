"use strict";

function registerStudioQuickInputCommands({
  vscode,
  output,
  status,
  buildWorkspaceActionContext,
  writeBridgeRequest,
  readBridgeState,
  studioContextQuickPickItems,
  studioToolQuickPickItems,
}) {
  return [
    vscode.commands.registerCommand("ioi.studio.openContextPicker", async () => {
      const contextSnapshot = buildWorkspaceActionContext("studio-native-context-picker");
      const items = studioContextQuickPickItems();
      const picker = vscode.window.createQuickPick();
      const disposables = [];

      picker.placeholder = "Search for files and context to add to your request";
      picker.matchOnDescription = true;
      picker.matchOnDetail = true;
      picker.ignoreFocusOut = true;
      picker.items = items;
      picker.activeItems = items.slice(0, 1);

      disposables.push(
        picker.onDidAccept(async () => {
          const selection = picker.selectedItems[0] || picker.activeItems[0];
          const row = selection?.row;
          if (!row) {
            return;
          }
          picker.hide();
          await writeBridgeRequest(row.requestType || "chat.contextPicker.select", {
            contextId: row.id,
            label: row.title,
            source: "studio-native-context-picker",
            runtimeAuthority: "daemon-owned",
            projectionOwner: "ioi-workbench-agent-studio",
          }, contextSnapshot).catch((error) => {
            output.appendLine(
              `[ioi-studio] context picker bridge request unavailable: ${error?.message || String(error)}`,
            );
          });
          if (row.command) {
            await vscode.commands.executeCommand(row.command).catch((error) => {
              output.appendLine(
                `[ioi-studio] context picker command unavailable: ${error?.message || String(error)}`,
              );
            });
          }
        }),
        picker.onDidHide(() => {
          for (const disposable of disposables) {
            disposable.dispose();
          }
          picker.dispose();
        }),
      );

      picker.show();
      status("Opened Studio context picker.");
    }),
    vscode.commands.registerCommand("ioi.studio.openToolPicker", async () => {
      const contextSnapshot = buildWorkspaceActionContext("studio-native-tool-picker");
      let state = {};
      try {
        state = await readBridgeState();
      } catch (error) {
        output.appendLine(
          `[ioi-studio] tool picker using local substrate rows: ${error?.message || String(error)}`,
        );
      }
      const items = studioToolQuickPickItems(state);
      const picker = vscode.window.createQuickPick();
      const toolButtons = {
        context: {
          iconPath: new vscode.ThemeIcon("paperclip"),
          tooltip: "Add Context",
        },
        manage: {
          iconPath: new vscode.ThemeIcon("extensions"),
          tooltip: "Manage Tools",
        },
        settings: {
          iconPath: new vscode.ThemeIcon("settings-gear"),
          tooltip: "Tool Settings",
        },
      };
      const disposables = [];

      picker.title = "Configure Tools";
      picker.placeholder = "Select tools that are available to chat.";
      picker.canSelectMany = true;
      picker.matchOnDescription = true;
      picker.matchOnDetail = true;
      picker.ignoreFocusOut = true;
      picker.buttons = [toolButtons.context, toolButtons.manage, toolButtons.settings];
      picker.items = items;
      picker.selectedItems = items.filter((item) => item.row && item.row.enabled !== false && item.row.selected);
      picker.activeItems = picker.selectedItems.slice(0, 1);

      disposables.push(
        picker.onDidAccept(async () => {
          const selectedRows = picker.selectedItems
            .map((item) => ({ item, row: item.row }))
            .filter(({ row }) => row && row.enabled !== false);
          picker.hide();
          await writeBridgeRequest("chat.toolControls", {
            action: "configureTools",
            selectedTools: selectedRows.map(({ item, row }) => ({
              toolId: row.id,
              label: row.title,
              detail: row.detail,
              section: item.sectionId,
              meta: row.meta,
            })),
            selectedCount: selectedRows.length,
            source: "studio-native-quick-input",
            runtimeAuthority: "daemon-owned",
            projectionOwner: "ioi-workbench-agent-studio",
          }, contextSnapshot).catch((error) => {
            output.appendLine(
              `[ioi-studio] tool control bridge request unavailable: ${error?.message || String(error)}`,
            );
          });
        }),
        picker.onDidTriggerButton(async (button) => {
          if (button === toolButtons.context) {
            await vscode.commands.executeCommand("ioi.studio.openContextPicker").catch((error) => {
              output.appendLine(
                `[ioi-studio] context picker command unavailable: ${error?.message || String(error)}`,
              );
            });
            return;
          }
          if (button === toolButtons.manage) {
            await writeBridgeRequest("chat.toolControls.manage", {
              source: "studio-native-tools-config",
              runtimeAuthority: "daemon-owned",
              projectionOwner: "ioi-workbench-agent-studio",
            }, contextSnapshot).catch((error) => {
              output.appendLine(
                `[ioi-studio] manage tools bridge request unavailable: ${error?.message || String(error)}`,
              );
            });
            return;
          }
          if (button === toolButtons.settings) {
            await vscode.commands.executeCommand("workbench.action.openSettings", "chat.tools").catch((error) => {
              output.appendLine(
                `[ioi-studio] settings command unavailable: ${error?.message || String(error)}`,
              );
            });
          }
        }),
        picker.onDidHide(() => {
          for (const disposable of disposables) {
            disposable.dispose();
          }
          picker.dispose();
        }),
      );

      picker.show();
      status("Opened Studio tool configuration.");
    }),
  ];
}

module.exports = {
  registerStudioQuickInputCommands,
};
