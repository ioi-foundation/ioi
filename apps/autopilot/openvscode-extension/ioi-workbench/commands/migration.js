function registerMigrationCommands({
  context,
  output,
  vscode,
  buildWorkspaceActionContext,
  writeBridgeRequest,
  workspaceSummary,
  status,
}) {
  const planMigrationImport = async (command, sourceEditor, importKind, payload = {}) => {
    const contextSnapshot = buildWorkspaceActionContext("migration-assistant");
    await writeBridgeRequest("migration.import.plan", {
      workspaceRoot: workspaceSummary().path,
      sourceCommand: command,
      sourceEditor,
      importKind,
      applyMode: "plan_only",
      policyReviewRequired: true,
      sandboxBoundaryPreserved: true,
      autoApply: false,
      runtimeAuthority: "daemon-owned",
      projectionOwner: "openvscode-workbench-adapter",
      ownsRuntimeState: false,
      payload: payload && typeof payload === "object" ? payload : {},
    }, contextSnapshot).catch((error) => {
      output.appendLine(
        `[ioi-migration] bridge request unavailable: ${error?.message || String(error)}`,
      );
    });
    status(`Planned ${sourceEditor} ${importKind} import.`);
  };

  context.subscriptions.push(
    vscode.commands.registerCommand("ioi.migration.openAssistant", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("migration-assistant");
      await writeBridgeRequest("migration.assistant.open", {
        workspaceRoot: workspaceSummary().path,
        sourceCommand: "ioi.migration.openAssistant",
        supportedSources: ["vscode", "cursor", "windsurf"],
        supportedImports: ["settings", "extensions", "keybindings", "exclusions"],
        applyMode: "plan_only",
        policyReviewRequired: true,
        sandboxBoundaryPreserved: true,
        autoApply: false,
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
        payload: payload && typeof payload === "object" ? payload : {},
      }, contextSnapshot).catch((error) => {
        output.appendLine(
          `[ioi-migration] bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
      status("Opened Migration Assistant plan.");
    }),
    vscode.commands.registerCommand("ioi.migration.importVSCodeSettings", (payload = {}) =>
      planMigrationImport("ioi.migration.importVSCodeSettings", "vscode", "settings", payload),
    ),
    vscode.commands.registerCommand("ioi.migration.importCursorSettings", (payload = {}) =>
      planMigrationImport("ioi.migration.importCursorSettings", "cursor", "settings", payload),
    ),
    vscode.commands.registerCommand("ioi.migration.importWindsurfSettings", (payload = {}) =>
      planMigrationImport("ioi.migration.importWindsurfSettings", "windsurf", "settings", payload),
    ),
    vscode.commands.registerCommand("ioi.migration.importVSCodeExtensions", (payload = {}) =>
      planMigrationImport("ioi.migration.importVSCodeExtensions", "vscode", "extensions", payload),
    ),
    vscode.commands.registerCommand("ioi.migration.importCursorExtensions", (payload = {}) =>
      planMigrationImport("ioi.migration.importCursorExtensions", "cursor", "extensions", payload),
    ),
    vscode.commands.registerCommand("ioi.migration.importWindsurfExtensions", (payload = {}) =>
      planMigrationImport("ioi.migration.importWindsurfExtensions", "windsurf", "extensions", payload),
    ),
  );
}

module.exports = {
  registerMigrationCommands,
};
