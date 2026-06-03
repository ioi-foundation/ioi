function extensionQuickInputFallbackEnabled(env = process.env) {
  return ["1", "true", "yes"].includes(
    String(env.IOI_QUICKINPUT_EXTENSION_FALLBACK || "").toLowerCase(),
  );
}

async function recordForkQuickInputCommand({
  command,
  payload,
  output,
  buildWorkspaceActionContext,
  writeBridgeRequest,
}) {
  const contextSnapshot = buildWorkspaceActionContext("fork-native-quickinput-command");
  await writeBridgeRequest(command.replace(/^ioi\.quickInput\./, "quickInput."), {
    ...(payload && typeof payload === "object" ? payload : {}),
    sourceCommand: command,
    nativeForkContributionExpected: true,
    extensionQuickPickFallbackUsed: false,
    runtimeAuthority: "daemon-owned",
    projectionOwner: "autopilot-workbench-fork-quickinput",
  }, contextSnapshot).catch((error) => {
    output.appendLine(
      `[ioi-quickinput] fork command bridge request unavailable: ${error?.message || String(error)}`,
    );
  });
}

function registerQuickInputCommands({
  context,
  output,
  vscode,
  buildWorkspaceActionContext,
  writeBridgeRequest,
  status,
  fallbackEnabled = extensionQuickInputFallbackEnabled,
}) {
  const recordForkCommand = (command, payload) =>
    recordForkQuickInputCommand({
      command,
      payload,
      output,
      buildWorkspaceActionContext,
      writeBridgeRequest,
    });

  context.subscriptions.push(
    vscode.commands.registerCommand("ioi.quickInput.context.open", async (payload = {}) => {
      if (fallbackEnabled()) {
        await vscode.commands.executeCommand("ioi.studio.openContextPicker", payload);
        return;
      }
      await recordForkCommand("ioi.quickInput.context.open", payload);
      status("Fork-native Add Context QuickInput requested.");
    }),
    vscode.commands.registerCommand("ioi.quickInput.tools.configure", async (payload = {}) => {
      if (fallbackEnabled()) {
        await vscode.commands.executeCommand("ioi.studio.openToolPicker", payload);
        return;
      }
      await recordForkCommand("ioi.quickInput.tools.configure", payload);
      status("Fork-native Configure Tools QuickInput requested.");
    }),
    vscode.commands.registerCommand("ioi.quickInput.modelRoute.pick", async (payload = {}) => {
      await recordForkCommand("ioi.quickInput.modelRoute.pick", payload);
      status("Fork-native model route picker requested.");
    }),
    vscode.commands.registerCommand("ioi.quickInput.workflowTarget.pick", async (payload = {}) => {
      await recordForkCommand("ioi.quickInput.workflowTarget.pick", payload);
      status("Fork-native workflow target picker requested.");
    }),
    vscode.commands.registerCommand("ioi.quickInput.agentMode.pick", async (payload = {}) => {
      await recordForkCommand("ioi.quickInput.agentMode.pick", payload);
      status("Fork-native agent mode picker requested.");
    }),
  );
}

module.exports = {
  extensionQuickInputFallbackEnabled,
  recordForkQuickInputCommand,
  registerQuickInputCommands,
};
